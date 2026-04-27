// Package exit implements the DO-side HTTP handler. Apps Script POSTs
// AES-encrypted frame batches here; we decrypt, demux by session_id, dial real
// upstream targets on SYN, pump bytes between net.Conn and session, and
// long-poll the response so downstream bytes get delivered with low latency.
package exit

import (
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"syscall"
	"time"

	"github.com/kianmhz/GooseRelayVPN/internal/frame"
	"github.com/kianmhz/GooseRelayVPN/internal/session"
)

const (
	// ActiveDrainWindow caps how long a batch that just performed real work
	// (SYN/connect or non-empty uplink data) waits for downstream bytes.
	// Kept short so the client's single poll loop can quickly cycle back
	// and send SYN frames for other sessions that queued up while this poll
	// was in-flight. A long value here (e.g. 2s) causes head-of-line
	// blocking: when YouTube opens 4-6 parallel connections, later SYNs
	// are delayed by ActiveDrainWindow × (position in queue), easily
	// pushing total setup time past the player's ~7s abort threshold.
	ActiveDrainWindow = 350 * time.Millisecond

	// LongPollWindow is how long the handler holds open a request waiting for
	// downstream bytes. UrlFetchApp has a practical read timeout of ~10s, so
	// keep this comfortably below that.
	LongPollWindow = 8 * time.Second

	// MaxFramePayload caps the bytes per downstream frame (matches carrier).
	MaxFramePayload = 128 * 1024

	// upstreamReadBuf is the chunk size for reading from real net.Conn before
	// pushing to session.EnqueueTx (which then chunks into frames).
	upstreamReadBuf = 128 * 1024

	// coalesceWindow lets us gather a few more frames before responding, which
	// improves throughput for video streams under higher RTT links.
	coalesceWindow = 25 * time.Millisecond

	// maxDrainFramesPerSession keeps one hot session from dominating an entire
	// response batch when many interactive sessions are active concurrently.
	maxDrainFramesPerSession = 8

	// maxDrainFramesPerBatch bounds total frames emitted in one HTTP response so
	// one poll does not become a very large base64 body under high concurrency.
	maxDrainFramesPerBatch = 48

	// Under high fan-out (mobile apps opening many parallel connections), allow
	// a larger but still bounded batch to reduce queueing delay.
	busySessionThreshold       = 24
	maxDrainFramesPerBatchBusy = 144

	// dialFailureBackoff is how long we suppress repeated SYN dial attempts to a
	// target after a structural network/DNS failure.
	dialFailureBackoff = 2 * time.Second
)

// Config is the DO server's configuration.
type Config struct {
	ListenAddr string // "0.0.0.0:8443"
	AESKeyHex  string // 64-char hex
}

// Server holds the per-process session state.
type Server struct {
	cfg  Config
	aead *frame.Crypto
	dial func(network, address string, timeout time.Duration) (net.Conn, error)

	mu          sync.Mutex
	sessions    map[[frame.SessionIDLen]byte]*session.Session
	dialFail    map[string]time.Time
	pendingRSTs []*frame.Frame // RST frames to send back on the next response

	activity chan struct{} // buffered len 1; coalesces "session has new tx" signals
}

// New constructs an exit Server.
func New(cfg Config) (*Server, error) {
	aead, err := frame.NewCryptoFromHexKey(cfg.AESKeyHex)
	if err != nil {
		return nil, err
	}
	return &Server{
		cfg:      cfg,
		aead:     aead,
		dial:     net.DialTimeout,
		sessions: make(map[[frame.SessionIDLen]byte]*session.Session),
		dialFail: make(map[string]time.Time),
		activity: make(chan struct{}, 1),
	}, nil
}

// ListenAndServe blocks. It binds an HTTP listener on cfg.ListenAddr with one
// route, POST /tunnel, that handles batched encrypted frames.
func (s *Server) ListenAndServe() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/tunnel", s.handleTunnel)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	httpSrv := &http.Server{
		Addr:        s.cfg.ListenAddr,
		Handler:     mux,
		ReadTimeout: 30 * time.Second,
		// WriteTimeout intentionally generous — long-poll responses can take
		// up to LongPollWindow to start writing.
		WriteTimeout: LongPollWindow + 10*time.Second,
	}
	log.Printf("[exit] listening on %s", s.cfg.ListenAddr)
	return httpSrv.ListenAndServe()
}

func (s *Server) handleTunnel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("[exit] read body: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	rxFrames, err := frame.DecodeBatch(s.aead, body)
	if err != nil {
		log.Printf("[exit] decode batch: %v", err)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	for _, f := range rxFrames {
		s.routeIncoming(f)
	}

	// Active batches use a shorter wait to avoid stalling unrelated sessions,
	// while empty polls keep long-poll behavior for push responsiveness.
	deadline := time.Now().Add(s.drainWindow(rxFrames))
	for {
		txFrames := s.drainAll()
		if len(txFrames) > 0 {
			// Coalesce bursts into one response to reduce per-request overhead.
			coalesceDeadline := time.Now().Add(coalesceWindow)
		coalesceLoop:
			for {
				if time.Now().After(coalesceDeadline) {
					break coalesceLoop
				}
				remainingCoalesce := time.Until(coalesceDeadline)
				select {
				case <-r.Context().Done():
					return
				case <-s.activity:
					txFrames = append(txFrames, s.drainAll()...)
				case <-time.After(remainingCoalesce):
					break coalesceLoop
				}
			}

			respBody, err := frame.EncodeBatch(s.aead, txFrames)
			if err != nil {
				log.Printf("[exit] encode response: %v", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write(respBody)
			s.gcDoneSessions()
			return
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			// Empty response (still a valid base64-encoded zero-frame batch).
			respBody, _ := frame.EncodeBatch(s.aead, nil)
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write(respBody)
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-s.activity:
			// loop and drain
		case <-time.After(remaining):
			// loop one more time, then exit on next iteration
		}
	}
}

func (s *Server) drainWindow(rxFrames []*frame.Frame) time.Duration {
	for _, f := range rxFrames {
		if f.HasFlag(frame.FlagSYN) || len(f.Payload) > 0 {
			return ActiveDrainWindow
		}
	}
	return LongPollWindow
}

// routeIncoming routes one incoming frame to its session, creating the session
// (and dialing upstream) if this is a SYN.
func (s *Server) routeIncoming(f *frame.Frame) {
	s.mu.Lock()
	sess, exists := s.sessions[f.SessionID]
	s.mu.Unlock()

	if !exists {
		if !f.HasFlag(frame.FlagSYN) {
			log.Printf("[exit] frame for unknown session (no SYN), sending RST")
			rst := &frame.Frame{SessionID: f.SessionID, Flags: frame.FlagRST}
			s.mu.Lock()
			s.pendingRSTs = append(s.pendingRSTs, rst)
			s.mu.Unlock()
			s.kick()
			return
		}
		if s.isDialSuppressed(f.Target) {
			return
		}
		var err error
		sess, err = s.openSession(f.SessionID, f.Target)
		if err != nil {
			s.recordDialFailure(f.Target, err)
			log.Printf("[exit] dial %s: %v", f.Target, err)
			return
		}
		s.clearDialFailure(f.Target)
	}
	sess.ProcessRx(f)
}

// openSession dials the upstream target, creates a Session for the given ID,
// registers it, and spawns the bidirectional pump goroutines.
func (s *Server) openSession(id [frame.SessionIDLen]byte, target string) (*session.Session, error) {
	upstream, err := s.dial("tcp", target, 15*time.Second)
	if err != nil {
		return nil, err
	}
	sess := session.New(id, target, false)
	sess.OnTx = s.kick

	s.mu.Lock()
	s.sessions[id] = sess
	s.mu.Unlock()

	log.Printf("[exit] new session %x -> %s", id[:4], target)

	// Upstream → session.EnqueueTx (downstream direction).
	go func() {
		defer upstream.Close()
		buf := make([]byte, upstreamReadBuf)
		for {
			n, err := upstream.Read(buf)
			if n > 0 {
				sess.EnqueueTx(buf[:n])
			}
			if err != nil {
				if err != io.EOF {
					log.Printf("[exit] upstream read %x: %v", id[:4], err)
				}
				sess.RequestClose()
				return
			}
		}
	}()

	// session.RxChan → upstream.Write (upstream direction).
	go func() {
		for data := range sess.RxChan {
			if _, err := upstream.Write(data); err != nil {
				log.Printf("[exit] upstream write %x: %v", id[:4], err)
				_ = upstream.Close()
				return
			}
		}
		_ = upstream.Close()
	}()

	return sess, nil
}

func (s *Server) drainAll() []*frame.Frame {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*frame.Frame
	if len(s.pendingRSTs) > 0 {
		out = append(out, s.pendingRSTs...)
		s.pendingRSTs = s.pendingRSTs[:0]
	}
	batchCap := maxDrainFramesPerBatch
	if len(s.sessions) >= busySessionThreshold {
		batchCap = maxDrainFramesPerBatchBusy
	}
	remaining := batchCap
	for _, sess := range s.sessions {
		if remaining <= 0 {
			break
		}
		perSessionCap := maxDrainFramesPerSession
		if remaining < perSessionCap {
			perSessionCap = remaining
		}
		frames := sess.DrainTxLimited(MaxFramePayload, perSessionCap)
		out = append(out, frames...)
		remaining -= len(frames)
	}
	return out
}

func (s *Server) gcDoneSessions() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, sess := range s.sessions {
		if sess.IsDone() {
			delete(s.sessions, id)
		}
	}
}

func (s *Server) kick() {
	select {
	case s.activity <- struct{}{}:
	default:
	}
}

func (s *Server) isDialSuppressed(target string) bool {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	until, ok := s.dialFail[target]
	if !ok {
		return false
	}
	if now.After(until) {
		delete(s.dialFail, target)
		return false
	}
	return true
}

func (s *Server) recordDialFailure(target string, err error) {
	if !isBackoffEligibleDialErr(err) {
		return
	}
	s.mu.Lock()
	s.dialFail[target] = time.Now().Add(dialFailureBackoff)
	s.mu.Unlock()
}

func (s *Server) clearDialFailure(target string) {
	s.mu.Lock()
	delete(s.dialFail, target)
	s.mu.Unlock()
}

func isBackoffEligibleDialErr(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return true
	}
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		return false
	}
	if opErr.Timeout() {
		return true
	}
	var errno syscall.Errno
	if !errors.As(opErr, &errno) {
		return false
	}
	switch errno {
	case syscall.ECONNREFUSED,
		syscall.EHOSTUNREACH,
		syscall.ENETUNREACH,
		syscall.ENETDOWN,
		syscall.EADDRNOTAVAIL,
		syscall.ETIMEDOUT:
		return true
	default:
		return false
	}
}
