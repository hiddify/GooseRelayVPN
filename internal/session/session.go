// Package session represents one tunneled TCP connection between a SOCKS5
// client and an upstream target. It owns the per-direction sequence counters,
// the out-of-order rx reassembly queue, the tx buffer with backpressure, and
// the rx channel that VirtualConn reads from.
//
// Ported from FlowDriver/internal/transport/session.go, simplified for the
// HTTP long-poll carrier (no timer-based flush — the carrier drives cadence).
package session

import (
	"sync"

	"github.com/kianmhz/relay-tunnel/internal/frame"
)

// TxBufHighWater is the soft ceiling on the per-session tx buffer; EnqueueTx
// blocks once exceeded so a fast SOCKS5 writer can't cause unbounded growth.
const TxBufHighWater = 8 * 1024 * 1024

// Session is one logical TCP connection across the relay.
type Session struct {
	ID     [frame.SessionIDLen]byte
	Target string // "host:port", carried on the SYN frame

	mu      sync.Mutex
	txCond  *sync.Cond
	txBuf   []byte
	txSeq   uint64
	rxSeq   uint64
	rxQueue map[uint64]*frame.Frame

	synNeeded bool // first outgoing frame must carry SYN+Target
	closeReq  bool // VirtualConn.Close() called; FIN must be sent on next drain
	finSent   bool
	rxClosed  bool // RxChan has been closed (peer FIN received)

	RxChan chan []byte

	// OnTx is invoked when EnqueueTx adds data and when closeReq transitions
	// true. The carrier sets it to wake its long-poll loop.
	OnTx func()
}

// New creates a session with a random ID is the caller's responsibility — pass
// it in. needsSYN should be true on the client side (so the first frame carries
// the SYN flag and Target), false on the server side (created from a received
// SYN).
func New(id [frame.SessionIDLen]byte, target string, needsSYN bool) *Session {
	s := &Session{
		ID:        id,
		Target:    target,
		rxQueue:   make(map[uint64]*frame.Frame),
		RxChan:    make(chan []byte, 1024),
		synNeeded: needsSYN,
	}
	s.txCond = sync.NewCond(&s.mu)
	return s
}

// EnqueueTx appends bytes to the session's tx buffer. Blocks while the buffer
// exceeds TxBufHighWater. Safe to call concurrently with DrainTx.
func (s *Session) EnqueueTx(data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.txBuf) > TxBufHighWater && !s.closeReq {
		s.txCond.Wait()
	}
	if s.closeReq {
		return
	}
	s.txBuf = append(s.txBuf, data...)
	s.notifyTxLocked()
}

// RequestClose marks the session for shutdown. The next DrainTx will emit a
// FIN frame, and EnqueueTx becomes a no-op.
func (s *Session) RequestClose() {
	s.mu.Lock()
	s.closeReq = true
	s.txCond.Broadcast()
	s.notifyTxLocked()
	s.mu.Unlock()
}

// CloseRx closes RxChan if not already closed. Idempotent.
func (s *Session) CloseRx() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.rxClosed {
		s.rxClosed = true
		close(s.RxChan)
	}
}

// HasPendingTx reports whether DrainTx would emit at least one frame.
func (s *Session) HasPendingTx() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.synNeeded || len(s.txBuf) > 0 || (s.closeReq && !s.finSent)
}

// IsDone reports whether both FIN frames (sent and received) have flowed.
// The carrier uses this to garbage-collect finished sessions from its map.
func (s *Session) IsDone() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.finSent && s.rxClosed
}

// DrainTx removes pending tx bytes and returns them as a sequence of frames,
// each capped at maxPayload bytes. Emits a SYN frame first if needed, and a
// trailing FIN frame if RequestClose was called and the FIN hasn't been sent yet.
func (s *Session) DrainTx(maxPayload int) []*frame.Frame {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.synNeeded && len(s.txBuf) == 0 && !(s.closeReq && !s.finSent) {
		return nil
	}

	var frames []*frame.Frame

	// SYN (possibly with first chunk of payload).
	if s.synNeeded {
		f := &frame.Frame{
			SessionID: s.ID,
			Seq:       s.txSeq,
			Flags:     frame.FlagSYN,
			Target:    s.Target,
		}
		s.txSeq++
		s.synNeeded = false
		if len(s.txBuf) > 0 {
			n := len(s.txBuf)
			if n > maxPayload {
				n = maxPayload
			}
			f.Payload = append([]byte(nil), s.txBuf[:n]...)
			s.txBuf = s.txBuf[n:]
		}
		frames = append(frames, f)
	}

	// Remaining payload chunks.
	for len(s.txBuf) > 0 {
		n := len(s.txBuf)
		if n > maxPayload {
			n = maxPayload
		}
		f := &frame.Frame{
			SessionID: s.ID,
			Seq:       s.txSeq,
			Payload:   append([]byte(nil), s.txBuf[:n]...),
		}
		s.txSeq++
		s.txBuf = s.txBuf[n:]
		frames = append(frames, f)
	}

	// Trailing FIN.
	if s.closeReq && !s.finSent {
		frames = append(frames, &frame.Frame{
			SessionID: s.ID,
			Seq:       s.txSeq,
			Flags:     frame.FlagFIN,
		})
		s.txSeq++
		s.finSent = true
	}

	s.txCond.Broadcast() // wake any backpressured writers
	return frames
}

// ProcessRx delivers an incoming frame to RxChan in seq order. Future-seq
// frames are buffered; past-seq frames (already delivered) are dropped.
// FIN closes RxChan after draining all in-order data.
//
// Payloads are gathered under the lock and then sent on RxChan after the lock
// is released, so a slow VirtualConn reader cannot block DrainTx or EnqueueTx.
// Callers must not invoke ProcessRx concurrently for the same session — the
// carrier loop and the exit handler both call it serially.
func (s *Session) ProcessRx(f *frame.Frame) {
	s.mu.Lock()
	if s.rxClosed {
		s.mu.Unlock()
		return
	}
	if f.Seq < s.rxSeq {
		s.mu.Unlock()
		return
	}
	if f.Seq > s.rxSeq {
		s.rxQueue[f.Seq] = f
		s.mu.Unlock()
		return
	}

	var toSend [][]byte
	var closeAfter bool
	for {
		if len(f.Payload) > 0 {
			toSend = append(toSend, f.Payload)
		}
		s.rxSeq++
		if f.HasFlag(frame.FlagFIN) {
			s.rxClosed = true
			closeAfter = true
			break
		}
		next, ok := s.rxQueue[s.rxSeq]
		if !ok {
			break
		}
		delete(s.rxQueue, s.rxSeq)
		f = next
	}
	s.mu.Unlock()

	for _, p := range toSend {
		s.RxChan <- p
	}
	if closeAfter {
		close(s.RxChan)
	}
}

func (s *Session) notifyTxLocked() {
	if s.OnTx != nil {
		// Don't hold the lock for the user callback.
		cb := s.OnTx
		go cb()
	}
}
