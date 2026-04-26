package carrier

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/kianmhz/relay-tunnel/internal/frame"
	"github.com/kianmhz/relay-tunnel/internal/session"
)

const (
	// MaxFramePayload caps the bytes per frame; larger writes are chunked.
	// Kept small so a single Apps Script POST stays well under any limit.
	MaxFramePayload = 128 * 1024

	// pollIdleSleep is the breather between polls when nothing is happening,
	// to avoid busy-looping if the server returns instantly with empty bodies.
	pollIdleSleep = 50 * time.Millisecond

	// pollTimeout is the per-request HTTP ceiling; should comfortably exceed
	// the server's long-poll window (~25s).
	pollTimeout = 60 * time.Second
)

// Config bundles everything the carrier needs to talk to the relay.
type Config struct {
	ScriptURL string // full https://script.google.com/macros/s/.../exec URL
	Fronting  FrontingConfig
	AESKeyHex string // 64-char hex, must match server
}

// Client owns the session map and the long-poll loop.
type Client struct {
	cfg  Config
	aead *frame.Crypto
	http *http.Client

	mu       sync.Mutex
	sessions map[[frame.SessionIDLen]byte]*session.Session

	kickCh chan struct{} // buffered len 1; coalesces OnTx wake-ups
}

// New constructs a Client. The HTTP client is preconfigured for domain
// fronting per cfg.Fronting.
func New(cfg Config) (*Client, error) {
	aead, err := frame.NewCryptoFromHexKey(cfg.AESKeyHex)
	if err != nil {
		return nil, err
	}
	return &Client{
		cfg:      cfg,
		aead:     aead,
		http:     NewFrontedClient(cfg.Fronting, pollTimeout),
		sessions: make(map[[frame.SessionIDLen]byte]*session.Session),
		kickCh:   make(chan struct{}, 1),
	}, nil
}

// NewSession creates a tunneled session for target ("host:port") and registers
// it with the long-poll loop. Returns the session for the caller (typically
// the SOCKS adapter) to wrap in a VirtualConn.
func (c *Client) NewSession(target string) *session.Session {
	var id [frame.SessionIDLen]byte
	if _, err := rand.Read(id[:]); err != nil {
		// crypto/rand failure is unrecoverable; panic so the process exits
		// rather than emitting an all-zero ID.
		panic(fmt.Errorf("crypto/rand: %w", err))
	}
	s := session.New(id, target, true)
	s.OnTx = c.kick
	c.mu.Lock()
	c.sessions[id] = s
	c.mu.Unlock()
	c.kick()
	return s
}

// Run drives the poll loop until ctx is canceled.
func (c *Client) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		didWork := c.pollOnce(ctx)
		c.gcDoneSessions()
		if !didWork {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-c.kickCh:
				// woken by EnqueueTx
			case <-time.After(pollIdleSleep):
			}
		}
	}
}

// pollOnce drains pending tx frames, POSTs them as a batch, and routes any
// response frames back to their sessions. Returns true if any work was done
// (frames sent or received) so the Run loop can decide whether to sleep.
func (c *Client) pollOnce(ctx context.Context) bool {
	frames := c.drainAll()

	body, err := frame.EncodeBatch(c.aead, frames)
	if err != nil {
		log.Printf("[carrier] failed to prepare encrypted request batch: %v", err)
		return false
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.ScriptURL, bytes.NewReader(body))
	if err != nil {
		log.Printf("[carrier] failed to build relay request: %v", err)
		return false
	}
	req.Header.Set("Content-Type", "text/plain")

	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() == nil {
			log.Printf("[carrier] relay request failed: %v (check internet access, script_key, and google_host)", err)
			time.Sleep(time.Second) // back off on transport errors
		}
		return false
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[carrier] failed to read relay response: %v", err)
		return false
	}

	if resp.StatusCode == http.StatusNoContent || len(respBody) == 0 {
		return len(frames) > 0
	}
	if resp.StatusCode != http.StatusOK {
		log.Printf("[carrier] relay returned HTTP %d (verify Apps Script deployment is live and access is set to Anyone)", resp.StatusCode)
		return false
	}

	rxFrames, err := frame.DecodeBatch(c.aead, respBody)
	if err != nil {
		log.Printf("[carrier] relay response was invalid (possibly HTML/error page instead of encrypted data): %v", err)
		return len(frames) > 0
	}

	for _, f := range rxFrames {
		c.routeRx(f)
	}
	return len(frames) > 0 || len(rxFrames) > 0
}

func (c *Client) drainAll() []*frame.Frame {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []*frame.Frame
	for _, s := range c.sessions {
		out = append(out, s.DrainTx(MaxFramePayload)...)
	}
	return out
}

func (c *Client) routeRx(f *frame.Frame) {
	c.mu.Lock()
	s, ok := c.sessions[f.SessionID]
	c.mu.Unlock()
	if !ok {
		return // unknown session — drop
	}
	s.ProcessRx(f)
}

func (c *Client) gcDoneSessions() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for id, s := range c.sessions {
		if s.IsDone() {
			delete(c.sessions, id)
		}
	}
}

// kick wakes the poll loop. Safe to call from any goroutine; coalesces.
func (c *Client) kick() {
	select {
	case c.kickCh <- struct{}{}:
	default:
	}
}
