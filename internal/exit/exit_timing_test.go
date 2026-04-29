package exit

import (
	"bytes"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"
	"time"

	"github.com/kianmhz/GooseRelayVPN/internal/frame"
	"github.com/kianmhz/GooseRelayVPN/internal/session"
)

const exitTimingTestKeyHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func mustExitTimingServer(tb testing.TB) *Server {
	tb.Helper()
	s, err := New(Config{ListenAddr: "127.0.0.1:0", AESKeyHex: exitTimingTestKeyHex})
	if err != nil {
		tb.Fatalf("new server: %v", err)
	}
	return s
}

func mustExitTimingCrypto(tb testing.TB) *frame.Crypto {
	tb.Helper()
	c, err := frame.NewCryptoFromHexKey(exitTimingTestKeyHex)
	if err != nil {
		tb.Fatalf("new crypto: %v", err)
	}
	return c
}

func invokeExitTunnel(tb testing.TB, s *Server, c *frame.Crypto, frames []*frame.Frame) time.Duration {
	tb.Helper()
	body, err := frame.EncodeBatch(c, frames)
	if err != nil {
		tb.Fatalf("encode request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/tunnel", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	t0 := time.Now()
	s.handleTunnel(rec, req)
	resp := rec.Result()
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return time.Since(t0)
}

func startSilentServer(tb testing.TB) (string, func()) {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(io.Discard, c)
			}(conn)
		}
	}()
	return ln.Addr().String(), func() {
		_ = ln.Close()
		<-done
	}
}

func TestExitDrainWindow_EmptyPollUsesLongWindow(t *testing.T) {
	s := mustExitTimingServer(t)
	c := mustExitTimingCrypto(t)
	elapsed := invokeExitTunnel(t, s, c, nil)
	if elapsed < LongPollWindow-500*time.Millisecond {
		t.Fatalf("empty poll returned too quickly: %v", elapsed)
	}
}

func TestExitDrainWindow_ActiveBatchUsesShortWindow(t *testing.T) {
	s := mustExitTimingServer(t)
	c := mustExitTimingCrypto(t)
	target, closeFn := startSilentServer(t)
	defer closeFn()
	elapsed := invokeExitTunnel(t, s, c, []*frame.Frame{{
		SessionID: [frame.SessionIDLen]byte{1},
		Seq:       0,
		Flags:     frame.FlagSYN,
		Target:    target,
		Payload:   []byte("PING"),
	}})
	if elapsed > ActiveDrainWindow+350*time.Millisecond {
		t.Fatalf("active batch waited too long: %v", elapsed)
	}
}

func BenchmarkExitActiveSilent(b *testing.B) {
	s := mustExitTimingServer(b)
	c := mustExitTimingCrypto(b)
	target, closeFn := startSilentServer(b)
	defer closeFn()
	frames := []*frame.Frame{{
		SessionID: [frame.SessionIDLen]byte{2},
		Seq:       0,
		Flags:     frame.FlagSYN,
		Target:    target,
		Payload:   []byte("GET / HTTP/1.0\r\n\r\n"),
	}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = invokeExitTunnel(b, s, c, frames)
	}
}

func TestIsBackoffEligibleDialErr(t *testing.T) {
	if !isBackoffEligibleDialErr(&net.OpError{Err: syscall.ECONNREFUSED}) {
		t.Fatal("expected ECONNREFUSED to be backoff-eligible")
	}
	if !isBackoffEligibleDialErr(&net.DNSError{IsNotFound: true}) {
		t.Fatal("expected DNS not found to be backoff-eligible")
	}
	if isBackoffEligibleDialErr(errors.New("some other error")) {
		t.Fatal("unexpected generic error to be backoff-eligible")
	}
}

func TestDialSuppressionExpiry(t *testing.T) {
	s := mustExitTimingServer(t)
	target := "127.0.0.1:1"
	s.recordDialFailure(target, &net.OpError{Err: syscall.ECONNREFUSED})
	if !s.isDialSuppressed(target) {
		t.Fatal("expected target to be dial-suppressed")
	}

	s.mu.Lock()
	s.dialFail[target] = time.Now().Add(-time.Millisecond)
	s.mu.Unlock()
	if s.isDialSuppressed(target) {
		t.Fatal("expected expired suppression to clear")
	}

	s.mu.Lock()
	_, exists := s.dialFail[target]
	s.mu.Unlock()
	if exists {
		t.Fatal("expected expired target entry to be deleted")
	}
}

func TestDrainAll_RespectsBatchFrameCap(t *testing.T) {
	t.Run("normal_cap", func(t *testing.T) {
		s := mustExitTimingServer(t)
		total := busySessionThreshold - 1
		if total <= 0 {
			total = 1
		}
		for i := 0; i < total; i++ {
			id := benchSessionID(i + 100)
			sess := session.New(id, "x:1", false)
			sess.EnqueueTx([]byte("x"))
			s.sessions[id] = sess
			s.txReady[id] = struct{}{}
		}
		frames, _ := s.drainAll()
		expected := total
		if expected > maxDrainFramesPerBatch {
			expected = maxDrainFramesPerBatch
		}
		if len(frames) != expected {
			t.Fatalf("expected %d frames, got %d", expected, len(frames))
		}
	})

	t.Run("busy_cap", func(t *testing.T) {
		s := mustExitTimingServer(t)
		total := maxDrainFramesPerBatchBusy * 2
		if total < busySessionThreshold+1 {
			total = busySessionThreshold + 1
		}
		for i := 0; i < total; i++ {
			id := benchSessionID(i + 500)
			sess := session.New(id, "x:1", false)
			sess.EnqueueTx([]byte("x"))
			s.sessions[id] = sess
			s.txReady[id] = struct{}{}
		}
		frames, _ := s.drainAll()
		if len(frames) != maxDrainFramesPerBatchBusy {
			t.Fatalf("expected busy cap %d frames, got %d", maxDrainFramesPerBatchBusy, len(frames))
		}
	})
}

func BenchmarkExitDialFailureBackoffComparison(b *testing.B) {
	target := "bench.invalid:443"
	muteLogsForBench(b)
	const burnCycles = 2048

	b.Run("before_no_backoff", func(b *testing.B) {
		s := mustExitTimingServer(b)
		dialCalls := 0
		s.dial = func(_, _ string, _ time.Duration) (net.Conn, error) {
			dialCalls++
			burnCPU(burnCycles)
			return nil, &net.OpError{Err: syscall.ECONNREFUSED}
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			f := &frame.Frame{
				SessionID: benchSessionID(i + 1),
				Flags:     frame.FlagSYN,
				Target:    target,
			}
			routeIncomingNoBackoff(s, f)
		}
		b.ReportMetric(float64(dialCalls)/float64(b.N), "dials/op")
	})

	b.Run("after_with_backoff", func(b *testing.B) {
		s := mustExitTimingServer(b)
		dialCalls := 0
		s.dial = func(_, _ string, _ time.Duration) (net.Conn, error) {
			dialCalls++
			burnCPU(burnCycles)
			return nil, &net.OpError{Err: syscall.ECONNREFUSED}
		}
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			f := &frame.Frame{
				SessionID: benchSessionID(i + 1),
				Flags:     frame.FlagSYN,
				Target:    target,
			}
			s.routeIncoming(f)
		}
		b.ReportMetric(float64(dialCalls)/float64(b.N), "dials/op")
	})
}

func burnCPU(cycles int) {
	x := 0
	for i := 0; i < cycles; i++ {
		x += i
	}
	if x == -1 {
		panic("unreachable")
	}
}

func routeIncomingNoBackoff(s *Server, f *frame.Frame) {
	s.mu.Lock()
	sess, exists := s.sessions[f.SessionID]
	s.mu.Unlock()

	if !exists {
		if !f.HasFlag(frame.FlagSYN) {
			return
		}
		var err error
		sess, err = s.openSession(f.SessionID, f.Target)
		if err != nil {
			return
		}
	}
	sess.ProcessRx(f)
}

func benchSessionID(n int) [frame.SessionIDLen]byte {
	var id [frame.SessionIDLen]byte
	u := uint64(n)
	for i := 0; i < frame.SessionIDLen; i++ {
		id[i] = byte(u >> (8 * i))
	}
	return id
}

func muteLogsForBench(tb testing.TB) {
	tb.Helper()
	prev := log.Writer()
	log.SetOutput(io.Discard)
	tb.Cleanup(func() {
		log.SetOutput(prev)
	})
}
