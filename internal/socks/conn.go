// Package socks adapts the SOCKS5 server to relay-tunnel sessions.
package socks

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/kianmhz/GooseRelayVPN/internal/session"
)

// VirtualConn fulfills net.Conn by reading from session.RxChan and writing to
// session.EnqueueTx. The SOCKS5 library hands this back to the local SOCKS
// client and treats it as a regular TCP connection.
//
// Ported from FlowDriver/internal/transport/conn.go.
type VirtualConn struct {
	s       *session.Session
	mu      sync.Mutex
	readBuf []byte
}

func NewVirtualConn(s *session.Session) *VirtualConn { return &VirtualConn{s: s} }

func (v *VirtualConn) Read(b []byte) (int, error) {
	for {
		v.mu.Lock()
		if len(v.readBuf) > 0 {
			n := copy(b, v.readBuf)
			v.readBuf = v.readBuf[n:]
			v.mu.Unlock()
			return n, nil
		}
		v.mu.Unlock()

		data, ok := <-v.s.RxChan
		if !ok {
			return 0, io.EOF
		}
		if len(data) == 0 {
			continue
		}
		v.mu.Lock()
		n := copy(b, data)
		if n < len(data) {
			v.readBuf = data[n:]
		}
		v.mu.Unlock()
		return n, nil
	}
}

func (v *VirtualConn) Write(b []byte) (int, error) {
	if len(b) > 0 {
		v.s.EnqueueTx(b)
	}
	return len(b), nil
}

func (v *VirtualConn) Close() error {
	v.s.RequestClose()
	return nil
}

func (v *VirtualConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}
func (v *VirtualConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}
}
func (v *VirtualConn) SetDeadline(t time.Time) error      { return nil }
func (v *VirtualConn) SetReadDeadline(t time.Time) error  { return nil }
func (v *VirtualConn) SetWriteDeadline(t time.Time) error { return nil }
