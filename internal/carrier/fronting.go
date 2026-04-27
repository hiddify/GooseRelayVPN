// Package carrier implements the client side of the Apps Script transport:
// a long-poll loop that batches outgoing frames, POSTs them through a
// domain-fronted HTTPS connection, and routes the response frames back to
// their sessions.
package carrier

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// FrontingConfig describes how to reach script.google.com without revealing
// the real Host to a passive on-path observer: dial GoogleIP, do a TLS
// handshake with one of the SNIHosts. Go's default behavior of Host = URL.Host
// then routes the request to the right Google backend (and follows the Apps
// Script 302 redirect to script.googleusercontent.com correctly).
//
// Multiple SNIHosts are supported: each creates an independent HTTP client
// with its own connection pool, which maps to a separate TLS SNI value and
// therefore a separate per-domain throttle bucket on the Google CDN. Requests
// are distributed across clients in round-robin order.
type FrontingConfig struct {
	GoogleIP string   // "ip:443"
	SNIHosts []string // e.g. ["www.google.com", "mail.google.com", "accounts.google.com"]
}

// NewFrontedClients returns one *http.Client per SNI host in cfg.SNIHosts.
// Each client has an independent transport/connection-pool so requests to
// different SNI names are genuinely separate TLS sessions, each consuming
// its own throttle bucket.
//
// pollTimeout is the per-request ceiling; it should comfortably exceed the
// server's long-poll window (we use ~25 s).
func NewFrontedClients(cfg FrontingConfig, pollTimeout time.Duration) []*http.Client {
	hosts := cfg.SNIHosts
	if len(hosts) == 0 {
		hosts = []string{"www.google.com"}
	}
	clients := make([]*http.Client, len(hosts))
	for i, sni := range hosts {
		clients[i] = newFrontedClient(cfg.GoogleIP, sni, pollTimeout)
	}
	return clients
}

// newFrontedClient builds a single *http.Client that dials googleIP and
// presents sniHost in the TLS handshake.
func newFrontedClient(googleIP, sniHost string, pollTimeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if googleIP != "" {
				return dialer.DialContext(ctx, "tcp", googleIP)
			}
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig: &tls.Config{
			ServerName: sniHost,
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &http.Client{Transport: transport, Timeout: pollTimeout}
}
