// Package goose is the public SDK surface of GooseRelayVPN's client side.
//
// External Go modules cannot import internal/* across module boundaries, so
// this package — living inside the same module — re-exports just enough of
// the carrier and session machinery for embedders (e.g. sing-box outbounds)
// to construct, run, and dial through the carrier without touching internal/.
//
// The intent is a minimal, stable surface: type aliases for configuration
// structs (so JSON decoding still works against the carrier's tags), a thin
// Client wrapper, and a Dial helper that returns a net.Conn-compatible
// session. Everything else stays internal.
package goose

import (
	"context"
	"net"

	"github.com/kianmhz/GooseRelayVPN/internal/carrier"
	"github.com/kianmhz/GooseRelayVPN/internal/socks"
)

// Config and FrontingConfig are aliased so callers can construct them without
// importing internal/. JSON tags and field semantics are inherited unchanged.
type (
	Config         = carrier.Config
	FrontingConfig = carrier.FrontingConfig
)

// Client is the SDK-facing carrier client.
type Client struct {
	inner *carrier.Client
}

// New constructs a Client. Validation of cfg (script URLs, AES key) is
// delegated to the underlying carrier.
func New(cfg Config) (*Client, error) {
	inner, err := carrier.New(cfg)
	if err != nil {
		return nil, err
	}
	return &Client{inner: inner}, nil
}

// Run drives the long-poll loop and blocks until ctx is canceled.
func (c *Client) Run(ctx context.Context) error {
	return c.inner.Run(ctx)
}

// Diagnose performs a one-shot reachability + decryption probe against the
// first configured endpoint and returns a user-actionable error on failure.
func (c *Client) Diagnose(ctx context.Context) error {
	return c.inner.Diagnose(ctx)
}

// Shutdown sends RST frames for any active sessions, best-effort, so the
// server can release upstream connections without waiting for idle GC.
// Safe to call before canceling the Run context.
func (c *Client) Shutdown(ctx context.Context) {
	c.inner.Shutdown(ctx)
}

// Dial opens a tunneled session for target ("host:port") and returns it as a
// net.Conn. Read/Write proxy through the carrier's frame machinery.
func (c *Client) Dial(target string) net.Conn {
	return socks.NewVirtualConn(c.inner.NewSession(target))
}
