package exit

import (
	"context"
	"net"
	"sync"
	"time"
)

// dnsCacheTTL is how long a successful resolution is reused before re-querying.
// Five minutes balances staleness against resolver round-trips on repeated
// connections to popular targets (CDNs, video hosts) where the same hostname
// is dialed dozens of times in quick succession.
const dnsCacheTTL = 5 * time.Minute

// dnsCache holds recent hostname → IP resolutions to skip the resolver on
// repeated dials to the same target. Goroutine-safe.
type dnsCache struct {
	mu      sync.Mutex
	entries map[string]dnsEntry
}

type dnsEntry struct {
	ip      string
	expires time.Time
}

func newDNSCache() *dnsCache {
	return &dnsCache{entries: make(map[string]dnsEntry)}
}

// get returns a cached IP for host, or "" if missing/expired. Expired entries
// are evicted on access to keep the map small.
func (c *dnsCache) get(host string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[host]
	if !ok {
		return ""
	}
	if time.Now().After(e.expires) {
		delete(c.entries, host)
		return ""
	}
	return e.ip
}

func (c *dnsCache) set(host, ip string) {
	c.mu.Lock()
	c.entries[host] = dnsEntry{ip: ip, expires: time.Now().Add(dnsCacheTTL)}
	c.mu.Unlock()
}

func (c *dnsCache) forget(host string) {
	c.mu.Lock()
	delete(c.entries, host)
	c.mu.Unlock()
}

// dialWithDNSCache resolves host:port through the cache, then dials the
// underlying TCP connection via baseDial. Falls through to baseDial directly
// when the address is already a literal IP or unparseable.
func dialWithDNSCache(
	cache *dnsCache,
	baseDial func(network, address string, timeout time.Duration) (net.Conn, error),
	network, address string,
	timeout time.Duration,
) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || net.ParseIP(host) != nil {
		// Literal IP or malformed — let baseDial handle it.
		return baseDial(network, address, timeout)
	}
	if ip := cache.get(host); ip != "" {
		conn, err := baseDial(network, net.JoinHostPort(ip, port), timeout)
		if err != nil {
			// Cached IP failed; evict so the next call re-resolves.
			cache.forget(host)
			return nil, err
		}
		return conn, nil
	}
	// Cache miss: resolve, then dial. Use a context bounded by `timeout`
	// so a slow resolver cannot eat the entire dial budget.
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	addrs, lerr := net.DefaultResolver.LookupIPAddr(ctx, host)
	if lerr != nil || len(addrs) == 0 {
		// Fall through to baseDial which will surface the same/similar error.
		return baseDial(network, address, timeout)
	}
	ip := addrs[0].IP.String()
	cache.set(host, ip)
	return baseDial(network, net.JoinHostPort(ip, port), timeout)
}
