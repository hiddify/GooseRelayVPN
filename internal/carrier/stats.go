package carrier

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"
)

// statsInterval is how often the periodic stats line is logged. Long enough
// to be unobtrusive, short enough to spot trends within a single session.
const statsInterval = 60 * time.Second

// runStatsLoop periodically emits a one-line summary of carrier health so a
// developer can spot drift (rising RST count, blacklisted endpoints, etc.)
// without grepping for individual events. Returns when ctx is canceled.
func (c *Client) runStatsLoop(ctx context.Context) {
	t := time.NewTicker(statsInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c.logStats()
		}
	}
}

func (c *Client) logStats() {
	c.mu.Lock()
	active := len(c.sessions)
	c.mu.Unlock()

	healthy, total := c.endpointHealthCounts()
	endpointDetail := c.endpointStatsLine()

	log.Printf("[stats] active=%d sessions(open=%d close=%d) frames(out=%d in=%d) bytes(out=%s in=%s) polls(ok=%d fail=%d) rst=%d endpoints=%d/%d_healthy endpoints=[%s]",
		active,
		c.stats.sessionsOpen.Load(), c.stats.sessionsClose.Load(),
		c.stats.framesOut.Load(), c.stats.framesIn.Load(),
		humanBytes(c.stats.bytesOut.Load()), humanBytes(c.stats.bytesIn.Load()),
		c.stats.pollsOK.Load(), c.stats.pollsFail.Load(),
		c.stats.rstFromServer.Load(),
		healthy, total,
		endpointDetail,
	)
}

func (c *Client) endpointHealthCounts() (healthy, total int) {
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	now := time.Now()
	total = len(c.endpoints)
	for _, ep := range c.endpoints {
		if !ep.blacklistedTill.After(now) {
			healthy++
		}
	}
	return
}

func (c *Client) endpointStatsLine() string {
	c.endpointMu.Lock()
	defer c.endpointMu.Unlock()
	if len(c.endpoints) == 0 {
		return "none"
	}
	now := time.Now()
	parts := make([]string, 0, len(c.endpoints))
	for _, ep := range c.endpoints {
		part := fmt.Sprintf("%s ok=%d fail=%d", shortScriptKey(ep.url), ep.statsOK, ep.statsFail)
		if ep.blacklistedTill.After(now) {
			remaining := time.Until(ep.blacklistedTill).Round(time.Second)
			part = fmt.Sprintf("%s bl=%s", part, remaining)
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, " | ")
}

// humanBytes formats a byte count as a short human-readable string. Used for
// stats lines that an operator scans visually.
func humanBytes(n uint64) string {
	const k = 1024
	switch {
	case n < k:
		return fmt.Sprintf("%dB", n)
	case n < k*k:
		return fmt.Sprintf("%.1fKB", float64(n)/float64(k))
	case n < k*k*k:
		return fmt.Sprintf("%.1fMB", float64(n)/float64(k*k))
	default:
		return fmt.Sprintf("%.2fGB", float64(n)/float64(k*k*k))
	}
}
