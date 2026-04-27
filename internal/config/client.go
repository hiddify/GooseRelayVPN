// Package config defines the JSON config structures for the client and server
// binaries.
package config

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Client is the relay-tunnel client config.
type Client struct {
	ListenAddr  string
	GoogleIP    string   // "ip:port"; empty when direct relay_urls mode is used
	SNIHost     string   // e.g. "www.google.com"; empty when direct relay_urls mode is used
	ScriptURLs  []string // one or more relay endpoints (Apps Script URLs or direct relay_urls)
	UseFronting bool
	AESKeyHex   string // 64-char hex
}

// clientFile is the user-friendly client config format.
type clientFile struct {
	// Local SOCKS listener.
	SocksHost string `json:"socks_host"`
	SocksPort int    `json:"socks_port"`

	// Google front endpoint.
	GoogleHost string `json:"google_host"`

	// TLS SNI.
	SNI string `json:"sni"`

	// Apps Script Deployment IDs (one or more).
	ScriptKeys []string `json:"script_keys"`

	// Optional direct relay endpoints for local/integration testing.
	// When set, these URLs are used as-is and Google fronting is disabled.
	RelayURLs []string `json:"relay_urls"`

	// Shared AES key (64-char hex).
	TunnelKey string `json:"tunnel_key"`
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" {
			return v
		}
	}
	return ""
}

func firstPositive(values ...int) int {
	for _, v := range values {
		if v > 0 {
			return v
		}
	}
	return 0
}

func normalizeDeploymentID(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	// Accept plain deployment key and tolerate pasting the full /exec URL.
	v = strings.TrimSuffix(v, "/exec")
	v = strings.Trim(v, "/")
	parts := strings.Split(v, "/")
	if len(parts) >= 2 {
		for i := 0; i < len(parts)-1; i++ {
			if parts[i] == "s" {
				return parts[i+1]
			}
		}
	}
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return v
}

func buildScriptURL(deploymentID string) string {
	return fmt.Sprintf("https://script.google.com/macros/s/%s/exec", deploymentID)
}

func dedupeStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func normalizeRelayURL(v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", nil
	}
	u, err := url.Parse(v)
	if err != nil {
		return "", fmt.Errorf("invalid relay_urls value %q: %w", v, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("invalid relay_urls value %q: scheme must be http or https", v)
	}
	if strings.TrimSpace(u.Host) == "" {
		return "", fmt.Errorf("invalid relay_urls value %q: host is required", v)
	}
	return u.String(), nil
}

// LoadClient reads and validates a client config file.
func LoadClient(path string) (*Client, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}

	var f clientFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}

	listenHost := firstNonEmpty(f.SocksHost, "127.0.0.1")
	listenPort := firstPositive(f.SocksPort)
	if listenPort == 0 {
		listenPort = 1080
	}
	if listenPort < 1 || listenPort > 65535 {
		return nil, fmt.Errorf("config: socks_port out of range (got %d)", listenPort)
	}

	relayURLs := make([]string, 0, len(f.RelayURLs))
	for _, raw := range f.RelayURLs {
		normalized, nerr := normalizeRelayURL(raw)
		if nerr != nil {
			return nil, fmt.Errorf("config: %w", nerr)
		}
		if normalized != "" {
			relayURLs = append(relayURLs, normalized)
		}
	}
	relayURLs = dedupeStrings(relayURLs)

	key := strings.TrimSpace(f.TunnelKey)
	if len(key) != 64 {
		return nil, fmt.Errorf("config: tunnel_key must be 64 hex chars (got %d)", len(key))
	}
	raw, err := hex.DecodeString(key)
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("config: tunnel_key must be valid 64-char hex AES-256 key")
	}

	useFronting := len(relayURLs) == 0
	scriptURLs := relayURLs
	googleIP := ""
	sniHost := ""

	if useFronting {
		googleHost := firstNonEmpty(f.GoogleHost, "216.239.38.120")
		googlePort := 443
		googleIP = net.JoinHostPort(googleHost, strconv.Itoa(googlePort))
		sniHost = firstNonEmpty(f.SNI, "www.google.com")

		deploymentIDs := make([]string, 0, len(f.ScriptKeys))
		for _, raw := range f.ScriptKeys {
			if deploymentID := normalizeDeploymentID(raw); deploymentID != "" {
				deploymentIDs = append(deploymentIDs, deploymentID)
			}
		}
		deploymentIDs = dedupeStrings(deploymentIDs)
		if len(deploymentIDs) == 0 {
			return nil, fmt.Errorf("config: either relay_urls or script_keys is required")
		}

		scriptURLs = make([]string, 0, len(deploymentIDs))
		for _, deploymentID := range deploymentIDs {
			scriptURLs = append(scriptURLs, buildScriptURL(deploymentID))
		}
	}

	c := Client{
		ListenAddr:  net.JoinHostPort(listenHost, strconv.Itoa(listenPort)),
		GoogleIP:    googleIP,
		SNIHost:     sniHost,
		ScriptURLs:  scriptURLs,
		UseFronting: useFronting,
		AESKeyHex:   key,
	}
	return &c, nil
}
