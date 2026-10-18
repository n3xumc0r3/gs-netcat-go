// v0.1.30: --multi-relay failover.
//
// Parses --multi-relay argument and produces a list of relay endpoints
// to try in order. 'auto' expands to all 26 [a-z].gs.thc.org:443
// production relays (matches RelayHostnameForAddr's derivation).
//
// Examples:
//   --multi-relay v.gs.thc.org:443,c.gs.thc.org:443
//   --multi-relay auto                          # all 26 production relays
//   --multi-relay 127.0.0.1:4433,auto           # local first, then prod
package main

import (
	"fmt"
	"strings"
)

// RelayEndpoint is a single relay host:port pair.
type RelayEndpoint struct {
	Host string
	Port int
}

// multiRelayList is set by main.go when --multi-relay is given. The
// dialer reads this to know which relays to try. Empty means
// --multi-relay was not given; the dialer uses the single
// opts.RelayHost/RelayPort.
var multiRelayList []RelayEndpoint

// parseMultiRelay parses the --multi-relay argument.
//
// Special values:
//   "auto" — expands to all 26 [a-z].gs.thc.org:443
//
// Otherwise: comma-separated list of host:port entries.
func parseMultiRelay(spec string, addr [16]byte) []RelayEndpoint {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil
	}

	// 'auto' expands to all 26 production relays.
	if spec == "auto" {
		out := make([]RelayEndpoint, 0, 26)
		// Place the GS-Address-derived relay FIRST — it's the one
		// the protocol would pick by default, so it's the most likely
		// to have a listener slot for us.
		derived := RelayEndpoint{
			Host: fmt.Sprintf("%c.gs.thc.org", 'a'+sumAddrMod26(addr)),
			Port: 443,
		}
		out = append(out, derived)
		for i := 0; i < 26; i++ {
			h := fmt.Sprintf("%c.gs.thc.org", 'a'+i)
			if h == derived.Host {
				continue
			}
			out = append(out, RelayEndpoint{Host: h, Port: 443})
		}
		return out
	}

	// Comma-separated list.
	parts := strings.Split(spec, ",")
	out := make([]RelayEndpoint, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if p == "auto" {
			// Allow mixing 'auto' with explicit relays.
			out = append(out, parseMultiRelay("auto", addr)...)
			continue
		}
		idx := strings.LastIndex(p, ":")
		if idx < 0 {
			// No port — default 443.
			out = append(out, RelayEndpoint{Host: p, Port: 443})
			continue
		}
		host := p[:idx]
		port := 0
		if _, err := fmt.Sscanf(p[idx+1:], "%d", &port); err != nil || port <= 0 || port > 65535 {
			continue
		}
		out = append(out, RelayEndpoint{Host: host, Port: port})
	}
	return out
}

// sumAddrMod26 returns sum(addr) % 26 — same logic as
// gsconn.RelayHostnameForAddr but inlined here to avoid the import.
func sumAddrMod26(addr [16]byte) int {
	sum := 0
	for _, b := range addr {
		sum += int(b)
	}
	return sum % 26
}

// validateAddr checks that s is a valid host:port string.
func validateAddr(s string) error {
	idx := strings.LastIndex(s, ":")
	if idx < 0 {
		return fmt.Errorf("must be host:port, got %q", s)
	}
	port := 0
	if _, err := fmt.Sscanf(s[idx+1:], "%d", &port); err != nil || port <= 0 || port > 65535 {
		return fmt.Errorf("port invalid in %q", s)
	}
	return nil
}
