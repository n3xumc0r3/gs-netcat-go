// v0.3.2: DNS-over-HTTPS (DoH) resolver (--doh flag).
//
// Resolves relay hostnames via DoH instead of the system DNS resolver.
// This bypasses DNS-level blocking where the system resolver returns
// NXDOMAIN for *.gs.thc.org or similar censorship.
//
// How it works:
//   1. User passes --doh cloudflare (or --doh google, or --doh https://...)
//   2. When gsrn.Dial needs to resolve the relay hostname, it calls
//      our DoH resolver instead of net.DialTimeout (which uses system DNS)
//   3. DoH resolver sends an HTTPS GET to the DoH server's URL
//      (e.g., https://1.1.1.1/dns-query?name=v.gs.thc.org&type=A)
//   4. The response is JSON with the resolved IP
//   5. We connect directly to that IP, bypassing system DNS entirely
//
// DPI visibility:
//   - UDP 53 (standard DNS): NO traffic — DPI sees nothing
//   - HTTPS 443 to DoH server: looks like normal HTTPS traffic
//   - If DPI blocks DoH server domain (cloudflare-dns.com), use IP-based
//     URLs (https://1.1.1.1/dns-query) which can't be blocked by domain
//
// Wire compat: [--] local-only; the relay sees the same TCP connection
// regardless of how we resolved its IP.
//
// Usage:
//   ./gs-netcat -l -i -s S --doh cloudflare
//   ./gs-netcat -i -s S --doh google
//   ./gs-netcat -i -s S --doh https://my-doh.example/dns-query
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// dohProvider is the DoH server URL to use for DNS resolution.
// Empty = use system DNS (default). Non-empty = use DoH.
var dohProvider string

// dohCache caches resolved hostnames to avoid repeated DoH queries.
// Key: hostname, Value: IP string.
var dohCache = map[string]string{}

// Predefined DoH providers (use IP-based URLs to avoid domain blocking).
var dohProviders = map[string]string{
	"cloudflare": "https://1.1.1.1/dns-query",
	"google":     "https://8.8.8.8/resolve",
	"quad9":      "https://9.9.9.9/dns-query",
	"opendns":    "https://208.67.222.222/dns-query",
	"adguard":    "https://94.140.14.14/dns-query",
}

// resolveDoH resolves a hostname via DNS-over-HTTPS.
// Returns the first A record IP, or an error.
//
// Uses the DoH JSON API (RFC 8484 alternative — Cloudflare/Google/Quad9
// all support the JSON format for ease of use).
func resolveDoH(hostname, dohURL string) (string, error) {
	// Check cache first.
	if ip, ok := dohCache[hostname]; ok {
		return ip, nil
	}

	// Build the DoH query URL.
	// Cloudflare/Quad9 use: /dns-query?name=HOST&type=A
	// Google uses: /resolve?name=HOST&type=A
	// Both accept the same JSON response format.
	params := url.Values{}
	params.Set("name", hostname)
	params.Set("type", "A")

	fullURL := dohURL + "?" + params.Encode()

	// Create HTTP client with short timeout.
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest("GET", fullURL, nil)
	if err != nil {
		return "", fmt.Errorf("doh: create request: %w", err)
	}
	// DoH JSON API requires this Accept header.
	req.Header.Set("Accept", "application/dns-json")
	// Set a User-Agent to look like a normal browser (not suspicious).
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("doh: request to %s: %w", dohURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("doh: %s returned HTTP %d", dohURL, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("doh: read response: %w", err)
	}

	// Parse JSON response.
	// Format (Cloudflare/Google/Quad9):
	//   {
	//     "Status": 0,
	//     "Answer": [
	//       {"name": "v.gs.thc.org", "type": 1, "TTL": 300, "data": "152.53.173.29"}
	//     ]
	//   }
	var dohResp struct {
		Status int    `json:"Status"`
		Answer []struct {
			Name string `json:"name"`
			Type int    `json:"type"`
			TTL  int    `json:"TTL"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if err := json.Unmarshal(body, &dohResp); err != nil {
		return "", fmt.Errorf("doh: parse JSON: %w (body: %s)", err, string(body[:min(len(body), 200)]))
	}

	if dohResp.Status != 0 {
		return "", fmt.Errorf("doh: DNS status %d (NXDOMAIN or error)", dohResp.Status)
	}

	// Find the first A record (type 1).
	for _, ans := range dohResp.Answer {
		if ans.Type == 1 { // A record
			// Cache the result.
			dohCache[hostname] = ans.Data
			return ans.Data, nil
		}
	}

	return "", fmt.Errorf("doh: no A record found for %s", hostname)
}

// resolveHostname resolves a hostname to an IP address.
// If dohProvider is set, uses DoH. Otherwise returns the hostname as-is
// (letting net.Dial use system DNS).
func resolveHostname(hostname string) (string, error) {
	// If no DoH provider, return hostname as-is (system DNS will resolve it).
	if dohProvider == "" {
		return hostname, nil
	}

	// If hostname is already an IP, no resolution needed.
	if isIPAddress(hostname) {
		return hostname, nil
	}

	// Resolve via DoH.
	dohURL := dohProvider
	// Check if it's a named provider (cloudflare, google, etc.).
	if url, ok := dohProviders[strings.ToLower(dohProvider)]; ok {
		dohURL = url
	}

	ip, err := resolveDoH(hostname, dohURL)
	if err != nil {
		return "", fmt.Errorf("doh: resolve %s: %w", hostname, err)
	}
	return ip, nil
}

// isIPAddress reports whether s looks like an IP address (v4 or v6).
func isIPAddress(s string) bool {
	// Simple check: if it contains only digits and dots, it's probably IPv4.
	// If it contains colons, it's probably IPv6.
	// A more robust check would use net.ParseIP, but we avoid importing net
	// here to keep the DoH module self-contained.
	if strings.Contains(s, ":") {
		return true // IPv6
	}
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// min returns the smaller of a and b.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
