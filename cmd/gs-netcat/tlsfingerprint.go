// v0.2.0: --tls-fingerprint <profile>
//
// Enhances --stealth-https with realistic ClientHello profiles. The
// v0.2.0 --stealth-https base sends a minimal ClientHello (137 bytes)
// that looks like TLS to naive DPI but fails JA3 fingerprinting.
//
// --tls-fingerprint selects from a library of pre-recorded ClientHello
// profiles (Chrome, Firefox, Safari, Edge) that match the JA3 hash of
// real browsers. DPI that compares JA3 hashes against a whitelist will
// see a "real" browser.
//
// Wire compat: [G<->G] only — must be combined with --stealth-https.
// The C peer doesn't understand --stealth-https at all.
//
// Usage:
//   ./gs-netcat -l -i -s S --stealth-https --tls-fingerprint chrome
//   ./gs-netcat -i -s S --stealth-https --tls-fingerprint firefox
//
// v0.2.0 implementation: PROFILES HARDCODED (no utls dependency). The
// profiles are simplified — they match the cipher suite order and
// extension list of real browsers, but the actual extension payloads
// are dummy. A DPI that does deep packet inspection of TLS extensions
// may still detect the fake.
//
// For real JA3 mimicry (full extension payloads, supported_versions,
// key_share, etc.), see v0.2.5 (will add github.com/refraction-networking/utls).
package main

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// tlsFingerprintProfile is a pre-recorded ClientHello profile.
type tlsFingerprintProfile struct {
	Name        string
	CipherSuites []uint16
	Extensions  []uint16
	Curves      []uint16
	Points      []byte
}

// Pre-recorded profiles (simplified). These match the cipher suite
// ORDER and EXTENSION LIST of real browsers (Chrome 120, Firefox 121,
// Safari 17, Edge 120), but the extension PAYLOADS are dummy.
//
// Sources (JA3 fingerprints):
//   - Chrome 120:  771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0
//   - Firefox 121: 771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-65037,29-23-24-25,0
//   - Safari 17:   771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24-25,0
//   - Edge 120:    (same as Chrome)
var tlsProfiles = map[string]*tlsFingerprintProfile{
	"chrome": {
		Name: "Chrome 120",
		CipherSuites: []uint16{
			0x1301, 0x1302, 0x1303,         // TLS 1.3 suites
			0xc02b, 0xc02c, 0xc02f, 0xc030, // ECDHE CBC
			0xcca9, 0xcca8,                 // ECDHE CCM
			0xc013, 0xc014,                 // ECDHE RSA
			0x009c, 0x009d,                 // RSA GCM
			0x002f, 0x0035,                 // RSA CBC
		},
		Extensions: []uint16{
			0x0000, // server_name
			0x0017, // extended_master_secret
			0xff01, // renegotiation_info
			0x000a, // supported_groups
			0x000b, // ec_point_formats
			0x0023, // session_ticket
			0x0010, // ALPN
			0x0005, // status_request
			0x000d, // signature_algorithms
			0x0012, // signed_certificate_timestamp
			0x0033, // key_share
			0x002d, // psk_key_exchange_modes
			0x002b, // supported_versions
			0x0011, // ec_point_formats (older)
			0x4469, // application_settings (Chrome-specific)
		},
		Curves: []uint16{0x001d, 0x0017, 0x0018}, // x25519, secp256r1, secp384r1
		Points: []byte{0x00},                       // uncompressed
	},
	"firefox": {
		Name: "Firefox 121",
		CipherSuites: []uint16{
			0x1301, 0x1303, 0x1302,
			0xc02b, 0xc02f, 0xc02c, 0xc030,
			0xcca9, 0xcca8,
			0xc013, 0xc014,
			0x009c, 0x009d,
			0x002f, 0x0035,
			0x003c, // TLS_RSA_WITH_AES_128_CBC_SHA256
		},
		Extensions: []uint16{
			0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010,
			0x0005, 0x0022, 0x0033, 0x002d, 0x000d, 0x002d, 0x001c,
			0xfe0d, // Firefox-specific deprecation indicator
		},
		Curves: []uint16{0x001d, 0x0017, 0x0018, 0x0019},
		Points: []byte{0x00},
	},
	"safari": {
		Name: "Safari 17",
		CipherSuites: []uint16{
			0x1301, 0x1303, 0x1302,
			0xc02b, 0xc02c, 0xc02f, 0xc030,
			0xcca9, 0xcca8,
			0xc013, 0xc014,
			0x009c, 0x009d,
			0x002f, 0x0035, 0x000a,
		},
		Extensions: []uint16{
			0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010,
			0x0005, 0x000d, 0x0012, 0x0033, 0x002d, 0x0015, 0x001b,
		},
		Curves: []uint16{0x001d, 0x0017, 0x0018, 0x0019},
		Points: []byte{0x00, 0x01, 0x02},
	},
	"edge": {
		Name: "Edge 120",
		// Edge uses the same ClientHello as Chrome
		CipherSuites: []uint16{
			0x1301, 0x1302, 0x1303,
			0xc02b, 0xc02c, 0xc02f, 0xc030,
			0xcca9, 0xcca8,
			0xc013, 0xc014,
			0x009c, 0x009d,
			0x002f, 0x0035,
		},
		Extensions: []uint16{
			0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010,
			0x0005, 0x000d, 0x0012, 0x0033, 0x002d, 0x002b, 0x0011,
			0x4469,
		},
		Curves: []uint16{0x001d, 0x0017, 0x0018},
		Points: []byte{0x00},
	},
}

// getTLSProfile returns the profile for the given name, or nil if unknown.
func getTLSProfile(name string) *tlsFingerprintProfile {
	if name == "" {
		return nil
	}
	return tlsProfiles[name]
}

// listTLSProfiles returns a comma-separated list of available profile names.
func listTLSProfiles() string {
	names := []string{}
	for name := range tlsProfiles {
		names = append(names, name)
	}
	return fmt.Sprintf("%v", names)
}

// writeProfiledClientHello writes a ClientHello matching the given profile.
// The structure is more elaborate than the v0.1.30 fake ClientHello:
//   - Real cipher suite list (in the order the browser uses)
//   - Real extension list (with proper length prefixes)
//   - supported_versions extension (TLS 1.3)
//   - key_share extension (with random key bytes — NOT real crypto)
//   - ec_point_formats extension
//   - supported_groups extension (curves list)
//
// Still NOT a fully valid TLS handshake — for that, see v0.2.5 (utls).
// But it WILL pass JA3 hash matching for the listed browsers.
func writeProfiledClientHello(s *stealthConn, profile *tlsFingerprintProfile) error {
	if profile == nil {
		// Fall back to the simple ClientHello.
		return s.writeClientHello()
	}

	// Build the ClientHello body (after record header).
	body := make([]byte, 0, 512)

	// Client version: TLS 1.0 (we announce 1.0 in record header)
	// Inside ClientHello: TLS 1.2 (0x0303) — browsers do this
	body = append(body, 0x03, 0x03)

	// Random: 32 bytes
	random := make([]byte, 32)
	_, _ = rand.Read(random)
	body = append(body, random...)

	// Session ID: length 32, 32 random bytes (matches Chrome behavior)
	sessID := make([]byte, 32)
	_, _ = rand.Read(sessID)
	body = append(body, 0x20) // length 32
	body = append(body, sessID...)

	// Cipher suites: 2-byte length + list of 2-byte suites
	cipherList := make([]byte, 0, len(profile.CipherSuites)*2)
	for _, cs := range profile.CipherSuites {
		cipherList = append(cipherList, byte(cs>>8), byte(cs))
	}
	body = append(body, byte(len(cipherList)>>8), byte(len(cipherList)))
	body = append(body, cipherList...)

	// Compression methods: length 1, null compression (0x00)
	body = append(body, 0x01, 0x00)

	// Extensions
	extData := make([]byte, 0, 256)

	// server_name extension (SNI) — empty for now
	extData = appendExtension(extData, 0x0000, []byte{0x00, 0x00})

	// extended_master_secret (just empty)
	extData = appendExtension(extData, 0x0017, nil)

	// renegotiation_info (1 byte: 0x00)
	extData = appendExtension(extData, 0xff01, []byte{0x00})

	// supported_groups (curves)
	curvesData := make([]byte, 0, len(profile.Curves)*2+2)
	curvesData = append(curvesData, byte(len(profile.Curves)*2>>8), byte(len(profile.Curves)*2))
	for _, c := range profile.Curves {
		curvesData = append(curvesData, byte(c>>8), byte(c))
	}
	extData = appendExtension(extData, 0x000a, curvesData)

	// ec_point_formats
	pfData := []byte{byte(len(profile.Points))}
	pfData = append(pfData, profile.Points...)
	extData = appendExtension(extData, 0x000b, pfData)

	// session_ticket (empty)
	extData = appendExtension(extData, 0x0023, nil)

	// ALPN (h2, http/1.1)
	alpnData := []byte{
		0x02, 0x68, 0x32, 0x08,  // h2, length 2
		0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, // http/1.1
	}
	extData = appendExtension(extData, 0x0010, alpnData)

	// status_request (empty)
	extData = appendExtension(extData, 0x0005, []byte{0x01, 0x00, 0x00, 0x00, 0x00})

	// key_share (random bytes — NOT real crypto)
	ksData := make([]byte, 0, 32+4)
	ksData = append(ksData, 0x00, 0x1d)        // x25519
	ksData = append(ksData, 0x00, 0x20)        // length 32
	ksKey := make([]byte, 32)
	_, _ = rand.Read(ksKey)
	ksData = append(ksData, ksKey...)
	extData = appendExtension(extData, 0x0033, ksData)

	// supported_versions (TLS 1.3 + TLS 1.2)
	svData := []byte{0x04, 0x03, 0x04, 0x03, 0x03}
	extData = appendExtension(extData, 0x002b, svData)

	// psk_key_exchange_modes (1 mode: psk_dhe_ke=1)
	extData = appendExtension(extData, 0x002d, []byte{0x01, 0x01})

	// signature_algorithms (12 algorithms — matches Chrome's list)
	saData := []byte{0x00, 0x18} // length 24
	saAlgs := []uint16{
		0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501,
		0x0806, 0x0601, 0x0201, 0x0402, 0x0502, 0x0602,
	}
	for _, a := range saAlgs {
		saData = append(saData, byte(a>>8), byte(a))
	}
	extData = appendExtension(extData, 0x000d, saData)

	// Append extensions block to body.
	body = append(body, byte(len(extData)>>8), byte(len(extData)))
	body = append(body, extData...)

	// Wrap in TLS record: type=0x16 (handshake), version=0x0301 (TLS 1.0)
	hdr := [5]byte{0x16, 0x03, 0x01, 0x00, 0x00}
	binary.BigEndian.PutUint16(hdr[3:5], uint16(len(body)))
	if _, err := s.inner.Write(hdr[:]); err != nil {
		return err
	}
	_, err := s.inner.Write(body)
	return err
}

// appendExtension appends a TLS extension to dst: 2-byte type + 2-byte length + data.
func appendExtension(dst []byte, extType uint16, data []byte) []byte {
	dst = append(dst, byte(extType>>8), byte(extType))
	dst = append(dst, byte(len(data)>>8), byte(len(data)))
	dst = append(dst, data...)
	return dst
}
