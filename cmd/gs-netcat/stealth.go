// v0.1.30: Stealth HTTPS mode (--stealth-https).
//
// v0.2.0 REWRITE: The original v0.1.30 implementation wrapped the GSRN
// relay TCP connection in fake TLS records. This does NOT work in
// practice because the production GSRN relay doesn't decode fake TLS —
// it expects plaintext GSRN _gs_listen/_gs_connect packets on port 443.
// The fake TLS framing caused the relay to reject the connection with
// instant EOF.
//
// v0.2.0 approach: --stealth-https now wraps the GS-encrypted channel
// (AFTER TLS-SRP handshake, INSIDE the relayed connection) in fake TLS
// records. The GSRN relay sees normal _gs_listen/_gs_connect packets
// (it doesn't care what flows after _gs_start). Both Go peers wrap their
// application data in fake TLS records, so DPI observing the bytes
// between the two peers sees what looks like HTTPS traffic.
//
// Wire compat: [G↔G] only — C peer would see application_data records
// as garbage bytes (no in-band decode). Both peers MUST pass --stealth-https.
//
// Implementation: stealthConn wraps the gsconn.Conn's rawConn (after
// TLS-SRP). On Write, frames data as TLS application_data records.
// On Read, parses incoming TLS records and returns application data.
// The fake ClientHello is sent once at the start of the session by the
// SSL-client side; the SSL-server side reads and discards it.
package main

import (
        "crypto/rand"
        "encoding/binary"
        "fmt"
        "io"
        "sync"
        "time"
)

// activeTLSProfile is set by main.go when --tls-fingerprint is given
// (combined with --stealth-https). When non-nil, the stealth wrapper
// uses this profile's ClientHello instead of the default minimal one.
var activeTLSProfile *tlsFingerprintProfile

// stealthConn wraps an io.ReadWriteCloser with fake TLS record framing.
type stealthConn struct {
        inner   io.ReadWriteCloser
        readMu  sync.Mutex
        writeMu sync.Mutex
        readBuf []byte // leftover bytes from a previous read
        // clientSide: true if we should write a ClientHello at the start.
        // Determined by who created the conn (the connector side writes
        // ClientHello; the listener side expects to receive it).
        clientSide bool
        helloDone  bool // true after ClientHello has been sent/received
}

// newStealthConn wraps c with fake TLS framing. If clientSide is true,
// the conn will write a fake ClientHello on first Write and expect the
// peer's ClientHello on first Read.
func newStealthConn(c io.ReadWriteCloser, clientSide bool) *stealthConn {
        return &stealthConn{inner: c, clientSide: clientSide}
}

// Write frames p as a TLS application_data record:
//   byte 0:    0x17 (application_data)
//   bytes 1-2: 0x03 0x03 (TLS 1.2)
//   bytes 3-4: BE uint16 length
//   bytes 5+:  payload (p)
//
// On first Write, if clientSide, sends a fake ClientHello first.
func (s *stealthConn) Write(p []byte) (int, error) {
        s.writeMu.Lock()
        defer s.writeMu.Unlock()

        // Send ClientHello on first Write (client side only).
        if s.clientSide && !s.helloDone {
                if err := s.writeClientHello(); err != nil {
                        return 0, err
                }
                s.helloDone = true
        }

        written := 0
        for written < len(p) {
                chunk := len(p) - written
                if chunk > 16384 { // TLS max record payload
                        chunk = 16384
                }
                hdr := [5]byte{0x17, 0x03, 0x03, 0, 0}
                binary.BigEndian.PutUint16(hdr[3:5], uint16(chunk))
                if _, err := s.inner.Write(hdr[:]); err != nil {
                        return written, err
                }
                n, err := s.inner.Write(p[written : written+chunk])
                written += n
                if err != nil {
                        return written, err
                }
        }
        return written, nil
}

// Read parses incoming TLS records and returns the application data.
// If the first byte is 0x16 (handshake), it's the peer's fake ClientHello —
// we skip it transparently. Otherwise it's application_data (0x17).
//
// On first Read, if server side, expects to receive peer's ClientHello.
func (s *stealthConn) Read(p []byte) (int, error) {
        s.readMu.Lock()
        defer s.readMu.Unlock()

        // If we have leftover decoded bytes, return them first.
        if len(s.readBuf) > 0 {
                n := copy(p, s.readBuf)
                s.readBuf = s.readBuf[n:]
                return n, nil
        }

        for {
                // Read 5-byte TLS record header.
                hdr := make([]byte, 5)
                if _, err := io.ReadFull(s.inner, hdr); err != nil {
                        return 0, err
                }
                recType := hdr[0]
                length := int(binary.BigEndian.Uint16(hdr[3:5]))
                if length > 16384+2048 { // TLS max + headroom
                        return 0, fmt.Errorf("stealth: record too long: %d", length)
                }
                payload := make([]byte, length)
                if _, err := io.ReadFull(s.inner, payload); err != nil {
                        return 0, err
                }
                if recType == 0x16 {
                        // Handshake record (fake ClientHello). Skip.
                        // Mark hello as done on server side.
                        s.helloDone = true
                        continue
                }
                // Application data — return to caller.
                n := copy(p, payload)
                if n < len(payload) {
                        s.readBuf = append(s.readBuf, payload[n:]...)
                }
                return n, nil
        }
}

// writeClientHello writes a fake ClientHello so the initial bytes the
// peer sees look like a TLS handshake initiation.
//
// If activeTLSProfile is set (via --tls-fingerprint), uses the
// profiled ClientHello (Chrome, Firefox, etc.) instead of the minimal
// default. The profiled ClientHello matches the cipher suite order and
// extension list of real browsers, helping evade JA3 fingerprinting.
//
// The ClientHello is NOT a real one — it's a static blob that mimics
// the structure (record type 0x16, version 0x0301, then handshake
// type 0x01, then a random session_id + cipher_suites + extensions).
// A DPI that only checks "is the first byte 0x16 and version 0x03xx"
// will pass it. A DPI that actually parses TLS will see it's bogus.
func (s *stealthConn) writeClientHello() error {
        // v0.2.0: Use profiled ClientHello if available.
        if activeTLSProfile != nil {
                return writeProfiledClientHello(s, activeTLSProfile)
        }
        // Build a 137-byte fake ClientHello.
        ch := make([]byte, 137)
        // Handshake type = 0x01 (ClientHello)
        ch[0] = 0x01
        // Length: 133 bytes (3-byte BE).
        ch[1] = 0x00
        ch[2] = 0x00
        ch[3] = 0x85
        // Client version: TLS 1.2 = 0x0303
        ch[4] = 0x03
        ch[5] = 0x03
        // Random: 32 bytes of crypto-random.
        _, _ = rand.Read(ch[6:38])
        // Session ID: length 0.
        ch[38] = 0x00
        // Cipher suites: length 2 (one suite), 0xC020 (TLS_SRP_SHA_WITH_AES_256_CBC_SHA)
        ch[39] = 0x00
        ch[40] = 0x02
        ch[41] = 0xC0
        ch[42] = 0x20
        // Compression methods: length 1, 0x00 (null)
        ch[43] = 0x01
        ch[44] = 0x00
        // Extensions length: rest of bytes (137-45-2 = 90)
        extLen := len(ch) - 45 - 2
        ch[45] = byte(extLen >> 8)
        ch[46] = byte(extLen)
        // Fill extensions with random bytes (DPI usually doesn't parse them).
        _, _ = rand.Read(ch[47:])

        // Wrap in a TLS record: type=0x16, version=0x0301, length.
        hdr := [5]byte{0x16, 0x03, 0x01, 0x00, byte(len(ch))}
        if _, err := s.inner.Write(hdr[:]); err != nil {
                return err
        }
        _, err := s.inner.Write(ch)
        return err
}

// Close closes the underlying conn. Sends a TLS close_notify record
// first if we've sent the ClientHello (mimicking a normal TLS shutdown).
func (s *stealthConn) Close() error {
        s.writeMu.Lock()
        if s.helloDone {
                // Send close_notify (type=0x15, version=0x0303, length=0).
                _, _ = s.inner.Write([]byte{0x15, 0x03, 0x03, 0x00, 0x00})
        }
        s.writeMu.Unlock()
        return s.inner.Close()
}

// LocalAddr / RemoteAddr / SetDeadline etc. are not supported (the
// underlying io.ReadWriteCloser may not be a net.Conn). This is OK
// because the wrapper sits BELOW gsconn.Conn, which provides its own
// SetDeadline/CloseWrite via type assertions — and those methods will
// return errors when wrapped (acceptable; deadlines are typically
// not used after the TLS handshake).
//
// SetDeadline is a no-op (returns nil) — deadlines on the underlying
// conn should be set BEFORE wrapping.
var _ = time.Second
