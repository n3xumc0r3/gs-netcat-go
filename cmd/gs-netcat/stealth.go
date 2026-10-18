// v0.1.30: Stealth HTTPS mode (--stealth-https).
//
// Wraps the GSRN relay TCP connection in fake TLS records so that the
// wire traffic looks like a normal HTTPS session. Defeats naive DPI that
// blocks non-TLS traffic on port 443 (notably Russia's TSPU).
//
// Wire format (Go-Go only):
//   - Initial 5-byte TLS record header: type=0x16 (handshake),
//     version=0x0301, length=BE uint16
//   - Fake ClientHello bytes (137 bytes of plausible-looking data)
//   - Subsequent records: type=0x17 (application data), version=0x0303,
//     length=BE uint16, payload (the actual GSRN packet)
//
// Both peers MUST pass --stealth-https. A C peer without the flag would
// see the fake TLS record header as garbage bytes and fail to parse the
// _gs_listen/_gs_connect packet.
//
// Limitations:
//   - NOT a real TLS implementation. No key exchange, no encryption layer
//     beyond the existing TLS-SRP. This just makes the wire bytes look
//     like TLS to a fingerprinting DPI. A DPI that actually decodes TLS
//     would see the ClientHello is bogus.
//   - For real TLS fingerprint mimicry (matching Chrome/Firefox JA3),
//     see the deferred --tls-fingerprint feature (v0.2).
//
// Wire compat: [G<->G] — Go-Go only. C peer will fail to handshake.
package main

import (
        "crypto/rand"
        "encoding/binary"
        "fmt"
        "io"
        "net"
        "sync"
        "time"
)

// stealthConn wraps a net.Conn with fake TLS record framing.
type stealthConn struct {
        inner   net.Conn
        readMu  sync.Mutex
        writeMu sync.Mutex
        readBuf []byte // leftover bytes from a previous read
}

// newStealthConn wraps c with fake TLS framing.
func newStealthConn(c net.Conn) *stealthConn {
        return &stealthConn{inner: c}
}

// Write frames p as a TLS application_data record:
//   byte 0:    0x17 (application_data)
//   bytes 1-2: 0x03 0x03 (TLS 1.2)
//   bytes 3-4: BE uint16 length
//   bytes 5+:  payload (p)
func (s *stealthConn) Write(p []byte) (int, error) {
        s.writeMu.Lock()
        defer s.writeMu.Unlock()

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

// WriteClientHello writes a fake ClientHello so the initial bytes the
// peer sees look like a TLS handshake initiation. Should be called
// immediately after the TCP connection is established, before any
// GSRN packets are sent.
//
// The ClientHello is NOT a real one — it's a static blob that mimics
// the structure (record type 0x16, version 0x0301, then handshake
// type 0x01, then a random session_id + cipher_suites + extensions).
// A DPI that only checks "is the first byte 0x16 and version 0x03xx"
// will pass it. A DPI that actually parses TLS will see it's bogus.
func (s *stealthConn) WriteClientHello() error {
        s.writeMu.Lock()
        defer s.writeMu.Unlock()

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

// ReadClientHello reads and discards the peer's fake ClientHello.
// Called immediately after the TCP connection is established.
func (s *stealthConn) ReadClientHello() error {
        // Read a handshake record.
        hdr := make([]byte, 5)
        if _, err := io.ReadFull(s.inner, hdr); err != nil {
                return fmt.Errorf("stealth: read peer ClientHello hdr: %w", err)
        }
        if hdr[0] != 0x16 {
                return fmt.Errorf("stealth: expected handshake record (0x16), got 0x%02x — peer is not in --stealth-https mode", hdr[0])
        }
        length := int(binary.BigEndian.Uint16(hdr[3:5]))
        discard := make([]byte, length)
        if _, err := io.ReadFull(s.inner, discard); err != nil {
                return fmt.Errorf("stealth: read peer ClientHello body: %w", err)
        }
        return nil
}

func (s *stealthConn) Close() error {
        return s.inner.Close()
}

func (s *stealthConn) LocalAddr() net.Addr                { return s.inner.LocalAddr() }
func (s *stealthConn) RemoteAddr() net.Addr               { return s.inner.RemoteAddr() }
func (s *stealthConn) SetDeadline(t time.Time) error       { return s.inner.SetDeadline(t) }
func (s *stealthConn) SetReadDeadline(t time.Time) error   { return s.inner.SetReadDeadline(t) }
func (s *stealthConn) SetWriteDeadline(t time.Time) error  { return s.inner.SetWriteDeadline(t) }
