// v0.1.30: Tor SOCKS5 proxy client.
//
// When --tor 127.0.0.1:9050 is set, the relay TCP connection is established
// via the specified Tor SOCKS5 proxy instead of a direct dial. This wraps
// the relay's net.Dial so that the rest of the code (gsrn.Dial, TLS-SRP
// handshake, in-band protocol) is unaware of the proxy.
//
// Wire compat: [G<->C] — the relay sees a TCP connection coming from the
// Tor exit node's IP, not from us. The wire protocol is unchanged. The
// C peer on the other end has no way to tell we used Tor.
package main

import (
        "encoding/binary"
        "fmt"
        "io"
        "net"
        "strconv"
        "time"
)

// torProxyAddr is set by main.go when --tor is given.
// Empty = direct dial. Non-empty = route via SOCKS5 proxy.
var torProxyAddr string

// ipv6Preferred hints the dialer to prefer IPv6.
// v0.3.0: Set by --ipv6 flag but not yet wired into the dialer logic.
// Kept for v0.4 implementation.
var ipv6Preferred bool //nolint:unused

// dialViaTor opens a TCP connection to targetHost:targetPort via the
// configured Tor SOCKS5 proxy (torProxyAddr).
//
// SOCKS5 handshake (RFC 1928):
//   - Send greeting: VER NMETHODS METHODS (we offer NO_AUTH only)
//   - Receive: VER METHOD (must be 0x00 = NO_AUTH)
//   - Send request: VER CMD RSV ATYP DST.ADDR DST.PORT
//   - Receive reply: VER REP RSV ATYP BND.ADDR BND.PORT
//   - REP == 0x00 means success
//
// We do NOT support authentication (Tor's default config doesn't require it
// for SOCKS5; if the user has enabled auth they need to configure Tor
// differently and this code will fail with a clear error).
func dialViaTor(targetHost, targetPort string) (net.Conn, error) {
        if torProxyAddr == "" {
                // No proxy — direct dial.
                return net.DialTimeout("tcp", net.JoinHostPort(targetHost, targetPort), 15*time.Second)
        }

        // Connect to the Tor SOCKS5 proxy.
        proxyConn, err := net.DialTimeout("tcp", torProxyAddr, 15*time.Second)
        if err != nil {
                return nil, fmt.Errorf("tor: dial proxy %s: %w", torProxyAddr, err)
        }
        // Set a deadline for the handshake — Tor should respond quickly.
        _ = proxyConn.SetDeadline(time.Now().Add(30 * time.Second))
        defer proxyConn.SetDeadline(time.Time{}) // clear after handshake

        // Greeting: VER=5, NMETHODS=1, METHODS=[NO_AUTH=0x00]
        if _, err := proxyConn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
                proxyConn.Close()
                return nil, fmt.Errorf("tor: send greeting: %w", err)
        }
        // Reply: VER METHOD
        buf := make([]byte, 2)
        if _, err := io.ReadFull(proxyConn, buf); err != nil {
                proxyConn.Close()
                return nil, fmt.Errorf("tor: read greeting reply: %w", err)
        }
        if buf[0] != 0x05 {
                proxyConn.Close()
                return nil, fmt.Errorf("tor: bad SOCKS version %d (want 5)", buf[0])
        }
        if buf[1] != 0x00 {
                proxyConn.Close()
                return nil, fmt.Errorf("tor: proxy requires auth method 0x%02x (only NO_AUTH supported)", buf[1])
        }

        // Build the request.
        // First resolve targetHost to an IP (Tor SOCKS5 accepts domains via
        // ATYP=0x03, but using ATYP=0x01 IPv4 is more reliable).
        port, _ := strconv.Atoi(targetPort)
        portBuf := make([]byte, 2)
        binary.BigEndian.PutUint16(portBuf, uint16(port))

        ip := net.ParseIP(targetHost)
        var req []byte
        if ip != nil {
                if ip4 := ip.To4(); ip4 != nil {
                        // IPv4.
                        req = make([]byte, 4+4+2)
                        req[0] = 0x05           // VER
                        req[1] = 0x01           // CMD_CONNECT
                        req[2] = 0x00           // RSV
                        req[3] = 0x01           // ATYP=IPv4
                        copy(req[4:8], ip4)
                        copy(req[8:10], portBuf)
                } else {
                        // IPv6.
                        req = make([]byte, 4+16+2)
                        req[0] = 0x05
                        req[1] = 0x01
                        req[2] = 0x00
                        req[3] = 0x04 // ATYP=IPv6
                        copy(req[4:20], ip.To16())
                        copy(req[20:22], portBuf)
                }
        } else {
                // Domain (ATYP=0x03).
                domain := []byte(targetHost)
                if len(domain) > 255 {
                        proxyConn.Close()
                        return nil, fmt.Errorf("tor: domain too long (%d bytes)", len(domain))
                }
                req = make([]byte, 4+1+len(domain)+2)
                req[0] = 0x05
                req[1] = 0x01
                req[2] = 0x00
                req[3] = 0x03 // ATYP=domain
                req[4] = byte(len(domain))
                copy(req[5:5+len(domain)], domain)
                copy(req[5+len(domain):7+len(domain)], portBuf)
        }

        if _, err := proxyConn.Write(req); err != nil {
                proxyConn.Close()
                return nil, fmt.Errorf("tor: send connect request: %w", err)
        }

        // Reply: VER REP RSV ATYP BND.ADDR BND.PORT
        hdr := make([]byte, 4)
        if _, err := io.ReadFull(proxyConn, hdr); err != nil {
                proxyConn.Close()
                return nil, fmt.Errorf("tor: read reply hdr: %w", err)
        }
        if hdr[0] != 0x05 {
                proxyConn.Close()
                return nil, fmt.Errorf("tor: bad reply version %d", hdr[0])
        }
        if hdr[1] != 0x00 {
                proxyConn.Close()
                return nil, fmt.Errorf("tor: proxy refused connect (REP=0x%02x)", hdr[1])
        }
        // Consume BND.ADDR based on ATYP.
        var bndLen int
        switch hdr[3] {
        case 0x01:
                bndLen = 4
        case 0x03:
                lenBuf := make([]byte, 1)
                if _, err := io.ReadFull(proxyConn, lenBuf); err != nil {
                        proxyConn.Close()
                        return nil, fmt.Errorf("tor: read domain len: %w", err)
                }
                bndLen = int(lenBuf[0])
        case 0x04:
                bndLen = 16
        default:
                proxyConn.Close()
                return nil, fmt.Errorf("tor: bad ATYP 0x%02x", hdr[3])
        }
        bndBuf := make([]byte, bndLen+2) // +2 for port
        if _, err := io.ReadFull(proxyConn, bndBuf); err != nil {
                proxyConn.Close()
                return nil, fmt.Errorf("tor: read bnd: %w", err)
        }

        // Handshake complete — proxyConn is now a tunnel to targetHost:targetPort.
        return proxyConn, nil
}
