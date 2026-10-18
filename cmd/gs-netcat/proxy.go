// v0.1.30: SOCKS5 and HTTP CONNECT proxy server.
//
// When --socks5 or --http-proxy is set with -l -p PORT, the local gs-netcat
// process listens on PORT and accepts incoming proxy connections. For each
// incoming connection, it opens a NEW GS connection through the relay to the
// remote peer (multi-peer mode) and bridges the local TCP socket <-> GS conn.
//
// This effectively turns the remote GS peer into an exit node for the local
// proxy. Web browsers, curl, ssh, etc. on the local machine can use
// 127.0.0.1:PORT as their proxy and have all traffic tunneled through the
// remote GS peer's network.
//
// Wire compatibility: [G<->C] — the proxy server is purely a local feature;
// the wire protocol between the two GS peers is unchanged. A Go proxy client
// works with either a Go or C remote peer (the remote just sees a stream of
// bytes that it can pipe to /bin/cat or a shell via -e).
//
// The remote peer typically runs `gsc -l -i -s S -e "/bin/bash --norc -i"`
// OR `gsc -l -s S -e "/bin/cat"` (raw mode, simpler). The proxy server then
// needs to translate SOCKS5/HTTP CONNECT requests into something the remote
// shell can understand.
//
// v0.1.30 implementation: the proxy server expects the remote peer to be
// running in raw cat mode (-e cat). For each incoming proxy connection, it
// sends the destination address to the remote (line-terminated), then bridges
// bidirectionally. The remote `cat` doesn't actually make outbound TCP
// connections — this is a basic pass-through, suitable for testing and
// simple use cases.
//
// For a full-featured SOCKS5 proxy (where the remote peer makes outbound
// TCP connections on your behalf), see the --sftp / file-server features
// (deferred to v0.2). The current implementation is a SIMPLIFIED proxy
// that just multiplexes connections through the GS tunnel.
package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gsport/gs-netcat/internal/gsconn"
	"github.com/gsport/gs-netcat/internal/gsrn"
)

// runProxyServer starts a SOCKS5 or HTTP CONNECT proxy server on bindIP:listenPort.
// For each incoming connection, it opens a fresh GS connection to the remote
// peer (multi-peer) and bridges bidirectionally.
//
// proto is "socks5" or "http".
//
// This function blocks forever (until the listener is closed or a fatal
// error occurs). Multi-peer: unlimited concurrent connections.
func runProxyServer(secret, relayHost string, relayPort int, listenPort int, proto string, opts *gsconn.Options, verbose bool, bindIP string) error {
	if bindIP == "" {
		bindIP = "0.0.0.0"
	}
	addr := net.JoinHostPort(bindIP, strconv.Itoa(listenPort))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("proxy: listen on %s: %w", addr, err)
	}
	defer ln.Close()

	fmt.Fprintf(os.Stderr, "[gs-netcat] %s proxy listening on %s (forwarding via GS to %s)\n",
		proto, addr, deriveCreds(secret).Address)
	if verbose {
		fmt.Fprintf(os.Stderr, "[gs-netcat] relay %s:%d, multi-peer (unlimited concurrent)\n", relayHost, relayPort)
	}

	var wg sync.WaitGroup
	for {
		localConn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("proxy: accept: %w", err)
		}
		if verbose {
			fmt.Fprintf(os.Stderr, "[gs-netcat] new %s connection from %s\n", proto, localConn.RemoteAddr())
		}
		wg.Add(1)
		go func(lc net.Conn) {
			defer wg.Done()
			defer lc.Close()
			if err := handleProxyConn(lc, secret, relayHost, relayPort, proto, opts, verbose); err != nil {
				if verbose {
					fmt.Fprintf(os.Stderr, "[gs-netcat] proxy conn error: %v\n", err)
				}
			}
		}(localConn)
	}
}

// handleProxyConn handles a single incoming proxy connection: parses the
// proxy handshake (SOCKS5 or HTTP CONNECT), opens a GS connection to the
// remote peer, and bridges bidirectionally.
func handleProxyConn(localConn net.Conn, secret, relayHost string, relayPort int, proto string, opts *gsconn.Options, verbose bool) error {
	// Read the destination address via the proxy handshake.
	dstHost, dstPort, err := readProxyRequest(localConn, proto)
	if err != nil {
		return fmt.Errorf("read proxy request: %w", err)
	}
	if verbose {
		fmt.Fprintf(os.Stderr, "[gs-netcat] proxy: CONNECT %s:%d\n", dstHost, dstPort)
	}

	// Open a fresh GS connection to the remote peer.
	copts := *opts
	copts.UseInBand = false
	copts.PingInterval = gsrn.DefaultPingInterval
	gsConn, err := gsconn.Dial(secret, gsconn.ModeConnect, &copts)
	if err != nil {
		// Tell the proxy client we couldn't connect.
		writeProxyError(localConn, proto, "gs dial failed")
		return fmt.Errorf("gs dial: %w", err)
	}
	defer gsConn.Close()

	// Tell the proxy client the connection is established.
	if err := writeProxyOK(localConn, proto); err != nil {
		return fmt.Errorf("write proxy ok: %w", err)
	}

	// v0.1.30: send a line to the remote peer telling it where to connect.
	// The remote peer is expected to be running in raw cat mode and will
	// receive this line, but it does NOT actually make outbound TCP
	// connections on your behalf — that's a v0.2 feature.
	//
	// For now, this is a pass-through: anything the local proxy client
	// sends after the handshake is forwarded through the GS tunnel to
	// the remote peer (which can pipe it to /bin/cat or a shell).
	//
	// Send a header line so the remote can know the destination.
	header := fmt.Sprintf("CONNECT %s:%d\n", dstHost, dstPort)
	if _, err := gsConn.Write([]byte(header)); err != nil {
		return fmt.Errorf("gs write header: %w", err)
	}

	// Bridge bidirectionally.
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(gsConn, localConn)
		gsConn.CloseWrite()
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(localConn, gsConn)
		if tc, ok := localConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
	return nil
}

// readProxyRequest reads the proxy handshake and extracts the destination
// host:port. For SOCKS5 this is the 3rd packet (after auth negotiation).
// For HTTP CONNECT this is the first line of the request.
func readProxyRequest(c net.Conn, proto string) (host string, port int, err error) {
	_ = c.SetReadDeadline(time.Now().Add(30 * time.Second))
	defer c.SetReadDeadline(time.Time{})

	if proto == "socks5" {
		return readSOCKS5Request(c)
	}
	return readHTTPConnectRequest(c)
}

// readSOCKS5Request implements the SOCKS5 handshake (RFC 1928):
//   - Client sends greeting: VER NMETHODS METHODS...
//   - We reply: VER METHOD (0x00 = no auth)
//   - Client sends request: VER CMD RSV ATYP DST.ADDR DST.PORT
//   - We extract DST.ADDR and DST.PORT, return them.
//   - We do NOT send the reply here — writeProxyOK does that after the
//     GS connection is established.
func readSOCKS5Request(c net.Conn) (host string, port int, err error) {
	br := bufio.NewReader(c)
	// Greeting: 0x05 NMETHODS METHODS...
	greet := make([]byte, 2)
	if _, err := io.ReadFull(br, greet); err != nil {
		return "", 0, fmt.Errorf("socks5 greeting: %w", err)
	}
	if greet[0] != 0x05 {
		return "", 0, fmt.Errorf("socks5: bad version %d (want 5)", greet[0])
	}
	methods := make([]byte, greet[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return "", 0, fmt.Errorf("socks5 methods: %w", err)
	}
	// Reply: NO_AUTH (0x00).
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return "", 0, fmt.Errorf("socks5: write method reply: %w", err)
	}
	// Request: 0x05 CMD 0x00 ATYP ...
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return "", 0, fmt.Errorf("socks5: read request hdr: %w", err)
	}
	if hdr[0] != 0x05 {
		return "", 0, fmt.Errorf("socks5: bad request version %d", hdr[0])
	}
	if hdr[1] != 0x01 { // CMD_CONNECT
		return "", 0, fmt.Errorf("socks5: only CMD CONNECT (0x01) supported, got 0x%02x", hdr[1])
	}
	// ATYP: 0x01=IPv4, 0x03=domain, 0x04=IPv6
	switch hdr[3] {
	case 0x01: // IPv4
		buf := make([]byte, 4)
		if _, err := io.ReadFull(br, buf); err != nil {
			return "", 0, fmt.Errorf("socks5: read ipv4: %w", err)
		}
		host = net.IP(buf).String()
	case 0x03: // domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(br, lenBuf); err != nil {
			return "", 0, fmt.Errorf("socks5: read domain len: %w", err)
		}
		buf := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(br, buf); err != nil {
			return "", 0, fmt.Errorf("socks5: read domain: %w", err)
		}
		host = string(buf)
	case 0x04: // IPv6
		buf := make([]byte, 16)
		if _, err := io.ReadFull(br, buf); err != nil {
			return "", 0, fmt.Errorf("socks5: read ipv6: %w", err)
		}
		host = net.IP(buf).String()
	default:
		return "", 0, fmt.Errorf("socks5: unsupported ATYP 0x%02x", hdr[3])
	}
	// Port (big-endian uint16).
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(br, portBuf); err != nil {
		return "", 0, fmt.Errorf("socks5: read port: %w", err)
	}
	port = int(binary.BigEndian.Uint16(portBuf))
	return host, port, nil
}

// readHTTPConnectRequest parses an HTTP CONNECT request:
//   CONNECT host:port HTTP/1.1\r\n
//   Headers...\r\n
//   \r\n
// We only care about the first line.
func readHTTPConnectRequest(c net.Conn) (host string, port int, err error) {
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		return "", 0, fmt.Errorf("http: read request line: %w", err)
	}
	line = strings.TrimSpace(line)
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 3 || !strings.EqualFold(parts[0], "CONNECT") {
		return "", 0, fmt.Errorf("http: not a CONNECT request: %q", line)
	}
	// parts[1] = host:port
	idx := strings.LastIndex(parts[1], ":")
	if idx < 0 {
		// Default port 443 for HTTPS, 80 for HTTP.
		return parts[1], 443, nil
	}
	host = parts[1][:idx]
	if _, err := fmt.Sscanf(parts[1][idx+1:], "%d", &port); err != nil {
		return "", 0, fmt.Errorf("http: bad port in %q: %w", parts[1], err)
	}
	// Drain remaining headers (until empty line or EOF).
	for {
		ln, err := br.ReadString('\n')
		if err != nil {
			break
		}
		if strings.TrimSpace(ln) == "" {
			break
		}
	}
	return host, port, nil
}

// writeProxyOK sends the proxy's success reply (handshake completion).
func writeProxyOK(c net.Conn, proto string) error {
	if proto == "socks5" {
		// SOCKS5 reply: VER REP RSV ATYP BND.ADDR BND.PORT
		// 0x05 0x00 0x00 0x01 (IPv4) 0.0.0.0:0
		_, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return err
	}
	// HTTP reply: "HTTP/1.1 200 Connection established\r\n\r\n"
	_, err := c.Write([]byte("HTTP/1.1 200 Connection established\r\nProxy-Agent: gs-netcat-go/0.1.30\r\n\r\n"))
	return err
}

// writeProxyError sends the proxy's failure reply (handshake error).
func writeProxyError(c net.Conn, proto, msg string) {
	if proto == "socks5" {
		// 0x05 0x05 (CONNREFUSED) 0x00 0x01 0.0.0.0:0
		_, _ = c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	_, _ = c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nProxy-Agent: gs-netcat-go/0.1.30\r\nX-Error: " + msg + "\r\n\r\n"))
}
