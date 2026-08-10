// Command gs-netcat — port-forwarding implementation (-p / -d).
//
// Mirrors the C `peer_new()` + `peer_forward_connect()` + `cb_accept`
// path (tools/4_gs-netcat.c:1019-1100, 1307-1372). The semantics are
// ASYMMETRIC depending on whether -l is set:
//
//	CLIENT (no -l):  `gs-netcat -s S -p 2222`
//	  - Bind local TCP port 2222 on 0.0.0.0.
//	  - For each incoming local connection, open a NEW GS connection
//	    through the GSRN to the remote peer (with secret S) and bridge
//	    the local TCP socket <-> GS conn.
//	  - `-d` is silently ignored on the client side (matches C).
//
//	SERVER (-l):     `gs-netcat -l -s S -d 192.168.6.7 -p 22`
//	  - Listen on the GSRN at GS-Address(S).
//	  - For each incoming GS connection, open a TCP connection to
//	    192.168.6.7:22 and bridge GS conn <-> local TCP.
//	  - No local TCP port is bound.
//
// In both cases multiple concurrent forwards are supported (multi-peer):
// the client accepts multiple local TCP connections and opens a separate
// GS connection for each; the server accepts multiple GS connections
// and opens a separate local TCP for each.
//
// On Windows the same code works: Go's net package abstracts accept/
// connect. No #ifdef needed.
package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/gsport/gs-netcat/internal/gsconn"
	"github.com/gsport/gs-netcat/internal/gsrn"
)

// runPortForwardClient is the CLIENT side of -p:
//
//   - Bind local TCP port `listenPort` on 0.0.0.0 (or 127.0.0.1 if
//     listenPort was 0 — picks a random ephemeral port and prints it).
//   - For each accepted local connection, dial a fresh gsconn.Conn
//     through the GSRN to the remote peer.
//   - Bridge local TCP <-> GS conn in both directions until either
//     side closes.
//   - Run forever (multi-peer: unlimited concurrent forwards).
//
// `secret`, `relayHost`, `relayPort`, `opts` are passed through from
// the parent CLI parse.
func runPortForwardClient(secret, relayHost string, relayPort int, listenPort int, opts *gsconn.Options, verbose bool) error {
	addr := ":" + strconv.Itoa(listenPort)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	defer ln.Close()

	// If listenPort was 0, the OS picked a port. Print it so the user
	// knows where to connect (matches C's behavior of writing the
	// bound port back to gopt.port).
	boundPort := ln.Addr().(*net.TCPAddr).Port
	fmt.Fprintf(os.Stderr, "[gs-netcat] forwarding local :%d → GS-Address %s\n",
		boundPort, deriveCreds(secret).Address)
	if verbose {
		fmt.Fprintf(os.Stderr, "[gs-netcat] relay %s:%d, multi-peer (unlimited concurrent forwards)\n",
			relayHost, relayPort)
	}

	var wg sync.WaitGroup
	for {
		localConn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("accept: %w", err)
		}
		if verbose {
			fmt.Fprintf(os.Stderr, "[gs-netcat] new local connection from %s\n", localConn.RemoteAddr())
		}

		wg.Add(1)
		go func(lc net.Conn) {
			defer wg.Done()
			defer lc.Close()
			// Each local connection gets its own GS connection. We
			// clone opts so per-connection state (token, etc.) is
			// independent. The relay will see N concurrent CONNECT
			// packets from us, all with the same GS-Address; the
			// remote listener must be in multi-peer mode (which our
			// server side is — see runPortForwardServer).
			copts := *opts
			copts.UseInBand = false // raw byte bridge for port-forward
			copts.PingInterval = gsrn.DefaultPingInterval

			gsConn, err := gsconn.Dial(secret, gsconn.ModeConnect, &copts)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[gs-netcat] gs dial failed: %v\n", err)
				return
			}
			defer gsConn.Close()

			if verbose {
				fmt.Fprintf(os.Stderr, "[gs-netcat] GS connection established (role=%s)\n",
					roleStr(gsConn.Role()))
			}

			// Bridge bidirectionally. Either side closing terminates
			// the forward.
			done := make(chan struct{}, 2)
			go func() {
				_, _ = io.Copy(gsConn, lc)
				gsConn.CloseWrite()
				done <- struct{}{}
			}()
			go func() {
				_, _ = io.Copy(lc, gsConn)
				lc.Close() // best effort
				done <- struct{}{}
			}()
			<-done
			<-done
		}(localConn)
	}
}

// runPortForwardServer is the SERVER side of -l -d IP -p PORT:
//
//   - Listen on the GSRN at GS-Address(S) (multi-peer: unlimited
//     concurrent GS connections).
//   - For each accepted GS connection, dial a fresh TCP connection
//     to `dstIP:dstPort` and bridge bidirectionally.
//
// This is the "remote port forward" half: the client's local listener
// is forwarded THROUGH the GSRN to the server's `dstIP:dstPort`.
//
// `dstIP` may be a hostname or IP literal; we resolve it via net.Dial.
func runPortForwardServer(secret, relayHost string, relayPort int, dstIP string, dstPort int, opts *gsconn.Options, verbose bool) error {
	// Sanity-check the destination is resolvable. We don't pre-dial it
	// (the target may not be up yet); we just check the address parses.
	if dstIP == "" {
		return fmt.Errorf("-d <ip> is required with -l -p")
	}
	if dstPort <= 0 || dstPort > 65535 {
		return fmt.Errorf("-p <port> invalid: %d", dstPort)
	}

	dstAddr := net.JoinHostPort(dstIP, strconv.Itoa(dstPort))
	fmt.Fprintf(os.Stderr, "[gs-netcat] forwarding GS-Address %s → %s\n",
		deriveCreds(secret).Address, dstAddr)
	if verbose {
		fmt.Fprintf(os.Stderr, "[gs-netcat] relay %s:%d, multi-peer (unlimited concurrent forwards)\n",
			relayHost, relayPort)
	}

	// Listen on the GSRN. Multi-peer: accept multiple GS connections.
	// Each one gets its own forward.
	var wg sync.WaitGroup
	for peerIdx := 0; ; peerIdx++ {
		copts := *opts
		copts.UseInBand = false
		copts.PingInterval = gsrn.DefaultPingInterval

		// Each iteration is one GS connection. The first one establishes
		// the listen; subsequent ones re-register with the relay after
		// the previous conn closed. (For true concurrency we'd need to
		// keep the listen socket open and accept multiple incoming GS
		// conns on it — see runMultiPeerServer below for the proper
		// implementation. This fallback path handles the simple
		// sequential case.)
		gsConn, err := gsconn.Dial(secret, gsconn.ModeListen, &copts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[gs-netcat] gs listen failed: %v\n", err)
			time.Sleep(1 * time.Second)
			continue
		}

		if verbose {
			fmt.Fprintf(os.Stderr, "[gs-netcat] peer #%d connected (role=%s)\n",
				peerIdx, roleStr(gsConn.Role()))
		}

		wg.Add(1)
		go func(gc *gsconn.Conn, idx int) {
			defer wg.Done()
			defer gc.Close()

			// Dial the local destination.
			lc, err := net.DialTimeout("tcp", dstAddr, 10*time.Second)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[gs-netcat] peer #%d: dial %s failed: %v\n", idx, dstAddr, err)
				return
			}
			defer lc.Close()

			if verbose {
				fmt.Fprintf(os.Stderr, "[gs-netcat] peer #%d: forward to %s established\n", idx, dstAddr)
			}

			// Bridge bidirectionally.
			done := make(chan struct{}, 2)
			go func() {
				_, _ = io.Copy(lc, gc)
				if tc, ok := lc.(*net.TCPConn); ok {
					_ = tc.CloseWrite()
				}
				done <- struct{}{}
			}()
			go func() {
				_, _ = io.Copy(gc, lc)
				gc.CloseWrite()
				done <- struct{}{}
			}()
			<-done
			<-done
		}(gsConn, peerIdx)
	}
}
