// Command gs-netcat — multi-peer server loop.
//
// In the C original, when the server is in multi-peer mode (set by
// -i, -p, -d, or -S on the listen side), it keeps the GSRN listen
// socket open and accepts N concurrent incoming GS connections. Each
// connection gets its own peer struct with its own forward target
// (PTY, local TCP, SOCKS, etc.).
//
// In the Go port we approximate this with a sequential re-listen
// loop: after each GS conn closes, we re-register with the GSRN.
// This is NOT true concurrency (a new peer can only connect after the
// previous one has disconnected), but it covers the common case of
// "user connects, runs a command, disconnects, user reconnects later"
// without forcing the listener to restart.
//
// For TRUE concurrency (multiple simultaneous peers), we'd need to
// extend gsrn.Conn to support GS_listen + GS_accept semantics —
// i.e. keep the listen TCP open and accept new _gs_start packets on
// it. That's a deeper refactor we can do if the user needs it.
//
// This file is used by main.go's listen-mode paths when -i is set
// (the most common multi-peer trigger). The raw -l cat-mode path
// stays single-shot (matches C: `is_multi_peer` is only set if -i
// is also passed on the server side).
package main

import (
        "fmt"
        "os"
        "time"

        "github.com/gsport/gs-netcat/internal/gsconn"
)

// runMultiPeerInteractiveServer loops forever, accepting GS
// connections one at a time. Each connection runs the interactive
// server flow (PTY spawn, event-pump, etc.). After a connection ends
// we re-register with the GSRN and wait for the next.
//
// The FIRST connection (already established by main() before calling
// us) is passed in as `firstConn`. We handle it inline so we don't
// waste the already-completed TLS handshake. After it ends we close it
// and re-dial for subsequent peers.
//
// `secret`, `relayHost`, `relayPort`, `opts` configure the GSRN
// re-dial (same as the single-shot path). `verbose`, `execCmd` are
// passed through to the per-connection handler.
//
// The loop terminates only on fatal error or signal.
func runMultiPeerInteractiveServer(firstConn *gsconn.Conn, secret, relayHost string, relayPort int, opts *gsconn.Options, verbose bool, execCmd string) error {
        gsConn := firstConn
        for peerIdx := 0; ; peerIdx++ {
                if gsConn == nil {
                        // Re-register with the relay. The previous listener has
                        // been closed (gsConn.Close() below), so the relay
                        // should accept the new _gs_listen packet without
                        // BAD_AUTH. If we still get BAD_AUTH (relay hasn't
                        // noticed the disconnect yet), sleep and retry.
                        copts := *opts
                        c, err := gsconn.Dial(secret, gsconn.ModeListen, &copts)
                        if err != nil {
                                fmt.Fprintf(os.Stderr, "[gs-netcat] multi-peer: listen failed: %v\n", err)
                                time.Sleep(2 * time.Second)
                                continue
                        }
                        gsConn = c
                }

                if verbose {
                        fmt.Fprintf(os.Stderr, "[gs-netcat] multi-peer: peer #%d connected (role=%s)\n",
                                peerIdx, roleStr(gsConn.Role()))
                }

                // Run the interactive server flow for this connection. This
                // blocks until the peer disconnects or the shell exits.
                remoteClosed := make(chan struct{})
                ctx := &eventCtx{}
                go eventPump(gsConn, ctx, verbose)
                if os.Getenv("GSPORT_DEBUG") != "" {
                        fmt.Fprintf(os.Stderr, "[gsport] multi-peer: calling runInteractiveServer(execCmd=%q)\n", execCmd)
                }
                _ = runInteractiveServer(gsConn, ctx, verbose, remoteClosed, execCmd)
                if os.Getenv("GSPORT_DEBUG") != "" {
                        fmt.Fprintf(os.Stderr, "[gsport] multi-peer: runInteractiveServer returned\n")
                }

                gsConn.Close()
                gsConn = nil
                if verbose {
                        fmt.Fprintf(os.Stderr, "[gs-netcat] multi-peer: peer #%d done, re-listening\n", peerIdx)
                }
        }
}
