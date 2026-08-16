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
        // Backoff for reconnect retries. Starts at 1s, doubles on each
        // consecutive failure, caps at 10s. Reset to 1s on success.
        // The previous fixed 2s sleep was too short for cross-continent
        // relays (relay sometimes takes 4-6s to release the listener
        // slot) AND too long when the slot was already free.
        backoff := time.Second
        const maxBackoff = 10 * time.Second
        for peerIdx := 0; ; peerIdx++ {
                if gsConn == nil {
                        // Re-register with the relay. The previous listener has
                        // been closed (gsConn.Close() below), so the relay
                        // should accept the new _gs_listen packet. With the
                        // token-stability fix in main.go, we now reuse the
                        // SAME 16-byte wire token across reconnects, so the
                        // relay treats this as a listener refresh rather than
                        // a new listener — BAD_AUTH should be rare.
                        //
                        // If we still get BAD_AUTH (relay hasn't noticed the
                        // disconnect yet, or a different relay node is handling
                        // the address), sleep with exponential backoff and retry.
                        copts := *opts
                        c, err := gsconn.Dial(secret, gsconn.ModeListen, &copts)
                        if err != nil {
                                fmt.Fprintf(os.Stderr, "[gs-netcat] multi-peer: listen failed: %v (retry in %v)\n", err, backoff)
                                time.Sleep(backoff)
                                backoff *= 2
                                if backoff > maxBackoff {
                                        backoff = maxBackoff
                                }
                                continue
                        }
                        gsConn = c
                        // Reconnect succeeded — reset backoff for next time.
                        backoff = time.Second
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
                // Brief pause to let the relay clean up the previous
                // listener's TCP before we re-register. Without this the
                // relay may briefly route a new _gs_connect to the old
                // (closing) listener, causing the connector to see
                // "TLS-SRP handshake: EOF" on rapid reconnect (Bug 4).
                // 1s is enough for the relay's TCP RST/FIN cycle on most
                // deployments; the exponential backoff above handles
                // slower relays. (Was 500ms in v0.1.10 — too short for
                // c.gs.thc.org which sometimes takes 800ms+ to release
                // the listener slot.)
                time.Sleep(time.Second)
        }
}
