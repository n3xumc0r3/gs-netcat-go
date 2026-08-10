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

        "github.com/gsport/gs-netcat/internal/gskdf"
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
//
// AUTH TOKEN REUSE: the C original generates a random auth-token on
// the FIRST listen and reuses it for all subsequent re-listens. The
// Go port previously generated a NEW random token on every re-dial,
// which caused the relay to reject re-listen attempts with BAD_AUTH
// (the relay still had the old token registered for the same
// GS-Address). We now generate the token ONCE (on first call) and
// persist it in opts.AuthToken so all subsequent Dial calls derive
// the same token via DeriveAuthToken.
func runMultiPeerInteractiveServer(firstConn *gsconn.Conn, secret, relayHost string, relayPort int, opts *gsconn.Options, verbose bool, execCmd string) error {
        // If no explicit auth token was set, generate a deterministic
        // one derived from the secret + GS-Address. This ensures all
        // re-listen attempts use the SAME token, avoiding BAD_AUTH
        // from the relay (which rejects a new token for an already-
        // claimed GS-Address). We piggyback on the DeriveAuthToken
        // path by setting opts.AuthToken to a fixed marker string;
        // gsconn.Dial will then call DeriveAuthToken(marker, addr)
        // which is deterministic and stable across re-dials.
        if opts.AuthToken == "" {
                // Use the secret itself as the token-derivation input.
                // This is deterministic: same secret → same token →
                // same auth claim across all re-listen attempts.
                opts.AuthToken = secret
        }

        gsConn := firstConn
        backoff := time.Second
        const maxBackoff = 30 * time.Second
        for peerIdx := 0; ; peerIdx++ {
                if gsConn == nil {
                        // Re-register with the relay. The previous listener has
                        // been closed (gsConn.Close() below), so the relay
                        // should accept the new _gs_listen packet.
                        //
                        // If we get BAD_AUTH (relay hasn't noticed the disconnect
                        // yet, or the session is still being cleaned up), we
                        // retry with exponential backoff: 1s, 2s, 4s, 8s, ...
                        // capped at 30s. This is much better than the old
                        // fixed 2s retry which wasn't enough for the relay's
                        // cleanup window.
                        copts := *opts
                        c, err := gsconn.Dial(secret, gsconn.ModeListen, &copts)
                        if err != nil {
                                fmt.Fprintf(os.Stderr, "[gs-netcat] multi-peer: listen failed (retry in %v): %v\n", backoff, err)
                                time.Sleep(backoff)
                                backoff *= 2
                                if backoff > maxBackoff {
                                        backoff = maxBackoff
                                }
                                continue
                        }
                        // Success — reset backoff for the next failure cycle.
                        backoff = time.Second
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
                // v0.1.10 fix: previously this was 3 seconds, which created
                // a long window where the client couldn't reconnect (the
                // user saw "TLS-SRP handshake EOF" if they tried during
                // this window). The exponential backoff above already
                // handles BAD_AUTH gracefully, so we don't need a long
                // upfront delay — 500ms is enough for the relay's TCP
                // teardown to propagate without making the user wait.
                time.Sleep(500 * time.Millisecond)
        }
}

// silence unused-import warning if gskdf is not otherwise referenced.
var _ = gskdf.DeriveAuthToken
