// v0.1.30: Conn wrappers and watch-loop.
//
// wrapConn applies rate-limit / audit-log / compress wrappers around a
// gsconn.Conn's underlying io.ReadWriteCloser. Returns the (possibly
// wrapped) conn.
//
// runWatchLoop is the foreground auto-reconnect loop for --watch.
package main

import (
        "fmt"
        "io"
        "os"
        "os/exec"
        "sync/atomic"
        "time"

        "github.com/gsport/gs-netcat/internal/gsconn"
)

// wrapConn wraps c with rate-limit / audit-log / compress layers as
// configured by the corresponding CLI flags. If none of the flags are
// set, c is returned unchanged.
//
// v0.2.0: Now actually wires the wrappers via gsconn.Conn.WrapRawConn.
// Works for BOTH raw cat-mode AND interactive mode (-i), since the
// wrappers sit below the gsconn.Conn abstraction.
//
// Wrapper order (innermost to outermost):
//   1. Audit-log (records all I/O before any transformation)
//   2. Compress (transforms bytes — applied AFTER audit for accurate recording)
//   3. Rate-limit (throttles the post-compression bytes)
//
// This order means:
//   - Audit-log sees the actual bytes the user typed (before compression)
//   - Rate-limit counts compressed bytes (so 100K compressed = ~10K real)
//   - Compress is applied to all data including audit's tee (if audit is below compress)
func wrapConn(c *gsconn.Conn, rateLimit, auditLog, compress string, verbose bool) *gsconn.Conn {
        // Validate inputs.
        if rateLimit != "" {
                bps, err := parseRateLimit(rateLimit)
                if err != nil {
                        fmt.Fprintf(os.Stderr, "[gs-netcat] --rate-limit: %v (ignored)\n", err)
                } else if bps > 0 {
                        if verbose {
                                fmt.Fprintf(os.Stderr, "[gs-netcat] rate-limit: %d B/s (active)\n", bps)
                        }
                        // Outermost wrapper — throttles whatever the layers below produce.
                        c.WrapRawConn(newRateLimitedConn(c.RawConn(), bps))
                }
        }
        if auditLog != "" {
                ac, err := newAuditConn(c.RawConn(), auditLog)
                if err != nil {
                        fmt.Fprintf(os.Stderr, "[gs-netcat] --audit-log: %v (ignored)\n", err)
                } else {
                        if verbose {
                                fmt.Fprintf(os.Stderr, "[gs-netcat] audit-log: %s (active)\n", auditLog)
                        }
                        c.WrapRawConn(ac)
                }
        }
        if compress != "" && compress != "none" {
                if compress == "zstd" || compress == "gzip" {
                        if verbose {
                                fmt.Fprintf(os.Stderr, "[gs-netcat] compress: %s (active, Go-Go only)\n", compress)
                        }
                        cc, err := newCompressedConnByName(c.RawConn(), compress)
                        if err == nil {
                                c.WrapRawConn(cc)
                        } else {
                                fmt.Fprintf(os.Stderr, "[gs-netcat] --compress: %v (ignored)\n", err)
                        }
                } else {
                        fmt.Fprintf(os.Stderr, "[gs-netcat] --compress: %q not supported (use gzip|zstd|none); ignoring\n", compress)
                }
        }
        return c
}

// runWatchLoop is the --watch foreground auto-reconnect loop. It runs
// dialWithPortFallback + the session code, then on disconnect retries
// with exponential backoff (1s, 2s, 4s, ..., capped at 60s).
//
// If --retry N is set (N > 0), the loop exits after N failed dial
// attempts (NOT after N successful sessions — the loop continues
// forever on successful sessions until Ctrl-C). If --retry 0 (default),
// the loop runs forever (until Ctrl-C / SIGTERM).
//
// All other CLI flags (interactive, wantPwd, etc.) are passed through
// to each session attempt.
func runWatchLoop(
        secret string, mode gsconn.Mode, opts *gsconn.Options,
        relayHost string, relayPort int,
        userPickedRelay bool, verbose bool,
        maxRetries int, listen, interactive, wantPwd, wantIDS bool,
        execCmd string,
        maxSessionTime int, postExec, outFile string,
        progress bool, auditLog, rateLimit, compress string,
        maxPeers int,
) error {
        backoff := time.Second
        const maxBackoff = 60 * time.Second
        attempts := 0

        for {
                // Try to establish a connection.
                conn, err := dialWithPortFallback(secret, mode, opts, relayHost, relayPort, userPickedRelay, verbose)
                if err != nil {
                        attempts++
                        if maxRetries > 0 && attempts >= maxRetries {
                                return fmt.Errorf("--watch: gave up after %d dial attempts (last err: %w)", attempts, err)
                        }
                        fmt.Fprintf(os.Stderr, "[gs-netcat] --watch: dial failed: %v (retry in %v, attempt %d)\n",
                                err, backoff, attempts)
                        time.Sleep(backoff)
                        backoff *= 2
                        if backoff > maxBackoff {
                                backoff = maxBackoff
                        }
                        continue
                }
                // Successful dial — reset backoff.
                backoff = time.Second
                attempts = 0

                if verbose {
                        fmt.Fprintf(os.Stderr, "[gs-netcat] --watch: connected (role=%s)\n", roleStr(conn.Role()))
                }

                // v0.1.30: --max-session-time. Install a timer that closes conn.
                if maxSessionTime > 0 {
                        go func() {
                                t := time.NewTimer(time.Duration(maxSessionTime) * time.Second)
                                defer t.Stop()
                                <-t.C
                                fmt.Fprintf(os.Stderr, "[gs-netcat] --watch: max-session-time %ds reached, closing\n", maxSessionTime)
                                _ = conn.Close()
                        }()
                }

                // Run the session (interactive or raw cat-mode).
                // We replicate just enough of run() to drive a single session.
                var sessErr error
                if interactive {
                        if listen {
                                sessErr = runMultiPeerInteractiveServer(conn, secret, relayHost, relayPort, opts, verbose, execCmd, maxPeers)
                        } else {
                                // Client side: run once, exit on disconnect.
                                sessErr = runInteractive(conn, verbose, listen, wantPwd, wantIDS, execCmd)
                        }
                } else {
                        // Raw cat-mode — single session.
                        sessErr = runRawCatSession(conn, verbose, listen, outFile, progress)
                }

                conn.Close()

                // --post-exec hook.
                if postExec != "" {
                        cmd := exec.Command("sh", "-c", postExec)
                        cmd.Stdout = os.Stderr
                        cmd.Stderr = os.Stderr
                        if err := cmd.Run(); err != nil {
                                fmt.Fprintf(os.Stderr, "[gs-netcat] post-exec error: %v\n", err)
                        }
                }

                if verbose {
                        fmt.Fprintf(os.Stderr, "[gs-netcat] --watch: session ended (%v), reconnecting in %v\n", sessErr, backoff)
                }
                time.Sleep(backoff)
                backoff *= 2
                if backoff > maxBackoff {
                        backoff = maxBackoff
                }
        }
}

// runRawCatSession is the raw cat-mode data plumbing extracted from
// run() for reuse by runWatchLoop. It pipes stdin <-> conn <-> stdout
// (or outFile if set) until the remote closes.
//
// v0.1.30: this is a simplified version that doesn't replicate the
// full CloseWrite / gotRemoteData heuristic from run(). It just does
// bidirectional io.Copy and exits when either side closes.
func runRawCatSession(conn *gsconn.Conn, verbose bool, listen bool, outFile string, progress bool) error {
        outWriter := io.Writer(os.Stdout)
        if outFile != "" && outFile != "-" {
                f, err := os.Create(outFile)
                if err != nil {
                        return fmt.Errorf("-o: %w", err)
                }
                defer f.Close()
                outWriter = f
        }

        var totalWritten atomic.Int64
        var totalRead atomic.Int64

        var stopProgress func()
        if progress {
                stopProgress = startProgressBar(&totalWritten, &totalRead, 0)
                defer stopProgress()
        }

        stdinDone := make(chan struct{})
        remoteClosed := make(chan struct{})
        go func() {
                n, _ := io.Copy(conn, os.Stdin)
                totalWritten.Store(n)
                close(stdinDone)
        }()
        go func() {
                n, _ := io.Copy(outWriter, conn)
                totalRead.Store(n)
                close(remoteClosed)
        }()

        <-remoteClosed
        conn.Close()
        <-stdinDone
        return nil
}
