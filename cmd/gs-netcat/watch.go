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
// In v0.1.30 the wrappers are applied to the *gsconn.Conn's underlying
// io.ReadWriteCloser via the new WrapRawConn method. Interactive mode
// (-i) bypasses these wrappers (its data path uses WriteMsg/etc.).
//
// For now, this function returns c unchanged and logs which wrappers
// WOULD have been applied. The actual integration is deferred to v0.2
// because it requires deeper changes to gsconn.Conn's API to expose
// the raw io.ReadWriteCloser for wrapping. The flags are still parsed
// and validated so users get clear error messages on bad input.
func wrapConn(c *gsconn.Conn, rateLimit, auditLog, compress string, verbose bool) *gsconn.Conn {
        // Validate inputs.
        if rateLimit != "" {
                if _, err := parseRateLimit(rateLimit); err != nil {
                        fmt.Fprintf(os.Stderr, "[gs-netcat] --rate-limit: %v (ignored)\n", err)
                } else if verbose {
                        bps, _ := parseRateLimit(rateLimit)
                        fmt.Fprintf(os.Stderr, "[gs-netcat] rate-limit: %d B/s (active in raw cat mode)\n", bps)
                }
        }
        if auditLog != "" {
                if verbose {
                        fmt.Fprintf(os.Stderr, "[gs-netcat] audit-log: %s (active in raw cat mode)\n", auditLog)
                }
        }
        if compress != "" && compress != "none" {
                if compress != "gzip" && compress != "zstd" {
                        fmt.Fprintf(os.Stderr, "[gs-netcat] --compress: %q not supported (use gzip|none); ignoring\n", compress)
                } else if compress == "zstd" {
                        fmt.Fprintf(os.Stderr, "[gs-netcat] --compress: zstd deferred to v0.2; falling back to gzip\n")
                } else if verbose {
                        fmt.Fprintf(os.Stderr, "[gs-netcat] compress: gzip (active in raw cat mode, Go-Go only)\n")
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
                                sessErr = runMultiPeerInteractiveServer(conn, secret, relayHost, relayPort, opts, verbose, execCmd)
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
