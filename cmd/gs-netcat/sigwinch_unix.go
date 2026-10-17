// SIGWINCH handling for gs-netcat. On Unix a real SIGWINCH is delivered
// when the terminal is resized; on Windows there is no equivalent signal,
// so we poll GetStdinWindowSize every 250ms and emit a resize event when
// the dimensions change.

//go:build !windows

package main

import (
        "os"
        "os/signal"
        "syscall"

        "github.com/gsport/gs-netcat/internal/gspty"
)

// watchWindowSize returns a channel that fires whenever the local
// terminal's window size changes. The caller is responsible for
// re-querying GetStdinWindowSize and sending a WSIZE message to the
// peer when the channel fires.
//
// On Unix this wraps signal.Notify(SIGWINCH); on Windows (sigwinch_windows.go)
// it polls GetStdinWindowSize every 250ms.
//
// v0.1.28 (audit-1 bug #3 + audit-4 bug #4, HIGH/MEDIUM): the caller
// MUST call stop() when done to tear down the SIGWINCH goroutine.
// Previously the goroutine leaked permanently per interactive client
// session. Each leaked goroutine held a reference to the closed conn
// (via the captured `conn` variable in the resizeCh goroutine in
// main.go), preventing GC. On long-lived processes or in reconnect
// loops this was an unbounded leak.
func watchWindowSize() (<-chan struct{}, func()) {
        ch := make(chan struct{}, 1)
        sigCh := make(chan os.Signal, 1)
        signal.Notify(sigCh, syscall.SIGWINCH)

        done := make(chan struct{})
        stopOnce := func() {
                // signal.Stop unregisters sigCh from receiving SIGWINCH; then
                // close(done) tells the goroutine to exit. The goroutine's
                // for-range over sigCh will block forever after signal.Stop
                // (no more sends), but the close(done) lets it exit via select.
                signal.Stop(sigCh)
                close(done)
        }

        go func() {
                for {
                        select {
                        case <-done:
                                return
                        case <-sigCh:
                                select {
                                case ch <- struct{}{}:
                                default:
                                        // drop if the caller hasn't drained the previous event
                                }
                        }
                }
        }()

        return ch, stopOnce
}

// _ = gspty keeps the import valid even if the file is the only user
// of gspty in some future refactor.
var _ = gspty.GetStdinWindowSize
