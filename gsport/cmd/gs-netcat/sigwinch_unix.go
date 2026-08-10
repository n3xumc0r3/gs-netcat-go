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
func watchWindowSize() <-chan struct{} {
	ch := make(chan struct{}, 1)
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGWINCH)
	go func() {
		for range sigCh {
			select {
			case ch <- struct{}{}:
			default:
				// drop if the caller hasn't drained the previous event
			}
		}
	}()
	return ch
}

// _ = gspty keeps the import valid even if the file is the only user
// of gspty in some future refactor.
var _ = gspty.GetStdinWindowSize
