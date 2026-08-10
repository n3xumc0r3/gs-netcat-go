// Window-size polling for Windows. Windows has no SIGWINCH equivalent;
// the console emits WINDOW_BUFFER_SIZE_EVENTs but they are only delivered
// to processes reading from the console input loop. We poll the size
// every 250ms instead — fast enough for interactive use, cheap enough
// not to consume CPU.

//go:build windows

package main

import (
	"time"

	"github.com/gsport/gs-netcat/internal/gspty"
)

func watchWindowSize() <-chan struct{} {
	ch := make(chan struct{}, 1)
	go func() {
		var prevCols, prevRows uint16
		// Initialize with the current size so we don't fire a spurious
		// resize event immediately.
		prevCols, prevRows = gspty.GetStdinWindowSize()
		t := time.NewTicker(250 * time.Millisecond)
		defer t.Stop()
		for range t.C {
			c, r := gspty.GetStdinWindowSize()
			if c != prevCols || r != prevRows {
				prevCols, prevRows = c, r
				select {
				case ch <- struct{}{}:
				default:
				}
			}
		}
	}()
	return ch
}
