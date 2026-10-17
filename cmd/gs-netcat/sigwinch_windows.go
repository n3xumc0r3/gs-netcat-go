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

// watchWindowSize polls GetConsoleScreenBufferInfo every 250ms and
// emits a resize event when the dimensions change.
//
// v0.1.20: hysteresis + debounce to suppress spurious resize events.
//
// PROBLEM: GetConsoleScreenBufferInfo's srWindow (visible viewport)
// can oscillate by 1 pixel during normal Windows Terminal usage:
//   - scrollback buffer changes when output is written
//   - zoom level changes (Ctrl+Wheel) momentarily report intermediate sizes
//   - Alt+Enter fullscreen transition reports in-between sizes
//   - terminal snap-to-edge can report 1-pixel-off sizes during drag
//
// Each spurious resize event is sent to the server as a WSIZE in-band
// packet. The C server applies it via TIOCSWINSZ → bash receives
// SIGWINCH → readline redraws the prompt. At 250ms polling this can
// fire 4x/second, causing:
//   - flickering prompt on the client
//   - bash/readline state corruption (visible as "stray characters")
//   - in extreme cases, readline deadlocks mid-redraw (the user's
//     reported "freeze after a few commands")
//
// FIX: two-layer filtering
//   1. Hysteresis: ignore changes of ≤2 pixels in either dimension.
//      Real user-driven resizes are typically >2 pixels; 1-2 pixel
//      oscillations are always noise.
//   2. Debounce: after a real change is detected, wait 200ms for
//      the size to stabilize before emitting the event. This coalesces
//      a burst of resize events (e.g. during a window drag) into one
//      final event with the settled size.
func watchWindowSize() <-chan struct{} {
        ch := make(chan struct{}, 1)
        go func() {
                var prevCols, prevRows uint16
                // Initialize with the current size so we don't fire a spurious
                // resize event immediately.
                prevCols, prevRows = gspty.GetStdinWindowSize()

                // hysteresis threshold: changes ≤ this many pixels in EITHER
                // dimension are ignored as noise.
                const hysteresis = 2

                // debounce: how long the size must be stable before we emit
                // a resize event. Coalesces drag/zoom bursts into one event.
                const debounce = 200 * time.Millisecond

                // pendingChange tracks whether we've seen a real (above-
                // hysteresis) change that hasn't yet stabilized for debounce.
                pendingChange := false
                var pendingCols, pendingRows uint16
                var pendingSince time.Time

                t := time.NewTicker(250 * time.Millisecond)
                defer t.Stop()
                for range t.C {
                        c, r := gspty.GetStdinWindowSize()

                        // Hysteresis: ignore changes ≤ hysteresis pixels.
                        dCol := absInt(int(c) - int(prevCols))
                        dRow := absInt(int(r) - int(prevRows))
                        if dCol <= hysteresis && dRow <= hysteresis {
                                // Within hysteresis band. If we had a pending
                                // change, check if it's stabilized to the
                                // current reading — if so, emit it.
                                if pendingChange {
                                        if c == pendingCols && r == pendingRows {
                                                if time.Since(pendingSince) >= debounce {
                                                        // Stable — emit.
                                                        prevCols, prevRows = c, r
                                                        pendingChange = false
                                                        select {
                                                        case ch <- struct{}{}:
                                                        default:
                                                        }
                                                }
                                                // else: still within debounce window,
                                                // keep waiting.
                                        } else {
                                                // Size changed again — restart
                                                // debounce timer with new size.
                                                pendingCols, pendingRows = c, r
                                                pendingSince = time.Now()
                                        }
                                }
                                continue
                        }

                        // Real change (> hysteresis). Start/restart debounce.
                        if !pendingChange || pendingCols != c || pendingRows != r {
                                pendingChange = true
                                pendingCols, pendingRows = c, r
                                pendingSince = time.Now()
                        } else if time.Since(pendingSince) >= debounce {
                                // Stable for debounce duration — emit.
                                prevCols, prevRows = c, r
                                pendingChange = false
                                select {
                                case ch <- struct{}{}:
                                default:
                                }
                        }
                }
        }()
        return ch
}

// absInt returns |x|. Tiny helper to avoid pulling in math.Abs (float).
func absInt(x int) int {
        if x < 0 {
                return -x
        }
        return x
}
