// Stub PTY implementation for platforms where native PTY support has
// not yet been implemented (currently: macOS, *BSD). All entry points
// return ErrNoPTY so the caller can fall back to a non-PTY pipe.
//
// On these platforms raw-mode and window-size helpers also degrade
// gracefully: SetRawStdin is a no-op (input is left in its default
// cooked mode), GetStdinWindowSize returns (80, 24).
//
// Adding native macOS/BSD PTY support requires using openpty(3) or
// the TIOCPTYGNAME/TIOCPTYUNL ioctls on macOS — a follow-up task.

//go:build darwin || freebsd || netbsd || openbsd

package gspty

import (
        "os"
)

// Spawn always returns ErrNoPTY on platforms without native PTY support.
func Spawn(cmd string, cols, rows uint16) (*PTY, error) {
        return nil, ErrNoPTY
}

// PTY is a placeholder type so that callers compiling against this
// stub don't need conditional code. No methods produce useful output.
type PTY struct {
        Master *os.File
}

// SetWindowSize is a no-op stub.
func (p *PTY) SetWindowSize(cols, rows uint16) error { return nil }

// Write is a no-op stub returning 0 bytes written. On platforms
// without PTY support the interactive path is not reachable (Spawn
// returns ErrNoPTY before the pipe is set up).
func (p *PTY) Write(b []byte) (int, error) { return 0, nil }

// Wait is a no-op stub.
func (p *PTY) Wait() error { return nil }

// PID is a no-op stub returning 0.
func (p *PTY) PID() int { return 0 }

// Close is a no-op stub.
func (p *PTY) Close() error { return nil }
