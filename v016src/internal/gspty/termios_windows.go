// Windows terminal raw-mode and window-size helpers for gspty.
//
// On Windows there is no termios API. Raw mode is approximated by:
//   - GetConsoleMode(stdin) → save current flags
//   - SetConsoleMode(stdin, ENABLE_VIRTUAL_TERMINAL_INPUT)
//     This is the closest Windows equivalent of stty_set_raw(): VT
//     input mode disables line editing, echo, and signal generation
//     (Ctrl-C is delivered as a key event rather than raising
//     SIGINT), letting keystrokes flow through verbatim.
//   - On restore, SetConsoleMode(stdin, saved_flags).
//
// Window size is queried via GetConsoleScreenBufferInfo. The relevant
// dimension is srWindow (the visible viewport) — Win32 distinguishes
// between the screen buffer (which can be larger than the window)
// and the window, but the C original uses the visible terminal size.

//go:build windows

package gspty

import (
        "fmt"
        "os"
        "syscall"
        "unsafe"
)

// SavedTermios holds the original console mode so it can be restored.
type SavedTermios struct {
        fd    syscall.Handle
        mode  uint32
        saved bool
}

// SaveStdin captures the current console mode of stdin for later
// restoration. If stdin is not a console, returns a SavedTermios with
// saved=false so RestoreStdin is a no-op.
func SaveStdin() (*SavedTermios, error) {
        fd := syscall.Handle(os.Stdin.Fd())
        var mode uint32
        r, _, _ := procGetConsoleMode.Call(uintptr(fd), uintptr(unsafe.Pointer(&mode)))
        if r == 0 {
                // Not a console (e.g. pipe). Treat as no-op.
                return &SavedTermios{fd: fd, saved: false}, nil
        }
        return &SavedTermios{fd: fd, mode: mode, saved: true}, nil
}

// RestoreStdin restores the console mode captured by SaveStdin.
// No-op if the original was not a console.
func (s *SavedTermios) RestoreStdin() error {
        if s == nil || !s.saved {
                return nil
        }
        r, _, err := procSetConsoleMode.Call(uintptr(s.fd), uintptr(s.mode))
        if r == 0 {
                return fmt.Errorf("gspty: SetConsoleMode restore: %w", err)
        }
        return nil
}

// SetRawStdin puts stdin into raw mode (the Windows equivalent).
// Returns the previous state for restoration on exit.
func SetRawStdin() (*SavedTermios, error) {
        fd := syscall.Handle(os.Stdin.Fd())
        var mode uint32
        r, _, err := procGetConsoleMode.Call(uintptr(fd), uintptr(unsafe.Pointer(&mode)))
        if r == 0 {
                // Not a console (e.g. pipe). No-op.
                return &SavedTermios{fd: fd, saved: false}, nil
        }
        saved := &SavedTermios{fd: fd, mode: mode, saved: true}
        // Raw mode on Windows = VT input only. This is closer to "no
        // line editing, no echo" than disabling ENABLE_PROCESSED_INPUT
        // (the latter would also drop Ctrl-C handling, which is what
        // we want for interactive shells).
        r, _, err = procSetConsoleMode.Call(uintptr(fd), uintptr(ENABLE_VIRTUAL_TERMINAL_INPUT))
        if r == 0 {
                return nil, fmt.Errorf("gspty: SetConsoleMode raw: %w", err)
        }
        return saved, nil
}

// GetStdinWindowSize returns the terminal's current visible size.
// Returns (80, 24) on any error (matching the C original's fallback).
func GetStdinWindowSize() (cols, rows uint16) {
        fd := syscall.Handle(os.Stdin.Fd())
        var info consoleScreenBufferInfo
        r, _, _ := procGetConsoleScreenBufferInfo.Call(uintptr(fd), uintptr(unsafe.Pointer(&info)))
        if r == 0 {
                return 80, 24
        }
        cols = uint16(info.Window.Right - info.Window.Left + 1)
        rows = uint16(info.Window.Bottom - info.Window.Top + 1)
        if cols == 0 {
                cols = 80
        }
        if rows == 0 {
                rows = 24
        }
        return cols, rows
}
