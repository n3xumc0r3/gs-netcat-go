// Windows terminal raw-mode and window-size helpers for gspty.
//
// On Windows there is no termios API. Raw mode is approximated by:
//   - GetConsoleMode(stdin) → save current flags
//   - SetConsoleMode(stdin, mode & ~(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT
//                    | ENABLE_PROCESSED_INPUT) | ENABLE_VIRTUAL_TERMINAL_INPUT)
//
//     IMPORTANT (v0.1.10 fix): previously this function set the mode to
//     ONLY ENABLE_VIRTUAL_TERMINAL_INPUT, clearing every other flag.
//     Clearing ENABLE_EXTENDED_FLAGS reverts the console to legacy
//     behaviour, which on modern Windows Terminal / conhost causes
//     visible glitches: the screen appears to be cleared and the
//     console may briefly enter an alternate-buffer-like state. The
//     user reported this as "окно консоли переоткрывается с затиранием,
//     ещё и на весь экран" — the C original never had this because its
//     stty_set_raw() only clears ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT
//     | ENABLE_PROCESSED_INPUT.
//
// Window size is queried via GetConsoleScreenBufferInfo on the OUTPUT
// handle (STD_OUTPUT_HANDLE), NOT on os.Stdin (STD_INPUT_HANDLE).
//
// IMPORTANT (v0.1.10 fix): MSDN documents GetConsoleScreenBufferInfo as
// requiring a handle to a console screen buffer (output). Calling it on
// an input handle returns "undefined" data — in practice on conhost the
// returned srWindow values are stale or zero, which caused
// watchWindowSize() to detect spurious size changes every 250ms and
// flood the server with WSIZE packets. Each WSIZE triggered a
// ResizePseudoConsole on the server's ConPTY, which made cmd.exe redraw
// its prompt — appearing on the client as dozens of empty
// "C:\Users\...>" lines. Using STD_OUTPUT_HANDLE gives stable, correct
// values.

//go:build windows

package gspty

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// Console mode flags (from wincon.h).
const (
	enableProcessedInput       uint32 = 0x0001
	enableLineInput            uint32 = 0x0002
	enableEchoInput            uint32 = 0x0004
	enableWindowInput          uint32 = 0x0008
	enableMouseInput           uint32 = 0x0010
	enableInsertMode           uint32 = 0x0020
	enableQuickEditMode        uint32 = 0x0040
	enableExtendedFlags        uint32 = 0x0080
	enableAutoPosition         uint32 = 0x0100
	enableVirtualTerminalInput uint32 = 0x0200
)

// stdHandle constants for GetStdHandle (winbase.h).
const (
	stdInputHandle  = ^uintptr(10) + 1 // (uintptr)(^uintptr(10) + 1) == (uintptr)(-10)
	stdOutputHandle = ^uintptr(11) + 1 // == (uintptr)(-11)
	stdErrorHandle  = ^uintptr(12) + 1 // == (uintptr)(-12)
)

// rawModeClearMask is the set of flags we clear when entering raw mode.
// We deliberately do NOT clear:
//   - ENABLE_WINDOW_INPUT (window-resize events)
//   - ENABLE_MOUSE_INPUT (mouse events — harmless, preserved for parity)
//   - ENABLE_INSERT_MODE / ENABLE_QUICK_EDIT_MODE / ENABLE_EXTENDED_FLAGS
//     (clearing ENABLE_EXTENDED_FLAGS reverts the console to legacy mode,
//     which on Windows Terminal causes a visible screen-clear glitch —
//     the v0.1.9 "окно переоткрывается с затиранием" bug)
//   - ENABLE_AUTO_POSITION
//
// We DO clear:
//   - ENABLE_ECHO_INPUT (the shell on the remote side echoes; if we
//     also echo locally the user sees double characters)
//   - ENABLE_LINE_INPUT (we want every keystroke, not cooked lines)
//   - ENABLE_PROCESSED_INPUT (Ctrl-C should be delivered as a key event,
//     not as a SIGINT-equivalent that terminates the process — same as
//     stty -isig on Unix)
const rawModeClearMask = enableEchoInput | enableLineInput | enableProcessedInput

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
//
// v0.1.10 fix: previously this set the mode to ONLY
// ENABLE_VIRTUAL_TERMINAL_INPUT, clearing every other flag. Clearing
// ENABLE_EXTENDED_FLAGS reverted the console to legacy mode and caused
// visible screen-clearing / "fullscreen" glitches on Windows Terminal.
// Now we preserve all flags except ECHO / LINE / PROCESSED, and OR in
// ENABLE_VIRTUAL_TERMINAL_INPUT. This matches the C original's
// stty_set_raw() behaviour exactly.
func SetRawStdin() (*SavedTermios, error) {
	fd := syscall.Handle(os.Stdin.Fd())
	var mode uint32
	r, _, err := procGetConsoleMode.Call(uintptr(fd), uintptr(unsafe.Pointer(&mode)))
	if r == 0 {
		// Not a console (e.g. pipe). No-op.
		return &SavedTermios{fd: fd, saved: false}, nil
	}
	saved := &SavedTermios{fd: fd, mode: mode, saved: true}
	// Preserve all existing flags except the three we must disable for
	// raw mode, then add ENABLE_VIRTUAL_TERMINAL_INPUT so VT sequences
	// (arrow keys, function keys, Ctrl- combos) arrive as escape codes
	// instead of cooked key events.
	newMode := (mode &^ rawModeClearMask) | enableVirtualTerminalInput
	r, _, err = procSetConsoleMode.Call(uintptr(fd), uintptr(newMode))
	if r == 0 {
		return nil, fmt.Errorf("gspty: SetConsoleMode raw: %w", err)
	}
	return saved, nil
}

// GetStdinWindowSize returns the terminal's current visible size.
// Returns (80, 24) on any error (matching the C original's fallback).
//
// v0.1.10 fix: previously this called GetConsoleScreenBufferInfo on
// os.Stdin.Fd() (STD_INPUT_HANDLE). MSDN documents that function as
// requiring a screen-buffer handle (output); on an input handle the
// returned srWindow values are undefined and can vary between calls
// even when the actual window size hasn't changed. That instability
// caused watchWindowSize() to fire spurious WSIZE events every 250ms,
// which made the server's ConPTY resize and cmd.exe redraw its prompt
// repeatedly — the user saw dozens of empty
// "C:\Users\Артём\Desktop>" lines on the client.
//
// We now query the screen-buffer info via STD_OUTPUT_HANDLE, which is
// what GetConsoleScreenBufferInfo is designed for and returns stable
// values.
func GetStdinWindowSize() (cols, rows uint16) {
	// GetStdHandle(STD_OUTPUT_HANDLE) returns the active screen buffer
	// handle. We use it for the buffer-info query.
	h, _, _ := procGetStdHandle.Call(stdOutputHandle)
	if h == 0 {
		return 80, 24
	}
	var info consoleScreenBufferInfo
	r, _, _ := procGetConsoleScreenBufferInfo.Call(h, uintptr(unsafe.Pointer(&info)))
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
