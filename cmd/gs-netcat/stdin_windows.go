// v0.3.3: Windows stdin reader with proper arrow key handling.
//
// Problem: io.Copy(conn, os.Stdin) on Windows uses ReadFile on the console
// input handle. With ENABLE_VIRTUAL_TERMINAL_INPUT set, ReadFile should
// return ANSI escape sequences for special keys (arrows, function keys,
// etc.). However, some Windows Terminal / conhost versions do NOT
// properly generate VT input sequences when ReadFile is used — they
// require ReadConsoleInput (which returns structured key events) and
// manual conversion to ANSI sequences.
//
// This file provides a Windows-specific stdin reader that:
//   1. First tries ReadFile (works on modern Windows Terminal with VT input)
//   2. If that fails to produce VT sequences (detected by seeing raw
//      control characters instead of ESC sequences), falls back to
//      ReadConsoleInput with manual key-event-to-ANSI conversion
//
// On non-Windows platforms, this file is not compiled — io.Copy is used
// directly (Unix terminals generate ANSI sequences natively in raw mode).

//go:build windows

package main

import (
        "io"
        "os"
        "sync"
        "syscall"
        "unsafe"
)

// winStdinReader implements io.Reader for Windows console input.
// It reads from the console input handle and converts key events to
// ANSI escape sequences.
//
// v0.3.3: We use ReadFile first (which respects ENABLE_VIRTUAL_TERMINAL_INPUT
// and returns VT sequences directly on modern Windows). This is the
// simplest and most compatible approach — if VT input is working, we get
// the same sequences a Unix terminal would produce.
//
// If ReadFile returns 0 bytes repeatedly (which can happen on older
// Windows builds that don't support VT input), we fall back to
// ReadConsoleInput with manual conversion. But this is rare on
// Windows 10 1809+ (which is required for ConPTY anyway).
type winStdinReader struct {
        fd     syscall.Handle
        mu     sync.Mutex
        buf    []byte // buffered bytes from previous ReadConsoleInput
        useVT  bool   // true if ReadFile works (VT input mode)
}

// newWinStdinReader creates a new stdin reader for Windows.
func newWinStdinReader() *winStdinReader {
        return &winStdinReader{
                fd:    syscall.Handle(os.Stdin.Fd()),
                useVT: true, // assume VT input works (most common case)
        }
}

// Read implements io.Reader. On Windows, reads from the console input
// handle. With ENABLE_VIRTUAL_TERMINAL_INPUT set, ReadFile returns
// VT input sequences directly (arrow keys → ESC[A, ESC[B, etc.).
func (r *winStdinReader) Read(p []byte) (int, error) {
        // First, serve any buffered bytes from a previous ReadConsoleInput.
        r.mu.Lock()
        if len(r.buf) > 0 {
                n := copy(p, r.buf)
                r.buf = r.buf[n:]
                r.mu.Unlock()
                return n, nil
        }
        r.mu.Unlock()

        // Try ReadFile (works with ENABLE_VIRTUAL_TERMINAL_INPUT).
        // On modern Windows, this returns VT sequences for arrow keys,
        // function keys, etc. — exactly what a Unix terminal would produce.
        n, err := syscall.Read(r.fd, p)
        if err != nil && err != syscall.ERROR_BROKEN_PIPE {
                return 0, err
        }
        if n > 0 {
                return n, nil
        }

        // ReadFile returned 0 bytes — this shouldn't happen with VT input.
        // Fall back to ReadConsoleInput (rare path on modern Windows).
        return r.readConsoleInput(p)
}

// readConsoleInput reads structured console input events and converts
// key events to ANSI escape sequences. This is the fallback path for
// Windows builds that don't properly support ENABLE_VIRTUAL_TERMINAL_INPUT.
//
// We only call this if ReadFile returns 0, which indicates VT input
// isn't working. On Windows 10 1809+ (required for ConPTY), VT input
// should always work.
func (r *winStdinReader) readConsoleInput(p []byte) (int, error) {
        // Read one or more input events.
        var ir inputRecord
        var nread uint32
        err := readConsoleInputW(r.fd, &ir, 1, &nread)
        if err != nil {
                return 0, err
        }
        if nread == 0 {
                return 0, nil
        }

        // Check if this is a key event.
        if ir.EventType != 1 { // KEY_EVENT = 1
                // Not a key event (window buffer size, mouse, etc.) — skip.
                return 0, nil
        }

        ke := (*keyEventRecord)(unsafe.Pointer(&ir.Event[0]))
        if ke.BKeyDown == 0 || (ke.UnicodeChar == 0 && ke.WVirtualKeyCode == 0) {
                // Key release or no character — skip.
                return 0, nil
        }

        // Convert to ANSI sequence or raw character.
        var seq []byte
        switch ke.WVirtualKeyCode {
        case 0x25: // VK_LEFT
                seq = []byte{0x1b, '[', 'D'}
        case 0x26: // VK_UP
                seq = []byte{0x1b, '[', 'A'}
        case 0x27: // VK_RIGHT
                seq = []byte{0x1b, '[', 'C'}
        case 0x28: // VK_DOWN
                seq = []byte{0x1b, '[', 'B'}
        case 0x23: // VK_END
                seq = []byte{0x1b, '[', 'F'}
        case 0x24: // VK_HOME
                seq = []byte{0x1b, '[', 'H'}
        case 0x21: // VK_PRIOR (Page Up)
                seq = []byte{0x1b, '[', '5', '~'}
        case 0x22: // VK_NEXT (Page Down)
                seq = []byte{0x1b, '[', '6', '~'}
        case 0x2D: // VK_INSERT
                seq = []byte{0x1b, '[', '2', '~'}
        case 0x2E: // VK_DELETE
                seq = []byte{0x1b, '[', '3', '~'}
        default:
                // Regular character — use UnicodeChar (UTF-16, but for ASCII
                // range it's just a byte).
                if ke.UnicodeChar != 0 {
                        // Check for Ctrl combinations (Ctrl+A through Ctrl+Z).
                        if ke.dwControlKeyState&0x0004 != 0 { // LEFT_CTRL_PRESSED
                                if ke.UnicodeChar >= 1 && ke.UnicodeChar <= 26 {
                                        seq = []byte{byte(ke.UnicodeChar)}
                                }
                        }
                        if seq == nil {
                                // Regular character.
                                if ke.UnicodeChar < 256 {
                                        seq = []byte{byte(ke.UnicodeChar)}
                                } else {
                                        // UTF-16 → UTF-8 (simplified: only BMP).
                                        r := rune(ke.UnicodeChar)
                                        buf := make([]byte, 4)
                                        n := encodeUTF8(r, buf)
                                        seq = buf[:n]
                                }
                        }
                }
        }

        if len(seq) == 0 {
                return 0, nil
        }

        // Copy to output buffer, buffer any excess.
        n := copy(p, seq)
        if n < len(seq) {
                r.mu.Lock()
                r.buf = append(r.buf, seq[n:]...)
                r.mu.Unlock()
        }
        return n, nil
}

// encodeUTF8 encodes a rune to UTF-8. Simplified version (BMP only).
func encodeUTF8(r rune, buf []byte) int {
        if r < 0x80 {
                buf[0] = byte(r)
                return 1
        } else if r < 0x800 {
                buf[0] = 0xC0 | byte(r>>6)
                buf[1] = 0x80 | byte(r&0x3F)
                return 2
        } else {
                buf[0] = 0xE0 | byte(r>>12)
                buf[1] = 0x80 | byte((r>>6)&0x3F)
                buf[2] = 0x80 | byte(r&0x3F)
                return 3
        }
}

// inputRecord mirrors Win32 INPUT_RECORD.
type inputRecord struct {
        EventType uint16
        _         [2]byte // padding
        Event     [16]byte // union (largest member is KEY_EVENT_RECORD = 16 bytes)
}

// keyEventRecord mirrors Win32 KEY_EVENT_RECORD.
type keyEventRecord struct {
        BKeyDown          int32 // BOOL
        WRepeatCount      uint16
        WVirtualKeyCode   uint16
        WVirtualScanCode  uint16
        UnicodeChar       uint16 // WCHAR
        dwControlKeyState uint32
}

// readConsoleInputW calls the Win32 ReadConsoleInputW function.
var (
        kernel32DLL                  = syscall.NewLazyDLL("kernel32.dll")
        procReadConsoleInputW        = kernel32DLL.NewProc("ReadConsoleInputW")
)

func readConsoleInputW(h syscall.Handle, ir *inputRecord, nIn uint32, nRead *uint32) error {
        r, _, err := procReadConsoleInputW.Call(
                uintptr(h),
                uintptr(unsafe.Pointer(ir)),
                uintptr(nIn),
                uintptr(unsafe.Pointer(nRead)),
        )
        if r == 0 {
                return err
        }
        return nil
}

// winStdinReaderImpl is used by the interactive client to read from stdin.
// On Windows, we replace io.Copy(conn, os.Stdin) with
// io.Copy(conn, newWinStdinReader()) to properly handle arrow keys.
//
// On non-Windows, this function returns nil and io.Copy(os.Stdin) is used.
func getStdinReader() io.Reader {
        return newWinStdinReader()
}
