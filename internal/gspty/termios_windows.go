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

// SetRawStdin puts stdin into raw mode (the Windows equivalent) and
// enables Virtual Terminal Processing on stdout so that ANSI escape
// sequences emitted by the remote shell (cursor positioning, color,
// clear-screen, etc. — which ConPTY produces in abundance after every
// ResizePseudoConsole) are interpreted by the local console host
// instead of being printed verbatim as raw text with extra newlines.
//
// Without ENABLE_VIRTUAL_TERMINAL_PROCESSING on stdout, the remote
// cmd.exe's redraw sequences (e.g. "\x1b[2J\x1b[H" sent after every
// resize) appear to the user as a flood of empty lines — Bug 3 in
// v0.1.9. On Windows 10+ this flag is the default for console hosts
// but is NOT set when stdin has been switched to VT-input mode (the
// console host treats the combination as "headless raw mode" and
// disables VT output as well). We re-enable it explicitly here.
//
// v0.1.21: REAL raw mode, not "VT input only".
//
// The previous version only set ENABLE_VIRTUAL_TERMINAL_INPUT and left
// the default input flags (ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT |
// ENABLE_PROCESSED_INPUT) enabled. That is NOT raw mode — Windows was
// still line-editing the input, echoing each keystroke, and processing
// Ctrl-C / Ctrl-S locally. Symptoms the user reported that this caused:
//
//   1. "Doubled characters" — every keystroke was echoed by BOTH the
//      local Windows console AND the remote bash PTY. The first 'l' in
//      'ls' was from Windows, the second from bash.
//
//   2. Readline hangs when prompt reaches bottom of window. Readline
//      sends cursor-positioning ANSI sequences to scroll / redraw; the
//      local Windows console's ENABLE_LINE_INPUT was intercepting
//      Enter as "submit line" instead of forwarding the raw \r to the
//      remote. Combined with ENABLE_ECHO_INPUT re-displaying partial
//      input, readline's redraw state machine desynced and blocked
//      waiting for a cursor-position report from the local console
//      (which never came because the input was buffered, not sent).
//
// The fix mirrors what ConPTY / OpenSSH's Windows port do: clear ALL
// the line-editing / echo / signal flags, then add ENABLE_VIRTUAL_TERMINAL_INPUT
// for VT input passthrough. ENABLE_EXTENDED_FLAGS is kept so that
// ENABLE_QUICK_EDIT_MODE (if the user had it on) doesn't get clobbered
// back on by the API.
//
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

        // Build raw-mode flag set.
        //
        // v0.1.22: also clear ENABLE_QUICK_EDIT_MODE and ENABLE_INSERT_MODE,
        // and explicitly set ENABLE_EXTENDED_FLAGS. This matches what
        // OpenSSH's Windows port does.
        //
        // WHY DISABLE QuickEdit:
        // QuickEdit mode (default ON in Windows 10/11) lets the user select
        // text in the console with the mouse. When a selection starts, the
        // console enters "selection mode" which PAUSES all console I/O:
        //   - keystrokes are queued but not delivered to ReadFile
        //   - output is buffered but not displayed
        // The user exits selection mode by pressing Esc or Enter, but during
        // the pause any in-flight keystrokes can be lost.
        //
        // This was the root cause of the user's "lost character" symptom:
        // the user typed 'ls', the first 'l' was delivered, then a stray
        // mouse click (or touchpad tap) entered selection mode, the 's' was
        // queued, when selection mode exited the 's' was lost (Windows
        // delivers a partial event batch in some cases).
        //
        // Disabling QuickEdit prevents this entire class of problems. The
        // user can still copy text via the system menu (right-click → Mark
        // on Windows 10, or via the title bar) but accidental clicks in the
        // console window no longer pause I/O.
        //
        // WHY DISABLE InsertMode:
        // Insert mode (also default ON) makes the console interpret Insert
        // key as a toggle between insert and overwrite. This can confuse
        // remote readline which has its own insert/overwrite state.
        //
        // WHY SET ENABLE_EXTENDED_FLAGS:
        // This is a meta-flag that tells Windows "the QuickEdit/InsertMode
        // bits are intentionally set". Without it, Windows ignores our
        // QuickEdit=0 / InsertMode=0 settings and uses the defaults
        // (QuickEdit=ON, InsertMode=ON), defeating the whole point.
        newMode := mode
        newMode |= ENABLE_EXTENDED_FLAGS        // meta-flag: respect the bits below
        newMode &^= ENABLE_ECHO_INPUT           // turn off local echo
        newMode &^= ENABLE_LINE_INPUT           // turn off line editing (readline gets raw bytes)
        newMode &^= ENABLE_PROCESSED_INPUT      // turn off Ctrl-C / Ctrl-S signal generation
        newMode &^= ENABLE_QUICK_EDIT_MODE      // turn off QuickEdit (prevents I/O freeze on mouse click)
        newMode &^= ENABLE_INSERT_MODE          // turn off Insert mode (don't confuse remote readline)
        newMode &^= ENABLE_MOUSE_INPUT          // v0.1.25: turn off mouse input — with VT input mode ON, Windows Terminal translates mouse clicks into SGR escape sequences (\x1b[<35;33;16M) which flood the remote readline and corrupt its state
        newMode |= ENABLE_VIRTUAL_TERMINAL_INPUT // VT input passthrough

        r, _, err = procSetConsoleMode.Call(uintptr(fd), uintptr(newMode))
        if r == 0 {
                return nil, fmt.Errorf("gspty: SetConsoleMode raw: %w", err)
        }
        // Bug 3 fix: ensure stdout has VT processing enabled so that
        // ANSI sequences from the remote shell are interpreted as
        // control sequences (cursor positioning, clear screen, color)
        // rather than printed as raw text — which previously caused
        // "excessive empty lines" on the client after the cmd.exe
        // prompt. We save stdout's mode so we can restore it on exit.
        enableStdoutVTProcessing()
        return saved, nil
}

// enableStdoutVTProcessing sets ENABLE_VIRTUAL_TERMINAL_PROCESSING
// (and the standard ENABLE_PROCESSED_OUTPUT + ENABLE_WRAP_AT_EOL_OUTPUT
// flags) on stdout. This is a best-effort, fire-and-forget call: if
// stdout isn't a console (e.g. piped to a file) or the SetConsoleMode
// call fails, we silently move on — the caller's data path is still
// correct, only the local interpretation of ANSI sequences is affected.
//
// The original stdout mode is NOT restored on exit because:
//   1. The process is exiting anyway and the console will reset.
//   2. If we restore, the LAST redraw sequences from the remote shell
//      (printed during our shutdown) would appear as garbage again.
func enableStdoutVTProcessing() {
        out := syscall.Handle(os.Stdout.Fd())
        var outMode uint32
        r, _, _ := procGetConsoleMode.Call(uintptr(out), uintptr(unsafe.Pointer(&outMode)))
        if r == 0 {
                // stdout isn't a console. Nothing to do.
                return
        }
        // OR in VT processing; keep the existing flags (wrap-at-eol,
        // processed-output) so we don't accidentally disable something
        // the user's terminal was relying on.
        newMode := outMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING | ENABLE_PROCESSED_OUTPUT
        // SetConsoleMode returns 0 on failure; we don't propagate the
        // error because VT output is a nice-to-have, not a correctness
        // requirement.
        _, _, _ = procSetConsoleMode.Call(uintptr(out), uintptr(newMode))
}

// GetStdinWindowSize returns the terminal's current visible size.
// Returns (80, 24) on any error (matching the C original's fallback).
//
// BUG FIX (v0.1.15): the previous version passed os.Stdin.Fd() to
// GetConsoleScreenBufferInfo. That API requires a console OUTPUT
// handle (hConsoleOutput), NOT an input handle. Passing stdin always
// fails with ERROR_INVALID_HANDLE (the call returns 0), so the code
// fell through to the `return 80, 24` fallback — EVERY Windows client
// reported 80x24 regardless of the actual window size.
//
// Net effect: the server created a ConPTY at 80x24, the remote shell
// formatted output for 80 columns, but the client's real terminal was
// e.g. 120 columns wide. VT cursor-positioning sequences (CUP, ED)
// emitted by the shell assumed 80-col layout and positioned the cursor
// at wrong columns on the wider client terminal — producing the
// "overwritten text" / "lines scramble" symptom the user reported.
//
// The function name "GetStdinWindowSize" is kept for source
// compatibility with the Unix build (where ioctl(TIOCGWINSZ) is done
// on stdin because stdin/stdout share the same tty device). On Windows
// the console input handle and screen buffer handle are distinct, so
// we query the screen buffer via stdout.
//
// Additional fix: if stdout is NOT a console (e.g. piped to a file),
// we fall back to trying stderr (which might still be a console), and
// only then to the 80x24 default. This covers the case where the user
// redirects stdout but still wants a sensible default.
func GetStdinWindowSize() (cols, rows uint16) {
        // Try stdout first — it's the most common console output handle.
        if c, r, ok := queryConsoleSize(os.Stdout.Fd()); ok {
                return c, r
        }
        // stdout isn't a console (maybe piped). Try stderr — if the user
        // only redirected stdout, stderr might still be a console.
        if c, r, ok := queryConsoleSize(os.Stderr.Fd()); ok {
                return c, r
        }
        // Neither is a console. Use the default.
        return 80, 24
}

// queryConsoleSize calls GetConsoleScreenBufferInfo on the given handle
// and returns (cols, rows, true) on success, or (0, 0, false) if the
// handle is not a console screen buffer.
func queryConsoleSize(fd uintptr) (cols, rows uint16, ok bool) {
        var info consoleScreenBufferInfo
        r, _, _ := procGetConsoleScreenBufferInfo.Call(fd, uintptr(unsafe.Pointer(&info)))
        if r == 0 {
                return 0, 0, false
        }
        cols = uint16(info.Window.Right - info.Window.Left + 1)
        rows = uint16(info.Window.Bottom - info.Window.Top + 1)
        if cols == 0 || rows == 0 {
                return 0, 0, false
        }
        return cols, rows, true
}
