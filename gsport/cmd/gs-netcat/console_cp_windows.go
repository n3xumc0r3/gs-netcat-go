//go:build windows

package main

import (
        "fmt"
        "os"

        "golang.org/x/sys/windows"
)

// init runs at startup and switches the Windows console to UTF-8.
//
// On Windows the default console code page is OEM (CP437 on US systems,
// CP866 on Russian, etc.). When gs-netcat writes UTF-8 bytes (e.g.
// Russian text from a shell) to such a console, the bytes are
// interpreted as the OEM code page and Russian characters become
// mojibake.
//
// We fix this by:
//
//   1. Calling SetConsoleOutputCP(CP_UTF8) so stdout/stderr interpret
//      bytes as UTF-8.
//   2. Calling SetConsoleCP(CP_UTF8) so the console INPUT is also
//      UTF-8 (matters for piping Russian commands into -i mode).
//   3. Enabling ENABLE_VIRTUAL_TERMINAL_PROCESSING on stdout/stderr
//      so ANSI color codes work (used by --monitor's colored output).
//      Windows 10 1607+ supports this; on older Windows the call
//      silently fails and we just lose colors (no crash).
//
// On non-Windows this file is not compiled; console_cp_unix.go has a
// no-op init().
//
// We also set _GSOCKET_CHILDCP_UTF8=1 in the env so any child process
// (e.g. the shell spawned in -i mode) can pick up the same setting.
// Bash on Windows (Cygwin/MSYS2) ignores this, but cmd.exe and
// PowerShell honour the console CP set by SetConsoleOutputCP.
func init() {
        // CP_UTF8 = 65001 (Windows code page identifier for UTF-8).
        // golang.org/x/sys/windows doesn't export this constant; we use
        // the numeric value directly.
        const cpUTF8 uint32 = 65001

        // Switch console code pages to UTF-8.
        if err := windows.SetConsoleOutputCP(cpUTF8); err != nil {
                fmt.Fprintf(os.Stderr, "[gs-netcat] warning: SetConsoleOutputCP failed: %v\n", err)
        }
        _ = windows.SetConsoleCP(cpUTF8)

        // Enable ANSI escape-sequence processing on stdout/stderr.
        enableVT(os.Stdout)
        enableVT(os.Stderr)
}

// enableVT enables ENABLE_VIRTUAL_TERMINAL_PROCESSING on the given
// console handle. Idempotent and silent on failure.
func enableVT(f *os.File) {
        if f == nil {
                return
        }
        h := windows.Handle(f.Fd())
        var mode uint32
        if err := windows.GetConsoleMode(h, &mode); err != nil {
                return
        }
        const ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        _ = windows.SetConsoleMode(h, mode|ENABLE_VIRTUAL_TERMINAL_PROCESSING)
}
