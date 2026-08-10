// Package gspty implements minimal pseudo-terminal (PTY) allocation and
// raw-mode terminal handling for the gs-netcat Go port's interactive
// (-i) mode, mirroring what the C original does in tools/utils.c via
// forkpty(3), stty_set_raw(), and get_winsize().
//
// # Platform support
//
// The package is split into per-OS files so it builds on every Go target:
//
//   - pty_unix.go    (linux, darwin, freebsd, netbsd, openbsd):
//     Unix98 PTY allocation via /dev/ptmx + ioctl(TIOCSPTLCK/TIOCGPTN),
//     window-size via TIOCGWINSZ/TIOCSWINSZ. Linux ioctl constants are
//     hardcoded because not all are exposed by Go's syscall package;
//     on BSD/macOS we use the syscall package's constants directly.
//
//   - pty_windows.go (windows): uses Windows 10 1809+ ConPTY via
//     CreatePseudoConsole. If the API is unavailable (older Windows)
//     Spawn returns ErrNoPTY, which the caller surfaces to the remote
//     peer as a STATUS/NOPTY in-band message — same code path the C
//     original takes when forkpty() fails.
//
//   - pty_other.go   (any other GOOS): returns ErrNoPTY from every
//     entry point. The interactive (-i) mode degrades to a non-PTY
//     pipe (raw stdin/stdout), so the tool still works for cat-mode
//     and for in-band message exchange.
//
// termios handling is split similarly:
//
//   - termios_linux.go: uses hardcoded ioctl constants + syscall.Termios.
//   - termios_bsd.go:   uses syscall.Termios + syscall constants.
//   - termios_windows.go: uses Windows console mode (SetConsoleMode).
//   - termios_other.go:  no-op stubs.
//
// # Wire compatibility
//
// The PTY's window size and the raw-mode termios settings match what
// the C gs-netcat uses (stty_set_raw in tools/utils.c lines 447-494):
// the SSH-style raw mode (IGNPAR set, ISTRIP|INLCR|IGNCR|ICRNL|IXON|IXANY|IXOFF
// cleared, ISIG|ICANON|ECHO|ECHOE|ECHOK|ECHONL|IEXTEN cleared, OPOST
// cleared, VMIN=1, VTIME=0).
package gspty

// ErrNoPTY is returned by Spawn on platforms without PTY support, or
// when the local OS can't allocate a pseudo-terminal (e.g. very old
// Windows without ConPTY). Callers should treat this as "interactive
// shell unavailable" — the remote peer should be notified via an
// in-band STATUS/NOPTY message so it can fall back to a non-PTY pipe.
var ErrNoPTY = errNoPTY{}

type errNoPTY struct{}

func (errNoPTY) Error() string { return "gspty: PTY not supported on this platform" }

// IsNoPTY reports whether err is ErrNoPTY (or wraps it).
func IsNoPTY(err error) bool {
	_, ok := err.(errNoPTY)
	return ok
}
