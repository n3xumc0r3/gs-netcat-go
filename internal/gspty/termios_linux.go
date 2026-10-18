// Terminal raw-mode and window-size helpers for gspty on Linux.
//
// These complement the PTY allocation in pty_linux.go with the client-side
// machinery: putting the local stdin into raw mode (so keystrokes
// like Ctrl-C are passed through to the remote shell verbatim
// instead of being interpreted by the local tty driver), saving the
// original termios for restoration, and querying the local terminal's
// window size so it can be advertised to the peer via WSIZE.

//go:build linux

package gspty

import (
        "fmt"
        "os"
        "syscall"
        "unsafe"
)

// SavedTermios holds the original termios state of a tty so it can be
// restored after raw-mode use. Call SaveStdin() at startup and
// RestoreStdin() on shutdown.
type SavedTermios struct {
        fd      int
        termios syscall.Termios
        saved   bool
}

// tcgetattr retrieves the current termios for fd.
func tcgetattr(fd int) (syscall.Termios, error) {
        var t syscall.Termios
        if err := ioctl(fd, tcgets, uintptr(unsafe.Pointer(&t))); err != nil {
                return syscall.Termios{}, err
        }
        return t, nil
}

// tcsetattr sets the termios for fd.
func tcsetattr(fd int, t syscall.Termios) error {
        return ioctl(fd, tcsets, uintptr(unsafe.Pointer(&t)))
}

// SaveStdin captures the current termios of fd 0 (stdin) for later
// restoration. If stdin is not a tty, returns a SavedTermios with
// saved=false so that RestoreStdin becomes a no-op.
func SaveStdin() (*SavedTermios, error) {
        fd := int(os.Stdin.Fd())
        if !isTty(fd) {
                return &SavedTermios{fd: fd, saved: false}, nil
        }
        t, err := tcgetattr(fd)
        if err != nil {
                return nil, fmt.Errorf("gspty: tcgetattr stdin: %w", err)
        }
        return &SavedTermios{fd: fd, termios: t, saved: true}, nil
}

// RestoreStdin restores the termios captured by SaveStdin. No-op if
// the original was not a tty.
func (s *SavedTermios) RestoreStdin() error {
        if s == nil || !s.saved {
                return nil
        }
        return tcsetattr(s.fd, s.termios)
}

// SetRawStdin puts stdin into raw mode, mirroring stty_set_raw() in
// tools/utils.c (the SSH-style variant). Returns the previous state
// (which the caller can pass to RestoreStdin) on success.
//
// Raw mode means: no input/output processing, no signal generation,
// no line editing, no echo. Keystrokes go through verbatim so the
// remote shell can interpret them (Ctrl-C, Ctrl-D, arrows, etc.).
func SetRawStdin() (*SavedTermios, error) {
        fd := int(os.Stdin.Fd())
        if !isTty(fd) {
                return &SavedTermios{fd: fd, saved: false}, nil
        }
        t, err := tcgetattr(fd)
        if err != nil {
                return nil, fmt.Errorf("gspty: tcgetattr: %w", err)
        }
        saved := &SavedTermios{fd: fd, termios: t, saved: true}

        // Match stty_set_raw in utils.c (the SSH-style variant):
        //   tios.c_iflag |=  IGNPAR;
        //   tios.c_iflag &= ~(ISTRIP | INLCR | IGNCR | ICRNL | IXON | IXANY | IXOFF);
        //   tios.c_lflag &= ~(ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHONL);
        //   tios.c_lflag &= ~IEXTEN;
        //   tios.c_oflag &= ~OPOST;
        //   tios.c_cc[VMIN]  = 1;
        //   tios.c_cc[VTIME] = 0;
        t.Iflag |= syscall.IGNPAR
        t.Iflag &^= syscall.ISTRIP | syscall.INLCR | syscall.IGNCR | syscall.ICRNL |
                syscall.IXON | syscall.IXANY | syscall.IXOFF
        t.Lflag &^= syscall.ISIG | syscall.ICANON | syscall.ECHO | syscall.ECHOE |
                syscall.ECHOK | syscall.ECHONL | syscall.IEXTEN
        t.Oflag &^= syscall.OPOST
        t.Cc[syscall.VMIN] = 1
        t.Cc[syscall.VTIME] = 0

        if err := tcsetattr(fd, t); err != nil {
                return nil, fmt.Errorf("gspty: tcsetattr raw: %w", err)
        }
        return saved, nil
}

// GetStdinWindowSize returns the terminal's current window size
// (cols, rows). If stdin is not a tty or the ioctl fails, returns
// (80, 24) — the standard fallback the C original uses in
// get_winsize() (utils.c line 160).
//
// v0.1.30 (P4 fix): probe STDOUT, not STDIN, to match C's
// get_winsize() (utils.c:154 `ioctl(STDOUT_FILENO, TIOCGWINSZ, ...)`).
// The previous Go code probed os.Stdin.Fd(), which gave correct results
// in the common case (stdin and stdout both tty) but diverged from C
// in edge cases where stdin and stdout differ in tty-ness. This also
// matches the Windows v0.1.15 fix. Falls back to stderr if stdout is
// not a tty (e.g. piped to file but stderr still terminal).
func GetStdinWindowSize() (cols, rows uint16) {
        // Try stdout first (matches C).
        fd := int(os.Stdout.Fd())
        var ws winsize
        if err := ioctl(fd, tiocgwinsz, uintptr(unsafe.Pointer(&ws))); err == nil && ws.Col != 0 {
                return ws.Col, ws.Row
        }
        // Try stderr as fallback (e.g. when stdout is piped to file).
        fd = int(os.Stderr.Fd())
        if err := ioctl(fd, tiocgwinsz, uintptr(unsafe.Pointer(&ws))); err == nil && ws.Col != 0 {
                return ws.Col, ws.Row
        }
        // Final fallback: stdin.
        fd = int(os.Stdin.Fd())
        if err := ioctl(fd, tiocgwinsz, uintptr(unsafe.Pointer(&ws))); err == nil && ws.Col != 0 {
                return ws.Col, ws.Row
        }
        return 80, 24
}

// isTty reports whether fd refers to a terminal. We use ioctl
// TIOCGWINSZ as the probe (the same call get_winsize uses in C).
func isTty(fd int) bool {
        var ws winsize
        return ioctl(fd, tiocgwinsz, uintptr(unsafe.Pointer(&ws))) == nil
}
