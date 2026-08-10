// Stub termios helpers for platforms without native raw-mode support
// (currently macOS, *BSD). SetRawStdin is a no-op; GetStdinWindowSize
// returns the standard fallback.

//go:build darwin || freebsd || netbsd || openbsd

package gspty

// SavedTermios is a placeholder for non-Linux platforms.
type SavedTermios struct {
	saved bool
}

// SaveStdin returns a no-op SavedTermios on platforms without termios.
func SaveStdin() (*SavedTermios, error) {
	return &SavedTermios{saved: false}, nil
}

// RestoreStdin is a no-op stub.
func (s *SavedTermios) RestoreStdin() error { return nil }

// SetRawStdin returns a no-op SavedTermios on platforms without termios.
// The terminal is left in its default cooked mode. Interactive shell
// sessions will still work but keystroke interpretation (e.g. Ctrl-C)
// is handled by the local tty driver rather than the remote shell.
func SetRawStdin() (*SavedTermios, error) {
	return &SavedTermios{saved: false}, nil
}

// GetStdinWindowSize returns (80, 24) on platforms without native
// terminal-size ioctl support.
func GetStdinWindowSize() (cols, rows uint16) {
	return 80, 24
}
