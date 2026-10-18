// Stub termios for 32-bit Windows. The real implementation in
// termios_windows.go depends on constants/proc vars defined in
// pty_windows.go (amd64-only).

//go:build windows && 386

package gspty

import "os"

// SavedTermios is a no-op on 32-bit Windows.
type SavedTermios struct {
	saved bool
}

// SaveStdin returns a no-op SavedTermios on 32-bit Windows.
func SaveStdin() (*SavedTermios, error) {
	return &SavedTermios{saved: false}, nil
}

// RestoreStdin is a no-op on 32-bit Windows.
func (s *SavedTermios) RestoreStdin() error { return nil }

// SetRawStdin returns a no-op SavedTermios on 32-bit Windows.
// (Spawn will return ErrNoPTY anyway, so raw mode is irrelevant.)
func SetRawStdin() (*SavedTermios, error) {
	return &SavedTermios{saved: false}, nil
}

// GetStdinWindowSize returns the default 80x24 on 32-bit Windows.
func GetStdinWindowSize() (cols, rows uint16) {
	return 80, 24
}

// _ keeps os import alive in case future code needs it.
var _ = os.Stdin
