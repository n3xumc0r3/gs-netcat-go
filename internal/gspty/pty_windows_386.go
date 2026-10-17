// Stub for 32-bit Windows: ConPTY struct layout in pty_windows.go is
// hardcoded for x64 (see audit-3 LOW bug #9 — startupInfoEx uses x64-
// specific padding). Instead of allowing a confusing compile error,
// this stub returns ErrNoPTY on 32-bit Windows so the caller falls
// back to a non-PTY pipe (same path as pre-1809 Windows without
// ConPTY support).
//
// ErrNoPTY is defined in doc.go (shared across all platforms).

//go:build windows && 386

package gspty

// PTY is a no-op type on 32-bit Windows (Spawn never returns a non-nil *PTY).
type PTY struct {
	// Master is kept for source-compat with amd64 build (callers may
	// reference pty.Master). Always nil on 386.
	Master interface{ Read([]byte) (int, error) }
}

// Spawn returns ErrNoPTY on 32-bit Windows.
func Spawn(cmd string, cols, rows uint16) (*PTY, error) {
	return nil, ErrNoPTY
}

func (p *PTY) Write(b []byte) (int, error)            { return 0, ErrNoPTY }
func (p *PTY) SetWindowSize(cols, rows uint16) error  { return ErrNoPTY }
func (p *PTY) Wait() error                            { return ErrNoPTY }
func (p *PTY) Close() error                           { return nil }
func (p *PTY) PID() int                               { return 0 }

// dummy variable to ensure the file compiles standalone
var _ = struct{}{}
