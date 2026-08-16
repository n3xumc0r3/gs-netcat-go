//go:build !windows

package main

// init on non-Windows is a no-op: terminals on Unix already speak
// UTF-8 and honour ANSI escape sequences natively. The only thing we
// could do here is call setlocale(LC_ALL, "") — but Go's runtime
// already sets up the locale correctly for terminal I/O.
func init() {
	// intentionally empty
}
