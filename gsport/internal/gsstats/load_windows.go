// Stub for gsstats on platforms where neither /proc/loadavg nor
// utmp is available: Windows (no /proc, no utmp), and any other
// non-Linux, non-BSD GOOS. Load() returns 0; Users() falls back
// to (1, currentUser).

//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd

package gsstats

// loadFromSysctl is a no-op on platforms without vm.loadavg.
func loadFromSysctl() (float64, bool) {
        return 0, false
}

// usersFromUtmp is a no-op on platforms without utmp.
func usersFromUtmp() (int, string, bool) {
        return 0, "", false
}
