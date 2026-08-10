// Linux-specific stub for loadFromSysctl: always returns (0, false).
// The real load is read from /proc/loadavg in gsstats.go.

//go:build linux

package gsstats

func loadFromSysctl() (float64, bool) {
        return 0, false
}
