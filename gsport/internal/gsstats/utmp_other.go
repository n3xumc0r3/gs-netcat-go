// Non-Linux stubs for gsstats utmp/idle functions. On macOS, *BSD,
// and Windows there is no Linux-style /var/run/utmp binary file:
//   - macOS/BSD use utmpx (different binary layout per OS).
//   - Windows has no utmp concept at all.
//
// For v1 we treat these platforms as "no utmp available": UtmpEntries
// returns (nil, false) and idleAndActive returns (0, "", 0, false).
// Users() falls back to (1, currentUser) and Idle() returns 0 — both
// acceptable to the peer's display logic.
//
// Native utmpx parsing on macOS/BSD is a follow-up (the C original
// uses getutxent() which abstracts the per-OS binary format).

//go:build !linux

package gsstats

// UtmpEntry is the cross-platform type returned by UtmpEntries(). On
// non-Linux platforms the fields are never populated (UtmpEntries
// always returns (nil, false)), but the type itself must be defined
// so that call sites in gsids/manager.go compile on all platforms.
type UtmpEntry struct {
        User string
        Line string
}

// UtmpEntries returns no entries on non-Linux platforms.
func UtmpEntries() ([]UtmpEntry, bool) {
        return nil, false
}

// idleAndActive returns (0, "", 0, false) on non-Linux platforms.
func idleAndActive() (idleSec int, activeUser string, nUsers int, ok bool) {
        return 0, "", 0, false
}

// IdleOfLine returns ok=false on non-Linux (no /dev/<line> stat-based
// idle computation). The gsids Manager will treat this as "skip entry".
func IdleOfLine(line string, now int64) (idle int64, ok bool) {
        return 0, false
}
