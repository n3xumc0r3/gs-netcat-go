// Legacy usersFromUtmp — kept as a thin wrapper around idleAndActive
// so that gsstats.Users() picks up the least-idle user (matching C's
// gopt.ids_active_user) instead of the last USER_PROCESS entry.
//
// Before Item 1 (idle-time enrichment) this function walked utmp
// directly. The walking logic now lives in utmp_linux.go so that
// both Users() and Idle() share a single utmp parse and report
// consistent user/idle values.

//go:build linux

package gsstats

// usersFromUtmp returns (nUsers, activeUser, ok) where activeUser is
// the least-idle user (matches gopt.ids_active_user in C). Returns
// ok=false if utmp is unavailable or no users are present.
func usersFromUtmp() (int, string, bool) {
	_, user, n, ok := idleAndActive()
	if !ok {
		return 0, "", false
	}
	if user == "" {
		return 0, "", false
	}
	return n, user, true
}
