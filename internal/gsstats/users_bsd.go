// Stub utmp parser for platforms without Linux utmp (macOS, *BSD).
// usersFromUtmp returns false here, and the Users() function in
// gsstats.go falls back to (1, currentUser). Native macOS/BSD utmp
// parsing (utmpx) is a follow-up.

//go:build darwin || freebsd || netbsd || openbsd

package gsstats

func usersFromUtmp() (int, string, bool) {
	return 0, "", false
}
