package gsstats

import (
	"os"
	"path/filepath"
	"testing"
)

// makeUtmpEntry builds a single 384-byte Linux utmp record of type
// USER_PROCESS (7) with the given user and tty line.
func makeUtmpEntry(user, line string) []byte {
	ent := make([]byte, utmpLinuxEntrySize)
	// ut_type = 7 (USER_PROCESS), little-endian at offset 0.
	ent[0] = utmpTypeUserProc
	// ut_line at offset 8, NUL-terminated.
	copy(ent[8:40], []byte(line))
	// ut_user at offset 44, NUL-terminated.
	copy(ent[44:76], []byte(user))
	return ent
}

// writeTestUtmp writes a temp utmp file with the given entries and
// sets utmpPathOverride to point at it. Returns a cleanup function.
func writeTestUtmp(t *testing.T, entries [][]byte) (cleanup func()) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "utmp")
	var buf []byte
	for _, e := range entries {
		buf = append(buf, e...)
	}
	if err := os.WriteFile(path, buf, 0600); err != nil {
		t.Fatalf("write test utmp: %v", err)
	}
	prev := utmpPathOverride
	utmpPathOverride = path
	return func() {
		utmpPathOverride = prev
	}
}

// TestParseUtmpUserProcess verifies that USER_PROCESS entries are
// correctly parsed for their ut_user and ut_line fields.
func TestParseUtmpUserProcess(t *testing.T) {
	cleanup := writeTestUtmp(t, [][]byte{
		makeUtmpEntry("alice", "tty1"),
		makeUtmpEntry("bob", "pts/0"),
	})
	defer cleanup()

	entries, ok := UtmpEntries()
	if !ok {
		t.Fatal("UtmpEntries returned ok=false")
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].User != "alice" || entries[0].Line != "tty1" {
		t.Errorf("entry 0: %+v", entries[0])
	}
	if entries[1].User != "bob" || entries[1].Line != "pts/0" {
		t.Errorf("entry 1: %+v", entries[1])
	}
}

// TestParseUtmpSkipsNonUserProcess verifies that entries of other
// types (e.g. LOGIN_PROCESS=6, BOOT_TIME=2) are skipped.
func TestParseUtmpSkipsNonUserProcess(t *testing.T) {
	// Build a 3-entry file: type=2, type=7, type=6. Only the middle
	// one should be returned.
	bootTime := makeUtmpEntry("", "")
	bootTime[0] = 2 // BOOT_TIME
	userProc := makeUtmpEntry("alice", "tty1")
	loginProc := makeUtmpEntry("", "")
	loginProc[0] = 6 // LOGIN_PROCESS

	cleanup := writeTestUtmp(t, [][]byte{bootTime, userProc, loginProc})
	defer cleanup()

	entries, ok := UtmpEntries()
	if !ok {
		t.Fatal("UtmpEntries returned ok=false")
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].User != "alice" {
		t.Errorf("expected alice, got %q", entries[0].User)
	}
}

// TestParseUtmpMalformed verifies that a non-384-multiple file is
// rejected (ok=false).
func TestParseUtmpMalformed(t *testing.T) {
	cleanup := writeTestUtmp(t, [][]byte{
		makeUtmpEntry("alice", "tty1"),
		[]byte("trailing garbage"), // makes total non-multiple
	})
	defer cleanup()

	_, ok := UtmpEntries()
	if ok {
		t.Fatal("expected ok=false for malformed utmp")
	}
}

// TestParseUtmpNULTermination verifies that usernames and tty lines
// containing NUL bytes are truncated at the first NUL.
func TestParseUtmpNULTermination(t *testing.T) {
	cleanup := writeTestUtmp(t, [][]byte{
		makeUtmpEntry("alice", "tty1"),
	})
	defer cleanup()

	// Hand-craft an entry where ut_user has trailing garbage after
	// a NUL — parser must stop at the NUL.
	data := makeUtmpEntry("alice", "tty1")
	copy(data[44:76], []byte("bob\x00garbage"))

	dir := t.TempDir()
	path := filepath.Join(dir, "utmp")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	prev := utmpPathOverride
	utmpPathOverride = path
	defer func() { utmpPathOverride = prev }()

	entries, ok := UtmpEntries()
	if !ok || len(entries) != 1 {
		t.Fatalf("expected 1 entry, ok=%v len=%d", ok, len(entries))
	}
	if entries[0].User != "bob" {
		t.Errorf("expected bob (NUL-truncated), got %q", entries[0].User)
	}
}

// TestIdleAndActiveFallbackForUnstatableTty verifies that when
// /dev/<line> cannot be stat'd (e.g. line="nonexistent"), the entry
// is skipped and idleSec falls back to 0 with activeUser being the
// first non-empty user (best-effort).
func TestIdleAndActiveFallbackForUnstatableTty(t *testing.T) {
	cleanup := writeTestUtmp(t, [][]byte{
		makeUtmpEntry("alice", "this_tty_does_not_exist"),
		makeUtmpEntry("bob", "also_does_not_exist"),
	})
	defer cleanup()

	idle, user, n, ok := idleAndActive()
	if !ok {
		t.Fatal("expected ok=true")
	}
	if idle != 0 {
		t.Errorf("expected idle=0 (no tty statable), got %d", idle)
	}
	if user != "alice" {
		t.Errorf("expected alice as fallback, got %q", user)
	}
	if n != 2 {
		t.Errorf("expected n=2, got %d", n)
	}
}

// TestIdleAndActiveEmptyUtmp verifies that an empty utmp file yields
// (0, "", 0, true) — not an error.
func TestIdleAndActiveEmptyUtmp(t *testing.T) {
	cleanup := writeTestUtmp(t, nil)
	defer cleanup()

	idle, user, n, ok := idleAndActive()
	if !ok {
		t.Fatal("expected ok=true for empty utmp")
	}
	if idle != 0 || user != "" || n != 0 {
		t.Errorf("expected (0, \"\", 0, true), got (%d, %q, %d, %v)",
			idle, user, n, ok)
	}
}

// TestIdleAndActiveNoUtmp verifies that when no utmp file exists,
// idleAndActive returns ok=false.
func TestIdleAndActiveNoUtmp(t *testing.T) {
	prev := utmpPathOverride
	utmpPathOverride = "/nonexistent/path/utmp"
	defer func() { utmpPathOverride = prev }()

	_, _, _, ok := idleAndActive()
	if ok {
		t.Fatal("expected ok=false for missing utmp")
	}
}

// TestIdleClamp15s verifies the <15s → 0 clamp from cbe_ids. We
// can't easily fake atime on /dev/pts/*, so this test just verifies
// that the clamp is applied by directly checking the Idle() return
// path: if bestIdle < 15, idleSec is 0.
//
// We force "no tty statable" so idleAndActive returns 0 (best-effort
// fallback), then Idle() should return 0. This isn't a perfect test
// of the clamp but it documents the intent.
func TestIdleClamp15s(t *testing.T) {
	cleanup := writeTestUtmp(t, [][]byte{
		makeUtmpEntry("alice", "this_tty_does_not_exist"),
	})
	defer cleanup()

	if v := Idle(); v != 0 {
		t.Errorf("Idle() = %d, expected 0 (clamp or fallback)", v)
	}
}
