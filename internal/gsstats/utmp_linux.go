// Linux utmp walker for gsstats. Reads /var/run/utmp (or /run/utmp)
// and exposes:
//
//   - utmpEntries(): all USER_PROCESS records (user + line).
//   - idleAndActive(): least-idle user via stat(/dev/<ut_line>) atime,
//     matching the C original's GS_IDS_utmp logic in tools/ids.c.
//
// The entry layout on Linux/glibc (sizeof=384):
//
//   int32   ut_type      // 0
//   pid_t   ut_pid       // 4 (4 bytes)
//   char    ut_line[32]  // 8
//   char    ut_id[4]     // 40
//   char    ut_user[32]  // 44
//   char    ut_host[256] // 76
//   struct  exit_status  // 332 (4 bytes)
//   int32   ut_session   // 336
//   struct  timeval      // 340 (8 bytes)
//   int32   ut_addr_v6[4]// 348 (16 bytes)
//   char    unused[20]   // 364
//                            // total: 384

//go:build linux

package gsstats

import (
        "os"
        "strings"
        "syscall"
        "time"
)

const (
        utmpLinuxEntrySize = 384
        utmpLinuxPath      = "/var/run/utmp"
        utmpLinuxAltPath   = "/run/utmp"
        utmpTypeUserProc   = 7 // USER_PROCESS

        // idleClamp15s mirrors the C original's cbe_ids rule:
        //   if (gopt.ids_idle < 15) gopt.ids_idle = 0;
        // Treat any idle below 15 seconds as fully active. This avoids
        // flicker on the peer's display (which formats "<100 sec" if
        // sec_idle < 100).
        idleClamp15s = 15
)

// UtmpEntry holds the parsed fields from a single USER_PROCESS utmp
// record. Line is the tty name WITHOUT the /dev/ prefix (e.g. "tty1",
// "pts/0"); call sites prepend "/dev/" before stat().
type UtmpEntry struct {
        User string
        Line string
}

// UtmpEntries walks /var/run/utmp (or /run/utmp) and returns all
// USER_PROCESS entries. Returns ok=false if utmp is unavailable or
// malformed. Exposed publicly so the gsids Manager can reuse the
// same parser.
func UtmpEntries() (entries []UtmpEntry, ok bool) {
        if v := utmpPathOverride; v != "" {
                return utmpEntriesFromFile(v)
        }
        data, err := os.ReadFile(utmpLinuxPath)
        if err != nil {
                data, err = os.ReadFile(utmpLinuxAltPath)
                if err != nil {
                        return nil, false
                }
        }
        return parseUtmp(data)
}

// utmpPathOverride, when non-empty, makes UtmpEntries read from this
// path instead of /var/run/utmp or /run/utmp. Used by tests; not
// safe to set in production code.
var utmpPathOverride string

// utmpEntriesFromFile reads + parses a utmp file at the given path.
func utmpEntriesFromFile(path string) ([]UtmpEntry, bool) {
        data, err := os.ReadFile(path)
        if err != nil {
                return nil, false
        }
        return parseUtmp(data)
}

// parseUtmp parses raw utmp bytes into entries. Returns (nil, false)
// if len(data) is not a multiple of utmpLinuxEntrySize.
//
// v0.1.28 (audit-4 bug #7, LOW): ut_type is `short int` (2 bytes) in
// glibc's struct utmp, NOT int32. The previous code read 4 bytes
// (including 2 padding bytes) and interpreted them as int32. On x86
// the padding is zero so the value was correct in practice, but on
// any architecture where padding is non-zero this would break. Now
// we read ut_type as int16 (2 bytes) and zero-extend to int32.
func parseUtmp(data []byte) ([]UtmpEntry, bool) {
        if len(data)%utmpLinuxEntrySize != 0 {
                return nil, false
        }
        var entries []UtmpEntry
        for off := 0; off+utmpLinuxEntrySize <= len(data); off += utmpLinuxEntrySize {
                ent := data[off : off+utmpLinuxEntrySize]
                // ut_type is `short int` at offset 0 — 2 bytes, little-endian.
                utType := int32(int16(uint16(ent[0])|uint16(ent[1])<<8))
                if utType != utmpTypeUserProc {
                        continue
                }
                // ut_user at offset 44, 32 bytes, NUL-terminated.
                u := ent[44:76]
                if i := strings.IndexByte(string(u), 0); i >= 0 {
                        u = u[:i]
                }
                // ut_line at offset 8, 32 bytes, NUL-terminated.
                l := ent[8:40]
                if i := strings.IndexByte(string(l), 0); i >= 0 {
                        l = l[:i]
                }
                entries = append(entries, UtmpEntry{User: string(u), Line: string(l)})
        }
        return entries, true
}

// idleAndActive walks utmp, stats /dev/<ut_line> for each USER_PROCESS
// entry to read atime, and returns:
//
//   - idleSec:   seconds since the least-idle user's tty was last
//                accessed, with the <15s → 0 clamp applied (matches
//                gopt.ids_idle after cbe_ids's clamp).
//   - activeUser: username of the least-idle user (matches
//                gopt.ids_active_user). Empty if no users.
//   - nUsers:    total USER_PROCESS count (matches gopt.n_users).
//   - ok:        false if utmp is unavailable or malformed.
//
// On any per-entry stat error (tty doesn't exist, permission denied,
// not a syscall.Stat_t) that entry is skipped — it cannot be the
// "least idle" user. If no entry produces a usable idle, idleSec=0
// and activeUser is the first non-empty user (best-effort fallback).
//
// This mirrors GS_IDS_utmp in tools/ids.c but is stateless (no DB):
// it reports the current snapshot only. Stateful new-login/new-active
// detection lives in the gsids package.
func idleAndActive() (idleSec int, activeUser string, nUsers int, ok bool) {
        entries, ok := UtmpEntries()
        if !ok {
                return 0, "", 0, false
        }
        if len(entries) == 0 {
                return 0, "", 0, true
        }
        now := time.Now().Unix()
        bestIdle := int64(1) << 62 // very large
        bestUser := ""
        usable := false
        for _, e := range entries {
                if e.User == "" {
                        continue
                }
                idle, statOK := idleOf(e.Line, now)
                if !statOK {
                        // tty not statable — skip; cannot be "least idle"
                        continue
                }
                if idle < bestIdle {
                        bestIdle = idle
                        bestUser = e.User
                        usable = true
                }
        }
        if !usable {
                // No tty was statable. Fall back to the first user with a
                // non-empty name so PONG still reports *some* active user.
                for _, e := range entries {
                        if e.User != "" {
                                bestUser = e.User
                                break
                        }
                }
                bestIdle = 0
        }
        // C: if (gopt.ids_idle < 15) gopt.ids_idle = 0;
        if bestIdle < idleClamp15s {
                bestIdle = 0
        }
        return int(bestIdle), bestUser, len(entries), true
}

// idleOf returns seconds since /dev/<line> was last accessed (atime).
// Returns ok=false if stat fails (tty doesn't exist, permission
// denied) or the file is not a syscall.Stat_t — caller should skip
// the entry. Matches the C original's
//   stat(buf, &s);
//   idle = MAX(0, gopt.tv_now.tv_sec - s.st_atime);
// behaviour, but with explicit error signalling (C silently treats
// a failed stat as "idle = now - 0" which is essentially "infinitely
// idle" — we instead report it as "skip this entry").
func idleOf(line string, now int64) (idle int64, ok bool) {
        return IdleOfLine(line, now)
}

// IdleOfLine is the public version of idleOf. It returns seconds
// since /dev/<line> was last accessed (atime). Exposed so the gsids
// package can reuse the same stat logic without duplicating it.
//
// now is the current unix timestamp (callers should pass time.Now().Unix()
// once per tick to avoid repeated syscalls).
func IdleOfLine(line string, now int64) (idle int64, ok bool) {
        if line == "" {
                return 0, false
        }
        fi, err := os.Stat("/dev/" + line)
        if err != nil {
                return 0, false
        }
        stat, ok := fi.Sys().(*syscall.Stat_t)
        if !ok {
                return 0, false
        }
        idle = now - stat.Atim.Sec
        if idle < 0 {
                return 0, true
        }
        return idle, true
}
