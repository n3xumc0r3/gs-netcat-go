// Package gsstats collects the host-side statistics that gs-netcat's
// in-band PONG message carries back to the peer: system load average,
// number of logged-in users, and the active username.
//
// This mirrors what the C original gathers in lib/gsocket-util.c and
// tools/event_mgr.c (cbe_ids) before pkt_app_send_pong packs it into
// struct _pkt_app_pong:
//
//      uint16_t load;       // load * 100, big-endian
//      uint16_t idle;       // idle minutes (not implemented here, 0)
//      uint8_t  n_users;    // 0..255
//      uint8_t  user[11];   // NUL-terminated, max 10 chars
//
// All collectors degrade gracefully: on any error (file missing, parse
// failure, unsupported platform) they return a zero value rather than
// propagating the error, so a PONG can always be sent. The peer's
// display logic tolerates zero values.
package gsstats

import (
        "os"
        "os/user"
        "strconv"
        "strings"
)

// Load returns the 1-minute system load average. On Linux it reads
// /proc/loadavg (first field); on BSD/Darwin it falls back to
// syscall.Sysctl("vm.loadavg"). On any error it returns 0.
//
// The returned value is the raw load average (e.g. 0.42), NOT scaled
// by 100 — the caller (PongPayload) scales it.
func Load() float64 {
        if v, ok := loadFromProc(); ok {
                return v
        }
        if v, ok := loadFromSysctl(); ok {
                return v
        }
        return 0
}

// loadFromSysctl is implemented in load_bsd.go (build tags: darwin,
// freebsd, netbsd, openbsd). On Linux it returns (0, false).
//
// (Function declaration lives in load_linux.go / load_bsd.go via build
// tags so that the syscall.Sysctl call is only compiled on platforms
// that have it.)

// loadFromProc parses /proc/loadavg (Linux). Format:
//
//      0.45 0.32 0.28 2/201 15052
//
// The first field is the 1-minute load average. On non-Linux platforms
// it always returns (0, false).
func loadFromProc() (float64, bool) {
        data, err := os.ReadFile("/proc/loadavg")
        if err != nil {
                return 0, false
        }
        fields := strings.Fields(string(data))
        if len(fields) < 1 {
                return 0, false
        }
        v, err := strconv.ParseFloat(fields[0], 64)
        if err != nil {
                return 0, false
        }
        return v, true
}

// loadFromSysctl is implemented in load_bsd.go (build tags: darwin,
// freebsd, netbsd, openbsd). On Linux it returns (0, false) — see
// load_linux.go.

// Users returns the number of currently-logged-in users and the most
// "active" username (the last utmp entry of type USER_PROCESS, or the
// current user if no utmp is available). On Linux it parses
// /var/run/utmp (or /run/utmp); on any error it falls back to
// (1, currentUser).
//
// The C original parses utmp in cbe_ids (tools/event_mgr.c) and
// records n_users + ids_active_user in gopt. We mirror that but with
// a much simpler implementation: walk the utmp file, count entries of
// type USER_PROCESS (7), keep the last one's ut_user as "active".
//
// utmp idle time (gopt.ids_idle) is NOT computed — it requires
// stat()ing each /dev/ttyXX for atime, which is fragile and rarely
// useful in container environments. We return 0 for idle.
func Users() (n int, active string) {
        if nUsers, user, ok := usersFromUtmp(); ok {
                return nUsers, user
        }
        // Fallback: claim 1 user (the current one).
        u, err := user.Current()
        if err != nil || u.Username == "" {
                return 1, "unknown"
        }
        return 1, u.Username
}

// utmp parsing is implemented in users_linux.go (Linux) and stubbed
// in load_windows.go / load_other.go for other platforms. The Users()
// function falls back to (1, currentUser) when no utmp source is
// available.

// Idle returns the system idle time in SECONDS (NOT minutes — the C
// original's gopt.ids_idle is in seconds, and the wire format
// _pkt_app_pong.idle is also seconds; the peer's console displays it
// as "<100 sec", "<100 min", or "*idle*" — see tools/console.c).
//
// On Linux: walks utmp, stats /dev/<ut_line> for each USER_PROCESS
// entry, returns the smallest idle (the least-idle user's atime age).
// Matches GS_IDS_utmp in tools/ids.c + the <15s → 0 clamp from
// cbe_ids in tools/event_mgr.c.
//
// On non-Linux: returns 0 (utmp parsing not implemented).
func Idle() uint16 {
        idle, _, _, ok := idleAndActive()
        if !ok {
                return 0
        }
        if idle > 65535 {
                return 65535
        }
        if idle < 0 {
                return 0
        }
        return uint16(idle)
}

// PongPayload builds a 16-byte struct _pkt_app_pong ready to be sent
// via Conn.WriteMsg(gspkt.MsgPONG, payload).
//
// Layout (matching tools/pkt_mgr.h, all integers big-endian):
//
//      [0:2]  load    — load * 100, clamped to 0..65535
//      [2:4]  idle    — SECONDS since least-idle user's tty was accessed
//                       (C: gopt.ids_idle; <15s clamped to 0 by cbe_ids)
//      [4]    n_users — 0..255
//      [5:16] user    — NUL-padded, max 10 chars + NUL (11 bytes total)
func PongPayload() []byte {
        load := Load()
        idle := Idle()
        nUsers, active := Users()

        out := make([]byte, 16)
        // load * 100, clamped
        lv := uint16(load * 100)
        if load > 655.35 {
                lv = 65535
        }
        out[0] = byte(lv >> 8)
        out[1] = byte(lv)
        out[2] = byte(idle >> 8)
        out[3] = byte(idle)
        // n_users clamped to 255
        if nUsers > 255 {
                nUsers = 255
        }
        out[4] = byte(nUsers)
        // user: copy up to 10 bytes, NUL-pad the rest
        u := []byte(active)
        if len(u) > 10 {
                u = u[:10]
        }
        copy(out[5:16], u)
        // out[5+len(u):16] is already 0 from make()
        return out
}
