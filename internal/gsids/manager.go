// Package gsids implements the IDS (Intrusion Detection System)
// subsystem for gs-netcat's interactive (-i) mode.
//
// When a client sends a MsgIDS in-band message to the server, it
// subscribes to receive IDS log alerts. The server then polls utmp
// every 5 seconds and sends MsgLOG messages back to all subscribers
// when:
//
//   - A new login is detected (user appears in utmp that wasn't there
//     in the previous tick). Message format: "Login : <user> [<host>]"
//     with type=ALERT (red).
//   - A user transitions from idle (>= 1 hour) to active. Message
//     format: "Active: <user> [idled for N mins]" with type=ALERT.
//
// This mirrors the C original's tools/ids.c (GS_IDS_utmp + utmp_db_*)
// and tools/event_mgr.c (cbe_ids) — see those files for the canonical
// algorithm.
//
// Architecture:
//
//   - Manager is a process-wide singleton (one utmp DB shared across
//     all subscribed clients, matching gopt.ids_peers in C).
//   - Subscribe(conn) registers a client and returns an unsubscribe
//     func. The Manager starts its background ticker on first
//     subscriber and stops it when the last subscriber leaves.
//   - The ticker calls tick() every 5s, which walks utmp, updates
//     the in-memory DB, detects events, and broadcasts MsgLOG to
//     all subscribers.
//   - On non-Linux platforms UtmpEntries returns no entries, so
//     tick() is effectively a no-op.
//
// Thread safety (v0.1.29 corrected): Manager.mu guards subs and udb.
// tick() acquires mu only for events() and the subscriber snapshot,
// then releases mu before broadcasting. sendLog/WriteMsg is called
// WITHOUT mu; WriteMsg may block on a slow client's TLS write buffer,
// but this blocks only the tick goroutine (other subscribers and the
// rest of the server are unaffected).
package gsids

import (
        "fmt"
        "sync"
        "time"

        "github.com/gsport/gs-netcat/internal/gsconn"
        "github.com/gsport/gs-netcat/internal/gspkt"
        "github.com/gsport/gs-netcat/internal/gsstats"
)

const (
        // tickInterval matches GS_APP_IDSFREQ (5 seconds in C).
        tickInterval = 5 * time.Second

        // idleThreshold matches C IDLE_THRESHOLD (1 hour, non-DEBUG).
        // A user is considered to have transitioned idle→active only if
        // their previous idle was >= this threshold AND their current
        // idle is smaller.
        idleThreshold int64 = 60 * 60

        // LogTypeAlert matches GS_PKT_APP_LOG_TYPE_ALERT (0x01, RED).
        // Used for both new-login and idle→active events.
        LogTypeAlert uint8 = 0x01
)

// userRec is the in-memory DB record for a single utmp user. Mirrors
// struct utmp_db_user in tools/ids.c.
type userRec struct {
        user    string
        idle    int64  // smallest idle seen this tick
        idleOld int64  // idle at previous tick (for idle→active detection)
        token   int64  // tick timestamp; stale records are pruned
        msg     string // formatted message ("user [host]")
}

// Manager tracks utmp state and broadcasts IDS log messages to
// subscribers. Process-wide singleton: see defaultMgr + Subscribe().
type Manager struct {
        mu      sync.Mutex
        subs    map[*gsconn.Conn]struct{}
        udb     map[string]*userRec
        started bool
        stopCh  chan struct{}
        // initialized is set true after the first tick completes. Before
        // that, new users found in utmp are added to the DB but NOT
        // reported as "new logins" (matches C's 'if (is_udb_init != 0)'
        // guard in GS_IDS_utmp).
        initialized bool
}

// defaultMgr is the process-wide singleton. Created lazily by
// newManager() on first Subscribe.
var defaultMgr = newManager()

func newManager() *Manager {
        return &Manager{
                subs: make(map[*gsconn.Conn]struct{}),
                udb:  make(map[string]*userRec),
        }
}

// Subscribe registers conn to receive IDS log messages (MsgLOG with
// type=ALERT) when new logins or idle→active transitions are
// detected. Returns an unsubscribe function that MUST be called when
// conn is closed (typically via defer in the caller).
//
// The Manager starts its background ticker when the first subscriber
// registers and stops it when the last subscriber leaves, mirroring
// the C original's behaviour where cbe_ids is scheduled by
// pkt_app_cb_ids and removed by cbe_ids itself when ids_peers becomes
// empty.
func Subscribe(conn *gsconn.Conn) func() {
        return defaultMgr.subscribe(conn)
}

func (m *Manager) subscribe(conn *gsconn.Conn) func() {
        m.mu.Lock()
        m.subs[conn] = struct{}{}
        needStart := !m.started
        if needStart {
                m.started = true
                m.stopCh = make(chan struct{})
        }
        m.mu.Unlock()

        if needStart {
                go m.run()
                // Initial tick to populate the udb. Matches C: cbe_ids is
                // called immediately after pkt_app_cb_ids registers the peer
                // (so the first batch of "new logins" is suppressed — only
                // logins that happen *after* subscription are reported).
                go m.tick()
        }

        return func() {
                m.mu.Lock()
                delete(m.subs, conn)
                // v0.1.28 (audit-4 bug #1, HIGH): capture stopCh under the
                // lock so we don't race with run()'s select reading it.
                // Previously run() read m.stopCh without holding mu, so a
                // new subscribe() could replace m.stopCh before run() saw
                // the close — leaking run() forever + duplicating ticks.
                var stopCh chan struct{}
                if len(m.subs) == 0 && m.started {
                        stopCh = m.stopCh
                        m.started = false
                        m.stopCh = nil
                }
                m.mu.Unlock()
                // Close outside the lock to avoid run()'s select blocking
                // on mu acquisition if it's currently in tick() (which also
                // holds mu).
                if stopCh != nil {
                        close(stopCh)
                }
        }
}

// run is the background ticker goroutine. Started on first subscribe,
// stopped when the last subscriber leaves.
//
// v0.1.28: read m.stopCh once at start, then never re-read it. The
// stopCh value can be replaced by subscribe() (when started=true
// creates a new channel) but THIS goroutine's lifetime is tied to
// the stopCh we captured at startup — the new stopCh belongs to the
// next run() goroutine that subscribe() spawns.
func (m *Manager) run() {
        m.mu.Lock()
        stopCh := m.stopCh
        m.mu.Unlock()
        if stopCh == nil {
                return // defensive; shouldn't happen
        }
        ticker := time.NewTicker(tickInterval)
        defer ticker.Stop()
        for {
                select {
                case <-ticker.C:
                        m.tick()
                case <-stopCh:
                        return
                }
        }
}

// tick walks utmp, updates the in-memory DB, detects new-logins and
// idle→active transitions, and broadcasts MsgLOG to all subscribers.
//
// Mirrors GS_IDS_utmp + cbe_ids in C. Holds m.mu for the events()
// computation and the subs-snapshot, then releases it before calling
// sendLog (so a slow client's WriteMsg can't block the IDS tick for
// other subscribers).
func (m *Manager) tick() {
        entries, ok := gsstats.UtmpEntries()
        if !ok {
                // No utmp available (non-Linux, or utmp file missing). Nothing
                // to do — don't even broadcast. C behaves the same (its
                // getutxent loop just yields nothing).
                return
        }
        now := time.Now().Unix()

        m.mu.Lock()
        newLogins, newActives := m.events(entries, now)
        // Snapshot subscribers under mu so we don't hold the lock during
        // sendLog (which may block on a slow client's TLS write buffer).
        subs := make([]*gsconn.Conn, 0, len(m.subs))
        for c := range m.subs {
                subs = append(subs, c)
        }
        m.mu.Unlock()

        // Broadcast to snapshot. If a subscriber unsubscribed between
        // snapshot and sendLog, the worst case is a write to a closing
        // conn — WriteMsg returns an error which we ignore (the
        // subscriber misses one tick's worth of IDS messages; not a
        // correctness issue since IDS messages are best-effort alerts).
        for _, conn := range subs {
                for _, msg := range newLogins {
                        sendLog(conn, LogTypeAlert, "Login : "+msg)
                }
                for _, msg := range newActives {
                        sendLog(conn, LogTypeAlert, "Active: "+msg)
                }
        }
}

// events walks utmp entries, updates the in-memory DB, and returns the
// list of new-login and new-active messages detected this tick. Pure
// logic (no I/O) so it can be unit-tested with synthetic entries.
//
// Caller MUST hold m.mu.
//
// Mirrors GS_IDS_utmp in tools/ids.c. The two-pass structure (walk
// utmp → prune logged-out users + detect idle→active) is identical
// to the C original.
func (m *Manager) events(entries []gsstats.UtmpEntry, now int64) (newLogins, newActives []string) {
        token := now

        // First pass: walk utmp, update DB, detect new logins.
        seen := make(map[string]bool, len(entries))
        for _, e := range entries {
                if e.User == "" {
                        continue
                }
                seen[e.User] = true

                idle, _ := gsstats.IdleOfLine(e.Line, now)

                rec, exists := m.udb[e.User]
                if !exists {
                        // New user. Add to DB. Only emit "new login" if udb was
                        // already initialized (matches C's
                        //   if (is_udb_init != 0) { ... GS_LIST_add(new_login, ...) }
                        // guard).
                        rec = &userRec{
                                user:  e.User,
                                idle:  idle,
                                token: token,
                        }
                        // Format message: "<user> [<host>]" — but we don't parse
                        // ut_host from utmp (gsstats.UtmpEntries only returns
                        // user+line). Use "console" as the host placeholder
                        // (matches C's ut->ut_host[0]?ut->ut_host:"console").
                        rec.msg = fmt.Sprintf("%.20s [console]", e.User)
                        m.udb[e.User] = rec
                        if m.initialized {
                                newLogins = append(newLogins, rec.msg)
                        }
                } else {
                        // Existing user: update token + idle.
                        if rec.token != token {
                                rec.token = token
                                rec.idle = idle
                        }
                        if idle < rec.idle {
                                rec.idle = idle
                        }
                }
        }

        // Second pass: prune logged-out users + detect idle→active.
        for user, rec := range m.udb {
                if !seen[user] {
                        delete(m.udb, user)
                        continue
                }
                if rec.idleOld >= idleThreshold && rec.idle < rec.idleOld {
                        msg := fmt.Sprintf("%.20s [idled for %d mins]", user, rec.idleOld/60)
                        newActives = append(newActives, msg)
                }
                rec.idleOld = rec.idle
        }

        m.initialized = true
        return newLogins, newActives
}

// sendLog sends a MsgLOG in-band message to conn. Payload layout
// matches struct _pkt_app_log in tools/pkt_mgr.h:
//
//      [0]    type   — log type (ALERT/NOTICE/INFO/DEFAULT)
//      [1:64] msg    — NUL-padded, max 62 chars + NUL
//
// v0.1.28 (audit-4 bug #6, LOW): truncate to 62 bytes, not 63.
// The C original uses `snprintf(%.62s)` which reserves 1 byte for
// the implicit NUL terminator (62 chars + NUL = 63 bytes in the
// 64-byte field). The previous code truncated to 63, leaving no
// room for the NUL — a latent wire-compat mismatch that could
// confuse the peer's NUL-terminated string handling.
func sendLog(conn *gsconn.Conn, logType uint8, msg string) {
        payload := make([]byte, 64)
        payload[0] = logType
        if len(msg) > 62 {
                msg = msg[:62]
        }
        copy(payload[1:64], []byte(msg))
        // payload[1+len(msg):64] is already 0 from make() — that zero
        // at position 1+len(msg) is the NUL terminator.
        _ = conn.WriteMsg(gspkt.MsgLOG, payload)
}

// Stats returns the current IDS DB statistics (n_users, ids_active_user,
// ids_idle) — useful for testing and for PONG enrichment if needed.
// Not currently used by the main code path (PongPayload computes its
// own snapshot via gsstats.PongPayload) but exposed for parity with
// gopt.ids_* in C.
func Stats() (nUsers int, activeUser string, idleSec int64) {
        defaultMgr.mu.Lock()
        defer defaultMgr.mu.Unlock()
        if len(defaultMgr.udb) == 0 {
                return 0, "", 0
        }
        var bestUser string
        var bestIdle int64 = 1 << 62
        for _, rec := range defaultMgr.udb {
                if rec.idle < bestIdle {
                        bestIdle = rec.idle
                        bestUser = rec.user
                }
        }
        return len(defaultMgr.udb), bestUser, bestIdle
}
