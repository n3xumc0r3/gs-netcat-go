package gsids

import (
        "sync"
        "testing"
        "time"

        "github.com/gsport/gs-netcat/internal/gsstats"
)

// newTestManager returns a fresh Manager (not the singleton) so each
// test starts with an empty DB. The subs map is left nil because the
// events() function (which is what we test here) doesn't touch it.
func newTestManager() *Manager {
        return &Manager{
                udb: make(map[string]*userRec),
        }
}

// TestEventsFirstTickNoAlerts verifies that the first tick populates
// the DB but does NOT emit any "new login" alerts (matches C's
// 'if (is_udb_init != 0)' guard — only logins AFTER the first tick
// are reported).
func TestEventsFirstTickNoAlerts(t *testing.T) {
        m := newTestManager()
        entries := []gsstats.UtmpEntry{
                {User: "alice", Line: "tty1"},
                {User: "bob", Line: "tty2"},
        }

        logins, actives := m.events(entries, time.Now().Unix())
        if len(logins) != 0 {
                t.Errorf("first tick should not emit logins, got %d: %v", len(logins), logins)
        }
        if len(actives) != 0 {
                t.Errorf("first tick should not emit actives, got %d: %v", len(actives), actives)
        }
        if len(m.udb) != 2 {
                t.Errorf("expected udb size 2, got %d", len(m.udb))
        }
        if !m.initialized {
                t.Error("expected initialized=true after first tick")
        }
}

// TestEventsNewLoginOnSecondTick verifies that a user appearing in
// the second tick (that wasn't in the first) is reported as a new
// login.
func TestEventsNewLoginOnSecondTick(t *testing.T) {
        m := newTestManager()
        now := time.Now().Unix()

        // First tick: alice + bob. No alerts (first tick).
        m.events([]gsstats.UtmpEntry{
                {User: "alice", Line: "tty1"},
                {User: "bob", Line: "tty2"},
        }, now)

        // Second tick (1s later): alice + bob + charlie.
        logins, actives := m.events([]gsstats.UtmpEntry{
                {User: "alice", Line: "tty1"},
                {User: "bob", Line: "tty2"},
                {User: "charlie", Line: "tty3"},
        }, now+1)

        if len(logins) != 1 {
                t.Fatalf("expected 1 new login, got %d: %v", len(logins), logins)
        }
        // Message format: "<user> [console]"
        expected := "charlie [console]"
        if logins[0] != expected {
                t.Errorf("login message: got %q, want %q", logins[0], expected)
        }
        if len(actives) != 0 {
                t.Errorf("expected 0 actives, got %d: %v", len(actives), actives)
        }
        if len(m.udb) != 3 {
                t.Errorf("expected udb size 3, got %d", len(m.udb))
        }
}

// TestEventsLogoutPrunesDB verifies that a user who disappears from
// utmp is removed from the DB on the next tick.
func TestEventsLogoutPrunesDB(t *testing.T) {
        m := newTestManager()
        now := time.Now().Unix()

        // First tick: alice + bob.
        m.events([]gsstats.UtmpEntry{
                {User: "alice", Line: "tty1"},
                {User: "bob", Line: "tty2"},
        }, now)

        // Second tick: only alice (bob logged out).
        m.events([]gsstats.UtmpEntry{
                {User: "alice", Line: "tty1"},
        }, now+1)

        if len(m.udb) != 1 {
                t.Errorf("expected udb size 1 after logout, got %d", len(m.udb))
        }
        if _, exists := m.udb["bob"]; exists {
                t.Error("bob should have been pruned from udb")
        }
        if _, exists := m.udb["alice"]; !exists {
                t.Error("alice should still be in udb")
        }
}

// TestEventsReLoginAfterLogout verifies that a user who logs out and
// logs back in is detected as a new login (not just an "active"
// transition).
func TestEventsReLoginAfterLogout(t *testing.T) {
        m := newTestManager()
        now := time.Now().Unix()

        // First tick: alice.
        m.events([]gsstats.UtmpEntry{
                {User: "alice", Line: "tty1"},
        }, now)

        // Second tick: alice gone (logout).
        m.events([]gsstats.UtmpEntry{}, now+1)

        // Third tick: alice back (re-login).
        logins, _ := m.events([]gsstats.UtmpEntry{
                {User: "alice", Line: "tty1"},
        }, now+2)

        if len(logins) != 1 {
                t.Fatalf("expected 1 re-login alert, got %d: %v", len(logins), logins)
        }
}

// TestEventsIdleToActiveTransition verifies that a user whose idle
// time drops from >= 1 hour to less than that is reported as "Active".
//
// We can't easily fake atime on /dev/pts/* in a unit test, so we
// directly manipulate the DB's idleOld field to simulate a user who
// was idle for 2 hours in the previous tick and is now active.
func TestEventsIdleToActiveTransition(t *testing.T) {
        m := newTestManager()
        now := time.Now().Unix()

        // First tick: alice. Her idle will be 0 (stat(/dev/tty1) fails
        // in test env, gsstats.IdleOfLine returns (0, false), events()
        // uses 0). We manually set idleOld to 2 hours to simulate "was
        // idle in previous tick".
        m.events([]gsstats.UtmpEntry{
                {User: "alice", Line: "tty1"},
        }, now)
        m.udb["alice"].idleOld = 2 * 60 * 60

        // Second tick: alice still here. Current idle = 0 (stat fails).
        // idle(0) < idleOld(7200) AND idleOld >= idleThreshold(3600) →
        // emit "Active: alice [idled for 120 mins]".
        logins, actives := m.events([]gsstats.UtmpEntry{
                {User: "alice", Line: "tty1"},
        }, now+1)

        if len(logins) != 0 {
                t.Errorf("expected 0 logins (alice already in DB), got %d", len(logins))
        }
        if len(actives) != 1 {
                t.Fatalf("expected 1 active alert, got %d: %v", len(actives), actives)
        }
        expected := "alice [idled for 120 mins]"
        if actives[0] != expected {
                t.Errorf("active message: got %q, want %q", actives[0], expected)
        }
}

// TestEventsNoActiveTransitionBelowThreshold verifies that a user
// whose idleOld was below the 1-hour threshold is NOT reported as
// "Active" even if their idle decreased.
func TestEventsNoActiveTransitionBelowThreshold(t *testing.T) {
        m := newTestManager()
        now := time.Now().Unix()

        // First tick: alice, idleOld will be set to current idle (0).
        m.events([]gsstats.UtmpEntry{
                {User: "alice", Line: "tty1"},
        }, now)
        // Force idleOld to 30 minutes (below 1h threshold).
        m.udb["alice"].idleOld = 30 * 60

        // Second tick: alice's idle is now 0 (decreased from 1800).
        _, actives := m.events([]gsstats.UtmpEntry{
                {User: "alice", Line: "tty1"},
        }, now+1)

        if len(actives) != 0 {
                t.Errorf("expected 0 actives (idleOld below threshold), got %d: %v", len(actives), actives)
        }
}

// TestEventsEmptyUserSkipped verifies that entries with empty User
// are silently skipped (defensive — utmp should never produce these
// but the parser is NUL-tolerant).
func TestEventsEmptyUserSkipped(t *testing.T) {
        m := newTestManager()
        now := time.Now().Unix()

        logins, _ := m.events([]gsstats.UtmpEntry{
                {User: "", Line: "tty1"}, // skipped
                {User: "alice", Line: "tty2"},
        }, now)

        if len(logins) != 0 {
                t.Errorf("first tick should not emit logins, got %d", len(logins))
        }
        if len(m.udb) != 1 {
                t.Errorf("expected udb size 1 (only alice), got %d", len(m.udb))
        }
}

// TestEventsMultipleNewLogins verifies that multiple simultaneous
// new logins all get reported (not just the first one).
func TestEventsMultipleNewLogins(t *testing.T) {
        m := newTestManager()
        now := time.Now().Unix()

        // First tick: empty.
        m.events(nil, now)

        // Second tick: 3 new users at once.
        logins, _ := m.events([]gsstats.UtmpEntry{
                {User: "alice", Line: "tty1"},
                {User: "bob", Line: "tty2"},
                {User: "charlie", Line: "tty3"},
        }, now+1)

        if len(logins) != 3 {
                t.Fatalf("expected 3 new logins, got %d: %v", len(logins), logins)
        }
        // All three should appear in the logins list.
        seen := map[string]bool{}
        for _, msg := range logins {
                seen[msg] = true
        }
        for _, u := range []string{"alice [console]", "bob [console]", "charlie [console]"} {
                if !seen[u] {
                        t.Errorf("missing login message %q in %v", u, logins)
                }
        }
}

// TestEventsConcurrentSafety is a smoke test that events() is safe
// to call concurrently with subscribe/unsubscribe (which also acquire
// m.mu). This is a race detector test — run with -race.
func TestEventsConcurrentSafety(t *testing.T) {
        m := newTestManager()
        var wg sync.WaitGroup

        // 10 concurrent event-computing goroutines.
        for i := 0; i < 10; i++ {
                wg.Add(1)
                go func(i int) {
                        defer wg.Done()
                        m.mu.Lock()
                        m.events([]gsstats.UtmpEntry{
                                {User: "alice", Line: "tty1"},
                        }, time.Now().Unix())
                        m.mu.Unlock()
                }(i)
        }
        wg.Wait()
}

// TestEventsMsgFormatTruncation verifies that user names longer than
// 20 chars are truncated (matches C's "%.20s" snprintf).
func TestEventsMsgFormatTruncation(t *testing.T) {
        m := newTestManager()
        now := time.Now().Unix()

        // First tick to populate.
        m.events(nil, now)

        // Second tick: a user with a 25-char name.
        logins, _ := m.events([]gsstats.UtmpEntry{
                {User: "abcdefghijklmnopqrstuvwxyz", Line: "tty1"}, // 26 chars
        }, now+1)

        if len(logins) != 1 {
                t.Fatalf("expected 1 login, got %d", len(logins))
        }
        // C: "%.20s" → first 20 chars only.
        expected := "abcdefghijklmnopqrst [console]" // 20 chars + " [console]"
        if logins[0] != expected {
                t.Errorf("login message: got %q, want %q", logins[0], expected)
        }
}
