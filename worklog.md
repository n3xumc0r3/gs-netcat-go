---
Task ID: window-size-fix-v0.1.15
Agent: main
Task: Fix "overwritten text" display corruption — client window is 120 cols but WSIZE sends 80.

Work Log:
- Root cause found: GetStdinWindowSize() in termios_windows.go passed os.Stdin.Fd() to GetConsoleScreenBufferInfo
- Win32 API GetConsoleScreenBufferInfo REQUIRES hConsoleOutput (output handle), NOT input handle
- Passing stdin always fails (returns 0) → fallback to return 80, 24 → EVERY Windows client reported 80x24
- Server created ConPTY at 80x24, shell formatted output for 80 cols
- Client's real terminal was 120 cols → VT cursor positioning sequences assumed 80-col layout → cursor at wrong columns → text overwritten/scrambled
- Same bug affected watchWindowSize polling (250ms) — never detected resizes because GetStdinWindowSize always returned 80x24
- Fix: use os.Stdout.Fd() (correct output handle), with fallback to os.Stderr.Fd() if stdout is piped
- Added queryConsoleSize helper for clean code
- Bumped version to v0.1.15-fix
- Built v0.1.15-fix.exe (3569152 bytes)

Stage Summary:
- This was the root cause of ALL display corruption symptoms:
  * "overwritten text" after ls output
  * PONG messages scrambling the prompt
  * Long commands getting truncated/overwritten
- After fix: client will send WSIZE 120x24 (matching real window)
- Server PTY will be 120 cols, shell will format for 120 cols, VT sequences will match client layout
- watchWindowSize polling will now actually detect resizes
- Artifact: /home/z/my-project/download/gs-netcat-v0.1.15-fix.exe

---
Task ID: v0.1.17-listen-timeout-fix
Agent: main
Task: Fix "gsrn: read start/status: i/o timeout" crash on Windows when running `-l -i -vvv` (LISTEN mode never managed to host a server).

Work Log:
- Root cause found in internal/gsconn/gsconn.go line 365: `relay.SetDeadline(time.Now().Add(opts.HandshakeTimeout))` was applied to the relay TCP socket BEFORE `relay.Start()` was called.
- `opts.HandshakeTimeout` defaults to 30s.
- In LISTEN mode `relay.Start()` blocks waiting for `_gs_start`, which the relay only sends when a CONNECT peer arrives — that can take minutes/hours/days.
- Result: 30s after LISTEN registration the read deadline fired with `i/o timeout`, killing the listener before any connector could ever connect.
- Matched all user symptoms exactly:
  * First run with new secret → 30s wait → i/o timeout ✓
  * Re-run with same secret → immediate EOF (relay rejects duplicate LISTEN registration) ✓
  * New relay (new password = new GS-Address) → 30s wait → i/o timeout ✓
  * Old relay (same password = duplicate) → immediate EOF ✓
- Fix:
  * In CONNECT mode the deadline is still set before Start() (relay must respond within seconds).
  * In LISTEN mode the deadline is NOT set before Start() — Start() may legitimately block indefinitely. The deadline is deferred to just before the TLS handshake (set after Start() returns successfully), so a hung TLS peer is still bounded but the wait for a connector is not.
- Added diagnostic GSPORT_DEBUG logs in gsrn.Start() to distinguish EOF (relay closed TCP) from i/o timeout (we timed out) — previously both surfaced as the same opaque "gsrn: read start/status: <err>" message.
- Added more GSPORT_DEBUG trace points in gsconn.Dial(): dialing relay, _gs_listen/_gs_connect sent, deadline set/cleared, role assigned, ready for TLS/raw.
- Wired -vvv to automatically set GSPORT_DEBUG=1 in the process env (previously the env var was undocumented and users had no way to enable it from the CLI). -v and -vv keep the original user-facing verbose output only.
- Added a user-visible "listening for incoming GS connections (will block until a peer connects)..." message in main.go before Dial() in LISTEN mode, so the user knows the program is doing what it's supposed to do.
- Bumped version to v0.1.17-fix.
- Built /home/z/my-project/download/gs-netcat-v0.1.17-fix.exe (3591680 bytes, Windows amd64).

Stage Summary:
- This was THE bug preventing the user from hosting a gs-netcat server on Windows. The Go port is now usable as a LISTEN-mode server.
- Same bug also affected -D (daemon) and -W (watchdog) modes that wrap a LISTEN-mode child — they would have crashed after 30s too.
- Verbose level differentiation (-v / -vv / -vvv) now matches the C original's intent: -vvv gives insanely verbose output, -vv gives more, -v gives normal.
- Artifact: /home/z/my-project/download/gs-netcat-v0.1.17-fix.exe
