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

---
Task ID: v0.1.19-diagnosis
Agent: external-audit
Task: Diagnose user-reported "disconnect after a few commands" + "character at idle" symptoms against the v0.1.18-fix HEAD.

Work Log:
- Cloned repo, read README, worklog, all internal/* packages, cmd/gs-netcat/*.
- Decoded all strs.Decode(...) obfuscated strings (8 call sites) — all benign (env names, log messages, /bin/sh, cmd.exe).
- Reviewed decoder state machine in internal/gspkt/gspkt.go — correct, no byte-leak path found.
- Reviewed inBandRead/inBandWrite in internal/gsconn/inband.go — correct concurrency (pktMu protects decoder + dataBuf + events channel).
- Reviewed tlssrp.Conn locking (in.Mutex / out.Mutex) — concurrent Read+Write safe.
- Identified 3 confirmed bugs + 6 contributing issues; applied minimal patches for the 3 confirmed bugs.

Root cause of "disconnect after a few commands":
- Bug 1 (PRIMARY): internal/gsconn/gsconn.go inBandPinger silently returns on WriteMsg error (network blip, DPI RST, momentary relay congestion). Connection lingers in half-dead state, no more PINGs sent, NAT/relay idle timeout fires 60-180s later → sudden disconnect.
- Bug 2 (CONTRIBUTING): cmd/gs-netcat/main.go handleMessage MsgPING case — PONG write failure logged but no conn.Close(). Client keeps PINGing into the void.
- Bug 4 (CONTRIBUTING): No PONG delivery tracking on client — cannot detect dead server until TCP retransmit timeout (minutes).

Root cause of "character at idle":
- Most likely Bug 7 (interop): C-original gs-netcat server intercepts Ctrl-e (0x05) for its console UI. Go client doesn't know about it; C server may send ANSI status sequences that appear as stray characters on Go client's stdout.
- Alternative: Bug 8 — spurious WSIZE events on Windows from polling GetConsoleScreenBufferInfo (srWindow may oscillate by 1px on scrollback/zoom), causing server's ConPTY to redraw cmd.exe screen.
- Could not reproduce deterministically without a live C server.

Patches applied to local clone (all compile, tests pass with -race):
- 01: inBandPinger now calls c.Close() on WriteMsg error (instead of silent return).
- 02: Server's MsgPONG handler now calls conn.Close() on WriteMsg error.
- 03: Conn.Close() now safely closes c.ib.events under pktMu + eventsClosed flag, so eventPump goroutine stops leaking on every disconnect.

Built artifacts:
- /home/z/my-project/download/gs-netcat-patched      (Linux amd64)
- /home/z/my-project/download/gs-netcat-patched.exe  (Windows amd64)
- /home/z/my-project/download/patches/all-three-fixes.patch
- /home/z/my-project/download/gs-netcat-go-diagnosis.md (full report)

Stage Summary:
- 3 of 9 identified issues patched. Remaining 6 (PONG tracking, client reconnect, DPI on established session, Ctrl-e interop, WSIZE hysteresis, instantEOF after Established) require larger changes and are documented in the diagnosis report.
- All existing unit tests still pass; no test regressions.
- Race detector clean.
- go vet reports the same pre-existing tlssrp lock-copy warning (unchanged).
