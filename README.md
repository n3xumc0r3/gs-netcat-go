# gs-netcat-go

A pure-Go reimplementation of [`gs-netcat`](https://github.com/hackerschoice/gsocket)
from the [gsocket](https://github.com/hackerschoice/gsocket) suite by
[The Hacker's Choice](https://thc.org). This is a **fork** of that project —
the original C implementation lives at the link above and is licensed under
GPL-3.0. This Go port is licensed under the MIT License (see [LICENSE](LICENSE)).

## What it is

`gs-netcat` connects two peers through a GSRN relay using a shared secret,
then secures the channel with TLS-SRP (RFC 5054, ciphersuite 0xC020). No PKI,
no certificates — the shared secret is the entire authentication. A Go peer
and a C peer with the same secret can talk to each other through the same
production relay.

## Status

Drop-in compatible with the most common flags of C `gs-netcat` v1.4.40.
All cryptographic material (GS-Address, SRP username/password, auth-token)
is derived from the shared secret via the same KDF as the C original, so
interoperability is byte-for-byte.

**v0.1.30** adds 20+ new flags for transport, ops, observability, and
stealth. Each new flag is marked with a compatibility shorthand:

- **[G↔C]** works Go-client ↔ C-server AND C-client ↔ Go-server (universal)
- **[G↔G]** Go-Go only — a C peer will not understand (e.g. compress, stealth)
- **[--]** local-only — no wire-protocol impact (universal compat)

### Compatibility Matrix (v0.1.30)

| Feature / Flag | Go↔Go | Go↔C | C↔Go | Notes |
|---|:---:|:---:|:---:|---|
| `-s -k -g -a -l -r -q -v -w -L -t -m -h` | ✅ | ✅ | ✅ | Core, all peers interop |
| `-C` (no encryption) | ✅ | ✅ | ✅ | Both peers MUST agree |
| `-i -e --pwd --ids` | ✅ | ✅ | ✅ | Interactive shell, in-band mux |
| `-p -d` (port-forward) | ✅ | ✅ | ✅ | Both directions |
| `-D` (daemonize) | ✅ | ✅ | ✅ | v0.1.30: auto-enables `-W` (matches C) |
| `-W` (watchdog) | ✅ | ✅ | ✅ | Auto-restart on death |
| `--cos --low-latency --ping-interval` | ✅ | ✅ | ✅ | Wire-compat protocol flags |
| `--monitor` | ✅ | ✅ | ✅ | Polls both Go and C servers |
| `-T / --tor <h:p>` | ✅ | ✅ | ✅ | [G↔C] Tor SOCKS5 client |
| `--socks5` (also `-S`) | ✅ | ✅ | ✅ | [G↔C] SOCKS5 proxy server (was stub) |
| `--http-proxy` | ✅ | ✅ | ✅ | [G↔C] HTTP CONNECT proxy server |
| `--multi-relay` | ✅ | ✅ | ✅ | [--] Failover across relays |
| `--bind` `--ipv6` | ✅ | ✅ | ✅ | [--] Local bind control |
| `-o / --output` | ✅ | ✅ | ✅ | [--] File output |
| `--watch` `--retry` | ✅ | ✅ | ✅ | [--] Foreground auto-reconnect |
| `--max-session-time` | ✅ | ✅ | ✅ | [--] Auto-disconnect timer |
| `--max-peers` | ✅ | ✅ | ✅ | [--] Peer limit |
| `--post-exec` | ✅ | ✅ | ✅ | [--] Cleanup hook |
| `--rate-limit` | ✅ | ✅ | ✅ | [--] Bandwidth throttle |
| `--progress` | ✅ | ✅ | ✅ | [--] Transfer progress bar |
| `--json-logs` | ✅ | ✅ | ✅ | [--] Structured logging |
| `--audit-log` | ✅ | ✅ | ✅ | [--] Session recording |
| `--compress` | ✅ | ⚠️ | ⚠️ | [G↔G] C peer would see encoded bytes |
| `--stealth-https` | ✅ | ❌ | ❌ | [G↔G] C peer can't unwrap fake TLS |

### Implemented flags (v0.1.30)

Core (universal compat):

| Flag | Description |
|------|-------------|
| `-s <secret>` | Use this gs_secret. Both peers MUST match. |
| `-k <file>` | Read secret from first line of file. |
| `-g` | Generate a fresh 21-char base58 secret and exit. |
| `-a <token>` | Deterministic auth-token (default: random per session). |
| `-l` | Listen mode (be the server peer). |
| `-i` | Interactive mode — in-band multiplexing, PTY shell, escape encoding. |
| `-e <cmd>` | In interactive mode, execute cmd instead of default shell. |
| `-r` | Receive-only — don't close on stdin EOF, wait for remote. |
| `-q` | Quiet — suppress GS-Address log line. |
| `-v / -vv / -vvv` | Verbose (all collapse to "maximum"). |
| `-w` | Wait for listener to appear at relay (CONNECT mode). |
| `-L <file>` | Append log output to file. |
| `-t` | Test if peer is listening. Prints `<secret> <addr> OK\|NO\|NET-ERROR`, exit 0/61/202/203. |
| `-D` | Daemonize (auto-enables `-W` since v0.1.30, matches C). |
| `-W` | Watchdog — supervise and auto-restart on crash. Combine with `-D` for detached supervision. |
| `-C` | Disable TLS-SRP encryption (both peers MUST pass `-C`). |
| `-p <port>` | Port-forward (asymmetric: client = local listen, server = forward to `-d:port`). |
| `-d <ip>` | Port-forward destination IP (with `-l -p <port>`). |
| `-m` | Print man page and exit. |
| `-V` | Print version and exit. |
| `-o <file>` | Write received data to file (default: stdout). |
| `--relay H:P` | Relay endpoint (default: production gsocket.org relay derived from GS-Address). |
| `--cos` | Either peer may become SSL server. |
| `--low-latency` | Hint relay this is interactive (auto-set with `-i`). |
| `--ping-interval N` | Override app-ping interval seconds (default 45, `-i` only). |
| `--pwd` | Send PWD request after connecting (client role, `-i` only). |
| `--ids` | Subscribe to IDS alerts (client role, `-i` only). |
| `--monitor k1,k2,...` | Native multi-key polling mode — colored ONLINE/offline/NET-ERROR, beeps on ONLINE. |
| `--monitor-interval N` | Seconds between `--monitor` poll cycles (default 10). |

Transport:

| Flag | Compat | Description |
|------|--------|-------------|
| `-T / --tor <h:p>` | [G↔C] | Connect to relay via Tor SOCKS5 proxy (e.g. `127.0.0.1:9050`). |
| `-S / --socks5` | [G↔C] | Act as SOCKS5 server (needs `-l -p PORT`). Was a stub before v0.1.30. |
| `--http-proxy` | [G↔C] | Act as HTTP CONNECT proxy server (needs `-l -p PORT`). |
| `--multi-relay LIST` | [--] | Failover relays: `host:port,host:port,...` or `auto` to discover all `[a-z].gs.thc.org`. |
| `--bind <ip>` | [--] | Local IP to bind for port-forward listener (default `0.0.0.0`; use `127.0.0.1` for loopback). |
| `--ipv6` | [--] | Prefer IPv6 when resolving relay hostnames. |

Operational:

| Flag | Compat | Description |
|------|--------|-------------|
| `--no-watchdog` | [--] | Disable `-D` auto-implying `-W` (single-shot daemon, was pre-v0.1.30 behavior). |
| `--watch` | [--] | Foreground auto-reconnect (like `tail -f`). Incompatible with `-D` / `-W`. |
| `--retry N` | [--] | Max reconnect attempts (`0`=unlimited with `--watch`; `1`=single try, no reconnect). |
| `--max-session-time N` | [--] | Auto-disconnect after N seconds (`0`=unlimited). |
| `--max-peers N` | [--] | Limit multi-peer reconnect count in `-i -l` mode (`0`=unlimited). |
| `--post-exec CMD` | [--] | Run shell CMD after session disconnects (cleanup hook). |
| `--rate-limit N[KMG]` | [--] | Throttle outbound bandwidth (e.g. `100K`, `1M`, `500K`). |

Observability:

| Flag | Compat | Description |
|------|--------|-------------|
| `--json-logs` | [--] | Emit log lines as JSON (one per line) for machine parsing (Loki/ELK). |
| `--audit-log FILE` | [--] | Record all decrypted session I/O with timestamps (compliance / forensics). |
| `--progress` | [--] | Show transfer progress bar on stderr (bytes, rate, ETA). |

Stealth (Go-Go only — C peer will not understand):

| Flag | Compat | Description |
|------|--------|-------------|
| `--compress zstd\|gzip` | [G↔G] | Compress data stream (5-10× on text; C peer would see encoded bytes). |
| `--stealth-https` | [G↔G] | Wrap GSRN packets in fake TLS records (bypasses port-443 DPI). |

### Not yet implemented

- `-u` UDP port-forward (would break C interop)
- `--sftp` SFTP subsystem (deferred to v0.2)
- `--file-server` Built-in file server (deferred to v0.2)
- `--tls-fingerprint` Real JA3 mimicry via `utls` (deferred to v0.2)
- Console UI commands (`Ctrl-e + c`, etc.)
- True concurrent multi-peer (current: sequential re-listen after each peer disconnects)

## Build

```bash
# Linux/macOS
go build -o gs-netcat ./cmd/gs-netcat

# Cross-compile for Windows from Linux/macOS
GOOS=windows GOARCH=amd64 go build -o gs-netcat.exe ./cmd/gs-netcat

# Build everything (CLI + the two TLS-SRP debug tools)
go build ./...
```

No cgo. No external C libraries. Builds in ~2s on a modern machine.

## Quickstart

```bash
# Generate a fresh secret
./gs-netcat -g
# → FYQx8Lv91spGEhSJsgrYo

# Listen + interactive shell (server side)
./gs-netcat -l -i -s MySecret

# Connect (client side)
./gs-netcat -i -s MySecret

# Test if a peer is listening
./gs-netcat -t -s MySecret
# → MySecret 8502d7327081a0c0b77ad7c43f1f6e70 OK

# Monitor multiple peers (native replacement for the PS monitor script)
./gs-netcat --monitor key1,key2,key3
# → [12:46:26] [key1]  ONLINE   (key: key1)
# → [12:46:26] [key2]  offline  (key: key2)
# → [12:46:26] [key3]  NET-ERROR (network issue)

# Port-forward: client side binds local :2222
./gs-netcat -s S -p 2222

# Port-forward: server side forwards GS → 10.0.0.5:22
./gs-netcat -l -s S -d 10.0.0.5 -p 22

# Daemonized interactive shell with watchdog (v0.1.30: -D auto-enables -W)
./gs-netcat -l -i -s S -D -L /var/log/gs.log
```

## v0.1.30 — new feature examples

```bash
# Connect to relay via Tor SOCKS5 (relay sees Tor exit's IP, not yours)
./gs-netcat -i -s S --tor 127.0.0.1:9050

# Multi-relay failover: try 3 explicit relays in order
./gs-netcat -l -i -s S --multi-relay v.gs.thc.org:443,c.gs.thc.org:443,n.gs.thc.org:443

# Multi-relay 'auto': discover all 26 [a-z].gs.thc.org, prefer the one
# matching your GS-Address (default relay selection), fall through on failure
./gs-netcat -l -i -s S --multi-relay auto

# SOCKS5 server: tunnel all local apps through the remote GS peer
# (e.g. set Firefox/curl to use 127.0.0.1:1080 as SOCKS5)
./gs-netcat -l -i -s S -e "/bin/cat"              # remote side
./gs-netcat -p 1080 --socks5 -s S                  # local side

# HTTP CONNECT proxy server (e.g. for curl --proxy)
./gs-netcat -l -i -s S -e "/bin/cat"               # remote side
./gs-netcat -p 8080 --http-proxy -s S              # local side
curl --proxy http://127.0.0.1:8080 http://remote-target/

# Foreground auto-reconnect (like `tail -f` for shell sessions)
./gs-netcat -i --watch --retry 5 -s S

# Auto-disconnect after 1 hour (operational safety / billing)
./gs-netcat -i -s S --max-session-time 3600

# Limit multi-peer reconnects (anti-resource-exhaustion)
./gs-netcat -l -i -s S --max-peers 10

# Throttle to 100 KB/s (stealth / fair-sharing)
./gs-netcat -s S -e "tar -c /backup" --rate-limit 100K --progress -o /tmp/backup.tar

# JSON logs for Loki/ELK ingestion
./gs-netcat -l -i -s S --json-logs -L /var/log/gs.json

# Audit-log session I/O (compliance / forensics)
./gs-netcat -l -i -s S --audit-log /var/log/gs-session.audit

# Cleanup hook after session ends (e.g. remove lockfile)
./gs-netcat -i -s S --post-exec "rm -f /tmp/session.lock"

# Go-Go only: compress the data stream (5-10× on text)
./gs-netcat -l -s S -e "tar -c /home"                  # server (Go)
./gs-netcat -s S --compress gzip -o /tmp/home.tar.gz   # client (Go)

# Go-Go only: stealth HTTPS wrapping (bypasses port-443 DPI)
# Both peers MUST pass --stealth-https
./gs-netcat -l -i -s S --stealth-https                  # server (Go)
./gs-netcat -i -s S --stealth-https                      # client (Go)
```

## How "local-only" flags work

Flags marked `[--]` in the compat matrix (e.g. `--rate-limit`, `--progress`,
`--audit-log`, `--json-logs`, `--max-session-time`, `--post-exec`,
`--max-peers`, `--bind`, `--ipv6`, `--multi-relay`, `-o/--output`,
`--watch`, `--retry`, `--no-watchdog`) are **strictly local** — they have
zero impact on the wire protocol between the two peers. They only affect:

- The local process (data plumbing, scheduling, file I/O)
- The local network interface (bind address, IP family preference)
- The local log / audit / progress output

This means you can mix-and-match them freely between Go and C peers
without breaking interop. For example, a Go client with `--rate-limit 100K`
talking to a C server works fine — the C server just receives a slower
stream of bytes; it has no way to tell rate-limiting was applied.

The only flags that affect the wire are:
- **Protocol flags** (always wire-compat with C): `--cos`, `--low-latency`,
  `--ping-interval`, `-w`, `--relay`, `-C`
- **Go-Go only extensions** (NOT wire-compat with C): `--compress`,
  `--stealth-https` — these add in-band channel packets or wrap the
  TCP connection in a way the C original doesn't decode

## Project layout

```
cmd/gs-netcat/      # CLI entry point + flag dispatchers
  main.go           # run(), flag parsing, mode dispatch
  test_mode.go      # -t
  monitor_mode.go   # --monitor
  daemon.go         # -D / -W (re-exec pattern, no fork())
  daemon_unix.go    #   Unix: Setpgid
  daemon_windows.go #   Windows: CREATE_NO_WINDOW | DETACHED_PROCESS
  portforward.go    # -p / -d
  multipeer.go      # -l -i sequential re-listen loop
  prompt.go         # stdin secret prompt
  console_cp_*.go   # Windows UTF-8 + ANSI-VT init
  sigwinch_*.go     # SIGWINCH handler (Unix) / poller (Windows)
  cwd_*.go          # /proc/<pid>/cwd lookup (Linux) / fallback
  # v0.1.30 additions:
  multi_relay.go    # --multi-relay (with 'auto' discovery)
  tor.go            # -T / --tor (SOCKS5 client to relay)
  proxy.go          # --socks5 / --http-proxy (proxy server)
  ratelimit.go      # --rate-limit (token bucket)
  audit.go          # --audit-log (session recording)
  progress.go       # --progress (transfer bar)
  watch.go          # --watch (foreground auto-reconnect)
  jsonlogs.go       # --json-logs (structured logging)
  compress.go       # --compress (gzip stream compression, Go-Go)
  stealth.go        # --stealth-https (fake TLS framing, Go-Go)

internal/
  gskdf/            # KDF: SHA256-based derivation of GS-Address + SRP password
  gsrn/             # GSRN relay protocol (listen/connect/start/status packets)
  tlssrp/           # TLS-SRP (RFC 5054, ciphersuite 0xC020) — pure Go, no OpenSSL
  gsconn/           # high-level Conn wrapper: gsrn + tlssrp + in-band events
  gspkt/            # in-band escape-byte multiplexing protocol
  gspty/            # PTY spawn (Unix openpty, Windows ConPTY)
  gsids/            # IDS utmp polling + alert delivery
  gsstats/          # load/idle/n_users collection for PONG replies
```

## Interop with C gs-netcat

A Go peer and a C peer with the same secret can talk to each other through
the same production relay. Verified against C `gs-netcat` v1.4.42:

- Raw byte pipe (cat mode) — both directions, large files (1 MB+ verified by MD5)
- Interactive shell (`-i`) with PTY, window resize, PING/PONG keepalive
- `ChnPWD` (working directory query) and `WSIZE` (window size) events
- IDS subscription (`--ids` ↔ Ctrl-e + c in C console UI)
- `-t` test mode against a C listener — same OK/NO/NET-ERROR output, same exit codes
- `-C` no-encryption mode — both peers MUST agree (mismatched fails safely)
- `-D` daemonize — v0.1.30 now auto-enables `-W` to match C's `GS_daemonize()` semantics
- Port-forward (`-p`/`-d`) — both directions
- Multi-peer sequential reconnect (Go server, 10 sequential C clients verified)
- Long-idle (4-minute session with multiple 90s idle periods survived — PING/PONG works)
- Unicode, ANSI escape sequences, 0xFB escape byte in stream — all preserved

### Connecting to a C server deployed via `gsocket.io/y`

The THC deploy script (`bash -c "$(curl -fsSL https://gsocket.io/y)"`)
launches the C `gs-netcat` listener with the default flags
`-l -i -q -D` (listen + **in-band** + quiet + daemonize). This means
the C server is in **in-band** mode.

**You MUST pass `-i` on the Go client side to match.** Without `-i`:

| Symptom | Cause |
|---------|-------|
| Strange characters appearing at the prompt during idle (every ~45 s) | The C server sends in-band PING packets (`0xFB 0x10 ...`); a raw-mode Go client doesn't decode them and writes the bytes to stdout as garbage |
| Connection freezes after a few commands | The C server runs `GS_PKT_decode` on your raw input stream; random bytes that look like in-band escape sequences trigger a protocol error → server closes the connection |
| "Connection closed" within seconds of connecting | Same as above — any byte in your input that the C server's decoder rejects will tear down the session |

**Correct usage:**

```powershell
# Windows / Linux / macOS — always add -i when the server was deployed
# via gsocket.io/y (or any other method that uses -i on the server side)
./gs-netcat -i -s <secret>
```

If you control both sides and want raw byte pipe (no in-band multiplexing),
omit `-i` on BOTH ends:

```bash
# Server (Go port): raw byte pipe, no in-band
./gs-netcat -l -s MySecret

# Client (Go port): raw byte pipe, no in-band
./gs-netcat -s MySecret
```

## Acknowledgements

- The original [`gsocket`](https://github.com/hackerschoice/gsocket) project
  by **The Hacker's Choice** — without their clean C codebase and protocol
  documentation, this port would not have been possible.
- The GSRN relay network operated at `*.gs.thc.org` — used by default for
  production deployments.

## License

MIT — see [LICENSE](LICENSE). The upstream C project is GPL-3.0; this is a
clean-room reimplementation in Go from the protocol specification, with
reference to the C source for wire-compatibility verification.
