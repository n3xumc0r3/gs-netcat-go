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

Implemented flags:

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
| `-D` | Daemonize — detach from terminal (Setpgid on Unix, CREATE_NO_WINDOW on Windows). |
| `-W` | Watchdog — supervise and auto-restart on crash. Combine with `-D` for detached supervision. |
| `-C` | Disable TLS-SRP encryption (both peers MUST pass `-C`). |
| `-p <port>` | Port-forward (asymmetric: client = local listen, server = forward to `-d:port`). |
| `-d <ip>` | Port-forward destination IP (with `-l -p <port>`). |
| `-m` | Print man page and exit. |
| `--relay H:P` | Relay endpoint (default: production gsocket.org relay derived from GS-Address). |
| `--cos` | Either peer may become SSL server. |
| `--low-latency` | Hint relay this is interactive. |
| `--ping-interval N` | Override app-ping interval seconds (default 45, `-i` only). |
| `--pwd` | Send PWD request after connecting (client role, `-i` only). |
| `--ids` | Subscribe to IDS alerts (client role, `-i` only). |
| `--monitor k1,k2,...` | Native multi-key polling mode — colored ONLINE/offline/NET-ERROR, beeps on ONLINE. |
| `--monitor-interval N` | Seconds between `--monitor` poll cycles (default 10). |

Not yet implemented (see `gs-netcat -m` for the full list):
- `-T` Tor/SOCKS proxy (use `--relay` to a local Tor relay instead)
- `-u` UDP port-forward
- `-S` SOCKS server (returns a clear error)
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

# Daemonized interactive shell with watchdog
./gs-netcat -l -i -s S -D -W -L /var/log/gs.log
```

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
the same production relay. Verified against C `gs-netcat` v1.4.40:

- Raw byte pipe (cat mode) — both directions, large files (1 MB+)
- Interactive shell (`-i`) with PTY, window resize, PING/PONG
- `ChnPWD` (working directory query) and `WSIZE` (window size) events
- IDS subscription (`--ids` ↔ Ctrl-e + c in C console UI)
- `-t` test mode against a C listener — same OK/NO/NET-ERROR output

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
