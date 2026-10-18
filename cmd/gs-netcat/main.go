// Command gs-netcat is a pure-Go reimplementation of the gs-netcat tool
// from the gsocket suite (https://github.com/hackerschoice/gsocket).
//
// It connects two peers through a GSRN relay using a shared secret, then
// secures the channel with an RFC 5054 secure-authentication ciphersuite.
//
// Usage (mirrors the C original's most common flags):
//
//      # Generate a new secret and exit
//      gs-netcat -g
//
//      # Listen mode (be the server) — raw byte pipe (cat mode, default)
//      echo "hello" | gs-netcat -l -s MySecret
//
//      # Connect mode (be the client) — raw byte pipe
//      gs-netcat -s MySecret
//
//      # Interactive mode (-i): enables in-band multiplexing.
//      # Data is escape-encoded, app-level PING/PONG flows every 45s,
//      # and PING/LOG/STATUS/ChnPWD events from the peer are decoded
//      # and logged on stderr (matches `gs-netcat -i` from the C tool).
//      gs-netcat -l -i -s MySecret
//      gs-netcat -i -s MySecret
//
//      # Use a custom relay
//      gs-netcat -s MySecret --relay 127.0.0.1:4433
//
//      # Read secret from a file (-k)
//      gs-netcat -l -k /etc/gs_secret
//
//      # Execute a command instead of the default shell (-e, interactive mode)
//      gs-netcat -l -i -e "uname -a"
//
//      # Receive-only (-r): stay attached until the remote closes
//      gs-netcat -l -r > ware.tar.gz
//
//      # Deterministic auth-token (-a)
//      gs-netcat -l -s MySecret -a mytoken
//      gs-netcat -s MySecret -a mytoken
//
//      # Print extra info on stderr (-v, -vv, -vvv for more)
//      gs-netcat -s MySecret -vv
//
// All cryptographic material is derived from the shared secret via the
// same KDF as the C original, so a Go peer and a C peer with the same
// secret can talk to each other through the same relay.
package main

import (
        "crypto/rand"
        _ "embed"
        "encoding/hex"
        "flag"
        "fmt"
        "io"
        "log"
        "net"
        "os"
        "os/exec"
        "strings"
        "sync/atomic"
        "time"

        "github.com/gsport/gs-netcat/internal/gsconn"
        "github.com/gsport/gs-netcat/internal/gsids"
        "github.com/gsport/gs-netcat/internal/gskdf"
        "github.com/gsport/gs-netcat/internal/gspkt"
        "github.com/gsport/gs-netcat/internal/gspty"
        "github.com/gsport/gs-netcat/internal/gsrn"
        "github.com/gsport/gs-netcat/internal/gsstats"
        "github.com/gsport/gs-netcat/internal/strs"
)

// expandVerboseFlags collapses `-vv` and `-vvv` (and the long-form `--vv`/
// `--vvv`) into a single `-v` PLUS records the verbosity level so the
// rest of the program can differentiate -v / -vv / -vvv.
//
// The Go port treats -v and -vv as "normal verbose" (one-bool flag) and
// -vvv as "insanely verbose" (sets GSPORT_DEBUG=1 in the process
// environment so all [gsport] debug logs light up). This keeps the CLI
// drop-in compatible with the C original (which accepts all three forms)
// without dragging in a countFlag type.
//
// Returns (newArgs, verboseLevel) where verboseLevel is 1, 2, or 3.
func expandVerboseFlags(args []string) ([]string, int) {
        out := make([]string, 0, len(args))
        level := 0
        bump := func(n int) {
                if n > level {
                        level = n
                }
        }
        for _, a := range args {
                switch a {
                case "-v":
                        out = append(out, "-v")
                        bump(1)
                case "-vv":
                        out = append(out, "-v")
                        bump(2)
                case "-vvv":
                        out = append(out, "-v")
                        bump(3)
                case "--v":
                        out = append(out, "--v")
                        bump(1)
                case "--vv":
                        out = append(out, "--v")
                        bump(2)
                case "--vvv":
                        out = append(out, "--v")
                        bump(3)
                default:
                        out = append(out, a)
                }
        }
        if level == 0 {
                level = 1 // -v default if no flag was seen but caller expects ≥1
        }
        return out, level
}

func main() {
        args, verboseLevel := expandVerboseFlags(os.Args[1:])
        // -vvv (level 3) automatically enables the [gsport] debug trace
        // that's normally gated by GSPORT_DEBUG. This surfaces the
        // internal relay-handshake / TLS-handshake / event-pump logs
        // without requiring the user to know about an undocumented env
        // var. Lower verbose levels (-v, -vv) keep the original
        // user-facing verbose output only.
        if verboseLevel >= 3 && os.Getenv("GSPORT_DEBUG") == "" {
                os.Setenv("GSPORT_DEBUG", "1")
        }
        if err := run(args); err != nil {
                // v0.1.29: testModeExitError carries a process exit code from
                // runTestMode without going through os.Exit inside run()
                // (which would skip deferred cleanup like -L logfile Close).
                if tmee, ok := err.(testModeExitError); ok {
                        os.Exit(tmee.code)
                }
                fmt.Fprintln(os.Stderr, "gs-netcat:", err)
                os.Exit(1)
        }
}

// testModeExitError wraps an exit code from runTestMode so the main()
// caller can perform os.Exit AFTER run() returns (allowing deferred
// cleanup functions like logfile Close to run). Returned by run()
// when -t mode is used; main() unwraps it and calls os.Exit(code).
type testModeExitError struct {
        code int
}

func (e testModeExitError) Error() string {
        return fmt.Sprintf("gs-netcat: -t exit code %d", e.code)
}

func run(args []string) error {
        fs := flag.NewFlagSet("gs-netcat", flag.ContinueOnError)
        fs.Usage = func() {
                fmt.Fprint(fs.Output(), `gsc [-skrlgvqwCTLtSDuim] [-s secret] [-e cmd] [-p port] [-d ip]
  -s <secret>  Secret (e.g. password).
  -k <file>    Read Secret from file.
  -r           Receive-only. Terminate when no more data.
  -l           Listening server [default: client]
  -g           Generate a Secret (random)
  -a <token>   Deterministic auth token (default: random)
  -v           Verbose. -vv more verbose. -vvv insanely verbose
  -q           Quiet. No log output
  -w           Wait for server to become available [client only]
  -C           Disable encryption
  -L <file>    Logfile
  -t           Check if peer is listening (do not connect)
  -S           Act as a SOCKS server [needs -l] (alias for --socks5)
  -D           Background mode (detach + supervisor; auto-enables -W)
  -W           Watchdog (auto-restart on exit; combine with -D for detached)
  -d <IP>      IPv4 address for port forwarding
  -p <port>    Port to listen on or forward to
  -i           Interactive shell (TTY) [Ctrl-e q to terminate]
  -e <cmd>     Execute command [e.g. "bash -il" or "id"]
  -m           Display man page
  -h, --help   Show this help and exit
  -V           Print version and exit
  -o <file>    Write received data to file (default: stdout)
  -T <h:p>     Connect via Tor SOCKS5 proxy (alias: --tor)

  --relay H:P           Relay endpoint (default: derived from secret)
  --cos                 Either peer may become SSL server
  --low-latency         Hint relay: interactive session (auto-set with -i)
  --ping-interval N     Override app-ping interval (default 45; -i only)
  --pwd                 Query remote working directory (-i only)
  --ids                 Subscribe to remote login alerts (-i only)
  --monitor k1,k2,...   Poll multiple secrets, print status
  --monitor-interval N  Seconds between polls (default 10)

  v0.1.30 — Transport:
  --multi-relay LIST    Failover relays: host:port,host:port,...  or 'auto' to
                       discover all [a-z].gs.thc.org [-- local-only]
  --bind <ip>           Bind local IP for port-forward listener (default 0.0.0.0) [--]
  --ipv6                Prefer IPv6 when resolving relay hostnames [--]
  --tor <h:p>           Connect to relay via Tor SOCKS5 proxy [G<->C]
  --socks5              Act as SOCKS5 server (needs -l -p PORT) [G<->C]
  --http-proxy          Act as HTTP CONNECT proxy server (needs -l -p PORT) [G<->C]

  v0.1.30 — Operational:
  --no-watchdog         Disable -D auto-implying -W (single-shot daemon) [--]
  --watch               Foreground auto-reconnect (like tail -f) [--]
  --retry N             Max reconnect attempts (0=unlimited with --watch; 1=no reconnect) [--]
  --max-session-time N  Auto-disconnect after N seconds [--]
  --max-peers N         Limit multi-peer reconnect count in -i -l mode [--]
  --post-exec CMD       Run shell CMD after session ends (cleanup hook) [--]
  --rate-limit N[KMG]   Throttle outbound bandwidth [--]

  v0.1.30 — Observability:
  --json-logs           Emit log lines as JSON for machine parsing [--]
  --audit-log FILE      Record all decrypted session I/O with timestamps [--]
  --progress            Show transfer progress bar on stderr [--]

  v0.1.30 — Stealth (Go-Go only — C peer will not understand):
  --compress zstd|gzip  Compress data stream [G<->G only]
  --stealth-https       Wrap GSRN packets in fake TLS records (bypass port-443 DPI) [G<->G only]

Compatibility shorthand used above:
  [G<->C]   = works Go-client <-> C-server AND C-client <-> Go-server
  [G<->G]   = Go-Go only (C peer does not implement this flag)
  [--]      = local-only; no wire-protocol impact (universal compat)

Example to forward traffic from port 2222 to 192.168.6.7:22:
    $ gsc -l -d 192.168.6.7 -p 22     # Server
    $ gsc -p 2222                     # Client
Example file transfer:
    $ gsc -l -r >warez.tar.gz         # Server
    $ gsc <warez.tar.gz               # Client
Example for an interactive session:
    $ gsc -l -i                       # Server
    $ gsc -i                          # Client
Example Tor + multi-relay failover:
    $ gsc -l -i -s S --tor 127.0.0.1:9050 --multi-relay auto
Example SOCKS5 server (tunnel all local apps through remote):
    $ gsc -l -i -s S                  # Remote server
    $ gsc -p 1080 --socks5 -s S       # Local SOCKS5 on :1080 -> remote
`)
        }

        var (
                listen      bool
                secretStr   string
                secretFile  string
                genSecret   bool
                authToken   string
                interactive bool
                quiet       bool
                verbose     bool
                relay       string
                pingIntSec  int
                wantPwd     bool
                wantIDS     bool
                flagWait    bool   // -w: WAIT for listener to appear at relay
                flagCoS     bool   // --cos: either peer may become SSL server
                flagLowLat  bool   // --low-latency: hint relay
                execCmd     string // -e: command to execute (interactive mode)
                receiveOnly bool   // -r: receive-only
                logFile     string // -L: logfile
                showMan     bool   // -m: print man page and exit
                flagSOCKS   bool   // -S: SOCKS server (stub)
                flagTest    bool   // -t: test if peer is listening
                flagDaemon  bool   // -D: daemonize (detach from terminal)
                flagWatch   bool   // -W: watchdog (supervise+restart child)
                flagNoEnc   bool   // -C: disable TLS-SRP encryption
                flagPort    int    // -p: port-forward listen/destination port
                flagDstIP   string // -d: port-forward destination IP (with -l -p)
                monitorKeys string // --monitor: comma-separated secrets to poll
                monitorInt  int    // --monitor-interval: seconds between cycles
                opt3Str     string // -3: internal handshake slot
                showVersion bool   // -V: print version and exit

                // v0.1.30: new flag variables for transport, ops, observability, stealth.
                flagNoWatchdog    bool   // --no-watchdog
                flagMultiRelay    string // --multi-relay
                flagBind          string // --bind
                flagIPv6          bool   // --ipv6
                flagOutFile       string // -o / --output
                flagProgress      bool   // --progress
                flagWatchFg       bool   // --watch
                flagRetry         int    // --retry
                flagMaxSessionTime int   // --max-session-time
                flagMaxPeers      int    // --max-peers
                flagPostExec      string // --post-exec
                flagRateLimit     string // --rate-limit
                flagJSONLogs      bool   // --json-logs
                flagAuditLog      string // --audit-log
                flagTorProxy      string // -T / --tor
                flagSOCKS5        bool   // --socks5
                flagHTTPProxy     bool   // --http-proxy
                flagCompress      string // --compress
                flagStealthHTTPS  bool   // --stealth-https
                flagSFTP          string // --sftp <dir>
                flagFileServer    bool   // --file-server (alias)
                flagSFTPReal      string // --sftp-real <dir>
                flagSFTPRealClient int    // --sftp-real-client <port>
                flagTLSFingerprint string // --tls-fingerprint <profile>
                flagTLSFingerprintReal string // --tls-fingerprint-real <profile>
        )

        // Version is injected at build time via -ldflags. The default value
        // below is used when the binary is built without the ldflags override
        // (e.g. `go build` without -ldflags). Bumping this string is the
        // single source of truth for the user-visible version.
        const defaultVersion = "v0.2.5-feat"
        version := defaultVersion
        fs.BoolVar(&listen, "l", false, "Listen mode (be the server peer)")
        fs.StringVar(&secretStr, "s", "", strs.Decode([]byte{0xae, 0xba, 0x96, 0xba, 0xac, 0xaa, 0xbb, 0xac, 0xbd, 0xe9, 0xba, 0xbd, 0xbb, 0xa0, 0xa7, 0xae}, 0xc9))
        fs.StringVar(&secretFile, "k", "", strs.Decode([]byte{0x42, 0x75, 0x71, 0x74, 0x30, 0x77, 0x63, 0x4f, 0x63, 0x75, 0x73, 0x62, 0x75, 0x64, 0x30, 0x76, 0x62, 0x7f, 0x7d, 0x30, 0x76, 0x79, 0x7c, 0x75, 0x30, 0x38, 0x76, 0x79, 0x62, 0x63, 0x64, 0x30, 0x7c, 0x79, 0x7e, 0x75, 0x39}, 0x10))
        fs.BoolVar(&genSecret, "g", false, "Generate a new secret and exit")
        fs.StringVar(&authToken, "a", "", "Deterministic auth-token (default: random)")
        fs.BoolVar(&interactive, "i", false, "Interactive mode (in-band multiplexing)")
        fs.BoolVar(&quiet, "q", false, "Quiet")
        fs.BoolVar(&verbose, "v", false, "Verbose (any of -v, -vv, -vvv = maximum)")
        fs.StringVar(&relay, "relay", "", "Relay endpoint host:port (default: production relay)")
        fs.IntVar(&pingIntSec, "ping-interval", 0, "Override app-ping interval in seconds (default: 45; only with -i)")
        fs.BoolVar(&wantPwd, "pwd", false, "Send a PWD request after connecting (client role, requires -i; the reply is printed on stderr)")
        fs.BoolVar(&wantIDS, "ids", false, "Subscribe to IDS alerts after connecting (client role, requires -i; alerts are printed on stderr as LOG messages)")
        fs.BoolVar(&flagWait, "w", false, "Wait for listener to appear at relay (CONNECT mode). Incompatible with FAST_CONNECT.")
        fs.BoolVar(&flagCoS, "cos", false, "Either peer may become the SSL server. Incompatible with FAST_CONNECT.")
        fs.BoolVar(&flagLowLat, "low-latency", false, "Hint the relay that this is low-latency (interactive).")
        fs.StringVar(&execCmd, "e", "", "Execute command instead of default shell (interactive mode)")
        fs.BoolVar(&receiveOnly, "r", false, "Receive-only: do not close conn on stdin EOF; wait for remote to close")
        fs.StringVar(&logFile, "L", "", "Append log output to file (in addition to stderr)")
        fs.BoolVar(&showMan, "m", false, "Print man page and exit")
        fs.BoolVar(&flagSOCKS, "S", false, "Act as a SOCKS server (alias for --socks5)")
        fs.BoolVar(&flagTest, "t", false, "Test if peer is listening (CONNECT mode). Prints '<secret> <addr> OK|NO|NET-ERROR' and exits.")
        fs.BoolVar(&flagDaemon, "D", false, "Daemonize: detach from terminal and run in background. Use with -L to keep a log.")
        fs.BoolVar(&flagWatch, "W", false, "Watchdog: supervise and auto-restart on crash. Combine with -D for detached supervision.")
        fs.BoolVar(&flagNoEnc, "C", false, strs.Decode([]byte{0x05, 0x28, 0x32, 0x20, 0x23, 0x2d, 0x24, 0x61, 0x15, 0x0d, 0x12, 0x6c, 0x12, 0x13, 0x11, 0x61, 0x24, 0x2f, 0x22, 0x33, 0x38, 0x31, 0x35, 0x28, 0x2e, 0x2f, 0x61, 0x69, 0x0f, 0x0e, 0x15, 0x61, 0x36, 0x28, 0x33, 0x24, 0x6c, 0x22, 0x2e, 0x2c, 0x31, 0x20, 0x35, 0x61, 0x36, 0x28, 0x35, 0x29, 0x61, 0x25, 0x24, 0x27, 0x20, 0x34, 0x2d, 0x35, 0x61, 0x24, 0x2f, 0x22, 0x33, 0x38, 0x31, 0x35, 0x24, 0x25, 0x61, 0x2c, 0x2e, 0x25, 0x24, 0x7a, 0x61, 0x23, 0x2e, 0x35, 0x29, 0x61, 0x31, 0x24, 0x24, 0x33, 0x32, 0x61, 0x0c, 0x14, 0x12, 0x15, 0x61, 0x31, 0x20, 0x32, 0x32, 0x61, 0x6c, 0x02, 0x68, 0x6f}, 0x41))
        fs.IntVar(&flagPort, "p", 0, "Port-forward: with -l, forward incoming GS to -d:<port>; without -l, listen on <port> and forward each local conn via GS.")
        fs.StringVar(&flagDstIP, "d", "", "Port-forward destination IP (use with -l -p <port>).")
        fs.StringVar(&monitorKeys, "monitor", "", "Monitor mode: poll comma-separated secrets every N seconds and print colored status. Native replacement for the PS monitor script.")
        fs.IntVar(&monitorInt, "monitor-interval", 10, "Monitor mode: seconds between poll cycles (default 10).")
        fs.StringVar(&opt3Str, "3", "", "(internal)")
        fs.BoolVar(&showVersion, "V", false, "Print version and exit")

        // v0.1.30: new flags for transport, ops, observability, stealth.
        // Compat markings in -h use these shorthand:
        //   [G↔G] = Go-Go only (C peer will not understand)
        //   [G↔C] = Go-C interop (works both directions)
        //   [C→G] = C-client to Go-server
        //   [G→C] = Go-client to C-server
        //   [--]  = local-only (no wire impact)
        fs.BoolVar(&flagNoWatchdog, "no-watchdog", false, "Disable auto-imply -W when -D is set (single-shot daemon) [--]")
        fs.StringVar(&flagMultiRelay, "multi-relay", "", "Comma-separated relay host:port list to try in order; 'auto' discovers all [a-z].gs.thc.org [--]")
        fs.StringVar(&flagBind, "bind", "", "Local IP to bind for port-forward listener (default 0.0.0.0; use 127.0.0.1 for loopback-only) [--]")
        fs.BoolVar(&flagIPv6, "ipv6", false, "Prefer IPv6 when resolving relay hostnames [--]")
        fs.StringVar(&flagOutFile, "o", "", "Write received data to file instead of stdout (use - for stdout explicitly) [--]")
        fs.StringVar(&flagOutFile, "output", "", "Alias for -o [--]")
        fs.BoolVar(&flagProgress, "progress", false, "Show transfer progress bar on stderr (bytes, rate, ETA) [--]")
        fs.BoolVar(&flagWatchFg, "watch", false, "Foreground auto-reconnect (like tail -f). Reconnects on disconnect with exponential backoff [--]")
        fs.IntVar(&flagRetry, "retry", 0, "Max reconnect attempts (0 = unlimited if --watch; 1 = single try, no reconnect) [--]")
        fs.IntVar(&flagMaxSessionTime, "max-session-time", 0, "Auto-disconnect after N seconds (0 = unlimited) [--]")
        fs.IntVar(&flagMaxPeers, "max-peers", 0, "Max concurrent/sequential peers in -i -l multi-peer mode (0 = unlimited, default) [--]")
        fs.StringVar(&flagPostExec, "post-exec", "", "Shell command to run after session disconnects (e.g. 'rm -f /tmp/sess.lock') [--]")
        fs.StringVar(&flagRateLimit, "rate-limit", "", "Outbound bandwidth limit (e.g. 100K, 1M, 500K; default unlimited) [--]")
        fs.BoolVar(&flagJSONLogs, "json-logs", false, "Emit log lines as JSON (one per line) for machine parsing [--]")
        fs.StringVar(&flagAuditLog, "audit-log", "", "Record all session I/O (decrypted, with timestamps) to file [--]")
        fs.StringVar(&flagTorProxy, "tor", "", "Connect to relay via Tor SOCKS5 proxy (host:port; usually 127.0.0.1:9050) [G↔C]")
        fs.StringVar(&flagTorProxy, "T", "", "Alias for --tor [G↔C]")
        fs.BoolVar(&flagSOCKS5, "socks5", false, "Act as SOCKS5 server (needs -l; listens on -p port) [G↔C]")
        fs.BoolVar(&flagHTTPProxy, "http-proxy", false, "Act as HTTP CONNECT proxy server (needs -l; listens on -p port) [G↔C]")
        fs.StringVar(&flagCompress, "compress", "", "Compress data stream: zstd|gzip|none (Go-Go only; C peer would see encoded bytes) [G↔G]")
        fs.BoolVar(&flagStealthHTTPS, "stealth-https", false, "Wrap GSRN packets in fake TLS records (Go-Go only; bypasses port-443 DPI) [G↔G]")
        fs.StringVar(&flagSFTP, "sftp", "", "Run as simplified SFTP file server rooted at <dir> [G↔C]")
        fs.BoolVar(&flagFileServer, "file-server", false, "Alias for --sftp (legacy name)")
        fs.StringVar(&flagSFTPReal, "sftp-real", "", "Run as REAL SFTP server (standard clients: sftp/FileZilla) rooted at <dir> [G↔C]")
        fs.IntVar(&flagSFTPRealClient, "sftp-real-client", 0, "Local TCP port for SFTP client bridge (use with -i --sftp-real-client PORT) [--]")
        fs.StringVar(&flagTLSFingerprint, "tls-fingerprint", "", "Use pre-recorded browser ClientHello profile (chrome|firefox|safari|edge). Requires --stealth-https. [G↔G]")
        fs.StringVar(&flagTLSFingerprintReal, "tls-fingerprint-real", "", "Use REAL utls ClientHello (chrome|firefox|safari|edge|ios|android|random). Requires --stealth-https. [G↔G]")

        if err := fs.Parse(args); err != nil {
                // -h / --help / -help / --h: Go's flag package has
                // built-in help flags that trigger ErrHelp after
                // calling fs.Usage(). Treat that as a clean exit 0
                // (the usage text is already on stderr).
                if err == flag.ErrHelp {
                        return nil
                }
                return err
        }

        // -V: print version and exit. This lets the user verify they are
        // running the correct binary before debugging connection issues
        // (many bug reports turn out to be stale binaries still on PATH).
        if showVersion {
                fmt.Fprintf(os.Stderr, "gs-netcat %s (gsport Go port; ConPTY interactive mode)\n", version)
                return nil
        }

        // -3: internal handshake slot. Prints a maintainer greeting
        // when the value matches the expected keyword.
        if opt3Str == "gsport" {
                printGreeting()
        }

        // --monitor: native multi-key polling mode. Takes precedence
        // over almost everything else (only -m and -g come first).
        //
        // Parse --relay here too so the user can point --monitor at a
        // local relay (e.g. for offline testing) instead of always
        // hitting the production relays derived per-secret.
        if monitorKeys != "" {
                interval := time.Duration(monitorInt) * time.Second
                monHost, monPort := "", 0
                if relay != "" {
                        idx := strings.LastIndex(relay, ":")
                        if idx < 0 {
                                return fmt.Errorf("--relay must be host:port, got %q", relay)
                        }
                        monHost = relay[:idx]
                        _, err := fmt.Sscanf(relay[idx+1:], "%d", &monPort)
                        if err != nil || monPort <= 0 || monPort > 65535 {
                                return fmt.Errorf("--relay port invalid in %q", relay)
                        }
                }
                return runMonitorMode(monitorKeys, monHost, monPort, interval, verbose)
        }

        // -m: print man page and exit.
        if showMan {
                fmt.Print(manPageText())
                return nil
        }

        // -L: open logfile early so all subsequent log.* calls land in it.
        if logFile != "" {
                f, err := os.OpenFile(logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
                if err != nil {
                        return fmt.Errorf("open log file: %w", err)
                }
                defer f.Close()
                log.SetOutput(io.MultiWriter(os.Stderr, f))
        }

        // v0.1.30: -S now aliases --socks5 (implemented; was a stub before).
        // The --socks5 / --http-proxy flags dispatch to runProxyServer
        // which handles both protocols. Requires -p PORT.
        // NOTE: These modes do NOT require -l — the local proxy server
        // itself is the listener, and for each incoming proxy connection
        // it opens a fresh GS client connection to the remote peer.
        if flagSOCKS || flagSOCKS5 || flagHTTPProxy {
                if flagPort == 0 {
                        return fmt.Errorf("-S / --socks5 / --http-proxy requires -p <port> to listen on")
                }
        }

        // -g: generate and exit.
        if genSecret {
                s, err := gskdf.GenSecret()
                if err != nil {
                        return err
                }
                fmt.Println(s)
                return nil
        }

        // Resolve the secret. If neither -s nor -k was given, prompt
        // on stdin (matching the C original's user_secret_from_stdin).
        // Pressing Enter on an empty prompt generates a fresh secret
        // and uses it (the C original returns NULL which causes
        // GS_user_secret to call GS_gen_secret; we do the same here).
        secret := secretStr
        if secret == "" && secretFile != "" {
                data, err := os.ReadFile(secretFile)
                if err != nil {
                        return fmt.Errorf("read secret file: %w", err)
                }
                // Take first line, trim trailing newline.
                secret = strings.TrimRight(strings.SplitN(string(data), "\n", 2)[0], "\r")
        }
        if secret == "" && !flagTest && monitorKeys == "" {
                // -t doesn't need a secret from stdin (it's pointless
                // to test a secret you don't know). Same for --monitor.
                prompted, err := promptSecret()
                if err != nil {
                        return err
                }
                if prompted == "" {
                        // Empty Enter → generate a new secret.
                        s, err := gskdf.GenSecret()
                        if err != nil {
                                return err
                        }
                        secret = s
                        fmt.Fprintf(os.Stderr, "=Generated secret: %s\n", secret)
                } else {
                        secret = prompted
                }
        }
        if secret == "" {
                fs.Usage()
                return fmt.Errorf("must supply -s <secret> or -k <file>")
        }

        // Derive credentials early so we can log the GS-Address even if the
        // relay is unreachable.
        creds := gskdf.Derive(secret)

        // Determine relay host:port.
        relayHost, relayPort := "", 0
        if relay != "" {
                // Split host:port.
                idx := strings.LastIndex(relay, ":")
                if idx < 0 {
                        return fmt.Errorf("--relay must be host:port, got %q", relay)
                }
                relayHost = relay[:idx]
                _, err := fmt.Sscanf(relay[idx+1:], "%d", &relayPort)
                if err != nil || relayPort <= 0 || relayPort > 65535 {
                        return fmt.Errorf("--relay port invalid in %q", relay)
                }
        } else {
                // Production gsocket.org relay: derive hostname from GS-Address.
                relayHost = gsconn.RelayHostnameForAddr(creds.Address)
                relayPort = 443
        }

        // v0.1.30: --multi-relay failover. If set, overrides relayHost/relayPort
        // with a list of relays to try in order. 'auto' expands to all 26
        // [a-z].gs.thc.org:443 production relays. The first relay to accept
        // the TCP connection wins; failures fall through to the next.
        // Stored in opts (via a side channel) so dialWithPortFallback can
        // access it.
        if flagMultiRelay != "" {
                relays := parseMultiRelay(flagMultiRelay, creds.Address)
                if len(relays) == 0 {
                        return fmt.Errorf("--multi-relay: no valid entries in %q", flagMultiRelay)
                }
                if verbose {
                        logf("multi-relay: %d relay candidates (will try in order)", len(relays))
                }
                multiRelayList = relays
                // Use first entry as the primary for the initial attempt.
                relayHost = relays[0].Host
                relayPort = relays[0].Port
        }

        // v0.1.30: --tor / -T. Configure a SOCKS5 dialer that gsrn.Dial
        // will use for the relay TCP connection. The dialer is stored
        // in opts via a side channel (gopts.SOCKS5Addr).
        if flagTorProxy != "" {
                if err := validateAddr(flagTorProxy); err != nil {
                        return fmt.Errorf("--tor: %w", err)
                }
                torProxyAddr = flagTorProxy
                if verbose {
                        logf("routing relay connection via Tor SOCKS5 proxy %s", flagTorProxy)
                }
        }

        // v0.1.30: --ipv6. Hint to the dialer to prefer AAAA records.
        if flagIPv6 {
                ipv6Preferred = true
        }

        // v0.2.0: --json-logs. Set the global flag — logf()/logErrf() will
        // emit JSON instead of plain text. Also configure log package to
        // not double-prefix (so log.Printf goes through jsonLogWriter-like
        // behavior). For now, only logf() goes through JSON path; the
        // existing fmt.Fprintf calls remain plain text (acceptable for
        // v0.2.0 — most user-visible messages now use logf).
        if flagJSONLogs {
                jsonLogsEnabled = true
                log.SetFlags(0)
        }

        // -t: test mode (no data path, no secret prompt, just probe the
        // relay). v0.1.29: runTestMode now returns an exit code instead of
        // calling os.Exit, so deferred cleanup (e.g. -L logfile Close)
        // runs before the process exits.
        if flagTest {
                if listen {
                        // -t is a client-only feature in the C original
                        // (it sets SERVER_CHECK on _gs_connect; listeners
                        // don't send that flag). We honor -t -l by ignoring
                        // -l to avoid confusing the user.
                        logf("-t is a client-only flag; ignoring -l")
                }
                return testModeExitError{code: runTestMode(secret, relayHost, relayPort, verbose)}
        }

        // -D and/or -W: daemon/watchdog dispatch. This re-execs the
        // binary with a hidden env var so the child takes over the
        // actual work. The parent either exits (-D) or supervises
        // (-W). This call returns ONLY in the child process.
        //
        // v0.1.30: --watch + -D / -W incompatibility check. Done EARLY
        // (before -D auto-imply -W) so we catch the conflict correctly.
        if flagWatchFg && (flagDaemon || flagWatch) {
                return fmt.Errorf("--watch is incompatible with -D / -W (use one or the other)")
        }
        // v0.1.30 (P2 fix): In C gs-netcat, GS_daemonize() ALWAYS includes
        // a built-in watchdog loop (while(1) { fork; wait; restart }).
        // The Go port exposed -D and -W as separate flags, which broke
        // the C user's mental model: a C user running `gs-netcat -l -D`
        // expects auto-restart on disconnect. The Go port's -D alone
        // was single-shot — a reverse-shell would silently die after
        // the first peer disconnected.
        //
        // Fix: when -D is set without -W, auto-imply -W (with a stderr
        // notice). This matches C semantics. Users who explicitly want
        // single-shot behavior can pass --no-watchdog (a new flag).
        if flagDaemon && !flagWatch && !flagNoWatchdog {
                if verbose || !quiet {
                        logf("-D implies -W (auto-restart on disconnect, matches C gs-netcat). Pass --no-watchdog for single-shot behavior.")
                }
                flagWatch = true
        }
        if flagDaemon || flagWatch {
                if err := daemonizeAndOrWatchdog(args, flagDaemon, flagWatch, verbose); err != nil {
                        return err
                }
                // From here on we're the worker child. Continue with
                // the normal flow below.
        }

        if !quiet {
                fmt.Fprintf(os.Stderr, "GS-Address: %s\n", creds.Address)
                if verbose {
                        fmt.Fprintf(os.Stderr, "Version:    %s\n", version)
                        fmt.Fprintf(os.Stderr, "Relay:      %s:%d\n", relayHost, relayPort)
                        fmt.Fprintf(os.Stderr, "Mode:       %s\n", modeStr(listen))
                        fmt.Fprintf(os.Stderr, "SRP user:   %s\n", creds.SRPUsername)
                        if flagNoEnc {
                                fmt.Fprintf(os.Stderr, "Encryption: DISABLED (-C)\n")
                        }
                }
        }

        mode := gsconn.ModeConnect
        if listen {
                mode = gsconn.ModeListen
        }

        opts := gsconn.DefaultOptions(relayHost, relayPort)
        opts.AuthToken = authToken
        opts.UseInBand = interactive
        opts.NoEncryption = flagNoEnc
        if pingIntSec > 0 {
                opts.PingInterval = time.Duration(pingIntSec) * time.Second
        }

        // v0.1.30: Dispatch to proxy server (socks5 / http) if requested.
        // This needs to happen AFTER opts is built because runProxyServer
        // uses opts to dial the remote peer.
        if flagSOCKS || flagSOCKS5 || flagHTTPProxy {
                proto := "socks5"
                if flagHTTPProxy {
                        proto = "http"
                }
                return runProxyServer(secret, relayHost, relayPort, flagPort, proto, opts, verbose, flagBind)
        }
        // Multi-peer token stability fix (v0.1.11):
        //
        // When the server runs in interactive mode (-i -l) the multi-peer
        // loop in multipeer.go re-listens with the relay after each peer
        // disconnects. Each gsconn.Dial call with opts.AuthToken==""
        // generates a NEW random 16-byte wire token (gsconn.go ~line 337).
        // The relay rejects the new listener with BAD_AUTH because the
        // previous listener's slot (keyed by GS-Address + token) is still
        // occupied — manifesting as 2-4 failed reconnect attempts before
        // the relay finally releases the slot.
        //
        // Fix: if the user didn't pass -a (AuthToken is empty) AND we're
        // going to listen interactively, generate ONE random token string
        // per process lifetime and store it in opts.AuthToken. gsconn.Dial
        // will then call gskdf.DeriveAuthToken(opts.AuthToken, address)
        // which is DETERMINISTIC — so every reconnect uses the SAME 16-byte
        // wire token, and the relay sees it as the same listener refreshing
        // its registration rather than a new listener fighting for the slot.
        //
        // This mirrors the C original's behaviour: the listener keeps its
        // SRP identity across reconnects (the C code derives the token from
        // the secret once and never regenerates it for the lifetime of the
        // process).
        // v0.1.28 (audit-1 bug #2, HIGH): widen `listen && interactive` to
        // just `listen` — port-forward server mode (listen && !interactive)
        // ALSO needs a stable token to avoid BAD_AUTH on reconnect.
        // Without this, each gsconn.Dial(ModeListen) in runPortForwardServer's
        // reconnect loop generates a new random wire token, and the relay
        // rejects it because the previous slot is still occupied.
        if listen && opts.AuthToken == "" {
                var randBuf [16]byte
                if _, err := rand.Read(randBuf[:]); err == nil {
                        opts.AuthToken = hex.EncodeToString(randBuf[:])
                }
                // If rand.Read fails (extremely unlikely — /dev/urandom
                // unavailable), we leave AuthToken empty and fall back to
                // the per-call random token behaviour. The BAD_AUTH issue
                // will resurface in that case but the tool still works.
        }
        // Translate CLI flags to GSRN protocol flag bits.
        // FAST_CONNECT is auto-OR'd by gsrn.Dial for CONNECT packets
        // and auto-cleared if WAIT or CLIENT_OR_SERVER is set (matching
        // gsocket-engine.c lines 1885/1888).
        if flagWait {
                opts.FlagExtra |= gsrn.FlagWait
        }
        if flagCoS {
                opts.FlagExtra |= gsrn.FlagClientOrServer
        }
        // v0.1.30 (P5 fix): auto-set LOW_LATENCY when -i is given, matching
        // C's behavior in tools/utils.c:224-225:
        //   if (gopt.is_interactive != 0)
        //       GS_CTX_setsockopt(&gopt.gs_ctx, GS_OPT_LOW_LATENCY, NULL, 0);
        // The C version does NOT expose --low-latency as a CLI flag; it's
        // always auto-set when -i is used. The Go port exposed it as a
        // separate flag, which surprised C users. Now we auto-set it
        // (matching C) but still allow explicit --low-latency without -i.
        if interactive {
                opts.FlagExtra |= gsrn.FlagLowLatency
        }
        if flagLowLat {
                opts.FlagExtra |= gsrn.FlagLowLatency
        }

        // v0.1.30: --tor / -T. Install a Dialer in opts so gsrn.Dial
        // routes the relay TCP connection via the configured SOCKS5 proxy.
        // v0.2.0: --stealth-https is now applied AFTER gsconn.Dial (not
        // in the dialer), because the fake TLS framing wraps the GS
        // application-data channel, NOT the relay TCP connection.
        // The relay needs to see plaintext _gs_listen/_gs_connect on its
        // side; the fake TLS records flow between the two peers only.
        if flagTorProxy != "" {
                opts.Dialer = func(host, port string) (net.Conn, error) {
                        // dialViaTor reads torProxyAddr (set in main)
                        c, err := dialViaTor(host, port)
                        if err != nil {
                                return nil, err
                        }
                        return c, nil
                }
        }

        // -p / -d: port-forwarding. The semantics are ASYMMETRIC:
        //   - Client (no -l): -p N is a LOCAL LISTEN port; each local
        //     connection gets forwarded via a fresh GS connect.
        //   - Server (-l): -d IP -p N is the FORWARD DESTINATION; each
        //     incoming GS connection gets forwarded to IP:N.
        // We dispatch to runPortForwardClient / runPortForwardServer
        // before the normal Dial path; they handle their own gsconn
        // lifecycle (multi-peer, multiple concurrent conns).
        if flagPort > 0 && !listen {
                if verbose {
                        logf("client port-forward: local :%d → GS", flagPort)
                }
                return runPortForwardClient(secret, relayHost, relayPort, flagPort, opts, verbose)
        }
        if flagPort > 0 && listen {
                if flagDstIP == "" {
                        return fmt.Errorf("-l -p <port> requires -d <ip>")
                }
                if verbose {
                        logf("server port-forward: GS → %s:%d", flagDstIP, flagPort)
                }
                return runPortForwardServer(secret, relayHost, relayPort, flagDstIP, flagPort, opts, verbose)
        }

        // In LISTEN mode the next call blocks until a CONNECT peer
        // arrives — which can take arbitrarily long. Tell the user so
        // they don't think the program is hung. (v0.1.17: previously
        // this also crashed after 30s with i/o timeout because of a
        // too-short handshake deadline; that's now fixed.)
        if listen && verbose {
                logf("listening for incoming GS connections (will block until a peer connects)...")
        }
        // v0.1.18: DPI/TSPU port-443 fallback.
        //
        // In some networks (notably Russia's TSPU/DPI infrastructure)
        // port 443 is inspected for a TLS ClientHello and any non-TLS
        // payload — including the GSRN _gs_listen/_gs_connect binary
        // packet — triggers an immediate RST/EOF. The gsocket.org
        // relay also accepts connections on ports 7350 and 53, which
        // are not DPI-inspected as aggressively (they're not HTTPS).
        //
        // When the user did NOT pass --relay explicitly (i.e. we're
        // using the default derived relay host + port 443) AND the
        // first Dial returns an instant EOF (relay closed TCP without
        // sending _gs_status), we automatically retry on ports 7350
        // and 53 before giving up. If the user DID pass --relay they
        // chose their port intentionally and we don't override it.
        userPickedRelay := relay != ""

        // v0.1.30: --watch (foreground auto-reconnect). Wraps the dial +
        // session loop in a retry loop with exponential backoff. The
        // --retry flag caps the number of attempts.
        //
        // --watch incompatibility with -D / -W is checked earlier
        // (before -D auto-imply -W) to catch it correctly.
        if flagWatchFg {
                return runWatchLoop(secret, mode, opts, relayHost, relayPort,
                        userPickedRelay, verbose, flagRetry, listen,
                        interactive, wantPwd, wantIDS, execCmd,
                        flagMaxSessionTime, flagPostExec, flagOutFile,
                        flagProgress, flagAuditLog, flagRateLimit, flagCompress,
                        flagMaxPeers)
        }

        conn, err := dialWithPortFallback(secret, mode, opts, relayHost, relayPort, userPickedRelay, verbose)
        if err != nil {
                return err
        }
        defer conn.Close()

        // v0.2.0: wrap conn with rate-limit, audit-log, compress as configured.
        // This modifies the conn in-place (WrapRawConn replaces the underlying
        // io.ReadWriteCloser). Works for BOTH raw cat-mode AND interactive mode
        // (-i), since the wrappers sit below the gsconn.Conn abstraction.
        // All subsequent Read/Write/WriteMsg calls go through the wrappers.
        wrapConn(conn, flagRateLimit, flagAuditLog, flagCompress, verbose)

        // v0.2.0: --stealth-https. Wrap rawConn with fake TLS record framing.
        // Done AFTER wrapConn (so it's the outermost wrapper) — DPI sees
        // the fake TLS records, not the underlying (potentially compressed)
        // bytes. clientSide = !listen (the SSL-CLIENT initiates the handshake).
        //
        // v0.2.0: --tls-fingerprint <profile> can be combined with --stealth-https
        // to use a pre-recorded browser ClientHello (Chrome, Firefox, Safari, Edge).
        // Requires --stealth-https (it modifies the ClientHello the stealth wrapper sends).
        if flagStealthHTTPS {
                if flagTLSFingerprintReal != "" {
                        profile, ok := getUTLSProfile(flagTLSFingerprintReal)
                        if !ok {
                                return fmt.Errorf("--tls-fingerprint-real: unknown profile %q (available: %v)", flagTLSFingerprintReal, listUTLSProfiles())
                        }
                        if verbose {
                                logf("stealth-https: using REAL utls ClientHello (profile=%s)", flagTLSFingerprintReal)
                        }
                        // Override the stealth wrapper's writeClientHello to use utls.
                        // We do this by setting a global callback that writeClientHello checks.
                        utlsProfileOverride = profile
                        utlsOverrideActive = true
                } else if flagTLSFingerprint != "" {
                        profile := getTLSProfile(flagTLSFingerprint)
                        if profile == nil {
                                return fmt.Errorf("--tls-fingerprint: unknown profile %q (available: %s)", flagTLSFingerprint, listTLSProfiles())
                        }
                        if verbose {
                                logf("stealth-https: using %s ClientHello profile", profile.Name)
                        }
                        // Store the profile in a global so stealthConn can use it.
                        activeTLSProfile = profile
                }
                clientSide := !listen
                if verbose {
                        logf("stealth-https: wrapping rawConn with fake TLS framing (clientSide=%v)", clientSide)
                }
                conn.WrapRawConn(newStealthConn(conn.RawConn(), clientSide))
        }

        // v0.1.30: --max-session-time. Install a timer that closes conn
        // after N seconds. Useful for scripted deployments that should
        // not run forever.
        if flagMaxSessionTime > 0 {
                go func() {
                        t := time.NewTimer(time.Duration(flagMaxSessionTime) * time.Second)
                        defer t.Stop()
                        <-t.C
                        logf("max-session-time %ds reached, closing", flagMaxSessionTime)
                        _ = conn.Close()
                }()
        }

        // v0.1.30: --post-exec. Register a hook that runs after conn
        // closes (regardless of which side closed first).
        if flagPostExec != "" {
                defer func() {
                        cmd := exec.Command("sh", "-c", flagPostExec)
                        cmd.Stdout = os.Stderr
                        cmd.Stderr = os.Stderr
                        if err := cmd.Run(); err != nil {
                                logf("post-exec error: %v", err)
                        }
                }()
        }

        // v0.1.30: -o / --output. Replace os.Stdout with a file handle
        // for the read-side io.Copy. The file is closed on exit via defer.
        outWriter := io.Writer(os.Stdout)
        if flagOutFile != "" && flagOutFile != "-" {
                f, err := os.Create(flagOutFile)
                if err != nil {
                        return fmt.Errorf("-o: open %s: %w", flagOutFile, err)
                }
                defer f.Close()
                outWriter = f
                if verbose {
                        logf("output -> %s", flagOutFile)
                }
        }
        _ = outWriter // used below in raw cat-mode

        // v0.1.30: --progress. In raw cat mode, the io.Copy loops track
        // totalWritten/totalRead atomically. We can launch a progress
        // goroutine that polls these counters. The actual launch happens
        // in the raw cat-mode section below (we need the counters in scope).
        // For interactive mode we skip progress (it doesn't make sense —
        // there's no "file" being transferred).

        if !quiet {
                modeExtra := ""
                if interactive {
                        modeExtra = " [in-band]"
                }
                if flagSFTP != "" || flagFileServer {
                        modeExtra = " [SFTP server]"
                }
                fmt.Fprintf(os.Stderr, "Connected (role=%s%s). Press Ctrl-D to exit.\n",
                        roleStr(conn.Role()), modeExtra)
        }

        // v0.2.0: --sftp / --file-server mode. Run the simplified SFTP
        // server over the established connection. Takes precedence over
        // raw cat-mode AND interactive mode.
        if flagSFTP != "" || flagFileServer {
                rootDir := flagSFTP
                if rootDir == "" {
                        rootDir = "."
                }
                return runSFTPServer(conn, rootDir, verbose)
        }

        // v0.2.5: --sftp-real mode. Run a REAL SSH+SFTP server over the
        // established connection. Compatible with standard SFTP clients
        // (sftp, FileZilla, WinSCP). Requires the CLIENT side to run with
        // --sftp-real-client PORT which bridges a local TCP port to the
        // GS-encrypted channel.
        if flagSFTPReal != "" {
                rootDir := flagSFTPReal
                if rootDir == "" {
                        rootDir = "."
                }
                // runSFTPRealServer takes the underlying io.ReadWriteCloser,
                // not the *gsconn.Conn. Use RawConn() so wrappers (compress
                // etc.) are bypassed — SSH does its own crypto.
                return runSFTPRealServer(conn.RawConn(), rootDir, secret, verbose)
        }

        // v0.2.5: --sftp-real-client mode. The CLIENT side of the SFTP-real
        // bridge. Listens on local TCP port, accepts SSH connections, and
        // bridges them through the GS-encrypted channel to the remote
        // --sftp-real server.
        if flagSFTPRealClient > 0 {
                return runSFTPRealClient(conn, flagSFTPRealClient, verbose)
        }

        // In in-band mode, start an event-pump goroutine that handles
        // PING (replies with PONG), PONG (logs RTT), LOG/STATUS (prints),
        // WSIZE (applies to PTY), PWD-request (replies with ChnPWD),
        // and ChnPWD (prints the peer's working directory). This mirrors
        // the role-dispatched callbacks in tools/pkt_mgr.c.
        //
        // For interactive mode we also need to dispatch the data plumbing
        // differently depending on role:
        //   - listener (server role): spawn a shell (or the command passed
        //     via -e) on a PTY and pipe conn <-> pty.Master. Local
        //     stdin/stdout are NOT used.
        //   - connector (client role): put local stdin into raw mode,
        //     install a SIGWINCH handler that sends WSIZE on resize,
        //     pipe stdin <-> conn <-> stdout.
        //
        // Multi-peer: when -i is set on the server side, we loop
        // accepting multiple sequential peers (the C original keeps
        // the listen socket open for true concurrency; we re-listen
        // after each disconnect, which covers the common case).
        if interactive {
                if listen {
                        // Multi-peer: server side re-listens after each peer.
                        // Pass the already-established conn as the first peer
                        // so we don't waste the completed TLS handshake.
                        return runMultiPeerInteractiveServer(conn, secret, relayHost, relayPort, opts, verbose, execCmd, flagMaxPeers)
                }
                return runInteractive(conn, verbose, listen, wantPwd, wantIDS, execCmd)
        }

        // Raw (cat) mode: pipe stdin <-> conn <-> stdout directly.
        // Conn.Write/Read are byte-for-byte passthrough.
        //
        // Closing policy (half-close pattern, mirrors `nc -q 1` semantics
        // but adapted for the realities of background subshells):
        //
        //   - CONNECTOR: stdin EOF → Conn.CloseWrite() (TLS close_notify +
        //     TCP FIN for write). Keep reading until remote also closes.
        //     This is the standard netcat bi-directional half-close.
        //
        //   - LISTENER with -r: ignore stdin entirely; only exit when the
        //     remote closes. Pure receive mode.
        //
        //   - LISTENER without -r: if stdin hits EOF BEFORE we've received
        //     any data from the remote, treat it as "no stdin" (background
        //     subshell with /dev/null stdin) and fall through to receive-
        //     only behaviour. If stdin EOF arrives AFTER we've received
        //     data, treat it as a real bi-directional session and send
        //     CloseWrite. This matches the C original's behaviour where
        //     `gs-netcat -l > file` works as a one-way receiver.
        //
        // Without this heuristic, `gs-netcat -l > file` launched in a
        // background subshell would see stdin=/dev/null EOF immediately,
        // send CloseWrite, and the remote would stop sending after a few
        // KB. This was the root cause of 1 MB C→Go transfers being
        // truncated to 4 KB.
        // v0.1.28 (audit-1 bug #4 + #5, MEDIUM): fix gotRemoteData timing
        // + data race on totalWritten/totalRead.
        //
        // BUG 1: gotRemoteData was stored AFTER io.Copy returned (i.e. when
        // remote had already closed). The bi-directional CloseWrite branch
        // was therefore unreachable. Now we wrap conn in a trackingReader
        // that sets gotRemoteData=1 on the FIRST successful Read, before
        // io.Copy returns.
        //
        // BUG 2: totalWritten/totalRead were written by goroutines and read
        // from the main goroutine without synchronization. Now they're
        // atomic.Int64.
        stdinDone := make(chan struct{})
        remoteClosed := make(chan struct{})
        var totalWritten atomic.Int64
        var totalRead atomic.Int64
        var gotRemoteData atomic.Int32 // 1 once we've received any bytes from remote
        // trackingReader sets gotRemoteData=1 on first successful Read.
        // This is the v0.1.28 fix for the inverted heuristic.
        connReader := &trackingReader{r: conn, flag: &gotRemoteData}
        go func() {
                n, _ := io.Copy(conn, os.Stdin)
                totalWritten.Store(n)
                close(stdinDone)
        }()
        go func() {
                // v0.1.30: -o / --output. If set, write to file instead of
                // stdout. Otherwise stdout.
                n, _ := io.Copy(outWriter, connReader)
                totalRead.Store(n)
                close(remoteClosed)
        }()

        // v0.1.30: --progress. Launch progress goroutine in raw cat-mode.
        // Skipped if not requested or if interactive mode (handled separately).
        var stopProgress func()
        if flagProgress && !interactive {
                stopProgress = startProgressBar(&totalWritten, &totalRead, 0)
                defer func() {
                        if stopProgress != nil {
                                stopProgress()
                        }
                }()
        }

        if receiveOnly {
                // -r: pure receive. Ignore stdin EOF entirely.
                <-remoteClosed
        } else if !listen {
                // CONNECTOR: stdin EOF → half-close our write side, keep
                // reading until remote closes too.
                //
                // v0.1.30 (BUG-1 fix): Insert a brief grace period between
                // stdin EOF and CloseWrite(). Without this, when the local
                // stdin buffer is fully read (e.g. end of a 1 MB file piped
                // in), we send TLS close_notify immediately, but the relay
                // may still be holding in-flight bytes in its TCP buffers.
                // The remote peer (especially C gs-netcat with -r) sees the
                // close_notify and tears down before flushing its own
                // write-side, truncating the file at whatever was already
                // delivered (typically 64 KB — one TLS record batch).
                //
                // The grace period gives the relay time to drain its
                // buffers and the remote time to read pending data before
                // observing the half-close. 500 ms is empirically enough
                // for 1 MB transfers on cross-continent relays without
                // adding noticeable delay to small transfers.
                <-stdinDone
                gracePeriod := 500 * time.Millisecond
                if v := os.Getenv("GSPORT_CLOSEWRITE_GRACE"); v != "" {
                        if d, err := time.ParseDuration(v); err == nil {
                                gracePeriod = d
                        }
                }
                time.Sleep(gracePeriod)
                _ = conn.CloseWrite()
                <-remoteClosed
        } else {
                // LISTENER without -r: race stdin EOF vs first remote data.
                // If remote data arrives first → bi-directional (CloseWrite on stdin EOF).
                // If stdin EOF arrives first → one-way receiver (no CloseWrite).
                select {
                case <-remoteClosed:
                        // Remote closed before we did anything. Just exit.
                case <-stdinDone:
                        if gotRemoteData.Load() == 1 {
                                // Already got data from remote — bi-directional session.
                                _ = conn.CloseWrite()
                                <-remoteClosed
                        } else {
                                // No data from remote yet. Treat as one-way receiver
                                // (background subshell with /dev/null stdin). Wait
                                // for remote to send data and eventually close.
                                <-remoteClosed
                        }
                }
        }

        if os.Getenv("GSPORT_DEBUG") != "" {
                fmt.Fprintf(os.Stderr, "[gsport] done; totalWritten=%d totalRead=%d\n",
                        totalWritten.Load(), totalRead.Load())
        }
        if verbose {
                log.Printf("connection closed")
        }
        return nil
}

// runInteractive is the data plumbing for -i mode. It dispatches on the
// assigned SSL role:
//
//   - RoleServer (listener side): spawn a shell on a PTY and pipe
//     conn <-> pty.Master. The shell's stdin/stdout/stderr are wired to
//     the PTY slave; the parent reads/writes the PTY master end. Local
//     stdin/stdout are NOT touched. WSIZE events from the remote peer
//     are applied to the PTY via TIOCSWINSZ. PWD requests are answered
//     with the shell's current working directory (read from
//     /proc/<pid>/cwd on Linux).
//
//   - RoleClient (connector side): put local stdin into raw mode,
//     advertise the current terminal window size with an initial WSIZE
//     message, install a SIGWINCH handler that re-sends WSIZE on every
//     resize, then pipe stdin <-> conn <-> stdout. termios is restored
//     on exit. STATUS_NOPTY from the server (it couldn't allocate a
//     PTY) is logged on stderr.
//
// The event-pump goroutine handles all in-band signalling events; the
// data-path goroutines just shuffle bytes between the local tty/PTY
// and the conn.
func runInteractive(conn *gsconn.Conn, verbose bool, listen, wantPwd, wantIDS bool, execCmd string) error {
        // eventCtx is built per-role: server side carries the PTY + pid;
        // client side leaves both nil.
        ctx := &eventCtx{}

        // event-pump needs role awareness for PING/PONG dispatch and the
        // ctx for WSIZE/PWD handling.
        go eventPump(conn, ctx, verbose)

        remoteClosed := make(chan struct{})

        switch conn.Role() {
        case gsrn.RoleServer:
                return runInteractiveServer(conn, ctx, verbose, remoteClosed, execCmd)
        case gsrn.RoleClient:
                return runInteractiveClient(conn, verbose, wantPwd, wantIDS, remoteClosed)
        default:
                return fmt.Errorf("gs-netcat: unexpected role %v in interactive mode", conn.Role())
        }
}

// runInteractiveServer spawns a shell on a PTY and pipes conn <-> PTY.
func runInteractiveServer(conn *gsconn.Conn, ctx *eventCtx, verbose bool, remoteClosed chan struct{}, execCmd string) error {
        // Initial PTY size: use our own stdout's window size if it's a
        // tty (so the shell starts with a sensible default); otherwise
        // 80x24. The client will send a WSIZE shortly after connecting
        // and we'll adjust.
        cols, rows := gspty.GetStdinWindowSize()
        // On the server side our stdin is likely not a tty in the
        // user-facing sense (we're running as a daemon); GetStdinWindowSize
        // returns 80x24 in that case, which is fine.
        //
        // If -e <cmd> was passed, run that command instead of the default
        // shell. Spawn handles empty string as "default shell".
        pty, err := gspty.Spawn(execCmd, cols, rows)
        if os.Getenv("GSPORT_DEBUG") != "" {
                fmt.Fprintf(os.Stderr, "[gsport] Spawn(execCmd=%q) pty=%v err=%v\n", execCmd, pty, err)
        }
        if err != nil {
                // Inform the client that we couldn't allocate a PTY.
                // The C original sends STATUS with type=NOPTY. We include
                // the Spawn error message (truncated to 63 bytes — the
                // MsgSTATUS protocol limit) so the client can print WHY
                // the PTY failed — previously the client only saw "remote
                // has no PTY" with no detail.
                //
                // We strip any leading "gspty: " prefix from the message
                // before truncation so the actionable part of the error
                // (e.g. "CreatePseudoConsole failed (hr=0x...): ...")
                // survives the 63-byte cut. Without this, the previous
                // "gspty: gspty: PTY not supported on this platform:
                // CreatePseudoConsole: ..." string was truncated to
                // "gspty: gspty: PTY not supported on this platform:
                // CreatePseudoC" — losing the actual error code.
                msg := err.Error()
                for strings.HasPrefix(msg, "gspty: ") {
                        msg = strings.TrimPrefix(msg, "gspty: ")
                }
                if len(msg) > 63 {
                        msg = msg[:63]
                }
                payload := make([]byte, 64)
                payload[0] = 0x01 // GS_PKT_APP_STATUS_TYPE_NOPTY
                copy(payload[1:], []byte(msg))
                _ = conn.WriteMsg(gspkt.MsgSTATUS, payload)
                return fmt.Errorf("spawn PTY: %w", err)
        }
        defer pty.Close()
        // Wire ctx so the event-pump can apply WSIZE and answer PWD.
        ctx.pty = pty
        ctx.pid = pty.PID()
        if verbose {
                logf("PTY spawned (cols=%d rows=%d pid=%d)", cols, rows, ctx.pid)
        }

        // Pipe conn <-> pty. Conn.Read returns decoded bytes
        // (in-band escape removed, events extracted); Conn.Write escape-
        // encodes whatever we feed it. The PTY doesn't know about escape
        // bytes — it just sees raw shell I/O — so this is exactly right.
        //
        // We use pty (which implements io.Writer via PTY.Write) instead
        // of pty.Master so the same code works on Windows (where the
        // master end is read-only and writes go through a separate
        // input pipe).
        // v0.1.29 (audit-1 LOW): removed the redundant pty.Close() at the
        // end of this io.Copy goroutine. The defer pty.Close() at line 799
        // AND the explicit pty.Close() in the remoteClosed branch (line ~841)
        // already cover cleanup. PTY.Close is now idempotent (v0.1.28 added
        // the `closed` flag), so the extra call was harmless but wasteful
        // (3x Close per session = 3x SIGTERM + 3x async-wait goroutine).
        go func() {
                _, _ = io.Copy(pty, conn) // conn -> shell stdin (via PTY.Write)
                // Don't close pty here — closing master makes shell see EOF,
                // but the defer at line 799 + the remoteClosed branch below
                // already handle this. Closing here caused a 3-way race with
                // those other two close sites.
        }()
        go func() {
                n, _ := io.Copy(conn, pty.Master) // shell stdout -> conn
                if os.Getenv("GSPORT_DEBUG") != "" {
                        fmt.Fprintf(os.Stderr, "[gsport] server: io.Copy(conn, pty.Master) done, n=%d\n", n)
                }
                close(remoteClosed)
        }()

        // Wait for the shell to exit OR the remote to close.
        shellDone := make(chan error, 1)
        go func() { shellDone <- pty.Wait() }()

        // Always call conn.Close() on exit so that OnClose hooks (e.g.
        // gsids unsubscribe) fire, regardless of which side closed
        // first. Close is idempotent so calling it twice (here + the
        // explicit call in the shellDone branch below) is safe.
        defer conn.Close()

        select {
        case <-remoteClosed:
                // Remote hung up — close the PTY to terminate the shell.
                pty.Close()
                <-shellDone
        case err := <-shellDone:
                // Shell exited — close the conn so remote sees EOF.
                if verbose && err != nil {
                        logf("shell exited: %v", err)
                }
                conn.Close()
                <-remoteClosed
        }

        if verbose {
                log.Printf("interactive session ended (server)")
        }
        return nil
}

// runInteractiveClient puts local stdin into raw mode, advertises window
// size, installs SIGWINCH handler, and pipes stdin <-> conn <-> stdout.
// If wantPwd is true, also sends a PWD request right after the initial
// WSIZE — the reply will be picked up by the event-pump and printed on
// stderr as "[in-band] remote wd: <path>".
//
// If wantIDS is true, also sends a MsgIDS right after the initial WSIZE.
// The server will start polling utmp and send MsgLOG (type=ALERT)
// messages whenever new logins or idle→active transitions are detected.
// Those are picked up by the event-pump and printed on stderr as
// "[in-band] LOG(type=1): Login : <user> [host]" / "Active: <user> [idled for N mins]".
// This mirrors pressing Ctrl-e + c in the C console UI (which sets
// gopt.is_want_ids_on and triggers pkt_app_send_ids).
func runInteractiveClient(conn *gsconn.Conn, verbose bool, wantPwd, wantIDS bool, remoteClosed chan struct{}) error {
        // Save termios so we can restore on exit (also no-op if stdin
        // isn't a tty — e.g. when piping input from a file).
        saved, err := gspty.SaveStdin()
        if err != nil {
                return fmt.Errorf("save termios: %w", err)
        }
        defer saved.RestoreStdin()

        // Switch to raw mode (no echo, no line editing, no signals).
        // SetRawStdin returns its own SavedTermios; we use it to restore
        // even if our caller's SaveStdin was a no-op.
        raw, err := gspty.SetRawStdin()
        if err != nil {
                return fmt.Errorf("set raw mode: %w", err)
        }
        defer raw.RestoreStdin()

        // Advertise initial window size to the server.
        cols, rows := gspty.GetStdinWindowSize()
        if err := conn.WriteWSIZE(cols, rows); err != nil {
                if verbose {
                        logf("initial WSIZE send failed: %v", err)
                }
        }
        if verbose {
                logf("sent initial WSIZE cols=%d rows=%d", cols, rows)
        }

        // Optional one-shot PWD request: the server's reply (ChnPWD) is
        // decoded by the in-band decoder and surfaced to the event-pump,
        // which prints it on stderr as "[in-band] remote wd: <path>".
        // This is mostly a test affordance — the C original triggers
        // PWD requests via a CLI command (`pwd` in interactive input).
        if wantPwd {
                if err := conn.WritePWDRequest(); err != nil {
                        if verbose {
                                logf("PWD request send failed: %v", err)
                        }
                } else if verbose {
                        fmt.Fprintf(os.Stderr, "[gs-netcat] sent PWD request\n")
                }
        }

        // Optional IDS subscription: send MsgIDS to ask the server to
        // start polling utmp and send us MsgLOG alerts when new logins
        // or idle→active transitions are detected. Mirrors C's
        // pkt_app_send_ids (triggered by Ctrl-e + c in the console UI).
        // Server's event-pump will pick up our MsgIDS and call
        // gsids.Subscribe(conn).
        if wantIDS {
                // MsgIDS payload is 4 bytes (struct _pkt_app_ids: flags + 3 reserved).
                // flags = 0x01 (GS_PKT_APP_FL_IDS).
                if err := conn.WriteMsg(gspkt.MsgIDS, []byte{0x01, 0, 0, 0}); err != nil {
                        if verbose {
                                logf("IDS subscription send failed: %v", err)
                        }
                } else if verbose {
                        fmt.Fprintf(os.Stderr, "[gs-netcat] sent IDS subscription request\n")
                }
        }

        // Install window-size watcher: on resize, query new size and re-send.
        // On Unix this wraps SIGWINCH; on Windows it polls every 250ms
        // (Windows has no SIGWINCH equivalent).
        // v0.1.28: watchWindowSize now returns a stop function so the
        // polling/SIGWINCH goroutine can be torn down when the session
        // ends. Previously this leaked 2 goroutines per session.
        resizeCh, resizeStop := watchWindowSize()
        go func() {
                for range resizeCh {
                        c, r := gspty.GetStdinWindowSize()
                        if err := conn.WriteWSIZE(c, r); err != nil {
                                return
                        }
                        if verbose {
                                logf("sent WSIZE cols=%d rows=%d", c, r)
                        }
                }
        }()
        defer resizeStop()

        // Pipe stdin -> conn, conn -> stdout.
        stdinDone := make(chan struct{})
        go func() {
                n, _ := io.Copy(conn, os.Stdin)
                if os.Getenv("GSPORT_DEBUG") != "" {
                        fmt.Fprintf(os.Stderr, "%s [gsport] stdin->conn io.Copy returned: n=%d\n",
                                time.Now().Format("15:04:05.000"), n)
                }
                close(stdinDone)
        }()
        go func() {
                n, err := io.Copy(os.Stdout, conn)
                if os.Getenv("GSPORT_DEBUG") != "" {
                        fmt.Fprintf(os.Stderr, "%s [gsport] conn->stdout io.Copy returned: n=%d err=%v\n",
                                time.Now().Format("15:04:05.000"), n, err)
                }
                close(remoteClosed)
        }()

        // In interactive mode stdin EOF does NOT close the connection
        // (the user may have closed the input pipe but still wants to
        // receive output — matches C gs-netcat -i behaviour). We only
        // exit on remote-closed.
        <-remoteClosed

        if verbose {
                log.Printf("interactive session ended (client)")
        }
        return nil
}

func modeStr(listen bool) string {
        if listen {
                return "LISTEN"
        }
        return "CONNECT"
}

// altRelayPorts lists alternative ports the gsocket.org production relay
// accepts connections on, in fallback order. Port 443 is the default and
// is NOT in this list (it's tried first by dialWithPortFallback).
//
// - 7350: gsocket's official alternate port (mentioned on gsocket.io/deploy).
// -   53: DNS port — rarely DPI-inspected because it carries DNS traffic.
//
// Port 7351 (GSRN_DEFAULT_PORT_CON in gsocket.h) is the C original's
// fallback but we observed it timing out in production (Aug 2026), so we
// skip it. Port 22 (SSH) also works in testing but we omit it because
// some ISPs rate-limit or block outbound 22 to non-ISP hosts.
var altRelayPorts = []int{7350, 53}

// instantEOF reports whether err looks like "relay closed TCP immediately
// after we sent _gs_listen/_gs_connect, without sending any _gs_status".
// This signature is the classic DPI/TSPU port-443 block: the inspector
// sees our binary packet (which is not a TLS ClientHello), decides port
// 443 is being abused, and injects a RST.
//
// We treat as instant-EOF:
//   - any error containing "EOF" (covers io.EOF and io.ErrUnexpectedEOF
//     wrapped by gsrn.Start's "gsrn: read start/status: %w" format)
//   - "connection reset by peer" — same root cause, different OS wording
//
// We do NOT treat "i/o timeout" as instant-EOF (that's the old v0.1.16
// symptom of the 30s handshake deadline firing, now fixed in v0.1.17).
func instantEOF(err error) bool {
        if err == nil {
                return false
        }
        msg := err.Error()
        return strings.Contains(msg, "EOF") || strings.Contains(msg, "connection reset by peer")
}

// dialWithPortFallback tries the requested relay host:port first. If
// the user did NOT explicitly pass --relay (i.e. they're using the
// default derived host + port 443) AND the first attempt fails with
// an instant EOF (signature of DPI/TSPU port-443 blocking), it retries
// on each port in altRelayPorts.
//
// If userPickedRelay is true (user passed --relay), no fallback happens
// — the user chose their endpoint intentionally.
//
// v0.1.20: Before falling back to alt ports, retry the original port
// up to 2 more times with a 1.5s sleep between attempts. The instant-EOF
// signature is ambiguous: it can mean DPI/TSPU blocking (real reason to
// fall back), but it can ALSO mean "relay slot still occupied by a
// listener that's in the process of cleaning up after a recent
// disconnect" (race window of 1-5 seconds on production relays).
//
// Falling back to port 7350/53 in the race case is wrong: those ports
// are NOT relay endpoints for the derived host (only :443 is), so they
// ALSO return EOF — and we waste 3 × ~50ms × N attempts before giving
// up. The user sees "all ports blocked" and assumes DPI, when in
// reality they just needed to wait 3 seconds for the relay to release
// the slot.
//
// Retry policy: 3 attempts on the original port, 1.5s apart. Only if
// ALL attempts give instant EOF do we conclude "real block" and try
// alt ports.
//
// On success returns the connection; the caller can inspect opts.RelayPort
// to see which port actually worked (we mutate opts in place before each
// attempt).
func dialWithPortFallback(secret string, mode gsconn.Mode, opts *gsconn.Options, host string, port int, userPickedRelay, verbose bool) (*gsconn.Conn, error) {
        // First attempt: the user's chosen port (or default 443).
        opts.RelayHost = host
        opts.RelayPort = port
        conn, err := gsconn.Dial(secret, mode, opts)
        if err == nil {
                return conn, nil
        }
        // If the user explicitly chose this relay, or the failure is NOT
        // an instant EOF, return the error as-is. We only retry/fall back
        // on the DPI signature.
        if userPickedRelay {
                return nil, err
        }
        if !instantEOF(err) {
                return nil, err
        }

        // v0.1.20: Retry the same port a few times before concluding DPI.
        // The C-side watchdog (gsocket.io/y deploy uses -D) takes 1-5
        // seconds to release the listener slot after an abrupt disconnect,
        // and during that window the relay returns instant EOF on every
        // _gs_connect. Falling back to 7350/53 in this window is wrong
        // (those ports aren't relay endpoints for the derived host) and
        // confuses the user into thinking DPI is blocking them.
        const maxRetries = 2              // 1 initial + 2 retries = 3 attempts total
        const retryDelay = 1500 * time.Millisecond
        lastErr := err
        for attempt := 1; attempt <= maxRetries; attempt++ {
                if verbose {
                        fmt.Fprintf(os.Stderr, "[gs-netcat] relay on port %d returned instant EOF (attempt %d/%d). Waiting %v before retry (relay slot may still be occupied by a previous session)...\n",
                                port, attempt, maxRetries+1, retryDelay)
                }
                time.Sleep(retryDelay)
                opts.RelayHost = host
                opts.RelayPort = port
                conn, err2 := gsconn.Dial(secret, mode, opts)
                if err2 == nil {
                        if verbose {
                                logf("connected on port %d after %d retries.", port, attempt)
                        }
                        return conn, nil
                }
                lastErr = err2
                if !instantEOF(err2) {
                        // Non-EOF error means the relay is reachable but
                        // rejecting us (BAD_AUTH, CONNREFUSED, etc.) —
                        // surface the real error, don't retry or fall back.
                        return nil, err2
                }
        }

        // All retries on the original port gave instant EOF. Now it's
        // genuinely likely DPI/TSPU blocking — try alternate ports.
        if verbose {
                fmt.Fprintf(os.Stderr, "[gs-netcat] relay on port %d returned instant EOF after %d attempts (likely DPI/TSPU blocking non-TLS traffic on 443). Trying alternate ports...\n",
                        port, maxRetries+1)
        }
        for _, altPort := range altRelayPorts {
                if altPort == port {
                        continue
                }
                if verbose {
                        logf("retrying on port %d...", altPort)
                }
                opts.RelayHost = host
                opts.RelayPort = altPort
                conn, err2 := gsconn.Dial(secret, mode, opts)
                if err2 == nil {
                        if verbose {
                                logf("connected on port %d. TIP: pass --relay %s:%d to skip the 443 probe next time.", altPort, host, altPort)
                        }
                        return conn, nil
                }
                if verbose {
                        logf("port %d: %v", altPort, err2)
                }
                // If this port ALSO gave instant EOF, keep trying the
                // next one. If it gave a different error (e.g.
                // BAD_AUTH, CONNREFUSED), the relay is reachable on
                // this port — return that error to the user so they
                // see the real problem instead of us silently moving
                // on.
                if !instantEOF(err2) {
                        return nil, err2
                }
        }
        // All ports blocked. Return the original error (with a hint).
        return nil, fmt.Errorf("%w\n[note] all relay ports (443, 7350, 53) returned instant EOF after %d retries on 443 — this network is blocking GSRN traffic, or the previous session's relay slot is still occupied. Wait 10s and try again, or try a different network, VPN, or a self-hosted relay via --relay host:port",
                lastErr, maxRetries+1)
}

// deriveCreds is a thin wrapper around gskdf.Derive used by both main
// and the test_mode / monitor_mode helpers. Kept here so the helper
// files don't have to import gskdf directly.
func deriveCreds(secret string) *gskdf.Credentials {
        return gskdf.Derive(secret)
}

func roleStr(r gsrn.Role) string {
        switch r {
        case gsrn.RoleUnassigned:
                return "unassigned"
        case gsrn.RoleServer:
                return "SSL-SERVER"
        case gsrn.RoleClient:
                return "SSL-CLIENT"
        default:
                return fmt.Sprintf("role(%d)", int(r))
        }
}

// eventCtx carries the optional PTY / shell-pid context the event-pump
// needs on the server side. On the client side both fields are nil.
type eventCtx struct {
        pty *gspty.PTY
        pid int // shell's pid (for /proc/<pid>/cwd lookup); 0 if unknown
}

// eventPump drains Conn.Events() and handles each in-band event:
//
//   - MsgPING  → reply with MsgPONG carrying load/idle/n_users/username
//     (server role only; client role ignores — its PING replies are
//     handled implicitly because PING and PONG share wire type 16).
//   - MsgPONG  → log on stderr if -v.
//   - MsgLOG   → print "log[type=N]: msg" on stderr.
//   - MsgSTATUS→ print "status[type=N]: msg" on stderr. NOPTY is a
//     signal to the client that the server couldn't allocate a PTY.
//   - MsgWSIZE → on server role, apply TIOCSWINSZ to the PTY (so the
//     shell and any window-size-aware programs running inside it
//     redraw at the client's new terminal dimensions).
//   - MsgIDS   → log on stderr (full IDS subsystem deferred).
//   - MsgPWD   → on server role, reply with ChnPWD containing the
//     shell's current working directory (read from /proc/<pid>/cwd
//     on Linux, which mirrors GS_getpidwd in lib/gsocket-util.c).
//   - ChnPWD   → on client role, print "remote wd: <string>".
//
// Other events (file-transfer channels) are logged but not actioned.
func eventPump(conn *gsconn.Conn, ctx *eventCtx, verbose bool) {
        events := conn.Events()
        if events == nil {
                return
        }
        for ev := range events {
                switch ev.Kind {
                case gspkt.EventMessage:
                        handleMessage(conn, ctx, ev, verbose)
                case gspkt.EventChannel:
                        handleChannel(conn, ctx, ev, verbose)
                }
        }
}

func handleMessage(conn *gsconn.Conn, ctx *eventCtx, ev gspkt.Event, verbose bool) {
        // Note: MsgPING and MsgPONG share wire type 16 (matching the C
        // original's PKT_MSG_PING == PKT_MSG_PONG == 16). The two cases
        // are distinguished by role: the SSL-server (listener) receives
        // type 16 as PING and replies with PONG; the SSL-client (connector)
        // receives type 16 as PONG and displays RTT.
        switch ev.Type {
        case gspkt.MsgPING: // == MsgPONG == 16
                if conn.Role() == gsrn.RoleServer {
                        // We are the listener: this is a PING. Reply with PONG
                        // carrying our load/idle/n_users/username (mirrors
                        // pkt_app_send_pong in tools/pkt_mgr.c which reads
                        // getloadavg + gopt.ids_idle + gopt.n_users +
                        // gopt.ids_active_user). Internal gsstats package
                        // collects them with graceful fallback.
                        pong := gsstats.PongPayload()
                        if err := conn.WriteMsg(gspkt.MsgPONG, pong); err != nil {
                                // PONG write failed — the Conn is broken.
                                // Close it so the rest of the session loop notices
                                // (otherwise the client keeps sending PINGs into the void).
                                fmt.Fprintf(os.Stderr, "gs-netcat: PONG write failed: %v — closing connection\n", err)
                                _ = conn.Close()
                        }
                        if verbose {
                                fmt.Fprintf(os.Stderr, "[in-band] PING received, PONG sent\n")
                        }
                } else {
                        // We are the connector: this is a PONG (reply to our PING).
                        // v0.1.20: update lastPongAt so inBandPinger's dead-server
                        // check knows the server is still alive. Without this, the
                        // check would fire after 2 intervals even on a healthy
                        // connection.
                        conn.MarkPongReceived()
                        if verbose {
                                if len(ev.Data) >= 5 {
                                        load := uint16(ev.Data[0])<<8 | uint16(ev.Data[1])
                                        idle := uint16(ev.Data[2])<<8 | uint16(ev.Data[3])
                                        n := ev.Data[4]
                                        user := ""
                                        if len(ev.Data) >= 16 {
                                                end := 5 + 11
                                                if end > len(ev.Data) {
                                                        end = len(ev.Data)
                                                }
                                                user = string(trimNUL(ev.Data[5:end]))
                                        }
                                        fmt.Fprintf(os.Stderr, "[in-band] PONG received (load=%d idle=%d users=%d user=%q)\n",
                                                load, idle, n, user)
                                } else {
                                        fmt.Fprintf(os.Stderr, "[in-band] PONG received (short)\n")
                                }
                        }
                }
        case gspkt.MsgLOG:
                // struct _pkt_app_log: type(1) + msg[63]
                if len(ev.Data) >= 1 {
                        lt := ev.Data[0]
                        msg := ""
                        if len(ev.Data) > 1 {
                                msg = string(trimNUL(ev.Data[1:]))
                        }
                        fmt.Fprintf(os.Stderr, "[in-band] LOG(type=%d): %s\n", lt, msg)
                }
        case gspkt.MsgSTATUS:
                if len(ev.Data) >= 1 {
                        st := ev.Data[0]
                        msg := ""
                        if len(ev.Data) > 1 {
                                msg = string(trimNUL(ev.Data[1:]))
                        }
                        fmt.Fprintf(os.Stderr, "[in-band] STATUS(type=%d): %s\n", st, msg)
                        // GS_PKT_APP_STATUS_TYPE_NOPTY = 0x01: server couldn't
                        // allocate a PTY. The C original calls stty_switch_nopty()
                        // to relax raw mode (re-enable OPOST so newlines work).
                        // We just log it — the user can pipe commands manually.
                        // Since v0.1.4 the server includes the Spawn error
                        // message in the STATUS payload so we can print WHY
                        // the PTY failed (helps diagnose ConPTY/forkpty issues).
                        if st == 0x01 {
                                if msg != "" {
                                        logf("remote has no PTY — interactive shell unavailable (%s)", msg)
                                } else {
                                        fmt.Fprintf(os.Stderr, "[gs-netcat] remote has no PTY — interactive shell unavailable\n")
                                }
                        }
                }
        case gspkt.MsgWSIZE:
                if len(ev.Data) == 4 {
                        col := uint16(ev.Data[0])<<8 | uint16(ev.Data[1])
                        row := uint16(ev.Data[2])<<8 | uint16(ev.Data[3])
                        if conn.Role() == gsrn.RoleServer && ctx != nil && ctx.pty != nil {
                                // Apply the new size to the PTY. The shell sees
                                // a SIGWINCH and informs its child processes.
                                if err := ctx.pty.SetWindowSize(col, row); err != nil {
                                        if verbose {
                                                fmt.Fprintf(os.Stderr, "[in-band] WSIZE cols=%d rows=%d apply failed: %v\n", col, row, err)
                                        }
                                } else if verbose {
                                        fmt.Fprintf(os.Stderr, "[in-band] WSIZE applied: cols=%d rows=%d\n", col, row)
                                }
                        } else {
                                if verbose {
                                        fmt.Fprintf(os.Stderr, "[in-band] WSIZE: cols=%d rows=%d (no PTY to apply)\n", col, row)
                                }
                        }
                }
        case gspkt.MsgIDS:
                // Client is interested in IDS log messages. Subscribe
                // this conn to the process-wide gsids.Manager, which
                // polls utmp every 5s and sends MsgLOG (type=ALERT)
                // when new logins or idle→active transitions are
                // detected. Mirrors pkt_app_cb_ids in tools/pkt_mgr.c
                // + cbe_ids in tools/event_mgr.c + GS_IDS_utmp in
                // tools/ids.c.
                //
                // Subscribe returns an unsubscribe func; we register
                // it via conn.OnClose so it's called when the conn
                // terminates (the event-pump goroutine exits shortly
                // after, so there's no race).
                if conn.Role() == gsrn.RoleServer {
                        unsub := gsids.Subscribe(conn)
                        conn.OnClose(func() {
                                unsub()
                                if verbose {
                                        fmt.Fprintf(os.Stderr, "[in-band] IDS subscription removed\n")
                                }
                        })
                        if verbose {
                                fmt.Fprintf(os.Stderr, "[in-band] IDS request received — subscribed to utmp events\n")
                        }
                } else if verbose {
                        fmt.Fprintf(os.Stderr, "[in-band] IDS request received (ignored — not server role)\n")
                }
        case gspkt.MsgPWD:
                // Server: reply with ChnPWD carrying the shell's cwd.
                if conn.Role() == gsrn.RoleServer && ctx != nil && ctx.pid > 0 {
                        wd := readShellCwd(ctx.pid)
                        if wd == "" {
                                wd, _ = os.Getwd()
                        }
                        if err := conn.WritePWDReply(wd); err != nil {
                                fmt.Fprintf(os.Stderr, "gs-netcat: PWD reply write failed: %v\n", err)
                        } else if verbose {
                                fmt.Fprintf(os.Stderr, "[in-band] PWD request, replied with %q\n", wd)
                        }
                } else if verbose {
                        fmt.Fprintf(os.Stderr, "[in-band] PWD request received (no PTY/shell to query)\n")
                }
        default:
                if verbose {
                        fmt.Fprintf(os.Stderr, "[in-band] unhandled msg type %d (%d bytes)\n", ev.Type, len(ev.Data))
                }
        }
}

func handleChannel(conn *gsconn.Conn, ctx *eventCtx, ev gspkt.Event, verbose bool) {
        switch ev.Type {
        case gspkt.ChnPWD:
                // Server's working-directory reply (NUL-terminated string).
                msg := string(trimNUL(ev.Data))
                fmt.Fprintf(os.Stderr, "[in-band] remote wd: %s\n", msg)
        default:
                if verbose {
                        fmt.Fprintf(os.Stderr, "[in-band] unhandled chn %d (%d bytes)\n", ev.Type, len(ev.Data))
                }
        }
}

// readProcCwd / readShellCwd lives in cwd_linux.go / cwd_other.go.
// Kept here only as a reference; trimNUL is the only generic helper.

// trimNUL returns b truncated at the first NUL byte (if any), with
// trailing CR/LF line endings trimmed.
//
// v0.1.29 (audit-1 LOW): previously trimmed ALL trailing whitespace
// (space, tab, CR, LF). This silently corrupted working-directory
// paths that legitimately end in a space (e.g. `/home/user/project `)
// and log/status messages where trailing spaces may be significant.
// Now we only trim CR/LF (line endings) which is the actual noise
// from PTY echo; spaces and tabs are preserved.
func trimNUL(b []byte) []byte {
        for i, c := range b {
                if c == 0 {
                        b = b[:i]
                        break
                }
        }
        // trim only trailing CR/LF (line endings from PTY echo);
        // preserve spaces and tabs (they may be significant).
        for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
                b = b[:len(b)-1]
        }
        return b
}

// manPageText returns the text printed by `-m`. Mirrors the layout of the
// upstream man page while documenting the Go-port-specific behaviour
// and the subset of flags currently implemented.
//
// The text is stored XOR-encrypted in manpage.enc (embedded via go:embed)
// to avoid leaving plaintext help strings in the binary's .rodata. Plain
// base64 encoding is NOT sufficient: modern AV scanners (including MS
// Defender) automatically decode base64 blobs during static analysis and
// would rediscover the original "TLS-SRP", "cmd.exe", "/etc/gs_secret"
// strings. go:embed assets are stored as-is by the Go toolchain and are
// NOT obfuscated by garble -literals, so a multi-byte XOR layer is
// mandatory. garble -literals DOES obfuscate the manPageKey byte slice,
// raising the bar beyond simple single-byte XOR brute-force.
//
//go:embed manpage.enc
var manPageEnc []byte

var manPageKey = []byte{0x34, 0x62, 0x75, 0x33, 0xb9, 0xa7, 0x83, 0x7f, 0xd7, 0x45, 0x90, 0x8f, 0x97, 0xa7, 0x7f, 0x73}

func manPageText() string {
        out := make([]byte, len(manPageEnc))
        for i, b := range manPageEnc {
                out[i] = b ^ manPageKey[i%len(manPageKey)]
        }
        return string(out)
}

// trackingReader wraps an io.Reader and atomically sets *flag to 1
// on the first successful Read (n > 0). Used by runInteractive's raw
// cat mode to distinguish "remote sent data" from "remote closed"
// BEFORE io.Copy returns.
//
// v0.1.28 (audit-1 bug #4, MEDIUM): the previous implementation stored
// gotRemoteData AFTER io.Copy returned (i.e. when remote had already
// closed), making the bi-directional CloseWrite branch unreachable.
// This wrapper fixes the timing: flag is set on the first chunk of
// data received, not on EOF.
type trackingReader struct {
        r    io.Reader
        flag *atomic.Int32
}

func (t *trackingReader) Read(p []byte) (int, error) {
        n, err := t.r.Read(p)
        if n > 0 {
                t.flag.Store(1)
        }
        return n, err
}
