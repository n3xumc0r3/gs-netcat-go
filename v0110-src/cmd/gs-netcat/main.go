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
        _ "embed"
        "flag"
        "fmt"
        "io"
        "log"
        "os"
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
// `--vvv`) into a single `-v`. The Go port treats any verbose level as
// "maximum": we don't differentiate between -v / -vv / -vvv. This keeps
// the CLI drop-in compatible with the C original (which accepts all
// three forms) without dragging in a countFlag type.
func expandVerboseFlags(args []string) []string {
        out := make([]string, 0, len(args))
        for _, a := range args {
                switch a {
                case "-vv", "-vvv":
                        out = append(out, "-v")
                case "--vv", "--vvv":
                        out = append(out, "--v")
                default:
                        out = append(out, a)
                }
        }
        return out
}

func main() {
        if err := run(expandVerboseFlags(os.Args[1:])); err != nil {
                fmt.Fprintln(os.Stderr, "gs-netcat:", err)
                os.Exit(1)
        }
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
  -S           Act as a SOCKS server [needs -l] (not implemented)
  -D           Background mode (detach + supervisor)
  -W           Watchdog (auto-restart on exit; combine with -D for detached)
  -d <IP>      IPv4 address for port forwarding
  -p <port>    Port to listen on or forward to
  -i           Interactive shell (TTY) [Ctrl-e q to terminate]
  -e <cmd>     Execute command [e.g. "bash -il" or "id"]
  -m           Display man page
  -h, --help   Show this help and exit

  --relay H:P           Relay endpoint (default: derived from secret)
  --cos                 Either peer may become SSL server
  --low-latency         Hint relay: interactive session
  --ping-interval N     Override app-ping interval (default 45; -i only)
  --pwd                 Query remote working directory (-i only)
  --ids                 Subscribe to remote login alerts (-i only)
  --monitor k1,k2,...   Poll multiple secrets, print status
  --monitor-interval N  Seconds between polls (default 10)

Example to forward traffic from port 2222 to 192.168.6.7:22:
    $ gsc -l -d 192.168.6.7 -p 22     # Server
    $ gsc -p 2222                     # Client
Example file transfer:
    $ gsc -l -r >warez.tar.gz         # Server
    $ gsc <warez.tar.gz               # Client
Example for an interactive session:
    $ gsc -l -i                       # Server
    $ gsc -i                          # Client
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
        )
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
        fs.BoolVar(&flagSOCKS, "S", false, "Act as a SOCKS server [needs -l] (NOT YET IMPLEMENTED in the Go port)")
        fs.BoolVar(&flagTest, "t", false, "Test if peer is listening (CONNECT mode). Prints '<secret> <addr> OK|NO|NET-ERROR' and exits.")
        fs.BoolVar(&flagDaemon, "D", false, "Daemonize: detach from terminal and run in background. Use with -L to keep a log.")
        fs.BoolVar(&flagWatch, "W", false, "Watchdog: supervise and auto-restart on crash. Combine with -D for detached supervision.")
        fs.BoolVar(&flagNoEnc, "C", false, strs.Decode([]byte{0x05, 0x28, 0x32, 0x20, 0x23, 0x2d, 0x24, 0x61, 0x15, 0x0d, 0x12, 0x6c, 0x12, 0x13, 0x11, 0x61, 0x24, 0x2f, 0x22, 0x33, 0x38, 0x31, 0x35, 0x28, 0x2e, 0x2f, 0x61, 0x69, 0x0f, 0x0e, 0x15, 0x61, 0x36, 0x28, 0x33, 0x24, 0x6c, 0x22, 0x2e, 0x2c, 0x31, 0x20, 0x35, 0x61, 0x36, 0x28, 0x35, 0x29, 0x61, 0x25, 0x24, 0x27, 0x20, 0x34, 0x2d, 0x35, 0x61, 0x24, 0x2f, 0x22, 0x33, 0x38, 0x31, 0x35, 0x24, 0x25, 0x61, 0x2c, 0x2e, 0x25, 0x24, 0x7a, 0x61, 0x23, 0x2e, 0x35, 0x29, 0x61, 0x31, 0x24, 0x24, 0x33, 0x32, 0x61, 0x0c, 0x14, 0x12, 0x15, 0x61, 0x31, 0x20, 0x32, 0x32, 0x61, 0x6c, 0x02, 0x68, 0x6f}, 0x41))
        fs.IntVar(&flagPort, "p", 0, "Port-forward: with -l, forward incoming GS to -d:<port>; without -l, listen on <port> and forward each local conn via GS.")
        fs.StringVar(&flagDstIP, "d", "", "Port-forward destination IP (use with -l -p <port>).")
        fs.StringVar(&monitorKeys, "monitor", "", "Monitor mode: poll comma-separated secrets every N seconds and print colored status. Native replacement for the PS monitor script.")
        fs.IntVar(&monitorInt, "monitor-interval", 10, "Monitor mode: seconds between poll cycles (default 10).")
        fs.StringVar(&opt3Str, "3", "", "(internal)")

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

        // -S: SOCKS server — not yet implemented in the Go port. Surface
        // a clear error so users don't get silent misbehaviour.
        if flagSOCKS {
                if !listen {
                        return fmt.Errorf("-S (SOCKS server) requires -l (listen mode)")
                }
                return fmt.Errorf("-S (SOCKS server) is not yet implemented in the Go port; see roadmap")
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

        // -t: test mode (no data path, no secret prompt, just probe the
        // relay). We exit from inside runTestMode.
        if flagTest {
                if listen {
                        // -t is a client-only feature in the C original
                        // (it sets SERVER_CHECK on _gs_connect; listeners
                        // don't send that flag). We honor -t -l by ignoring
                        // -l to avoid confusing the user.
                        fmt.Fprintf(os.Stderr, "[gs-netcat] -t is a client-only flag; ignoring -l\n")
                }
                return runTestMode(secret, relayHost, relayPort, verbose)
        }

        // -D and/or -W: daemon/watchdog dispatch. This re-execs the
        // binary with a hidden env var so the child takes over the
        // actual work. The parent either exits (-D) or supervises
        // (-W). This call returns ONLY in the child process.
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
        // If no explicit auth token (-a) was provided AND we're in listen
        // mode, derive a DETERMINISTIC token from the secret. This ensures
        // that multi-peer re-listen attempts (after a client disconnects)
        // use the SAME token as the first listen — otherwise the relay
        // rejects the re-listen with BAD_AUTH because it still has the
        // old (random) token registered for the same GS-Address.
        //
        // The token derivation is: SHA256(secret || gs_addr)[0:16]
        // (see gskdf.DeriveAuthToken). Same secret + same addr = same
        // token, so re-listens always match the first listen's token.
        if opts.AuthToken == "" && listen {
                opts.AuthToken = secret
        }
        opts.UseInBand = interactive
        opts.NoEncryption = flagNoEnc
        if pingIntSec > 0 {
                opts.PingInterval = time.Duration(pingIntSec) * time.Second
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
        if flagLowLat {
                opts.FlagExtra |= gsrn.FlagLowLatency
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
                        fmt.Fprintf(os.Stderr, "[gs-netcat] client port-forward: local :%d → GS\n", flagPort)
                }
                return runPortForwardClient(secret, relayHost, relayPort, flagPort, opts, verbose)
        }
        if flagPort > 0 && listen {
                if flagDstIP == "" {
                        return fmt.Errorf("-l -p <port> requires -d <ip>")
                }
                if verbose {
                        fmt.Fprintf(os.Stderr, "[gs-netcat] server port-forward: GS → %s:%d\n", flagDstIP, flagPort)
                }
                return runPortForwardServer(secret, relayHost, relayPort, flagDstIP, flagPort, opts, verbose)
        }

        // v0.1.10: when -w (WAIT) is set on the client side, wrap the
        // Dial in a retry loop. The relay returns CONNREFUSED while no
        // listener is registered for the GS-Address; with -w the user
        // wants us to keep trying until the server appears.
        //
        // We also retry on transient TLS-SRP EOF, which happens when the
        // server has just finished a previous session and is in its
        // brief re-listen window — the relay may match our _gs_connect
        // with the still-closing previous TCP, and the server's FIN
        // arrives as EOF during our TLS handshake. Retrying after a
        // short backoff gives the server time to re-register.
        //
        // Backoff: 1s, 2s, 4s, ... capped at 30s. Reset on successful
        // dial. The loop terminates as soon as the dial succeeds OR
        // the user hits Ctrl-C (SIGINT propagates as os.Exit).
        var conn *gsconn.Conn
        if flagWait && !listen {
                backoff := time.Second
                const maxBackoff = 30 * time.Second
                for attempt := 1; ; attempt++ {
                        c, derr := gsconn.Dial(secret, mode, opts)
                        if derr == nil {
                                conn = c
                                break
                        }
                        // Non-retryable errors: BAD_AUTH, proto errors,
                        // anything that isn't CONNREFUSED / EOF / timeout.
                        // We retry on:
                        //   - gsrn.StatusError with code CONNREFUSED
                        //     (relay says no listener yet — keep waiting)
                        //   - TLS-SRP handshake EOF
                        //     (server in re-listen window — retry shortly)
                        //   - Network timeouts (relay temporarily slow)
                        if !isRetryableDialErr(derr) {
                                return derr
                        }
                        if !quiet {
                                fmt.Fprintf(os.Stderr, "[gs-netcat] waiting for server (attempt %d, retry in %v): %v\n",
                                        attempt, backoff, derr)
                        }
                        time.Sleep(backoff)
                        backoff *= 2
                        if backoff > maxBackoff {
                                backoff = maxBackoff
                        }
                }
        } else {
                c, derr := gsconn.Dial(secret, mode, opts)
                if derr != nil {
                        return derr
                }
                conn = c
        }
        defer conn.Close()

        if !quiet {
                modeExtra := ""
                if interactive {
                        modeExtra = " [in-band]"
                }
                fmt.Fprintf(os.Stderr, "Connected (role=%s%s). Press Ctrl-D to exit.\n",
                        roleStr(conn.Role()), modeExtra)
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
                        return runMultiPeerInteractiveServer(conn, secret, relayHost, relayPort, opts, verbose, execCmd)
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
        stdinDone := make(chan struct{})
        remoteClosed := make(chan struct{})
        var totalWritten int64
        var totalRead int64
        var gotRemoteData int32 // atomic; 1 once we've received any bytes
        go func() {
                n, _ := io.Copy(conn, os.Stdin)
                totalWritten = n
                close(stdinDone)
        }()
        go func() {
                n, _ := io.Copy(os.Stdout, conn)
                atomic.StoreInt32(&gotRemoteData, 1)
                totalRead = n
                close(remoteClosed)
        }()

        if receiveOnly {
                // -r: pure receive. Ignore stdin EOF entirely.
                <-remoteClosed
        } else if !listen {
                // CONNECTOR: stdin EOF → half-close our write side, keep
                // reading until remote closes too.
                <-stdinDone
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
                        if atomic.LoadInt32(&gotRemoteData) == 1 {
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
                fmt.Fprintf(os.Stderr, "[gsport] done; totalWritten=%d totalRead=%d\n", totalWritten, totalRead)
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
                // the Spawn error message (truncated to 63 bytes) so the
                // client can print WHY the PTY failed — previously the
                // client only saw "remote has no PTY" with no detail.
                msg := err.Error()
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
                fmt.Fprintf(os.Stderr, "[gs-netcat] PTY spawned (cols=%d rows=%d pid=%d)\n", cols, rows, ctx.pid)
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
        go func() {
                _, _ = io.Copy(pty, conn) // conn -> shell stdin (via PTY.Write)
                pty.Close()               // closing master makes shell see EOF
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
                        fmt.Fprintf(os.Stderr, "[gs-netcat] shell exited: %v\n", err)
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
                        fmt.Fprintf(os.Stderr, "[gs-netcat] initial WSIZE send failed: %v\n", err)
                }
        }
        if verbose {
                fmt.Fprintf(os.Stderr, "[gs-netcat] sent initial WSIZE cols=%d rows=%d\n", cols, rows)
        }

        // Optional one-shot PWD request: the server's reply (ChnPWD) is
        // decoded by the in-band decoder and surfaced to the event-pump,
        // which prints it on stderr as "[in-band] remote wd: <path>".
        // This is mostly a test affordance — the C original triggers
        // PWD requests via a CLI command (`pwd` in interactive input).
        if wantPwd {
                if err := conn.WritePWDRequest(); err != nil {
                        if verbose {
                                fmt.Fprintf(os.Stderr, "[gs-netcat] PWD request send failed: %v\n", err)
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
                                fmt.Fprintf(os.Stderr, "[gs-netcat] IDS subscription send failed: %v\n", err)
                        }
                } else if verbose {
                        fmt.Fprintf(os.Stderr, "[gs-netcat] sent IDS subscription request\n")
                }
        }

        // Install window-size watcher: on resize, query new size and re-send.
        // On Unix this wraps SIGWINCH; on Windows it polls every 250ms
        // (Windows has no SIGWINCH equivalent).
        resizeCh := watchWindowSize()
        go func() {
                for range resizeCh {
                        c, r := gspty.GetStdinWindowSize()
                        if err := conn.WriteWSIZE(c, r); err != nil {
                                return
                        }
                        if verbose {
                                fmt.Fprintf(os.Stderr, "[gs-netcat] sent WSIZE cols=%d rows=%d\n", c, r)
                        }
                }
        }()

        // Pipe stdin -> conn, conn -> stdout.
        stdinDone := make(chan struct{})
        go func() {
                _, _ = io.Copy(conn, os.Stdin)
                close(stdinDone)
        }()
        go func() {
                _, _ = io.Copy(os.Stdout, conn)
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
                                fmt.Fprintf(os.Stderr, "gs-netcat: PONG write failed: %v\n", err)
                        }
                        if verbose {
                                fmt.Fprintf(os.Stderr, "[in-band] PING received, PONG sent\n")
                        }
                } else {
                        // We are the connector: this is a PONG (reply to our PING).
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
                                        fmt.Fprintf(os.Stderr, "[gs-netcat] remote has no PTY — interactive shell unavailable (%s)\n", msg)
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
// trailing whitespace trimmed.
func trimNUL(b []byte) []byte {
        for i, c := range b {
                if c == 0 {
                        b = b[:i]
                        break
                }
        }
        // trim trailing whitespace
        for len(b) > 0 && (b[len(b)-1] == ' ' || b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == '\t') {
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

// isRetryableDialErr reports whether a gsconn.Dial error is worth
// retrying when the user has asked us to wait (-w / WAIT flag).
//
// Retryable errors are transient conditions that are expected to
// resolve themselves without code changes:
//
//   - gsrn.StatusError with code CONNREFUSED: the relay says no
//     listener is currently registered for this GS-Address. With -w
//     the user explicitly wants us to wait for one to appear.
//   - gsrn.StatusError with code IDLE_TIMEOUT: the relay gave up
//     waiting (shouldn't happen with our 24h deadline, but be
//     defensive).
//   - Errors whose message contains "EOF" or "connection reset":
//     transient TCP failures, typically when the server is in its
//     brief re-listen window after a previous session ended and the
//     relay matched us with a closing connection.
//   - Net errors (dial timeouts, EOF on relay TCP): the relay is
//     reachable in principle but the connection didn't complete.
//
// Non-retryable errors (we exit immediately):
//
//   - BAD_AUTH: the auth token is wrong — retrying won't help.
//   - PROTOERROR: protocol version mismatch — needs binary update.
//   - Any error containing "no such host" / "no route to host":
//     network-level failures that won't resolve without user action.
func isRetryableDialErr(err error) bool {
        if err == nil {
                return false
        }
        // GSRN status errors: retry on CONNREFUSED and IDLE_TIMEOUT.
        if se, ok := err.(gsrn.StatusError); ok {
                switch se.Code {
                case gsrn.StatusConnRefused, gsrn.StatusIdleTimeout, gsrn.StatusNetError:
                        return true
                }
                // BAD_AUTH, PROTOERROR, etc. are not retryable.
                return false
        }
        // Generic errors: retry on EOF / reset / timeout / refused.
        msg := err.Error()
        for _, marker := range []string{"EOF", "connection reset", "broken pipe", "i/o timeout", "deadline exceeded"} {
                if strings.Contains(msg, marker) {
                        return true
                }
        }
        // Default: don't retry unknown errors.
        return false
}
