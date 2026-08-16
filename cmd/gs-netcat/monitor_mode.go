// Command gs-netcat — monitor mode (--monitor) implementation.
//
// Native replacement for the PowerShell monitor script the user was
// running externally: takes a comma-separated list of secrets, polls
// each one in parallel with -t semantics, prints a colored status line
// per secret, and repeats every N seconds.
//
// Output format (one line per secret per cycle):
//
//      [HH:MM:SS] [SECRET]  ONLINE   (key: <secret>)         <- green
//      [HH:MM:SS] [SECRET]  offline  (key: <secret>)         <- red
//      [HH:MM:SS] [SECRET]  NET-ERROR (network issue)        <- yellow
//
// On Windows the colored output goes through github.com/gookit/color
// or ANSI emulation; on Unix terminals it's native ANSI. Both work
// because we use the same escape codes as the C original.
//
// The cycle interval defaults to 10s (matches the PS script); can be
// overridden with --monitor-interval. A short beep is emitted on each
// ONLINE transition (matches the PS script's [System.Media.SystemSounds]::Beep).
package main

import (
        "fmt"
        "os"
        "os/signal"
        "strings"
        "sync"
        "syscall"
        "time"

        "github.com/gsport/gs-netcat/internal/gsconn"
        "github.com/gsport/gs-netcat/internal/gsrn"
)

// ANSI color codes — same as the C original's console_display.c palette.
// We deliberately don't pull in a color library to keep the binary small
// and to behave the same on Windows 10+ (which supports ANSI via
// SetConsoleMode(ENABLE_VIRTUAL_TERMINAL_PROCESSING), enabled in
// console_cp_windows.go).
const (
        colorReset  = "\x1b[0m"
        colorGreen  = "\x1b[32m"
        colorRed    = "\x1b[31m"
        colorYellow = "\x1b[33m"
        colorGray   = "\x1b[90m"
        colorCyan   = "\x1b[36m"
)

// runMonitorMode implements `--monitor k1,k2,k3[,k4,...]`.
//
// Polls each secret in parallel every `interval` seconds using the same
// DialTest path as -t. Prints a timestamped, colored status line per
// secret. Runs forever until interrupted (Ctrl-C).
//
// `relayHost`/`relayPort` are passed through from the parent CLI parse
// (so --relay works with --monitor too). If empty, the production relay
// is derived from each secret's GS-Address (which can be a DIFFERENT
// relay per secret — the C original does the same).
func runMonitorMode(secretsCSV string, relayHost string, relayPort int, interval time.Duration, verbose bool) error {
        if interval <= 0 {
                interval = 10 * time.Second
        }

        // Parse comma-separated secrets, trim whitespace, drop empties.
        parts := strings.Split(secretsCSV, ",")
        var secrets []string
        for _, s := range parts {
                s = strings.TrimSpace(s)
                if s != "" {
                        secrets = append(secrets, s)
                }
        }
        if len(secrets) == 0 {
                return fmt.Errorf("--monitor: empty secret list")
        }

        fmt.Fprintf(os.Stderr, "%s[*] Monitoring started for %d server(s).%s\n",
                colorCyan, len(secrets), colorReset)
        fmt.Fprintf(os.Stderr, "%s--------------------------------------------------%s\n",
                colorGray, colorReset)

        // Install Ctrl-C handler for clean exit.
        stop := make(chan os.Signal, 1)
        signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

        // Track previous status per secret to detect ONLINE transitions
        // (for the beep). Keyed by secret string.
        var mu sync.Mutex
        prev := make(map[string]string, len(secrets))

        for {
                // Poll all secrets in parallel.
                var wg sync.WaitGroup
                results := make([]monitorResult, len(secrets))
                for i, s := range secrets {
                        wg.Add(1)
                        go func(idx int, secret string) {
                                defer wg.Done()
                                results[idx] = monitorPoll(secret, relayHost, relayPort, verbose)
                        }(i, s)
                }
                wg.Wait()

                // Print results sorted by input order, with timestamp.
                ts := time.Now().Format("15:04:05")
                for _, r := range results {
                        printMonitorLine(ts, r, &mu, prev)
                }
                fmt.Fprintf(os.Stderr, "%s--------------------------------------------------%s\n",
                        colorGray, colorReset)

                // Wait for next cycle or interrupt.
                select {
                case <-stop:
                        fmt.Fprintf(os.Stderr, "%s[*] Monitoring stopped.%s\n", colorCyan, colorReset)
                        return nil
                case <-time.After(interval):
                }
        }
}

// monitorResult is the outcome of a single -t probe for one secret.
type monitorResult struct {
        secret  string
        addrHex string
        status  string // "ONLINE", "offline", "NET-ERROR", "UNKNOWN"
        color   string // ANSI color code for the status word
        note    string // optional parenthetical
}

// monitorPoll does a single DialTest for one secret and returns a
// human-readable result. Mirrors the PS script's logic exactly:
//   - OK → ONLINE (green), beep on transition from non-ONLINE
//   - NO → offline (red)
//   - NET-ERROR → NET-ERROR (yellow)
//   - unexpected output → UNKNOWN (magenta)
func monitorPoll(secret, relayHost string, relayPort int, verbose bool) monitorResult {
        // Per-secret relay derivation (each secret may hash to a different
        // production relay). If --relay was passed, use that for all.
        host, port := relayHost, relayPort
        if host == "" {
                creds := deriveCreds(secret)
                host = gsconn.RelayHostnameForAddr(creds.Address)
                port = 443
        }
        if port == 0 {
                port = 443
        }

        opts := &gsconn.Options{
                RelayHost: host,
                RelayPort: port,
        }
        // Shorter timeout than -t (single-shot): in monitor mode we want
        // to fail fast so a dead relay doesn't hold up the whole cycle.
        // 8s is enough for the relay's SERVER_OK/CONNREFUSED round-trip
        // even on a slow link.
        status, err := gsconn.DialTest(secret, opts, 8*time.Second)

        creds := deriveCreds(secret)
        addrHex := creds.Address.String()

        switch {
        case err != nil:
                // Distinguish "relay closed connection" (EOF) from real network
                // errors. EOF means the relay accepted our TCP connection but
                // closed it without sending _gs_status — this typically means
                // "no listener for this secret" on relays that don't fully
                // support SERVER_CHECK. We classify it as "offline" rather
                // than "NET-ERROR" because the relay WAS reachable; it just
                // had no peer for us.
                //
                // Real network errors (TCP timeout, connection refused, DNS
                // failure) are classified as NET-ERROR (yellow).
                errStr := err.Error()
                isEOF := strings.Contains(errStr, "EOF") ||
                        strings.Contains(errStr, "connection reset") ||
                        strings.Contains(errStr, "broken pipe")
                if verbose {
                        fmt.Fprintf(os.Stderr, "[monitor] %s: error: %v\n", secret, err)
                }
                if isEOF {
                        return monitorResult{secret, addrHex, "offline", colorRed, "(relay closed — no listener)"}
                }
                return monitorResult{secret, addrHex, "NET-ERROR", colorYellow, "(network: " + truncateErr(errStr) + ")"}
        case status == gsrn.StatusServerOK:
                return monitorResult{secret, addrHex, "ONLINE", colorGreen, "(key: " + secret + ")"}
        case status == gsrn.StatusConnRefused:
                return monitorResult{secret, addrHex, "offline", colorRed, "(key: " + secret + ")"}
        default:
                return monitorResult{secret, addrHex, "NET-ERROR", colorYellow, "(relay status 0x" + fmt.Sprintf("%02x", status) + ")"}
        }
}

// truncateErr shortens an error message to fit in the monitor output
// line (max 40 chars). Keeps the beginning of the message since that's
// usually where the most diagnostic info is.
func truncateErr(s string) string {
        if len(s) <= 40 {
                return s
        }
        return s[:37] + "..."
}

// printMonitorLine prints one status line and emits a beep on the
// ONLINE→ONLINE transition (matches the PS script's behavior).
func printMonitorLine(ts string, r monitorResult, mu *sync.Mutex, prev map[string]string) {
        mu.Lock()
        prevStatus := prev[r.secret]
        prev[r.secret] = r.status
        mu.Unlock()

        // Beep on ONLINE transition (was not ONLINE, now is).
        if r.status == "ONLINE" && prevStatus != "ONLINE" {
                // ASCII 7 = BEL — terminal bell. Most terminals will sound
                // a short beep. On Windows it works the same way via the
                // console subsystem. This mirrors [System.Media.SystemSounds]::Beep.
                fmt.Fprint(os.Stderr, "\a")
        }

        note := r.note
        if note == "" {
                note = "(key: " + r.secret + ")"
        }
        fmt.Fprintf(os.Stderr, "%s[%s]%s [%s] %s%s%s %s%s\n",
                colorGray, ts, colorReset,
                r.secret,
                r.color, r.status, colorReset,
                colorGray, note)
}
