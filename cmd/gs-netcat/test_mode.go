// Command gs-netcat — test-mode (-t) implementation.
//
// Mirrors the C `is_try_server` path (4_gs-netcat.c:1483-1487, 1190-1238):
// connect to the GSRN with FlagServerCheck set, get a _gs_status back,
// print "<secret> <32-hex-addr> OK|NO|NET-ERROR" on stdout, exit.
//
// Wire-side: the SERVER_CHECK flag (0x10) is OR'd into the _gs_connect
// packet's flags byte. The relay short-circuits and returns _gs_status
// with code SERVER_OK (0x06), CONNREFUSED (0x02), or NETERROR (0x07)
// without putting the peers in contact. No TLS handshake, no data path.
//
// Exit codes match the C original:
//
//      0  → OK (server is listening)
//      61 → NO  (no server listening, EX_CONNREFUSED)
//      202 → NET-ERROR via SIGALRM (15s timeout, EX_ALARM)
//      203 → NET-ERROR via TCP failure to relay (EX_NETERROR)
//      255 → NET-ERROR, other fatal error
package main

import (
        "fmt"
        "os"
        "time"

        "github.com/gsport/gs-netcat/internal/gsconn"
        "github.com/gsport/gs-netcat/internal/gsrn"
)

// exit codes — match common.h in the C original
const (
        exitOK           = 0
        exitConnRefused  = 61  // EX_CONNREFUSED — server not listening
        exitBadAuth      = 201 // EX_BAD_AUTH
        exitAlarm        = 202 // EX_ALARM — SIGALRM fired (timeout)
        exitNetError     = 203 // EX_NETERROR — TCP to relay failed
        exitFatal        = 255 // EX_FATAL — anything else
        exitBadSelect    = 204 // EX_BADSELECT — unused, reserved
)

// runTestMode implements `-t`:
//
//  1. Resolve the secret + relay.
//  2. Call gsconn.DialTest with a 15s timeout (C default).
//  3. Print "<secret> <32-hex-addr> OK|NO|NET-ERROR\n" to stdout.
//  4. Return the matching exit code.
//
// `quiet` is forced ON in -t mode (matches C: line 1486 sets is_quiet=1).
//
// v0.1.29 (audit-1 LOW): returns exit code instead of calling os.Exit.
// Previously os.Exit() bypassed deferred f.Close() for the -L logfile,
// leaking the fd and leaving log.SetOutput pointing at a stale MultiWriter.
// Now the caller (run/main) performs the exit after defers run.
func runTestMode(secret, relayHost string, relayPort int, verbose bool) int {
        // Determine relay host:port — same logic as the main run() function.
        if relayHost == "" {
                creds := deriveCreds(secret)
                relayHost = gsconn.RelayHostnameForAddr(creds.Address)
                relayPort = 443
        }
        if relayPort == 0 {
                relayPort = 443
        }

        // C default timeout: 15 seconds. The user can override with
        // _GSOCKET_SERVER_CHECK_SEC env in C; we use a CLI flag instead.
        timeout := 15 * time.Second

        opts := &gsconn.Options{
                RelayHost: relayHost,
                RelayPort: relayPort,
        }
        if verbose {
                fmt.Fprintf(os.Stderr, "[gs-netcat] -t: testing %s (relay %s:%d, timeout %v)\n",
                        secret, relayHost, relayPort, timeout)
        }

        status, err := gsconn.DialTest(secret, opts, timeout)

        // Derive the GS-Address for the output line.
        creds := deriveCreds(secret)
        addrHex := creds.Address.String() // 32 lowercase hex chars

        // Decide OK / NO / NET-ERROR + exit code.
        switch {
        case err != nil:
                // Timeout, TCP failure, etc.
                if verbose {
                        fmt.Fprintf(os.Stderr, "[gs-netcat] -t: error: %v\n", err)
                }
                // Distinguish timeout from network error by inspecting the error.
                if isTimeoutErr(err) {
                        fmt.Printf("%s %s NET-ERROR\n", secret, addrHex)
                        return exitAlarm
                }
                fmt.Printf("%s %s NET-ERROR\n", secret, addrHex)
                return exitNetError
        case status == gsrn.StatusServerOK:
                fmt.Printf("%s %s OK\n", secret, addrHex)
                return exitOK
        case status == gsrn.StatusConnRefused:
                fmt.Printf("%s %s NO\n", secret, addrHex)
                return exitConnRefused
        case status == gsrn.StatusBadAuth:
                // Auth-token mismatch — for `-t` the token is irrelevant so this
                // shouldn't happen, but treat as NET-ERROR to match C's atexit path.
                fmt.Printf("%s %s NET-ERROR\n", secret, addrHex)
                return exitBadAuth
        default:
                // NETERROR or any other status code.
                if verbose {
                        fmt.Fprintf(os.Stderr, "[gs-netcat] -t: relay status code 0x%02x\n", status)
                }
                fmt.Printf("%s %s NET-ERROR\n", secret, addrHex)
                return exitFatal
        }
}

// isTimeoutErr returns true if err looks like a deadline/timeout error.
// We use a string match on the error message because the underlying
// errors come from net package without a typed sentinel we can compare
// against (and time.Error("i/o timeout") is unexported).
func isTimeoutErr(err error) bool {
        if err == nil {
                return false
        }
        msg := err.Error()
        // Common timeout strings from Go's net package.
        for _, sub := range []string{"i/o timeout", "deadline exceeded", "timeout"} {
                if contains(msg, sub) {
                        return true
                }
        }
        return false
}

func contains(s, sub string) bool {
        if len(sub) == 0 {
                return true
        }
        for i := 0; i+len(sub) <= len(s); i++ {
                if s[i:i+len(sub)] == sub {
                        return true
                }
        }
        return false
}
