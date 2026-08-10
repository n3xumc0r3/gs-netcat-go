// Command tlssrp_client is a tiny test client for the tlssrp package.
// It connects to a TLS-SRP server at addr, performs the handshake with
// the given username/password, writes the given payload (if any), reads
// any reply, and exits.
//
// Usage:
//
//      tlssrp_client -addr 127.0.0.1:4433 -user user -pass 'Blah....blubb-SRPSEC' \
//                    -send 'hello from go client'
//
// All diagnostic output goes to stderr.  On success, the program exits 0.
// On failure, exits 1 with the error message.
package main

import (
        "crypto/sha256"
        "encoding/hex"
        "flag"
        "fmt"
        "io"
        "net"
        "os"
        "time"

        "github.com/gsport/gs-netcat/internal/tlssrp"
)

func main() {
        addr := flag.String("addr", "", "server address host:port (required)")
        user := flag.String("user", "user", "SRP username")
        pass := flag.String("pass", "", "SRP password (required)")
        send := flag.String("send", "", "data to send after handshake")
        secret := flag.String("secret", "", "if set, derive the wrapped SRP password from this gs_secret (overrides -pass)")
        verbose := flag.Bool("v", false, "verbose")
        flag.Parse()

        if *addr == "" {
                fmt.Fprintln(os.Stderr, "must set -addr")
                os.Exit(2)
        }

        password := *pass
        if *secret != "" {
                // Reproduce gs-netcat's password wrapping:
                //   "Blah." + hex(SHA256("/kd/srp/1" || secret))[0:33] + ".blubb-SRPSEC"
                h := sha256.New()
                h.Write([]byte("/kd/srp/1"))
                h.Write([]byte(*secret))
                inner := hex.EncodeToString(h.Sum(nil))[:33]
                password = "Blah." + inner + ".blubb-SRPSEC"
                if *verbose {
                        fmt.Fprintf(os.Stderr, "derived SRP password: %s (len=%d)\n",
                                password, len(password))
                }
        }
        if password == "" {
                fmt.Fprintln(os.Stderr, "must set -pass or -secret")
                os.Exit(2)
        }

        // Dial TCP.
        tcpConn, err := net.DialTimeout("tcp", *addr, 10*time.Second)
        if err != nil {
                fmt.Fprintf(os.Stderr, "dial: %v\n", err)
                os.Exit(1)
        }
        defer tcpConn.Close()

        cfg := &tlssrp.Config{
                MinVersion:             tlssrp.VersionTLS12,
                MaxVersion:             tlssrp.VersionTLS12,
                CipherSuites:           []uint16{tlssrp.TLS_SRP_SHA_WITH_AES_256_CBC_SHA},
                SessionTicketsDisabled: true,
                SRPUser:                *user,
                SRPPassword:            password,
                SRPGroups:              []*tlssrp.SRPGroup{&tlssrp.SRPGroup4096},
        }

        conn := tlssrp.Client(tcpConn, cfg)
        if err := conn.Handshake(); err != nil {
                fmt.Fprintf(os.Stderr, "handshake: %v\n", err)
                os.Exit(1)
        }
        if *verbose {
                st := conn.ConnectionState()
                fmt.Fprintf(os.Stderr, "handshake OK: cipher=0x%04x user=%q handshakeComplete=%v\n",
                        st.CipherSuite, st.SRPUser, st.HandshakeComplete)
        }

        // Send payload (if any).
        if *send != "" {
                if _, err := conn.Write([]byte(*send)); err != nil {
                        fmt.Fprintf(os.Stderr, "write: %v\n", err)
                        os.Exit(1)
                }
                if *verbose {
                        fmt.Fprintf(os.Stderr, "sent %d bytes\n", len(*send))
                }
        }

        // Read any reply (best effort — server may close after echo).
        buf := make([]byte, 4096)
        _ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
        n, _ := conn.Read(buf)
        if n > 0 {
                os.Stdout.Write(buf[:n])
                if *verbose {
                        fmt.Fprintf(os.Stderr, "read %d bytes\n", n)
                }
        }

        // Graceful close.
        _ = conn.Close()
        // Drain any remaining bytes (in case the server sent more after our read).
        if _, err := io.Copy(io.Discard, conn); err != nil && *verbose {
                fmt.Fprintf(os.Stderr, "drain: %v\n", err)
        }
}
