// Command tlssrp_server is a tiny test server for the tlssrp package.
// It listens on a TCP port, accepts TLS-SRP connections, computes the
// verifier on-the-fly from a gs_secret (using the same KDF as gs-netcat),
// and echoes received bytes back to the client.
//
// Usage:
//
//	tlssrp_server -addr 127.0.0.1:4433 -secret MyTestSecret123
//
// This program exists for interop testing: a C (OpenSSL) client should be
// able to TLS-SRP-handshake with this server and exchange data, proving
// the vendored tlssrp package is wire-compatible with OpenSSL's TLS-SRP.
package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/gsport/gs-netcat/internal/gskdf"
	"github.com/gsport/gs-netcat/internal/tlssrp"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:4433", "listen address host:port")
	secret := flag.String("secret", "", "gs_secret for deriving SRP password (required)")
	verbose := flag.Bool("v", false, "verbose")
	flag.Parse()

	if *secret == "" {
		fmt.Fprintln(os.Stderr, "must set -secret")
		os.Exit(2)
	}

	creds := gskdf.Derive(*secret)
	if *verbose {
		fmt.Fprintf(os.Stderr, "[server] derived SRP password: %s\n", creds.SRPPassword)
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[server] listen: %v\n", err)
		os.Exit(1)
	}
	defer ln.Close()
	fmt.Fprintf(os.Stderr, "[server] listening on %s\n", *addr)

	// Accept up to 5 connections (readiness probes / multiple test runs).
	for i := 0; i < 5; i++ {
		tcpConn, err := ln.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[server] accept: %v\n", err)
			continue
		}
		fmt.Fprintf(os.Stderr, "[server] client connected (conn #%d)\n", i+1)

		// Per-connection deadline to avoid hanging on readiness probes.
		_ = tcpConn.SetReadDeadline(time.Now().Add(10 * time.Second))

		cfg := &tlssrp.Config{
			MinVersion:             tlssrp.VersionTLS12,
			MaxVersion:             tlssrp.VersionTLS12,
			CipherSuites:           []uint16{tlssrp.TLS_SRP_SHA_WITH_AES_256_CBC_SHA},
			SessionTicketsDisabled: true,
			SRPUser:                gskdf.SRPUsername,
			SRPPassword:            creds.SRPPassword,
			SRPGroups:              []*tlssrp.SRPGroup{&tlssrp.SRPGroup4096},
			SRPSaltKey:             "gsport-test-salt-key",
			SRPSaltSize:            gskdf.SaltLength,
			SRPLookup: &onTheFlyLookup{
				user:     gskdf.SRPUsername,
				password: creds.SRPPassword,
				group:    &tlssrp.SRPGroup4096,
			},
		}

		conn := tlssrp.Server(tcpConn, cfg)
		if err := conn.Handshake(); err != nil {
			fmt.Fprintf(os.Stderr, "[server] handshake failed: %v\n", err)
			conn.Close()
			continue
		}
		// Clear the deadline for data transfer.
		_ = tcpConn.SetReadDeadline(time.Time{})

		st := conn.ConnectionState()
		fmt.Fprintf(os.Stderr, "[server] handshake OK, cipher=0x%04x user=%q\n",
			st.CipherSuite, st.SRPUser)

		// Echo loop.
		buf := make([]byte, 4096)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				fmt.Fprintf(os.Stderr, "[server] received %d bytes: %s\n",
					n, string(buf[:n]))
				if _, werr := conn.Write(buf[:n]); werr != nil {
					fmt.Fprintf(os.Stderr, "[server] write: %v\n", werr)
					break
				}
				fmt.Fprintf(os.Stderr, "[server] echoed %d bytes back\n", n)
			}
			if err != nil {
				if err != io.EOF {
					fmt.Fprintf(os.Stderr, "[server] read: %v\n", err)
				}
				break
			}
		}
		conn.Close()
		break // real client served, done
	}
}

// onTheFlyLookup mirrors what gs-netcat does: computes the verifier from
// the password on every Lookup call.  A fresh 20-byte salt is generated
// per call (matches OpenSSL's SRP_create_verifier_BN behaviour).
type onTheFlyLookup struct {
	user     string
	password string
	group    *tlssrp.SRPGroup
}

func (l *onTheFlyLookup) Lookup(user string) (v, s []byte, grp tlssrp.SRPGroup, err error) {
	if user != l.user {
		// Unknown user — return nil v/s but valid grp so tlssrp's fake-salt
		// protection kicks in (no user enumeration).
		return nil, nil, *l.group, nil
	}
	s = make([]byte, gskdf.SaltLength)
	if _, err := rand.Read(s); err != nil {
		return nil, nil, tlssrp.SRPGroup{}, fmt.Errorf("gen salt: %w", err)
	}
	v = tlssrp.SRPVerifier(l.user, l.password, s, *l.group)
	return v, s, *l.group, nil
}
