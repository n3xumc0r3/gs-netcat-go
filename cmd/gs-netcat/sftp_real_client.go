// v0.2.5: --sftp-real-client — client side of the SFTP-real bridge.
//
// Listens on a local TCP port and bridges incoming SSH connections
// through the GS-encrypted channel to the remote --sftp-real server.
//
// Usage:
//   ./gs-netcat -i -s S --sftp-real-client 2222
//   # Then connect from any standard SFTP client:
//   sftp -P 2222 gsuser@localhost
package main

import (
        "fmt"
        "io"
        "net"
        "strconv"
)

// runSFTPRealClient listens on localPort and bridges incoming SSH
// connections through the GS-encrypted channel to the remote
// --sftp-real server.
//
// `gsConn` is the already-established GS connection to the remote
// peer running --sftp-real.
//
// Each incoming local TCP connection is bridged bidirectionally to
// the GS conn (and thus to the remote SSH server).
//
// Limitation: v0.2.5 supports only ONE concurrent SFTP session at a
// time. A second incoming connection will queue until the first one
// closes. (For true concurrency, the remote would need --multi-peer
// which the current simplified SFTP-real doesn't support.)
//
// This is acceptable for the typical use case (one SFTP client
// session at a time, e.g. WinSCP or FileZilla with a single window).
func runSFTPRealClient(gsConn io.ReadWriteCloser, localPort int, verbose bool) error {
        addr := ":" + strconv.Itoa(localPort)
        ln, err := net.Listen("tcp", addr)
        if err != nil {
                return fmt.Errorf("sftp-real-client: listen on %s: %w", addr, err)
        }
        defer ln.Close()

        logf("sftp-real-client: listening on %s, bridging to remote SFTP server", addr)
        if verbose {
                logf("sftp-real-client: connect with: sftp -P %d gsuser@localhost", localPort)
                logf("sftp-real-client: password: <the GS secret>")
        }

        // v0.2.5: Single session at a time. Multi-peer would need the remote
        // to re-listen after each disconnect (use --watch for auto-reconnect).
        localConn, err := ln.Accept()
        if err != nil {
                return fmt.Errorf("sftp-real-client: accept: %w", err)
        }
        if verbose {
                logf("sftp-real-client: new SFTP connection from %s", localConn.RemoteAddr())
        }
        // Bridge bidirectionally. The GS conn is one-shot — when this
        // local connection closes, the GS conn closes too, and we exit.
        done := make(chan struct{}, 2)
        go func() {
                _, _ = io.Copy(gsConn, localConn)
                done <- struct{}{}
        }()
        go func() {
                _, _ = io.Copy(localConn, gsConn)
                done <- struct{}{}
        }()
        <-done
        localConn.Close()
        gsConn.Close()
        if verbose {
                logf("sftp-real-client: SFTP session closed, exiting (use --watch to reconnect)")
        }
        return nil
}
