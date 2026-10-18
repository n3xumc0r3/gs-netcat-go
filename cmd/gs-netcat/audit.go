// v0.1.30: Audit log (--audit-log FILE).
//
// Records all decrypted session I/O to a file with timestamps. Each line
// is one direction-byte chunk, formatted as:
//
//   2026-10-17T22:30:15.123Z DIR NBYTES\n
//   <hex of NBYTES bytes>\n
//
// Where DIR is "C2S" (client→server, written via Conn.Write) or "S2C"
// (server→client, read via Conn.Read).
//
// This is the decrypted payload — the actual bytes the user's shell saw,
// not the TLS-encrypted wire bytes. Useful for compliance, forensics, and
// debugging interactive sessions.
//
// Wire compat: [--] local-only; the remote peer sees no difference.
package main

import (
        "encoding/hex"
        "fmt"
        "io"
        "os"
        "sync"
        "time"
)

// auditConn wraps an io.ReadWriteCloser and tees all I/O to an audit log.
type auditConn struct {
        inner    io.ReadWriteCloser
        logFile  *os.File
        mu       sync.Mutex
}

func newAuditConn(c io.ReadWriteCloser, path string) (io.ReadWriteCloser, error) {
        f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
        if err != nil {
                return nil, fmt.Errorf("audit-log: open %s: %w", path, err)
        }
        // Write a session-start marker.
        fmt.Fprintf(f, "# session start %s\n", time.Now().Format(time.RFC3339Nano))
        return &auditConn{inner: c, logFile: f}, nil
}

func (a *auditConn) Read(p []byte) (int, error) {
        n, err := a.inner.Read(p)
        if n > 0 {
                a.mu.Lock()
                fmt.Fprintf(a.logFile, "%s S2C %d\n", time.Now().Format(time.RFC3339Nano), n)
                fmt.Fprintln(a.logFile, hex.EncodeToString(p[:n]))
                a.mu.Unlock()
        }
        return n, err
}

func (a *auditConn) Write(p []byte) (int, error) {
        n, err := a.inner.Write(p)
        if n > 0 {
                a.mu.Lock()
                fmt.Fprintf(a.logFile, "%s C2S %d\n", time.Now().Format(time.RFC3339Nano), n)
                fmt.Fprintln(a.logFile, hex.EncodeToString(p[:n]))
                a.mu.Unlock()
        }
        return n, err
}

func (a *auditConn) Close() error {
        a.mu.Lock()
        fmt.Fprintf(a.logFile, "# session end %s\n", time.Now().Format(time.RFC3339Nano))
        _ = a.logFile.Close()
        a.mu.Unlock()
        return a.inner.Close()
}
