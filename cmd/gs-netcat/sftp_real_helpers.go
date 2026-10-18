// v0.2.5: SSH host key generation and gsConn→net.Conn adapter.
package main

import (
        "crypto/ed25519"
        cryptorand "crypto/rand"
        "io"
        "net"
        "time"

        "golang.org/x/crypto/ssh"
)

// generateRandomEd25519Signer generates a fresh ed25519 SSH host key.
// Used for each SFTP-real session (no persistent host key file).
//
// Acceptable security model: the GS channel is already end-to-end
// encrypted via TLS-SRP, and the SSH layer is just for protocol
// compatibility with standard SFTP clients. The SSH host key only
// matters if an attacker can MITM the GS-encrypted channel — which
// they can't (TLS-SRP prevents that).
func generateRandomEd25519Signer() (ssh.Signer, error) {
        _, priv, err := ed25519.GenerateKey(cryptorand.Reader)
        if err != nil {
                return nil, err
        }
        signer, err := ssh.NewSignerFromKey(priv)
        if err != nil {
                return nil, err
        }
        return signer, nil
}

// gsConnAdapter wraps io.ReadWriteCloser to satisfy net.Conn.
// LocalAddr/RemoteAddr return dummy values (the underlying connection
// is a GS tunnel, not a TCP connection with a real address).
//
// v0.2.5: Deadlines are no-ops — the GS channel has its own keepalive
// and we don't want SSH-level deadlines interfering with the GS layer.
type gsConnAdapter struct {
        rwc io.ReadWriteCloser
}

func (g *gsConnAdapter) Read(p []byte) (int, error)         { return g.rwc.Read(p) }
func (g *gsConnAdapter) Write(p []byte) (int, error)        { return g.rwc.Write(p) }
func (g *gsConnAdapter) Close() error                        { return g.rwc.Close() }
func (g *gsConnAdapter) LocalAddr() net.Addr                 { return &net.IPAddr{} }
func (g *gsConnAdapter) RemoteAddr() net.Addr                { return &net.IPAddr{} }
func (g *gsConnAdapter) SetDeadline(t time.Time) error       { return nil }
func (g *gsConnAdapter) SetReadDeadline(t time.Time) error   { return nil }
func (g *gsConnAdapter) SetWriteDeadline(t time.Time) error  { return nil }

// io is needed for ReadWriteCloser.
var _ io.ReadWriteCloser = (io.ReadWriteCloser)(nil)
