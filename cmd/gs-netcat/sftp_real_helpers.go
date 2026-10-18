// v0.2.5: SSH host key generation and gsConn→net.Conn adapter.
package main

import (
        "crypto/ed25519"
        cryptorand "crypto/rand"
        "crypto/sha256"
        "fmt"
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

// deriveEd25519SignerFromSecret derives an ed25519 SSH host key
// deterministically from the GS secret.
//
// v0.3.0: This solves the "host key changed" warning that breaks
// automated SFTP clients (WinSCP, lftp). The same secret always
// produces the same SSH host key, so clients can pin it once and
// reconnect without warnings.
//
// Implementation: SHA256("sftp-host-key/" || secret) → 32-byte ed25519 seed.
// ed25519.NewKeyFromSeed takes a 32-byte seed and produces a private key.
//
// Security: this is acceptable because:
//   1. The GS channel is already E2E encrypted via TLS-SRP
//   2. The SSH host key is just for protocol compatibility
//   3. An attacker who knows the secret can already MITM the GS channel
//      (and thus the SSH layer), so deriving the host key from the
//      secret adds no new attack surface
//   4. Without persistence, every reconnect shows "host key changed"
//      warnings that break automated SFTP clients
func deriveEd25519SignerFromSecret(secret string) (ssh.Signer, error) {
        h := sha256.New()
        h.Write([]byte("sftp-host-key/"))
        h.Write([]byte(secret))
        seed := h.Sum(nil) // 32 bytes
        if len(seed) != ed25519.SeedSize {
                return nil, fmt.Errorf("internal: SHA256 produced %d bytes (want %d)", len(seed), ed25519.SeedSize)
        }
        priv := ed25519.NewKeyFromSeed(seed)
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
