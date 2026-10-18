// v0.2.5: --sftp-real — real SFTP server via pkg/sftp + crypto/ssh.
//
// Runs a real SSH server over the GS-encrypted channel and serves the
// SFTP subsystem. Standard SFTP clients (sftp, lftp, FileZilla, WinSCP)
// can connect.
//
// Wire compat: [G<->C] — the wire protocol is SSH-on-top-of-GS, which
// is application-layer on top of the GS-encrypted channel. The remote
// peer just sees bytes flowing through.
//
// Usage:
//   # Server side (Go port, listen mode):
//   ./gs-netcat -l -i -s S --sftp-real /var/www
//
//   # Client side (Go port, connects to server, exposes local SSH port):
//   ./gs-netcat -i -s S --sftp-real-client 2222
//
//   # Then from any standard SFTP client:
//   sftp -P 2222 gsuser@localhost
//   # Password: the GS secret
//
// Authentication: username "gsuser", password = the GS secret.
// The GS channel is already end-to-end encrypted via TLS-SRP — the
// SSH layer is just for protocol compatibility with standard clients.
//
// Dependencies:
//   golang.org/x/crypto/ssh — SSH protocol implementation
//   github.com/pkg/sftp — SFTP subsystem handler
package main

import (
        "fmt"
        "io"
        "os"
        "path/filepath"

        "github.com/pkg/sftp"
        "golang.org/x/crypto/ssh"
)

// runSFTPRealServer runs a real SSH+SFTP server over the established
// GS connection. The conn is used as the SSH transport (one SSH session
// per GS connection).
//
// `rootDir` is the filesystem path the SFTP server treats as the
// working directory. Empty = use current working directory.
//
// Authentication: username "gsuser", password = the GS secret.
//
// This function blocks until the GS connection closes.
func runSFTPRealServer(gsConn io.ReadWriteCloser, rootDir, secret string, verbose bool) error {
        if rootDir == "" {
                rootDir, _ = os.Getwd()
        }
        absRoot, err := filepath.Abs(rootDir)
        if err != nil {
                return fmt.Errorf("sftp-real: resolve root %q: %w", rootDir, err)
        }
        if verbose {
                logf("sftp-real: serving %s over GS (auth: gsuser/<secret>)", absRoot)
        }

        // v0.3.0: Persistent host key. We derive an ed25519 key deterministically
        // from the GS secret (via SHA256). This means the same secret always
        // produces the same SSH host key — clients won't see "host key changed"
        // warnings when reconnecting with the same secret.
        //
        // Security: this is acceptable because:
        //   1. The GS channel is already E2E encrypted via TLS-SRP
        //   2. The SSH host key is just for protocol compatibility — an
        //      attacker who knows the secret can already MITM the GS channel
        //      (and thus the SSH layer), so deriving the host key from the
        //      secret adds no new attack surface.
        //   3. Without persistence, every reconnect shows a "host key changed"
        //      warning that breaks automated SFTP clients (WinSCP, lftp).
        hostKey, err := deriveEd25519SignerFromSecret(secret)
        if err != nil {
                return fmt.Errorf("sftp-real: derive host key: %w", err)
        }

        // Configure the SSH server.
        config := &ssh.ServerConfig{
                PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
                        if c.User() == "gsuser" && string(pass) == secret {
                                return nil, nil
                        }
                        return nil, fmt.Errorf("auth failed (user=%q)", c.User())
                },
        }
        config.AddHostKey(hostKey)

        // Wrap gsConn as a net.Conn for the SSH handshake.
        netConn := &gsConnAdapter{rwc: gsConn}

        // Perform the SSH handshake (server side).
        sConn, chans, reqs, err := ssh.NewServerConn(netConn, config)
        if err != nil {
                return fmt.Errorf("sftp-real: SSH handshake: %w", err)
        }
        defer sConn.Close()
        if verbose {
                logf("sftp-real: SSH connection from %s (user=%s)", sConn.RemoteAddr(), sConn.User())
        }

        // Discard out-of-band global requests.
        go ssh.DiscardRequests(reqs)

        // Handle channel requests (each SFTP session opens a "session" channel).
        for newChannel := range chans {
                if newChannel.ChannelType() != "session" {
                        newChannel.Reject(ssh.UnknownChannelType, "only session channels supported")
                        continue
                }
                channel, requests, err := newChannel.Accept()
                if err != nil {
                        if verbose {
                                logf("sftp-real: accept channel: %v", err)
                        }
                        continue
                }
                go handleSFTPSession(channel, requests, absRoot, verbose)
        }
        return nil
}

// handleSFTPSession handles one SSH "session" channel — typically a
// single SFTP subsystem request.
func handleSFTPSession(channel ssh.Channel, requests <-chan *ssh.Request, rootDir string, verbose bool) {
        defer channel.Close()

        for req := range requests {
                switch req.Type {
                case "subsystem":
                        // Subsystem name is in req.Payload as a string (SSH wire format).
                        name := string(req.Payload[4:]) // first 4 bytes are length
                        if name == "sftp" {
                                req.Reply(true, nil)
                                // Hand off to the SFTP handler.
                                handler := sftp.NewRequestServer(channel, sftp.Handlers{
                                        FileGet:  &sftpRootHandler{root: rootDir},
                                        FilePut:  &sftpRootHandler{root: rootDir},
                                        FileCmd:  &sftpRootHandler{root: rootDir},
                                        FileList: &sftpRootHandler{root: rootDir},
                                })
                                if err := handler.Serve(); err != nil && err != io.EOF {
                                        if verbose {
                                                logf("sftp-real: serve: %v", err)
                                        }
                                }
                                handler.Close()
                                return
                        }
                        req.Reply(false, []byte("unknown subsystem"))
                case "exec":
                        // Allow "sftp" command (some clients use exec instead of subsystem).
                        cmd := string(req.Payload[4:])
                        if cmd == "sftp" {
                                req.Reply(true, nil)
                                handler := sftp.NewRequestServer(channel, sftp.Handlers{
                                        FileGet:  &sftpRootHandler{root: rootDir},
                                        FilePut:  &sftpRootHandler{root: rootDir},
                                        FileCmd:  &sftpRootHandler{root: rootDir},
                                        FileList: &sftpRootHandler{root: rootDir},
                                })
                                if err := handler.Serve(); err != nil && err != io.EOF {
                                        if verbose {
                                                logf("sftp-real: serve (exec): %v", err)
                                        }
                                }
                                handler.Close()
                                return
                        }
                        req.Reply(false, []byte("only 'sftp' exec supported"))
                case "shell":
                        req.Reply(false, []byte("shell not supported; use SFTP"))
                case "env":
                        req.Reply(true, nil)
                case "pty-req":
                        req.Reply(false, nil)
                default:
                        req.Reply(false, nil)
                }
        }
}

// sftpRootHandler implements sftp.Handlers (FileGet, FilePut, FileCmd, FileList).
// It serves the local filesystem rooted at sftpRootHandler.root.
// v0.3.0: chroot enforced via resolvePath (EvalSymlinks + prefix check).
type sftpRootHandler struct {
        root string
}

// FileGet / FilePut / FileCmd / FileList methods on sftpRootHandler
// are defined in sftp_real_handler.go.
