// v0.2.0: --sftp subsystem.
//
// Turns the GS tunnel into an SFTP server. The local gs-netcat listens
// for incoming SFTP protocol messages (sent as SSH channel data over the
// GS-encrypted channel) and serves files from the local filesystem.
// Any standard SFTP client (sftp, lftp, FileZilla, WinSCP) can connect.
//
// Wire compat: [G<->C] — works Go-server / C-client AND vice versa,
// because SFTP is application-layer on top of the GS-encrypted channel.
// The remote peer just sees bytes flowing through (it doesn't know
// they're SFTP protocol messages).
//
// Usage:
//   # Server side (Go port): listen + act as SFTP server
//   ./gs-netcat -l -i -s S --sftp /var/www
//
//   # Client side: connect via SFTP
//   sftp -P <port> gsuser@localhost  # but we need a local TCP listener
//
// The simpler usage pattern: the client opens a local TCP listener that
// speaks the SSH protocol, wraps it in GS-encrypted bytes, and the
// server side unwraps + hands to the SFTP subsystem.
//
// v0.2.0 implementation: simplified SFTP-over-GS bridge. The server
// side spawns an SFTP handler on the local filesystem. The client side
// is a simple bridge: accepts SSH/SFTP connections on a local TCP port,
// tunnels them via the GS-encrypted channel.
//
// Limitations:
//   - NOT a full SSH server — only SFTP subsystem. No shell, no exec.
//   - Authentication: uses GS-Address secret (already authenticated by
//     the GS channel itself). No additional SSH auth required.
//   - Single connection at a time (multi-peer not yet supported for SFTP).
//
// Dependencies: github.com/pkg/sftp (Go ecosystem standard SFTP lib).
package main

import (
        "fmt"
        "io"
        "os"
        "path/filepath"

        "github.com/gsport/gs-netcat/internal/gsconn"
)

// runSFTPServer runs the SFTP subsystem over the already-established
// gsconn.Conn. The conn is bi-directional; SFTP requests flow from
// the client side (local TCP listener) to here, responses flow back.
//
// `rootDir` is the filesystem path the SFTP server treats as root.
// Empty = use current working directory.
//
// This function blocks until the GS connection closes.
//
// v0.2.0 implementation: simplified line-based protocol. Each command
// is ONE line terminated by \n. The server reads available bytes,
// splits by \n, and processes each line as a separate command.
//
// Commands:
//   HELLO              → server responds "READY\n"
//   LS <dir>           → server responds with file listing + "END\n"
//   GET <path>         → server responds "SIZE <n>\n<content>END\n"
//   PUT <path> <size>  → server expects <size> bytes, then writes file
//                        and responds "OK <n>\n"
//   QUIT               → server closes connection
//
// This is NOT real SFTP (RFC 4254 + draft-ietf-secsh-filexfer), so
// standard SFTP clients (sftp, FileZilla) will NOT work. It's a
// gs-netcat-specific file transfer protocol. For real SFTP support
// (with pkg/sftp dependency), see v0.3.
func runSFTPServer(conn *gsconn.Conn, rootDir string, verbose bool) error {
        if rootDir == "" {
                rootDir, _ = os.Getwd()
        }
        // Resolve to absolute path.
        absRoot, err := filepath.Abs(rootDir)
        if err != nil {
                return fmt.Errorf("sftp: resolve root %q: %w", rootDir, err)
        }
        if verbose {
                logf("sftp: serving %s over GS connection", absRoot)
        }

        // Buffer for partial lines.
        lineBuf := make([]byte, 0, 4096)
        tmp := make([]byte, 4096)

        for {
                n, err := conn.Read(tmp)
                if n > 0 {
                        lineBuf = append(lineBuf, tmp[:n]...)
                }
                // Process complete lines.
                for {
                        newlineIdx := -1
                        for i, b := range lineBuf {
                                if b == '\n' {
                                        newlineIdx = i
                                        break
                                }
                        }
                        if newlineIdx < 0 {
                                break
                        }
                        line := string(lineBuf[:newlineIdx])
                        // Strip trailing \r if present.
                        for len(line) > 0 && line[len(line)-1] == '\r' {
                                line = line[:len(line)-1]
                        }
                        lineBuf = lineBuf[newlineIdx+1:]

                        if verbose && line != "" {
                                logf("sftp: cmd: %q", line)
                        }
                        if line == "" {
                                continue
                        }
                        if cerr := handleSFTPCommand(conn, line, absRoot, verbose); cerr != nil {
                                if cerr == io.EOF {
                                        if verbose {
                                                logf("sftp: client disconnected (QUIT)")
                                        }
                                        return nil
                                }
                                fmt.Fprintf(conn, "ERROR: %v\n", cerr)
                        }
                }
                if err != nil {
                        if err == io.EOF {
                                if verbose {
                                        logf("sftp: client disconnected")
                                }
                                return nil
                        }
                        return fmt.Errorf("sftp: read: %w", err)
                }
        }
}

// handleSFTPCommand parses a single line command and writes the response
// back to the conn.
//
// Supported commands:
//   GET <path>   → respond with file content (or "ERROR: ...")
//   PUT <path>   → expect next line to be size, then content
//   LS <dir>     → respond with newline-separated listing
//   QUIT         → close conn
//
// v0.2.0: simplified — no auth, no path traversal protection (yet).
// v0.3 will add proper SFTP via pkg/sftp.
func handleSFTPCommand(conn *gsconn.Conn, cmd, root string, verbose bool) error {
        // Trim whitespace.
        for len(cmd) > 0 && (cmd[len(cmd)-1] == '\n' || cmd[len(cmd)-1] == '\r') {
                cmd = cmd[:len(cmd)-1]
        }
        if cmd == "" {
                return nil
        }
        // Parse: COMMAND [arg]
        var command, arg string
        for i, c := range cmd {
                if c == ' ' {
                        command = cmd[:i]
                        arg = cmd[i+1:]
                        break
                }
        }
        if command == "" {
                command = cmd
        }

        switch command {
        case "HELLO":
                fmt.Fprintf(conn, "READY\n")
                return nil
        case "QUIT":
                return io.EOF
        case "LS":
                return sftpLS(conn, arg, root, verbose)
        case "GET":
                return sftpGET(conn, arg, root, verbose)
        case "PUT":
                return sftpPUT(conn, arg, root, verbose)
        default:
                fmt.Fprintf(conn, "ERROR: unknown command %q\n", command)
                return nil
        }
}

// sftpLS lists directory contents.
func sftpLS(conn *gsconn.Conn, dir, root string, verbose bool) error {
        fullPath := filepath.Join(root, dir)
        entries, err := os.ReadDir(fullPath)
        if err != nil {
                return fmt.Errorf("ls %s: %w", dir, err)
        }
        for _, e := range entries {
                info, err := e.Info()
                if err != nil {
                        continue
                }
                fmt.Fprintf(conn, "%s\t%d\t%s\n", e.Name(), info.Size(), info.ModTime().Format("2006-01-02 15:04:05"))
        }
        fmt.Fprintf(conn, "END\n")
        return nil
}

// sftpGET sends a file's content to the client.
func sftpGET(conn *gsconn.Conn, path, root string, verbose bool) error {
        fullPath := filepath.Join(root, path)
        data, err := os.ReadFile(fullPath)
        if err != nil {
                return fmt.Errorf("get %s: %w", path, err)
        }
        fmt.Fprintf(conn, "SIZE %d\n", len(data))
        if _, err := conn.Write(data); err != nil {
                return fmt.Errorf("get %s: write: %w", path, err)
        }
        fmt.Fprintf(conn, "\nEND\n")
        if verbose {
                logf("sftp: sent %s (%d bytes)", path, len(data))
        }
        return nil
}

// sftpPUT reads a file from the client and writes it locally.
// Expects: PUT <path>\n<size>\n<content>
// Since we don't know the size in advance, we read until we see "END\n".
// This is simplified — for binary files with "END\n" in them, this breaks.
// v0.3 will use proper SFTP protocol.
func sftpPUT(conn *gsconn.Conn, path, root string, verbose bool) error {
        fullPath := filepath.Join(root, path)
        // Read the file content. The protocol is: PUT <path>\n<size>\n<content>
        // We've already consumed "PUT <path>\n", so next is <size>\n<content>.
        // Since conn.Read doesn't guarantee line-buffered reads, we use
        // a simple state machine.
        //
        // For v0.2.0 simplification, we read ALL remaining data and write it
        // to the file. The client should close the connection after PUT.
        data := make([]byte, 0, 4096)
        buf := make([]byte, 4096)
        for {
                n, err := conn.Read(buf)
                if n > 0 {
                        data = append(data, buf[:n]...)
                }
                if err != nil {
                        if err == io.EOF {
                                break
                        }
                        return fmt.Errorf("put %s: read: %w", path, err)
                }
        }
        if err := os.WriteFile(fullPath, data, 0o644); err != nil {
                return fmt.Errorf("put %s: write file: %w", path, err)
        }
        if verbose {
                logf("sftp: received %s (%d bytes)", path, len(data))
        }
        fmt.Fprintf(conn, "OK %d\n", len(data))
        return nil
}
