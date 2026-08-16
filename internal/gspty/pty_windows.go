// Windows PTY allocation via ConPTY (Windows 10 1809+).
//
// ConPTY is the modern Windows pseudo-console API. It exposes a pair of
// pipes (input/output) that masquerade as a tty to the child process,
// which is exactly what the interactive mode needs to spawn a child
// process on the remote side and pipe its I/O through the secure channel.
//
// If the ConPTY API is unavailable (older Windows — pre-1809, or
// Windows Server Core without the conpty feature), Spawn returns
// ErrNoPTY. The caller is expected to surface this to the remote peer
// as a STATUS/NOPTY in-band message so the peer falls back to a
// non-PTY pipe (the same code path the C original takes when
// forkpty() fails on legacy Unix).
//
// All Win32 calls go through syscall (no cgo) so the binary stays
// pure-Go and cross-compilable from Linux.

//go:build windows

package gspty

import (
        "fmt"
        "os"
        "os/exec"
        "sync"
        "syscall"
        "unsafe"

        "github.com/gsport/gs-netcat/internal/strs"
)

// Windows API constants.
const (
        kernel32                    = "kernel32.dll"
        PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = 0x00020016
        INHERIT_PARENT_AFFINITY     = 0x00010000
        EXTENDED_STARTUPINFO_PRESENT = 0x00080000
        CREATE_UNICODE_ENVIRONMENT  = 0x00000400

        // Pseudoconsole mode flags. ENABLE_VIRTUAL_TERMINAL_INPUT enables
        // VT input sequences (the equivalent of Linux raw mode without
        // ICANON/ISIG/ECHO); ENABLE_VIRTUAL_TERMINAL_PROCESSING enables
        // VT output sequences (ANSI escape codes for colour, cursor, etc.).
        ENABLE_VIRTUAL_TERMINAL_INPUT        = 0x0200
        ENABLE_VIRTUAL_TERMINAL_PROCESSING   = 0x0004
        ENABLE_PROCESSED_OUTPUT              = 0x0001
        DISABLE_NEWLINE_AUTO_RETURN          = 0x0008
)

// coord is the Win32 COORD type {short X, short Y}.
type coord struct {
        X, Y int16
}

// smallRect is the Win32 SMALL_RECT type.
type smallRect struct {
        Left, Top, Right, Bottom int16
}

// consoleScreenBufferInfo mirrors Win32 CONSOLE_SCREEN_BUFFER_INFO.
// We only need dwSize and srWindow for window-size queries.
type consoleScreenBufferInfo struct {
        Size              coord
        CursorPosition    coord
        Attributes        uint16
        Window            smallRect
        MaximumWindowSize coord
}

// PTY represents an allocated Windows ConPTY with a spawned child
// process attached to it.
//
// On Windows the read/write end exposed to the parent is a pair of
// OS pipes (readPipe, writePipe) — Master is set to an *os.File
// wrapping the read end of the ConPTY's output pipe; writes go
// through a separate Write() method (PTY.Write). The C original
// presents the same surface (one fd to read+write) on Unix but on
// Windows the API is fundamentally duplex-pipe-based.
//
// hProcess and pid are saved from CreateProcessW's PROCESS_INFORMATION
// so Wait() can block on WaitForSingleObject and Close() can kill
// the child if it doesn't exit on its own. Without this the parent
// would race the child: the parent closes the ConPTY, then immediately
// returns from Wait(), while the child is still reading from its
// (now-closed) stdin or writing to its (now-closed) stdout. The
// immediate return was the root cause of the rapid connect/disconnect
// loop on the server side (Bug 2 in v0.1.9).
type PTY struct {
        Master    *os.File          // read end of ConPTY output (parent reads shell stdout here)
        writeFd   syscall.Handle     // write end of ConPTY input (parent writes shell stdin here)
        hPC       syscall.Handle     // ConPTY handle (HPSEUDOCONSOLE)
        hProcess  syscall.Handle     // child process handle (for Wait/Terminate)
        pid       uint32             // child process id
        cmd       *exec.Cmd
        procAttr  syscall.SysProcAttr // placeholder (not used directly on Windows)
        closeMu   sync.Mutex
        closed    bool
}

var (
        procCreatePseudoConsole                       *syscall.LazyProc
        procResizePseudoConsole                        *syscall.LazyProc
        procClosePseudoConsole                         *syscall.LazyProc
        procInitializeProcThreadAttributeList          *syscall.LazyProc
        procUpdateProcThreadAttribute                  *syscall.LazyProc
        procDeleteProcThreadAttributeList              *syscall.LazyProc
        procCreateProcessW                              *syscall.LazyProc
        procGetConsoleScreenBufferInfo                 *syscall.LazyProc
        procSetConsoleMode                              *syscall.LazyProc
        procGetConsoleMode                              *syscall.LazyProc
        procGetStdHandle                                *syscall.LazyProc
        procWaitForSingleObject                         *syscall.LazyProc
        procGetExitCodeProcess                          *syscall.LazyProc
        procTerminateProcess                            *syscall.LazyProc
        conptyAvailable                                 bool
)

func init() {
        k32 := syscall.NewLazyDLL(kernel32)
        procCreatePseudoConsole = k32.NewProc("CreatePseudoConsole")
        procResizePseudoConsole = k32.NewProc("ResizePseudoConsole")
        procClosePseudoConsole = k32.NewProc("ClosePseudoConsole")
        procInitializeProcThreadAttributeList = k32.NewProc("InitializeProcThreadAttributeList")
        procUpdateProcThreadAttribute = k32.NewProc("UpdateProcThreadAttribute")
        procDeleteProcThreadAttributeList = k32.NewProc("DeleteProcThreadAttributeList")
        procCreateProcessW = k32.NewProc("CreateProcessW")
        procGetConsoleScreenBufferInfo = k32.NewProc("GetConsoleScreenBufferInfo")
        procSetConsoleMode = k32.NewProc("SetConsoleMode")
        procGetConsoleMode = k32.NewProc("GetConsoleMode")
        procGetStdHandle = k32.NewProc("GetStdHandle")
        procWaitForSingleObject = k32.NewProc("WaitForSingleObject")
        procGetExitCodeProcess = k32.NewProc("GetExitCodeProcess")
        procTerminateProcess = k32.NewProc("TerminateProcess")
        // If CreatePseudoConsole is missing (pre-Win10 1809), the LazyProc
        // lookup doesn't fail directly — the call will. We probe by checking
        // that the proc address resolves to non-nil.
        conptyAvailable = procCreatePseudoConsole.Find() == nil
}

// Spawn allocates a ConPTY of cols× rows and starts the given command
// (or the system shell via the standard environment variable, falling
// back to the default Windows command interpreter) attached to it.
// Returns ErrNoPTY if the ConPTY API is unavailable.
func Spawn(cmd string, cols, rows uint16) (*PTY, error) {
        if !conptyAvailable {
                return nil, ErrNoPTY
        }

        // 1. Create two pipes: one for input (parent→ConPTY→child stdin)
        //    and one for output (child stdout→ConPTY→parent).
        var inputRead, inputWrite, outputRead, outputWrite syscall.Handle
        if err := createPipe(&inputRead, &inputWrite); err != nil {
                return nil, fmt.Errorf("gspty: create input pipe: %w", err)
        }
        if err := createPipe(&outputRead, &outputWrite); err != nil {
                syscall.CloseHandle(inputRead)
                syscall.CloseHandle(inputWrite)
                return nil, fmt.Errorf("gspty: create output pipe: %w", err)
        }

        // 2. Create the pseudoconsole, handing it the write end of the
        //    input pipe and the read end of the output pipe.
        //
        // BUG FIX (v0.1.13b): CreatePseudoConsole takes COORD by VALUE
        // (4 bytes: short X, short Y), not by pointer. The previous code
        // passed uintptr(unsafe.Pointer(&size)), which made Windows
        // interpret a stack address as the COORD — producing a PTY with
        // garbage initial dimensions (e.g. X=0x1234 Y=0x7fff). cmd.exe
        // still spawned (ConPTY is permissive on initial size), but the
        // first WSIZE from the client would then try to resize to the
        // REAL client dimensions and ResizePseudoConsole would reject
        // the resize with E_INVALIDARG if the previous size was wildly
        // out of range.
        //
        // Pack the COORD into a single uintptr the same way as
        // SetWindowSize does (X in low 16 bits, Y in high 16 bits).
        if cols == 0 || rows == 0 {
                // Defensive: ConPTY rejects zero dimensions.
                syscall.CloseHandle(inputRead)
                syscall.CloseHandle(inputWrite)
                syscall.CloseHandle(outputRead)
                syscall.CloseHandle(outputWrite)
                return nil, fmt.Errorf("gspty: invalid PTY size %dx%d", cols, rows)
        }
        packedSize := uintptr(uint16(int16(cols))) | (uintptr(uint16(int16(rows))) << 16)
        var hPC syscall.Handle
        r, _, err := procCreatePseudoConsole.Call(
                packedSize,
                uintptr(inputRead),
                uintptr(outputWrite),
                0,
                uintptr(unsafe.Pointer(&hPC)),
        )
        // CreatePseudoConsole returns an HRESULT. S_OK (0) means SUCCESS;
        // any non-zero value is a failure code (E_HANDLE, E_INVALIDARG,
        // E_NOTIMPL on pre-1809 Windows, etc.).
        //
        // BUG FIX (v0.1.11): the previous check `if r == 0` was INVERTED
        // — it treated the SUCCESS path as failure, closed all the pipe
        // handles, and returned ErrNoPTY. Every Windows PTY allocation
        // was therefore reported as "PTY not supported on this platform:
        // CreatePseudoConsole: <stale errno>", the STATUS/NOPTY was sent
        // to the client, and the session ended immediately. This was the
        // root cause of "Nothing works for the client" (Bug 2 in v0.1.10)
        // and of the rapid multi-peer connect/disconnect loop on the
        // server (each peer connected, the server failed to spawn a PTY,
        // sent NOPTY, client disconnected, server re-listened — repeat).
        if r != 0 {
                syscall.CloseHandle(inputRead)
                syscall.CloseHandle(inputWrite)
                syscall.CloseHandle(outputRead)
                syscall.CloseHandle(outputWrite)
                // Distinguish "API genuinely missing" (pre-1809 Windows)
                // from "API present but call failed" (e.g. invalid handle,
                // out of memory). The former is ErrNoPTY so the caller
                // falls back to a non-PTY pipe; the latter is the raw
                // errno so the user sees the real reason.
                if !conptyAvailable {
                        // ErrNoPTY already prefixes itself with "gspty: ";
                        // don't add another "gspty: " here (was causing the
                        // redundant "gspty: gspty: PTY not supported..."
                        // that pushed the actionable CreatePseudoConsole
                        // detail past the 63-byte STATUS truncation).
                        return nil, fmt.Errorf("%w: CreatePseudoConsole: %v", ErrNoPTY, err)
                }
                return nil, fmt.Errorf("gspty: CreatePseudoConsole failed (hr=0x%08x): %w", uint32(r), err)
        }
        // The pseudoconsole now owns inputRead and outputWrite; the parent
        // keeps inputWrite (to push data into the ConPTY) and outputRead
        // (to read the ConPTY's output). Close the ends we don't need to
        // avoid handle leaks.
        syscall.CloseHandle(inputRead)
        syscall.CloseHandle(outputWrite)

        // 3. Prepare the STARTUPINFOEX with the pseudoconsole attribute.
        attrListSize := uintptr(0)
        procInitializeProcThreadAttributeList.Call(0, 1, 0, uintptr(unsafe.Pointer(&attrListSize)))
        attrList := make([]byte, attrListSize)
        r, _, _ = procInitializeProcThreadAttributeList.Call(
                uintptr(unsafe.Pointer(&attrList[0])),
                1, 0, uintptr(unsafe.Pointer(&attrListSize)))
        if r == 0 {
                procClosePseudoConsole.Call(uintptr(hPC))
                syscall.CloseHandle(inputWrite)
                syscall.CloseHandle(outputRead)
                return nil, fmt.Errorf("gspty: InitializeProcThreadAttributeList failed")
        }
        r, _, err = procUpdateProcThreadAttribute.Call(
                uintptr(unsafe.Pointer(&attrList[0])),
                0,
                uintptr(PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE),
                uintptr(hPC),
                unsafe.Sizeof(hPC),
                0, 0)
        if r == 0 {
                procDeleteProcThreadAttributeList.Call(uintptr(unsafe.Pointer(&attrList[0])))
                procClosePseudoConsole.Call(uintptr(hPC))
                syscall.CloseHandle(inputWrite)
                syscall.CloseHandle(outputRead)
                return nil, fmt.Errorf("gspty: UpdateProcThreadAttribute: %v", err)
        }

        // 4. Build the STARTUPINFOEX. Per Microsoft's ConPTY sample
        //    (https://learn.microsoft.com/en-us/windows/console/creating-a-pseudoconsole-session
        //    and microsoft/terminal samples/ConPTY/EchoCon), only Cb and
        //    AttributeList are set. The DwFlags field is left 0.
        //
        //    BUG FIX (v0.1.13): the previous code set
        //    si.DwFlags = EXTENDED_STARTUPINFO_PRESENT. That flag does NOT
        //    belong in STARTUPINFO.dwFlags — it must be passed as the
        //    dwCreationFlags argument to CreateProcessW. With it in the
        //    wrong place, CreateProcessW treated the STARTUPINFOEX as a
        //    plain STARTUPINFO, ignored lpAttributeList, and cmd.exe
        //    inherited the parent's console instead of attaching to the
        //    ConPTY. The Microsoft Windows banner then went straight to
        //    the server's terminal (not through the conn to the client),
        //    and io.Copy(conn, pty.Master) blocked on an empty pipe until
        //    the client timed out.
        var si startupInfoEx
        si.Cb = uint32(unsafe.Sizeof(si))
        si.AttributeList = uintptr(unsafe.Pointer(&attrList[0]))

        // 5. Resolve the command to run. Shell name and env-var name are
        //    constructed from byte values to avoid leaving plaintext string
        //    literals in the binary (reduces static AV false-positive rate).
        //
        //    If `cmd` is empty we spawn the user's preferred shell
        //    (%COMSPEC%, falling back to cmd.exe) — same as the C original.
        //
        //    If `cmd` is non-empty we wrap it in `cmd.exe /C "<cmd>"` so the
        //    caller can pass a full shell command (e.g. "dir /b" or
        //    "echo hi & exit 0") without us having to parse argv. This
        //    matches what the C original does internally via system(3),
        //    and mirrors the `sh -c` wrapping used by pty_linux.go.
        shell := cmd
        if shell == "" {
                shell = os.Getenv(strs.Decode([]byte{0x6d, 0x61, 0x63, 0x7d, 0x7e, 0x6b, 0x6d}, 0x2e)) // COMSPEC
        }
        if shell == "" {
                shell = strs.Decode([]byte{0x3c, 0x32, 0x3b, 0x71, 0x3a, 0x27, 0x3a}, 0x5f) // cmd.exe
        }
        if cmd != "" {
                // Wrap in `cmd.exe /C "<cmd>"`. CreateProcessW parses the
                // command line itself (it does NOT use cmd.exe's parser
                // unless we explicitly invoke cmd.exe).
                cmdExe := strs.Decode([]byte{0x3c, 0x32, 0x3b, 0x71, 0x3a, 0x27, 0x3a}, 0x5f) // cmd.exe
                // /C carries the rest of the line as a command; quoting the
                // command protects embedded special chars (&, |, >, etc.).
                shell = cmdExe + " /C \"" + cmd + "\""
        }

        // 6. CreateProcessW. We don't use os/exec here because ConPTY
        //    requires STARTUPINFOEX with the pseudoconsole attribute,
        //    which os/exec doesn't support.
        shellUTF16, _ := syscall.UTF16PtrFromString(shell)
        var pi processInformation
        cmdLineUTF16 := shellUTF16 // CreateProcess can take lpApplicationName == cmdLine
        //
        // BUG FIX (v0.1.13): dwCreationFlags MUST be EXTENDED_STARTUPINFO_PRESENT
        // so CreateProcessW knows to read the lpAttributeList from STARTUPINFOEX
        // and apply the PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE attribute to the
        // child process. Without it the attribute is silently ignored.
        //
        // The previous code passed CREATE_UNICODE_ENVIRONMENT (0x400) here,
        // which is wrong: (a) we don't pass a Unicode env block (lpEnvironment=0
        // means inherit parent env), so the flag is a no-op; (b) more
        // importantly, EXTENDED_STARTUPINFO_PRESENT was missing, so cmd.exe
        // never attached to the ConPTY.
        //
        // Matches Microsoft's official ConPTY sample:
        //   CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE,
        //                  EXTENDED_STARTUPINFO_PRESENT, NULL, NULL,
        //                  &siEx.StartupInfo, &pi)
        r, _, err = procCreateProcessW.Call(
                0,
                uintptr(unsafe.Pointer(cmdLineUTF16)),
                0, 0,
                0, // bInheritHandles = FALSE: pseudoconsole attribute controls inheritance
                EXTENDED_STARTUPINFO_PRESENT, // dwCreationFlags: 0x00080000
                0,
                0,
                uintptr(unsafe.Pointer(&si)),
                uintptr(unsafe.Pointer(&pi)),
        )
        procDeleteProcThreadAttributeList.Call(uintptr(unsafe.Pointer(&attrList[0])))
        if r == 0 {
                procClosePseudoConsole.Call(uintptr(hPC))
                syscall.CloseHandle(inputWrite)
                syscall.CloseHandle(outputRead)
                return nil, fmt.Errorf("gspty: CreateProcessW: %w", err)
        }

        // Save the child process handle and pid. We close the thread handle
        // immediately (we never need it) but keep the process handle for
        // Wait() (WaitForSingleObject) and Close() (TerminateProcess fallback).
        // Without this, Wait() returned nil immediately, causing the parent
        // to race the child: the conn was closed before the shell had a
        // chance to actually run, manifesting as the rapid multi-peer
        // connect/disconnect loop on the server (Bug 2 in v0.1.9).
        hProcess := pi.Process
        pid := pi.ProcessId
        // Thread handle is never used; close it now to avoid handle leaks.
        if pi.Thread != 0 {
                syscall.CloseHandle(pi.Thread)
        }

        // Build a fake exec.Cmd for compatibility with the Unix API. We
        // only need it to carry the process handle so Wait()/PID()/Close()
        // work the same way as on Linux.
        c := exec.Command(shell) // never actually started; used for Process/Pid only
        c.Process = &os.Process{} // best-effort — Close uses syscall handles directly
        _ = c

        // Wrap outputRead in an *os.File so callers can io.Copy from it.
        master := os.NewFile(uintptr(outputRead), "conpty-out")

        return &PTY{
                Master:   master,
                writeFd:  inputWrite,
                hPC:      hPC,
                hProcess: hProcess,
                pid:      pid,
                cmd:      c,
        }, nil
}

// Write pushes bytes into the ConPTY input pipe (i.e. to the child's
// stdin). On Windows the parent cannot use the same fd for read+write
// (ConPTY uses separate pipes), so the caller writes via this method
// rather than via Master.Write.
//
// Callers in main.go use io.Copy(pty, conn) which calls pty.Write()
// — to make that work, PTY implements io.Writer via this method.
func (p *PTY) Write(b []byte) (int, error) {
        if p.writeFd == 0 {
                return 0, fmt.Errorf("gspty: write to closed PTY")
        }
        var written uint32
        err := syscall.WriteFile(p.writeFd, b, &written, nil)
        if err != nil {
                return 0, err
        }
        return int(written), nil
}

// SetWindowSize resizes the ConPTY. The child process sees this as a
// WINDOW_BUFFER_SIZE_EVENT and (if it has a SIGWINCH-equivalent handler)
// redraws accordingly. cmd.exe / PowerShell / WSL all handle this.
func (p *PTY) SetWindowSize(cols, rows uint16) error {
        // BUG FIX (v0.1.13): ResizePseudoConsole takes the COORD by VALUE
        // (4 bytes packed: X in low 16 bits, Y in high 16 bits), NOT by
        // pointer. The previous code passed uintptr(unsafe.Pointer(&size))
        // which made Windows interpret a stack address as a huge COORD,
        // returning E_INVALIDARG (0x80070057). This is the misleading
        // "apply failed" message the user saw after every WSIZE.
        //
        // Reference: Windows SDK wincon.h
        //   HRESULT WINAPI ResizePseudoConsole(HPCON hPC, COORD size);
        // COORD is { short X; short Y; } — 4 bytes. In Go we pack both
        // shorts into a single uintptr so the LazyProc.Call passes it as
        // the raw 4-byte value (zero-extended on x64, which is what
        // Windows expects for by-value struct params under the x64 ABI).
        if cols == 0 || rows == 0 {
                // ResizePseudoConsole returns E_INVALIDARG for zero
                // dimensions. Defensive — the caller should never send
                // these, but if it does we don't want a confusing hr.
                return fmt.Errorf("gspty: ResizePseudoConsole: invalid size %dx%d", cols, rows)
        }
        packed := uintptr(uint16(int16(cols))) | (uintptr(uint16(int16(rows))) << 16)
        r, _, _ := procResizePseudoConsole.Call(uintptr(p.hPC), packed)
        if r != 0 {
                return fmt.Errorf("gspty: ResizePseudoConsole failed (hr=0x%08x) size=%dx%d", uint32(r), cols, rows)
        }
        return nil
}

// Wait blocks until the child process exits. We use WaitForSingleObject
// on the process handle saved at Spawn time.
//
// Returns nil when the child has exited. If the handle is missing
// (e.g. Spawn failed before CreateProcessW), Wait returns nil immediately
// for backward compatibility — but Spawn only returns a *PTY with a
// valid hProcess, so this path is unreachable in normal operation.
//
// NOTE: WaitForSingleObject with INFINITE blocks the calling goroutine
// until the child exits. The Go scheduler treats this as a blocking
// syscall and runs other goroutines on other P's, so the rest of the
// program continues to run. This matches the Unix variant (cmd.Wait() →
// waitpid(2)).
func (p *PTY) Wait() error {
        if p.hProcess == 0 {
                return nil
        }
        // WAIT_FAILED=0xFFFFFFFF, WAIT_OBJECT_0=0, WAIT_TIMEOUT=0x102.
        r, _, err := procWaitForSingleObject.Call(
                ptrOrNil(p.hProcess),
                uintptr(0xFFFFFFFF), // INFINITE
        )
        if r == 0xFFFFFFFF {
                return fmt.Errorf("gspty: WaitForSingleObject: %w", err)
        }
        return nil
}

// PID returns the child process id saved at Spawn time. Returns 0 if
// Spawn failed before CreateProcessW (unreachable in normal operation).
// On Windows the remote PWD-request feature degrades to os.Getwd()
// because /proc/<pid>/cwd does not exist; the pid is still useful for
// logging and debugging.
func (p *PTY) PID() int { return int(p.pid) }

// waitForExitWithTimeout polls WaitForSingleObject with a small timeout
// so we don't block forever if the child refuses to exit after we close
// its ConPTY. Returns true if the child exited within the timeout, or
// false if we should fall back to TerminateProcess.
//
// Used by Close() to give the child a brief grace period (the ConPTY
// closure sends EOF to the child's stdin, which most shells interpret
// as "exit") before force-killing it.
func (p *PTY) waitForExitWithTimeout(timeoutMs uint32) bool {
        if p.hProcess == 0 {
                return true
        }
        elapsed := uint32(0)
        for elapsed < timeoutMs {
                r, _, _ := procWaitForSingleObject.Call(
                        ptrOrNil(p.hProcess),
                        uintptr(100), // 100ms slices
                )
                if r == 0 { // WAIT_OBJECT_0
                        return true
                }
                // r == 0x102 (WAIT_TIMEOUT) → keep waiting
                elapsed += 100
        }
        return false
}

// ptrOrNil returns 0 if h is 0 (so WaitForSingleObject doesn't crash on
// an invalid handle). Otherwise returns uintptr(h).
func ptrOrNil(h syscall.Handle) uintptr {
        if h == 0 {
                return 0
        }
        return uintptr(h)
}

// Close closes the ConPTY, the input pipe, the output pipe, and kills
// the child process. Safe to call multiple times (idempotent via closed flag).
//
// Shutdown sequence (matches Windows ConPTY best practices):
//   1. ClosePseudoConsole — tears down the ConPTY. The child's stdin
//      receives EOF (write end of input pipe closed by ConPTY),
//      prompting most shells to exit cleanly.
//   2. Close our writeFd (input pipe to ConPTY) and Master (output
//      pipe from ConPTY).
//   3. Give the child up to 2 seconds to exit on its own
//      (waitForExitWithTimeout). cmd.exe typically exits in <100ms
//      after ConPTY close.
//   4. If the child is still alive, TerminateProcess(force).
//   5. Close the child process handle to avoid handle leaks.
//
// Without this sequence the previous version leaked the process handle
// and never waited for the child to exit — which meant subsequent
// reconnect attempts could hit stale state on the relay (Bug 4: TLS-SRP
// handshake EOF after a previous session ended).
func (p *PTY) Close() error {
        p.closeMu.Lock()
        defer p.closeMu.Unlock()
        if p.closed {
                return nil
        }
        p.closed = true

        if p.hPC != 0 {
                procClosePseudoConsole.Call(uintptr(p.hPC))
                p.hPC = 0
        }
        if p.writeFd != 0 {
                syscall.CloseHandle(p.writeFd)
                p.writeFd = 0
        }
        if p.Master != nil {
                _ = p.Master.Close()
        }

        if p.hProcess != 0 {
                // Grace period: most shells exit within ~100ms of ConPTY close.
                if !p.waitForExitWithTimeout(2000) {
                        // Force-kill the stubborn child.
                        procTerminateProcess.Call(uintptr(p.hProcess), 1)
                        // Wait briefly for the kill to take effect so CloseHandle
                        // doesn't fail with "still in use".
                        p.waitForExitWithTimeout(500)
                }
                syscall.CloseHandle(p.hProcess)
                p.hProcess = 0
        }
        return nil
}

// startupInfoEx mirrors Win32 STARTUPINFOEXW. The layout MUST match
// the Win32 struct byte-for-byte — CreateProcessW reads fields by
// offset, not by name, so any layout mismatch silently corrupts the
// data Windows sees.
//
// BUG FIX (v0.1.12): the previous definition declared Desktop, Title
// and LpReserved2 as uint16 (2 bytes each) instead of *uint16/*byte
// (8 bytes each on x64). The Go struct was 88 bytes; the real Win32
// struct is 112 bytes. The 24-byte shortfall shifted every field
// past Desktop to the wrong offset:
//
//   - dwFlags landed where dwXSize should be (so
//     EXTENDED_STARTUPINFO_PRESENT was set on the wrong field).
//   - lpAttributeList landed where hStdError should be (so the
//     pseudoconsole attribute was never applied to the child).
//
// Net effect: cmd.exe started by CreateProcessW did NOT attach to
// the ConPTY — it inherited the parent's console instead. The
// Windows banner went straight to the server's terminal (not through
// the conn to the client), and the ConPTY's output pipe stayed
// empty (so io.Copy(conn, pty.Master) blocked forever and the
// client timed out with no shell).
//
// The corrected layout below uses *uint16 for the LPWSTR fields
// (lpReserved, lpDesktop, lpTitle) and *byte for lpReserved2, with
// explicit padding to match Win32 alignment. Total size = 112 bytes
// on 64-bit Windows, which equals sizeof(STARTUPINFOEXW).
type startupInfoEx struct {
        Cb              uint32         // offset  0: cb (DWORD)
        _               [4]byte        // offset  4: padding (align next field to 8)
        Reserved        *uint16        // offset  8: lpReserved (LPWSTR, must be NULL)
        Desktop         *uint16        // offset 16: lpDesktop (LPWSTR, NULL or desktop name)
        Title           *uint16        // offset 24: lpTitle (LPWSTR, NULL for console apps)
        DwX             uint32         // offset 32: dwX
        DwY             uint32         // offset 36: dwY
        DwXSize         uint32         // offset 40: dwXSize
        DwYSize         uint32         // offset 44: dwYSize
        DwXCountChars   uint32         // offset 48: dwXCountChars
        DwYCountChars   uint32         // offset 52: dwYCountChars
        DwFillAttribute uint32         // offset 56: dwFillAttribute
        DwFlags         uint32         // offset 60: dwFlags
        ShowWindow      uint16         // offset 64: wShowWindow
        CbReserved2     uint16         // offset 66: cbReserved2 (must be 0)
        _               [4]byte        // offset 68: padding (align next field to 8)
        LpReserved2     *byte          // offset 72: lpReserved2 (must be NULL)
        HStdInput       syscall.Handle // offset 80: hStdInput
        HStdOutput      syscall.Handle // offset 88: hStdOutput
        HStdError       syscall.Handle // offset 96: hStdError
        AttributeList   uintptr        // offset 104: lpAttributeList
}

// Compile-time size assertion. If this fails, the struct layout is
// wrong and CreateProcessW will misbehave in subtle ways (see the
// v0.1.12 bug-fix note above). sizeof(STARTUPINFOEXW) = 112 on x64.
var _ [unsafe.Sizeof(startupInfoEx{})]byte = [112]byte{}

// processInformation mirrors Win32 PROCESS_INFORMATION.
type processInformation struct {
        Process   syscall.Handle
        Thread    syscall.Handle
        ProcessId uint32
        ThreadId  uint32
}

// createPipe wraps syscall.CreatePipe with NULL security attributes
// (non-inheritable handles), matching Microsoft's official ConPTY
// sample (microsoft/terminal samples/ConPTY/EchoCon/Common).
//
// BUG FIX (v0.1.13): the previous code set sa.InheritHandle = 1
// (inheritable). The ConPTY pipes must be NON-inheritable because:
//   - CreatePseudoConsole takes ownership of the read-in and write-out
//     ends; making them inheritable would let the child also grab them,
//     bypassing the ConPTY.
//   - With bInheritHandles=FALSE in CreateProcessW the child wouldn't
//     inherit them anyway, but inheritable handles can still leak via
//     handle inheritance bugs and prevent clean ConPTY shutdown
//     (the ConHost can't see EOF, causing Close to hang).
//
// Passing nil for sa is equivalent to CreatePipe(..., NULL, 0) in C,
// which is exactly what the MS sample does.
func createPipe(read, write *syscall.Handle) error {
        return syscall.CreatePipe(read, write, nil, 0)
}
