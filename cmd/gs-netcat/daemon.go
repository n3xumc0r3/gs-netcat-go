// Command gs-netcat — daemon (-D) and watchdog (-W) implementation.
//
// Go does not have fork(); we use the re-exec pattern: the parent
// process spawns a child copy of itself with an extra hidden flag
// (--_daemonized or --_watchdog-child) and the child takes over the
// actual work. The parent either exits (daemon) or supervises+restarts
// the child (watchdog).
//
// Behavior matrix (matches the C original as closely as possible):
//
//      no flags:        normal foreground execution
//      -D:              detach from terminal, run once, parent exits
//      -W:              supervise: parent stays alive, restarts child on exit
//                       (in C this required _GSOCKET_INTERNAL; we expose
//                       it directly via the -W flag as the user asked)
//      -D -W:           detach AND supervise (parent watchdog runs detached)
//
// Restart policy (mirrors GS_daemonize in lib/gsocket-util.c:512-592):
//
//   - Child ran >60s before dying → restart immediately (1s sleep)
//   - Child exited with code 201 (EX_BAD_AUTH) → sleep 10s, retry
//   - Two consecutive EX_BAD_AUTH exits → parent exits (another daemon
//     with the same secret is already running)
//   - Otherwise → sleep 60s, retry
//
// On Windows:
//   - "Detach" means: spawn the child with CREATE_NO_WINDOW and
//     DETACHED_PROCESS creation flags, redirect stdio to NUL/DEVNULL,
//     parent exits. There is no setsid() equivalent; the child just
//     has no console and no parent tty attachment.
//   - "Watchdog" works the same: parent waits on child process exit,
//     restarts on death.
//
// BAD_AUTH detection (matches C): when -D is set we generate a unique
// auth-token based on the PID + secret, so a second daemon with the
// same secret will see BAD_AUTH from the relay and exit(201).
package main

import (
        "fmt"
        "os"
        "os/exec"
        "syscall"
        "time"
)

// exit codes used by the daemon/watchdog logic.
const (
        exitWatchdogBadAuth = 201 // matches EX_BAD_AUTH in C
)

// daemonizeAndOrWatchdog is called early in main() when -D and/or -W
// are set. It performs the parent/child fork emulation and returns
// ONLY in the child process (the actual worker). The parent either
// exits (daemon-only) or supervises+exits (watchdog).
//
// `args` is the original os.Args[1:] (already parsed). We re-build
// the child argv with the hidden flag appended so the child knows
// it's the worker and doesn't re-daemonize.
//
// Returns:
//   - nil  → caller is the child, continue normal execution
//   - non-nil → caller should exit with this error (only happens in
//     pathological cases like fork bomb prevention)
func daemonizeAndOrWatchdog(args []string, daemon, watchdog bool, verbose bool) error {
        // If we're already the worker child, just return. The hidden flag
        // is stripped by the parent before calling this.
        if os.Getenv("_GSNETCAT_CHILD") == "1" {
                if verbose {
                        fmt.Fprintf(os.Stderr, "[gs-netcat] running as daemonized child (pid=%d)\n", os.Getpid())
                }
                return nil
        }

        // Build the child argv: same flags as parent + hidden marker.
        // We use an env var instead of a CLI flag to avoid polluting the
        // user-visible flag namespace and to survive getopt re-parsing.
        childArgs := make([]string, len(args))
        copy(childArgs, args)

        childEnv := append(os.Environ(), "_GSNETCAT_CHILD=1")

        // Helper to spawn a child with given stdio disposition.
        spawn := func(detach bool) (*exec.Cmd, error) {
                exe, err := os.Executable()
                if err != nil {
                        return nil, fmt.Errorf("locate executable: %w", err)
                }
                cmd := exec.Command(exe, childArgs...)
                cmd.Env = childEnv
                // Inherit the working directory.
                cmd.Dir, _ = os.Getwd()

                if detach {
                        // Detached mode: stdio → DEVNULL, no terminal attachment.
                        // On Unix this approximates setsid() via Setpgid.
                        // On Windows this hides the console window.
                        devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
                        if err == nil {
                                cmd.Stdin = devNull
                                cmd.Stdout = devNull
                                cmd.Stderr = devNull
                        }
                        setDetachedAttrs(cmd)
                } else {
                        // Watchdog-only (no -D): keep stdio attached so the user
                        // can see child output. We don't inherit os.Stdin/Stdout/
                        // Stderr directly because we need to detect child exit
                        // (which requires cmd.Process.Wait, not a pipe).
                        cmd.Stdin = os.Stdin
                        cmd.Stdout = os.Stdout
                        cmd.Stderr = os.Stderr
                }

                if err := cmd.Start(); err != nil {
                        return nil, fmt.Errorf("spawn child: %w", err)
                }
                return cmd, nil
        }

        // --- Watchdog-only path (-W without -D) ---
        //
        // Spawn the first child, wait for it to exit, restart per policy.
        // We stay attached to the user's terminal so they see child output
        // and Ctrl-C kills us (and we kill the child).
        if watchdog && !daemon {
                return runWatchdogLoop(spawn, false, verbose)
        }

        // --- Daemon-only path (-D without -W) ---
        //
        // Spawn one detached child, parent exits immediately. The child
        // runs to completion (no restart on death).
        if daemon && !watchdog {
                cmd, err := spawn(true)
                if err != nil {
                        return err
                }
                // Release the child: parent exits.
                if verbose {
                        fmt.Fprintf(os.Stderr, "[gs-netcat] daemonized: child pid=%d, parent exiting\n", cmd.Process.Pid)
                }
                _ = cmd.Process.Release()
                os.Exit(0)
        }

        // --- Daemon + Watchdog path (-D -W) ---
        //
        // Spawn detached children in a restart loop.
        if daemon && watchdog {
                return runWatchdogLoop(spawn, true, verbose)
        }

        return nil
}

// runWatchdogLoop spawns children in a restart loop per the C
// GS_daemonize() policy. If `detach` is true, children are detached
// from the terminal (used for -D -W); otherwise stdio is inherited
// (used for -W alone).
//
// The loop runs forever unless:
//   - Two consecutive BAD_AUTH (exit 201) deaths → exit 0 (another
//     daemon with the same secret is already running)
//   - The child runs cleanly and exits 0 → exit 0 (clean shutdown)
//   - Wait, that's NOT what the C does. C restarts even on clean exit
//     because the watchdog is meant to keep the daemon up. We follow
//     the C behavior: only BAD_AUTH (twice) stops us.
func runWatchdogLoop(spawn func(detach bool) (*exec.Cmd, error), detach bool, verbose bool) error {
        var lastStartTime time.Time
        consecutiveBadAuth := 0

        for {
                cmd, err := spawn(detach)
                if err != nil {
                        fmt.Fprintf(os.Stderr, "[gs-netcat] watchdog: spawn failed: %v\n", err)
                        time.Sleep(5 * time.Second)
                        continue
                }
                lastStartTime = time.Now()
                if verbose {
                        fmt.Fprintf(os.Stderr, "[gs-netcat] watchdog: child pid=%d started\n", cmd.Process.Pid)
                }

                // Wait for the child to exit.
                err = cmd.Wait()
                exitCode := 0
                if err != nil {
                        if ee, ok := err.(*exec.ExitError); ok {
                                if ws, ok := ee.ProcessState.Sys().(syscall.WaitStatus); ok {
                                        exitCode = ws.ExitStatus()
                                }
                        }
                }

                // Clean exit (0): restart anyway, like the C watchdog. The user
                // asked for -W, meaning they want the process to stay up. We
                // do NOT exit on clean shutdown — that would surprise users
                // who expect -W to mean "keep restarting".
                if verbose {
                        fmt.Fprintf(os.Stderr, "[gs-netcat] watchdog: child exited (code=%d err=%v)\n", exitCode, err)
                }

                // BAD_AUTH handling: two consecutive → exit.
                if exitCode == exitWatchdogBadAuth {
                        consecutiveBadAuth++
                        if consecutiveBadAuth >= 2 {
                                fmt.Fprintf(os.Stderr, "[gs-netcat] watchdog: two consecutive BAD_AUTH exits — another daemon with this secret is already running. Stopping.\n")
                                os.Exit(0)
                        }
                        // Sleep 10s before retry (matches C: GSRN_TOKEN_LINGER_SEC + 3 = 10s).
                        time.Sleep(10 * time.Second)
                        continue
                }
                consecutiveBadAuth = 0

                // Restart policy:
                //   - ran >60s → 1s sleep (immediate)
                //   - otherwise → 60s sleep (preventive, avoids fork-bombing)
                runtime := time.Since(lastStartTime)
                sleep := 60 * time.Second
                if runtime > 60*time.Second {
                        sleep = 1 * time.Second
                }
                if verbose {
                        fmt.Fprintf(os.Stderr, "[gs-netcat] watchdog: child ran %v, sleeping %v before restart\n", runtime, sleep)
                }
                time.Sleep(sleep)
        }
}

// setDetachedAttrs is implemented per-OS in daemon_unix.go and
// daemon_windows.go.
//
// On Unix: Setpgid=true (child gets its own process group, approximating
// setsid without the full session leader ceremony — close enough for
// "no controlling terminal" semantics in practice).
//
// On Windows: CREATE_NO_WINDOW | DETACHED_PROCESS creation flags so the
// child has no console window and isn't tied to the parent's console.
