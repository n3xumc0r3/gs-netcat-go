//go:build !windows

package main

import (
	"syscall"

	"os/exec"
)

// setDetachedAttrs configures an *exec.Cmd to run detached from the
// controlling terminal on Unix-like systems. Go's os/exec doesn't
// expose setsid() directly; we use Setpgid=true (child becomes its
// own process-group leader, which is close enough for daemon semantics:
// the child is no longer in the parent's process group, so signals
// sent to the parent's group don't propagate to the child, and the
// child has no controlling tty once the parent exits).
//
// For a true setsid we'd need to use syscall.Syscall(SYS_SETSID, ...)
// inside the child — which Go doesn't support pre-exec. Setpgid is
// the standard workaround used by, e.g., daemonize libraries.
func setDetachedAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
}
