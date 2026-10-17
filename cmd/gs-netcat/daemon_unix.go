//go:build !windows

package main

import (
	"syscall"

	"os/exec"
)

// setDetachedAttrs configures an *exec.Cmd to run detached from the
// controlling terminal on Unix-like systems.
//
// v0.1.28 (audit-4 bug #2, MEDIUM): use Setsid=true (real setsid)
// instead of just Setpgid=true. The previous comment claimed Go
// doesn't expose setsid — false, syscall.SysProcAttr.Setsid exists
// on Linux and calls SYS_SETSID via the child's pre-exec hook.
// Without Setsid the detached daemon retains the controlling terminal
// and dies on SIGHUP when the parent's session ends. Setpgid alone
// only detaches from the parent's process group, not the session.
//
// Setsid also implies Setpgid (the new session leader is a new
// process group leader by definition), so we don't need to set both.
func setDetachedAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}
}
