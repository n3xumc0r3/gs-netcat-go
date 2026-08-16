//go:build windows

package main

import (
	"os/exec"
	"syscall"
)

// setDetachedAttrs configures an *exec.Cmd to run detached from the
// parent's console on Windows. We use CREATE_NO_WINDOW (no new console
// window flashes) and DETACHED_PROCESS (no inherited console either).
// Combined, this gives us a child with no UI presence — the closest
// Windows equivalent of Unix's setsid()+close(stdio).
//
// Note: Windows doesn't have a fork() analog. Every "daemon" is really
// a separate process spawned by CreateProcess. The child inherits the
// parent's environment but no console, and is reparented to the service
// manager when the parent exits.
func setDetachedAttrs(cmd *exec.Cmd) {
	const CREATE_NO_WINDOW = 0x08000000
	const DETACHED_PROCESS = 0x00000008
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: CREATE_NO_WINDOW | DETACHED_PROCESS,
	}
}
