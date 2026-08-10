// Working-directory lookup for the in-band PWD request/reply feature.
//
// On Linux we read /proc/<pid>/cwd to get the shell's current working
// directory (mirrors GS_getpidwd in lib/gsocket-util.c).
// On other platforms (Windows, macOS, *BSD) /proc doesn't exist, so we
// fall back to the parent process's cwd (os.Getwd()) — slightly less
// accurate (it's the cwd of gs-netcat, not the shell's cwd) but the
// feature is informational and the wire format is the same.

package main

import (
	"fmt"
	"os"
)

// readShellCwd returns the current working directory of the shell
// running inside the PTY. On Linux it reads /proc/<pid>/cwd; on
// other platforms it falls back to os.Getwd().
//
// Returns "" on any error. The caller (event-pump) then falls back
// to os.Getwd() itself, ensuring a non-empty reply if at all possible.
func readShellCwd(pid int) string {
	if pid <= 0 {
		return ""
	}
	wd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	if err != nil {
		return ""
	}
	return wd
}
