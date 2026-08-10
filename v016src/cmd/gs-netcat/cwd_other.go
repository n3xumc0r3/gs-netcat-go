// Fallback working-directory lookup for platforms without /proc.
// Returns "" so the caller falls back to os.Getwd().

//go:build !linux

package main

func readShellCwd(pid int) string {
	return ""
}
