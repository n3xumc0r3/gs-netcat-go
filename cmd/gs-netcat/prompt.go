// Command gs-netcat — interactive secret prompt on stdin.
//
// Mirrors the C user_secret_from_stdin (lib/gsocket-util.c:62-83):
//
//	"Enter Secret (or press Enter to generate): "
//
// Reads a line from stdin. If empty → caller generates a new secret
// (returns ""). If non-empty but <8 chars → re-prompts ("Too short.").
// Otherwise returns the trimmed string.
//
// On Windows the prompt is written to stderr (not stdout) so it
// doesn't corrupt piped stdout output. Same on Unix. Stdin is read
// in line-buffered mode — we don't disable echo (the user typing
// their own secret in their own terminal is the common case; the
// C original doesn't disable echo either).
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// promptSecret asks the user on stderr for a secret, reads a line
// from stdin, and returns it trimmed. Empty string = "user pressed
// Enter, please generate one for me". Returns an error only if stdin
// is unreadable (e.g. closed pipe).
func promptSecret() (string, error) {
	r := bufio.NewReader(os.Stdin)
	for {
		fmt.Fprint(os.Stderr, "Enter Secret (or press Enter to generate): ")
		line, err := r.ReadString('\n')
		if err != nil && line == "" {
			return "", err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			return "", nil
		}
		if len(line) < 8 {
			fmt.Fprintln(os.Stderr, "Too short.")
			continue
		}
		return line, nil
	}
}
