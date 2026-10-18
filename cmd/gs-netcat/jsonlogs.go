// v0.2.0: --json-logs structured logging helper.
//
// Provides a `logf()` function that replaces `fmt.Fprintf(os.Stderr, "[gs-netcat] ...")`.
// When --json-logs is active, logf emits a JSON object per line:
//
//   {"ts":"2026-10-18T07:00:00.123Z","level":"info","msg":"..."}
//
// When --json-logs is NOT active, logf emits the same plain-text format
// as before (backwards compatible).
//
// Migration strategy: gradually replace `fmt.Fprintf(os.Stderr, "[gs-netcat] ...")`
// calls with `logf(...)`. The most common ones are converted; the rest
// remain as plain stderr writes (which --json-logs leaves untouched).
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// jsonLogsEnabled is set by main.go when --json-logs is parsed.
var jsonLogsEnabled bool

// jsonMu serializes JSON log writes so they don't interleave on stderr.
var jsonMu sync.Mutex

// logf prints a [gs-netcat]-prefixed log line. If --json-logs is enabled,
// emits a JSON object instead. Format and args are fmt.Printf-style.
func logf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if jsonLogsEnabled {
		jsonMu.Lock()
		defer jsonMu.Unlock()
		obj := map[string]interface{}{
			"ts":    time.Now().UTC().Format(time.RFC3339Nano),
			"level": "info",
			"msg":   msg,
			"src":   "gs-netcat",
		}
		enc := json.NewEncoder(os.Stderr)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(obj)
		return
	}
	fmt.Fprintf(os.Stderr, "[gs-netcat] %s\n", msg)
}

// logErrf is like logf but uses level="error".
func logErrf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if jsonLogsEnabled {
		jsonMu.Lock()
		defer jsonMu.Unlock()
		obj := map[string]interface{}{
			"ts":    time.Now().UTC().Format(time.RFC3339Nano),
			"level": "error",
			"msg":   msg,
			"src":   "gs-netcat",
		}
		enc := json.NewEncoder(os.Stderr)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(obj)
		return
	}
	fmt.Fprintf(os.Stderr, "[gs-netcat] ERROR: %s\n", msg)
}
