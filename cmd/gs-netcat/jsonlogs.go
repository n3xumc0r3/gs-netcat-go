// v0.1.30: JSON structured logging (--json-logs).
//
// Replaces the standard log package's text output with one JSON object
// per line on stderr. Format compatible with Loki/ELK/Splunk ingestion.
//
// Each log line is:
//   {"ts":"2026-10-17T22:30:15.123Z","level":"info","msg":"..."}
//
// Wire compat: [--] local-only.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// jsonLogWriter is a thin io.Writer that wraps each Write call in a
// JSON object and emits to the underlying writer (typically os.Stderr).
type jsonLogWriter struct {
	out io.Writer
}

func (w *jsonLogWriter) Write(p []byte) (int, error) {
	// The log package already adds a newline; strip it before JSON-encoding
	// the message.
	msg := string(p)
	if len(msg) > 0 && msg[len(msg)-1] == '\n' {
		msg = msg[:len(msg)-1]
	}
	obj := map[string]interface{}{
		"ts":    time.Now().UTC().Format(time.RFC3339Nano),
		"level": "info",
		"msg":   msg,
	}
	enc := json.NewEncoder(w.out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(obj); err != nil {
		// Fallback: write raw text if JSON encoding fails.
		fmt.Fprintf(os.Stderr, "[json-logs-encode-error] %v: %s\n", err, msg)
		return len(p), nil
	}
	return len(p), nil
}
