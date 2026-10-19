// Non-Windows stdin reader — returns nil, meaning io.Copy(conn, os.Stdin)
// is used directly (Unix terminals generate ANSI sequences natively in raw mode).

//go:build !windows

package main

import "io"

func getStdinReader() io.Reader {
	return nil // use os.Stdin directly
}
