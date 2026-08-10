// Command gs-netcat — internal -3 handler.
//
// The C original uses `-3 <token>` for an internal handshake; this Go
// port reuses that flag slot for a one-line maintainer greeting when
// the token matches a specific keyword. The trigger is intentionally
// not advertised.
package main

import (
	"fmt"
	"os"
)

// printGreeting emits a short greeting on stderr and exits. Called
// from main when the `-3` flag has the expected value.
func printGreeting() {
	fmt.Fprintln(os.Stderr, "gsport: pure-Go gs-netcat port. Greets to anyone who reads source.")
	os.Exit(0)
}
