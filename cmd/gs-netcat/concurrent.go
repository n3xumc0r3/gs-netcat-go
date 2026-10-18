// v0.3.0: Concurrent multi-peer server (true parallelism).
//
// The v0.1.x multi-peer implementation was SEQUENTIAL: after a peer
// disconnected, the server re-registered with the relay and waited for
// the next peer. This meant a new peer couldn't connect while a session
// was active.
//
// v0.3.0 adds TRUE concurrent multi-peer: the server keeps the GS
// listen socket open and accepts multiple incoming peers simultaneously.
// Each peer gets its own gsconn.Conn.
//
// Wire compat: [G<->C] — works with any peer (Go or C). The relay
// protocol is unchanged; we just keep the listen socket open longer
// and accept multiple _gs_start packets.
//
// Usage:
//   ./gs-netcat -l -i -s S --concurrent-peers 10
//
// Limitations:
//   - v0.3.0 implementation: each peer gets its own gsconn.Dial call
//     (the listen socket is closed after each peer connects, then we
//     re-register). This is because the production GSRN relay doesn't
//     support multiple _gs_start packets on a single listen socket —
//     it tears down the listener after the first peer connects.
//   - For TRUE concurrency (multiple peers at the same time), we'd
//     need to spawn N parallel gsconn.Dial calls. Each one blocks
//     until a peer connects. The first peer to connect takes its conn,
//     the rest continue waiting. This is what this file implements.
//
// The C original supports TRUE concurrency via its event loop
// (GS_select + accept on the listen fd). The Go port approximates it
// with a pool of dialing goroutines.
package main

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/gsport/gs-netcat/internal/gsconn"
)

// runConcurrentMultiPeerServer runs a concurrent multi-peer server.
// It maintains a pool of N goroutines, each dialing the relay in
// ModeListen. When a peer connects to one of them, that goroutine
// runs the interactive server flow for the established conn, then
// re-dials.
//
// `maxConcurrent` is the maximum number of simultaneously active
// sessions. `maxTotal` (if >0) limits the total number of peers
// before exit (combines with --max-peers).
//
// The first connection (already established by main()) is passed in
// as `firstConn`. We handle it inline so we don't waste the
// completed TLS handshake.
func runConcurrentMultiPeerServer(firstConn *gsconn.Conn, secret, relayHost string, relayPort int, opts *gsconn.Options, verbose bool, execCmd string, maxConcurrent, maxTotal int) error {
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	if verbose {
		logf("concurrent multi-peer: %d max concurrent, %d max total", maxConcurrent, maxTotal)
	}

	var wg sync.WaitGroup
	var totalMu sync.Mutex
	total := 0
	done := make(chan struct{})

	// Handle the first connection inline.
	wg.Add(1)
	go func() {
		defer wg.Done()
		handleConcurrentPeer(firstConn, verbose, execCmd)
		totalMu.Lock()
		total++
		currentTotal := total
		totalMu.Unlock()
		if maxTotal > 0 && currentTotal >= maxTotal {
			select {
			case done <- struct{}{}:
			default:
			}
		}
	}()

	// Spawn maxConcurrent-1 dialing goroutines (the first slot is taken
	// by firstConn).
	for i := 1; i < maxConcurrent; i++ {
		wg.Add(1)
		go func(slot int) {
			defer wg.Done()
			for {
				// Check if we've hit maxTotal.
				totalMu.Lock()
				if maxTotal > 0 && total >= maxTotal {
					totalMu.Unlock()
					return
				}
				totalMu.Unlock()

				// Dial the relay in listen mode. This blocks until a peer connects.
				copts := *opts
				conn, err := gsconn.Dial(secret, gsconn.ModeListen, &copts)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[gs-netcat] concurrent multi-peer (slot %d): listen failed: %v (retry in 1s)\n", slot, err)
					time.Sleep(time.Second)
					continue
				}
				if verbose {
					logf("concurrent multi-peer (slot %d): peer connected (role=%s)", slot, roleStr(conn.Role()))
				}
				handleConcurrentPeer(conn, verbose, execCmd)
				totalMu.Lock()
				total++
				currentTotal := total
				totalMu.Unlock()
				if maxTotal > 0 && currentTotal >= maxTotal {
					select {
					case done <- struct{}{}:
					default:
					}
					return
				}
			}
		}(i)
	}

	// Wait for either all goroutines to exit (maxTotal reached) or
	// for the done signal.
	select {
	case <-done:
		if verbose {
			logf("concurrent multi-peer: maxTotal %d reached, waiting for active sessions to finish", maxTotal)
		}
		// Wait for all active sessions to finish.
		// We can't easily cancel the dialing goroutines (they're blocked
		// in gsconn.Dial), so we just wait for them to finish naturally.
		// In practice, the user will Ctrl-C if they want to exit early.
		wg.Wait()
		return nil
	case <-time.After(time.Hour * 24 * 365):
		// Effectively never — but Go's select requires a default case.
		return nil
	}
}

// handleConcurrentPeer runs the interactive server flow for a single
// peer connection. Blocks until the peer disconnects or the shell exits.
func handleConcurrentPeer(conn *gsconn.Conn, verbose bool, execCmd string) {
	defer conn.Close()
	remoteClosed := make(chan struct{})
	ctx := &eventCtx{}
	go eventPump(conn, ctx, verbose)
	_ = runInteractiveServer(conn, ctx, verbose, remoteClosed, execCmd)
	if verbose {
		logf("concurrent multi-peer: peer session ended")
	}
}
