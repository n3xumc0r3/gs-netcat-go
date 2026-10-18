// v0.3.0: Concurrent multi-peer server (true parallelism).
//
// v0.3.1: Fixed max-peers race condition. The v0.3.0 implementation
// used a counter+mutex to track total peers, which had a TOCTOU race:
// multiple goroutines could check `total < maxTotal` concurrently and
// all pass, then all increment, exceeding the limit.
//
// v0.3.1 fix: use a semaphore (buffered channel of size maxTotal).
// Each goroutine acquires from the semaphore BEFORE dialing. If the
// semaphore is empty, the goroutine blocks until a slot frees up. This
// is race-free because the channel send is atomic.
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
// v0.3.1: maxTotal is enforced via a semaphore (buffered channel).
// Each goroutine must acquire a token from the semaphore before
// handling a peer. When all tokens are consumed, no new peers are
// accepted. This is race-free.
func runConcurrentMultiPeerServer(firstConn *gsconn.Conn, secret, relayHost string, relayPort int, opts *gsconn.Options, verbose bool, execCmd string, maxConcurrent, maxTotal int) error {
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	if verbose {
		logf("concurrent multi-peer: %d max concurrent, %d max total", maxConcurrent, maxTotal)
	}

	// v0.3.1: Semaphore for maxTotal enforcement. If maxTotal > 0,
	// create a buffered channel of that size. Each peer handler must
	// acquire a token before proceeding. This is race-free because
	// channel send/receive is atomic.
	//
	// If maxTotal == 0 (unlimited), use nil channel — send to nil
	// channel blocks forever, so we skip the send entirely (see below).
	var semaphore chan struct{}
	if maxTotal > 0 {
		semaphore = make(chan struct{}, maxTotal)
		// Pre-fill the semaphore with maxTotal tokens.
		for i := 0; i < maxTotal; i++ {
			semaphore <- struct{}{}
		}
	}
	// acquireSlot tries to get a token from the semaphore.
	// Returns false if maxTotal has been reached (or semaphore is nil
	// which means unlimited — always returns true).
	acquireSlot := func() bool {
		if semaphore == nil {
			return true // unlimited
		}
		select {
		case <-semaphore:
			return true
		default:
			return false
		}
	}

	var wg sync.WaitGroup
	done := make(chan struct{})

	// Handle the first connection inline.
	wg.Add(1)
	go func() {
		defer wg.Done()
		// v0.3.1: The first conn was already established (doesn't
		// consume a semaphore token — it was dialed before we entered
		// this function). Consume one token to account for it.
		if semaphore != nil {
			<-semaphore
		}
		handleConcurrentPeer(firstConn, verbose, execCmd)
		// Check if semaphore is exhausted (all peers served).
		if semaphore != nil && len(semaphore) == 0 {
			select {
			case done <- struct{}{}:
			default:
			}
		}
	}()

	// Spawn maxConcurrent-1 dialing goroutines.
	for i := 1; i < maxConcurrent; i++ {
		wg.Add(1)
		go func(slot int) {
			defer wg.Done()
			for {
				// v0.3.1: Check semaphore BEFORE dialing.
				if !acquireSlot() {
					// maxTotal reached — exit this goroutine.
					return
				}
				// Dial the relay in listen mode.
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
				// Check if semaphore is exhausted.
				if semaphore != nil && len(semaphore) == 0 {
					select {
					case done <- struct{}{}:
					default:
					}
					return
				}
			}
		}(i)
	}

	// Wait for done signal (maxTotal reached) or forever.
	select {
	case <-done:
		if verbose {
			logf("concurrent multi-peer: maxTotal %d reached, waiting for active sessions to finish", maxTotal)
		}
		wg.Wait()
		return nil
	case <-time.After(time.Hour * 24 * 365):
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
