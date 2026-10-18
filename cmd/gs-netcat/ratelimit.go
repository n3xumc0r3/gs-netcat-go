// v0.1.30: Bandwidth rate limiter (--rate-limit).
//
// v0.3.1: Rewritten for accuracy. The v0.1.30 implementation chunked
// writes into 4KB pieces and called take() per chunk, causing excessive
// overhead and inaccurate rate limiting. The new implementation uses
// a simpler approach: for each Write call, compute how many tokens are
// needed, wait for the bucket to have enough, then write the whole thing
// in one shot.
//
// Wire compat: [--] local-only; the remote peer sees no difference.
package main

import (
	"fmt"
	"io"
	"sync"
	"time"
)

// rateLimitedConn wraps an io.ReadWriteCloser with a write-side token
// bucket. Reads pass through.
type rateLimitedConn struct {
	inner  io.ReadWriteCloser
	bucket *tokenBucket
}

// tokenBucket is a time-based token bucket.
// tokens = bytes available to write. refilled at `rate` bytes per second.
type tokenBucket struct {
	mu     sync.Mutex
	tokens int64     // current available bytes
	rate   int64     // bytes per second
	maxBurst int64   // max tokens (cap)
	last   time.Time
}

// newTokenBucket creates a bucket with the given rate (bytes/sec) and
// a burst cap of 2x the rate.
func newTokenBucket(bytesPerSec int64) *tokenBucket {
	if bytesPerSec < 1 {
		bytesPerSec = 1
	}
	return &tokenBucket{
		tokens:   bytesPerSec, // start full (allows initial burst)
		rate:     bytesPerSec,
		maxBurst: bytesPerSec * 2,
		last:     time.Now(),
	}
}

// waitFor blocks until n tokens are available, then deducts them.
// Uses integer math for precision (no float64 rounding errors).
//
// v0.3.1: Instead of sleeping in 100ms increments and re-checking,
// computes the exact wait time and sleeps once. This eliminates the
// over-throttling bug where the old implementation slept too long
// due to repeated lock/unlock cycles.
func (b *tokenBucket) waitFor(n int64) {
	b.mu.Lock()
	// Refill based on elapsed time.
	now := time.Now()
	elapsedNs := now.Sub(b.last).Nanoseconds()
	// tokens_to_add = elapsed_seconds * rate = (elapsedNs / 1e9) * rate
	// Use integer math: tokens_to_add = (elapsedNs * rate) / 1e9
	b.tokens += (elapsedNs * b.rate) / int64(time.Second)
	if b.tokens > b.maxBurst {
		b.tokens = b.maxBurst
	}
	b.last = now

	if b.tokens >= n {
		// Enough tokens — deduct and return.
		b.tokens -= n
		b.mu.Unlock()
		return
	}

	// Not enough — deduct what we have, compute wait for the rest.
	deficit := n - b.tokens
	b.tokens = 0
	b.mu.Unlock()

	// Wait for deficit tokens to refill.
	// wait_ns = deficit * 1e9 / rate
	waitNs := (deficit * int64(time.Second)) / b.rate
	if waitNs > 0 {
		time.Sleep(time.Duration(waitNs))
	}
}

// newRateLimitedConn wraps c with a write-side rate limiter.
func newRateLimitedConn(c io.ReadWriteCloser, bytesPerSec int64) io.ReadWriteCloser {
	if bytesPerSec <= 0 {
		return c
	}
	return &rateLimitedConn{
		inner:  c,
		bucket: newTokenBucket(bytesPerSec),
	}
}

func (r *rateLimitedConn) Read(p []byte) (int, error) {
	return r.inner.Read(p)
}

func (r *rateLimitedConn) Write(p []byte) (int, error) {
	// v0.3.1: Wait for ALL tokens at once, then write the entire buffer.
	// This is more accurate than chunking and reduces per-chunk overhead.
	// For very large writes (>burst), this blocks until enough tokens
	// accumulate, which is the correct behavior.
	r.bucket.waitFor(int64(len(p)))
	return r.inner.Write(p)
}

func (r *rateLimitedConn) Close() error {
	return r.inner.Close()
}

// parseRateLimit parses strings like "100K", "1M", "500K", "10240".
func parseRateLimit(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	if len(s) > 2 && s[len(s)-2:] == "/s" {
		s = s[:len(s)-2]
	}
	if s == "" {
		return 0, nil
	}
	mult := int64(1)
	last := s[len(s)-1]
	switch last {
	case 'K', 'k':
		mult = 1024
		s = s[:len(s)-1]
	case 'M', 'm':
		mult = 1024 * 1024
		s = s[:len(s)-1]
	case 'G', 'g':
		mult = 1024 * 1024 * 1024
		s = s[:len(s)-1]
	}
	var n int64
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return 0, fmt.Errorf("rate-limit: invalid number in %q: %w", s, err)
	}
	return n * mult, nil
}
