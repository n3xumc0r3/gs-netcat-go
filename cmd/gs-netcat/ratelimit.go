// v0.1.30: Bandwidth rate limiter (--rate-limit).
//
// Wraps a gsconn.Conn (or any io.ReadWriteCloser) with a token-bucket
// limiter on the Write side. Reads pass through unchanged. The bucket
// refills at a constant rate (bytes per second) and can burst up to 2x
// the rate (to amortize small writes and TLS record overhead).
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
	inner    io.ReadWriteCloser
	bucket   *tokenBucket
}

// tokenBucket is a simple time-based token bucket.
// tokens = bytes available to write. refilled at `rate` bytes per second.
type tokenBucket struct {
	mu       sync.Mutex
	tokens   int64       // current available bytes
	rate     int64       // bytes per second
	maxBurst int64       // max tokens (cap)
	last     time.Time
}

// newTokenBucket creates a bucket with the given rate (bytes/sec) and
// a burst cap of 2x the rate (so small writes can be sent immediately
// if the bucket has accumulated).
func newTokenBucket(bytesPerSec int64) *tokenBucket {
	if bytesPerSec < 1 {
		bytesPerSec = 1
	}
	return &tokenBucket{
		tokens:   bytesPerSec, // start full
		rate:     bytesPerSec,
		maxBurst: bytesPerSec * 2,
		last:     time.Now(),
	}
}

// take blocks until n tokens are available, then deducts them.
// n must be > 0.
func (b *tokenBucket) take(n int) {
	for {
		b.mu.Lock()
		// Refill based on elapsed time since last call.
		now := time.Now()
		elapsed := now.Sub(b.last).Seconds()
		b.tokens += int64(elapsed * float64(b.rate))
		if b.tokens > b.maxBurst {
			b.tokens = b.maxBurst
		}
		b.last = now
		if b.tokens >= int64(n) {
			b.tokens -= int64(n)
			b.mu.Unlock()
			return
		}
		// Need to wait. Compute how long until we have enough.
		deficit := int64(n) - b.tokens
		waitDur := time.Duration(float64(deficit) / float64(b.rate) * float64(time.Second))
		b.mu.Unlock()
		// Sleep with a small cap so we don't oversleep on huge writes.
		if waitDur > 100*time.Millisecond {
			waitDur = 100 * time.Millisecond
		}
		time.Sleep(waitDur)
	}
}

// newRateLimitedConn wraps c with a write-side rate limiter.
// bytesPerSec is the maximum write throughput; 0 means unlimited
// (returns c unchanged).
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
	// Throttle in chunks so a huge Write doesn't deplete the bucket
	// all at once (which would block for a very long time).
	written := 0
	for written < len(p) {
		chunk := len(p) - written
		if chunk > 4096 {
			chunk = 4096
		}
		r.bucket.take(chunk)
		n, err := r.inner.Write(p[written : written+chunk])
		written += n
		if err != nil {
			return written, err
		}
	}
	return written, nil
}

func (r *rateLimitedConn) Close() error {
	return r.inner.Close()
}

// parseRateLimit parses strings like "100K", "1M", "500K", "10240".
// Returns bytes per second.
// Suffixes: K=1024, M=1024*1024, G=1024*1024*1024 (binary, not SI).
func parseRateLimit(s string) (int64, error) {
	if s == "" {
		return 0, nil
	}
	// Strip optional "/s" suffix.
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
