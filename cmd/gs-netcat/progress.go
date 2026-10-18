// v0.1.30: Transfer progress bar (--progress).
//
// During raw cat-mode transfers, periodically prints a progress line to
// stderr showing bytes transferred, rate, and elapsed time. Useful for
// large file transfers to see what's happening.
//
// Output format (one line per ~250ms, overwritten via \r):
//   [====>          ] 2.3 MB / 10.0 MB  256 KB/s  30s elapsed  ETA 9s
//
// When --progress is set and -i is NOT set, the progress goroutine runs
// alongside the io.Copy loops, polling the atomic counters.
//
// Wire compat: [--] local-only; the remote peer sees no difference.
package main

import (
	"fmt"
	"os"
	"sync/atomic"
	"time"
)

// startProgressBar launches a goroutine that prints progress to stderr
// every 250ms until done is closed. totalWritten/totalRead are read
// atomically. totalSize is the expected total (0 = unknown, show only
// what's transferred).
func startProgressBar(totalWritten, totalRead *atomic.Int64, totalSize int64) (stop func()) {
	ticker := time.NewTicker(250 * time.Millisecond)
	done := make(chan struct{})
	go func() {
		startTime := time.Now()
		lastWritten := int64(0)
		lastTime := startTime
		for {
			select {
			case <-done:
				ticker.Stop()
				// Final print.
				cur := totalWritten.Load() + totalRead.Load()
				elapsed := time.Since(startTime)
				rate := float64(cur) / elapsed.Seconds()
				fmt.Fprintf(os.Stderr, "\r[done] %s in %s (%s/s)            \n",
					humanBytes(cur), elapsed.Round(time.Second), humanBytes(int64(rate)))
				return
			case t := <-ticker.C:
				cur := totalWritten.Load() + totalRead.Load()
				elapsed := t.Sub(startTime)
				if elapsed < 250*time.Millisecond {
					continue
				}
				rate := float64(cur-lastWritten) / t.Sub(lastTime).Seconds()
				lastWritten = cur
				lastTime = t

				if totalSize > 0 {
					pct := float64(cur) / float64(totalSize) * 100
					if pct > 100 {
						pct = 100
					}
					bar := progressBar(int(pct), 20)
					eta := ""
					if rate > 0 {
						remain := int64(float64(totalSize-cur) / rate)
						eta = "  ETA " + (time.Duration(remain) * time.Second).Round(time.Second).String()
					}
					fmt.Fprintf(os.Stderr, "\r[%s] %s / %s  %s/s  %s%s   ",
						bar, humanBytes(cur), humanBytes(totalSize),
						humanBytes(int64(rate)),
						elapsed.Round(time.Second), eta)
				} else {
					fmt.Fprintf(os.Stderr, "\r%s  %s/s  %s   ",
						humanBytes(cur), humanBytes(int64(rate)),
						elapsed.Round(time.Second))
				}
			}
		}
	}()
	return func() { close(done) }
}

func progressBar(pct int, width int) string {
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	filled := pct * width / 100
	out := ""
	for i := 0; i < width; i++ {
		if i < filled {
			out += "="
		} else if i == filled {
			out += ">"
		} else {
			out += " "
		}
	}
	return out
}

func humanBytes(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	const unit = 1024
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	suffix := "KMGTPE"[exp : exp+1]
	return fmt.Sprintf("%.1f %sB", float64(n)/float64(div), suffix)
}
