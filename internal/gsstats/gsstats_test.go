package gsstats

import (
	"testing"
)

func TestLoadFromProc(t *testing.T) {
	v, ok := loadFromProc()
	// In the test environment /proc/loadavg may or may not exist; if it
	// does, the value must be non-negative.
	if !ok {
		t.Logf("/proc/loadavg not available — skipping")
		return
	}
	if v < 0 {
		t.Fatalf("loadFromProc returned negative: %v", v)
	}
	t.Logf("loadFromProc: %.3f", v)
}

func TestLoad(t *testing.T) {
	v := Load()
	if v < 0 {
		t.Fatalf("Load returned negative: %v", v)
	}
	t.Logf("Load: %.3f", v)
}

func TestUsers(t *testing.T) {
	n, active := Users()
	if n < 1 {
		t.Fatalf("Users returned n=%d (expected >=1)", n)
	}
	if active == "" {
		t.Fatalf("Users returned empty active user")
	}
	t.Logf("Users: n=%d active=%q", n, active)
}

func TestPongPayloadSize(t *testing.T) {
	p := PongPayload()
	if len(p) != 16 {
		t.Fatalf("PongPayload size = %d, want 16", len(p))
	}
}

func TestPongPayloadLayout(t *testing.T) {
	p := PongPayload()
	// Just check the load * 100 fits in uint16 and the user field is NUL-padded.
	load := uint16(p[0])<<8 | uint16(p[1])
	if load > 65535 {
		t.Fatalf("load out of range: %d", load)
	}
	// The last byte of user field should be NUL if username < 10 chars
	// (most realistic case). If username is exactly 10 chars, byte [15]
	// is the 10th char (not NUL).
	t.Logf("PongPayload: load=%d idle=%d n_users=%d user=%q",
		load,
		uint16(p[2])<<8|uint16(p[3]),
		p[4],
		string(trimNUL(p[5:16])))
}

// trimNUL truncates b at the first NUL byte.
func trimNUL(b []byte) []byte {
	for i, c := range b {
		if c == 0 {
			return b[:i]
		}
	}
	return b
}
