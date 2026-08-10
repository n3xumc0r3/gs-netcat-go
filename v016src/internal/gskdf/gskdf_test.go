package gskdf

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// TestDeriveMatchesWireCapture verifies that Derive() reproduces the exact
// GS-Address A5 captured from a real gs-netcat v1.4.42 binary.
//
// The captured gs_secret was "MyTestSecret123" and the captured GS-Address
// bytes (offset 32..47 of the _gs_connect packet) were
// 07 c7 cd fa ad 58 8b 99 9a 7e 1b c9 87 3b c5 b8.
// See /home/z/my-project/research/capture/gsrn_capture.txt and
// /home/z/my-project/research/gs-netcat-analysis.md §12.2.
func TestDeriveMatchesWireCapture(t *testing.T) {
	creds := Derive("MyTestSecret123")

	want := "07c7cdfaad588b999a7e1bc9873bc5b8"
	got := creds.Address.String()
	if got != want {
		t.Fatalf("GS-Address mismatch:\n got %s\nwant %s", got, want)
	}

	// Cross-check the GS-Address by computing SHA256("/kd/addr/2" || secret)
	// manually — this catches regressions in the domain prefix.
	h := sha256.New()
	h.Write([]byte("/kd/addr/2"))
	h.Write([]byte("MyTestSecret123"))
	manualAddr := hex.EncodeToString(h.Sum(nil)[:16])
	if manualAddr != want {
		t.Fatalf("manual addr cross-check failed: %s != %s", manualAddr, want)
	}

	// Username is always "user" (lib/gsocket-ssl.c:31,87,153).
	if creds.SRPUsername != "user" {
		t.Fatalf("SRPUsername = %q, want %q", creds.SRPUsername, "user")
	}

	// Password must be exactly 51 chars:
	//   "Blah." (5) + 33 hex chars + ".blubb-SRPSEC" (13) = 51.
	if len(creds.SRPPassword) != 51 {
		t.Fatalf("SRPPassword length = %d, want 51", len(creds.SRPPassword))
	}
	if !strings.HasPrefix(creds.SRPPassword, "Blah.") {
		t.Fatalf("SRPPassword prefix = %q, want %q", creds.SRPPassword[:5], "Blah.")
	}
	if !strings.HasSuffix(creds.SRPPassword, ".blubb-SRPSEC") {
		t.Fatalf("SRPPassword suffix = %q, want %q",
			creds.SRPPassword[38:], ".blubb-SRPSEC")
	}

	// The 33-char inner hex must equal hex(SHA256("/kd/srp/1" || secret))[:33].
	h2 := sha256.New()
	h2.Write([]byte("/kd/srp/1"))
	h2.Write([]byte("MyTestSecret123"))
	wantInner := hex.EncodeToString(h2.Sum(nil))[:33]
	gotInner := creds.SRPPassword[5 : 5+33]
	if gotInner != wantInner {
		t.Fatalf("SRP inner hex mismatch:\n got %s\nwant %s", gotInner, wantInner)
	}
}

// TestGenSecretFormat checks that GenSecret returns a 21-char base58 string
// matching the format that `gs-netcat -g` prints.
func TestGenSecretFormat(t *testing.T) {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	for i := 0; i < 64; i++ {
		s, err := GenSecret()
		if err != nil {
			t.Fatalf("GenSecret: %v", err)
		}
		if len(s) != 21 {
			t.Fatalf("len(GenSecret()) = %d, want 21 (got %q)", len(s), s)
		}
		for _, r := range s {
			if !strings.ContainsRune(alphabet, r) {
				t.Fatalf("GenSecret() returned non-base58 char %q in %q", r, s)
			}
		}
	}

	// Two consecutive calls should produce different secrets (sanity check
	// that we're actually using crypto/rand).
	a, _ := GenSecret()
	b, _ := GenSecret()
	if a == b {
		t.Fatalf("GenSecret returned identical secrets twice: %q", a)
	}
}

// TestGenSecretRoundTrip checks that the same secret string always
// derives the same address.
func TestDeriveDeterministic(t *testing.T) {
	const secret = "round-trip-test-secret"
	a := Derive(secret)
	b := Derive(secret)
	if a.Address != b.Address {
		t.Fatalf("Derive non-deterministic: %s != %s", a.Address, b.Address)
	}
	if a.SRPPassword != b.SRPPassword {
		t.Fatalf("Derive non-deterministic password: %q != %q",
			a.SRPPassword, b.SRPPassword)
	}
}

// TestDeriveAuthToken checks the deterministic auth-token derivation
// used by the `-a` CLI flag.
func TestDeriveAuthToken(t *testing.T) {
	addr := Derive("secret-x").Address

	// Same inputs → same token.
	t1 := DeriveAuthToken("mytoken", addr)
	t2 := DeriveAuthToken("mytoken", addr)
	if t1 != t2 {
		t.Fatalf("DeriveAuthToken non-deterministic")
	}

	// Different token strings → different tokens.
	t3 := DeriveAuthToken("different", addr)
	if t1 == t3 {
		t.Fatalf("DeriveAuthToken produced same token for different inputs")
	}

	// Manual cross-check against SHA256(token_str || addr)[0:16].
	h := sha256.New()
	h.Write([]byte("mytoken"))
	h.Write(addr[:])
	var want [16]byte
	copy(want[:], h.Sum(nil)[:16])
	if t1 != want {
		t.Fatalf("DeriveAuthToken mismatch:\n got %x\nwant %x", t1, want)
	}
}
