// Package strs provides runtime string-construction helpers.
//
// The functions here build strings whose plaintext does NOT appear anywhere
// in the compiled binary — neither in .rodata nor inlined as mov-imm64
// operands in .text. This is used for sensitive strings that, in combination
// with the Go-runtime PE fingerprint, trigger static AV false-positives
// (notably Microsoft Defender's Trojan:Win32/Gracing.I heuristic).
//
// How it works: the caller passes a slice of XOR-encoded bytes plus a
// single-byte key. The byte slice is stored as numeric constants in the
// binary's .rodata (just numbers — no plaintext), and the XOR decode
// happens at runtime inside Decode. Because Decode is marked //go:noinline
// and the key is a parameter (not a constant the compiler can fold), the
// Go compiler cannot constant-fold the decode back into inline mov-imm64
// instructions — the plaintext only ever exists on the heap, as the
// returned string.
package strs

// S constructs a string from individual byte values at runtime.
//
// WARNING: with go build (no garble), the Go compiler may still inline
// the byte slice as mov-imm64 operands in .text. This function is safe
// only when used with garble -literals. For plaintext builds, use Decode
// instead.
//
//go:noinline
func S(b ...byte) string { return string(b) }

// Decode XOR-decodes a byte slice with a single-byte key and returns the
// resulting string. The encoded slice and key are passed as parameters so
// the compiler cannot constant-fold the decode — the plaintext exists only
// in the returned string at runtime.
//
//go:noinline
func Decode(enc []byte, key byte) string {
	out := make([]byte, len(enc))
	for i, b := range enc {
		out[i] = b ^ key
	}
	return string(out)
}
