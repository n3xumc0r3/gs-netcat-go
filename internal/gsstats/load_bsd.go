// BSD/Darwin-specific loadFromSysctl: reads vm.loadavg via syscall.Sysctl.
// Linux has its own stub in load_linux.go.

//go:build darwin || freebsd || netbsd || openbsd

package gsstats

import "syscall"

// v0.1.28 (audit-4 bug #3, MEDIUM): fixed fscale offset on macOS.
//
// The loadavg struct on Darwin (xnu/bsd/sys/resource.h):
//
//   struct loadavg {
//       fixpt_t ldavg[3];      // 3 × uint32 = 12 bytes (offsets 0..11)
//       fixpt_t fscale;        // uint32 at offset 12 on 32-bit, BUT on
//                              // 64-bit Darwin the kernel ABI pads
//                              // differently. The actual kernel
//                              // struct (XNU source) keeps fscale
//                              // immediately after ldavg[3] as a
//                              // uint32 at offset 12 — the previous
//                              // code was correct for 64-bit too.
//                              //
//                              // HOWEVER: the bytes returned by
//                              // syscall.Sysctl("vm.loadavg") on
//                              // darwin/amd64 are NOT a raw struct —
//                              // they're a struct loadavg with
//                              // different padding. Empirical testing
//                              // shows fscale at offset 12 yields 0
//                              // (padding bytes), and the real fscale
//                              // is at offset 16.
//   };
//
// We try offset 12 first (correct for 32-bit and XNU source layout),
// then fall back to offset 16 (correct for 64-bit Darwin in practice).
// If both yield 0 we return false (matches old behaviour).
func loadFromSysctl() (float64, bool) {
	raw, err := syscall.Sysctl("vm.loadavg")
	if err != nil || len(raw) < 20 {
		return 0, false
	}
	b := []byte(raw)
	if len(b) < 16 {
		return 0, false
	}
	ldavg := uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
	// Try offset 12 first (matches struct layout per XNU source).
	fscale := uint32(b[12]) | uint32(b[13])<<8 | uint32(b[14])<<16 | uint32(b[15])<<24
	// v0.1.28: fall back to offset 16 (matches actual 64-bit Darwin
	// ABI — struct has 4 bytes of padding before fscale).
	if fscale == 0 && len(b) >= 20 {
		fscale = uint32(b[16]) | uint32(b[17])<<8 | uint32(b[18])<<16 | uint32(b[19])<<24
	}
	if fscale == 0 {
		return 0, false
	}
	return float64(ldavg) / float64(fscale), true
}
