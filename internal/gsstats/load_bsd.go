// BSD/Darwin-specific loadFromSysctl: reads vm.loadavg via syscall.Sysctl.
// Linux has its own stub in load_linux.go.

//go:build darwin || freebsd || netbsd || openbsd

package gsstats

import "syscall"

func loadFromSysctl() (float64, bool) {
        raw, err := syscall.Sysctl("vm.loadavg")
        if err != nil || len(raw) < 16 {
                return 0, false
        }
        b := []byte(raw)
        if len(b) < 16 {
                return 0, false
        }
        ldavg := uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
        fscale := uint32(b[12]) | uint32(b[13])<<8 | uint32(b[14])<<16 | uint32(b[15])<<24
        if fscale == 0 {
                return 0, false
        }
        return float64(ldavg) / float64(fscale), true
}
