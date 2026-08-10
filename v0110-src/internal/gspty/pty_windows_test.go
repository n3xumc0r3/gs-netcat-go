//go:build windows

package gspty

import (
	"testing"
	"unsafe"
)

// TestStartupInfoExLayout locks the startupInfoEx struct to the
// exact byte layout Win32 STARTUPINFOEXW expects on amd64.
//
// This is a regression test for the v0.1.3 bug where the struct used
// uint16 for the LPWSTR / LPBYTE fields, collapsing it to 88 bytes
// (Windows wants 112). With that layout:
//   - cb was 88 (Windows expected 104 or 112)
//   - EXTENDED_STARTUPINFO_PRESENT (in DwFlags) landed at offset 40,
//     but Windows reads dwFlags from offset 60 — so Windows saw 0
//     and never even looked at lpAttributeList.
//   - lpAttributeList itself was at offset 80, but Windows reads it
//     from offset 104 — beyond the struct (garbage pointer).
//
// The result was that CreateProcessW started the child shell WITHOUT
// the ConPTY attached, so the shell had no stdin/stdout/stderr and
// the interactive session appeared dead.
//
// If this test ever fails, DO NOT ship the binary — the Windows
// interactive mode will be broken.
func TestStartupInfoExLayout(t *testing.T) {
	t.Run("size is 112 bytes on amd64", func(t *testing.T) {
		if got, want := unsafe.Sizeof(startupInfoEx{}), uintptr(112); got != want {
			t.Fatalf("startupInfoEx size = %d, want %d (sizeof(STARTUPINFOEXW) on x64)", got, want)
		}
	})

	t.Run("cb at offset 0", func(t *testing.T) {
		if got, want := unsafe.Offsetof(startupInfoEx{}.Cb), uintptr(0); got != want {
			t.Errorf("Cb offset = %d, want %d", got, want)
		}
	})

	t.Run("lpReserved at offset 8", func(t *testing.T) {
		if got, want := unsafe.Offsetof(startupInfoEx{}.Reserved), uintptr(8); got != want {
			t.Errorf("Reserved (lpReserved) offset = %d, want %d", got, want)
		}
	})

	t.Run("lpDesktop at offset 16", func(t *testing.T) {
		if got, want := unsafe.Offsetof(startupInfoEx{}.Desktop), uintptr(16); got != want {
			t.Errorf("Desktop (lpDesktop) offset = %d, want %d", got, want)
		}
	})

	t.Run("lpTitle at offset 24", func(t *testing.T) {
		if got, want := unsafe.Offsetof(startupInfoEx{}.Title), uintptr(24); got != want {
			t.Errorf("Title (lpTitle) offset = %d, want %d", got, want)
		}
	})

	t.Run("dwFlags at offset 60", func(t *testing.T) {
		if got, want := unsafe.Offsetof(startupInfoEx{}.Flags), uintptr(60); got != want {
			t.Errorf("Flags (dwFlags) offset = %d, want %d — EXTENDED_STARTUPINFO_PRESENT must land here or Windows won't see it", got, want)
		}
	})

	t.Run("lpReserved2 at offset 72", func(t *testing.T) {
		if got, want := unsafe.Offsetof(startupInfoEx{}.Reserved2), uintptr(72); got != want {
			t.Errorf("Reserved2 (lpReserved2) offset = %d, want %d", got, want)
		}
	})

	t.Run("hStdInput at offset 80", func(t *testing.T) {
		if got, want := unsafe.Offsetof(startupInfoEx{}.StdInput), uintptr(80); got != want {
			t.Errorf("StdInput (hStdInput) offset = %d, want %d", got, want)
		}
	})

	t.Run("hStdOutput at offset 88", func(t *testing.T) {
		if got, want := unsafe.Offsetof(startupInfoEx{}.StdOutput), uintptr(88); got != want {
			t.Errorf("StdOutput (hStdOutput) offset = %d, want %d", got, want)
		}
	})

	t.Run("hStdError at offset 96", func(t *testing.T) {
		if got, want := unsafe.Offsetof(startupInfoEx{}.StdError), uintptr(96); got != want {
			t.Errorf("StdError (hStdError) offset = %d, want %d", got, want)
		}
	})

	t.Run("lpAttributeList at offset 104", func(t *testing.T) {
		if got, want := unsafe.Offsetof(startupInfoEx{}.AttributeList), uintptr(104); got != want {
			t.Errorf("AttributeList (lpAttributeList) offset = %d, want %d — must be the LAST field of STARTUPINFOEXW", got, want)
		}
	})
}

// TestProcessInformationLayout locks processInformation to Win32
// PROCESS_INFORMATION. This struct was already correct in v0.1.3 but
// we keep the test to prevent future regressions.
func TestProcessInformationLayout(t *testing.T) {
	if got, want := unsafe.Sizeof(processInformation{}), uintptr(24); got != want {
		t.Fatalf("processInformation size = %d, want %d (sizeof(PROCESS_INFORMATION) on x64)", got, want)
	}
	if got, want := unsafe.Offsetof(processInformation{}.Process), uintptr(0); got != want {
		t.Errorf("Process offset = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(processInformation{}.Thread), uintptr(8); got != want {
		t.Errorf("Thread offset = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(processInformation{}.ProcessId), uintptr(16); got != want {
		t.Errorf("ProcessId offset = %d, want %d", got, want)
	}
	if got, want := unsafe.Offsetof(processInformation{}.ThreadId), uintptr(20); got != want {
		t.Errorf("ThreadId offset = %d, want %d", got, want)
	}
}
