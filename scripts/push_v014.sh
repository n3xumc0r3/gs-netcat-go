#!/bin/bash
# v0.1.4 push script — runs in a single shell invocation to avoid
# losing git branch state between separate Bash tool calls.
set -e

cd /home/z/my-project

echo "=== Step 1: Verify main has the v0.1.4 files ==="
echo "  main HEAD: $(git rev-parse --short main)"
echo "  main.go v0.1.4 markers: $(git show main:cmd/gs-netcat/main.go | grep -c 'Since v0.1.4')"
echo "  versioninfo FileVersion: $(git show main:gsport/cmd/gs-netcat/versioninfo.json | grep '^    \"FileVersion\":' | tail -1)"
echo "  pty_windows.go *uint16: $(git show main:internal/gspty/pty_windows.go | grep -c 'Reserved.*\\*uint16')"
echo "  pty_windows_test.go in main: $(git cat-file -e main:internal/gspty/pty_windows_test.go 2>&1 && echo yes || echo no)"
echo "  .syso size: $(git cat-file -s main:gsport/cmd/gs-netcat/resource_windows_amd64.syso) bytes"

echo ""
echo "=== Step 2: Delete old v014-push and v014-clean, create fresh v014-push from origin/main ==="
git branch -D v014-push 2>/dev/null || true
git branch -D v014-clean 2>/dev/null || true
git checkout -b v014-push origin/main 2>&1 | tail -3

echo ""
echo "=== Step 3: Verify on v014-push at clean v0.1.3 ==="
echo "  branch: $(git branch --show-current)"
echo "  HEAD: $(git rev-parse --short HEAD)"
echo "  pty_windows.go *uint16 (should be 0): $(grep -c 'Reserved.*\\*uint16' internal/gspty/pty_windows.go)"
echo "  pty_windows_test.go exists (should be no): $(test -f internal/gspty/pty_windows_test.go && echo yes || echo no)"
echo "  main.go v0.1.4 markers (should be 0): $(grep -c 'Since v0.1.4' cmd/gs-netcat/main.go)"
echo "  versioninfo FileVersion (should be 0.1.3.0): $(grep '^    \"FileVersion\":' gsport/cmd/gs-netcat/versioninfo.json | tail -1)"

echo ""
echo "=== Step 4: Extract all 5 v0.1.4 files from main into v014-push working tree ==="
# Use git show to extract file content from main's HEAD
git show main:internal/gspty/pty_windows.go > internal/gspty/pty_windows.go
git show main:internal/gspty/pty_windows_test.go > internal/gspty/pty_windows_test.go
git show main:cmd/gs-netcat/main.go > cmd/gs-netcat/main.go
git show main:gsport/cmd/gs-netcat/versioninfo.json > gsport/cmd/gs-netcat/versioninfo.json
# .syso is binary — use git cat-file
git cat-file -p main:gsport/cmd/gs-netcat/resource_windows_amd64.syso > gsport/cmd/gs-netcat/resource_windows_amd64.syso

echo ""
echo "=== Step 5: Verify all 5 files now have v0.1.4 content ==="
echo "  pty_windows.go *uint16 (should be 1): $(grep -c 'Reserved.*\\*uint16' internal/gspty/pty_windows.go)"
echo "  pty_windows_test.go exists (should be yes): $(test -f internal/gspty/pty_windows_test.go && echo yes || echo no)"
echo "  main.go v0.1.4 markers (should be 1): $(grep -c 'Since v0.1.4' cmd/gs-netcat/main.go)"
echo "  versioninfo FileVersion (should be 0.1.4.0): $(grep '^    \"FileVersion\":' gsport/cmd/gs-netcat/versioninfo.json | tail -1)"
echo "  .syso size: $(stat -c %s gsport/cmd/gs-netcat/resource_windows_amd64.syso) bytes"

echo ""
echo "=== Step 6: git status before add ==="
git status --short

echo ""
echo "=== Step 7: git add + commit ==="
git add internal/gspty/pty_windows.go internal/gspty/pty_windows_test.go cmd/gs-netcat/main.go gsport/cmd/gs-netcat/versioninfo.json gsport/cmd/gs-netcat/resource_windows_amd64.syso

echo "After add:"
git status --short

echo ""
echo "Committing..."
git commit -m "v0.1.4: Fix Windows ConPTY struct layout — resolves \"remote has no PTY\"

The startupInfoEx struct in pty_windows.go used uint16 for the Win32
LPWSTR fields (lpReserved / lpDesktop / lpTitle) and LPBYTE
(lpReserved2), collapsing it to 88 bytes — Windows requires 112 for
STARTUPINFOEXW on x64. As a result:
  - cb was 88 (Windows expects 104/112); CreateProcessW treated the
    struct as malformed.
  - EXTENDED_STARTUPINFO_PRESENT (set in Flags) landed at Go offset 40
    but Windows reads dwFlags from Win32 offset 60 — Windows saw
    dwFlags=0 and never consulted lpAttributeList.
  - lpAttributeList itself was read from Win32 offset 104, which is
    BEYOND the 88-byte struct — random stack/heap garbage was used as
    the attribute list pointer.

Net effect: CreateProcessW started the child shell WITHOUT the ConPTY
attached. stdin/stdout/stderr were wired to nothing, the interactive
session was dead, and the server reported \"remote has no PTY\".

Fix:
  - Rewrote startupInfoEx with the correct Win32 layout: pointers are
    *uint16 / *byte (8 bytes on x64), with explicit [4]byte padding
    to maintain 8-byte alignment. Total size now 112 bytes.
  - PTY struct now stores hProcess, hThread, pid from CreateProcessW's
    PROCESS_INFORMATION output (previously discarded).
  - Wait() now calls WaitForSingleObject(hProcess, INFINITE) and
    reaps both handles — was a no-op returning nil immediately.
  - Close() no longer touches hProcess / hThread (owned by Wait),
    avoiding the MSDN-documented UB where closing a handle that
    another thread is waiting on inside WaitForSingleObject produces
    undefined behaviour.
  - Close() also closes Master (the ConPTY output pipe os.File).
  - PID() returns the actual Windows pid (was always 0).

Other v0.1.4 changes:
  - main.go: the NOPTY STATUS message now includes the Spawn error
    string (truncated to 63 bytes) so the client can print WHY the
    PTY failed — previously the client only saw \"remote has no PTY\"
    with no diagnostic detail.
  - versioninfo.json: bumped to 0.1.4.0 (FileVersion + ProductVersion).
  - resource_windows_amd64.syso: regenerated from the new versioninfo.

Regression test (pty_windows_test.go):
  - TestStartupInfoExLayout and TestProcessInformationLayout use
    unsafe.Offsetof / unsafe.Sizeof to lock every struct field to its
    Win32-mandated offset. Fails loudly if anyone re-introduces the
    bug. Compiles under GOOS=windows." 2>&1 | tail -5

echo ""
echo "=== Step 8: Verify commit has all 5 files ==="
git show --stat HEAD | tail -10

echo ""
echo "=== Step 9: Move v0.1.4 tag to new commit ==="
git tag -d v0.1.4 2>/dev/null || true
git tag -a v0.1.4 -m "v0.1.4: Fix Windows ConPTY struct layout

Root cause: startupInfoEx struct in pty_windows.go had wrong field types
(uint16 instead of *uint16 for LPWSTR fields), collapsing it to 88 bytes
instead of the required 112. EXTENDED_STARTUPINFO_PRESENT flag landed at
the wrong offset and was never seen by CreateProcessW; the attribute
list pointer was read from beyond the struct (garbage). CreateProcessW
then started the child shell WITHOUT the ConPTY attached — no
stdin/stdout/stderr connection, dead session, 'remote has no PTY' error.

Fix: rewrote the struct to match Win32 STARTUPINFOEXW exactly, plus
handle-hygiene fixes (Wait now actually waits + reaps, Close no longer
races with Wait). Regression test added.

Bug reported on Windows-to-Windows v0.1.3 (same laptop, both sides)."

echo ""
echo "=== Step 10: Final state ==="
echo "  branch: $(git branch --show-current)"
echo "  HEAD: $(git rev-parse HEAD)"
echo "  Tag v0.1.4 -> commit: $(git rev-parse v0.1.4^{commit})"
echo "  Commits ahead of origin/main: $(git rev-list --count origin/main..HEAD)"
echo ""
echo "=== Diff vs origin/main (should show 5 files) ==="
git diff --stat origin/main HEAD

echo ""
echo "=== Step 11: Push v014-push to origin/main ==="
export GH_TOKEN='GH_TOKEN_ENV'
export GIT_ASKPASS='/home/z/my-project/scripts/gh-askpass-v014.sh'
export GIT_TERMINAL_PROMPT=0

# Push branch v014-push to origin's main
git push origin v014-push:main 2>&1 | tail -10

echo ""
echo "=== Step 12: Push tag v0.1.4 ==="
git push origin v0.1.4 2>&1 | tail -5

echo ""
echo "=== PUSH COMPLETE ==="
echo "  Commit: $(git rev-parse HEAD)"
echo "  Tag: v0.1.4"
echo "  Remote: https://github.com/n3xumc0r3/gs-netcat-go"
