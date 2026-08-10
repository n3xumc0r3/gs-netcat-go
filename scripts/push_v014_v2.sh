#!/bin/bash
# v0.1.4 push — uses git plumbing (commit-tree) to create a clean commit
# on top of origin/main WITHOUT switching branches. Avoids the persistent
# shell session issue where git checkout state is lost between Bash calls.
set -e

cd /home/z/my-project

GH_TOKEN='GH_TOKEN_ENV'
export GH_TOKEN GIT_ASKPASS='/home/z/my-project/scripts/gh-askpass-v014.sh' GIT_TERMINAL_PROMPT=0

ORIGIN_MAIN=$(git rev-parse origin/main)
echo "=== origin/main: $ORIGIN_MAIN ==="

# Step 1: Create a temporary index based on origin/main's tree
echo ""
echo "=== Step 1: Build a fresh index from origin/main ==="
TMPINDEX=$(mktemp)
export GIT_INDEX_FILE="$TMPINDEX"
git read-tree "$ORIGIN_MAIN"

# Step 2: Stage the 5 v0.1.4 files into this index.
# Source the file contents from commit a0a51f4a (the amended commit
# that has all 5 files at v0.1.4).
V014_SRC=a0a51f4a  # amended commit with all 5 files

echo ""
echo "=== Step 2: Stage 5 v0.1.4 files from $V014_SRC ==="
git update-index --add --cacheinfo 100644,$(git rev-parse $V014_SRC:internal/gspty/pty_windows.go),internal/gspty/pty_windows.go
git update-index --add --cacheinfo 100644,$(git rev-parse $V014_SRC:internal/gspty/pty_windows_test.go),internal/gspty/pty_windows_test.go
git update-index --add --cacheinfo 100644,$(git rev-parse $V014_SRC:cmd/gs-netcat/main.go),cmd/gs-netcat/main.go
git update-index --add --cacheinfo 100644,$(git rev-parse $V014_SRC:gsport/cmd/gs-netcat/versioninfo.json),gsport/cmd/gs-netcat/versioninfo.json
# .syso is binary — mode 100755 (executable bit set in original)
git update-index --add --cacheinfo 100755,$(git rev-parse $V014_SRC:gsport/cmd/gs-netcat/resource_windows_amd64.syso),gsport/cmd/gs-netcat/resource_windows_amd64.syso

echo "  pty_windows.go blob: $(git rev-parse $V014_SRC:internal/gspty/pty_windows.go)"
echo "  pty_windows_test.go blob: $(git rev-parse $V014_SRC:internal/gspty/pty_windows_test.go)"
echo "  main.go blob: $(git rev-parse $V014_SRC:cmd/gs-netcat/main.go)"
echo "  versioninfo.json blob: $(git rev-parse $V014_SRC:gsport/cmd/gs-netcat/versioninfo.json)"
echo "  .syso blob: $(git rev-parse $V014_SRC:gsport/cmd/gs-netcat/resource_windows_amd64.syso)"

# Step 3: Write the new tree
echo ""
echo "=== Step 3: Write new tree ==="
NEWTREE=$(git write-tree)
echo "  New tree: $NEWTREE"

# Verify the tree has all 5 files
echo "  Files in new tree:"
git ls-tree -r $NEWTREE | grep -E "pty_windows|cmd/gs-netcat/main.go|versioninfo.json|resource_windows_amd64.syso" | head -10

# Step 4: Diff the new tree against origin/main's tree
echo ""
echo "=== Step 4: Diff new tree vs origin/main tree ==="
git diff-tree --stat $ORIGIN_MAIN $NEWTREE

# Step 5: Create the commit
echo ""
echo "=== Step 5: Create commit on top of origin/main ==="
COMMIT_MSG='v0.1.4: Fix Windows ConPTY struct layout — resolves "remote has no PTY"

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
session was dead, and the server reported "remote has no PTY".

Fix:
  - Rewrote startupInfoEx with the correct Win32 layout: pointers are
    *uint16 / *byte (8 bytes on x64), with explicit [4]byte padding
    to maintain 8-byte alignment. Total size now 112 bytes.
  - PTY struct now stores hProcess, hThread, pid from CreateProcessW'"'"'s
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
    PTY failed — previously the client only saw "remote has no PTY"
    with no diagnostic detail.
  - versioninfo.json: bumped to 0.1.4.0 (FileVersion + ProductVersion).
  - resource_windows_amd64.syso: regenerated from the new versioninfo.

Regression test (pty_windows_test.go):
  - TestStartupInfoExLayout and TestProcessInformationLayout use
    unsafe.Offsetof / unsafe.Sizeof to lock every struct field to its
    Win32-mandated offset. Fails loudly if anyone re-introduces the
    bug. Compiles under GOOS=windows.'

NEWCOMMIT=$(echo "$COMMIT_MSG" | git commit-tree $NEWTREE -p $ORIGIN_MAIN)
echo "  New commit: $NEWCOMMIT"
git show --stat $NEWCOMMIT | head -20

# Step 6: Update v014-push ref to point to this commit
echo ""
echo "=== Step 6: Update v014-push branch ref ==="
git update-ref refs/heads/v014-push $NEWCOMMIT $ORIGIN_MAIN
echo "  v014-push: $(git rev-parse v014-push)"

# Step 7: Update tag v0.1.4
echo ""
echo "=== Step 7: Create/update tag v0.1.4 ==="
git tag -d v0.1.4 2>/dev/null || true
TAG_MSG='v0.1.4: Fix Windows ConPTY struct layout

Root cause: startupInfoEx struct in pty_windows.go had wrong field types
(uint16 instead of *uint16 for LPWSTR fields), collapsing it to 88 bytes
instead of the required 112. EXTENDED_STARTUPINFO_PRESENT flag landed at
the wrong offset and was never seen by CreateProcessW; the attribute
list pointer was read from beyond the struct (garbage). CreateProcessW
then started the child shell WITHOUT the ConPTY attached — no
stdin/stdout/stderr connection, dead session, "remote has no PTY" error.

Fix: rewrote the struct to match Win32 STARTUPINFOEXW exactly, plus
handle-hygiene fixes (Wait now actually waits + reaps, Close no longer
races with Wait). Regression test added.

Bug reported on Windows-to-Windows v0.1.3 (same laptop, both sides).'

git tag -a v0.1.4 -m "$TAG_MSG" $NEWCOMMIT
echo "  Tag v0.1.4 -> commit: $(git rev-parse v0.1.4^{commit})"

# Step 8: Verify the commit is exactly 1 ahead of origin/main
echo ""
echo "=== Step 8: Verify commit history ==="
echo "  Commits ahead of origin/main: $(git rev-list --count origin/main..v014-push)"
git log --oneline origin/main..v014-push

# Step 9: Push v014-push to origin/main
echo ""
echo "=== Step 9: Push v014-push -> origin/main ==="
git push origin v014-push:main 2>&1 | tail -10

# Step 10: Push tag v0.1.4
echo ""
echo "=== Step 10: Push tag v0.1.4 ==="
git push origin v0.1.4 2>&1 | tail -5

# Cleanup
unset GIT_INDEX_FILE
rm -f "$TMPINDEX"

echo ""
echo "=== PUSH COMPLETE ==="
echo "  Commit: $NEWCOMMIT"
echo "  Tag: v0.1.4"
echo "  Remote: https://github.com/n3xumc0r3/gs-netcat-go"
echo "  Release URL: https://github.com/n3xumc0r3/gs-netcat-go/releases/tag/v0.1.4"
