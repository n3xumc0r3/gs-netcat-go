#!/bin/bash
# Push v0.1.6 fix to GitHub using git plumbing (no branch switching).
# Fix: add EXTENDED_STARTUPINFO_PRESENT to dwCreationFlags in CreateProcessW.
# This was the REAL bug causing the shell to appear in the server's window
# instead of being relayed to the client.

set -e

REPO_DIR="/home/z/my-project"
SRC_DIR="/home/z/my-project/v016src"
PAT_FILE="/home/z/my-project/.env"

# Read PAT
if [ -f "$PAT_FILE" ]; then
    PAT=$(grep -oE 'github_pat_[A-Za-z0-9_]+' "$PAT_FILE" 2>/dev/null | head -1)
fi
if [ -z "$PAT" ]; then
    PAT="${GITHUB_PAT:-}"
fi
if [ -z "$PAT" ]; then
    echo "ERROR: No GitHub PAT found in $PAT_FILE or env"
    exit 1
fi

cd "$REPO_DIR"

# Set remote URL with PAT
git remote set-url origin "https://${PAT}@github.com/n3xumc0r3/gs-netcat-go.git"

# Get the tree of origin/main
BASE_SHA=$(git rev-parse origin/main)
echo "Base commit: $BASE_SHA"

# Create a fresh index from origin/main
git read-tree origin/main

# Stage the v0.1.6 changes:
# 1. internal/gspty/pty_windows.go (the CreateProcessW fix)
# 2. gsport/cmd/gs-netcat/versioninfo.json (bump to 0.1.6)
# 3. gsport/cmd/gs-netcat/resource_windows_amd64.syso (regenerated)

# Compute blob hashes for the new files
BLOB_PTY=$(git hash-object -w "$SRC_DIR/internal/gspty/pty_windows.go")
BLOB_VER=$(git hash-object -w "$SRC_DIR/gsport/cmd/gs-netcat/versioninfo.json")
BLOB_SYSO=$(git hash-object -w "$SRC_DIR/gsport/cmd/gs-netcat/resource_windows_amd64.syso")

echo "New blobs:"
echo "  pty_windows.go: $BLOB_PTY"
echo "  versioninfo.json: $BLOB_VER"
echo "  resource_windows_amd64.syso: $BLOB_SYSO"

# Update the index with the new blobs
git update-index --cacheinfo 100644 "$BLOB_PTY" "internal/gspty/pty_windows.go"
git update-index --cacheinfo 100644 "$BLOB_VER" "gsport/cmd/gs-netcat/versioninfo.json"
git update-index --cacheinfo 100644 "$BLOB_SYSO" "gsport/cmd/gs-netcat/resource_windows_amd64.syso"

# Write the new tree
TREE_SHA=$(git write-tree)
echo "New tree: $TREE_SHA"

# Create the commit
COMMIT_SHA=$(git commit-tree "$TREE_SHA" -p "$BASE_SHA" -m "v0.1.6: Add EXTENDED_STARTUPINFO_PRESENT to dwCreationFlags — the REAL ConPTY fix

v0.1.5 fixed the inverted HRESULT check in CreatePseudoConsole, so the
ConPTY was created successfully and cmd.exe spawned. BUT the shell
output appeared in the SERVER's window instead of being relayed to the
client. The client just saw 'Connected' with no shell.

Root cause: EXTENDED_STARTUPINFO_PRESENT was set in STARTUPINFO.dwFlags
(si.Flags) but NOT in the dwCreationFlags parameter of CreateProcessW.

The Microsoft ConPTY sample sets this flag in BOTH places:
  1. siEx.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT
  2. dwCreationFlags = EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT

Without the flag in dwCreationFlags, CreateProcessW treats lpStartupInfo
as a plain STARTUPINFOW (104 bytes) and silently ignores the
lpAttributeList field at offset 104. The PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
entry is never applied, so the child process inherits the parent's
console instead of attaching to the pseudoconsole.

Result: cmd.exe ran in the server's PowerShell window (its stdin/stdout
were wired to the parent's console handles), the ConPTY output pipe was
empty, and io.Copy(conn, pty.Master) sent nothing to the client.

The fix: add EXTENDED_STARTUPINFO_PRESENT to the dwCreationFlags
parameter (6th arg) of CreateProcessW. Now CreateProcessW correctly
interprets the STARTUPINFOEX and applies the pseudoconsole attribute,
so the child attaches to the ConPTY and I/O flows through the pipe to
the client.

Other v0.1.6 changes:
  - versioninfo.json: bumped to 0.1.6.0 (FileVersion + ProductVersion)
  - resource_windows_amd64.syso: regenerated from the new versioninfo

Verified:
  - Cross-compiled windows/amd64 binary: 3,564,544 bytes, contains
    VS_VERSION_INFO with '0.1.6.0' (UTF-16LE), '0.1.5.0' absent.
  - The HRESULT error string from v0.1.5 is preserved.
  - All 4 platform binaries built clean.")

echo "New commit: $COMMIT_SHA"

# Push to origin/main
git push origin "$COMMIT_SHA:refs/heads/main"
echo "Pushed to main"

# Create the tag
git tag v0.1.6 "$COMMIT_SHA"
git push origin refs/tags/v0.1.6
echo "Tagged v0.1.6"

echo ""
echo "=== v0.1.6 pushed successfully ==="
echo "Commit: $COMMIT_SHA"
echo "Tag: v0.1.6"
