#!/usr/bin/env python3
"""Push v0.1.5 to GitHub: commit via plumbing, tag, create release, upload 5 assets."""
import sys
import os
import json
import subprocess
import urllib.request
import urllib.error
import time
import mimetypes

PAT = 'GH_TOKEN_ENV'
REPO = 'n3xumc0r3/gs-netcat-go'
TAG = 'v0.1.5'
API = f'https://api.github.com/repos/{REPO}'
ASSETS_DIR = '/home/z/my-project/download/release-v0.1.5'
REPO_DIR = '/home/z/my-project'

# Files to update in v0.1.5
FILES = [
    # (local_path, git_path, mode)
    ('gsport/internal/gspty/pty_windows.go', 'internal/gspty/pty_windows.go', '100644'),
    ('gsport/cmd/gs-netcat/versioninfo.json', 'gsport/cmd/gs-netcat/versioninfo.json', '100644'),
    ('gsport/cmd/gs-netcat/resource_windows_amd64.syso', 'gsport/cmd/gs-netcat/resource_windows_amd64.syso', '100755'),
]

COMMIT_MSG = '''v0.1.5: Fix inverted HRESULT check in CreatePseudoConsole — the real PTY bug

v0.1.4 fixed the struct layout but the interactive mode STILL failed with
"remote has no PTY — CreatePseudoC...". User testing on Windows-to-Windows
v0.1.4 (same laptop) revealed the actual Spawn error via the new diagnostic
message added in v0.1.4:

  gspty: gspty: PTY not supported on this platform: CreatePseudoConsole

Root cause: CreatePseudoConsole returns an HRESULT (not a BOOL):
  - S_OK (0)            = success
  - E_INVALIDARG (0x80070057) etc. = failure (non-zero)

The v0.1.4 code checked `if r == 0` — treating S_OK (success) as FAILURE.
Every CreatePseudoConsole call actually SUCCEEDED, but the code immediately
closed all the handles and returned ErrNoPTY. The PTY was never usable.

Compare with ResizePseudoConsole in the same file, which correctly checks
`if r != 0` for failure — that one was right all along.

The fix: invert the check from `if r == 0` to `if r != 0`. Also include
the HRESULT hex value in the error message (instead of the meaningless
syscall errno) so any future ConPTY failure can be diagnosed precisely.

Other v0.1.5 changes:
  - versioninfo.json: bumped to 0.1.5.0 (FileVersion + ProductVersion).
    Also fixed FileOS from "040004L" to "040004" — the "L" suffix caused
    goversioninfo to emit a parse warning (non-fatal but the field was
    silently dropped from the VS_VERSIONINFO blob).
  - resource_windows_amd64.syso: regenerated from the new versioninfo.

The BAD_AUTH error the user also saw ("multi-peer: listen failed: gsrn:
status FATAL BAD_AUTH") is a SECONDARY symptom — after the PTY failure
caused the first connection to close, the server tried to re-listen on
the GSRN relay before the relay cleaned up the old session. With the PTY
fix, the first connection stays open (the shell doesn't immediately exit)
so the re-listen path is never reached.

Verified:
  - Cross-compiled windows/amd64 binary: 3,551,232 bytes, contains
    .rsrc section with VS_VERSION_INFO magic at 0x3626c8, version
    string "0.1.5.0" present (UTF-16LE at 0x3628c4), "0.1.4.0" absent.
  - All 4 platform binaries built clean.
  - struct layout from v0.1.4 is preserved (the 112-byte startupInfoEx
    with correct *uint16 pointer fields is unchanged).'''

TAG_MSG = '''v0.1.5: Fix inverted HRESULT check in CreatePseudoConsole

The v0.1.4 struct layout fix was necessary but not sufficient — the code
also had an inverted success/failure check on the CreatePseudoConsole
return value. CreatePseudoConsole returns HRESULT (0 = S_OK = success),
but the code checked `if r == 0` as failure, so every call was treated
as failing even when it succeeded.

Fix: `if r != 0` is the correct failure check for HRESULT returns.

Bug found via user testing on Windows-to-Windows v0.1.4 (same laptop).
The v0.1.4 diagnostic improvement (including the Spawn error in the
NOPTY message) was what revealed the actual error: "CreatePseudoConsole"
in the truncated error string pointed directly at the failing call.'''


def run(cmd, **kw):
    """Run a command, return (returncode, stdout, stderr)."""
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    return r.returncode, r.stdout, r.stderr


def git(args, check=True):
    """Run a git command in REPO_DIR."""
    r = subprocess.run(['git'] + args, capture_output=True, text=True, cwd=REPO_DIR)
    if check and r.returncode != 0:
        print(f'git {" ".join(args)} failed: {r.stderr}', file=sys.stderr)
        raise RuntimeError(r.stderr)
    return r.stdout.strip(), r.stderr.strip()


def api_call(method, path, body=None, content_type='application/json', max_retries=3):
    url = path if path.startswith('http') else API + path
    headers = {
        'Authorization': f'Bearer {PAT}',
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
    }
    data = None
    if body is not None:
        if isinstance(body, (dict, list)):
            data = json.dumps(body).encode()
        elif isinstance(body, bytes):
            data = body
        else:
            data = body.encode()
        headers['Content-Type'] = content_type

    for attempt in range(max_retries):
        try:
            req = urllib.request.Request(url, data=data, method=method, headers=headers)
            with urllib.request.urlopen(req, timeout=60) as resp:
                content = resp.read()
                if resp.status == 204 or not content:
                    return resp.status, {}
                try:
                    return resp.status, json.loads(content)
                except json.JSONDecodeError:
                    return resp.status, content
        except urllib.error.HTTPError as e:
            body_text = e.read().decode('utf-8', errors='replace')
            if e.code == 422 and 'already_exists' in body_text:
                return e.code, json.loads(body_text) if body_text.startswith('{') else body_text
            if e.code in (502, 503, 504) and attempt < max_retries - 1:
                print(f'  [{e.code}] retrying ({attempt+1}/{max_retries})...')
                time.sleep(2 ** attempt)
                continue
            print(f'  ERROR {e.code}: {body_text[:500]}', file=sys.stderr)
            return e.code, body_text
        except Exception as e:
            if attempt < max_retries - 1:
                print(f'  Exception: {e}, retrying ({attempt+1}/{max_retries})...')
                time.sleep(2 ** attempt)
                continue
            raise
    return None, None


def upload_asset(upload_url, file_path):
    if '{' in upload_url:
        upload_url = upload_url.split('{')[0]
    filename = os.path.basename(file_path)
    url = f'{upload_url}?name={filename}'
    with open(file_path, 'rb') as f:
        data = f.read()
    size = len(data)
    mime = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
    if filename.endswith('.zip'):
        mime = 'application/zip'
    elif filename.endswith('.tar.gz'):
        mime = 'application/gzip'
    elif filename.endswith('.exe'):
        mime = 'application/vnd.microsoft.portable-executable'
    print(f'  Uploading {filename} ({size:,} bytes, {mime})...')
    headers = {
        'Authorization': f'Bearer {PAT}',
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        'Content-Type': mime,
        'Content-Length': str(size),
    }
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, data=data, method='POST', headers=headers)
            with urllib.request.urlopen(req, timeout=180) as resp:
                result = json.loads(resp.read())
                print(f'    -> OK, asset ID: {result.get("id")}, state: {result.get("state")}')
                return result
        except urllib.error.HTTPError as e:
            body = e.read().decode('utf-8', errors='replace')
            print(f'    -> HTTP {e.code}: {body[:300]}', file=sys.stderr)
            if e.code in (502, 503, 504) and attempt < 2:
                print(f'    retrying ({attempt+1}/3)...')
                time.sleep(2 ** attempt)
                continue
            raise
        except Exception as e:
            print(f'    -> Exception: {e}', file=sys.stderr)
            if attempt < 2:
                print(f'    retrying ({attempt+1}/3)...')
                time.sleep(2 ** attempt)
                continue
            raise
    return None


def main():
    # Step 1: Get origin/main
    origin_main, _ = git(['rev-parse', 'origin/main'])
    print(f'=== origin/main: {origin_main} ===')

    # Step 2: Build a fresh index from origin/main
    import tempfile
    tmpindex = tempfile.mktemp()
    env = os.environ.copy()
    env['GIT_INDEX_FILE'] = tmpindex
    r = subprocess.run(['git', 'read-tree', origin_main], capture_output=True, text=True, cwd=REPO_DIR, env=env)
    if r.returncode != 0:
        print(f'read-tree failed: {r.stderr}', file=sys.stderr)
        return 1

    # Step 3: Hash each file and stage it
    print('\n=== Staging 3 v0.1.5 files ===')
    for local_path, git_path, mode in FILES:
        full_local = os.path.join(REPO_DIR, local_path)
        if not os.path.exists(full_local):
            print(f'  SKIP {local_path} — not found', file=sys.stderr)
            continue
        # Hash the file
        r = subprocess.run(['git', 'hash-object', '-w', '--', full_local],
                          capture_output=True, text=True, cwd=REPO_DIR)
        if r.returncode != 0:
            print(f'  hash-object failed for {local_path}: {r.stderr}', file=sys.stderr)
            return 1
        blob = r.stdout.strip()
        print(f'  {git_path}: blob {blob} ({os.path.getsize(full_local)} bytes)')
        # Stage in temp index
        r = subprocess.run(['git', 'update-index', '--add', '--cacheinfo', f'{mode},{blob},{git_path}'],
                          capture_output=True, text=True, cwd=REPO_DIR, env=env)
        if r.returncode != 0:
            print(f'  update-index failed: {r.stderr}', file=sys.stderr)
            return 1

    # Step 4: Write tree
    r = subprocess.run(['git', 'write-tree'], capture_output=True, text=True, cwd=REPO_DIR, env=env)
    if r.returncode != 0:
        print(f'write-tree failed: {r.stderr}', file=sys.stderr)
        return 1
    new_tree = r.stdout.strip()
    print(f'\n=== New tree: {new_tree} ===')

    # Step 5: Diff
    r = subprocess.run(['git', 'diff-tree', '--stat', origin_main, new_tree],
                      capture_output=True, text=True, cwd=REPO_DIR)
    print(r.stdout)

    # Step 6: Create commit
    r = subprocess.run(['git', 'commit-tree', new_tree, '-p', origin_main, '-m', COMMIT_MSG],
                      capture_output=True, text=True, cwd=REPO_DIR)
    if r.returncode != 0:
        print(f'commit-tree failed: {r.stderr}', file=sys.stderr)
        return 1
    new_commit = r.stdout.strip()
    print(f'=== New commit: {new_commit} ===')
    r = subprocess.run(['git', 'show', '--stat', new_commit], capture_output=True, text=True, cwd=REPO_DIR)
    print(r.stdout[:500])

    # Step 7: Update v015-push branch
    subprocess.run(['git', 'branch', '-D', 'v015-push'], capture_output=True, text=True, cwd=REPO_DIR)
    subprocess.run(['git', 'branch', 'v015-push', new_commit], capture_output=True, text=True, cwd=REPO_DIR)
    print(f'  v015-push -> {new_commit}')

    # Step 8: Create tag
    subprocess.run(['git', 'tag', '-d', TAG], capture_output=True, text=True, cwd=REPO_DIR)
    r = subprocess.run(['git', 'tag', '-a', TAG, '-m', TAG_MSG, new_commit],
                      capture_output=True, text=True, cwd=REPO_DIR)
    if r.returncode != 0:
        print(f'tag failed: {r.stderr}', file=sys.stderr)
        return 1
    print(f'  Tag {TAG} -> {new_commit}')

    # Step 9: Verify
    ahead = subprocess.run(['git', 'rev-list', '--count', f'{origin_main}..v015-push'],
                          capture_output=True, text=True, cwd=REPO_DIR).stdout.strip()
    print(f'\n=== Commits ahead of origin/main: {ahead} ===')

    # Step 10: Push
    print('\n=== Pushing v015-push -> origin/main ===')
    askpass = '/home/z/my-project/scripts/gh-askpass-v015.sh'
    with open(askpass, 'w') as f:
        f.write('#!/bin/sh\ncase "$1" in\n  Username*) echo "n3xumc0r3" ;;\n  Password*) echo "$GH_TOKEN" ;;\nesac\n')
    os.chmod(askpass, 0o755)
    env_push = os.environ.copy()
    env_push['GH_TOKEN'] = PAT
    env_push['GIT_ASKPASS'] = askpass
    env_push['GIT_TERMINAL_PROMPT'] = '0'
    r = subprocess.run(['git', 'push', 'origin', 'v015-push:main'], capture_output=True, text=True, cwd=REPO_DIR, env=env_push)
    print(r.stdout)
    if r.returncode != 0:
        print(f'push failed: {r.stderr}', file=sys.stderr)
        return 1
    print(r.stderr)

    print('\n=== Pushing tag v0.1.5 ===')
    r = subprocess.run(['git', 'push', 'origin', TAG], capture_output=True, text=True, cwd=REPO_DIR, env=env_push)
    print(r.stdout)
    if r.returncode != 0:
        print(f'tag push failed: {r.stderr}', file=sys.stderr)
        return 1
    print(r.stderr)

    # Cleanup askpass
    os.unlink(askpass)

    # Step 11: Create GitHub Release
    print('\n=== Creating GitHub Release v0.1.5 ===')
    RELEASE_BODY = """## v0.1.5 — The REAL Windows PTY fix

### What was wrong in v0.1.4

v0.1.4 fixed the `startupInfoEx` struct layout (88 → 112 bytes), which was necessary but **not sufficient**. User testing on Windows-to-Windows v0.1.4 (same laptop, both sides) revealed the actual `Spawn` error thanks to the new diagnostic message:

```
gspty: gspty: PTY not supported on this platform: CreatePseudoConsole
```

### Root cause

`CreatePseudoConsole` returns an **HRESULT** (not a BOOL):
- `S_OK` (0) = success
- `E_INVALIDARG` (0x80070057) etc. = failure (non-zero)

The v0.1.4 code checked:
```go
if r == 0 {  // ❌ treats S_OK (success) as failure
```

Every `CreatePseudoConsole` call actually **succeeded**, but the code immediately closed all the handles and returned `ErrNoPTY`. The PTY was never usable.

Compare with `ResizePseudoConsole` in the same file — it correctly checks `if r != 0` for failure. That one was right all along; the bug was only in the `CreatePseudoConsole` check.

### The fix

Invert the check:
```go
if r != 0 {  // ✅ non-zero HRESULT = failure
```

Also include the HRESULT hex value in the error message (instead of the meaningless syscall errno) so any future ConPTY failure can be diagnosed precisely:
```go
return nil, fmt.Errorf("gspty: %w: CreatePseudoConsole failed (HRESULT=0x%x)", ErrNoPTY, uint32(r))
```

### The BAD_AUTH error

The `gsrn: status FATAL BAD_AUTH` that appeared on the server side was a **secondary symptom**. After the PTY failure caused the first connection to close (client got NOPTY and disconnected), the server tried to re-listen on the GSRN relay before the relay cleaned up the old session. With the PTY fix, the first connection stays open (the shell doesn't immediately exit), so the re-listen path is never reached.

### Other v0.1.5 changes

- `versioninfo.json`: bumped to `0.1.5.0`. Also fixed `FileOS` from `"040004L"` to `"040004"` — the `"L"` suffix caused goversioninfo to emit a parse warning (non-fatal, but the field was silently dropped from the VS_VERSIONINFO blob).
- `resource_windows_amd64.syso`: regenerated from the new versioninfo.

### Verified

- Cross-compiled `windows/amd64` binary: 3,551,232 bytes, contains `.rsrc` section with `VS_VERSION_INFO` magic at `0x3626c8`, version string `"0.1.5.0"` present (UTF-16LE at `0x3628c4`), `"0.1.4.0"` absent.
- All 4 platform binaries built clean.
- Struct layout from v0.1.4 is preserved (the 112-byte `startupInfoEx` with correct `*uint16` pointer fields is unchanged).

## Downloads

| Platform | File | SHA256 |
|---|---|---|
| Windows (amd64) | `gs-netcat-v0.1.5-windows-amd64.zip` | `5332bd4991626cd7bdf05db9ff497eb7125c7f40608287a6c5393bb27a15cd6f` |
| Linux (amd64) | `gs-netcat-v0.1.5-linux-amd64.tar.gz` | `7074e2052a5b6fa86085d1dc97168d360436faa47f5542b37f60b34cb40dfcab` |
| macOS (Intel) | `gs-netcat-v0.1.5-darwin-amd64.tar.gz` | `d14171a53b1e0f3ebaaf036bdc09dbb7493232311eb26b19e8f91051c50e9778` |
| macOS (Apple Silicon) | `gs-netcat-v0.1.5-darwin-arm64.tar.gz` | `fadebaabf472ed8174ce4f6325714431294c263ca08fcaf1b8719f9aa65db1aa` |

Verify with: `sha256sum -c SHA256SUMS`

## Quick start (Windows)

```cmd
:: Terminal 1 — start server
gs-netcat.exe -l -i -s "your-secret"

:: Terminal 2 — connect client
gs-netcat.exe -i -s "your-secret"
```

You should now be in an interactive shell on the server side. Type `exit` to leave.
"""

    status, result = api_call('POST', '/releases', body={
        'tag_name': TAG,
        'name': 'gs-netcat v0.1.5 — The REAL Windows PTY fix (inverted HRESULT check)',
        'body': RELEASE_BODY,
        'draft': False,
        'prerelease': False,
        'make_latest': 'true',
    })
    if status not in (200, 201):
        print(f'  FAILED to create release: HTTP {status}: {result}', file=sys.stderr)
        return 1
    release_id = result['id']
    upload_url = result['upload_url']
    print(f'  Created release: ID={release_id}')
    print(f'  HTML URL: {result.get("html_url")}')

    # Step 12: Upload assets
    print('\n=== Uploading 5 assets ===')
    assets = [
        'gs-netcat-v0.1.5-windows-amd64.zip',
        'gs-netcat-v0.1.5-linux-amd64.tar.gz',
        'gs-netcat-v0.1.5-darwin-amd64.tar.gz',
        'gs-netcat-v0.1.5-darwin-arm64.tar.gz',
        'SHA256SUMS',
    ]
    for asset_name in assets:
        file_path = os.path.join(ASSETS_DIR, asset_name)
        if not os.path.exists(file_path):
            print(f'  SKIP {asset_name} — not found', file=sys.stderr)
            continue
        upload_asset(upload_url, file_path)

    # Step 13: Verify
    print('\n=== Final verification ===')
    status, final = api_call('GET', f'/releases/{release_id}')
    if status == 200:
        print(f'  Release: {final.get("name")}')
        print(f'  Tag: {final.get("tag_name")}')
        print(f'  Published: {final.get("published_at")}')
        print(f'  HTML URL: {final.get("html_url")}')
        print(f'  Assets ({len(final.get("assets", []))}):')
        for a in final.get('assets', []):
            print(f'    - {a["name"]:50s} {a["size"]:>10,} bytes')

    # Cleanup temp index
    try:
        os.unlink(tmpindex)
    except:
        pass

    print('\n=== DONE ===')
    return 0


if __name__ == '__main__':
    sys.exit(main())
