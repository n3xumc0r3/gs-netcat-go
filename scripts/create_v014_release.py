#!/usr/bin/env python3
"""Create GitHub Release v0.1.4 and upload 5 assets."""
import sys
import json
import urllib.request
import urllib.error
import os
import mimetypes
import time

PAT = 'GH_TOKEN_ENV'
REPO = 'n3xumc0r3/gs-netcat-go'
TAG = 'v0.1.4'
API = f'https://api.github.com/repos/{REPO}'
ASSETS_DIR = '/home/z/my-project/download/release-v0.1.4'

RELEASE_BODY = """## v0.1.4 — Windows ConPTY struct layout fix

### Root cause

The `-i` interactive shell mode was completely broken on Windows in v0.1.3: every attempt to connect produced `remote has no PTY — interactive shell unavailable` on the client side, regardless of which shell (`cmd.exe`, `powershell.exe`) the server tried to spawn.

The bug was in `internal/gspty/pty_windows.go`: the `startupInfoEx` struct was hand-rolled with **wrong field types** for the Win32 `LPWSTR` fields:

| Field | v0.1.3 (buggy) | v0.1.4 (correct) |
|---|---|---|
| `lpReserved` | `uint16` (2 bytes) | `*uint16` (8 bytes on x64) |
| `lpDesktop` | `uint16` (2 bytes) | `*uint16` (8 bytes on x64) |
| `lpTitle` | `uint16` (2 bytes) | `*uint16` (8 bytes on x64) |
| `lpReserved2` | `uint16` (2 bytes) | `*byte` (8 bytes on x64) |

This collapsed the struct to **88 bytes** — Windows requires **112 bytes** for `STARTUPINFOEXW` on x64. Concretely:

1. `cb` was 88; `CreateProcessW` expects 104 (STARTUPINFOW) or 112 (STARTUPINFOEXW) and treats smaller values as a malformed struct.
2. `EXTENDED_STARTUPINFO_PRESENT` (the flag that tells `CreateProcessW` "this is actually a `STARTUPINFOEX`, look at `lpAttributeList`") was written to Go offset 40, but Windows reads `dwFlags` from Win32 offset 60 — Windows saw `dwFlags=0` and never consulted the attribute list.
3. The attribute list pointer itself was written to Go offset 80, but Windows reads `lpAttributeList` from Win32 offset 104 — **beyond the 88-byte struct**. Random stack/heap garbage was dereferenced as the attribute list pointer.

**Net effect:** `CreateProcessW` started the child shell WITHOUT the ConPTY attached. The shell had no stdin/stdout/stderr connection to the parent's pipes. `Spawn()` either returned an error (causing the `NOPTY` message) or returned a PTY that produced no I/O (silent hang). Either way, the interactive session was dead.

### The fix

1. **`startupInfoEx` struct rewritten** with the correct Win32 layout — pointers are `*uint16` / `*byte` (8 bytes on x64), with explicit `[4]byte` padding before `Reserved` and `Reserved2` to maintain 8-byte alignment. Total size now 112 bytes, matching `STARTUPINFOEXW` exactly. Field offsets documented inline so future maintainers can't accidentally re-introduce the bug.

2. **`PTY` struct now stores `hProcess`, `hThread`, `pid`** from `CreateProcessW`'s `PROCESS_INFORMATION` output. Previously these handles were discarded entirely — the code built a fake `*exec.Cmd` and `Wait()` was a no-op that returned `nil` immediately.

3. **`Wait()` actually waits now** — calls `WaitForSingleObject(hProcess, INFINITE)`, then closes both `hProcess` and `hThread`. Matches Go's `os.Process` convention ("Wait owns the process handle").

4. **`Close()` no longer touches `hProcess` / `hThread`** — they're owned by `Wait()`. This avoids the MSDN-documented undefined behaviour where closing a handle that another thread is waiting on inside `WaitForSingleObject` produces UB. `ClosePseudoConsole` is what terminates the child, which is what unblocks `Wait()`.

5. **`PID()` returns the actual Windows pid** (was always 0).

6. **`Close()` also closes `Master`** (the `os.File` wrapping the ConPTY output pipe) — previously it leaked.

7. **`main.go`**: the `NOPTY` STATUS message now includes the `Spawn` error string (truncated to 63 bytes) so the client can print **WHY** the PTY failed — previously the client only saw `remote has no PTY` with no diagnostic detail.

8. **`versioninfo.json`**: bumped to `0.1.4.0` (`FileVersion` + `ProductVersion`). **`resource_windows_amd64.syso`**: regenerated from the new `versioninfo.json` — the Windows binary still has the real `.rsrc` section with `VS_VERSIONINFO` + app manifest, so Windows Defender's `Wacapew.A!ml` ML classifier stays calm (the fix from v0.1.3 is preserved).

### Regression test

`internal/gspty/pty_windows_test.go` contains `TestStartupInfoExLayout` and `TestProcessInformationLayout` which use `unsafe.Offsetof` / `unsafe.Sizeof` to lock every struct field to its Win32-mandated offset. If anyone ever changes the struct in a way that breaks the layout, `go test ./internal/gspty/` (run on Windows) will fail with a clear message. The test compiles cleanly under `GOOS=windows`.

### Verified

- Cross-compiled `windows/amd64` binary: 3,551,232 bytes, contains `.rsrc` section with `VS_VERSION_INFO` magic at offset `0x3626c8`, version string `"0.1.4.0"` present, `"0.1.3.0"` absent.
- Linux test suite (`go test ./...`) passes for `gsids` / `gskdf` / `gspkt` / `gsrn` / `gsstats`.
- Struct-layout audit script confirms all 16 offsets/sizes match Win32 expectations.

### Bug report

> "Нет же, что клиент, что сервер под windows, запушены на одном ноуте и все равно не могут связаться. Оба v0.1.3"

(Both client and server on Windows, same laptop, both v0.1.3, still can't communicate.)

This was the critical clue: the bug reproduced on a **single Windows laptop** with no cross-platform or network variable — pointing directly at the Windows PTY allocation code path.

## Downloads

| Platform | File | SHA256 |
|---|---|---|
| Windows (amd64) | `gs-netcat-v0.1.4-windows-amd64.zip` | `7235c548b9c22024eb706046da3d1ed2b2b4b39ce7f4c0352896f8b7dd05e72c` |
| Linux (amd64) | `gs-netcat-v0.1.4-linux-amd64.tar.gz` | `17bdf216f106e53f69e54fa4c109f8bbd5c8d0fffc473193057c0bba7f1142da` |
| macOS (Intel) | `gs-netcat-v0.1.4-darwin-amd64.tar.gz` | `b7a71e8be636d6ab9ef798d8de2568ead0d7782a4b4e3dfe35e4dde96ba552ad` |
| macOS (Apple Silicon) | `gs-netcat-v0.1.4-darwin-arm64.tar.gz` | `e6a29583f9de9c43c0853fabeaab7422b0ccf6750c8433c4d43bccdc0141a97e` |

Verify with: `sha256sum -c SHA256SUMS`

## Quick start (Windows)

```cmd
:: Start a server (listen for incoming -i connections)
gs-netcat.exe -l -i -s "your-secret"

:: From another terminal on the same machine (or another Windows box)
gs-netcat.exe -i -s "your-secret"
```

You should now be in an interactive shell on the server side. Type `exit` to leave.

## What's next

If you still see `remote has no PTY` after upgrading to v0.1.4, the error message will now include the `Spawn` error string in parentheses — please open an issue with that exact text so we can diagnose further.
"""


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
                print(f'  [422 already_exists] — release already created, will fetch existing')
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
    # upload_url is like https://uploads.github.com/repos/.../releases/RID/assets?name=...
    # Strip the {?name,label} template part if present
    if '{' in upload_url:
        upload_url = upload_url.split('{')[0]

    filename = os.path.basename(file_path)
    url = f'{upload_url}?name={filename}'

    with open(file_path, 'rb') as f:
        data = f.read()

    size = len(data)
    mime = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
    # Override mime for known archive types
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
                print(f'    -> OK, asset ID: {result.get("id")}, state: {result.get("state")}, download: {result.get("browser_download_url")}')
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
    # Step 1: Check if release already exists
    print('=== Step 1: Check for existing release ===')
    status, existing = api_call('GET', f'/releases/tags/{TAG}')
    if status == 200:
        print(f'  Release already exists: ID={existing.get("id")}, draft={existing.get("draft")}, assets={len(existing.get("assets", []))}')
        release_id = existing['id']
        upload_url = existing['upload_url']
        existing_assets = {a['name']: a for a in existing.get('assets', [])}
    else:
        print(f'  No existing release (HTTP {status}). Creating new one.')
        existing_assets = {}
        release_id = None
        upload_url = None

    # Step 2: Create release if it doesn't exist
    if release_id is None:
        print('')
        print('=== Step 2: Create release v0.1.4 ===')
        body = {
            'tag_name': TAG,
            'name': 'gs-netcat v0.1.4 — Windows ConPTY struct layout fix',
            'body': RELEASE_BODY,
            'draft': False,
            'prerelease': False,
            'make_latest': 'true',
        }
        status, result = api_call('POST', '/releases', body=body)
        if status not in (200, 201):
            print(f'  FAILED to create release: HTTP {status}', file=sys.stderr)
            print(f'  Response: {result}', file=sys.stderr)
            sys.exit(1)
        release_id = result['id']
        upload_url = result['upload_url']
        print(f'  Created release: ID={release_id}')
        print(f'  Upload URL: {upload_url}')
        print(f'  HTML URL: {result.get("html_url")}')
    else:
        print(f'  Using existing release ID={release_id}')

    # Step 3: Upload 5 assets
    print('')
    print('=== Step 3: Upload 5 assets ===')

    assets_to_upload = [
        'gs-netcat-v0.1.4-windows-amd64.zip',
        'gs-netcat-v0.1.4-linux-amd64.tar.gz',
        'gs-netcat-v0.1.4-darwin-amd64.tar.gz',
        'gs-netcat-v0.1.4-darwin-arm64.tar.gz',
        'SHA256SUMS',
    ]

    for asset_name in assets_to_upload:
        file_path = os.path.join(ASSETS_DIR, asset_name)
        if not os.path.exists(file_path):
            print(f'  SKIP {asset_name} — file not found at {file_path}', file=sys.stderr)
            continue

        # If asset already exists, delete it first (so re-runs are idempotent)
        if asset_name in existing_assets:
            old_id = existing_assets[asset_name]['id']
            print(f'  Deleting existing {asset_name} (asset ID {old_id})...')
            del_status, _ = api_call('DELETE', f'/releases/assets/{old_id}')
            if del_status == 204:
                print(f'    -> deleted')
            else:
                print(f'    -> delete returned HTTP {del_status} (continuing)')

        upload_asset(upload_url, file_path)

    # Step 4: Verify final release state
    print('')
    print('=== Step 4: Verify final release ===')
    status, final = api_call('GET', f'/releases/{release_id}')
    if status == 200:
        print(f'  Release: {final.get("name")}')
        print(f'  Tag: {final.get("tag_name")}')
        print(f'  Published: {final.get("published_at")}')
        print(f'  HTML URL: {final.get("html_url")}')
        print(f'  Assets ({len(final.get("assets", []))}):')
        for a in final.get('assets', []):
            print(f'    - {a["name"]:50s} {a["size"]:>10,} bytes  downloads={a["download_count"]}  state={a["state"]}')
        print('')
        print(f'  Download all: {final.get("html_url")}')
    else:
        print(f'  Could not fetch release (HTTP {status})', file=sys.stderr)


if __name__ == '__main__':
    main()
