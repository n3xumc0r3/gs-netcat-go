#!/usr/bin/env python3
"""Create v0.1.6 GitHub release and upload 5 assets."""
import sys, os, json, subprocess, urllib.request, urllib.error, time, mimetypes

with open('/tmp/.gh_pat') as f:
    PAT = f.read().strip()
REPO = 'n3xumc0r3/gs-netcat-go'
TAG = 'v0.1.6'
API = f'https://api.github.com/repos/{REPO}'
DIST = '/home/z/my-project/v016src/dist'

def gh(method, url, data=None, content_type='application/json', expect=200):
    if data is not None and isinstance(data, (dict, list)):
        data = json.dumps(data).encode()
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header('Authorization', f'token {PAT}')
    req.add_header('Accept', 'application/vnd.github+json')
    if content_type:
        req.add_header('Content-Type', content_type)
    try:
        with urllib.request.urlopen(req) as r:
            body = r.read()
            return r.status, json.loads(body) if body and content_type == 'application/json' else body
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

# Get commit SHA
status, body = gh('GET', f'{API}/commits/{TAG}')
if status != 200:
    print(f'Failed to get commit: {status} {body}')
    sys.exit(1)
commit_sha = body['sha']
print(f'Tag {TAG} -> commit {commit_sha}')

# Create release
release_body = """## v0.1.6 — The REAL ConPTY fix (EXTENDED_STARTUPINFO_PRESENT in dwCreationFlags)

### The bug

v0.1.5 fixed the inverted HRESULT check, so `CreatePseudoConsole` finally succeeded and `cmd.exe` spawned on the server. **BUT** the shell output appeared in the SERVER's PowerShell window instead of being relayed to the client. The client just saw:

```
GS-Address: 07ddd55cfc2bfd2ab259cf3254841b72
Connected (role=SSL-CLIENT [in-band]). Press Ctrl-D to exit.
```

…and nothing else.

### Root cause

`EXTENDED_STARTUPINFO_PRESENT` was set in `STARTUPINFO.dwFlags` (`si.Flags`) but **NOT** in the `dwCreationFlags` parameter of `CreateProcessW`.

The [Microsoft ConPTY sample](https://github.com/microsoft/terminal/blob/main/samples/ConPTY/EchoCon/Common/EchoCon.cpp) sets this flag in **BOTH** places:
1. `siEx.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT`
2. `dwCreationFlags = EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT`

Without the flag in `dwCreationFlags`, `CreateProcessW` treats `lpStartupInfo` as a plain `STARTUPINFOW` (104 bytes) and silently ignores the `lpAttributeList` field at offset 104. The `PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE` entry is never applied, so the child process inherits the parent's console instead of attaching to the pseudoconsole.

### Result before the fix

- `cmd.exe` ran in the server's PowerShell window (its stdin/stdout were wired to the parent's console handles)
- The ConPTY output pipe was empty
- `io.Copy(conn, pty.Master)` sent nothing to the client
- The user could type `ls`, `powershell` etc. IN THE SERVER WINDOW — but the client saw nothing

### The fix

One line: add `EXTENDED_STARTUPINFO_PRESENT` to the `dwCreationFlags` parameter (6th arg) of `CreateProcessW`.

```go
CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT,
```

Now `CreateProcessW` correctly interprets the `STARTUPINFOEX` and applies the pseudoconsole attribute, so the child attaches to the ConPTY and I/O flows through the pipe to the client.

### Other changes

- `versioninfo.json`: bumped to `0.1.6.0`
- `resource_windows_amd64.syso`: regenerated

### Verification

- Cross-compiled windows/amd64 binary: 3,564,544 bytes
- Contains VS_VERSION_INFO with `0.1.6.0` (UTF-16LE)
- `0.1.5.0` string absent
- HRESULT error string from v0.1.5 preserved
- All 4 platform binaries built clean
"""

release_data = {
    'tag_name': TAG,
    'target_commitish': 'main',
    'name': f'gs-netcat {TAG} — The REAL ConPTY fix (EXTENDED_STARTUPINFO_PRESENT)',
    'body': release_body,
    'draft': False,
    'prerelease': False,
}
status, body = gh('POST', f'{API}/releases', release_data)
if status != 201:
    print(f'Failed to create release: {status} {body}')
    sys.exit(1)
release_id = body['id']
upload_url = body['upload_url'].split('{')[0]
print(f'Release created: id={release_id}')

# Upload assets
assets = sorted(os.listdir(DIST))
for asset in assets:
    path = os.path.join(DIST, asset)
    if not os.path.isfile(path):
        continue
    print(f'Uploading {asset} ({os.path.getsize(path)} bytes)...')
    with open(path, 'rb') as f:
        data = f.read()
    ct = mimetypes.guess_type(asset)[0] or 'application/octet-stream'
    url = f'{upload_url}?name={asset}'
    status, body = gh('POST', url, data, content_type=ct)
    if status == 201:
        print(f'  OK: {asset}')
    else:
        print(f'  FAIL: {status} {body}')

print(f'\n=== Release {TAG} published ===')
print(f'https://github.com/{REPO}/releases/tag/{TAG}')
