#!/usr/bin/env python3
"""Create v0.1.8 GitHub release and upload 5 assets."""
import sys, os, json, urllib.request, urllib.error, mimetypes

with open('/tmp/.gh_pat') as f:
    PAT = f.read().strip()
REPO = 'n3xumc0r3/gs-netcat-go'
TAG = 'v0.1.8'
API = f'https://api.github.com/repos/{REPO}'
DIST = '/home/z/my-project/v016src/dist'

def gh(method, url, data=None, content_type='application/json'):
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
            return r.status, (json.loads(body) if body and content_type == 'application/json' else body)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

release_body = """## v0.1.8 — Fix multi-peer BAD_AUTH + sanitize binary garbage in error messages

### The bugs

User reported three issues after v0.1.7:

1. **SERVER**: `multi-peer: listen failed: gsrn: status FATAL BAD_AUTH: <binary garbage>` — two consecutive BAD_AUTH errors after the first connection ended
2. **CLIENT**: `gs-netcat: gsrn: status FATAL CONNREFUSED: <binary garbage>` — client couldn't connect because the server's re-listen was failing
3. **Binary garbage** in error messages — the status message field contained non-printable bytes that corrupted the terminal

### Root causes & fixes

**A. Binary garbage in error messages**

`StatusMsg()` in `internal/gsrn/gsrn.go` returned raw bytes (offset 4..31 of the `_gs_status` packet) as a Go string without checking if they were printable. When the relay sends binary data (session hash, token bytes) in the message field, it appeared as garbage characters.

**Fix**: `StatusMsg()` now checks if all bytes are printable ASCII (0x20–0x7e). If any byte is non-printable, the message is returned as `hex:<hex>` instead of raw bytes. Terminal stays clean, diagnostics preserved.

**B. BAD_AUTH on re-listen**

The multi-peer loop re-called `gsconn.Dial(ModeListen)` after each connection. `gsconn.Dial` generates a **NEW random** 16-byte auth-token on every call. The relay still had the OLD token registered for the same GS-Address, so it rejected the new listen with BAD_AUTH.

**Fix**: If `opts.AuthToken` is empty, set it to the secret string. `gsconn.Dial` then calls `DeriveAuthToken(secret, addr)` which is **deterministic** — same secret + same addr = same token. All re-listen attempts now use the SAME token.

**C. Fixed 2-second retry wasn't enough**

The old code slept a fixed 2 seconds between retries. The relay's cleanup window can be longer.

**Fix**: Exponential backoff (1s → 2s → 4s → 8s → ... → 30s cap) with reset on success. Also added 500ms delay after each connection ends to give the relay time to clean up.

### Other changes

- `versioninfo.json`: bumped to `0.1.8.0`
- `resource_windows_amd64.syso`: regenerated

### Verification

- Cross-compiled windows/amd64 binary: 3,568,640 bytes
- Contains VS_VERSION_INFO with `0.1.8.0` (UTF-16LE)
- All 4 platform binaries built clean
- Archives are proper ZIP (Windows) / tar.gz (Linux, macOS)
"""

release_data = {
    'tag_name': TAG,
    'target_commitish': 'main',
    'name': f'gs-netcat {TAG} — Fix multi-peer BAD_AUTH + sanitize binary garbage in errors',
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

for asset in sorted(os.listdir(DIST)):
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
