#!/usr/bin/env python3
"""Create v0.1.9 GitHub release and upload 5 assets."""
import sys, os, json, urllib.request, urllib.error, mimetypes

with open('/tmp/.gh_pat') as f:
    PAT = f.read().strip()
REPO = 'n3xumc0r3/gs-netcat-go'
TAG = 'v0.1.9'
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

release_body = """## v0.1.9 — Fix BAD_AUTH: set deterministic auth token BEFORE first Dial

### The bug

v0.1.8 fixed the hex encoding of binary garbage in error messages (✅ no more terminal corruption) and tried to fix BAD_AUTH by reusing the auth token in `multipeer.go`. **BUT** the token reuse was applied INSIDE `runMultiPeerInteractiveServer`, which runs AFTER the first `gsconn.Dial` in `main.go`. So:

```
First listen:  random token T1 (opts.AuthToken was still empty)
Re-listen:     DeriveAuthToken(secret, addr) = T2 (different from T1)
Relay:         sees T2 ≠ T1 for same GS-Address → BAD_AUTH
```

### The fix

In `main.go`, set `opts.AuthToken = secret` **BEFORE** the first `gsconn.Dial` when in listen mode and no explicit `-a` token was given. Now:

```
First listen:  DeriveAuthToken(secret, addr) = T
Re-listen:     DeriveAuthToken(secret, addr) = T (same!)
Relay:         T == T → accept ✓
```

Also increased the post-connection delay from 500ms to **3 seconds** to give the relay more cleanup time before re-listen (the relay's cleanup window is typically 2–5 seconds).

### Other changes

- `versioninfo.json`: bumped to `0.1.9.0`
- `resource_windows_amd64.syso`: regenerated

### Verification

- Cross-compiled windows/amd64 binary: 3,568,640 bytes
- Contains VS_VERSION_INFO with `0.1.9.0` (UTF-16LE)
- All 4 platform binaries built clean
"""

release_data = {
    'tag_name': TAG,
    'target_commitish': 'main',
    'name': f'gs-netcat {TAG} — Fix BAD_AUTH: deterministic auth token before first Dial',
    'body': release_body,
    'draft': False,
    'prerelease': False,
}
status, body = gh('POST', f'{API}/releases', release_data)
if status != 201:
    print(f'Failed: {status} {body}')
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
    print(f'  {"OK" if status == 201 else "FAIL"}: {asset}')

print(f'\n=== Release {TAG} published ===')
print(f'https://github.com/{REPO}/releases/tag/{TAG}')
