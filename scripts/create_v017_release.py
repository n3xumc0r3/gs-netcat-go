#!/usr/bin/env python3
"""Create v0.1.7 GitHub release and upload 5 assets."""
import sys, os, json, urllib.request, urllib.error, mimetypes

with open('/tmp/.gh_pat') as f:
    PAT = f.read().strip()
REPO = 'n3xumc0r3/gs-netcat-go'
TAG = 'v0.1.7'
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

release_body = """## v0.1.7 — Fix "More?" bug: use Windows Job Object to kill entire process tree on Close

### The bug

After v0.1.6 fixed the ConPTY relay, the shell was correctly sent to the client. **BUT** when the client disconnected, the shell process tree (cmd.exe + any children like powershell.exe) was **NOT killed**. The orphaned processes reattached to the server's console window, stealing keyboard input and producing weird "More?" prompts and garbage characters.

User report (v0.1.6):
```
PS> .\\gs-netcat.exe -s "user1448" -i -l
...
C:\\Users\\Артём\\Desktop>
More? Users\\Артём\\Desktop>
PS C:\\Users\\Артём\\Desktop> More?
PS C:\\Users\\Артём\\Desktop> ссссссMore?
```

### Root cause

`Close()` called `ClosePseudoConsole` (which releases the pseudoconsole resources) but did **NOT** kill the child processes. `TerminateProcess` only kills the immediate child (cmd.exe), not its children (powershell.exe, wsl.exe, etc.). The orphaned children reattached to the parent's console and intercepted keystrokes.

### The fix: Windows Job Object with `KILL_ON_JOB_CLOSE`

When the job handle is closed, **ALL** processes in the job — the immediate child AND any grandchildren — are terminated immediately. This is the ONLY reliable way to clean up a process tree on Windows.

### Implementation

1. Added `CREATE_SUSPENDED` flag to `CreateProcessW` — starts the child suspended so we can assign it to the job BEFORE it runs any code.
2. Create a Job Object with `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.
3. Assign the suspended child to the job.
4. `ResumeThread` — the child starts running, now inside the job. Any grandchildren it spawns are also in the job.
5. Store `hJob` in the PTY struct.
6. In `Close()`, close `hJob` **FIRST** (before `ClosePseudoConsole`) — this kills the entire process tree before the ConPTY is torn down, preventing any process from reattaching to the parent's console.

### New Windows API calls

- `CreateJobObjectW`
- `SetInformationJobObject` (with `JobObjectExtendedLimitInformation`)
- `AssignProcessToJobObject`
- `ResumeThread`

### Other changes

- `versioninfo.json`: bumped to `0.1.7.0`
- `resource_windows_amd64.syso`: regenerated

### Verification

- Cross-compiled windows/amd64 binary: 3,567,616 bytes
- Contains VS_VERSION_INFO with `0.1.7.0` (UTF-16LE)
- All 4 platform binaries built clean
- The `CREATE_SUSPENDED` + Job Object pattern matches the Microsoft recommended approach for process tree lifecycle management.
"""

release_data = {
    'tag_name': TAG,
    'target_commitish': 'main',
    'name': f'gs-netcat {TAG} — Fix "More?" bug: Job Object kills entire process tree on Close',
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
