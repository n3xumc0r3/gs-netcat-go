#!/usr/bin/env python3
"""Create a GitHub Release and upload assets for a given tag.

Usage:
    python3 scripts/create_release.py <tag> <release_dir>

The release dir should contain prebuilt assets named with the tag (e.g.
gs-netcat-v0.1.0-linux-amd64.tar.gz). A SHA256SUMS file is expected to be
present in the same directory.

Auth: reads GITHUB_TOKEN env var. Token must have Contents:Read/Write,
Workflows:Read/Write, Administration:Read/Write on the target repo.
"""
import json
import os
import sys
import urllib.request
import urllib.error
import urllib.parse

TOKEN = os.environ.get("GITHUB_TOKEN")
if not TOKEN:
    sys.exit("GITHUB_TOKEN env var not set")

REPO = "n3xumc0r3/gs-netcat-go"
if len(sys.argv) < 3:
    sys.exit("usage: create_release.py <tag> <release_dir>")
TAG = sys.argv[1]
REL_DIR = sys.argv[2]

BODY = f"""# gs-netcat-go {TAG}

See [CHANGELOG](https://github.com/{REPO}/blob/main/README.md) for details.

## Downloads

| File | OS | Arch | Notes |
|------|----|-----:|-------|
| `gs-netcat-{TAG}-linux-amd64.tar.gz` | Linux | x86_64 | |
| `gs-netcat-{TAG}-windows-amd64.zip` | Windows | x86_64 | plain build |
| `gs-netcat-{TAG}-windows-amd64-obf.zip` | Windows | x86_64 | **obfuscated** (recommended — see note below) |
| `gs-netcat-{TAG}-darwin-amd64.tar.gz` | macOS | Intel | |
| `gs-netcat-{TAG}-darwin-arm64.tar.gz` | macOS | Apple Silicon | |
| `SHA256SUMS` | — | checksums | |

## Windows Defender note

The plain Windows build may trigger a false-positive in Windows
Defender (and other AVs that use static string heuristics on Go
binaries). This is a known issue with Go binaries of network
utilities — Defender's ML model flags the combination of Go-binary
fingerprint + network I/O + PTY/ConPTY spawning.

The `-obf.zip` variant is built with [garble](https://github.com/burrowers/garble)
(`-literals -tiny`), which obfuscates symbol names and encrypts
string literals. It is functionally identical to the plain build
but has a significantly lower false-positive rate on Windows.

If you still see a detection on the obfuscated build, either:
1. Build from source with garble: `garble -literals -tiny build ./cmd/gs-netcat`
2. Add the binary path to Defender exclusions
3. Use the Linux/macOS build

## Verification

```bash
sha256sum -c SHA256SUMS --ignore-missing
```
"""

def api(method, path, data=None, content_type="application/json"):
    url = f"https://api.github.com/repos/{REPO}/{path}"
    headers = {
        "Authorization": f"token {TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    body = None
    if data is not None:
        if content_type == "application/json":
            body = json.dumps(data).encode()
        else:
            body = data
        headers["Content-Type"] = content_type
    req = urllib.request.Request(url, method=method, headers=headers, data=body)
    try:
        with urllib.request.urlopen(req) as r:
            txt = r.read()
            return r.status, json.loads(txt) if txt and r.headers.get("Content-Type", "").startswith("application/json") else txt
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")

print(f"Creating release {TAG}...")
status, resp = api("POST", "releases", {
    "tag_name": TAG,
    "target_commitish": "main",
    "name": f"gs-netcat-go {TAG}",
    "body": BODY,
    "draft": False,
    "prerelease": False,
    "make_latest": "true",
})
if status != 201:
    print(f"ERROR creating release: HTTP {status}")
    print(resp if isinstance(resp, str) else json.dumps(resp, indent=2))
    sys.exit(1)
release = resp
print(f"  created release id={release['id']}")
upload_base = release["upload_url"].split("{")[0]

# Collect assets present in the release dir.
assets = []
for name in sorted(os.listdir(REL_DIR)):
    if name.startswith("gs-netcat-") or name == "SHA256SUMS":
        assets.append(name)

for name in assets:
    path = os.path.join(REL_DIR, name)
    if not os.path.isfile(path):
        continue
    size = os.path.getsize(path)
    print(f"  uploading {name} ({size} bytes)...")
    with open(path, "rb") as f:
        data = f.read()
    url = f"{upload_base}?name={urllib.parse.quote(name)}"
    req = urllib.request.Request(url, method="POST", data=data, headers={
        "Authorization": f"token {TOKEN}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/octet-stream",
    })
    try:
        with urllib.request.urlopen(req) as r:
            r.read()
            print(f"    OK ({r.status})")
    except urllib.error.HTTPError as e:
        print(f"    FAIL: HTTP {e.code}")
        print(e.read().decode("utf-8", "replace"))

print()
print(f"Release URL: https://github.com/{REPO}/releases/tag/{TAG}")
