#!/usr/bin/env python3
"""Upload 5 assets to existing v0.1.3 release (ID 367449957)."""
import json
import os
import sys
import urllib.parse
import urllib.request

TOKEN = 'GH_TOKEN_ENV'
OWNER = 'n3xumc0r3'
REPO = 'gs-netcat-go'
RELEASE_ID = 367449957

ASSETS = [
    ('gs-netcat-v0.1.3-windows-amd64.zip',  'application/zip'),
    ('gs-netcat-v0.1.3-linux-amd64.tar.gz', 'application/gzip'),
    ('gs-netcat-v0.1.3-darwin-amd64.tar.gz','application/gzip'),
    ('gs-netcat-v0.1.3-darwin-arm64.tar.gz','application/gzip'),
    ('SHA256SUMS',                          'text/plain'),
]

RELEASE_DIR = '/home/z/my-project/download/release-v0.1.3'


def api(method, url, data=None, content_type='application/json', raw_body=None):
    headers = {
        'Authorization': f'Bearer {TOKEN}',
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
    }
    if content_type:
        headers['Content-Type'] = content_type
    body = raw_body if raw_body is not None else (json.dumps(data).encode() if data else None)
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req) as r:
            response_body = r.read()
            try:
                return r.status, json.loads(response_body)
            except json.JSONDecodeError:
                return r.status, response_body
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def main():
    base = f'https://uploads.github.com/repos/{OWNER}/{REPO}/releases/{RELEASE_ID}/assets'
    for fname, mime in ASSETS:
        path = os.path.join(RELEASE_DIR, fname)
        if not os.path.exists(path):
            print(f'  MISSING: {path}')
            return 1
        size = os.path.getsize(path)
        print(f'  Uploading {fname} ({size:,} bytes)...')
        with open(path, 'rb') as f:
            raw = f.read()
        url = f'{base}?name={urllib.parse.quote(fname)}'
        status, resp = api('POST', url, content_type=mime, raw_body=raw)
        if status not in (200, 201):
            print(f'    FAILED: {status}')
            err_text = resp.decode() if isinstance(resp, bytes) else str(resp)
            print(f'    {err_text[:500]}')
            return 1
        if isinstance(resp, dict):
            print(f'    OK: {resp.get("browser_download_url", "?")}')

    print()
    print(f'=== Release v0.1.3 is LIVE ===')
    print(f'  https://github.com/{OWNER}/{REPO}/releases/tag/v0.1.3')
    return 0


if __name__ == '__main__':
    sys.exit(main())
