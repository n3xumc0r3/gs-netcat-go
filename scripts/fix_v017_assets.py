#!/usr/bin/env python3
"""Replace v0.1.7 release assets with correctly-built archives."""
import sys, os, json, urllib.request, urllib.error, mimetypes

with open('/tmp/.gh_pat') as f:
    PAT = f.read().strip()
REPO = 'n3xumc0r3/gs-netcat-go'
TAG = 'v0.1.7'
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

# Get release info
status, body = gh('GET', f'{API}/releases/tags/{TAG}')
if status != 200:
    print(f'Failed to get release: {status} {body}')
    sys.exit(1)
release_id = body['id']
assets = {a['name']: a['id'] for a in body.get('assets', [])}
print(f'Release {TAG} (id={release_id}) has {len(assets)} assets')

# Delete all existing assets
for name, aid in assets.items():
    print(f'  Deleting {name} (id={aid})...')
    status, body = gh('DELETE', f'{API}/releases/assets/{aid}')
    print(f'    -> {status}')

# Get upload_url template
status, body = gh('GET', f'{API}/releases/{release_id}')
upload_url = body['upload_url'].split('{')[0]

# Upload new correct archives
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

print(f'\n=== v0.1.7 assets replaced ===')
print(f'https://github.com/{REPO}/releases/tag/{TAG}')
