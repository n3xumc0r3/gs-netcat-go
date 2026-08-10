#!/bin/bash
# Build v0.1.4 release: same as v0.1.3 (with .rsrc section) + 2 fixes:
#   1. StatusMsg filters binary garbage from production GSRN relay's
#      _gs_status packets (fixes garbled output after "CONNREFUSED:").
#   2. Server-side STATUS NOPTY packet now carries the Spawn error message
#      so the client can print WHY the PTY failed (e.g. ConPTY unavailable,
#      forkpty failed, /bin/sh not found, etc.).
set -e
cd /home/z/my-project/gsport

GO=/tmp/my-project/.local/go/bin/go
export GOPATH=/home/z/go
export GOCACHE=/tmp/gocache
mkdir -p $GOCACHE

# Regenerate .syso with v0.1.4 version info.
python3 /home/z/my-project/scripts/gen_resource_syso.py

OUT=/home/z/my-project/download/release-v0.1.4
VERSION=v0.1.4

mkdir -p "$OUT"

# Build all 4 platforms.
for target in linux/amd64 windows/amd64 darwin/amd64 darwin/arm64; do
    GOOS=${target%/*}
    GOARCH=${target#*/}
    ext=""
    [ "$GOOS" = "windows" ] && ext=".exe"
    out="$OUT/gs-netcat-${VERSION}-${GOOS}-${GOARCH}${ext}"
    echo "Building $out..."
    GOOS=$GOOS GOARCH=$GOARCH CGO_ENABLED=0 \
        $GO build -trimpath -ldflags='-s -w' -o "$out" ./cmd/gs-netcat
done

# Run all unit tests on Linux binary (sanity check).
echo "Running unit tests..."
$GO test ./... 2>&1 | tail -10

# Package: tar.gz for unix, zip for windows.
cd "$OUT"
for f in gs-netcat-${VERSION}-linux-amd64 \
         gs-netcat-${VERSION}-darwin-amd64 \
         gs-netcat-${VERSION}-darwin-arm64; do
    echo "Packaging $f.tar.gz..."
    tar -czf "$f.tar.gz" "$f"
done

# Windows zip (binary named gs-netcat.exe inside for drop-in).
echo "Packaging gs-netcat-${VERSION}-windows-amd64.zip..."
python3 -c "
import zipfile
with zipfile.ZipFile('gs-netcat-${VERSION}-windows-amd64.zip', 'w', zipfile.ZIP_DEFLATED) as z:
    z.write('gs-netcat-${VERSION}-windows-amd64.exe', 'gs-netcat.exe')
"

# SHA256SUMS for all release archives.
echo "Generating SHA256SUMS..."
sha256sum \
    gs-netcat-${VERSION}-linux-amd64.tar.gz \
    gs-netcat-${VERSION}-windows-amd64.zip \
    gs-netcat-${VERSION}-darwin-amd64.tar.gz \
    gs-netcat-${VERSION}-darwin-arm64.tar.gz > SHA256SUMS

echo
echo "Built and packaged in $OUT:"
ls -la "$OUT"
