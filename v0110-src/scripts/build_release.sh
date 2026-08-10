#!/bin/bash
# Build release binaries for all 4 platforms + package into archives + SHA256SUMS.
#
# Produces two Windows variants:
#   1. gs-netcat-${VERSION}-windows-amd64.exe          — plain build
#   2. gs-netcat-${VERSION}-windows-amd64-obf.exe      — obfuscated via garble
#      (string-literal obfuscation + symbol hashing via mvdan.cc/garble)
#
# The obfuscated variant is recommended for Windows users because
# Windows Defender tends to flag plain Go binaries of network tools
# as "potentially unwanted applications" based on static string
# analysis. Garble strips/hashes the symbol names and encrypts
# string literals, which significantly reduces false-positive rate.
#
# Usage: scripts/build_release.sh <version> <output_dir>
# Example: scripts/build_release.sh v0.1.1 /tmp/release
set -e

VERSION="${1:?usage: build_release.sh <version> <output_dir>}"
OUT="${2:?usage: build_release.sh <version> <output_dir>}"

mkdir -p "$OUT"
cd "$(dirname "$0")/.."

# Copy the Windows .syso (build artifact, lives in gsport/cmd/gs-netcat/)
# into the actual build package dir (cmd/gs-netcat/). Go's linker picks
# up *.syso files from the package dir automatically and merges their
# .rsrc section into the final PE. Without this copy the Windows binary
# would have NO .rsrc section — which is what made Win32/Defender flag
# v0.1.2 as Wacapew.A!ml (empty .rsrc = strong malware indicator).
echo "Copying resource_windows_amd64.syso to cmd/gs-netcat/..."
cp gsport/cmd/gs-netcat/resource_windows_amd64.syso cmd/gs-netcat/resource_windows_amd64.syso

# Detect garble. If not on PATH, skip the obfuscated Windows build
# with a warning instead of failing the whole release.
GARBLE="$(command -v garble || true)"
if [ -z "$GARBLE" ]; then
    echo "WARNING: garble not found on PATH; skipping obfuscated Windows build."
    echo "         Install with: go install mvdan.cc/garble@latest"
fi

# Build 4 platforms with -trimpath + -ldflags='-s -w' for smaller binaries.
for target in linux/amd64 windows/amd64 darwin/amd64 darwin/arm64; do
    GOOS=${target%/*}
    GOARCH=${target#*/}
    ext=""
    [ "$GOOS" = "windows" ] && ext=".exe"
    out="$OUT/gs-netcat-${VERSION}-${GOOS}-${GOARCH}${ext}"
    echo "Building $out..."
    GOOS=$GOOS GOARCH=$GOARCH CGO_ENABLED=0 \
        go build -trimpath -ldflags='-s -w' -o "$out" ./cmd/gs-netcat
done

# Build the obfuscated Windows variant via garble.
if [ -n "$GARBLE" ]; then
    OBF="$OUT/gs-netcat-${VERSION}-windows-amd64-obf.exe"
    echo "Building $OBF (garble -literals -tiny)..."
    GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
        "$GARBLE" -literals -tiny build -o "$OBF" ./cmd/gs-netcat
fi

# Package: tar.gz for unix, zip for windows.
cd "$OUT"
for f in gs-netcat-${VERSION}-linux-amd64 \
         gs-netcat-${VERSION}-darwin-amd64 \
         gs-netcat-${VERSION}-darwin-arm64; do
    tar -czf "$f.tar.gz" "$f"
done

# Windows: plain zip (binary named gs-netcat.exe inside).
python3 -c "
import zipfile
with zipfile.ZipFile('gs-netcat-${VERSION}-windows-amd64.zip', 'w', zipfile.ZIP_DEFLATED) as z:
    z.write('gs-netcat-${VERSION}-windows-amd64.exe', 'gs-netcat.exe')
"

# Windows: obfuscated zip (binary named gs-netcat.exe inside so it's
# a drop-in replacement for the plain zip).
if [ -n "$GARBLE" ]; then
    python3 -c "
import zipfile
with zipfile.ZipFile('gs-netcat-${VERSION}-windows-amd64-obf.zip', 'w', zipfile.ZIP_DEFLATED) as z:
    z.write('gs-netcat-${VERSION}-windows-amd64-obf.exe', 'gs-netcat.exe')
"
fi

# SHA256SUMS for all release archives.
if [ -n "$GARBLE" ]; then
    sha256sum \
        gs-netcat-${VERSION}-linux-amd64.tar.gz \
        gs-netcat-${VERSION}-windows-amd64.zip \
        gs-netcat-${VERSION}-windows-amd64-obf.zip \
        gs-netcat-${VERSION}-darwin-amd64.tar.gz \
        gs-netcat-${VERSION}-darwin-arm64.tar.gz > SHA256SUMS
else
    sha256sum \
        gs-netcat-${VERSION}-linux-amd64.tar.gz \
        gs-netcat-${VERSION}-windows-amd64.zip \
        gs-netcat-${VERSION}-darwin-amd64.tar.gz \
        gs-netcat-${VERSION}-darwin-arm64.tar.gz > SHA256SUMS
fi

echo
echo "Built and packaged in $OUT:"
ls -la "$OUT"
