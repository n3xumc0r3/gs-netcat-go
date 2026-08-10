#!/usr/bin/env python3
"""
Generate resource_windows_amd64.syso for the gs-netcat Windows build.

This .syso embeds two RT resources into the final PE's .rsrc section:
  - RT_VERSION (id=1): VS_VERSIONINFO with real CompanyName/Product/etc.
  - RT_MANIFEST (id=1): Windows app manifest (asInvoker + DPI aware + Win10/11 compat)

Both resources use ID=1 within their own TYPE directories, which is the
standard convention and does not conflict in the resource tree:
  .rsrc/
    RT_VERSION/1/0 (LANGID 0 = neutral) -> VS_VERSIONINFO blob
    RT_MANIFEST/1/0                      -> manifest XML

Output: cmd/gs-netcat/resource_windows_amd64.syso
        (also resource_windows_386.syso, but we don't build 386)

This is the missing piece that made Win32/Wacapew.A!ml flag v0.1.2:
the v0.1.2 binary had NO .rsrc section at all (empty Resource Directory),
which ML classifiers treat as a strong malware indicator (legitimate
Windows apps always have at least VS_VERSIONINFO + a manifest).

We use the `rsrc` tool for the manifest (simple) and `goversioninfo`
for the VS_VERSIONINFO blob, then merge the two .syso files by hand
using coffmerge logic. Actually — go build accepts multiple *.syso
files in the package dir and the linker merges their .rsrc sections.

But there's a simpler trick: goversioninfo alone can emit BOTH the
version info AND a manifest if you pass --manifest. Let's use that.
"""
import os
import subprocess
import sys
import shutil

HERE = os.path.dirname(os.path.abspath(__file__))
GSNETCAT_DIR = os.path.join(HERE, "..", "gsport", "cmd", "gs-netcat")
GSNETCAT_DIR = os.path.abspath(GSNETCAT_DIR)

RSRC = "/home/z/go/bin/rsrc"
GOVERSIONINFO = "/home/z/go/bin/goversioninfo"

MANIFEST = os.path.join(GSNETCAT_DIR, "app.manifest")
VERSION_JSON = os.path.join(GSNETCAT_DIR, "versioninfo.json")
OUT_AMD64 = os.path.join(GSNETCAT_DIR, "resource_windows_amd64.syso")

VERSION_JSON_CONTENT = {
    "FixedFileInfo": {
        "FileVersion":    {"Major": 0, "Minor": 1, "Patch": 4, "Build": 0},
        "ProductVersion": {"Major": 0, "Minor": 1, "Patch": 4, "Build": 0},
        "FileFlagsMask":  "3f",
        "FileFlags":      "00",
        "FileOS":         "040004L",   # VOS_NT_WINDOWS64
        "FileType":       "01",        # VFT_APP
        "FileSubType":    "00",
    },
    "StringFileInfo": {
        "Comments":        "gs-netcat: encrypted GSRN relay pipe for secure remote shell and file transfer.",
        "CompanyName":     "n3xumc0r3",
        "FileDescription": "gs-netcat - secure peer-to-peer relay pipe",
        "FileVersion":     "0.1.4.0",
        "InternalName":    "gs-netcat",
        "LegalCopyright":  "Copyright (c) 2026 n3xumc0r3",
        "LegalTrademarks": "",
        "OriginalFilename": "gs-netcat.exe",
        "PrivateBuild":    "",
        "ProductName":     "gs-netcat",
        "ProductVersion":  "0.1.4.0",
        "SpecialBuild":    "",
    },
    "VarFileInfo": {
        "Translation": {"LangID": "0409", "CharsetID": "04b0"},
    },
    "IconPath": "",
    "ManifestPath": MANIFEST,
}


def main():
    import json
    print(f"[*] Working dir: {GSNETCAT_DIR}")
    print(f"[*] Manifest: {MANIFEST}")

    if not os.path.exists(MANIFEST):
        print(f"[!] Manifest not found: {MANIFEST}", file=sys.stderr)
        return 1

    # Write versioninfo.json
    with open(VERSION_JSON, "w") as f:
        json.dump(VERSION_JSON_CONTENT, f, indent=2)
    print(f"[*] Wrote {VERSION_JSON}")

    # goversioninfo defaults to -64=true (64-bit COFF), which is what we want
    # for the windows/amd64 target. The -o flag sets the output filename.
    # The output .syso includes VS_VERSIONINFO + the manifest XML.
    cmd = [
        GOVERSIONINFO,
        "-64",
        "-propagate-ver-strings",
        f"-o={OUT_AMD64}",
        VERSION_JSON,
    ]
    print(f"[*] Running: {' '.join(cmd)}")
    r = subprocess.run(cmd, cwd=GSNETCAT_DIR, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout)
        print(r.stderr, file=sys.stderr)
        return r.returncode
    print(r.stdout)

    if not os.path.exists(OUT_AMD64):
        print(f"[!] Output .syso not created: {OUT_AMD64}", file=sys.stderr)
        return 1

    size = os.path.getsize(OUT_AMD64)
    print(f"[+] Created {OUT_AMD64}  ({size} bytes)")

    # Verify: dump the COFF symbols from the .syso to confirm .rsrc section.
    print()
    print("[*] Verifying .syso via objdump -h:")
    r = subprocess.run(["objdump", "-h", OUT_AMD64], capture_output=True, text=True)
    print(r.stdout)
    if ".rsrc" not in r.stdout:
        print("[!] .rsrc section NOT found in .syso!", file=sys.stderr)
        return 1
    print("[+] .rsrc section present in .syso. Good.")

    # Clean up the 386 artifact if it was created (goversioninfo default).
    stray_386 = os.path.join(GSNETCAT_DIR, "resource_windows_386.syso")
    if os.path.exists(stray_386):
        os.unlink(stray_386)
        print(f"[*] Removed stray {stray_386} (we only build amd64).")

    # Cleanup intermediate json (keep for reproducibility actually)
    # We'll keep versioninfo.json — it documents how the .syso was built.
    return 0


if __name__ == "__main__":
    sys.exit(main())
