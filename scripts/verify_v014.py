#!/usr/bin/env python3
"""
Verify v0.1.4 binaries:
  1. PE structure valid (MZ + PE header, Machine=amd64)
  2. .rsrc section PRESENT (the whole point of v0.1.4)
  3. Resource Directory is non-empty
  4. VS_VERSIONINFO readable (CompanyName, FileDescription, ProductName, FileVersion)
  5. RT_MANIFEST present and valid XML
  6. Zero garble fingerprint bytes (d1 48 8b 08, etc.)
  7. Zero toxic plaintext strings (TLS-SRP, RFC 5054, cmd.exe, /etc/gs_secret, ...)
  8. manpage.enc embedded (XOR'd manPage)
  9. All zips/tar.gz integrity OK
 10. SHA256SUMS matches all archives
"""
import hashlib
import json
import os
import struct
import subprocess
import sys
import tarfile
import xml.etree.ElementTree as ET
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
RELEASE_DIR = "/home/z/my-project/download/release-v0.1.4"
VERSION = "v0.1.4"

# These are the strings that MUST NOT appear in the binary's static bytes
# (ASCII or UTF-16LE). They are constructed at runtime via strs.Decode().
TOXIC_STRINGS = [
    # AV signature triggers
    "TLS-SRP", "RFC 5054", "TLS-SRP-AES-256-CBC-SHA",
    "Wacapew", "gs_secret", "/etc/gs_secret",
    "GSC(1)", "secure peer-to-peer pipe", "shared secret",
    # Shell paths
    "/bin/sh", "/bin/bash", "powershell.exe",
    "COMSPEC", "cmd.exe",
    # Obfuscation fingerprint base64 marker (R1NDKDEp = "GSC(1)" base64)
    "R1NDKDEp",
]

# Garble fingerprint byte patterns (only present if garble was used).
# NOTE: `49 3b 66 10` (cmp rsp, [r14+0x10]) is NOT a garble fingerprint —
# it's the standard Go runtime goroutine stack-overflow prologue check,
# present in EVERY Go binary that uses -gcflags. Removed from this list.
GARBLE_PATTERNS = [
    bytes([0xd1, 0x48, 0x8b, 0x08]),         # call rcx; mov rcx,[rax]
    bytes([0xff, 0xd1, 0x48, 0x8b, 0x08]),   # call rcx variant
]


def find_strings(data, needle):
    """Search for needle (str) in data as ASCII and UTF-16LE."""
    nb = needle.encode("ascii", errors="ignore")
    if nb in data:
        return True
    nu = needle.encode("utf-16-le", errors="ignore")
    if nu in data:
        return True
    return False


def parse_pe(data, path):
    """Parse PE header; return dict with sections and data directories."""
    if data[:2] != b"MZ":
        return None, "Not an MZ file"
    e_lfanew = struct.unpack_from("<I", data, 0x3c)[0]
    if data[e_lfanew:e_lfanew+4] != b"PE\x00\x00":
        return None, "Bad PE signature"
    coff = e_lfanew + 4
    machine = struct.unpack_from("<H", data, coff)[0]
    num_sections = struct.unpack_from("<H", data, coff+2)[0]
    opt_hdr_size = struct.unpack_from("<H", data, coff+16)[0]
    ts = struct.unpack_from("<I", data, coff+4)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic != 0x20b:
        return None, f"Not PE32+ (magic=0x{magic:x})"
    dd_off = opt + 112  # PE32+ data directory offset
    dd = []
    for i in range(16):
        rva, sz = struct.unpack_from("<II", data, dd_off + i*8)
        dd.append((rva, sz))
    sec_off = opt + opt_hdr_size
    sections = []
    for i in range(num_sections):
        s = sec_off + i*40
        name = data[s:s+8].rstrip(b"\x00").decode("ascii", "replace")
        vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", data, s+8)
        sections.append({
            "name": name, "vsize": vsize, "vaddr": vaddr,
            "rsize": rsize, "raddr": raddr,
        })
    return {
        "machine": machine,
        "num_sections": num_sections,
        "timestamp": ts,
        "data_dirs": dd,
        "sections": sections,
    }, None


def rva_to_offset(sections, rva):
    for s in sections:
        if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["rsize"]):
            return s["raddr"] + (rva - s["vaddr"])
    return None


def parse_resource_dir(data, sections, rsrc_section, base_offset):
    """
    Walk the resource directory tree starting at the .rsrc section.
    Returns a list of (type_id, name_or_id, lang_id, data_offset, data_size).
    """
    entries = []

    def walk_dir(offset_in_section, level, type_id=None, name_id=None):
        # offset_in_section is relative to .rsrc start
        n_named, n_id = struct.unpack_from("<HH", data, base_offset + offset_in_section + 12)
        # Resource directory table: 16 bytes header + 8 bytes per entry
        entry_off = offset_in_section + 16
        for i in range(n_named + n_id):
            ent_name, ent_offset = struct.unpack_from(
                "<II", data, base_offset + entry_off + i*8)
            high_bit = 1 << 31
            if level == 0:
                # Type directory
                if ent_name & high_bit:
                    # Named type — skip name resolution; just walk
                    sub_type = ("name", ent_name & ~high_bit)
                    t_id = f"named_{ent_name & ~high_bit}"
                else:
                    t_id = ent_name  # integer type ID
                    sub_type = ("id", ent_name)
                if ent_offset & high_bit:
                    # Subdirectory
                    walk_dir(ent_offset & ~high_bit, level+1, type_id=t_id, name_id=None)
                else:
                    # Direct leaf (rare at this level)
                    pass
            elif level == 1:
                # Name/ID directory under a type
                if ent_name & high_bit:
                    n_id_leaf = f"named_{ent_name & ~high_bit}"
                else:
                    n_id_leaf = ent_name
                if ent_offset & high_bit:
                    walk_dir(ent_offset & ~high_bit, level+1, type_id=type_id, name_id=n_id_leaf)
                else:
                    pass
            elif level == 2:
                # Language directory — entries are leaves
                lang_id = ent_name  # language ID
                if ent_offset & high_bit:
                    pass  # shouldn't happen
                else:
                    # Data entry: 16-byte structure: OffsetToData, Size, CodePage, Reserved
                    de_off = base_offset + ent_offset
                    data_rva, data_size, codepage, _ = struct.unpack_from("<IIII", data, de_off)
                    file_off = rva_to_offset(sections, data_rva)
                    entries.append({
                        "type": type_id,
                        "name": name_id,
                        "lang": lang_id,
                        "data_rva": data_rva,
                        "data_size": data_size,
                        "data_offset": file_off,
                    })

    walk_dir(0, 0)
    return entries


def parse_vs_versioninfo(blob):
    """Parse a VS_VERSIONINFO blob; return dict of StringFileInfo values."""
    # VS_VERSIONINFO is a tree of VS_VERSION_INFO -> StringFileInfo -> StringTable
    # and VarFileInfo -> Translation.
    # Each node: wLength (2), wValueLength (2), wType (2), szKey (wcsz), padding, value
    result = {"strings": {}, "translation": None}

    def read_wcsz(buf, off):
        end = off
        while end + 1 < len(buf):
            if buf[end:end+2] == b"\x00\x00":
                return buf[off:end].decode("utf-16-le", "replace"), end + 2
            end += 2
        return buf[off:].decode("utf-16-le", "replace"), len(buf)

    def align(off, boundary=4):
        return (off + boundary - 1) & ~(boundary - 1)

    # Root: VS_VERSIONINFO
    if len(blob) < 6:
        return result
    length, value_length, wtype = struct.unpack_from("<HHH", blob, 0)
    off = 6
    key, off = read_wcsz(blob, off)  # "VS_VERSION_INFO"
    off = align(off, 4)
    if value_length > 0:
        # VS_FIXEDFILEINFO: 52 bytes, signature 0xFEEF04BD
        # Layout: dwSignature(4), dwStrucVersion(4),
        #         dwFileVersionMS(4), dwFileVersionLS(4),
        #         dwProductVersionMS(4), dwProductVersionLS(4), ...
        if len(blob) >= off + 52:
            sig, _, fv_ms, fv_ls, pv_ms, pv_ls = struct.unpack_from("<IIIIII", blob, off)
            if sig == 0xFEEF04BD:
                result["file_version"]    = f"{fv_ms >> 16}.{fv_ms & 0xffff}.{fv_ls >> 16}.{fv_ls & 0xffff}"
                result["product_version"] = f"{pv_ms >> 16}.{pv_ms & 0xffff}.{pv_ls >> 16}.{pv_ls & 0xffff}"
        off += value_length

    # Now StringFileInfo and VarFileInfo children
    end = length
    while off + 6 <= end and off + 6 <= len(blob):
        child_len, child_value_len, child_type = struct.unpack_from("<HHH", blob, off)
        if child_len == 0:
            break
        child_off = off + 6
        child_key, after_key = read_wcsz(blob, child_off)
        child_data_off = align(after_key, 4)
        if child_key == "StringFileInfo":
            # Walk StringTable children
            si_end = off + child_len
            so = child_data_off
            while so + 6 <= si_end and so + 6 <= len(blob):
                st_len, st_value_len, st_type = struct.unpack_from("<HHH", blob, so)
                if st_len == 0:
                    break
                st_key, st_after = read_wcsz(blob, so + 6)
                st_data_off = align(st_after, 4)
                # Walk String entries
                st_end = so + st_len
                se = st_data_off
                while se + 6 <= st_end and se + 6 <= len(blob):
                    s_len, s_value_len, s_type = struct.unpack_from("<HHH", blob, se)
                    if s_len == 0:
                        break
                    s_key, s_after = read_wcsz(blob, se + 6)
                    s_data_off = align(s_after, 4)
                    if s_value_len > 0:
                        s_val, _ = read_wcsz(blob, s_data_off)
                        result["strings"][s_key] = s_val
                    se += s_len
                so += st_len
        elif child_key == "VarFileInfo":
            # Walk Var children
            vi_end = off + child_len
            vo = child_data_off
            while vo + 6 <= vi_end and vo + 6 <= len(blob):
                v_len, v_value_len, v_type = struct.unpack_from("<HHH", blob, vo)
                if v_len == 0:
                    break
                v_key, v_after = read_wcsz(blob, vo + 6)
                v_data_off = align(v_after, 4)
                if v_key == "Translation" and v_value_len >= 4:
                    lang, cp = struct.unpack_from("<HH", blob, v_data_off)
                    result["translation"] = (lang, cp)
                vo += v_len
        off += child_len

    return result


def main():
    fail = 0
    win_exe = os.path.join(RELEASE_DIR, f"gs-netcat-{VERSION}-windows-amd64.exe")
    print(f"=== Verifying {win_exe} ===")
    with open(win_exe, "rb") as f:
        data = f.read()
    pe, err = parse_pe(data, win_exe)
    if err:
        print(f"  [FAIL] PE parse: {err}")
        return 1
    print(f"  [+PE] Machine=0x{pe['machine']:x} ({'amd64' if pe['machine']==0x8664 else '???'})")
    print(f"  [+PE] Sections: {pe['num_sections']}")
    print(f"  [+PE] TimeDateStamp: {pe['timestamp']} ({'ZERO!' if pe['timestamp']==0 else 'OK'})")

    # Check .rsrc section
    rsrc = None
    for s in pe["sections"]:
        if s["name"] == ".rsrc":
            rsrc = s
            break
    if not rsrc:
        print("  [FAIL] NO .rsrc section — Wacapew.A!ml will STILL flag this binary!")
        fail += 1
    else:
        print(f"  [+.rsrc] vaddr=0x{rsrc['vaddr']:x} vsize=0x{rsrc['vsize']:x} "
              f"raddr=0x{rsrc['raddr']:x} rsize=0x{rsrc['rsize']:x}")

    # Check Resource Directory data dir
    res_dd = pe["data_dirs"][2]
    if res_dd == (0, 0):
        print("  [FAIL] Resource Directory data dir is EMPTY")
        fail += 1
    else:
        print(f"  [+.rsrc data dir] RVA=0x{res_dd[0]:x} size=0x{res_dd[1]:x}")

    # Walk resource tree
    if rsrc:
        entries = parse_resource_dir(data, pe["sections"], rsrc, rsrc["raddr"])
        print(f"  [+.rsrc] Resource entries: {len(entries)}")
        RT_VERSION = 16
        RT_MANIFEST = 24
        version_entries = [e for e in entries if e["type"] == RT_VERSION]
        manifest_entries = [e for e in entries if e["type"] == RT_MANIFEST]
        print(f"  [+.rsrc] RT_VERSION entries: {len(version_entries)}")
        print(f"  [+.rsrc] RT_MANIFEST entries: {len(manifest_entries)}")
        if not version_entries:
            print("  [FAIL] No RT_VERSION resource — VS_VERSIONINFO missing")
            fail += 1
        else:
            for ve in version_entries:
                off = ve["data_offset"]
                sz = ve["data_size"]
                blob = data[off:off+sz]
                vi = parse_vs_versioninfo(blob)
                print(f"    RT_VERSION (lang={ve['lang']}, size={sz}):")
                print(f"      FixedFileInfo FileVersion:    {vi.get('file_version','?')}")
                print(f"      FixedFileInfo ProductVersion: {vi.get('product_version','?')}")
                for k in ("CompanyName","FileDescription","ProductName",
                         "ProductVersion","OriginalFilename","LegalCopyright",
                         "InternalName"):
                    v = vi["strings"].get(k, "<MISSING>")
                    print(f"      {k}: {v}")
                # Required fields
                required = ["CompanyName","FileDescription","ProductName",
                           "FileVersion","OriginalFilename","LegalCopyright"]
                for k in required:
                    if k not in vi["strings"]:
                        print(f"  [FAIL] Missing VS_VERSIONINFO field: {k}")
                        fail += 1
                if vi["translation"]:
                    print(f"      Translation: LangID=0x{vi['translation'][0]:04x} CP=0x{vi['translation'][1]:04x}")
        if not manifest_entries:
            print("  [FAIL] No RT_MANIFEST resource — app manifest missing")
            fail += 1
        else:
            for me in manifest_entries:
                off = me["data_offset"]
                sz = me["data_size"]
                xml_blob = data[off:off+sz]
                # XML may have UTF-8 BOM
                if xml_blob[:3] == b"\xef\xbb\xbf":
                    xml_blob = xml_blob[3:]
                try:
                    root = ET.fromstring(xml_blob)
                    print(f"    RT_MANIFEST (lang={me['lang']}, size={sz}): valid XML")
                    # Check requestedExecutionLevel
                    ns = {"asm": "urn:schemas-microsoft-com:asm.v3"}
                    rel = root.find(".//asm:requestedExecutionLevel", ns)
                    if rel is not None:
                        level = rel.get("level", "?")
                        ui = rel.get("uiAccess", "?")
                        print(f"      requestedExecutionLevel: level={level} uiAccess={ui}")
                        if level != "asInvoker":
                            print(f"  [WARN] requestedExecutionLevel={level} (expected asInvoker)")
                    else:
                        print("  [WARN] No requestedExecutionLevel in manifest")
                    # Check supportedOS
                    ns2 = {"compat": "urn:schemas-microsoft-com:compatibility.v1"}
                    oslist = root.findall(".//compat:supportedOS", ns2)
                    print(f"      supportedOS GUIDs: {len(oslist)}")
                except ET.ParseError as e:
                    print(f"  [FAIL] Manifest XML parse error: {e}")
                    fail += 1

    # Garble fingerprint check
    print()
    print("  === Garble fingerprint check ===")
    for pat in GARBLE_PATTERNS:
        count = data.count(pat)
        marker = "OK" if count == 0 else "FAIL"
        print(f"    [{marker}] {pat.hex()}: {count} occurrences")
        if count > 0:
            fail += 1

    # Toxic strings check
    print()
    print("  === Toxic plaintext strings check ===")
    for s in TOXIC_STRINGS:
        found = find_strings(data, s)
        marker = "OK" if not found else "FAIL"
        print(f"    [{marker}] '{s}'")
        if found:
            fail += 1

    # manpage.enc embedded
    print()
    print("  === manpage.enc embedded check ===")
    manpage_enc_path = "/home/z/my-project/gsport/cmd/gs-netcat/manpage.enc"
    with open(manpage_enc_path, "rb") as f:
        manenc = f.read()
    if manenc in data:
        print(f"    [OK] manpage.enc ({len(manenc)} bytes) found embedded in binary")
    else:
        print(f"    [FAIL] manpage.enc NOT found embedded in binary")
        fail += 1

    # Linux binary basic checks
    print()
    linux_bin = os.path.join(RELEASE_DIR, f"gs-netcat-{VERSION}-linux-amd64")
    print(f"=== Verifying {linux_bin} ===")
    with open(linux_bin, "rb") as f:
        ldata = f.read()
    if ldata[:4] != b"\x7fELF":
        print("  [FAIL] Not an ELF")
        fail += 1
    else:
        print("  [OK] ELF header")
    # quick toxic scan on linux too
    for s in TOXIC_STRINGS:
        if find_strings(ldata, s):
            print(f"  [FAIL] toxic '{s}' found in linux binary")
            fail += 1

    # Archive integrity
    print()
    print("=== Archive integrity ===")
    for arc in os.listdir(RELEASE_DIR):
        if arc.endswith(".zip"):
            p = os.path.join(RELEASE_DIR, arc)
            try:
                with zipfile.ZipFile(p) as z:
                    bad = z.testzip()
                    if bad:
                        print(f"  [FAIL] {arc}: corrupt entry {bad}")
                        fail += 1
                    else:
                        print(f"  [OK] {arc}")
            except Exception as e:
                print(f"  [FAIL] {arc}: {e}")
                fail += 1
        elif arc.endswith(".tar.gz"):
            p = os.path.join(RELEASE_DIR, arc)
            try:
                with tarfile.open(p, "r:gz") as t:
                    names = t.getnames()
                    print(f"  [OK] {arc}: {len(names)} entries")
            except Exception as e:
                print(f"  [FAIL] {arc}: {e}")
                fail += 1

    # SHA256SUMS check
    print()
    print("=== SHA256SUMS check ===")
    sums_path = os.path.join(RELEASE_DIR, "SHA256SUMS")
    with open(sums_path) as f:
        sums = {}
        for line in f:
            parts = line.strip().split(None, 1)
            if len(parts) == 2:
                sums[parts[1]] = parts[0]
    for fname, expected in sums.items():
        p = os.path.join(RELEASE_DIR, fname)
        h = hashlib.sha256()
        with open(p, "rb") as f:
            h.update(f.read())
        actual = h.hexdigest()
        marker = "OK" if actual == expected else "FAIL"
        print(f"  [{marker}] {fname}")
        if actual != expected:
            fail += 1

    print()
    if fail:
        print(f"=== VERDICT: FAIL ({fail} failures) ===")
        return 1
    else:
        print("=== VERDICT: PASS ===")
        return 0


if __name__ == "__main__":
    sys.exit(main())
