#!/usr/bin/env python3
"""Prepare v0.2.0 for another signing attempt; this does not sign an IPA.

Remove the stale signatures of CydiaSubstrate and both SKEngine slices. Keep
all executable sections, dependencies, symbols and application data intact.
Only the exact audited input is accepted. No binary is executed.
"""
import argparse
import copy
import hashlib
import json
import os
import plistlib
import shutil
import struct
import tempfile
import zipfile
from pathlib import Path

from analyze_ipa import parse_macho, slices

SOURCE_SHA256 = "1aa15e724ee46b9170b4b8a98fa67a6ce86c1422b28e026543aaa6c8b6551f95"
TARGETS = {
    "Payload/Snapchat.app/Frameworks/CydiaSubstrate.framework/CydiaSubstrate":
        "a1d7f23bedb4508cc5332caa8c1fa2b0826da4e85b763217ffe5b5e8f8dfe54f",
    "Payload/Snapchat.app/SKEngine.dylib":
        "8a9ed3123b64d7c0d1a9daff6312c64c8006de2a34f97a7e5b6185c035116204",
}
REMOVED = {
    "Payload/Snapchat.app/_CodeSignature/",
    "Payload/Snapchat.app/_CodeSignature/CodeResources",
    "Payload/Snapchat.app/Frameworks/CydiaSubstrate.framework/_CodeSignature/",
    "Payload/Snapchat.app/Frameworks/CydiaSubstrate.framework/_CodeSignature/CodeResources",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def strip_thin(original):
    require(original[:4] == bytes.fromhex("cffaedfe"), "Expected little-endian 64-bit Mach-O")
    meta = parse_macho(original)
    require(not any(e["cryptid"] for e in meta["encryption"]), "Encrypted target is unsupported")
    count, commands_size = struct.unpack_from("<II", original, 16)
    commands_end = 32 + commands_size
    cursor = 32
    signature = None
    linkedit = None
    symtab = None
    for _ in range(count):
        cmd, size = struct.unpack_from("<II", original, cursor)
        require(size >= 8 and cursor + size <= commands_end, "Invalid load command")
        if cmd == 0x1d:
            require(signature is None and size == 16, "Unexpected code-signature command")
            require(cursor + size == commands_end, "Code signature must be the last load command")
            signature = (cursor, *struct.unpack_from("<II", original, cursor + 8))
        if cmd == 0x19 and original[cursor+8:cursor+24].rstrip(b"\0") == b"__LINKEDIT":
            require(linkedit is None, "Duplicate LINKEDIT segment")
            linkedit = (cursor, *struct.unpack_from("<QQQQ", original, cursor + 24))
        if cmd == 2:
            require(symtab is None, "Duplicate symbol table")
            symtab = struct.unpack_from("<4I", original, cursor + 8)
        cursor += size
    require(cursor == commands_end and signature and linkedit and symtab, "Required metadata missing")
    sig_cmd, sig_offset, sig_size = signature
    link_cmd, vmaddr, vmsize, fileoff, filesize = linkedit
    symoff, nsyms, stroff, strsize = symtab
    data_end = stroff + strsize
    require(fileoff + filesize == len(original), "LINKEDIT must end at EOF")
    require(fileoff <= symoff and symoff + nsyms * 16 <= stroff, "Invalid symbol table bounds")
    require(data_end <= sig_offset and sig_offset - data_end < 16, "Unexpected signature alignment")
    require(not any(original[data_end:sig_offset]), "Nonzero data before the signature")
    require(sig_offset + sig_size <= len(original), "Signature exceeds the file")
    require(len(original) - (sig_offset + sig_size) < 16, "Unexpected trailing bytes")
    require(not any(original[sig_offset + sig_size:]), "Nonzero bytes after the signature")
    magic, length, blobs = struct.unpack_from(">III", original, sig_offset)
    require(magic == 0xfade0cc0 and length <= sig_size, "Invalid embedded signature")
    for i in range(blobs):
        slot, relative = struct.unpack_from(">II", original, sig_offset + 12 + 8 * i)
        _, blob_size = struct.unpack_from(">II", original, sig_offset + relative)
        require(relative + blob_size <= length, "Signature blob out of bounds")
        if slot == 5:
            entitlements = plistlib.loads(original[sig_offset + relative + 8:sig_offset + relative + blob_size])
            require(entitlements == {}, "Do not silently discard nonempty entitlements")
    modified = bytearray(original[:data_end])
    struct.pack_into("<II", modified, 16, count - 1, commands_size - 16)
    struct.pack_into("<Q", modified, link_cmd + 48, data_end - fileoff)
    modified[sig_cmd:sig_cmd + 16] = bytes(16)
    # Keep virtual layout unchanged. Only shrink the final file-backed range,
    # as in the removal path of Apple's codesign_allocate.
    allowed = set(range(16, 24)) | set(range(link_cmd + 48, link_cmd + 56)) | set(range(sig_cmd, sig_cmd + 16))
    require(all(a == b or i in allowed for i, (a, b) in enumerate(zip(original, modified))),
            "Unexpected modification before the removed signature")
    require(parse_macho(bytes(modified)) == meta, "Sections, symbols or dependencies changed")
    checked = 0
    for section in meta["sections"]:
        # Zerofill sections have no bytes stored in the file.
        if section["flags"] & 0xff in (1, 0xc, 0x12):
            continue
        start, size = section["offset"], section["size"]
        require(start + size <= data_end, "Section would be truncated")
        require(original[start:start+size] == modified[start:start+size], "Section bytes changed")
        checked += 1
    return bytes(modified), {
        "architecture": meta["architecture"], "cpu_subtype": meta["cpu_subtype"],
        "original_bytes": len(original), "output_bytes": len(modified),
        "removed_bytes": len(original) - len(modified), "sections_preserved": checked,
        "original_signature_offset": sig_offset, "original_signature_bytes": sig_size,
        "output_has_code_signature": False, "virtual_layout_unchanged": True,
        "symbols_and_dependencies_unchanged": True,
    }


def strip_binary(original):
    parts = list(slices(original))
    if original[:4] == bytes.fromhex("cffaedfe"):
        output, report = strip_thin(original)
        return output, [report]
    require(original[:4] == bytes.fromhex("cafebabe") and len(parts) == 2,
            "Only the audited two-slice FAT32 file is supported")
    output = bytearray(original)
    reports = []
    previous_end = 8 + 20 * len(parts)
    last_end = None
    for index, offset, data in parts:
        cpu, subtype, recorded_offset, size, alignment = struct.unpack_from(">5I", original, 8 + index * 20)
        require(recorded_offset == offset and size == len(data), "FAT architecture mismatch")
        require(offset % (1 << alignment) == 0, "Unaligned FAT slice")
        require(not any(original[previous_end:offset]), "Unexpected data between FAT slices")
        require(struct.unpack_from("<II", data, 4) == (cpu, subtype), "FAT/thin CPU mismatch")
        modified, report = strip_thin(data)
        output[offset:offset + len(modified)] = modified
        output[offset + len(modified):offset + size] = bytes(size - len(modified))
        struct.pack_into(">I", output, 8 + index * 20 + 12, len(modified))
        report.update({"fat_index": index, "fat_offset_unchanged": offset})
        reports.append(report)
        previous_end = offset + size
        last_end = offset + len(modified)
    require(not any(original[previous_end:]), "Unexpected FAT trailer")
    del output[last_end:]
    require(len(list(slices(output))) == len(parts), "Lost a FAT architecture")
    return bytes(output), reports


def verify_archive(source, output, replacements):
    unchanged = 0
    with zipfile.ZipFile(source) as before, zipfile.ZipFile(output) as after:
        require(after.namelist() == [name for name in before.namelist() if name not in REMOVED],
                "Unexpected archive member list")
        for entry in after.infolist():
            original = before.getinfo(entry.filename)
            require(entry.external_attr == original.external_attr and entry.date_time == original.date_time,
                    "File permissions or timestamps changed")
            if entry.filename in replacements:
                require(after.read(entry) == replacements[entry.filename], "Incorrect modified member")
            else:
                with before.open(original) as a, after.open(entry) as b:
                    while True:
                        left, right = a.read(1024 * 1024), b.read(1024 * 1024)
                        require(left == right, "Unexpected content change: " + entry.filename)
                        if not left:
                            break
                unchanged += 1
    return unchanged


def run(source, output, report_path):
    require(len({source.resolve(), output.resolve(), report_path.resolve()}) == 3, "Paths must differ")
    require(not output.exists() and not report_path.exists(), "Output already exists")
    require(digest(source) == SOURCE_SHA256, "Expected the exact unsigned v0.2.0-profile-test IPA")
    replacements, changes = {}, []
    with zipfile.ZipFile(source) as archive:
        entries = archive.infolist()
        require(len({e.filename for e in entries}) == len(entries), "Duplicate ZIP members")
        require(REMOVED.issubset(archive.namelist()), "Expected resource seals missing")
        for member, expected_hash in TARGETS.items():
            data = archive.read(member)
            require(hashlib.sha256(data).hexdigest() == expected_hash, "Unexpected target binary: " + member)
            modified, details = strip_binary(data)
            replacements[member] = modified
            changes.append({"member": member, "original_sha256": expected_hash,
                            "output_sha256": hashlib.sha256(modified).hexdigest(), "slices": details})
        output.parent.mkdir(parents=True, exist_ok=True)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        handle, staging = tempfile.mkstemp(prefix=".resign-prep-", dir=output.parent)
        os.close(handle)
        staging = Path(staging)
        try:
            with zipfile.ZipFile(staging, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as result:
                result.comment = archive.comment
                for original in entries:
                    if original.filename in REMOVED:
                        continue
                    entry = copy.copy(original)
                    entry.compress_type = zipfile.ZIP_DEFLATED
                    if entry.filename in replacements:
                        result.writestr(entry, replacements[entry.filename], compresslevel=6)
                    else:
                        with archive.open(original) as src, result.open(entry, "w") as dst:
                            shutil.copyfileobj(src, dst, 1024 * 1024)
            unchanged = verify_archive(source, staging, replacements)
            report = {
                "source_sha256": SOURCE_SHA256, "output_filename": output.name,
                "output_sha256": digest(staging), "output_bytes": staging.stat().st_size,
                "modified_members": changes, "removed_members": sorted(REMOVED),
                "verification": {"all_member_crcs_checked": True, "unchanged_members": unchanged,
                                 "all_target_sections_unchanged": True, "architectures_preserved": True,
                                 "profile_patch_unchanged": True, "devicecheck_unchanged": True,
                                 "signed_ipa_validated": False, "ios_installation_tested": False},
                "requires_complete_resigning": True,
                "limitations": [
                    "Experimental preparation for re-signing, not an installable or Apple-signed IPA.",
                    "Only two libraries have their stale signatures removed; other existing signatures still require re-signing.",
                    "No signing key, certificate or provisioning profile from the user's Signulous download is included.",
                    "No change to instructions, app behavior, DeviceCheck, App Attest, or the v0.2.0 profile patch.",
                    "Whether Signulous now processes these libraries must be checked in the next signed output.",
                ],
            }
            with report_path.open("x", encoding="utf-8") as destination:
                json.dump(report, destination, ensure_ascii=False, indent=2)
                destination.write("\n")
            os.link(staging, output)
            return report
        finally:
            staging.unlink(missing_ok=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ipa", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = run(args.ipa, args.output, args.report)
    print(json.dumps({key: report[key] for key in ("output_filename", "output_sha256", "output_bytes", "verification")}, indent=2))
