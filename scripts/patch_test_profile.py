#!/usr/bin/env python3
"""Patch verified SCRT test constants in the v0.1.0 IPA, without executing it.

This changes a User-Agent and internal exemption-list data. It does not
implement hardware/serial spoofing or generate a new Apple DeviceCheck identity.
The resulting IPA requires complete re-signing before installation.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import tempfile
import zipfile
import zlib
from pathlib import Path

from analyze_ipa import parse_macho

IPA_SHA256 = "07765d546d122056e985d05d7673f6d2424007f9b69747688769fee7452cad0d"
SCRT_SHA256 = "8e928a6c91e6ffa32cafb0ad07d9caa3e260d8597b99bc71bb61cf1fbb2387a9"
MEMBER = "Payload/Snapchat.app/Frameworks/SCRT.framework/SCRT"
PROFILE_PATH = Path(__file__).resolve().parents[1] / "profiles/iphone12mini-test.json"


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(8 * 1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def patch_scrt(original, profile):
    require(hashlib.sha256(original).hexdigest() == SCRT_SHA256, "Unexpected SCRT input hash")
    require(profile["model_identifier"] == "iPhone13,1", "This patch targets iPhone 12 mini only")
    require(profile["ios_version"] == "17.4.1" and profile["build"] == "21E236", "Unexpected OS/build pair")
    require(profile["serial_is_synthetic"] is True, "A synthetic test serial is required")
    require(re.fullmatch(r"LAB12M[0-9]{6}", profile["serial"]) is not None, "Use a LAB12M serial with six digits")
    meta = parse_macho(original)
    require(not any(e["cryptid"] for e in meta["encryption"]), "Encrypted SCRT is unsupported")
    cstrings = next(s for s in meta["sections"] if s["name"] == "__cstring")
    cfstrings = next(s for s in meta["sections"] if s["name"] == "__cfstring")
    modified = bytearray(original)
    patches = []

    def replace_string(label, before, after):
        before, after = before.encode("ascii"), after.encode("ascii")
        require(len(after) <= len(before), "Replacement would grow a Mach-O string")
        area = original[cstrings["offset"]:cstrings["offset"] + cstrings["size"]]
        needle = before + b"\0"
        require(area.count(needle) == 1, f"Expected one complete string for {label}")
        offset = cstrings["offset"] + area.index(needle)
        address = cstrings["address"] + offset - cstrings["offset"]
        replacement = after + b"\0" * (len(needle) - len(after))
        modified[offset:offset + len(needle)] = replacement
        patches.append({"label": label, "kind": "cstring", "offset": offset,
                        "before_hex": needle.hex(), "after_hex": replacement.hex(),
                        "before": before.decode(), "after": after.decode()})
        refs = []
        for position in range(cfstrings["offset"], cfstrings["offset"] + cfstrings["size"], 32):
            pointer, length = struct.unpack_from("<QQ", original, position + 16)
            # This hash-pinned image uses low 32-bit image-relative rebase targets.
            if (pointer & ((1 << 36) - 1)) == address:
                require(length == len(before), f"Unexpected CFString length for {label}")
                refs.append(position)
                if len(after) != length:
                    value = struct.pack("<Q", len(after))
                    modified[position + 24:position + 32] = value
                    patches.append({"label": label + " CFString length", "kind": "cfstring_length",
                                    "offset": position + 24,
                                    "before_hex": struct.pack("<Q", length).hex(), "after_hex": value.hex()})
        require(len(refs) == 1, f"Expected one CFString object for {label}")

    replace_string("exemption model", "iPhone10,3", profile["model_identifier"])
    replace_string("exemption serial", "C39VWAELJCLF", profile["serial"])
    # Both old whitelist records use the same model and serial. Preserve the
    # structure and make their build value agree with the one test OS profile.
    replace_string("exemption build A", "20H115", profile["build"])
    replace_string("exemption build B", "20H364", profile["build"])
    replace_string("user agent", "Snapchat/%@ Beta (iPhone10,3; iOS 16.7.12; gzip)",
                   f"Snapchat/%@ Beta ({profile['model_identifier']}; iOS {profile['ios_version']}; gzip)")
    # The other setter uses a shorter iPhone6,1 literal. Redirect its CFString
    # to the new template instead of growing the binary or shifting offsets.
    # Verify the image's chained-rebase format before editing the target bits.
    position = 32
    formats = []
    for _ in range(struct.unpack_from("<I", original, 16)[0]):
        command, size = struct.unpack_from("<II", original, position)
        if command == 0x80000034:  # LC_DYLD_CHAINED_FIXUPS
            fixups = struct.unpack_from("<I", original, position + 8)[0]
            starts = fixups + struct.unpack_from("<I", original, fixups + 4)[0]
            count = struct.unpack_from("<I", original, starts)[0]
            for index in range(count):
                relative = struct.unpack_from("<I", original, starts + 4 + index * 4)[0]
                if relative:
                    formats.append(struct.unpack_from("<H", original, starts + relative + 6)[0])
        position += size
    require(formats and set(formats) == {6}, "Expected DYLD_CHAINED_PTR_64_OFFSET")
    old_template = b"Snapchat/%@ Beta (iPhone6,1; iOS 12.5.7; gzip)"
    new_template = f"Snapchat/%@ Beta ({profile['model_identifier']}; iOS {profile['ios_version']}; gzip)".encode()
    old_offset = original.index(old_template + b"\0")
    new_offset = modified.index(new_template + b"\0")
    old_address = cstrings["address"] + old_offset - cstrings["offset"]
    new_address = cstrings["address"] + new_offset - cstrings["offset"]
    mask = (1 << 36) - 1
    redirected = 0
    for position in range(cfstrings["offset"], cfstrings["offset"] + cfstrings["size"], 32):
        pointer, length = struct.unpack_from("<QQ", original, position + 16)
        if pointer & mask != old_address:
            continue
        require(pointer >> 63 == 0 and length == len(old_template), "Invalid legacy CFString rebase")
        new_pointer = (pointer & ~mask) | new_address
        for label, field, value in [("legacy UA CFString target", position + 16, new_pointer),
                                    ("legacy UA CFString length", position + 24, len(new_template))]:
            replacement = struct.pack("<Q", value)
            patches.append({"label": label, "kind": "cfstring_redirect", "offset": field,
                            "before_hex": original[field:field + 8].hex(), "after_hex": replacement.hex()})
            modified[field:field + 8] = replacement
        require((pointer & ~mask) == (new_pointer & ~mask), "Rebase-chain control bits changed")
        redirected += 1
    require(redirected == 1, "Expected one legacy User-Agent CFString")
    allowed = set()
    for patch in patches:
        for position in range(patch["offset"], patch["offset"] + len(bytes.fromhex(patch["before_hex"]))):
            require(position not in allowed, "Overlapping binary patches")
            allowed.add(position)
    require(len(modified) == len(original), "Mach-O length changed")
    require(all(a == b or i in allowed for i, (a, b) in enumerate(zip(original, modified))), "Unexpected byte change")
    require(parse_macho(bytes(modified)) == meta, "Mach-O metadata changed")
    for section in meta["sections"]:
        if section["flags"] & 0x80000400:
            start, size = section["offset"], section["size"]
            require(original[start:start + size] == modified[start:start + size], "Instruction bytes changed")
    return bytes(modified), patches


def locate_zip_records(path, entries, target, central_start):
    with path.open("rb") as source:
        source.seek(target.header_offset)
        local = source.read(30)
        require(local[:4] == b"PK\x03\x04", "Invalid local ZIP header")
        name_size, extra_size = struct.unpack_from("<HH", local, 26)
        require(source.read(name_size) == MEMBER.encode(), "Wrong local member name")
        data_start = target.header_offset + 30 + name_size + extra_size
        position = central_start
        found = []
        for entry in entries:
            source.seek(position)
            header = source.read(46)
            require(header[:4] == b"PK\x01\x02", "Invalid central ZIP header")
            n, e, c = struct.unpack_from("<HHH", header, 28)
            name = source.read(n)
            require(name.decode("utf-8" if entry.flag_bits & 0x800 else "cp437") == entry.filename,
                    "Central ZIP order mismatch")
            if entry.filename == MEMBER:
                require(struct.unpack_from("<I", header, 42)[0] == target.header_offset, "Wrong local header offset")
                found.append(position)
            position += 46 + n + e + c
        require(len(found) == 1, "Expected one SCRT central-directory record")
        return data_start, found[0]


def verify_archive(original_path, patched_path):
    unchanged = 0
    with zipfile.ZipFile(original_path) as original, zipfile.ZipFile(patched_path) as patched:
        require(original.namelist() == patched.namelist(), "Archive entries changed")
        for left, right in zip(original.infolist(), patched.infolist()):
            require(left.file_size == right.file_size, "Member size changed")
            with original.open(left) as a, patched.open(right) as b:
                while True:
                    x, y = a.read(1024 * 1024), b.read(1024 * 1024)
                    if left.filename != MEMBER:
                        require(x == y, "Unexpected modified member: " + left.filename)
                    if not x and not y:
                        break
            if left.filename != MEMBER:
                unchanged += 1
        # Reading each stream to EOF above also verifies every member's CRC.
    return unchanged


def run(source, output, report_path):
    require(source.resolve() != output.resolve(), "Input and output must differ")
    require(not output.exists() and not report_path.exists(), "Output/report already exists")
    require(digest(source) == IPA_SHA256, "Use the exact v0.1.0-audit release IPA; input hash differs")
    profile = json.loads(PROFILE_PATH.read_text())
    with zipfile.ZipFile(source) as archive:
        entries = archive.infolist()
        require(len({e.filename for e in entries}) == len(entries), "Duplicate ZIP members")
        target = archive.getinfo(MEMBER)
        require(target.compress_type == zipfile.ZIP_STORED and not target.flag_bits & 9,
                "This patch requires an unencrypted stored member without a data descriptor")
        original = archive.read(target)
        modified, patches = patch_scrt(original, profile)
        central_start = archive.start_dir
    data_start, central_header = locate_zip_records(source, entries, target, central_start)
    crc = zlib.crc32(modified) & 0xffffffff
    output.parent.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    handle, staging = tempfile.mkstemp(prefix=".profile-patch-", dir=output.parent)
    os.close(handle)
    staging = Path(staging)
    try:
        shutil.copyfile(source, staging)
        with staging.open("r+b") as destination:
            for patch in patches:
                destination.seek(data_start + patch["offset"])
                destination.write(bytes.fromhex(patch["after_hex"]))
            for offset in (target.header_offset + 14, central_header + 16):
                destination.seek(offset)
                destination.write(struct.pack("<I", crc))
        unchanged = verify_archive(source, staging)
        report = {"profile": profile, "source_sha256": IPA_SHA256,
                  "output_sha256": digest(staging), "output_filename": output.name,
                  "output_bytes": staging.stat().st_size, "modified_member": MEMBER,
                  "original_member_sha256": SCRT_SHA256,
                  "patched_member_sha256": hashlib.sha256(modified).hexdigest(),
                  "binary_patches": patches,
                  "zip_crc_offsets": [target.header_offset + 14, central_header + 16],
                  "zip_member_data_offset": data_start,
                  "verification": {"crc_verified_for_all_members": True,
                                   "unchanged_archive_members": unchanged,
                                   "instruction_bytes_unchanged": True,
                                   "macho_metadata_unchanged": True,
                                   "ios_runtime_tested": False,
                                   "server_requests_observed": False},
                  "requires_resigning": True,
                  "limitations": ["Serial/model/build constants belong to an exemption list, not a hardware identity provider.",
                                  "Both User-Agent CFString objects point to the iPhone12mini template; the unused legacy literal remains in storage.",
                                  "No Apple DeviceCheck or App Attest token is created or modified.",
                                  "Existing code signatures are invalid after patching; re-sign the complete app before installation."]}
        with report_path.open("x", encoding="utf-8") as report_file:
            json.dump(report, report_file, indent=2, ensure_ascii=False)
            report_file.write("\n")
        # Hard-link installation refuses to overwrite a path created concurrently.
        os.link(staging, output)
        return report
    finally:
        staging.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ipa", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = run(args.ipa, args.output, args.report)
    print(json.dumps({k: report[k] for k in ["output_filename", "output_sha256", "verification", "requires_resigning"]}, indent=2))


if __name__ == "__main__":
    main()
