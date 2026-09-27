#!/usr/bin/env python3
"""Package the audited SKEngine library as an iOS framework; no code execution."""
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

SOURCE_SHA = "27073a52d57004729be1b5dff473e837d7dfce829e38dea5d9767dcc2a3301f7"
APP = "Payload/Snapchat.app/"
MAIN = APP + "Snapchat"
OLD_LIBRARY = APP + "SKEngine.dylib"
FRAMEWORK = APP + "Frameworks/SKEngine.framework/"
NEW_LIBRARY = FRAMEWORK + "SKEngine"
NEW_PATH = "@rpath/SKEngine.framework/SKEngine"
EXPECTED = {
    MAIN: "0809297a540a291180ef64eba75fafa882b9cab88ee9481b69c1322d4df24205",
    OLD_LIBRARY: "3455d36aad25b3e7f22e2ceab3d37ff76dbd8c21455ecf5b62b5652d1ed3c26b",
}


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def patch_path(original, command, old_path):
    require(original[:4] == bytes.fromhex("cffaedfe"), "Expected ARM64 Mach-O")
    output = bytearray(original)
    meta = parse_macho(original)
    cursor = 32
    commands_end = 32 + struct.unpack_from("<I", original, 20)[0]
    matches = []
    for index in range(struct.unpack_from("<I", original, 16)[0]):
        cmd, size = struct.unpack_from("<II", original, cursor)
        require(size >= 8 and cursor + size <= commands_end, "Invalid command bounds")
        if cmd == command:
            string_offset = struct.unpack_from("<I", original, cursor + 8)[0]
            value = original[cursor + string_offset:cursor + size].split(b"\0", 1)[0]
            if value.decode() == old_path:
                matches.append((cursor, size, string_offset, index))
        cursor += size
    require(cursor == commands_end and len(matches) == 1, "Expected exactly one load path")
    position, size, string_offset, index = matches[0]
    replacement = NEW_PATH.encode() + b"\0"
    needed_size = (string_offset + len(replacement) + 7) & ~7
    final_size = max(size, needed_size)
    growth = final_size - size
    allowed = [(position + string_offset, position + final_size)]
    if growth:
        require(position + size == commands_end, "Only the final command may grow")
        first_data = min(s["offset"] for s in meta["sections"]
                         if s["offset"] and (s["flags"] & 255) not in (1, 12, 18))
        require(commands_end + growth <= first_data, "Insufficient header padding")
        require(not any(original[commands_end:commands_end + growth]), "Nonzero header padding")
        struct.pack_into("<I", output, 20, commands_end - 32 + growth)
        struct.pack_into("<I", output, position + 4, final_size)
        allowed.extend([(20, 24), (position + 4, position + 8)])
    output[position + string_offset:position + final_size] = replacement.ljust(final_size - string_offset, b"\0")
    cursor = 0
    for left, right in sorted(allowed):
        require(original[cursor:left] == output[cursor:left], "Unexpected byte modification")
        cursor = right
    require(original[cursor:] == output[cursor:], "Unexpected trailing modification")
    after = parse_macho(bytes(output))
    expected_meta = copy.deepcopy(meta)
    for dependency in expected_meta["dylibs"]:
        if dependency == {"command": hex(command), "path": old_path}:
            dependency["path"] = NEW_PATH
    require(after == expected_meta, "Unexpected Mach-O metadata change")
    checked = 0
    for section in meta["sections"]:
        if not section["offset"] or (section["flags"] & 255) in (1, 12, 18):
            continue
        start, length = section["offset"], section["size"]
        require(original[start:start + length] == output[start:start + length], "Section changed")
        checked += 1
    return bytes(output), {"load_command_offset": position, "command": hex(command),
                           "old_path": old_path, "new_path": NEW_PATH,
                           "header_padding_used": growth, "sections_identical": checked,
                           "all_other_bytes_identical": True}


def run(source, destination, report_path):
    require(len({source.resolve(), destination.resolve(), report_path.resolve()}) == 3, "Paths must differ")
    require(not destination.exists() and not report_path.exists(), "Output already exists")
    require(digest(source) == SOURCE_SHA, "Expected exact unsigned v0.2.1 IPA")
    destination.parent.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    handle, stage_name = tempfile.mkstemp(prefix=".framework-prep-", dir=destination.parent)
    os.close(handle)
    stage = Path(stage_name)
    try:
        with zipfile.ZipFile(source) as before:
            names = before.namelist()
            require(len(names) == len(set(names)), "Duplicate ZIP members")
            require(not any(n.startswith(FRAMEWORK) for n in names), "Framework already present")
            changes = []
            for path, sha in EXPECTED.items():
                require(hashlib.sha256(before.read(path)).hexdigest() == sha, "Unexpected binary: " + path)
            main, details = patch_path(before.read(MAIN), 0x80000018, "@executable_path/SKEngine.dylib")
            changes.append({"member": MAIN, **details})
            engine = bytearray(before.read(OLD_LIBRARY))
            for index, offset, part in slices(bytes(engine)):
                modified, details = patch_path(part, 0xd, "/Library/MobileSubstrate/DynamicLibraries/SKEngine.dylib")
                require(len(modified) == len(part), "FAT slice size must remain unchanged")
                engine[offset:offset + len(part)] = modified
                changes.append({"member": NEW_LIBRARY, "slice": index, **details})
            info = plistlib.dumps({
                "CFBundleDevelopmentRegion": "en", "CFBundleExecutable": "SKEngine",
                "CFBundleIdentifier": "com.damsptc.sandbox.SKEngine", "CFBundleInfoDictionaryVersion": "6.0",
                "CFBundleName": "SKEngine", "CFBundlePackageType": "FMWK",
                "CFBundleShortVersionString": "1.0", "CFBundleVersion": "1",
                "CFBundleSupportedPlatforms": ["iPhoneOS"], "MinimumOSVersion": "16.0",
            }, fmt=plistlib.FMT_BINARY, sort_keys=True)
            replacements = {MAIN: main, NEW_LIBRARY: bytes(engine), FRAMEWORK + "Info.plist": info}
            with zipfile.ZipFile(stage, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as after:
                after.comment = before.comment
                for entry in before.infolist():
                    updated = copy.copy(entry)
                    updated.filename = NEW_LIBRARY if entry.filename == OLD_LIBRARY else entry.filename
                    updated.compress_type = zipfile.ZIP_DEFLATED
                    if updated.filename in replacements:
                        after.writestr(updated, replacements[updated.filename], compresslevel=6)
                    else:
                        with before.open(entry) as src, after.open(updated, "w") as dst:
                            shutil.copyfileobj(src, dst, 1024 * 1024)
                metadata = zipfile.ZipInfo(FRAMEWORK + "Info.plist", before.getinfo(OLD_LIBRARY).date_time)
                metadata.create_system = 3
                metadata.external_attr = 0o100644 << 16
                metadata.compress_type = zipfile.ZIP_DEFLATED
                after.writestr(metadata, info, compresslevel=6)
            unchanged = 0
            with zipfile.ZipFile(stage) as after:
                expected_names = [NEW_LIBRARY if n == OLD_LIBRARY else n for n in names] + [FRAMEWORK + "Info.plist"]
                require(after.namelist() == expected_names, "Unexpected archive members")
                for entry in after.infolist():
                    content = after.read(entry)
                    if entry.filename in replacements:
                        require(content == replacements[entry.filename], "Modified output mismatch")
                    else:
                        require(content == before.read(entry.filename), "Unrelated file modified")
                        unchanged += 1
                require(OLD_LIBRARY not in after.namelist(), "Stale library path remains")
            report = {
                "source_sha256": SOURCE_SHA, "output_filename": destination.name,
                "output_sha256": digest(stage), "output_bytes": stage.stat().st_size,
                "changes": changes, "moved_library": {"from": OLD_LIBRARY, "to": NEW_LIBRARY},
                "added_info_plist": FRAMEWORK + "Info.plist",
                "verification": {"all_member_crcs_checked": True, "unchanged_members": unchanged,
                                 "all_sections_preserved": True, "architectures_preserved": True,
                                 "scrt_and_profile_patch_unchanged": True,
                                 "signulous_output_checked": False, "ios_installation_tested": False},
                "requires_complete_resigning": True,
                "limitations": ["Experimental framework packaging; Signulous processing must be checked next.",
                                "The app's old signature is invalidated by the load-path change and must be replaced.",
                                "No instruction or data section changes, and no DeviceCheck/App Attest changes.",
                                "No personal Signulous certificate, key or profile is copied into this IPA."],
            }
            with report_path.open("x") as output:
                json.dump(report, output, indent=2)
                output.write("\n")
            os.link(stage, destination)
            return report
    finally:
        stage.unlink(missing_ok=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ipa", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = run(args.ipa, args.output, args.report)
    print(json.dumps({key: report[key] for key in ("output_filename", "output_sha256", "output_bytes", "verification")}, indent=2))
