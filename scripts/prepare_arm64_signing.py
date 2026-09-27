#!/usr/bin/env python3
"""Extract SKEngine's existing ARM64 slice for an isolated signing test."""
import argparse
import copy
import hashlib
import json
import os
import shutil
import struct
import tempfile
import zipfile
from pathlib import Path

from analyze_ipa import parse_macho, slices

SOURCE_SHA = "3cd1f09f17abc56894bb278654761abc85a8accf87ed1270d58842a536619f23"
MEMBER = "Payload/Snapchat.app/Frameworks/SKEngine.framework/SKEngine"
FAT_SHA = "a86f711efbda2e102872d4e04293f0d4176925787672db482a73080027bf6610"
ARM64_SHA = "b8d3be0d1f251c7b65a834a3cc5fb6a4963d13473be2794ed0b26388d474d1b7"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(source, destination, report_path):
    require(len({source.resolve(), destination.resolve(), report_path.resolve()}) == 3, "Paths must differ")
    require(not destination.exists() and not report_path.exists(), "Output already exists")
    require(digest(source) == SOURCE_SHA, "Expected exact unsigned v0.2.2 IPA")
    destination.parent.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    handle, stage_name = tempfile.mkstemp(prefix=".arm64-signing-", dir=destination.parent)
    os.close(handle)
    stage = Path(stage_name)
    try:
        with zipfile.ZipFile(source) as before:
            names = before.namelist()
            require(len(names) == len(set(names)), "Duplicate ZIP members")
            fat = before.read(MEMBER)
            require(hashlib.sha256(fat).hexdigest() == FAT_SHA, "Unexpected SKEngine")
            architectures = list(slices(fat))
            require(len(architectures) == 2, "Expected two source architectures")
            selected = [(i, off, data) for i, off, data in architectures
                        if data[:4] == bytes.fromhex("cffaedfe")
                        and struct.unpack_from("<II", data, 4) == (0x100000c, 0)]
            require(len(selected) == 1, "Expected one ordinary ARM64 slice")
            index, offset, thin = selected[0]
            require(hashlib.sha256(thin).hexdigest() == ARM64_SHA, "Unexpected ARM64 contents")
            metadata = parse_macho(thin)
            require(metadata["file_type"] == 6, "Expected a dynamic library")
            require({"command": "0xd", "path": "@rpath/SKEngine.framework/SKEngine"} in metadata["dylibs"],
                    "Unexpected framework install name")
            require(not any(e["cryptid"] for e in metadata["encryption"]), "Encrypted input")
            with zipfile.ZipFile(stage, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as after:
                after.comment = before.comment
                for entry in before.infolist():
                    updated = copy.copy(entry)
                    updated.compress_type = zipfile.ZIP_DEFLATED
                    if entry.filename == MEMBER:
                        after.writestr(updated, thin, compresslevel=6)
                    else:
                        with before.open(entry) as src, after.open(updated, "w") as dst:
                            shutil.copyfileobj(src, dst, 1024 * 1024)
            with zipfile.ZipFile(stage) as after:
                require(after.namelist() == names, "Archive members changed")
                for entry in after.infolist():
                    original = before.getinfo(entry.filename)
                    require(entry.external_attr == original.external_attr and entry.date_time == original.date_time,
                            "Permissions or timestamps changed")
                    expected = thin if entry.filename == MEMBER else before.read(entry.filename)
                    require(after.read(entry) == expected, "Content or CRC mismatch: " + entry.filename)
            report = {
                "source_sha256": SOURCE_SHA, "output_filename": destination.name,
                "output_sha256": digest(stage), "output_bytes": stage.stat().st_size,
                "modified_member": MEMBER, "old_binary_sha256": FAT_SHA, "new_binary_sha256": ARM64_SHA,
                "source_slice_index": index, "source_slice_offset": offset,
                "old_binary_bytes": len(fat), "new_binary_bytes": len(thin),
                "kept_architecture": "arm64", "removed_architecture": "arm64e",
                "verification": {"extracted_slice_byte_identical": True,
                                 "all_other_members_identical": len(names) - 1,
                                 "all_member_crcs_checked": True, "permissions_and_timestamps_preserved": True,
                                 "app_load_path_and_framework_info_unchanged": True,
                                 "signulous_output_checked": False, "ios_installation_tested": False},
                "requires_complete_resigning": True,
                "limitations": ["This tests whether the universal binary format is why Signulous skips SKEngine.",
                                "The cause inside Signulous is not established; signing and installation are untested.",
                                "ARM64e is removed, not converted. The existing ARM64 slice is copied without edits.",
                                "No personal Signulous certificate, key or profile is added."],
            }
            with report_path.open("x") as out:
                json.dump(report, out, indent=2)
                out.write("\n")
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
    print(json.dumps({k: report[k] for k in ("output_filename", "output_sha256", "output_bytes", "verification")}, indent=2))
