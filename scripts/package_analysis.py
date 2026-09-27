#!/usr/bin/env python3
"""Validate byte coverage and package the audit outputs for a GitHub release."""
import argparse
import json
import zipfile
from pathlib import Path
from analyze_ipa import sha256


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = args.output.resolve()
    summary = json.loads((root / 'analysis/summary.json').read_text())
    ipa = root / 'artifacts' / summary['input_file']
    if sha256(ipa) != summary['sha256']:
        raise ValueError('IPA differs from the audited input')
    binaries = json.loads((root / 'analysis/macho.json').read_text())
    lines = ['# Couverture du désassemblage', '',
        'Analyse linéaire des sections marquées comme instructions. Les octets exclus correspondent aux plages déclarées chiffrées ; les octets non décodés sont représentés par des lignes `.byte`.', '',
        '| Binaire | Tranche | Octets des sections | Octets traités | Chiffrés exclus | Non décodés | Instructions |',
        '| --- | --- | ---: | ---: | ---: | ---: | ---: |']
    totals = [0] * 5
    referenced = set()
    for binary in binaries:
        for item in binary['slices']:
            report = item['disassembly']
            path = root / report['file']
            if sha256(path) != report['sha256']:
                raise ValueError('Disassembly hash mismatch: ' + str(path))
            referenced.add(path.resolve())
            for section in report['sections']:
                if section['processed_bytes'] + section.get('encrypted_bytes_skipped', 0) != section['bytes']:
                    raise ValueError('Incomplete byte accounting: ' + binary['path'])
            stats = [sum(s.get(key, 0) for s in report['sections']) for key in (
                'bytes', 'processed_bytes', 'encrypted_bytes_skipped', 'undecoded_bytes', 'instructions')]
            totals = [a + b for a, b in zip(totals, stats)]
            arch = 'arm64e' if item['cpu_subtype'] & 0xffffff == 2 else item['architecture']
            lines.append('| `' + Path(binary['path']).name + '` | ' + arch + ' | ' +
                         ' | '.join(f'{n:,}'.replace(',', ' ') for n in stats) + ' |')
    actual = {p.resolve() for p in (root / 'disassembly').glob('*.asm.gz')}
    if actual != referenced:
        raise ValueError('Unexpected or missing disassembly files')
    lines.extend(['| **Total** | | ' + ' | '.join(f'{n:,}'.replace(',', ' ') for n in totals) + ' |', '',
        'Les `.asm.gz` comprennent une ligne par instruction ou groupe d’octets non décodés. Les positions de chiffrement et les chemins exacts se trouvent dans `macho.json`. Le comptage ne garantit pas que chaque instruction appartienne à un chemin réellement exécuté.', ''])
    (root / 'analysis/COVERAGE.md').write_text('\n'.join(lines))
    files = [root / name for name in ('README.md', 'requirements.txt', '.gitignore')]
    for directory in ('docs', 'analysis', 'disassembly', 'scripts'):
        files.extend(p for p in (root / directory).rglob('*') if p.is_file() and '__pycache__' not in p.parts)
    destination = root / 'artifacts/Snapchat_desassemblage.zip'
    with zipfile.ZipFile(destination, 'w', allowZip64=True) as archive:
        for path in sorted(files):
            compression = zipfile.ZIP_STORED if path.suffix == '.gz' else zipfile.ZIP_DEFLATED
            archive.write(path, path.relative_to(root).as_posix(), compress_type=compression, compresslevel=6)
    with zipfile.ZipFile(destination) as archive:
        bad_member = archive.testzip()
        if bad_member:
            raise ValueError('ZIP CRC mismatch: ' + bad_member)
    sums = root / 'artifacts/SHA256SUMS.txt'
    sums.write_text(''.join(f'{sha256(path)}  {path.name}\n' for path in (ipa, destination)))
    print(json.dumps(dict(archive=str(destination), size_bytes=destination.stat().st_size,
        files=len(files), disassemblies=len(actual), coverage_totals=totals), indent=2))


if __name__ == '__main__':
    main()
