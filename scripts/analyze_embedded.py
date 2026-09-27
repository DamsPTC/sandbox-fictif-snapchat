#!/usr/bin/env python3
"""Analyze the observed XOR-encoded Assets.der payload, without running it.

Run after analyze_ipa.py. XOR decoding is only a byte transformation; the
Mach-O's declared encrypted ranges remain encrypted and are not disassembled.
"""
import argparse
import gzip
import hashlib
import io
import json
import re
from pathlib import Path
from urllib.parse import urlsplit
from analyze_ipa import MAGICS, slices, parse_macho, disassemble, write_json, sha256


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = args.output.resolve()
    source = root / 'extracted/Payload/Snapchat.app/Assets.der'
    encoded = source.read_bytes()
    data = encoded.translate(bytes(value ^ 0x5a for value in range(256)))
    if data[:4] not in MAGICS:
        raise ValueError('The observed XOR 0x5a encoding does not apply to this file')
    derived = root / 'decoded/Assets.der.xor5a.macho'
    derived.parent.mkdir(parents=True, exist_ok=True)
    derived.write_bytes(data)
    binary = dict(path=derived.relative_to(root).as_posix(), size_bytes=len(data),
        sha256=hashlib.sha256(data).hexdigest(), slices=[],
        provenance=dict(source='Payload/Snapchat.app/Assets.der', source_sha256=hashlib.sha256(encoded).hexdigest(),
                        transform='each byte XOR 0x5a; no execution and no FairPlay decryption'))
    indicators_path = root / 'analysis/indicators.json'
    indicators = json.loads(indicators_path.read_text())
    for index, fat_offset, thin in slices(data):
        label = f'Assets.der.xor5a.slice{index}'
        meta = parse_macho(thin)
        meta['index'], meta['fat_offset'] = index, fat_offset
        symbol_path = root / 'analysis/symbols' / (label + '.json')
        write_json(symbol_path, meta.pop('symbols'))
        meta['symbols_file'] = symbol_path.relative_to(root).as_posix()
        strings = re.findall(rb'[\x20-\x7e]{5,}', thin)
        strings_path = root / 'analysis/strings' / (label + '.txt.gz')
        with strings_path.open('wb') as raw, gzip.GzipFile(filename='',mode='wb',fileobj=raw,mtime=0) as output:
            output.write(b'\n'.join(strings) + b'\n')
        hosts, matches = set(), set()
        for value in strings:
            for url in re.findall(rb'https?://[^\s<>"\x27]+', value):
                try:
                    host = urlsplit(url.decode('ascii')).hostname
                    if host and re.fullmatch(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,63}|[0-9]{1,3})', host):
                        hosts.add(host.lower())
                except ValueError:
                    pass
            if re.search(rb'(snapchat\+\+|snap\+\+|snapbreak|wicked|ss06|devicecheck|attest|substrate|skengine|spoof|bypass)', value, re.I):
                text = value.decode('ascii')
                if len(text) < 500 and '://' not in text:
                    matches.add(text)
        indicators[label] = dict(url_hostnames=sorted(hosts), matching_strings=sorted(matches))
        destination = root / 'disassembly' / (label + '.asm.gz')
        print('Disassemble embedded payload', label, flush=True)
        meta['disassembly'] = disassemble(thin, meta, destination)
        meta['disassembly']['file'] = destination.relative_to(root).as_posix()
        meta['disassembly']['sha256'] = sha256(destination)
        binary['slices'].append(meta)
    macho_path = root / 'analysis/macho.json'
    binaries = [b for b in json.loads(macho_path.read_text()) if b['path'] != binary['path']]
    binaries.append(binary)
    write_json(macho_path, binaries)
    write_json(indicators_path, indicators)
    summary_path = root / 'analysis/summary.json'
    summary = json.loads(summary_path.read_text())
    summary['derived_macho_files'] = 1
    summary['total_macho_files_including_derived'] = len(binaries)
    summary['total_architecture_slices_including_derived'] = sum(len(b['slices']) for b in binaries)
    summary['limitations'][-1] = 'No encrypted code is decrypted; declared encrypted byte ranges are skipped.'
    write_json(summary_path, summary)
    print(json.dumps(binary['slices'][0]['disassembly'], indent=2), flush=True)


if __name__ == '__main__':
    main()
