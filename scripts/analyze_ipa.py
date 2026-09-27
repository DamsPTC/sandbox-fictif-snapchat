#!/usr/bin/env python3
"""Offline inventory and linear disassembly of an IPA; never executes its code."""
import argparse
import gzip
import hashlib
import io
import json
import plistlib
import re
import struct
import zipfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

MAGICS = {bytes.fromhex(x) for x in (
    'cffaedfe', 'cefaedfe', 'feedfacf', 'feedface',
    'cafebabe', 'bebafeca', 'cafebabf', 'bfbafeca')}
DYLIB_COMMANDS = {0xc, 0xd, 0x18, 0x1f, 0x20, 0x23}


def sha256(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(8 * 1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def name(raw):
    return raw.split(b'\0', 1)[0].decode('utf-8', 'replace')


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n')


def slices(data):
    magic = data[:4]
    if magic in (b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf',
                 b'\xbe\xba\xfe\xca', b'\xbf\xba\xfe\xca'):
        endian = '>' if magic[:2] == b'\xca\xfe' else '<'
        fat64 = magic in (b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca')
        count = struct.unpack_from(endian + 'I', data, 4)[0]
        if count > 64:
            raise ValueError('Invalid FAT architecture count')
        fmt = endian + ('IIQQII' if fat64 else 'IIIII')
        for index in range(count):
            values = struct.unpack_from(fmt, data, 8 + index * struct.calcsize(fmt))
            offset, size = values[2:4]
            if offset + size > len(data):
                raise ValueError('FAT slice outside file')
            yield index, offset, data[offset:offset + size]
    else:
        yield 0, 0, data


def parse_macho(data):
    magic = data[:4]
    endian = '<' if magic in (b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe') else '>'
    is64 = magic in (b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf')
    if magic not in MAGICS or magic in (b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf'):
        raise ValueError('Invalid thin Mach-O')
    header = struct.unpack_from(endian + '7I', data)
    cpu, subtype, filetype, ncmds, sizeofcmds, flags = header[1:]
    pos = 32 if is64 else 28
    end = pos + sizeofcmds
    if end > len(data) or ncmds > 65536:
        raise ValueError('Invalid Mach-O load commands')
    result = dict(cpu_type=cpu, cpu_subtype=subtype, is_64_bit=is64,
                  architecture={0x100000c: 'arm64', 0xc: 'arm', 0x1000007: 'x86_64', 7: 'x86'}.get(cpu, 'unknown'),
                  file_type=filetype, flags=flags, sections=[], dylibs=[], rpaths=[], encryption=[], symbols=[])
    for _ in range(ncmds):
        cmd, size = struct.unpack_from(endian + 'II', data, pos)
        if size < 8 or pos + size > end:
            raise ValueError('Invalid load-command size')
        basecmd = cmd & 0x7fffffff
        if basecmd in DYLIB_COMMANDS:
            str_off = struct.unpack_from(endian + 'I', data, pos + 8)[0]
            result['dylibs'].append(dict(command=hex(cmd), path=name(data[pos + str_off:pos + size])))
        elif basecmd == 0x1c:
            str_off = struct.unpack_from(endian + 'I', data, pos + 8)[0]
            result['rpaths'].append(name(data[pos + str_off:pos + size]))
        elif basecmd in (0x21, 0x2c):
            off, length, cryptid = struct.unpack_from(endian + 'III', data, pos + 8)
            result['encryption'].append(dict(offset=off, size=length, cryptid=cryptid))
        elif basecmd in (1, 0x19):
            seg64 = basecmd == 0x19
            segment_fmt = endian + ('II16sQQQQiiII' if seg64 else 'II16sIIIIiiII')
            segment = struct.unpack_from(segment_fmt, data, pos)
            section_fmt = endian + ('16s16sQQIIIIIIII' if seg64 else '16s16sIIIIIIIII')
            secpos = pos + struct.calcsize(segment_fmt)
            nsects = segment[-2]
            if secpos + nsects * struct.calcsize(section_fmt) > pos + size:
                raise ValueError('Sections exceed segment command')
            for j in range(nsects):
                sec = struct.unpack_from(section_fmt, data, secpos + j * struct.calcsize(section_fmt))
                result['sections'].append(dict(name=name(sec[0]), segment=name(sec[1]),
                    address=sec[2], size=sec[3], offset=sec[4], flags=sec[8]))
        elif basecmd == 2:
            symoff, nsyms, stroff, strsize = struct.unpack_from(endian + 'IIII', data, pos + 8)
            symfmt = endian + ('IBBHQ' if is64 else 'IBBHI')
            symsize = struct.calcsize(symfmt)
            if symoff + nsyms * symsize > len(data) or stroff + strsize > len(data):
                raise ValueError('Symbol table outside file')
            for j in range(nsyms):
                strx, typ, sect, desc, value = struct.unpack_from(symfmt, data, symoff + j * symsize)
                if strx < strsize:
                    endstr = data.find(b'\0', stroff + strx, stroff + strsize)
                    if endstr >= 0:
                        result['symbols'].append(dict(name=data[stroff + strx:endstr].decode('utf-8','replace'),
                            type=typ, section=sect, address=value))
        pos += size
    return result


def disassemble(data, meta, destination):
    import capstone
    cpu = meta['cpu_type']
    if cpu == 0x100000c:
        decoder = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        block_size = 65536
    elif cpu in (7, 0x1000007):
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if cpu == 0x1000007 else capstone.CS_MODE_32)
        block_size = None
    else:
        return dict(status='unsupported_architecture', sections=[])
    decoder.skipdata = True
    decoder.detail = False
    report = dict(status='complete', engine='Capstone ' + capstone.__version__,
                  method='linear sweep of sections marked as instructions', sections=[])
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open('wb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0, compresslevel=1) as gz:
        with io.TextIOWrapper(gz, encoding='utf-8', newline='\n') as out:
            out.write('; Linear disassembly. Literal data and unreachable bytes may be decoded as instructions.\n')
            out.write('; This is not recovered source code. .byte marks bytes not decoded by Capstone.\n')
            for section in meta['sections']:
                if not (section['flags'] & 0x80000400):
                    continue
                start, length = section['offset'], section['size']
                entry = dict(section=section['segment'] + ',' + section['name'], bytes=length,
                             virtual_address=hex(section['address']), instructions=0, undecoded_bytes=0, processed_bytes=0,
                             encrypted_bytes_skipped=0)
                report['sections'].append(entry)
                if start + length > len(data):
                    raise ValueError('Instruction section outside file')
                out.write('\n; SECTION ' + entry['section'] + '\n')
                code = data[start:start + length]
                chunk_size = block_size or max(length, 1)
                intervals = [(0, length)]
                for encrypted in meta['encryption']:
                    if not encrypted['cryptid']:
                        continue
                    lo = max(0, encrypted['offset'] - start)
                    hi = min(length, encrypted['offset'] + encrypted['size'] - start)
                    if lo >= hi:
                        continue
                    remaining = []
                    for left, right in intervals:
                        if hi <= left or lo >= right:
                            remaining.append((left, right))
                            continue
                        if left < lo:
                            remaining.append((left, lo))
                        if hi < right:
                            remaining.append((hi, right))
                    intervals = remaining
                entry['encrypted_bytes_skipped'] = length - sum(r-l for l,r in intervals)
                if entry['encrypted_bytes_skipped']:
                    report['status'] = 'partial'
                    out.write('; Encrypted ranges are omitted; see analysis/macho.json.\n')
                blocks = ((offset, min(chunk_size, right-offset))
                          for left, right in intervals for offset in range(left, right, chunk_size))
                for offset, count in blocks:
                    block = code[offset:offset + count]
                    base = section['address'] + offset
                    covered = 0
                    lines = []
                    for addr, insn_size, mnemonic, operands in decoder.disasm_lite(block, base):
                        local = addr - base
                        lines.append(f'{addr:016x}  {block[local:local+insn_size].hex():<30}  {mnemonic:<10} {operands}\n')
                        covered += insn_size
                        if mnemonic == '.byte':
                            entry['undecoded_bytes'] += insn_size
                        else:
                            entry['instructions'] += 1
                    if covered < len(block):
                        tail = block[covered:]
                        lines.append(f'{base+covered:016x}  {tail.hex()}  .byte ; trailing undecoded bytes\n')
                        entry['undecoded_bytes'] += len(tail)
                    out.writelines(lines)
                    entry['processed_bytes'] += len(block)
                entry['status'] = 'partial_encrypted' if entry['encrypted_bytes_skipped'] else 'complete'
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('ipa', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-url', default='')
    parser.add_argument('--disassemble', action='store_true')
    args = parser.parse_args()
    root = args.output.resolve()
    extract_root = root / 'extracted'
    extract_root.mkdir(parents=True, exist_ok=True)
    analysis = root / 'analysis'
    analysis.mkdir(parents=True, exist_ok=True)
    binaries, inventory, infos, indicators = [], [], {}, {}
    with zipfile.ZipFile(args.ipa) as archive:
        entries = archive.infolist()
        if len(entries) > 100000 or sum(e.file_size for e in entries) > 8 * 1024**3:
            raise ValueError('Archive exceeds analysis limits')
        seen = set()
        for item in entries:
            path = PurePosixPath(item.filename)
            if path.is_absolute() or '..' in path.parts or '\\' in item.filename:
                raise ValueError('Unsafe archive path')
            if item.filename in seen:
                raise ValueError('Duplicate archive path')
            seen.add(item.filename)
            if (item.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError('Symbolic links are not extracted')
            target = extract_root.joinpath(*path.parts)
            if item.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if target.is_symlink() or any(p.is_symlink() for p in target.parents if p != root.parent):
                raise ValueError('Symlink in extraction destination')
            data = archive.read(item)  # zipfile checks the member CRC.
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            inventory.append(dict(path=item.filename, bytes=len(data), sha256=hashlib.sha256(data).hexdigest()))
            if path.name == 'Info.plist':
                try:
                    info = plistlib.loads(data)
                    infos[item.filename] = {k: info.get(k) for k in (
                        'CFBundleDisplayName', 'CFBundleName', 'CFBundleIdentifier', 'CFBundleExecutable',
                        'CFBundleShortVersionString', 'CFBundleVersion', 'MinimumOSVersion')}
                except (ValueError, plistlib.InvalidFileException):
                    pass
            if data[:4] not in MAGICS:
                continue
            print('Analyze', item.filename, flush=True)
            binary = dict(path=item.filename, size_bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), slices=[])
            for index, fat_offset, thin in slices(data):
                meta = parse_macho(thin)
                label = re.sub(r'[^A-Za-z0-9_.-]', '_', item.filename) + f'.slice{index}'
                meta['index'], meta['fat_offset'] = index, fat_offset
                symbol_path = analysis / 'symbols' / (label + '.json')
                write_json(symbol_path, meta.pop('symbols'))
                meta['symbols_file'] = symbol_path.relative_to(root).as_posix()
                strings_path = analysis / 'strings' / (label + '.txt.gz')
                strings_path.parent.mkdir(parents=True, exist_ok=True)
                strings = re.findall(rb'[\x20-\x7e]{5,}', thin)
                with strings_path.open('wb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as out:
                    out.write(b'\n'.join(strings) + b'\n')
                hosts = set()
                matches = set()
                for value in strings:
                    for url in re.findall(rb'https?://[^\s<>"\x27]+', value):
                        try:
                            host = urlsplit(url.decode('ascii')).hostname
                            if host and re.fullmatch(r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,63}|[0-9]{1,3})', host):
                                hosts.add(host.lower())
                        except ValueError:
                            pass
                    if re.search(rb'(snapchat\+\+|snap\+\+|snapbreak|wicked|sco[tth]*man|sideload|substrate|ss06|devicecheck|attest|skengine|spoof|bypass)', value, re.I):
                        text = value.decode('ascii')
                        if len(text) < 500 and '://' not in text:
                            matches.add(text)
                indicators[label] = dict(url_hostnames=sorted(hosts), matching_strings=sorted(matches))
                if args.disassemble:
                    destination = root / 'disassembly' / (label + '.asm.gz')
                    print('Disassemble', label, flush=True)
                    meta['disassembly'] = disassemble(thin, meta, destination)
                    if destination.exists():
                        meta['disassembly']['file'] = destination.relative_to(root).as_posix()
                        meta['disassembly']['sha256'] = sha256(destination)
                binary['slices'].append(meta)
            binaries.append(binary)
    summary = dict(input_file=args.ipa.name, size_bytes=args.ipa.stat().st_size,
                   sha256=sha256(args.ipa), source_url=args.source_url,
                   archive_entries=len(entries), regular_files=len(inventory),
                   extracted_bytes=sum(i['bytes'] for i in inventory),
                   macho_files=len(binaries), architecture_slices=sum(len(b['slices']) for b in binaries),
                   disassembly_requested=args.disassemble, bundle_info=infos,
                   limitations=['Static analysis only; no runtime behavior or server ownership verified.',
                                'Linear disassembly is not source code or a rebuildable project.',
                                'Strings and dependencies do not prove a feature is active.',
                                'No encrypted code is decrypted; declared encrypted byte ranges are skipped.'])
    write_json(analysis / 'summary.json', summary)
    write_json(analysis / 'macho.json', binaries)
    write_json(analysis / 'indicators.json', indicators)
    with (analysis / 'archive-files.tsv').open('w') as out:
        out.write('sha256\tbytes\tpath\n')
        for item in inventory:
            out.write(f"{item['sha256']}\t{item['bytes']}\t{item['path']}\n")
    print(json.dumps({k: v for k, v in summary.items() if k != 'bundle_info'}, indent=2), flush=True)


if __name__ == '__main__':
    main()
