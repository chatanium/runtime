#!/usr/bin/env python3
"""Unprivileged worker-only USTAR producer; never prepares or executes root code."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from artifacts import canonical_json as canonical, digest

MAX_BYTES = 4 << 30
MAX_FILES = 4096


def pack(source, output, base_digest, voice):
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', base_digest):
        raise RuntimeError('Installed base bundle digest required')
    root = source.resolve(strict=True)
    selected = [('bin/chatanium-worker', root / 'chatanium-worker')]
    if voice:
        for directory, prefix in [('lib', 'bin/voice-runtime/lib'),
                                  ('licenses', 'licenses/voice'), ('provenance', 'provenance/voice')]:
            origin = root / 'voice-runtime' / directory
            if not origin.is_dir() or origin.is_symlink():
                raise RuntimeError('Missing worker native closure: ' + directory)
            for path in sorted(origin.rglob('*')):
                if path.is_dir() and not path.is_symlink():
                    continue
                relative = path.relative_to(origin)
                if directory == 'lib' and len(relative.parts) != 1:
                    raise RuntimeError('Native worker libraries must have flat basenames')
                selected.append((prefix + '/' + str(relative), path))
    if len(selected) > MAX_FILES:
        raise RuntimeError('Worker candidate inventory exceeds 4096 files')
    files = []
    sources = {}
    total = 0
    for name, path in sorted(selected):
        real = path.resolve(strict=True)
        real.relative_to(root)
        info = real.stat()
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError('Worker candidate contains a nonregular source')
        total += info.st_size
        if total > MAX_BYTES:
            raise RuntimeError('Worker candidate exceeds the fixed archive bound')
        mode = 0o555 if name == 'bin/chatanium-worker' or name.startswith('bin/voice-runtime/lib/') else 0o444
        files.append({'path': name, 'digest': 'sha256:' + digest(real), 'size': info.st_size, 'mode': mode})
        sources[name] = real
    manifest = {'version': 1, 'base_bundle_digest': base_digest, 'platform': 'linux/amd64',
                'cpu_baseline': 'amd64-v2', 'native_abi': 'EL9', 'worker_control_version': 1,
                'runtime_control_version': 2, 'runtime_config_version': 2, 'voice': voice, 'files': files}
    manifest['digest'] = 'sha256:' + hashlib.sha256(b'chatanium-development-worker-v1\x00' + canonical(manifest)).hexdigest()
    raw = canonical(manifest)
    if len(raw) > 1 << 20:
        raise RuntimeError('Worker manifest exceeds one MiB')
    created = False
    try:
        with output.open('xb') as stream:
            created = True
            os.fchmod(stream.fileno(), 0o600)
            with tarfile.open(fileobj=stream, mode='w', format=tarfile.USTAR_FORMAT) as archive:
                header = tarfile.TarInfo('worker-manifest.json')
                header.mode, header.size = 0o444, len(raw)
                archive.addfile(header, io.BytesIO(raw))
                for file in files:
                    header = tarfile.TarInfo(file['path'])
                    header.mode, header.size = file['mode'], file['size']
                    with sources[file['path']].open('rb') as data:
                        archive.addfile(header, data)
            padding = -stream.tell() % 4096
            stream.write(bytes(padding))
            if stream.tell() > MAX_BYTES:
                raise RuntimeError('Worker USTAR exceeds the fixed archive bound')
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        if created:
            output.unlink(missing_ok=True)
        raise
    return {'archive_digest': 'sha256:' + digest(output), 'archive_bytes': output.stat().st_size,
            'manifest_digest': manifest['digest']}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--base-bundle-digest', required=True)
    parser.add_argument('--disable-voice', action='store_true')
    args = parser.parse_args()
    try:
        print(json.dumps(pack(args.source, args.output, args.base_bundle_digest, not args.disable_voice), separators=(',', ':')))
    except (OSError, ValueError, RuntimeError, tarfile.TarError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
