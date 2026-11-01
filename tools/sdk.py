#!/usr/bin/env python3
"""Prepare and resolve the pinned upstream SDK plus the maintained patch stack."""
import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
MODULE = 'github.com/bwmarrin/discordgo'
STAMP = '.flexmodule-sdk.json'
PROVENANCE = ('Path', 'Version', 'Sum', 'GoModSum', 'PatchSHA256', 'SourceSHA256')


def _go_environment(go, readonly):
    toolchain = next(line.split(':=', 1)[1].strip()
                     for line in (ROOT / 'tools/versions.mk').read_text().splitlines()
                     if line.startswith('GO_TOOLCHAIN :='))
    env = {**os.environ, 'GO_TOOLCHAIN': toolchain,
           'GOTOOLCHAIN': 'local' if readonly else toolchain,
           'GOWORK': 'off', 'GOFLAGS': '', 'GO111MODULE': 'on'}
    env.pop('GOROOT', None)
    if readonly:
        # Go opens telemetry counters even for env/mod edit; GOTELEMETRY is not
        # an environment-only off switch. The pinned Go's test override sends
        # counters/uploads to a non-directory sink without writing a mode file.
        env['TEST_TELEMETRY_DIR'] = os.devnull
    if go is None:
        go = os.environ.get('BOOTSTRAP_GO')
        if not go:
            candidate = ROOT / '.tools/go/bin/go'
            if candidate.is_file() and os.access(candidate, os.X_OK):
                go = str(candidate)
        if not go:
            go = next((str(Path(directory) / 'go') for directory in os.get_exec_path()
                       if 'shims' not in Path(directory).parts
                       and os.access(Path(directory) / 'go', os.X_OK)
                       and (Path(directory) / 'go').is_file()), None)
        if not go:
            raise RuntimeError('Set BOOTSTRAP_GO or install the pinned Go distribution in .tools/go')
    go = str(go)
    actual = subprocess.check_output([go, 'env', 'GOVERSION'], env=env, text=True).strip()
    if readonly and actual != toolchain:
        # A bootstrap compiler may have already downloaded the selected toolchain.
        # Inspect that location without invoking Go's downloading toolchain selector.
        values = subprocess.check_output([go, 'env', 'GOMODCACHE', 'GOOS', 'GOARCH'],
                                         env=env, text=True).splitlines()
        candidate = (Path(values[0]) /
                     f'golang.org/toolchain@v0.0.1-{toolchain}.{values[1]}-{values[2]}' / 'bin/go')
        if candidate.is_file():
            go = str(candidate)
            actual = subprocess.check_output([go, 'env', 'GOVERSION'], env=env, text=True).strip()
    if actual != toolchain:
        raise RuntimeError(f'Go version is {actual}; require {toolchain}')
    return go, env


def _manifest(go, env, directory):
    # Unlike go list, this works before a local replacement has been prepared.
    return json.loads(subprocess.check_output(
        [go, '-C', str(directory), 'mod', 'edit', '-json'], env=env, text=True))


def _require(manifest):
    entries = [entry for entry in manifest.get('Require') or [] if entry['Path'] == MODULE]
    if len(entries) != 1 or not entries[0].get('Version'):
        raise RuntimeError(f'go.mod must require an exact {MODULE} version')
    return entries[0]['Version']


def _owned_path(path):
    relative = path.relative_to(ROOT)
    current = ROOT
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise RuntimeError(f'Unsafe symlink in SDK owned path: {current}')


def _contract(go, env, module_dir, target):
    root = _manifest(go, env, ROOT)
    version = _require(root)
    checksum_file = ROOT / 'third_party/discordgo/upstream.sum'
    _owned_path(checksum_file)
    sums = {}
    for line in checksum_file.read_text().splitlines():
        fields = line.split()
        if (len(fields) != 3 or fields[0] != MODULE
                or fields[1] not in (version, version + '/go.mod')
                or fields[1] in sums
                or not re.fullmatch(r'h1:[A-Za-z0-9+/]{43}=', fields[2])):
            raise RuntimeError('upstream.sum must contain exactly the pinned SDK and go.mod checksum records')
        sums[fields[1]] = fields[2]
    if set(sums) != {version, version + '/go.mod'}:
        raise RuntimeError('upstream.sum must pin upstream SDK and go.mod checksums')
    for directory in dict.fromkeys((ROOT, module_dir)):
        manifest = root if directory == ROOT else _manifest(go, env, directory)
        if _require(manifest) != version:
            raise RuntimeError(f'{directory} must require {MODULE} {version}')
        replacements = [entry for entry in manifest.get('Replace') or []
                        if entry['Old']['Path'] == MODULE]
        if len(replacements) != 1:
            raise RuntimeError(f'{directory} must have exactly one owned SDK replacement')
        replacement = replacements[0]
        new = replacement['New']
        path = Path(new['Path'])
        if (replacement['Old'].get('Version') or new.get('Version') or path.is_absolute()
                or Path(os.path.abspath(directory / path)) != target):
            raise RuntimeError(f'{directory} must replace {MODULE} with the owned prepared SDK')
    return {'Path': MODULE, 'Version': version, 'Sum': sums[version],
            'GoModSum': sums[version + '/go.mod']}


def _patches():
    directory = ROOT / 'third_party/discordgo/patches'
    _owned_path(directory)
    patches = []
    for path in sorted(directory.iterdir()):
        if not re.fullmatch(r'[0-9]{4}-[A-Za-z0-9][A-Za-z0-9._-]*\.patch', path.name):
            raise RuntimeError(f'Invalid SDK patch entry: {path.name}')
        if path.is_symlink() or not path.is_file() or not path.stat().st_size:
            raise RuntimeError(f'Invalid SDK patch file: {path}')
        patches.append((path.name, path.read_bytes()))
    if not patches:
        raise RuntimeError('SDK patch stack must not be empty')
    digest = hashlib.sha256()
    for name, content in patches:
        digest.update(name.encode() + b'\0' + str(len(content)).encode() + b'\0' + content)
    return patches, digest.hexdigest()


def _source_digest(directory):
    if directory.is_symlink() or not directory.is_dir():
        raise RuntimeError(f'Prepared SDK source is unavailable: {directory}')
    digest = hashlib.sha256()
    for path in sorted(directory.rglob('*')):
        relative = path.relative_to(directory).as_posix()
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise RuntimeError(f'Unsafe SDK source entry: {relative}')
        if relative == STAMP:
            continue
        content = path.read_bytes()
        digest.update(relative.encode() + b'\0' + str(len(content)).encode() + b'\0' + content)
    return digest.hexdigest()


def _existing(target):
    if not target.exists():
        return None
    stamp = target / STAMP
    if stamp.is_symlink() or not stamp.is_file():
        raise RuntimeError('Existing SDK has no valid provenance; refusing to overwrite it')
    try:
        metadata = json.loads(stamp.read_text())
    except (ValueError, OSError) as error:
        raise RuntimeError('Existing SDK provenance is unreadable') from error
    if (not isinstance(metadata, dict) or set(metadata) != set(PROVENANCE)
            or any(not isinstance(metadata[key], str) for key in PROVENANCE)):
        raise RuntimeError('Existing SDK provenance is invalid')
    if _source_digest(target) != metadata['SourceSHA256']:
        raise RuntimeError('Prepared SDK source was modified; refusing to overwrite it')
    return metadata


def _generation_path(metadata):
    identity = hashlib.sha256(json.dumps(provenance(metadata), sort_keys=True).encode()).hexdigest()
    return ROOT / '.tools/deps/discordgo-generations' / identity


def _current(target):
    _owned_path(target.parent)
    if not target.is_symlink():
        if target.exists():
            raise RuntimeError(f'Prepared SDK alias must be an owned relative symlink; '
                               f'review and move {target} aside explicitly before preparing')
        return None
    relative = os.readlink(target)
    if not re.fullmatch(r'discordgo-generations/[0-9a-f]{64}', relative):
        raise RuntimeError('Unsafe prepared SDK alias target')
    generation = target.parent / relative
    _owned_path(generation)
    metadata = _existing(generation)
    if metadata is None or _generation_path(metadata) != generation:
        raise RuntimeError('Prepared SDK generation provenance does not match its address')
    return generation, metadata


def _h1(entries):
    # golang.org/x/mod/sumdb/dirhash.Hash1: sorted names, then the hash of
    # each file, two spaces, its name and a newline; hash that summary again.
    digest = hashlib.sha256()
    for name, content in sorted(entries):
        if '\n' in name:
            raise RuntimeError('Unsafe newline in upstream archive path')
        digest.update(f'{hashlib.sha256(content).hexdigest()}  {name}\n'.encode())
    return 'h1:' + base64.b64encode(digest.digest()).decode()


def _archive_entries(archive, metadata):
    prefix = MODULE + '@' + metadata['Version'] + '/'
    entries = []
    seen = set()
    with zipfile.ZipFile(archive) as source:
        for info in source.infolist():
            name = info.filename
            relative = name[len(prefix):] if name.startswith(prefix) else ''
            parts = PurePosixPath(relative).parts
            mode = info.external_attr >> 16
            if (not relative or '\\' in relative or '\n' in relative or '\x00' in relative
                    or relative.startswith('/') or any(part in ('.', '..', '.git') for part in parts)
                    or str(PurePosixPath(relative)) != relative.rstrip('/')
                    or relative.rstrip('/') == STAMP or name in seen
                    or (stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR))):
                raise RuntimeError(f'Unsafe upstream archive entry: {name}')
            seen.add(name)
            entries.append((name, source.read(info)))
    if _h1(entries) != metadata['Sum']:
        raise RuntimeError('Upstream SDK archive checksum mismatch')
    files = [(name[len(prefix):], content) for name, content in entries if not name.endswith('/')]
    return files


def _download(go, env, metadata, work, cache):
    isolated = {**env, 'GOMODCACHE': str(cache)}
    downloaded = json.loads(subprocess.check_output(
        [go, '-C', str(work), 'mod', 'download', '-json', MODULE + '@' + metadata['Version']],
        env=isolated, text=True))
    if downloaded.get('Error') or any(downloaded.get(key) != metadata[key]
                                      for key in ('Path', 'Version', 'Sum', 'GoModSum')):
        raise RuntimeError('Downloaded SDK does not match pinned upstream metadata')
    # Never trust downloaded['Dir']: Go does not re-hash an edited extracted cache.
    files = _archive_entries(downloaded['Zip'], metadata)
    go_mod = Path(downloaded['GoMod']).read_bytes()
    if (_h1([('go.mod', go_mod)]) != metadata['GoModSum']
            or dict(files).get('go.mod') != go_mod):
        raise RuntimeError('Upstream SDK go.mod checksum mismatch')
    return files


def _stage(go, env, metadata, patches, work, cache):
    source = work / 'source'
    source.mkdir()
    for name, content in _download(go, env, metadata, work, cache):
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    patch_env = {key: value for key, value in env.items() if not key.startswith('GIT_')}
    patch_env.update({'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
                      'GIT_CEILING_DIRECTORIES': str(work)})
    for name, content in patches:
        # Git's default application rejects unsafe paths, missing context and
        # partially applicable patches. No --3way, --reject or whitespace fixing.
        subprocess.run(['git', 'apply', '--whitespace=nowarn', '-'], cwd=source,
                       env=patch_env, input=content, check=True)
    if (source / STAMP).exists():
        raise RuntimeError('SDK patches must not create the reserved provenance file')
    source_digest = _source_digest(source)
    manifest = _manifest(go, env, source)
    if (manifest.get('Module') or {}).get('Path') != MODULE:
        raise RuntimeError('Prepared SDK must retain the upstream module identity')
    result = {**metadata, 'SourceSHA256': source_digest}
    (source / STAMP).write_text(json.dumps(result, sort_keys=True) + '\n')
    return source, result


def _publish(source, result, target, work):
    generation = _generation_path(result)
    _owned_path(generation)
    generation.parent.mkdir(parents=True, exist_ok=True)
    existing = _existing(generation)
    if existing is not None:
        if existing != result:
            raise RuntimeError('Existing SDK generation provenance does not match staged output')
    else:
        source.rename(generation)
    # Replacing a symlink is one atomic operation. Old generations stay alive
    # for callers that obtained their immutable Dir before this publication.
    alias = work / 'alias'
    alias.symlink_to(generation.relative_to(target.parent))
    alias.replace(target)
    return generation


def resolve(go=None, module_dir=ROOT, *, prepare=True):
    module_dir = Path(module_dir).resolve()
    target = ROOT / '.tools/deps/discordgo'
    _owned_path(target.parent)
    go, env = _go_environment(go, not prepare)
    metadata = _contract(go, env, module_dir, target)
    patches, patch_digest = _patches()
    metadata['PatchSHA256'] = patch_digest
    if not prepare:
        current = _current(target)
        if current is None or any(current[1][key] != value for key, value in metadata.items()):
            raise RuntimeError('Prepared SDK is missing or stale; prepare it on the host first')
        return {**current[1], 'Dir': str(current[0])}
    deps = target.parent
    deps.mkdir(parents=True, exist_ok=True)
    lock = deps / 'discordgo.lock'
    _owned_path(lock)
    with lock.open('a') as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        # Re-read patch bytes after acquiring the lock so staged content and
        # reported provenance always refer to the same captured inputs.
        patches, metadata['PatchSHA256'] = _patches()
        current = _current(target)
        if current is not None and all(current[1][key] == value for key, value in metadata.items()):
            return {**current[1], 'Dir': str(current[0])}
        cache = deps / 'download-cache'
        _owned_path(cache)
        with tempfile.TemporaryDirectory(prefix='discordgo-stage-', dir=deps) as directory:
            work = Path(directory)
            source, result = _stage(go, env, metadata, patches, work, cache)
            generation = _publish(source, result, target, work)
        return {**result, 'Dir': str(generation)}


def provenance(metadata):
    return {key: metadata[key] for key in PROVENANCE}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', help='Selected Go binary (otherwise use the pinned toolchain)')
    parser.add_argument('--module-dir', type=Path, default=ROOT)
    parser.add_argument('--json', action='store_true', help='Print metadata instead of the source directory')
    parser.add_argument('--verify-only', action='store_true', help='Validate prepared source without writes or downloads')
    args = parser.parse_args()
    metadata = resolve(args.go, args.module_dir, prepare=not args.verify_only)
    print(json.dumps(metadata) if args.json else metadata['Dir'])


if __name__ == '__main__':
    main()
