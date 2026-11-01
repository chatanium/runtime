"""Build-only helpers. No runtime installers, credentials or host provisioning."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import urllib.request


def run(*args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, **kwargs)


def capture(*args, **kwargs):
    return subprocess.check_output([str(a) for a in args], text=True, **kwargs).strip()


def digest(path):
    result = hashlib.sha256()
    with open(path, 'rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def fetch(url, sha256, destination):
    destination = Path(destination)
    if destination.is_file() and digest(destination) == sha256:
        return destination
    partial = destination.with_suffix(destination.suffix + '.partial')
    try:
        with urllib.request.urlopen(url, timeout=120) as source, partial.open('wb') as output:
            shutil.copyfileobj(source, output)
        if digest(partial) != sha256:
            raise RuntimeError('SHA256 mismatch: ' + url)
        os.replace(partial, destination)
    finally:
        partial.unlink(missing_ok=True)
    return destination


def checkout(url, commit, destination):
    destination = Path(destination)
    if not destination.exists():
        run('git', 'init', destination)
        run('git', '-C', destination, 'remote', 'add', 'origin', url)
    if capture('git', '-C', destination, 'status', '--porcelain', '--untracked-files=no'):
        raise RuntimeError('Source checkout already modified: ' + str(destination))
    run('git', '-C', destination, 'fetch', '--depth=1', 'origin', commit)
    run('git', '-C', destination, 'checkout', '--detach', commit)
    if capture('git', '-C', destination, 'rev-parse', 'HEAD') != commit:
        raise RuntimeError('Source commit mismatch')
    return destination


def inventory(root):
    root = Path(root)
    return {str(p.relative_to(root)): digest(p) for p in sorted(root.rglob('*')) if p.is_file() and not p.is_symlink()}


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def elf_closure(executables, destination, exclude_system=False):
    """Resolve all DT_NEEDED recursively via the builder's real loader.

    Media stages canonical system-provider paths and preserves file aliases
    without replacing merged-/usr directory symlinks in the pinned base. EL9
    host bundles keep libc on host and carry other dependencies by SONAME.
    """
    destination = Path(destination)
    copied = {}
    queue = list(executables)
    visited = set()
    while queue:
        item = Path(queue.pop())
        if str(item) in visited:
            continue
        visited.add(str(item))
        with item.open('rb') as source:
            if source.read(4) != b'\x7fELF':
                continue
        result = run('ldd', item, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if 'not found' in result.stdout:
            raise RuntimeError('Unresolved ELF dependency: ' + str(item))
        for line in result.stdout.splitlines():
            words = line.split()
            path = words[2] if len(words) >= 3 and words[1] == '=>' else words[0] if words else ''
            if not path.startswith('/'):
                continue
            library = Path(path)
            if exclude_system and (library.name.startswith(('libc.so', 'libm.so', 'libpthread.so', 'libdl.so', 'librt.so', 'ld-linux'))):
                continue
            target = destination / (library.name if exclude_system else str(library).lstrip('/'))
            if exclude_system:
                target.parent.mkdir(parents=True, exist_ok=True)
                if not target.exists():
                    shutil.copy2(library.resolve(), target)
            elif not target.exists() and not target.is_symlink():
                # The tool-owned /opt tree is already staged. For external
                # providers, /lib and /lib64 may be base-image directory
                # aliases: stage the real /usr file, never a conflicting /lib
                # directory, and retain every SONAME/interpreter file alias.
                real = library.resolve(strict=True)
                real_target = destination / str(real).lstrip('/')
                real_target.parent.mkdir(parents=True, exist_ok=True)
                if not real_target.exists():
                    shutil.copy2(real, real_target)
                node = library
                while node.is_symlink():
                    alias = destination / str(node.parent.resolve() / node.name).lstrip('/')
                    link = os.readlink(node)
                    alias.parent.mkdir(parents=True, exist_ok=True)
                    if alias.is_symlink():
                        if os.readlink(alias) != link:
                            raise RuntimeError('Conflicting ELF provider alias: ' + str(alias))
                    elif alias.exists():
                        raise RuntimeError('ELF alias collides with a staged file: ' + str(alias))
                    else:
                        alias.symlink_to(link)
                    node = Path(link) if os.path.isabs(link) else node.parent / link
                target = destination / str(library.parent.resolve() / library.name).lstrip('/')
            copied[str(library)] = str(target)
            queue.append(library)
    return copied


def check_elf_versions(executables):
    """Match each needed ELF version to the actual loader-selected provider.

    Distro version numbers are not ABI ceilings: EL9 glibc 2.34 exports some
    backported GLIBC_2.35 nodes. Check provider definitions, never infer them.
    """
    environment = os.environ.copy()
    environment['LC_ALL'] = 'C'
    environment['LANG'] = 'C'
    queue = [Path(path) for path in executables]
    visited, definitions, evidence = set(), {}, {}
    while queue:
        item = queue.pop().resolve()
        if item in visited:
            continue
        visited.add(item)
        output = capture('readelf', '--wide', '--version-info', item, env=environment)
        required = output.partition('Version needs section')[2]
        loaded = capture('ldd', item, env=environment)
        if 'not found' in loaded:
            raise RuntimeError('Unresolved target ELF dependency: ' + str(item))
        providers = {}
        for line in loaded.splitlines():
            words = line.split()
            if len(words) >= 3 and words[1] == '=>' and words[2].startswith('/'):
                providers[words[0]] = Path(words[2]).resolve()
            elif words and words[0].startswith('/'):
                providers[Path(words[0]).name] = Path(words[0]).resolve()
        queue.extend(providers.values())
        current = None
        checked = {}
        for line in required.splitlines():
            provider = re.search(r'\bFile:\s+(\S+)', line)
            if provider:
                current = provider.group(1)
            version = re.search(r'\bName:\s+(\S+)', line)
            if not version:
                continue
            name = version.group(1)
            if current not in providers:
                raise RuntimeError(f'{item}: version provider not loaded: {current}')
            path = providers[current]
            if path not in definitions:
                provider_output = capture('readelf', '--wide', '--version-info', path, env=environment)
                declared = provider_output.partition('Version definition section')[2].partition('Version needs section')[0]
                definitions[path] = set(re.findall(r'\bName:\s+(\S+)', declared))
            if name not in definitions[path]:
                raise RuntimeError(f'{item}: requires {current}:{name}, absent from actual provider {path}')
            checked.setdefault(current, {'path': str(path), 'versions': []})['versions'].append(name)
        evidence[str(item)] = checked
    return evidence
