#!/usr/bin/env python3
"""Build-only EL9 user-space closure. Never resolves programs from host PATH.

Run in the existing pinned native builder. Every distributed byte is taken from
hash-locked RPMs or the separately receipted native build, not its installed OS.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, '/source/tools/build')
from artifacts import capture, digest, fetch, inventory, run, write_json

source = Path('/source')
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--worker', type=Path)
parser.add_argument('--voice-libraries', type=Path)
args = parser.parse_args()
if args.worker is None and args.voice_libraries is None:
    parser.error('actual worker or native-library inputs are required')
work = Path('/work/runtime')
work.mkdir(parents=True, exist_ok=True)
lock = json.loads((source / 'tools/native/runtime-packages.lock.json').read_text())
root = work / 'rpm-root'
if root.exists():
    shutil.rmtree(root)
root.mkdir()
downloads = work / 'downloads'
downloads.mkdir(exist_ok=True)
for name, package in lock.items():
    rpm = fetch(package['url'], package['sha256'], downloads / (name + '.rpm'))
    # RPM metadata is informational; archive SHA256 is the authority.
    identity = capture('rpm', '-qp', '--qf', '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}', rpm)
    expected = f"{name} {package['epoch']}:{package['version']}-{package['release']}.{package['arch']}"
    if identity != expected:
        raise RuntimeError('RPM identity differs from locked acquisition: ' + name)
    archive = work / 'payload.cpio'
    with archive.open('wb') as output:
        run('rpm2cpio', rpm, stdout=output)
    with archive.open('rb') as input_file:
        run('cpio', '-idm', '--quiet', '--no-absolute-filenames', cwd=root, stdin=input_file)
    archive.unlink()

out = Path('/work/runtime-bundle')
if out.exists():
    shutil.rmtree(out)
for name in ['libexec', 'lib/xtables', 'licenses/rpms', 'provenance']:
    (out / name).mkdir(parents=True)

# Follow RPM links inside the extracted package root, never the builder root.
def resolve(p):
    for _ in range(32):
        if not p.is_symlink():
            if not p.is_file():
                raise RuntimeError('Missing locked RPM file: ' + str(p))
            return p
        target = os.readlink(p)
        p = root / target.lstrip('/') if target.startswith('/') else Path(os.path.normpath(p.parent / target))
        p.relative_to(root)
    raise RuntimeError('RPM symlink cycle')

providers = {}
for base in ['usr/lib64', 'lib64', 'usr/lib', 'lib']:
    directory = root / base
    if directory.is_dir() and not directory.is_symlink():
        for p in directory.iterdir():
            if p.is_file() or p.is_symlink():
                providers.setdefault(p.name, p)

queue = []
programs = []
for id_, name, candidates in [
    ('mkfs-xfs', 'mkfs.xfs', ['usr/sbin/mkfs.xfs']),
    ('xfs-quota', 'xfs_quota', ['usr/sbin/xfs_quota']),
    ('ip', 'ip', ['usr/sbin/ip']),
    ('iptables', 'iptables', ['usr/sbin/xtables-nft-multi']),
    ('ip6tables', 'ip6tables', ['usr/sbin/xtables-nft-multi']),
    ('conntrack', 'conntrack', ['usr/sbin/conntrack']),
    ('useradd', 'useradd', ['usr/sbin/useradd']),
    ('groupadd', 'groupadd', ['usr/sbin/groupadd']),
    ('userdel', 'userdel', ['usr/sbin/userdel']),
    ('groupdel', 'groupdel', ['usr/sbin/groupdel']),
]:
    original = next((root / p for p in candidates if (root / p).exists()), None)
    if original is None:
        raise RuntimeError('Missing pinned executable: ' + id_)
    target = out / 'libexec' / name
    shutil.copyfile(resolve(original), target)
    queue.append((target, False))
    programs.append({'id': id_, 'path': str(target.relative_to(out)),
                     'interpreter': 'lib/ld-linux-x86-64.so.2', 'library_directories': ['lib'],
                     **({'environment': ['XTABLES_LIBDIR=lib/xtables']} if id_ in ['iptables', 'ip6tables'] else {})})

extensions = root / 'usr/lib64/xtables'
if not extensions.is_dir():
    raise RuntimeError('Missing pinned xtables extensions')
for p in sorted(extensions.glob('*.so')):
    target = out / 'lib/xtables' / p.name
    shutil.copyfile(resolve(p), target)
    queue.append((target, False))
required_extensions = ['libxt_conntrack.so', 'libxt_comment.so', 'libxt_addrtype.so',
                       'libxt_tcp.so', 'libxt_udp.so', 'libxt_multiport.so',
                       'libxt_SNAT.so', 'libipt_icmp.so', 'libip6t_icmp6.so']
for name in required_extensions:
    if not (out / 'lib/xtables' / name).is_file():
        raise RuntimeError('Missing required xtables extension: ' + name)

# Native roles search their separately receipted adjacent libraries first.
# Privileged tools never acquire dependencies from the worker's native closure.
native_providers = {}
native_inputs = {}
fixed_interpreters = {Path(program['interpreter']).name for program in programs}

def seed_native(path, logical):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError('Missing or unnormalized native closure input: ' + str(path))
    with path.open('rb') as stream:
        if stream.read(4) != b'\x7fELF':
            raise RuntimeError('Native closure input is not ELF: ' + str(path))
    native_inputs[logical] = digest(path)
    queue.append((path, True))

if args.worker is not None:
    seed_native(args.worker, 'chatanium-worker')
if args.voice_libraries is not None:
    if args.voice_libraries.is_symlink() or not args.voice_libraries.is_dir():
        raise RuntimeError('Missing actual native-library directory')
    for path in sorted(args.voice_libraries.iterdir()):
        seed_native(path, 'voice-runtime/lib/' + path.name)
        native_providers[path.name] = path

seen = set()
for name in ['libstdc++.so.6', 'libgcc_s.so.1']:
    provider = resolve(providers[name])
    target = out / 'lib' / name
    shutil.copyfile(provider, target)
    queue.append((target, False))
while queue:
    p, native = queue.pop()
    identity = (p, native)
    if identity in seen:
        continue
    seen.add(identity)
    dynamic = capture('readelf', '-d', p)
    needed = re.findall(r'\(NEEDED\).*?\[(.*?)\]', dynamic)
    headers = capture('readelf', '-l', p)
    interpreters = re.findall(r'Requesting program interpreter: (.*?)\]', headers)
    needed += [Path(p).name for p in interpreters]
    for name in needed:
        if native and name not in fixed_interpreters and name in native_providers:
            queue.append((native_providers[name], True))
            continue
        if name not in providers:
            raise RuntimeError('ELF closure is not locked: ' + name)
        provider = resolve(providers[name])
        target = out / 'lib' / name
        if target.exists():
            if digest(provider) != digest(target):
                raise RuntimeError('Conflicting library providers: ' + name)
        else:
            shutil.copyfile(provider, target)
        queue.append((target, native))

for directory in ['usr/share/licenses', 'usr/share/doc']:
    base = root / directory
    if base.exists():
        for p in sorted(base.rglob('*')):
            if p.is_file() and not p.is_symlink() and ('license' in str(p).lower() or 'copying' in p.name.lower() or 'copyright' in p.name.lower()):
                target = out / 'licenses/rpms' / p.relative_to(base)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(p, target)
if not any((out / 'licenses/rpms').rglob('*')):
    raise RuntimeError('Locked RPM notices missing')
write_json(out / 'provenance/runtime-packages.lock.json', lock)
write_json(out / 'provenance/runtime-programs.json', programs)
write_json(out / 'provenance/runtime-native-inputs.json', {
    'version': 1, 'generator_sha256': digest(source / 'tools/native/runtime.py'),
    'inputs': native_inputs,
})
write_json(out / 'provenance/runtime-inventory.json', inventory(out))
for p in out.rglob('*'):
    if p.is_file():
        p.chmod(0o555 if p.parent.name in ['libexec', 'lib', 'xtables'] else 0o444)
print('Pinned RPM executable/loader/library/xtables closure assembled at ' + str(out))
