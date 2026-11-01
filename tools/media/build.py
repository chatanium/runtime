#!/usr/bin/env python3
"""Pinned media closure producer, run in an isolated builder with /work on /home."""
import json
import os
from pathlib import Path
import shutil
import sys
import tarfile
import zipfile

sys.path.insert(0, '/source/tools/build')
from artifacts import capture, checkout, digest, elf_closure, fetch, inventory, run, write_json

source, work = Path('/source'), Path('/work')
lock = json.loads((source / 'tools/media/tool-lock.json').read_text())
for directory in ['downloads', 'src', 'tmp', 'home']:
    (work / directory).mkdir(parents=True, exist_ok=True)
os.environ.update(TMPDIR='/work/tmp', HOME='/work/home')
os.chdir(work)
# Fresh staging, never publish an incomplete tool tree.
stage = work / 'stage'
if stage.exists():
    shutil.rmtree(stage)
root = stage / 'rootfs'
prefix = root / 'opt/flexmodule'
(prefix / 'bin').mkdir(parents=True)
licenses = prefix / 'licenses'
licenses.mkdir()
archives = {}
for key in ['opus', 'yt_dlp', 'deno', 'ejs']:
    item = lock[key]
    archives[key] = fetch(item['url'], item['sha256'], work / 'downloads' / item['url'].rsplit('/', 1)[1])
opus_source = work / 'src' / ('opus-' + lock['opus']['version'])
if not opus_source.exists():
    with tarfile.open(archives['opus']) as archive:
        archive.extractall(work / 'src', filter='data')
opus_build = work / 'opus-build'
run('cmake', '-S', opus_source, '-B', opus_build, '-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release',
    '-DCMAKE_INSTALL_PREFIX=/opt/flexmodule', '-DCMAKE_INSTALL_LIBDIR=lib',
    '-DOPUS_BUILD_SHARED_LIBRARY=ON', '-DOPUS_BUILD_PROGRAMS=OFF', '-DOPUS_BUILD_TESTING=OFF',
    '-DOPUS_DRED=OFF', '-DOPUS_OSCE=OFF')
run('cmake', '--build', opus_build, '--parallel', os.environ['BUILD_JOBS'])
env = os.environ.copy()
env['DESTDIR'] = str(root)
run('cmake', '--install', opus_build, env=env)
# Make exact installed paths visible while linking, never host path lookup.
# This path is the builder's private mount, not host /opt.
installed_tree = work / 'install'
if installed_tree.exists():
    shutil.rmtree(installed_tree)
installed_tree.mkdir()
install = Path('/opt/flexmodule')
shutil.copytree(prefix, install, dirs_exist_ok=True)
ffmpeg = checkout(lock['ffmpeg']['repository'], lock['ffmpeg']['commit'], work / 'src/ffmpeg')
# FFmpeg's version.sh derives the release name from local tag refs. Fetching
# only into FETCH_HEAD verifies identity but leaves binaries labeled short-SHA.
release_ref = 'refs/tags/n' + lock['ffmpeg']['version']
run('git', '-C', ffmpeg, 'fetch', '--depth=1', 'origin', release_ref + ':' + release_ref)
if capture('git', '-C', ffmpeg, 'rev-parse', 'FETCH_HEAD^{tag}') != lock['ffmpeg']['tag_object']:
    raise RuntimeError('FFmpeg annotated tag identity mismatch')
if capture('git', '-C', ffmpeg, 'rev-parse', 'FETCH_HEAD^{commit}') != lock['ffmpeg']['commit']:
    raise RuntimeError('FFmpeg tag does not resolve to locked commit')
ffbuild = work / 'ffmpeg-build'
ffbuild.mkdir(exist_ok=True)
env.update(PKG_CONFIG_PATH='/opt/flexmodule/lib/pkgconfig', LD_LIBRARY_PATH='/opt/flexmodule/lib')
flags = ['--prefix=/opt/flexmodule', '--libdir=/opt/flexmodule/lib', '--disable-static', '--enable-shared',
         '--disable-autodetect', '--disable-doc', '--disable-checkasm', '--disable-ffplay',
         '--disable-avdevice', '--disable-devices', '--disable-hwaccels', '--enable-libopus',
         '--enable-openssl', '--enable-version3', '--extra-ldflags=-Wl,-rpath,/opt/flexmodule/lib']
run(ffmpeg / 'configure', *flags, cwd=ffbuild, env=env)
run('make', '-j' + os.environ['BUILD_JOBS'], cwd=ffbuild, env=env)
run('make', 'install', 'DESTDIR=' + str(root), cwd=ffbuild, env=env)
# Official onedir: keep every file, including interpreter, EJS, extensions and notices.
extracted = work / 'yt-dlp-extracted'
if extracted.exists():
    shutil.rmtree(extracted)
with zipfile.ZipFile(archives['yt_dlp']) as archive:
    archive.extractall(extracted)
ytdlp = [path for path in extracted.rglob('yt-dlp_linux') if path.is_file()]
if len(ytdlp) != 1:
    raise RuntimeError('Unexpected official yt-dlp onedir layout')
shutil.copytree(ytdlp[0].parent, prefix / 'yt-dlp')
(prefix / 'yt-dlp/yt-dlp_linux').rename(prefix / 'yt-dlp/yt-dlp')
(prefix / 'yt-dlp/yt-dlp').chmod(0o755)
with zipfile.ZipFile(archives['deno']) as archive:
    with archive.open('deno') as src, (prefix / 'bin/deno').open('wb') as dst:
        shutil.copyfileobj(src, dst)
(prefix / 'bin/deno').chmod(0o755)
# EJS wheel is provenance/source material, not a second runtime install.
with zipfile.ZipFile(archives['ejs']) as archive:
    archive.extractall(licenses / 'ejs-distribution')
for directory, label in [(opus_source, 'opus'), (ffmpeg, 'ffmpeg')]:
    for pattern in ['COPYING*', 'LICENSE*']:
        for notice in directory.glob(pattern):
            if notice.is_file():
                target = licenses / label / notice.name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(notice, target)
# Collect all native ELF dependencies, including the whole Python onedir.
shutil.copytree(prefix, install, dirs_exist_ok=True)
elfs = []
for path in install.rglob('*'):
    if path.is_file():
        with path.open('rb') as stream:
            if stream.read(4) == b'\x7fELF':
                elfs.append(path)
os.environ['LD_LIBRARY_PATH'] = ':'.join(['/opt/flexmodule/lib'] + sorted({str(path.parent) for path in elfs if '/yt-dlp/' in str(path)}))
closure = elf_closure(elfs, root)
# OpenSSL providers can be dlopen'd rather than listed in DT_NEEDED.
for path in Path('/usr/lib/x86_64-linux-gnu/ossl-modules').glob('*.so'):
    target = root / str(path).lstrip('/')
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, target)
    closure.update(elf_closure([path], root))
shutil.copytree('/etc/ssl/certs', root / 'etc/ssl/certs', symlinks=False)
shutil.copy2('/etc/ssl/openssl.cnf', root / 'etc/ssl/openssl.cnf')
# Package copyright and exact binary versions accompany the resolved loader graph.
packages = set()
for path in closure:
    if path.startswith('/opt/flexmodule/'):
        continue
    owner = capture('dpkg-query', '-S', Path(path).resolve()).split(': ', 1)[0]
    packages.add(owner)
for package in packages | {'ca-certificates', 'libssl3t64'}:
    directory = Path('/usr/share/doc') / package.split(':')[0]
    if directory.exists():
        shutil.copytree(directory, licenses / 'debian' / directory.name, symlinks=False, dirs_exist_ok=True)
# Retain exact upstream sources and every locked Rust/V8 crate's notices.
# Crate archives are content-addressed by the upstream Cargo.lock checksums;
# this is source/license collection, never a runtime dependency installer.
import tomllib
deno_source = checkout('https://github.com/denoland/deno.git', lock['deno_source_commit'], work / 'src/deno')
run('git', '-C', deno_source, 'submodule', 'update', '--init', '--recursive', '--depth=1', 'tools/lzld')
yt_source = checkout('https://github.com/yt-dlp/yt-dlp.git', lock['yt_dlp_source_commit'], work / 'src/yt-dlp')
for directory, label in [(deno_source, 'deno'), (yt_source, 'yt-dlp')]:
    for notice in directory.rglob('*'):
        if '.git' in notice.parts or not notice.is_file():
            continue
        if notice.name.upper().startswith(('LICENSE', 'COPYING', 'NOTICE', 'THIRD_PARTY_LICENSE')):
            target = licenses / label / notice.relative_to(directory)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(notice, target)
rust_lock = tomllib.loads((deno_source / 'Cargo.lock').read_text())
for package in rust_lock['package']:
    registry = package.get('source', '')
    if registry.startswith('git+'):
        raise RuntimeError('Unclosed Deno git dependency: ' + registry)
    if not registry.startswith('registry+'):
        continue
    name, version = package['name'], package['version']
    archive = fetch(f'https://static.crates.io/crates/{name}/{name}-{version}.crate',
                    package['checksum'], work / 'downloads' / f'{name}-{version}.crate')
    with tarfile.open(archive) as contents:
        for member in contents.getmembers():
            basename = Path(member.name).name.upper()
            if member.isfile() and basename.startswith(('LICENSE', 'COPYING', 'NOTICE')):
                if Path(member.name).is_absolute() or '..' in Path(member.name).parts:
                    raise RuntimeError('Unsafe crate notice archive path')
                target = licenses / 'deno-crates' / member.name
                target.parent.mkdir(parents=True, exist_ok=True)
                with contents.extractfile(member) as src, target.open('wb') as dst:
                    shutil.copyfileobj(src, dst)
provenance = prefix / 'provenance'
provenance.mkdir()
shutil.copy2(source / 'tools/media/tool-lock.json', provenance / 'tool-lock.json')
shutil.copytree('/opt/flexmodule-builder', provenance / 'builder')
(provenance / 'ffmpeg-configure.json').write_text(json.dumps(flags, indent=2) + '\n')
(provenance / 'ffmpeg-config.log').write_text((ffbuild / 'ffbuild/config.log').read_text())
(provenance / 'deno-gitlinks.txt').write_text(capture('git', '-C', deno_source, 'submodule', 'status', '--recursive') + '\n')
write_json(provenance / 'download-sha256.json', inventory(work / 'downloads'))
write_json(provenance / 'builder-source-sha256.json', {
    path: digest(source / path) for path in [
        'tools/media/build.py', 'tools/media/Builder.Dockerfile',
        'tools/media/Tools.Dockerfile', 'tools/media/Module.Dockerfile',
        'tools/build/artifacts.py', 'tools/build/images.py',
    ]
})
write_json(provenance / 'elf-closure.json', closure)
write_json(provenance / 'symlink-aliases.json', {
    str(path.relative_to(root)): os.readlink(path)
    for path in sorted(root.rglob('*')) if path.is_symlink()
})
write_json(provenance / 'files-sha256.json', inventory(root))
# Exercise loader/version contracts inside final filesystem, without network.
# chroot requires root, so use the copied loader and explicit library path.
for tool, expected in [('ffmpeg', '9.0.2'), ('ffprobe', '9.0.2'), ('deno', '2.9.8')]:
    output = capture(prefix / 'bin' / tool, '-version' if tool != 'deno' else '--version')
    if expected not in output.splitlines()[0]:
        raise RuntimeError('Unexpected media tool version: ' + tool)
if capture(prefix / 'yt-dlp/yt-dlp', '--ignore-config', '--no-update', '--version') != lock['yt_dlp']['version']:
    raise RuntimeError('Unexpected yt-dlp version')
