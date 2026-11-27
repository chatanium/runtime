#!/usr/bin/env python3
"""Executed only inside the pinned EL9 builder, by tools/build/voice.sh."""
import ctypes
import json
import os
from pathlib import Path
import re
import shutil
import sys

# /source is read-only, including imported build helpers.
sys.dont_write_bytecode = True

sys.path.insert(0, '/source/tools/build')
from artifacts import capture, checkout, check_elf_versions, digest, elf_closure, inventory, run, write_json
sys.path.insert(0, '/source/tools')
from sdk import provenance as sdk_provenance, resolve as resolve_sdk

source = Path('/source')
work = Path('/work')
sdk = json.loads((work / 'sdk-module.json').read_text())
sdk_source = (source / '.tools/deps/discordgo').resolve(strict=True)
lock_path = source / 'tools/native/native-lock.json'
patch_dir = source / 'third_party/libdave/patches'
for path in (lock_path, patch_dir):
    if path.is_symlink() or not path.exists():
        raise RuntimeError('Missing or unsafe native build input: ' + str(path))
lock = json.loads(lock_path.read_text())
patches = sorted(patch_dir.glob('*.patch'))
approved_patches = lock['libdave']['patches']
if not patches or set(approved_patches) != {patch.name for patch in patches}:
    raise RuntimeError('Native patch set differs from tools/native/native-lock.json')
for patch in patches:
    if (patch.is_symlink() or not patch.is_file()
            or not re.fullmatch(r'[0-9]{4}-.+\.patch', patch.name)
            or not re.fullmatch(r'[0-9a-f]{64}', approved_patches[patch.name])
            or digest(patch) != approved_patches[patch.name]):
        raise RuntimeError('Unapproved libdave patch: ' + str(patch))
work.mkdir(exist_ok=True)
os.environ.update(TMPDIR='/work/tmp', HOME='/work/home', VCPKG_DOWNLOADS='/work/downloads',
                  VCPKG_DEFAULT_BINARY_CACHE='/work/vcpkg-cache', VCPKG_MAX_CONCURRENCY=os.environ['BUILD_JOBS'])
for name in ['tmp', 'home', 'downloads', 'vcpkg-cache', 'go-cache', 'go-modcache']:
    (work / name).mkdir(exist_ok=True)
# Native BoringSSL code generation needs the same pinned Go compiler even
# when application compilation is intentionally deferred.
os.environ.update(PATH='/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                  GOTOOLCHAIN='local', GOWORK='off', GOENV='off', GOFLAGS='', GOAMD64='v2',
                  GOPATH='/work/go', GOCACHE='/work/go-cache', GOMODCACHE='/work/go-modcache')
if capture('/go/bin/go', 'env', 'GOVERSION') != os.environ['GO_TOOLCHAIN']:
    raise RuntimeError('Pinned Go compiler mismatch')
# Validate both native-only and application builds before any native work.
# The relative go.mod replacement is visible through /source, not a host path.
resolved_sdk = resolve_sdk('/go/bin/go', source, prepare=False)
if (Path(resolved_sdk['Dir']) != sdk_source
        or sdk_provenance(resolved_sdk) != sdk_provenance(sdk)):
    raise RuntimeError('Prepared SDK differs from the host-approved dependency')
if os.environ.get('NATIVE_ONLY') == '2':
    worker = source / 'bin/chatanium-worker'
    arguments = [sys.executable, source / 'tools/native/runtime.py', '--worker', worker]
    if os.environ.get('DISABLE_VOICE', '0') != '1':
        libraries = source / 'bin/voice-runtime/lib'
        receipt = json.loads((source / 'bin/voice-runtime/provenance/bundle-sha256.json').read_text())
        inputs = {'chatanium-worker': worker}
        inputs.update({'voice-runtime/lib/' + path.name: path for path in libraries.iterdir()})
        for logical, path in inputs.items():
            if path.is_symlink() or not path.is_file() or receipt.get(logical) != digest(path):
                raise RuntimeError('Published native artifact differs from its build receipt: ' + logical)
        arguments += ['--voice-libraries', libraries]
    run(*arguments)
    sys.exit(0)
# Fresh checkout per invocation: patched worktrees never masquerade as upstream.
checkout_dir = work / 'libdave'
if checkout_dir.exists():
    shutil.rmtree(checkout_dir)
repo = checkout(lock['libdave']['repository'], lock['libdave']['commit'], checkout_dir)
gitlink = capture('git', '-C', repo, 'rev-parse', 'HEAD:cpp/vcpkg')
if gitlink != lock['vcpkg_commit']:
    raise RuntimeError('Unexpected vcpkg gitlink')
run('git', '-C', repo, 'submodule', 'update', '--init', '--depth=1', 'cpp/vcpkg')
manifest = json.loads((repo / 'cpp/vcpkg-alts/boringssl/vcpkg.json').read_text())
if manifest['builtin-baseline'] != lock['builtin_baseline']:
    raise RuntimeError('Unexpected BoringSSL baseline')
# Port version records contain historical git-tree IDs. Fetch the complete
# history reachable from BOTH locked commits, not a moving branch and not only
# baseline.json: vcpkg must also materialize the recorded historical port trees.
vcpkg = repo / 'cpp/vcpkg'
history_flags = ['--unshallow'] if capture('git', '-C', vcpkg, 'rev-parse', '--is-shallow-repository') == 'true' else []
run('git', '-C', vcpkg, 'fetch', '--no-tags', *history_flags, 'origin',
    lock['vcpkg_commit'], lock['builtin_baseline'])
if capture('git', '-C', vcpkg, 'rev-parse', 'HEAD') != lock['vcpkg_commit']:
    raise RuntimeError('vcpkg checkout moved from its locked gitlink')
run('git', '-C', vcpkg, 'cat-file', '-e', lock['builtin_baseline'] + ':versions/baseline.json')
mls_manifest = json.loads((repo / 'cpp/vcpkg-alts/overlay-ports/mlspp/vcpkg.json').read_text())
if lock['mlspp_commit'] not in mls_manifest.values():
    raise RuntimeError('Unexpected MLSPP source pin')
run('git', '-C', repo, 'apply', '--check', *patches)
run('git', '-C', repo, 'apply', *patches)
run(repo / 'cpp/vcpkg/bootstrap-vcpkg.sh', '-disableMetrics')
triplets = work / 'triplets'
triplets.mkdir(exist_ok=True)
(triplets / 'x64-linux-flex.cmake').write_text('set(VCPKG_TARGET_ARCHITECTURE x64)\nset(VCPKG_CRT_LINKAGE dynamic)\nset(VCPKG_LIBRARY_LINKAGE static)\nset(VCPKG_CMAKE_SYSTEM_NAME Linux)\nset(VCPKG_BUILD_TYPE release)\nset(VCPKG_C_FLAGS "-fPIC")\nset(VCPKG_CXX_FLAGS "-fPIC")\n')
build = work / 'native-build'
prefix = work / 'prefix'
for directory in [build, prefix]:
    if directory.exists():
        shutil.rmtree(directory)
run('cmake', '-S', repo / 'cpp', '-B', build, '-G', 'Ninja',
    '-DCMAKE_BUILD_TYPE=Release', '-DBUILD_SHARED_LIBS=ON', '-DREQUIRE_BORINGSSL=ON',
    '-DPERSISTENT_KEYS=OFF', '-DTESTING=OFF', '-DINSTALL_VCPKG_LICENSES=ON',
    '-DCMAKE_INSTALL_PREFIX=' + str(prefix),
    '-DCMAKE_INSTALL_RPATH=$ORIGIN',
    '-DCMAKE_TOOLCHAIN_FILE=' + str(repo / 'cpp/vcpkg/scripts/buildsystems/vcpkg.cmake'),
    '-DVCPKG_MANIFEST_DIR=' + str(repo / 'cpp/vcpkg-alts/boringssl'),
    '-DVCPKG_OVERLAY_TRIPLETS=' + str(triplets), '-DVCPKG_TARGET_TRIPLET=x64-linux-flex',
    '-DVCPKG_INSTALLED_DIR=/work/vcpkg-installed')
run('cmake', '--build', build, '--parallel', os.environ['BUILD_JOBS'])
run('cmake', '--install', build)
lib = next(prefix.rglob('libdave.so'))
symbols = capture('nm', '-D', '--defined-only', lib)
for symbol in lock['required_extensions'] + ['daveSessionCreate', 'daveEncryptorCreate', 'daveDecryptorCreate', 'daveFree']:
    if not re.search(r'\b' + re.escape(symbol) + r'$', symbols, re.M):
        raise RuntimeError('Missing native ABI: ' + symbol)
ctypes.CDLL(str(lib), mode=os.RTLD_NOW)
bundle = work / 'bundle'
if bundle.exists():
    shutil.rmtree(bundle)
(bundle / 'lib').mkdir(parents=True)
shutil.copy2(lib.resolve(), bundle / 'lib/libdave.so')
closure = elf_closure([lib], bundle / 'lib', exclude_system=True)
# Require every version node from the loader-selected real providers, including
# EL9's backported nodes; a numeric glibc release is not an export-version cap.
os.environ['LD_LIBRARY_PATH'] = str(bundle / 'lib')
builder_abi = check_elf_versions([bundle / 'lib/libdave.so'])
licenses = bundle / 'licenses'
shutil.copytree(prefix / 'licenses', licenses)
# Preserve every vcpkg installed dependency copyright, not only direct deps.
for notice in (work / 'vcpkg-installed').rglob('copyright'):
    relative = notice.relative_to(work / 'vcpkg-installed')
    target = licenses / 'vcpkg' / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(notice, target)
for library in closure:
    package = capture('rpm', '-qf', Path(library).resolve())
    for file in capture('rpm', '-ql', package).splitlines():
        p = Path(file)
        if p.is_file() and ('/licenses/' in file or '/license/' in file or p.name.upper().startswith(('COPYING', 'LICENSE', 'NOTICE'))):
            target = licenses / 'system' / file.lstrip('/')
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, target)
provenance = bundle / 'provenance'
provenance.mkdir()
write_json(provenance / 'builder-abi.json', builder_abi)
shutil.copy2(lock_path, provenance / 'native-lock.json')
(provenance / 'libdave-patches').mkdir()
for patch in patches:
    shutil.copy2(patch, provenance / 'libdave-patches' / patch.name)
shutil.copy2('/opt/flexmodule-builder/packages.txt', provenance / 'builder-packages.txt')
(provenance / 'native-symbols.txt').write_text(symbols)
(provenance / 'configure-cache.txt').write_text((build / 'CMakeCache.txt').read_text())
(provenance / 'source.patch').write_text(capture('git', '-C', repo, 'diff', '--binary'))
shutil.copyfile(work / 'vcpkg-installed/vcpkg/status', provenance / 'vcpkg-status.txt')
write_json(provenance / 'compiler-inputs.json', {
    'go_codegen': capture('/go/bin/go', 'version'),
    'cc': capture('gcc', '--version'),
    'cxx': capture('g++', '--version'),
    'cmake': capture('cmake', '--version'),
    'vcpkg_sha256': digest(repo / 'cpp/vcpkg/vcpkg'),
    'triplet_sha256': digest(triplets / 'x64-linux-flex.cmake'),
})
write_json(provenance / 'builder-source-sha256.json', {
    path: digest(source / path) for path in [
        'tools/native/build.py', 'tools/native/Builder.Dockerfile',
        'tools/native/repositories.repo', 'tools/build/artifacts.py', 'tools/build/voice.sh',
        'tools/native/check_abi.py', 'tools/native/runtime.py',
        'tools/native/runtime-packages.lock.json', 'tools/sdk.py', 'tools/versions.mk',
    ]
})
write_json(provenance / 'downloads.json', inventory(work / 'downloads'))
write_json(provenance / 'sdk-module.json', sdk_provenance(sdk))
write_json(provenance / 'native-assets-sha256.json', {
    str(path.relative_to(source)): digest(path) for path in (lock_path, *patches)
})
write_json(provenance / 'sdk-source-sha256.json', {
    str(path.relative_to(sdk_source)): digest(path)
    for path in sdk_source.rglob('*')
    if path.is_file() and (path.suffix == '.go' or path.name in ('go.mod', 'go.sum'))
})
if os.environ.get('NATIVE_ONLY') == '1':
    write_json(provenance / 'bundle-sha256.json', inventory(bundle))
    run(sys.executable, source / 'tools/native/runtime.py', '--voice-libraries', bundle / 'lib')
    print('Native-only source build complete: /work/prefix and /work/bundle; no root Go packages compiled.')
    sys.exit(0)

# Build and link Go in the SAME EL9 compiler environment; no host C toolchain.
env = os.environ.copy()
env.update(CGO_ENABLED='1', GOOS='linux', GOARCH='amd64', GOTOOLCHAIN='local', GOWORK='off',
           GOPATH='/work/go', GOCACHE='/work/go-cache', GOMODCACHE='/work/go-modcache',
           CGO_CFLAGS='-I' + str(prefix / 'include'),
           CGO_LDFLAGS='-L' + str(lib.parent) + ' -Wl,-rpath,$ORIGIN/voice-runtime/lib')
dependencies = capture('/go/bin/go', '-C', source, 'list', '-mod=readonly',
                       '-tags=voice', '-deps', './cmd/chatanium-worker', env=env)
if 'github.com/thirdscam/chatanium/internal/releasepayload' in dependencies.splitlines():
    raise RuntimeError('Native worker must never recursively embed releasepayload')
run('/go/bin/go', '-C', source, 'build', '-mod=readonly', '-trimpath', '-tags=voice', '-o', bundle / 'chatanium-worker', './cmd/chatanium-worker', env=env)
env['LD_LIBRARY_PATH'] = str(bundle / 'lib')
run('/lib64/ld-linux-x86-64.so.2', '--list', bundle / 'chatanium-worker', env=env)
(provenance / 'go-build-info.txt').write_text(capture('/go/bin/go', 'version', '-m', bundle / 'chatanium-worker'))
go_sources = {}
for directory, children, files in os.walk(source):
    children[:] = [name for name in children if not name.startswith('.') and name not in ('bin', 'temp_audio')]
    for name in files:
        if name.endswith('.go') or name in ('go.mod', 'go.sum'):
            file = Path(directory) / name
            go_sources[str(file.relative_to(source))] = digest(file)
write_json(provenance / 'go-source-sha256.json', go_sources)
# Voice receipt paths are relative to the published bin/ layout, not /work/bundle.
write_json(provenance / 'bundle-sha256.json', {
    path if path == 'chatanium-worker' else 'voice-runtime/' + path: checksum
    for path, checksum in inventory(bundle).items()
})
# Seed the pinned RPM closure only after the real worker exists, including all
# adjacent native DSOs. No system dependency is inferred from libdave alone.
run(sys.executable, source / 'tools/native/runtime.py',
    '--worker', bundle / 'chatanium-worker', '--voice-libraries', bundle / 'lib')
