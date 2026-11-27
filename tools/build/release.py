#!/usr/bin/env python3
"""Verify original GVX assets, build the portable closure and embed it offline."""
import argparse
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
from urllib.parse import urlsplit
import urllib.request
import zipfile

sys.dont_write_bytecode = True
from artifacts import canonical_json, capture, digest, run, write_json

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / 'internal/bundle/portable-release-lock.json'
PAYLOAD = ROOT / 'internal/releasepayload/assets'
NOTICES = ('LICENSE', 'README.md', 'THIRD_PARTY_LICENSES.txt')
PAYLOAD_PKG = 'github.com/thirdscam/chatanium/internal/releasepayload'


class BuildProgress:
    def __init__(self):
        self.live = sys.stdout.isatty() and os.environ.get('CHATANIUM_BUILD_TTY') == '1'
        self.color = self.live and not os.environ.get('NO_COLOR')
        self.detail_visible = False

    def label(self, step, style='36'):
        if self.color:
            return f'\x1b[1;{style}m[ RT ]\x1b[0m \x1b[1m[{step}]\x1b[0m'
        return f'[ RT ] [{step}]'

    def clear_detail(self):
        if self.detail_visible:
            print('\r\x1b[2K', end='', flush=True)
            self.detail_visible = False

    def stage(self, step, message):
        self.clear_detail()
        print(f'{self.label(step)} {message}', flush=True)

    def detail(self, step, total, message):
        if self.live:
            columns = shutil.get_terminal_size().columns
            line = f'       {step}/{total}  {message}'
            print('\r\x1b[2K' + line[:max(0, columns - 1)], end='', flush=True)
            self.detail_visible = True

    def done(self, message):
        self.clear_detail()
        print(f'{self.label("OK", "32")} {message}', flush=True)

    def failed(self, error):
        if self.detail_visible:
            # A tool may have written diagnostics since the last update.
            print(flush=True)
            self.detail_visible = False
        print(f'{self.label("FAIL", "31")} {error}', file=sys.stderr, flush=True)


def _trusted_verifier_path(supplied):
    if not supplied.is_absolute():
        raise RuntimeError('TRUSTED_GH must be an independently trusted absolute path')
    verifier = supplied.resolve(strict=True)
    if not verifier.is_file() or not os.access(verifier, os.X_OK):
        raise RuntimeError('TRUSTED_GH is not a regular executable')
    for path in (verifier, *verifier.parents):
        info = path.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise RuntimeError(f'Untrusted verifier path: {path}')
    return verifier


def trusted_verifier():
    supplied = os.environ.get('TRUSTED_GH')
    if supplied is not None:
        return _trusted_verifier_path(Path(supplied))
    for entry in os.environ.get('PATH', '').split(os.pathsep):
        directory = Path(entry)
        if not directory.is_absolute():
            continue
        try:
            return _trusted_verifier_path(directory / 'gh')
        except (OSError, RuntimeError):
            continue
    raise RuntimeError('No trusted gh executable found in PATH; set TRUSTED_GH to an '
                       'independently trusted root-owned GitHub CLI executable')


def download(url, destination, size, sha256):
    if destination.is_symlink() or (destination.exists() and not destination.is_file()):
        raise RuntimeError(f'Unsafe download destination: {destination}')
    if destination.exists() and destination.stat().st_size == size and digest(destination) == sha256:
        return destination
    with tempfile.NamedTemporaryFile(dir=destination.parent, prefix='.acquire-', delete=False) as temporary:
        path = Path(temporary.name)
        try:
            checksum = hashlib.sha256()
            with urllib.request.urlopen(url, timeout=120) as response:
                origin = urlsplit(response.geturl())
                if origin.scheme != 'https' or origin.hostname != 'release-assets.githubusercontent.com':
                    raise RuntimeError(f'Unexpected GitHub asset download origin: {url}')
                remaining = size
                while remaining and (data := response.read(min(remaining, 1 << 20))):
                    temporary.write(data)
                    checksum.update(data)
                    remaining -= len(data)
                if remaining or response.read(1):
                    raise RuntimeError(f'Pinned asset size mismatch: {url}')
            if checksum.hexdigest() != sha256:
                raise RuntimeError(f'Pinned asset digest mismatch: {url}')
            temporary.flush()
            os.fchmod(temporary.fileno(), 0o444)
            os.replace(path, destination)
        finally:
            path.unlink(missing_ok=True)
    return destination


def publish_file(source, destination, mode):
    if destination.is_symlink() or (destination.exists() and not destination.is_file()):
        raise RuntimeError(f'Unsafe build output: {destination}')
    with tempfile.NamedTemporaryFile(dir=destination.parent, prefix='.publish-', delete=False) as output:
        path = Path(output.name)
        try:
            with source.open('rb') as data:
                shutil.copyfileobj(data, output)
            output.flush()
            os.fchmod(output.fileno(), mode)
            os.replace(path, destination)
        finally:
            path.unlink(missing_ok=True)


def asset_name(lock, target):
    prefix = f'rungv-{lock["release"]}-{target.replace("/", "-")}'
    return prefix, prefix + ('.zip' if target.startswith('windows/') else '.tar.gz')


def verify_attestation(gh, env, trust, lock, archive, attestation, asset):
    ref = 'refs/tags/' + lock['release']
    policy = ['attestation', 'verify', str(archive), '--bundle', str(attestation),
              '--custom-trusted-root', str(trust), '--repo', lock['repository'],
              '--signer-workflow', lock['workflow'], '--source-ref', ref,
              '--source-digest', lock['commit'], '--deny-self-hosted-runners', '--format', 'json']
    result = json.loads(capture(gh, *policy, env=env))
    signer = 'https://github.com/' + lock['workflow'] + '@' + ref
    identities = {'issuer': 'https://token.actions.githubusercontent.com', 'buildSignerURI': signer,
                  'buildSignerDigest': lock['commit'], 'runnerEnvironment': 'github-hosted',
                  'sourceRepositoryURI': 'https://github.com/' + lock['repository'],
                  'sourceRepositoryIdentifier': lock['repository_id'],
                  'sourceRepositoryOwnerIdentifier': lock['owner_id'], 'sourceRepositoryRef': ref,
                  'sourceRepositoryDigest': lock['commit'], 'buildTrigger': 'push'}
    for verified in result:
        entry = verified.get('verificationResult', {})
        cert = entry.get('signature', {}).get('certificate', {})
        statement = entry.get('statement', {})
        subject = [s for s in statement.get('subject', []) if s.get('name') == archive.name]
        if (all(cert.get(key) == value for key, value in identities.items()) and
                statement.get('predicateType') == 'https://slsa.dev/provenance/v1' and
                subject == [{'name': archive.name, 'digest': {'sha256': asset['archive_sha256']}}]):
            return {'policy': identities, 'verification_result': entry}
    raise RuntimeError('No verified attestation binds exact target asset, workflow, repository/owner identities, tag and commit')


def unpack_asset(archive, prefix, destination, executable):
    names = set((*NOTICES, executable))
    is_zip = archive.suffix == '.zip'
    container = zipfile.ZipFile(archive) if is_zip else tarfile.open(archive, 'r:gz')
    with container:
        for entry in container.infolist() if is_zip else container:
            name = entry.filename if is_zip else entry.name
            if (entry.is_dir() if is_zip else entry.isdir()) and name.rstrip('/') == prefix:
                continue
            relative = name.removeprefix(prefix + '/')
            size = entry.file_size if is_zip else entry.size
            regular = stat.S_ISREG(entry.external_attr >> 16) if is_zip else entry.isreg() and not entry.pax_headers
            if relative == name or relative not in names or not regular or not 0 < size <= 128 << 20:
                raise RuntimeError(f'Unexpected GVX release member: {name}')
            reader = container.open(entry) if is_zip else container.extractfile(entry)
            with reader as source, (destination / relative).open('xb') as output:
                shutil.copyfileobj(source, output)
                if output.tell() != size:
                    raise RuntimeError(f'Truncated GVX release member: {name}')
            names.remove(relative)
    if names:
        raise RuntimeError(f'Missing GVX release members: {sorted(names)}')


def verify_hvf_signature(path):
    # Upstream ships ad-hoc signing, not an Apple signing identity. Check the
    # embedded entitlement, its CodeDirectory hash, and all signed Mach-O pages
    # without running anything or re-signing the attested bytes.
    with path.open('rb') as file:
        magic, cpu, _, kind, commands, command_bytes, _, _ = struct.unpack('<8I', file.read(32))
        if (magic, cpu, kind) != (0xfeedfacf, 0x100000c, 2) or command_bytes > 1 << 20:
            raise RuntimeError('Invalid HVF Mach-O header')
        loads = file.read(command_bytes)
        offset = 0
        signature = []
        for _ in range(commands):
            command, size = struct.unpack_from('<II', loads, offset)
            if size < 8 or offset + size > len(loads):
                raise RuntimeError('Invalid HVF Mach-O load command')
            if command == 0x1d and size == 16:  # LC_CODE_SIGNATURE
                signature.append(struct.unpack_from('<II', loads, offset + 8))
            offset += size
        if offset != command_bytes or len(signature) != 1:
            raise RuntimeError('Missing unique HVF code signature')
        offset, size = signature[0]
        if size > 1 << 20 or offset + size != path.stat().st_size:
            raise RuntimeError('Invalid HVF code signature boundary')
        file.seek(offset)
        blob = file.read(size)
        magic, length, count = struct.unpack_from('>III', blob)
        if magic != 0xfade0cc0 or not 12 + 8 * count <= length <= len(blob):
            raise RuntimeError('Invalid HVF signature superblob')
        slots = {}
        for i in range(count):
            slot, start = struct.unpack_from('>II', blob, 12 + i * 8)
            _, size = struct.unpack_from('>II', blob, start)
            if slot in slots or start < 12 + 8 * count or size < 8 or start + size > length:
                raise RuntimeError('Invalid HVF signature slot')
            slots[slot] = blob[start:start + size]
        code, entitlements, der = slots[0], slots[5], slots[7]
        magic, _, _, flags, hashes, _, special, pages, limit, width, algorithm, _, shift = struct.unpack_from('>9I4B', code)
        if (magic != 0xfade0c02 or not flags & 2 or (width, algorithm) != (32, 2) or
                struct.unpack_from('>I', entitlements)[0] != 0xfade7171 or
                plistlib.loads(entitlements[8:]).get('com.apple.security.hypervisor') is not True or
                struct.unpack_from('>I', der)[0] != 0xfade7172 or
                not 12 <= shift <= 16 or limit != offset or special < 7 or hashes < special * width or
                hashes + pages * width > len(code)):
            raise RuntimeError('Expected SHA-256 ad-hoc code signature with the HVF entitlement')
        for index, entitlement in ((5, entitlements), (7, der)):
            if hashlib.sha256(entitlement).digest() != code[hashes - index * width:hashes - (index - 1) * width]:
                raise RuntimeError('HVF entitlement is not bound to the code signature')
        page_size = 1 << shift
        if pages != (limit + page_size - 1) // page_size:
            raise RuntimeError('Invalid HVF signature code-page count')
        file.seek(0)
        for page in range(pages):
            data = file.read(min(page_size, limit - page * page_size))
            index = hashes + page * width
            if hashlib.sha256(data).digest() != code[index:index + width]:
                raise RuntimeError(f'HVF code signature page {page} does not match executable bytes')


def target_env(target, asset):
    os_name, arch = target.split('/')
    arch_key, level = asset['go_arch_setting'].split('=')
    env = {k: v for k, v in os.environ.items() if k not in ('GOAMD64', 'GOARM64', 'GOEXPERIMENT', 'GOFIPS140')}
    env.update(GOOS=os_name, GOARCH=arch, CGO_ENABLED='0', GOENV='off', GOFLAGS='', GOWORK='off')
    env[arch_key] = level
    return env


def executable_info(go, path, target, asset, lock=None):
    os_name, arch = target.split('/')
    metadata = json.loads(capture(go, 'version', '-m', '-json', path))
    settings = {item['Key']: item['Value'] for item in metadata['Settings']}
    arch_key, level = asset['go_arch_setting'].split('=')
    expected = {'CGO_ENABLED': '0', 'GOOS': os_name, 'GOARCH': arch, arch_key: level}
    if lock:
        expected.update({'vcs.revision': lock['commit'], 'vcs.modified': 'false'})
        main = metadata['Main']
        if (metadata['Path'] != 'z.gfire.dev/gvx/cmd/rungv' or
                main['Path'] != 'z.gfire.dev/gvx' or main['Version'] != lock['release'] or
                main.get('Replace') is not None):
            raise RuntimeError(f'Wrong GVX executable path or release: {path}')
    mismatched = sorted(key for key, value in expected.items() if settings.get(key) != value)
    if mismatched:
        raise RuntimeError(f'Wrong executable target or ABI: {path}: {mismatched}')
    if os_name == 'linux' and 'INTERP' in capture('readelf', '-lW', path):
        raise RuntimeError(f'Expected a static Linux executable: {path}')
    if lock and asset.get('native_signature') == 'adhoc-hvf-entitlement':
        verify_hvf_signature(path)
    return metadata


def upstream(go, gh, gh_env, trust, lock, target, downloads, attestation, stage):
    asset = lock['targets'][target]
    prefix, name = asset_name(lock, target)
    base = f'https://github.com/{lock["repository"]}/releases/download/{lock["release"]}/'
    archive = download(base + name, downloads / name, asset['archive_size'], asset['archive_sha256'])
    evidence = verify_attestation(gh, gh_env, trust, lock, archive, attestation, asset)
    tag = target.replace('/', '-')
    files = stage / 'licenses' / 'rungv' / tag
    files.mkdir(parents=True)
    executable = 'rungv.exe' if target.startswith('windows/') else 'rungv'
    unpack_asset(archive, prefix, files, executable)
    original = files / executable
    if digest(original) != asset['executable_sha256']:
        raise RuntimeError(f'Pinned GVX executable digest mismatch for {target}')
    evidence['go_build_info'] = executable_info(go, original, target, asset, lock)
    evidence['archive_url'] = base + name
    write_json(stage / 'provenance' / f'rungv-{tag}.json', evidence)
    record = {'release': lock['release'], 'commit': lock['commit'],
              'archive_digest': 'sha256:' + asset['archive_sha256'],
              'attestation_digest': 'sha256:' + lock['attestation_sha256'],
              'executable_digest': 'sha256:' + asset['executable_sha256']}
    if 'native_signature' in asset:
        record['native_signature'] = asset['native_signature']
    return original, record


def collect_go_modules(go, env, packages, modules, helper=False):
    # Selective go list does not resolve embed patterns. This lists the actual
    # native dependencies even on a fresh source checkout before payload assembly.
    data = capture(go, 'list', '-mod=readonly', '-deps', '-json=ImportPath,Module', *packages, env=env)
    decoder = json.JSONDecoder()
    while data:
        package, end = decoder.raw_decode(data)
        data = data[end:].lstrip()
        if helper and package['ImportPath'] == PAYLOAD_PKG:
            raise RuntimeError('Worker or helper must not recursively embed the portable payload')
        module = package.get('Module')
        if module and not module.get('Main'):
            modules[module['Path']] = module


def go_build(go, package, output, env):
    run(go, 'build', '-mod=readonly', '-trimpath', '-tags=', '-o', output, package, env=env)


def build_program(go, package, output, target, asset, stage):
    go_build(go, package, output, target_env(target, asset))
    name = output.name.removesuffix('.exe')
    write_json(stage / 'provenance' / (name + '-build.json'), executable_info(go, output, target, asset))


def sbom(go, stage, modules, engines):
    components = []
    for label, identity in engines.items():
        components.append({'type': 'application', 'name': 'rungv', 'version': identity['release'],
                           'bom-ref': 'rungv-' + label,
                           'hashes': [{'alg': 'SHA-256', 'content': identity['executable_digest'][7:]}],
                           'licenses': [{'license': {'id': 'Apache-2.0'}}],
                           'properties': [{'name': 'chatanium:target', 'value': label},
                                          {'name': 'chatanium:upstream_notices', 'value': f'licenses/rungv/{label}/THIRD_PARTY_LICENSES.txt'}]})
    shutil.copyfile(ROOT / 'LICENSE', stage / 'licenses' / 'CHATANIUM-LICENSE')
    shutil.copyfile(ROOT / 'LICENSE.flexmodule', stage / 'licenses' / 'LICENSE.flexmodule')
    goroot = Path(capture(go, 'env', 'GOROOT'))
    for name in ('LICENSE', 'PATENTS'):
        shutil.copyfile(goroot / name, stage / 'licenses' / ('GO-' + name))
    for i, (name, module) in enumerate(sorted(modules.items())):
        directory = Path(module.get('Replace', module)['Dir'])
        notices = sorted(p for p in directory.iterdir() if p.is_file() and
                         p.name.lower().startswith(('license', 'copying', 'notice', 'copyright')))
        if not notices:
            raise RuntimeError(f'Missing license notice for distributed Go dependency {name}')
        dest = stage / 'licenses' / 'go' / str(i)
        dest.mkdir(parents=True)
        properties = [{'name': 'go:sum', 'value': module.get('Sum', '')}]
        for j, notice in enumerate(notices):
            path = dest / f'{j}.txt'
            shutil.copyfile(notice, path)
            properties.append({'name': 'chatanium:notice:' + notice.name, 'value': path.relative_to(stage).as_posix()})
        components.append({'type': 'library', 'name': name, 'version': module.get('Version', ''), 'properties': properties})
    write_json(stage / 'sbom.json', {'bomFormat': 'CycloneDX', 'specVersion': '1.6', 'version': 1, 'components': components})


def assemble(go, stage, inputs, target, lock, engine, guest_engine, executables):
    os_name, arch = target.split('/')
    asset = lock['targets'][target]
    manifest = {'format': 'portable-v2', 'target': {'os': os_name, 'arch': arch, 'backend': asset['backend'],
                'cpu_baseline': asset['cpu_baseline']}, 'native_voice': False, 'engine': engine,
                'guest_engine': guest_engine, 'files': []}
    for path in sorted(stage.rglob('*')):
        if path.is_file():
            manifest['files'].append({'path': path.relative_to(stage).as_posix(), 'size': path.stat().st_size,
                                      'digest': 'sha256:' + digest(path), 'mode': 0o555 if path in executables else 0o444})
    identity = hashlib.sha256(b'chatanium-bundle-portable-v2\0' + canonical_json(manifest)).hexdigest()
    manifest['digest'] = 'sha256:' + identity
    inputs.mkdir()
    (inputs / 'manifest.json').write_bytes(canonical_json(manifest) + b'\n')
    with (inputs / 'bundle.tar.gz').open('wb') as stream, gzip.GzipFile(fileobj=stream, mode='wb', mtime=0, filename='') as gz, tarfile.open(fileobj=gz, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for item in manifest['files']:
            header = tarfile.TarInfo(item['path'])
            header.size, header.mode = item['size'], item['mode']
            with (stage / item['path']).open('rb') as data:
                archive.addfile(header, data)
    host = capture(go, 'env', 'GOHOSTOS', 'GOHOSTARCH').replace('\n', '/')
    host_os, host_arch = host.split('/')
    env = dict(os.environ, GOOS=host_os, GOARCH=host_arch, CGO_ENABLED='0', GOFLAGS='', GOENV='off')
    run(go, 'run', '-mod=readonly', './tools/build/verifybundle', target, inputs, env=env, stdout=subprocess.DEVNULL)
    return host


def build(target, progress):
    lock = json.loads(LOCK.read_text())
    if target not in lock['targets']:
        raise RuntimeError(f'Unsupported portable-v2 target: {target}')
    progress.stage('2/3', f'Verify pinned GVX for {target} ({lock["targets"][target]["backend"]})')
    gh = trusted_verifier()
    go = os.environ['GO_BINARY']
    os_name, arch = target.split('/')
    tag = target.replace('/', '-')
    guest_target = 'linux/' + arch
    guest_tag = guest_target.replace('/', '-')
    host_env = target_env(target, lock['targets'][target])
    guest_env = target_env(guest_target, lock['targets'][guest_target])
    work = ROOT / '.tools/release/portable'
    downloads = work / 'downloads'
    out = work / tag
    for directory in (work, downloads, out, PAYLOAD, ROOT / 'bin'):
        if directory.is_symlink():
            raise RuntimeError(f'Symlink in portable build path: {directory}')
        directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=work, prefix='.stage-') as temporary:
        temp = Path(temporary)
        stage = temp / 'bundle'
        for directory in ('bin', 'guest', 'licenses', 'provenance'):
            (stage / directory).mkdir(parents=True)
        attestation_name = f'rungv-{lock["release"]}.sigstore.json'
        url = f'https://github.com/{lock["repository"]}/releases/download/{lock["release"]}/{attestation_name}'
        attestation = download(url, downloads / attestation_name, lock['attestation_size'], lock['attestation_sha256'])
        signed = json.loads(attestation.read_bytes())
        cert = base64.b64decode(signed['verificationMaterial']['certificate']['rawBytes'], validate=True)
        if hashlib.sha256(cert).hexdigest() != lock['certificate_sha256']:
            raise RuntimeError('Pinned GVX release signing certificate mismatch')
        # Use official Sigstore trust root discovery, never an inherited GH
        # enterprise host, custom root override, or verifier configuration.
        gh_env = {'PATH': os.defpath, 'HOME': str(temp), 'GH_CONFIG_DIR': str(temp / 'gh'),
                  'GH_HOST': 'github.com', 'GH_PROMPT_DISABLED': '1'}
        trust = temp / 'trusted-root.json'
        trust.write_text(capture(gh, 'attestation', 'trusted-root', env=gh_env) + '\n')
        shutil.copyfile(attestation, stage / 'provenance' / 'rungv.sigstore.json')
        shutil.copyfile(LOCK, stage / 'provenance' / LOCK.name)
        (stage / 'provenance' / 'verifier-version.txt').write_text(capture(gh, '--version', env=gh_env) + '\n')
        original, engine = upstream(go, gh, gh_env, trust, lock, target, downloads, attestation, stage)
        host_rungv = stage / 'bin' / original.name
        original.rename(host_rungv)
        engines = {tag: engine}
        guest_engine, guest_rungv = engine, host_rungv
        if target != guest_target:
            original, guest_engine = upstream(go, gh, gh_env, trust, lock, guest_target, downloads, attestation, stage)
            guest_rungv = stage / 'guest' / original.name
            original.rename(guest_rungv)
            engines[guest_tag] = guest_engine
        progress.stage('3/3', 'Build and package the portable launcher')
        progress.detail(1, 7, 'Resolve Go dependencies')

        worker_pkg = './cmd/chatanium-worker'
        guest_pkgs = ('./cmd/gvx-guest-bridge', './cmd/gvx-preparer')
        modules = {}
        collect_go_modules(go, host_env, (worker_pkg,), modules, helper=True)
        collect_go_modules(go, guest_env, guest_pkgs, modules, helper=True)
        collect_go_modules(go, host_env, ('.',), modules)
        suffix = '.exe' if os_name == 'windows' else ''
        worker = stage / 'bin' / ('chatanium-worker' + suffix)
        progress.detail(2, 7, 'Compile runtime worker')
        build_program(go, worker_pkg, worker, target, lock['targets'][target], stage)
        guest_programs = []
        for index, package in enumerate(guest_pkgs, start=3):
            progress.detail(index, 7, f'Compile {package.rsplit("/", 1)[1]}')
            output = stage / 'guest' / package.rsplit('/', 1)[1]
            build_program(go, package, output, guest_target, lock['targets'][guest_target], stage)
            guest_programs.append(output)
        progress.detail(5, 7, 'Assemble and verify the embedded bundle')
        sdk = json.loads(capture('python3', ROOT / 'tools/sdk.py', '--go', go, '--verify-only', '--json'))
        sdk.pop('Dir', None)
        write_json(stage / 'provenance' / 'sdk-module.json', sdk)
        write_json(stage / 'provenance' / 'product-source.json', {
            'checkout_head': capture('git', 'rev-parse', 'HEAD'),
            'clean_checkout': not capture('git', 'status', '--porcelain'),
            'native_voice': False,
            'product_authentication': 'External CI artifact attestation only; a local build is not an attested product release.',
        })
        sbom(go, stage, modules, engines)
        inputs = temp / 'embed'
        host = assemble(go, stage, inputs, target, lock, engine, guest_engine,
                        {host_rungv, guest_rungv, worker, *guest_programs})
        # Keep the generated inputs for local Go work. The build script holds
        # the shared workspace's release lock across embedding and compilation.
        for name in ('manifest.json', 'bundle.tar.gz'):
            publish_file(inputs / name, PAYLOAD / name, 0o644)
        launcher = temp / ('chatanium-' + tag + suffix)
        progress.detail(6, 7, 'Compile and verify the launcher')
        go_build(go, '.', launcher, host_env)
        executable_info(go, launcher, target, lock['targets'][target])
        progress.detail(7, 7, 'Publish launcher, manifest and SBOM')
        publish_file(inputs / 'manifest.json', out / 'bundle-manifest.json', 0o444)
        publish_file(stage / 'sbom.json', out / 'sbom.json', 0o444)
        publish_file(launcher, out / launcher.name, 0o755)
        if host == target:
            publish_file(launcher, ROOT / 'bin' / ('chatanium' + suffix), 0o755)
    progress.done(str((out / launcher.name).relative_to(ROOT)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target', help='exact GOOS/GOARCH pair')
    args = parser.parse_args()
    progress = BuildProgress()
    try:
        os.chdir(ROOT)
        build(args.target, progress)
    except (KeyError, OSError, ValueError, RuntimeError, struct.error, tarfile.TarError, zipfile.BadZipFile,
            subprocess.CalledProcessError) as error:
        progress.failed(error)
        sys.exit(1)
