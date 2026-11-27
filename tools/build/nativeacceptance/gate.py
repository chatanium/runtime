#!/usr/bin/env python3
"""Create the test OCI archive, qualify an exact native candidate, or verify its receipt."""
import argparse
import asyncio
import ctypes
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import socket
import stat
import subprocess
import sys
import tempfile
import uuid

HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE.parent))
from module_oci import pack

ROOT = HERE.parents[2]
LOCK = ROOT / 'internal/bundle/portable-release-lock.json'
PROMPT = re.compile(rb'Type (sha256:[0-9a-f]{64}) to approve: ')
PUBLIC = ('1.1.1.1', 443)
VOLUME = 16 << 20
BUDGET = 12 << 30
MODULE = 'release-probe'
CHECKS = [
    'read-only doctor verified installed code, rejected an extra file without removing it, and skipped uninstalled code',
    'fixed singleton path and bounded installation plan on an isolated data home or disposable account',
    'same-ISA offline OCI preparation and approved configuration',
    'native nonroot init, serve and observed clean stop in NONE and PUBLIC_INTERNET',
    'TCP closed before approval, public TCP open after approval, private listener blocked',
    'requested NAT policy and nonzero send/receive ceilings verified by native adapter',
    'persistent seed survived, scratch and tmp were fresh, shared and separate volume ceilings enforced',
    'uninstall removed code and retained data; approved purge retained the shared parent and launcher without a terminal receipt',
]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def file_hash(path):
    with path.open('rb') as file:
        return 'sha256:' + hashlib.file_digest(file, 'sha256').hexdigest()


def document(path, value):
    path.write_bytes(canonical(value) + b'\n')
    return path


def files(directory, target):
    tag = target.replace('/', '-')
    return (directory / ('chatanium-' + tag + ('.exe' if target.startswith('windows/') else '')),
            directory / ('bundle-manifest-' + tag + '.json'), directory / ('sbom-' + tag + '.json'),
            directory / ('native-acceptance-' + tag + '.json'), directory / ('native-acceptance-' + tag + '.sigstore.json'))


def workflow_identity():
    return {key.lower(): os.environ['GITHUB_' + key] for key in ('SHA', 'REF', 'RUN_ID', 'RUN_ATTEMPT')}


def expected_receipt(candidate, target):
    lock = json.loads(LOCK.read_bytes())
    launcher, manifest, sbom, _, _ = files(candidate, target)
    data = json.loads(manifest.read_bytes())
    os_name, arch = target.split('/')
    host, guest = lock['targets'][target], lock['targets']['linux/' + arch]
    require(data['format'] == 'portable-v2' and data['native_voice'] is False and data['target'] == {
        'os': os_name, 'arch': arch, 'backend': host['backend'], 'cpu_baseline': host['cpu_baseline']},
        'candidate manifest is not the requested portable native target')
    for kind, asset in (('engine', host), ('guest_engine', guest)):
        engine = {'release': lock['release'], 'commit': lock['commit'],
                  'archive_digest': 'sha256:' + asset['archive_sha256'],
                  'attestation_digest': 'sha256:' + lock['attestation_sha256'],
                  'executable_digest': 'sha256:' + asset['executable_sha256']}
        if 'native_signature' in asset:
            engine['native_signature'] = asset['native_signature']
        require(data[kind] == engine, 'candidate carries a different pinned GVX engine')
    members = {f['path']: f for f in data['files']}
    require(members['sbom.json']['digest'] == file_hash(sbom), 'standalone SBOM differs from bundled SBOM')
    return {'schema': 1, 'target': target, 'backend': host['backend'], 'workflow': workflow_identity(),
            'launcher_sha256': file_hash(launcher), 'manifest_sha256': file_hash(manifest), 'sbom_sha256': file_hash(sbom),
            'bundle_digest': data['digest'], 'gvx_commit': lock['commit'], 'gvx_release': lock['release'],
            'gvx_host_executable': data['engine']['executable_digest'],
            'gvx_guest_executable': data['guest_engine']['executable_digest'], 'checks': CHECKS}


def require_native_user(target):
    machine = platform.machine().lower()
    arch = {'x86_64': 'amd64', 'amd64': 'amd64', 'arm64': 'arm64', 'aarch64': 'arm64'}.get(machine)
    require(target == platform.system().lower() + '/' + str(arch), 'runner is not native to the requested OS/ISA')
    if os.name == 'nt':
        # LocalAppData follows the native token, not HOME or LOCALAPPDATA in the environment.
        require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted',
                'Windows qualification requires a disposable GitHub-hosted runner account')
        # PROCESSOR_ARCHITEW6432 is set for a WOW64-emulated Python process.
        require(not os.environ.get('PROCESSOR_ARCHITEW6432') and not ctypes.windll.shell32.IsUserAnAdmin(),
                'Windows runner requires a native, non-administrator token')
    else:
        require(os.getuid() != 0 and os.geteuid() == os.getuid() and os.getegid() == os.getgid(),
                'native smoke requires an ordinary unprivileged account')
        if platform.system() == 'Linux':
            status = Path('/proc/self/status').read_text()
            caps = re.findall(r'^Cap(?:Inh|Prm|Eff|Amb):\s*([0-9a-f]+)$', status, re.MULTILINE)
            require(len(caps) == 4 and all(int(value, 16) == 0 for value in caps), 'Linux runner has elevated process capabilities')


def windows_local_app_data():
    # FOLDERID_LocalAppData, with the same flags and current token as the launcher.
    folder = (ctypes.c_ubyte * 16).from_buffer_copy(uuid.UUID('f1b32785-6fba-4fcf-9d55-7b8e7f157091').bytes_le)
    get_path = ctypes.windll.shell32.SHGetKnownFolderPath
    get_path.argtypes = (ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p))
    get_path.restype = ctypes.c_long
    free = ctypes.windll.ole32.CoTaskMemFree
    free.argtypes = (ctypes.c_void_p,)
    free.restype = None
    result = ctypes.c_void_p()
    try:
        status = get_path(ctypes.byref(folder), 0, None, ctypes.byref(result))
        require(status == 0 and result.value, f'could not resolve native LocalAppData (HRESULT 0x{status & 0xffffffff:08x})')
        raw = ctypes.wstring_at(result.value)
    finally:
        free(result)
    path = Path(raw)
    require(path.is_absolute() and re.fullmatch(r'[A-Za-z]:', path.drive) and str(path) == raw and '..' not in path.parts,
            'native LocalAppData is not a canonical absolute path on a local drive')
    return path


def directory_identity(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and
            not (os.name == 'nt' and info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT),
            f'qualification path is not a plain directory: {path}')
    return info.st_dev, info.st_ino


class Trial:
    def __init__(self, launcher, base, target):
        self.launcher = launcher
        self.base = base
        self.env = {key: value for key, value in os.environ.items() if key.upper() in {
            'PATH', 'SYSTEMROOT', 'WINDIR', 'LANG', 'TMP', 'TEMP', 'TMPDIR', 'USERPROFILE'}}
        self.env['HOME'] = str(base)
        if target.startswith('linux/'):
            data_home = base / 'data'
            self.env['XDG_DATA_HOME'] = str(data_home)
        elif target.startswith('darwin/'):
            data_home = base / 'Library/Application Support'
        else:
            data_home = windows_local_app_data()
            self.env['LOCALAPPDATA'] = str(data_home)
        self.root = data_home / 'chatanium' / 'runtime'
        self.staging = self.root.with_name('.init-runtime')
        self.terminal = self.root.with_name('.purge-runtime.json')

    def check_slot(self, identity=None):
        for parent in reversed(self.root.parents):
            try:
                directory_identity(parent)
            except FileNotFoundError:
                break
        paths = (self.staging, self.terminal, self.terminal.with_name('.writing-' + self.terminal.name))
        if identity is None:
            paths = (self.root, *paths)
        else:
            require(directory_identity(self.root) == identity, 'qualification installation was replaced')
        for path in paths:
            try:
                path.lstat()
            except FileNotFoundError:
                continue
            raise RuntimeError(f'refusing to use an occupied qualification path: {path}')

    async def spawn(self, command, *args):
        return await asyncio.create_subprocess_exec(str(self.launcher), command, *map(str, args),
            env=self.env, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)

    async def call(self, command, *args, approvals=(), expected_error=None):
        proc = await self.spawn(command, *args)
        stdout = asyncio.create_task(proc.stdout.read())
        stderr = bytearray()
        pending = bytearray()
        seen = 0
        try:
            async with asyncio.timeout(420 if command == 'prepare-image' else 90):
                while data := await proc.stderr.read(16384):
                    stderr.extend(data)
                    pending.extend(data)
                    require(len(stderr) <= 16 << 20, 'native command diagnostics exceeded the release probe bound')
                    while match := PROMPT.search(pending):
                        require(seen < len(approvals), command + ': unexpected additional approval')
                        plans = [line for line in pending[:match.start()].splitlines() if line.startswith(b'{')]
                        require(bool(plans), command + ': approval did not show a JSON scope')
                        approval = json.loads(plans[-1])
                        require(approvals[seen](approval), command + ': approval scope did not match the release fixture')
                        proc.stdin.write(match.group(1) + b'\n')
                        await proc.stdin.drain()
                        seen += 1
                        del pending[:match.end()]
                result = await proc.wait()
                matched = result == 0 if expected_error is None else result == 1 and expected_error in stderr.splitlines()
                require(matched, f'{command} returned unexpected status or diagnostics ({result}): '
                        f'{stderr[-3000:].decode(errors="replace")}')
                require(seen == len(approvals), command + ': missing explicit approval')
                return json.loads(await stdout)
        finally:
            await terminate(proc)
            if not stdout.done():
                stdout.cancel()

    async def run(self, identity):
        proc = await self.spawn('serve')
        stderr = asyncio.create_task(proc.stderr.read())
        try:
            async with asyncio.timeout(75):
                while line := await proc.stdout.readline():
                    ready = json.loads(line)
                    require(ready['type'] != 'FAILED', 'native worker failed: ' + str(ready))
                    if ready['type'] == 'READY':
                        break
                else:
                    raise RuntimeError('worker ended before READY: ' + (await stderr)[-3000:].decode(errors='replace'))
            modules = ready['modules']
            require(len(modules) == 1 and modules[0]['module_id'] == MODULE and modules[0]['state'] == 'RUNNING',
                    'the real release probe module did not reach RUNNING')
            live = modules[0]['instance_id']
            self.check_slot(identity)
            stopped = await self.call('stop')
            require(stopped['state'] == 'STOPPED', 'supervisor did not observe STOPPED')
            async with asyncio.timeout(75):
                remaining, diagnostics = await asyncio.gather(proc.stdout.read(), stderr)
                status = await proc.wait()
            require(status == 0, 'serve exited unsuccessfully: ' + diagnostics[-3000:].decode(errors='replace'))
            drained = [event for line in remaining.splitlines() if (event := json.loads(line))['type'] == 'DRAINED']
            require(len(drained) == 1 and drained[0]['clean'] is True, 'native stop did not prove clean writer exit')
            return live
        finally:
            await terminate(proc)
            if not stderr.done():
                stderr.cancel()


async def terminate(proc):
    if proc.returncode is None:
        try:
            proc.terminate()
        except ProcessLookupError:
            pass
        try:
            await asyncio.wait_for(proc.wait(), 15)
        except TimeoutError:
            proc.kill()
            await proc.wait()


def resource_grant(public):
    capabilities = [{'name': capability, 'resourceScopes': [{'selector': {}}]}
                    for capability in (['core.config.read', 'core.network.public_egress'] if public else ['core.config.read'])]
    return {'coreCapabilities': capabilities, 'resourceClass': 'RESOURCE_CLASS_GENERAL',
            'resourceLimits': {'cpuMillicores': 500, 'memoryBytes': str(256 << 20), 'maxPids': 128,
                               'persistentBytes': str(VOLUME), 'scratchBytes': str(VOLUME)},
            'egressPolicy': 'EGRESS_POLICY_PUBLIC_INTERNET' if public else 'EGRESS_POLICY_NONE'}


async def qualify(candidate, target, image):
    require_native_user(target)
    receipt = expected_receipt(candidate, target)
    launcher, bundle_path, _, result_path, _ = files(candidate, target)
    bundle = json.loads(bundle_path.read_bytes())
    source = file_hash(image)
    with socket.create_connection(PUBLIC, timeout=5) as connection:
        address = connection.getsockname()[0]
    private_networks = tuple(map(ipaddress.ip_network, ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')))
    require(any(ipaddress.ip_address(address) in block for block in private_networks),
            'runner does not have a routed private IPv4 address for a positive-control host listener')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener, tempfile.TemporaryDirectory(prefix='ctrg-') as temporary:
        listener.bind((address, 0))
        listener.listen(8)
        port = listener.getsockname()[1]
        listener.settimeout(3)
        with socket.create_connection((address, port), timeout=3):
            control, _ = listener.accept()
            control.close()
        trial = Trial(launcher, Path(temporary).resolve(strict=True), target)
        root = trial.root
        trial.check_slot()
        own = lambda plan: plan.get('format') == 'portable-v2' and plan.get('installation_directory') == str(root)
        doc = await trial.call('doctor')
        trial.check_slot()
        require(doc['format'] == 'portable-v2' and Path(doc['installation_directory']) == root and not root.exists() and
                doc['bundle_target'] == bundle['target'] and doc['pinned_engine'] == bundle['engine'] and
                doc['verified_embedded_manifest'] == bundle['digest'], 'doctor crossed a user path or disagreed with the exact release manifest')
        require('installed_bundle_verification' not in doc, 'doctor crossed a user path or disagreed with the exact release manifest')

        def approve_init(plan):
            trial.check_slot()
            return (own(plan) and plan.get('initialization_staging_directory') == str(trial.staging) and
                    'installation_id' not in plan and
                    plan.get('shared_parent_retained_after_purge') == str(root.parent) and
                    plan.get('bundle') == bundle and plan.get('maximum_installation_bytes') == BUDGET)

        init = await trial.call('init', '--json-approvals', '--budget-bytes', BUDGET, approvals=(approve_init,))
        require(init['state'] == 'INITIALIZING' and 'installation_id' not in init,
                'empty portable root was not initialized or its internal identity was exposed in status')
        root_identity = directory_identity(root)
        require(root_identity[1] != 0, 'cannot establish qualification installation directory identity')
        trial.check_slot(root_identity)
        manifest_path = root / 'installation.json'
        manifest = json.loads(manifest_path.read_bytes())
        installation_id = manifest['installation_id']
        require(re.fullmatch(r'[0-9a-f]{32}', installation_id) and manifest['plan_digest'] == init['plan_digest'] and
                manifest['config']['host']['runtime_installation_id'] == installation_id,
                'initialized manifest and host config did not share the new installation identity')

        doc = await trial.call('doctor')
        require(doc['installed_manifest_state'] == 'INITIALIZING' and doc['installed_bundle_digest'] == bundle['digest'] and
                doc['installed_bundle_verification'] == 'VERIFIED', 'doctor did not verify the clean initializing installation')
        code = root / json.loads((root / 'installation.json').read_bytes())['code_directory']
        require(code.parent == root and code.is_dir() and code.resolve(strict=True) == code,
                'code generation is outside the fixture installation')
        extra = code / 'native-acceptance-extra'
        extra.touch(exist_ok=False)
        try:
            diagnostic = f'Error: installed bundle verification failed: unlisted or unsafe portable file: {extra.name}'.encode()
            doc = await trial.call('doctor', expected_error=diagnostic)
            require(doc['installed_bundle_verification'] == 'FAILED' and extra.is_file(),
                    'doctor did not report failed verification or did not leave the extra file in place')
        finally:
            extra.unlink(missing_ok=True)

        prepared = await trial.call('prepare-image', '--source-kind', 'oci-archive', '--source', image, '--digest', source,
            approvals=(lambda plan: own(plan) and plan.get('archive_path') == str(image) and
                plan.get('bundle_digest') == bundle['digest'] and
                plan['image_plan']['architecture'] == bundle['target']['arch'] and
                plan['image_plan']['source'] == {'kind': 'oci-archive', 'digest': source},))
        require(prepared['state'] == 'PREPARED' and prepared['source_digest'] == source, 'exact offline OCI image was not prepared')
        instance = None
        for public in (False, True):
            module_cfg = {'expect_persistent': public, 'private_endpoint': f'{address}:{port}'}
            config = document(trial.base / 'module.json', module_cfg)
            proposed_grant = resource_grant(public)
            grant = document(trial.base / 'grants.json', proposed_grant)
            profile = {'mode': 'PUBLIC_INTERNET', 'address_family': 'ipv4', 'dns_servers': ['1.1.1.1'],
                       'net_tx_bps': 1_000_000, 'net_rx_bps': 2_000_000,
                       'allow_unlimited_tx': False, 'allow_unlimited_rx': False}
            network = document(trial.base / 'network.json', profile) if public else None
            proposal = await trial.call('generate-config', '--image', prepared['id'], '--module-id', MODULE,
                '--module-config', config, '--approval', grant, *(['--network-profile', network] if network else []))
            candidate_file = document(trial.base / 'candidate.json', proposal)
            state = await trial.call('configure', '--config', candidate_file, approvals=(
                lambda p: p['plan']['Installation'] == str(root) and p['plan']['BundleDigest'] == bundle['digest'],
                lambda p: p['module_id'] == MODULE and p['source_digest'] == source and
                    p['review']['installation_id'] == installation_id and
                    p['review']['module_config'] == module_cfg and p['review']['grant'] == proposed_grant and
                    p['review']['engine_digest'] == bundle['engine']['executable_digest'] and
                    (all(p['review']['network'][k] == v for k, v in profile.items()) if public
                     else p['review']['network']['mode'] == 'NONE')))
            require(state['state'] == 'READY' and 'installation_id' not in state and state['modules'] == 1,
                    'reviewed native module configuration was not activated or its internal identity was exposed in status')
            live = await trial.run(root_identity)
            require(live and live != instance, 'first and second native launches did not have distinct instance identities')
            instance = live

        def approve_purge(plan):
            trial.check_slot(root_identity)
            ledger_identity = plan['ledger']['installation_identity']
            return (own(plan) and plan.get('shared_parent_retained') == str(root.parent) and
                    plan.get('temporary_parent_receipt') == trial.terminal.name and
                    plan.get('installation_manifest_digest') == manifest_digest and
                    ledger_identity['ID'] == installation_id and ledger_identity['BundleDigest'] == bundle['digest'])

        volumes = list((root / 'volumes').glob('*.ext4'))
        require(len(volumes) == 1 and volumes[0].stat().st_size == VOLUME, 'persistent volume did not retain the approved bounded image')
        trial.check_slot(root_identity)
        code = root / json.loads((root / 'installation.json').read_bytes())['code_directory']
        require(code.parent == root and code.is_dir(), 'code generation is outside the fixture installation')
        state = await trial.call('uninstall')
        require('installation_id' not in state, 'uninstall status exposed the internal installation identity')
        require(state['state'] == 'UNINSTALLED' and not code.exists() and volumes[0].is_file(), 'uninstall did not preserve the data-only state')
        doc = await trial.call('doctor')
        require(doc['installed_manifest_state'] == 'UNINSTALLED' and doc['installed_bundle_verification'] == 'NOT_APPLICABLE',
                'doctor did not skip verification for the uninstalled installation')

        trial.check_slot(root_identity)
        manifest_digest = file_hash(manifest_path)
        state = await trial.call('purge', approvals=(approve_purge,))
        trial.check_slot()
        require(state['state'] == 'PURGED' and root.parent.is_dir(), 'purge did not delete only the owned installation')
    require(expected_receipt(candidate, target) == receipt, 'release candidate changed during native qualification')
    receipt['tested_oci_sha256'] = source
    document(result_path, receipt)
    print(f'Native qualification passed for {target}: {receipt["launcher_sha256"]}')


def verify(candidate, target, gh):
    expected = expected_receipt(candidate, target)
    launcher, manifest, sbom, report, signed = files(candidate, target)
    receipt = json.loads(report.read_bytes())
    image = receipt.pop('tested_oci_sha256', '')
    require(bool(re.fullmatch(r'sha256:[0-9a-f]{64}', image)) and receipt == expected,
            'native acceptance is not bound to these exact candidate files and workflow run')
    repo = os.environ['GITHUB_REPOSITORY']
    workflow = repo + '/.github/workflows/release.yml'
    ref = os.environ['GITHUB_REF']
    verification = json.loads(subprocess.check_output([gh, 'attestation', 'verify', report, '--bundle', signed,
        '--repo', repo, '--signer-workflow', workflow, '--source-ref', ref, '--source-digest', os.environ['GITHUB_SHA'],
        '--deny-self-hosted-runners', '--format', 'json']))
    run_uri = f'https://github.com/{repo}/actions/runs/{os.environ["GITHUB_RUN_ID"]}/attempts/{os.environ["GITHUB_RUN_ATTEMPT"]}'
    subjects = sorted((p.name, file_hash(p)[7:]) for p in (launcher, manifest, sbom, report))
    for entry in verification:
        result = entry['verificationResult']
        cert = result['signature']['certificate']
        statement = result['statement']
        bound = sorted((s['name'], s['digest'].get('sha256')) for s in statement['subject'])
        if (cert['runInvocationURI'] == run_uri and cert['sourceRepositoryIdentifier'] == os.environ['GITHUB_REPOSITORY_ID'] and
                cert['sourceRepositoryOwnerIdentifier'] == os.environ['GITHUB_REPOSITORY_OWNER_ID'] and
                cert['runnerEnvironment'] == 'github-hosted' and cert['buildTrigger'] == 'push' and
                statement['predicateType'] == 'https://slsa.dev/provenance/v1' and bound == subjects):
            print(f'Exact native acceptance attestation verified for {target}')
            return
    raise RuntimeError('no hosted acceptance attestation covers this exact run, launcher, manifest, SBOM and receipt')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    packing = commands.add_parser('pack')
    packing.add_argument('arch', choices=['amd64', 'arm64'])
    packing.add_argument('probe', type=Path)
    packing.add_argument('output', type=Path)
    native = commands.add_parser('qualify')
    native.add_argument('target')
    native.add_argument('candidate', type=Path)
    native.add_argument('image', type=Path)
    verification = commands.add_parser('verify')
    verification.add_argument('target')
    verification.add_argument('candidate', type=Path)
    verification.add_argument('gh')
    args = parser.parse_args()
    if args.command == 'pack':
        pack(args.arch, args.probe, HERE / 'fixture/manifest.json', args.output,
             executable='probe', include_manifest=False)
    elif args.command == 'qualify':
        asyncio.run(qualify(args.candidate.resolve(strict=True), args.target, args.image.resolve(strict=True)))
    else:
        verify(args.candidate, args.target, args.gh)


if __name__ == '__main__':
    main()
