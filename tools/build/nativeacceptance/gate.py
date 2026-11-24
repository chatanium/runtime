#!/usr/bin/env python3
"""Create the test OCI archive, qualify an exact native candidate, or verify its receipt."""
import argparse
import asyncio
import ctypes
import gzip
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import socket
import subprocess
import tarfile
import tempfile
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
LOCK = ROOT / 'internal/bundle/portable-release-lock.json'
PROMPT = re.compile(rb'Type (sha256:[0-9a-f]{64}) to approve: ')
PUBLIC = ('1.1.1.1', 443)
VOLUME = 16 << 20
BUDGET = 12 << 30
MODULE = 'release-probe'
CHECKS = [
    'read-only doctor and bounded installation plan',
    'same-ISA offline OCI preparation and approved configuration',
    'native nonroot init, start and observed clean stop in NONE and PUBLIC_INTERNET',
    'TCP closed before approval, public TCP open after approval, private listener blocked',
    'requested NAT policy and nonzero send/receive ceilings verified by native adapter',
    'persistent seed survived, scratch and tmp were fresh, shared and separate volume ceilings enforced',
    'uninstall removed code and retained data; approved purge retained shared parent and launcher',
]


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def checksum(data):
    return 'sha256:' + hashlib.sha256(data).hexdigest()


def file_hash(path):
    with path.open('rb') as file:
        return 'sha256:' + hashlib.file_digest(file, 'sha256').hexdigest()


def document(path, value):
    path.write_bytes(canonical(value) + b'\n')
    return path


def pack(arch, program, path):
    contents = {}
    oci = 'application/vnd.oci.image.'

    def blob(media, data):
        digest = checksum(data)
        contents['blobs/sha256/' + digest[7:]] = data
        return {'mediaType': oci + media, 'digest': digest, 'size': len(data)}

    def entry(archive, name, data, mode):
        info = tarfile.TarInfo(name)
        info.mode = mode
        if data is None:
            info.type = tarfile.DIRTYPE
            archive.addfile(info)
        else:
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))

    layer = io.BytesIO()
    with tarfile.open(fileobj=layer, mode='w', format=tarfile.USTAR_FORMAT) as tar:
        for name in ('bin', 'dev', 'etc', 'proc', 'sys', 'tmp', 'var', 'var/lib', 'var/lib/flexmodule',
                     'var/lib/flexmodule/data', 'var/lib/flexmodule/scratch', 'work'):
            entry(tar, name, None, 0o1777 if name == 'tmp' else 0o755)
        entry(tar, 'bin/probe', program.read_bytes(), 0o555)
    raw = layer.getvalue()
    layers = [blob('layer.v1.tar+gzip', gzip.compress(raw, mtime=0))]
    config = blob('config.v1+json', canonical({'architecture': arch, 'os': 'linux',
        'rootfs': {'type': 'layers', 'diff_ids': [checksum(raw)]}, 'config': {
            'User': '1000:1000', 'WorkingDir': '/work', 'Entrypoint': ['/bin/probe'],
            'Labels': {'org.chatanium.flexmodule.manifest.v2': (HERE / 'fixture/manifest.json').read_text(),
                       'org.chatanium.flexmodule.resources.v2': 'portable-v2'},
        }}))
    manifest = blob('manifest.v1+json', canonical({'schemaVersion': 2, 'mediaType': oci + 'manifest.v1+json',
                                                   'config': config, 'layers': layers}))
    manifest['platform'] = {'architecture': arch, 'os': 'linux'}
    contents['oci-layout'] = canonical({'imageLayoutVersion': '1.0.0'})
    contents['index.json'] = canonical({'schemaVersion': 2, 'mediaType': oci + 'index.v1+json', 'manifests': [manifest]})
    with tarfile.open(path, 'x', format=tarfile.USTAR_FORMAT) as tar:
        for name, data in sorted(contents.items()):
            entry(tar, name, data, 0o444)


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


class Trial:
    def __init__(self, launcher, base, target):
        self.launcher = launcher
        self.base = base
        self.id = 'rg-' + uuid.uuid4().hex[:12]
        self.env = {key: value for key, value in os.environ.items() if key.upper() in {
            'PATH', 'SYSTEMROOT', 'WINDIR', 'LANG', 'TMP', 'TEMP', 'TMPDIR', 'USERPROFILE', 'LOCALAPPDATA'}}
        self.env.update(HOME=str(base), XDG_DATA_HOME=str(base / 'data'))
        if target.startswith('linux/'):
            self.root = base / 'data/chatanium/portable-v2' / self.id
        elif target.startswith('darwin/'):
            self.root = base / 'Library/Application Support/chatanium/portable-v2' / self.id
        else:
            self.root = Path(os.environ['LOCALAPPDATA']).resolve(strict=True) / 'chatanium/portable-v2' / self.id

    async def spawn(self, command, *args):
        return await asyncio.create_subprocess_exec(str(self.launcher), command, '--installation-id', self.id, *map(str, args),
            env=self.env, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)

    async def call(self, command, *args, approvals=()):
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
                require(result == 0, f'{command} failed ({result}): {stderr[-3000:].decode(errors="replace")}')
                require(seen == len(approvals), command + ': missing explicit approval')
                return json.loads(await stdout)
        finally:
            await terminate(proc)
            if not stdout.done():
                stdout.cancel()

    async def run(self):
        proc = await self.spawn('start', '--foreground')
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
            stopped = await self.call('stop')
            require(stopped['state'] == 'STOPPED', 'supervisor did not observe STOPPED')
            async with asyncio.timeout(75):
                remaining, diagnostics = await asyncio.gather(proc.stdout.read(), stderr)
                status = await proc.wait()
            require(status == 0, 'start exited unsuccessfully: ' + diagnostics[-3000:].decode(errors='replace'))
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
        require(not root.exists(), 'release fixture installation ID unexpectedly exists')
        doc = await trial.call('doctor')
        require(doc['format'] == 'portable-v2' and Path(doc['installation_directory']) == root and not root.exists() and
                doc['bundle_target'] == bundle['target'] and doc['pinned_engine'] == bundle['engine'] and
                doc['verified_embedded_manifest'] == bundle['digest'], 'doctor crossed a user path or disagreed with the exact release manifest')
        own = lambda plan: plan.get('format') == 'portable-v2' and Path(plan.get('installation_directory', '.')) == root
        init = await trial.call('init', '--budget-bytes', BUDGET, approvals=(lambda plan:
            own(plan) and plan.get('bundle') == bundle and plan.get('maximum_installation_bytes') == BUDGET,))
        require(init['state'] == 'INITIALIZING', 'empty portable root was not initialized')
        prepared = await trial.call('prepare-image', '--source-kind', 'oci-archive', '--source', image, '--digest', source,
            approvals=(lambda plan: own(plan) and Path(plan.get('archive_path', '.')) == image and
                plan.get('bundle_digest') == bundle['digest'],))
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
                lambda p: Path(p['plan']['Installation']) == root and p['plan']['BundleDigest'] == bundle['digest'],
                lambda p: p['module_id'] == MODULE and p['source_digest'] == source and
                    p['review']['module_config'] == module_cfg and p['review']['grant'] == proposed_grant and
                    p['review']['engine_digest'] == bundle['engine']['executable_digest'] and
                    (all(p['review']['network'][k] == v for k, v in profile.items()) if public
                     else p['review']['network']['mode'] == 'NONE')))
            require(state['state'] == 'READY' and state['modules'] == 1, 'reviewed native module configuration was not activated')
            live = await trial.run()
            require(live and live != instance, 'first and second native launches did not have distinct instance identities')
            instance = live
        volumes = list((root / 'volumes').glob('*.ext4'))
        require(len(volumes) == 1 and volumes[0].stat().st_size == VOLUME, 'persistent volume did not retain the approved bounded image')
        code = root / json.loads((root / 'installation.json').read_bytes())['code_directory']
        require(code.parent == root and code.is_dir(), 'code generation is outside the fixture installation')
        state = await trial.call('uninstall')
        require(state['state'] == 'UNINSTALLED' and not code.exists() and volumes[0].is_file(), 'uninstall did not preserve the data-only state')
        state = await trial.call('purge', approvals=(own,))
        require(state['state'] == 'PURGED' and not root.exists() and root.parent.exists(), 'purge did not delete only the owned installation')
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
        pack(args.arch, args.probe, args.output)
    elif args.command == 'qualify':
        asyncio.run(qualify(args.candidate.resolve(strict=True), args.target, args.image.resolve(strict=True)))
    else:
        verify(args.candidate, args.target, args.gh)


if __name__ == '__main__':
    main()
