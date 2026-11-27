#!/usr/bin/env python3
"""Legacy v1 build/publish/reload coordinator for an explicitly selected launcher."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import select
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass

from control import ControlError, MAX_LOCK_JSON, coordination_metadata, request as control_request
from execution import ExecutionError, Identity, trusted
from observations import ObservationError, RuntimeObservations
from processes import BuildCleanupError, capture_tree, spawn_owned, terminate_tree

LABEL = 'org.chatanium.flexmodule.manifest.v2'
IMAGE = re.compile(r'^([a-z0-9][a-z0-9._:/-]*)@sha256:[0-9a-f]{64}$')
MAX_JSON = 16 << 20
IGNORED = {'.git', '.tools', 'bin', 'logs', '__pycache__', 'node_modules',
           'vendor', 'storage', 'runtime-storage', '.musicbot'}
# Compiler/build tools receive no application tokens or arbitrary inherited env.
BUILD_ENV = {'PATH', 'HOME', 'USER', 'LOGNAME', 'TMPDIR', 'LANG', 'LC_ALL',
             'DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_CONFIG', 'DOCKER_CERT_PATH',
             'DOCKER_TLS_VERIFY', 'XDG_RUNTIME_DIR',
             'GOOS', 'GOARCH', 'GO_TOOLCHAIN', 'BUF_VERSION',
             'PROTOC_GEN_GO_VERSION', 'PROTOC_GEN_GO_GRPC_VERSION', 'BUILD_JOBS',
             'BUILD_OUTPUTS', 'MODULE', 'DISABLE_VOICE', 'LEGACY_RUNTIME', 'BOOTSTRAP_GO'}


class DevelopmentError(Exception):
    """Only finite, non-sensitive diagnostics cross the CLI boundary."""


class Cancelled(Exception):
    pass


class Stale(Exception):
    pass


def note(message):
    print('dev: ' + message, file=sys.stderr, flush=True)


def strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DevelopmentError('duplicate JSON field')
        result[key] = value
    return result


def decode(raw):
    try:
        return json.loads(raw, object_pairs_hook=strict_object,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, TypeError):
        raise DevelopmentError('invalid JSON document') from None


def repository(image):
    match = IMAGE.fullmatch(image) if isinstance(image, str) else None
    if not match or ':' in match[1].rsplit('/', 1)[-1]:
        raise DevelopmentError('immutable repository digest required')
    return match[1]


def no_symlinks(path):
    if not path.is_absolute() or '..' in path.parts:
        raise DevelopmentError('canonical absolute path required')
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        if current.is_symlink():
            raise DevelopmentError('symlink traversal refused')


def private_directory(path):
    no_symlinks(path)
    if not path.exists():
        # Only the final private directory is created; no host provisioning.
        path.mkdir(mode=0o700)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise DevelopmentError('control directory must be owned by this user with mode 0700')


class SessionLock:
    def __init__(self, metadata, identity):
        self.identity = identity
        payload = json.dumps(metadata, separators=(',', ':')).encode() + b'\n'
        if len(payload) > MAX_LOCK_JSON:
            raise DevelopmentError('installed coordination metadata exceeds helper bound')
        command = [identity.python, '-I', str(identity.directory / 'control.py'), 'lock']
        self.process = subprocess.Popen(identity.argv(command), env=identity.safe_env,
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, cwd='/', start_new_session=True)
        try:
            deadline = time.monotonic() + 15
            fd, offset = self.process.stdin.fileno(), 0
            os.set_blocking(fd, False)
            while offset < len(payload):
                _, writable, _ = select.select([], [fd], [], max(0, deadline - time.monotonic()))
                if not writable:
                    raise DevelopmentError('runtime session lock input deadline exceeded')
                try:
                    written = os.write(fd, memoryview(payload)[offset:])
                except BlockingIOError:
                    continue
                if written <= 0:
                    raise DevelopmentError('runtime session lock input closed')
                offset += written
            os.set_blocking(fd, True)
            readable, _, _ = select.select([self.process.stdout], [], [], max(0, deadline - time.monotonic()))
            if not readable or self.process.stdout.readline(16) != b'READY\n':
                raise DevelopmentError('runtime session lock unavailable or already held')
        except BaseException:
            self.close()
            raise

    def close(self):
        self.process.stdin.close()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.identity.abort(self.process)
        finally:
            self.process.stdout.close()


def duration(value):
    # Go duration strings, including composite and fractional units.
    if not isinstance(value, str):
        raise DevelopmentError('shutdown deadlines must be Go duration strings')
    units = {'h': 3600, 'm': 60, 's': 1, 'ms': .001, 'us': .000001, 'µs': .000001, 'μs': .000001, 'ns': .000000001}
    parts = list(re.finditer(r'(\d+(?:\.\d*)?|\.\d+)(ns|us|µs|μs|ms|s|m|h)', value))
    if not parts or ''.join(p[0] for p in parts) != value:
        raise DevelopmentError('invalid shutdown deadline')
    result = sum(float(p[1]) * units[p[2]] for p in parts)
    if not 0 < result <= 9223372036:
        raise DevelopmentError('shutdown deadline outside Go duration bounds')
    return result


@dataclass(frozen=True)
class Installed:
    module_id: str
    image: str
    entrypoint: str


@dataclass(frozen=True)
class Source:
    directory: str
    go_directory: str
    binary: str
    name: str


@dataclass(frozen=True)
class Binding:
    installed: Installed
    source: Source


def inspect_config(identity, args):
    raw = identity.manage(['inspect-config', *args], max_output_bytes=MAX_JSON)
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_JSON:
        raise DevelopmentError('invalid or oversized installed configuration response')
    return raw


def inspect_dev_lock(identity, args):
    try:
        return coordination_metadata(identity.manage(
            ['inspect-dev-lock', *args], max_output_bytes=MAX_LOCK_JSON))
    except ControlError:
        raise DevelopmentError('invalid installed development coordination metadata') from None


def management_directory(raw):
    doc = decode(raw)
    host = doc.get('host') if isinstance(doc, dict) else None
    if not isinstance(host, dict):
        raise DevelopmentError('installed app storage is missing')
    storage, management = host.get('storage_root'), host.get('management_directory')
    if (not isinstance(storage, str) or not isinstance(management, str) or
            not storage.startswith('/') or str(PurePosixPath(storage)) != storage or
            '..' in PurePosixPath(storage).parts or
            management != str(PurePosixPath(storage) / 'app') or
            any(ord(char) < 32 for char in storage)):
        raise DevelopmentError('installed management directory must be canonical StorageRoot/app')
    return Path(management)


def load_config(raw, excluded_paths=None):
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_JSON:
        raise DevelopmentError('invalid or oversized installed configuration')
    doc = decode(raw)
    if not isinstance(doc, dict):
        raise DevelopmentError('operator configuration must be an object')
    try:
        installed = {}
        for item in doc['modules']:
            module_id = item['module_id']
            image = item['image']
            entrypoint = item['entrypoint'][0]
            repository(image)
            if not isinstance(module_id, str) or not module_id or module_id in installed:
                raise DevelopmentError('invalid or duplicate installed module ID')
            if not isinstance(entrypoint, str) or entrypoint == '/' or not entrypoint.startswith('/') or str(PurePosixPath(entrypoint)) != entrypoint or '..' in PurePosixPath(entrypoint).parts or any(ord(c) < 32 for c in entrypoint):
                raise DevelopmentError('invalid installed executable path')
            installed[module_id] = Installed(module_id, image, entrypoint)
        grace = duration(doc.get('defaults', {}).get('drain_deadline', '10s')) + duration(doc['limits']['termination_deadline']) + 5
        startup = duration(doc.get('defaults', {}).get('startup_deadline', '30s'))
    except (KeyError, IndexError, TypeError, AttributeError):
        raise DevelopmentError('invalid operator development inputs') from None
    secret_environment = {}
    backends = doc.get('backends', {})
    if not isinstance(backends, dict):
        raise DevelopmentError('invalid backend source bindings')
    for backend in backends.values():
        if not isinstance(backend, dict) or not isinstance(backend.get('secret_sources', {}), dict):
            raise DevelopmentError('invalid backend source bindings')
        for source in backend.get('secret_sources', {}).values():
            if not isinstance(source, str) or not re.fullmatch(r'env:[A-Za-z_][A-Za-z0-9_]*', source):
                raise DevelopmentError('runtime secrets require explicit env:NAME sources')
            name = source[4:]
            if name in BUILD_ENV or name.startswith(('DOCKER_', 'LD_', 'DYLD_', 'PYTHON', 'SUDO_')) or name in {'ENV', 'BASH_ENV', 'SHELLOPTS', 'CDPATH', 'IFS'}:
                raise DevelopmentError('secret source name conflicts with runtime execution controls')
            value = os.environ.get(name)
            if not value or any(char in value for char in '\r\n\0'):
                raise DevelopmentError('export each configured runtime secret source before watching')
            secret_environment[name] = value
    if excluded_paths is not None:
        host = doc.get('host', {})
        if not isinstance(host, dict):
            raise DevelopmentError('invalid runtime storage paths')
        excluded_paths.clear()
        for field in ('storage_root', 'ipc_root', 'management_directory'):
            path_value = host.get(field)
            if isinstance(path_value, str) and Path(path_value).is_absolute():
                excluded_paths.add(Path(path_value))
    return installed, grace, startup, secret_environment


def file_stamp(path):
    try:
        info = path.lstat()
        return (info.st_mtime_ns, info.st_ctime_ns, info.st_size, info.st_ino, info.st_mode)
    except FileNotFoundError:
        return None


def snapshot(root, config_digest, excluded_paths=()):
    result = {'@config': config_digest}
    for parent, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [name for name in dirs if name not in IGNORED and not name.startswith('.') and not (Path(parent) / name).is_symlink() and Path(parent) / name not in excluded_paths]
        for name in files:
            if name.startswith('.') and name != '.go-version':
                continue
            if name.endswith(('.pyc', '.swp', '.swo', '~', '.tmp')):
                continue
            path = Path(parent) / name
            if not path.is_symlink():
                result[path.relative_to(root).as_posix()] = file_stamp(path)
    return result


class Changes:
    def __init__(self, read_snapshot, debounce=.35, clock=time.monotonic):
        self.read_snapshot = read_snapshot
        self.previous = read_snapshot()
        self.pending = {'@initial'}
        self.generation = 0
        self.clock = clock
        self.changed_at = clock() - debounce
        self.debounce = debounce

    def poll(self):
        current = self.read_snapshot()
        changed = {p for p in current.keys() | self.previous.keys() if current.get(p) != self.previous.get(p)}
        self.previous = current
        if changed:
            self.pending.update(changed)
            self.generation += 1
            self.changed_at = self.clock()

    def take(self):
        if self.pending and self.clock() - self.changed_at >= self.debounce:
            pending, self.pending = self.pending, set()
            return pending
        return set()


def classify(paths, sources):
    runtime = '@initial' in paths or '@config' in paths
    affected = set()
    for path in paths:
        if path.startswith('@'):
            continue
        owners = [source for source in sources if path == source.directory or path.startswith(source.directory + '/')]
        if owners:
            affected.update(source.directory for source in owners)
            continue
        # An uninstalled module tree is not a runtime dependency or an approval.
        if path.startswith(('modules/', 'examples/')):
            continue
        runtime = True
        # Shared inputs and Go dependency/build changes can affect every module.
        if path.startswith(('shared/', 'proto/', 'third_party/', 'tools/', 'database/')) or path in {'go.mod', 'go.sum', 'go.work', 'go.work.sum', '.go-version', 'Makefile'}:
            affected.update(source.directory for source in sources)
        for source in sources:
            if source.go_directory != '.' and path.startswith(source.go_directory + '/'):
                affected.add(source.directory)
    if '@initial' in paths or '@config' in paths:
        affected.update(source.directory for source in sources)
    return runtime, affected




class Runner:
    def __init__(self, root, tick, cancelled):
        self.root, self.tick, self.cancelled = root, tick, cancelled
        self.env = {key: value for key, value in os.environ.items() if key in BUILD_ENV}
        self.env.update(CGO_ENABLED='0', PYTHONDONTWRITEBYTECODE='1')
        self.process = None

    def run(self, args, capture=False, timeout=3600):
        if self.cancelled():
            raise Cancelled()
        # Capture without sending untrusted metadata/config to terminal logs.
        with tempfile.TemporaryFile() as output:
            self.process = spawn_owned([str(a) for a in args], cwd=self.root, env=self.env,
                                            stdout=output, stderr=subprocess.DEVNULL,
                                            stdin=subprocess.DEVNULL, start_new_session=True)
            process = self.process
            deadline = time.monotonic() + timeout
            completed = False
            try:
                while True:
                    # Retain observed child identities before a root exit can
                    # reparent them, including nested compiler sessions.
                    if self.cancelled():
                        raise Cancelled()
                    if time.monotonic() > deadline:
                        raise DevelopmentError('development command timed out')
                    capture_tree(process, allow_completed=True)
                    if process.poll() is not None:
                        completed = process.returncode == 0
                        break
                    self.tick()
                    time.sleep(.1)
                if process.returncode:
                    stage = 'image publication' if args[:2] == ['docker', 'push'] else 'image build or lookup' if str(args[0]) == 'docker' else 'source build or discovery'
                    raise DevelopmentError(stage + ' failed; verify existing toolchain and registry authorization')
                if capture:
                    output.seek(0)
                    raw = output.read(MAX_JSON + 1)
                    if len(raw) > MAX_JSON:
                        raise DevelopmentError('oversized development command result')
                    return raw
                return b''
            finally:
                allow_completed = completed and not self.cancelled()
                try:
                    capture_tree(process, allow_completed=allow_completed)
                finally:
                    terminate_tree(process, allow_completed=allow_completed)
                self.process = None




class Client:
    def __init__(self, path, timeout, identity=None):
        self.path, self.timeout, self.identity = path, timeout, identity

    def request(self, method, path, payload=None):
        try:
            if self.identity is None:
                return control_request(self.path, self.timeout, method, path, payload)
            operation = 'modules' if method == 'GET' else 'reload'
            raw = json.dumps(payload).encode() if payload is not None else None
            return decode(self.identity.control(self.path, operation, self.timeout, raw))
        except (ControlError, ExecutionError):
            raise DevelopmentError('development control request failed') from None

    def modules(self):
        doc = self.request('GET', '/v1/modules')
        try:
            records = {record['module_id']: record for record in doc['modules']}
            if len(records) != len(doc['modules']):
                raise DevelopmentError('duplicate runtime module record')
            for record in records.values():
                repository(record['image'])
                committed = record['committed_image']
                if not isinstance(committed, str):
                    raise DevelopmentError('invalid committed runtime image')
                if committed:
                    repository(committed)
                if not isinstance(record['instance_id'], str) or not record['instance_id']:
                    raise DevelopmentError('runtime module has no instance identity')
            return records
        except (KeyError, TypeError):
            raise DevelopmentError('invalid runtime module response') from None

    def reload(self, module_id, expected, image):
        result = self.request('POST', '/v1/modules/reload',
                              {'module_id': module_id, 'expected_instance_id': expected, 'image': image})
        if not isinstance(result, dict) or result.get('module_id') != module_id or result.get('image') != image or result.get('committed_image') != image or not result.get('instance_id') or result['instance_id'] == expected:
            raise DevelopmentError('runtime replacement acknowledgement differs')
        return result


class Publisher:
    def __init__(self, root, work, runner):
        self.root, self.work, self.runner = root, work, runner
        # Only verified publications from this process can authorize rebasing.
        # Scope ancestry to the exact executable replaced by the overlay.
        self._origins = {}

    def inspect(self, image):
        repository(image)
        try:
            raw = self.runner.run(['docker', 'image', 'inspect', image], capture=True, timeout=60)
        except DevelopmentError:
            self.runner.run(['docker', 'pull', image], timeout=300)
            raw = self.runner.run(['docker', 'image', 'inspect', image], capture=True, timeout=60)
        result = decode(raw)
        if not isinstance(result, list) or len(result) != 1:
            raise DevelopmentError('invalid image inspection response')
        metadata = result[0]
        if not isinstance(metadata, dict) or image not in metadata.get('RepoDigests', []):
            raise DevelopmentError('installed image has no matching real RepoDigest')
        return metadata

    def manifest_name(self, image):
        metadata = self.inspect(image)
        try:
            manifest = decode(metadata['Config']['Labels'][LABEL])
            name = manifest['name']
            if not isinstance(name, str) or not name:
                raise DevelopmentError('image manifest name missing')
            return name
        except (KeyError, TypeError):
            raise DevelopmentError('installed image canonical manifest label missing') from None

    def publish(self, binding, current_image):
        repo = repository(current_image)
        self.inspect(current_image)
        source = binding.source
        self.runner.run(['make', '--no-print-directory', 'build-module', source.directory])
        manifest = self.root / source.directory / 'manifest.json'
        self.runner.run(['bash', 'tools/dev/discover.sh', 'validate', manifest])
        declaration = manifest.read_bytes()
        if len(declaration) > MAX_JSON or decode(declaration).get('name') != source.name:
            raise DevelopmentError('source canonical manifest identity changed')
        tag = repo + ':dev-' + uuid.uuid4().hex
        with tempfile.TemporaryDirectory(prefix='image-', dir=self.work) as directory:
            context = Path(directory)
            shutil.copy2(self.root / source.binary, context / 'module')
            (context / 'manifest.json').write_bytes(declaration)
            executable = binding.installed.entrypoint
            origin = self._origins.get((current_image, executable))
            base_image = origin if origin is not None else current_image
            # JSON COPY destinations prevent Dockerfile instruction injection.
            dockerfile = ('FROM ' + base_image + '\n' +
                          'COPY --chmod=0555 ' + json.dumps(['module', executable]) + '\n' +
                          'COPY --chmod=0444 ["manifest.json", "/opt/flexmodule/manifest.json"]\n')
            (context / 'Dockerfile').write_text(dockerfile)
            self.runner.run(['docker', 'build', '--platform', 'linux/amd64', '--network=none',
                             '--label', LABEL + '=' + declaration.decode(),
                             '--label', 'org.chatanium.flexmodule.manifest.sha256=' + hashlib.sha256(declaration).hexdigest(),
                             '--tag', tag, context])
            self.runner.run(['docker', 'push', tag], timeout=600)
            metadata = decode(self.runner.run(['docker', 'image', 'inspect', tag], capture=True, timeout=60))[0]
            if metadata.get('Config', {}).get('Labels', {}).get(LABEL) != declaration.decode():
                raise DevelopmentError('published image manifest bytes differ')
            digests = [image for image in metadata.get('RepoDigests', []) if IMAGE.fullmatch(image) and repository(image) == repo]
            if len(set(digests)) != 1:
                raise DevelopmentError('publication did not produce one real repository digest')
            image = digests[0]
            verified = self.inspect(image)
            if verified.get('Id') != metadata.get('Id'):
                raise DevelopmentError('published repository digest resolves to another image')
            # Preserve effects inherited by the first successful overlay (such
            # as ONBUILD), then avoid adding two layers on every later reload.
            self._origins[(image, executable)] = origin if origin is not None else image
            return image


def discover(root, runner):
    raw = runner.run(['bash', 'tools/dev/discover.sh', 'sources'], capture=True)
    sources = []
    try:
        for line in raw.decode().splitlines():
            directory, go_directory, binary = line.split('\t')
            declaration = decode((root / directory / 'manifest.json').read_bytes())
            name = declaration['name']
            if not isinstance(name, str) or not name:
                raise DevelopmentError('source manifest name missing')
            sources.append(Source(directory, go_directory, binary, name))
    except (ValueError, KeyError, UnicodeError, TypeError):
        raise DevelopmentError('invalid canonical module discovery result') from None
    return sources


def bind(installed, sources, publisher, overrides):
    names = {}
    for source in sources:
        names.setdefault(source.name, []).append(source)
    result = {}
    for module_id, module in installed.items():
        name = publisher.manifest_name(overrides.get(module_id, module.image))
        matches = names.get(name, [])
        if len(matches) > 1:
            raise DevelopmentError('installed image matches ambiguous source manifest names')
        if matches:
            result[module_id] = Binding(module, matches[0])
    return result


class RuntimeProcess:
    def __init__(self, root, control, args, cancelled, tick, identity):
        self.root, self.control, self.args = root, control, args
        self.cancelled, self.tick, self.identity = cancelled, tick, identity
        self.environment = dict(identity.safe_env)
        self.process = None
        self.artifact = None
        self.observations = None
        self.expected_repositories = {}
        self.candidates = {}

    def start(self, artifact, overrides):
        if self.process is not None:
            raise DevelopmentError('runtime overlap refused')
        revision = self.candidates.get(artifact)
        if not revision:
            raise DevelopmentError('worker candidate has not been published by the installed owner')
        command = ['start', '--foreground', '--dev-mode', '--dev-revision', revision,
                   '--dev-socket', str(self.control), *self.args]
        for module_id, image in sorted(overrides.items()):
            command += ['--dev-module-image', module_id + '=' + image]
        secrets = {key: value for key, value in self.environment.items() if key not in self.identity.safe_env}
        self.process = subprocess.Popen(self.identity.management_argv(command, secrets), env=self.environment,
                                        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                        cwd='/', start_new_session=True)
        self.artifact = artifact
        try:
            self.observations = RuntimeObservations(self.process.stdout, self.expected_repositories)
        except (OSError, RuntimeError):
            try:
                self.identity.abort(self.process)
            finally:
                self.process.stdout.close()
            raise DevelopmentError('runtime observation ownership failed') from None

    def alive(self):
        return self.process is not None and self.process.poll() is None

    def stop(self, grace):
        process = self.process
        if process is None:
            return {}
        # A spontaneous exit is not evidence of a requested cleanup barrier.
        if process.poll() is not None:
            self.finish_observations()
            raise DevelopmentError('runtime exited unexpectedly; automatic restart refused')
        process.send_signal(signal.SIGTERM)
        deadline = time.monotonic() + grace
        while process.poll() is None and time.monotonic() < deadline:
            self.tick()
            time.sleep(.1)
        if process.poll() is None:
            try:
                self.identity.abort(process)
            finally:
                self.finish_observations()
            raise DevelopmentError('runtime cleanup timed out; replacement refused')
        receipt = self.finish_observations()
        if receipt is None:
            raise DevelopmentError('runtime cleanup receipt missing or invalid; replacement refused')
        self.confirm_root_cleanup(grace)
        self.process = None
        self.artifact = None
        return receipt

    def confirm_root_cleanup(self, grace):
        report = decode(self.identity.manage(['stop', *self.args], timeout=max(60, grace)))
        installation = self.args[self.args.index('--installation-id') + 1]
        if (not isinstance(report, dict) or report.get('installation_id') != installation or
                report.get('complete') is not True or report.get('desired_run_state') != 'STOPPED' or
                report.get('pending') or report.get('failures')):
            raise DevelopmentError('root owner cleanup remains incomplete; replacement refused')

    def discard_candidate(self, artifact):
        revision = self.candidates.get(artifact)
        if revision is None:
            raise DevelopmentError('unknown prepared worker candidate; cleanup refused')
        report = decode(self.identity.manage(['discard-dev-revision', *self.args, '--revision', revision]))
        installation = self.args[self.args.index('--installation-id') + 1]
        if (not isinstance(report, dict) or report.get('installation_id') != installation or
                report.get('complete') is not True or report.get('pending') or report.get('failures')):
            raise DevelopmentError('worker generation reclamation remains incomplete')
        self.candidates.pop(artifact)
        self.identity.remove_generation(artifact)

    def discard_superseded(self, keep):
        for artifact in tuple(self.candidates):
            if artifact != keep:
                self.discard_candidate(artifact)

    def finish_observations(self):
        if self.observations is None:
            return None
        try:
            return self.observations.finish()
        except ObservationError:
            raise DevelopmentError('runtime observation cleanup failed; replacement refused') from None

    def join_on_exit(self, grace, retain=False):
        if self.alive():
            self.stop(grace)
        elif self.process is not None:
            self.process.wait()
            receipt = self.finish_observations()
            if not retain:
                if receipt is None:
                    raise DevelopmentError('worker exited without a complete cleanup receipt')
                self.confirm_root_cleanup(grace)
                self.process = None
                self.artifact = None
        if not retain:
            self.discard_superseded(None)


class Watcher:
    def __init__(self, root, config, control, args, identity, poll=.2, debounce=.35):
        self.root, self.config, self.control = root, config, control
        self.identity = identity
        self.args = tuple(args)
        self.poll_interval, self.cancelled = poll, False
        self.excluded_paths = set()
        load_config(config, self.excluded_paths)
        self.config_digest = hashlib.sha256(config).digest()
        self.config_poll_at = 0
        self.changes = Changes(lambda: snapshot(root, self.config_digest, self.excluded_paths), debounce)
        self.runner = Runner(root, self.tick, lambda: self.cancelled)
        self.work = Path(tempfile.mkdtemp(prefix='session-', dir=root / '.tools/dev'))
        self.publisher = Publisher(root, self.work, self.runner)
        self.runtime = RuntimeProcess(root, control, args, lambda: self.cancelled, self.tick, identity)
        self.overrides, self.installed_images = {}, {}
        self.grace, self.startup = 30, 30
        self.ready = False
        self.fatal = False
        self.worker_preparation_uncertain = False

    def tick(self, force_config=False):
        now = time.monotonic()
        if force_config or now >= self.config_poll_at:
            config = inspect_config(self.identity, self.args)
            if config != self.config:
                self.config, self.config_digest = config, hashlib.sha256(config).digest()
            self.config_poll_at = now + 1
        self.changes.poll()

    def stable(self, generation):
        self.tick(force_config=True)
        if self.cancelled:
            raise Cancelled()
        if generation != self.changes.generation:
            raise Stale()

    def prepare_runtime(self):
        if self.worker_preparation_uncertain:
            raise DevelopmentError('worker publication outcome is unresolved; automatic resubmission refused')
        # Only the nonroot worker/native closure is a development candidate.
        self.runner.run(['make', '--no-print-directory', 'build-dev-worker'])
        directory = Path(tempfile.mkdtemp(prefix='worker-', dir=self.work))
        try:
            shutil.copy2(self.root / 'bin/chatanium-worker', directory / 'chatanium-worker')
            native = self.root / 'bin/voice-runtime'
            if os.environ.get('DISABLE_VOICE') != '1' and native.exists():
                shutil.copytree(native, directory / 'voice-runtime')
            public = self.identity.stage(directory)
            archive = self.work / ('worker-' + uuid.uuid4().hex + '.tar')
            submitted = False
            try:
                base = decode(self.config)['host']['bundle_digest']
                arguments = ['python3', 'tools/build/development.py', '--source', str(public),
                             '--output', str(archive), '--base-bundle-digest', base]
                if os.environ.get('DISABLE_VOICE') == '1':
                    arguments.append('--disable-voice')
                identity = decode(self.runner.run(arguments, capture=True))
                if (not isinstance(identity, dict) or set(identity) != {'archive_digest', 'archive_bytes', 'manifest_digest'} or
                        not re.fullmatch(r'sha256:[0-9a-f]{64}', str(identity['archive_digest'])) or
                        not re.fullmatch(r'sha256:[0-9a-f]{64}', str(identity['manifest_digest'])) or
                        type(identity['archive_bytes']) is not int or
                        not 0 < identity['archive_bytes'] <= 4 << 30 or identity['archive_bytes'] % 4096):
                    raise DevelopmentError('invalid worker artifact receipt')
                with archive.open('rb') as data:
                    submitted = True
                    record = decode(self.identity.manage(['prepare-dev-worker', *self.args,
                        '--input', '-', '--sha256', identity['archive_digest'],
                        '--size', str(identity['archive_bytes'])], input_file=data, max_output_bytes=64 << 20))
                if not isinstance(record, dict):
                    raise DevelopmentError('installed owner returned a non-record worker result')
                revision = record.get('id')
                binding = record.get('development_worker')
                if (not isinstance(revision, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', revision) or
                        record.get('bundle_digest') != base or not isinstance(binding, dict) or
                        binding.get('artifact_digest') != identity['manifest_digest']):
                    raise DevelopmentError('installed owner returned an invalid worker revision binding')
                self.runtime.candidates[public] = revision
                return public
            except BaseException:
                if submitted:
                    self.worker_preparation_uncertain = True
                self.identity.remove_generation(public)
                raise
            finally:
                archive.unlink(missing_ok=True)
        finally:
            shutil.rmtree(directory)

    def await_ready(self):
        deadline = time.monotonic() + self.startup * max(1, len(self.installed_images)) + 10
        client = Client(self.control, self.grace + self.startup + 5, self.identity)
        while time.monotonic() < deadline:
            self.tick()
            if self.cancelled:
                raise Cancelled()
            if not self.runtime.alive():
                self.fatal = True
                raise DevelopmentError('runtime exited during startup; automatic restart refused')
            try:
                client.modules()
                self.ready = True
                return
            except DevelopmentError:
                time.sleep(self.poll_interval)
        self.fatal = True
        raise DevelopmentError('runtime control startup timed out')

    def merge_committed(self, installed, overrides, committed):
        for module_id, image in committed.items():
            if module_id not in installed or installed[module_id].image != self.installed_images.get(module_id):
                continue
            if repository(image) != repository(installed[module_id].image):
                raise DevelopmentError('committed runtime image repository differs')
            overrides[module_id] = image
            self.overrides[module_id] = image

    def reconcile_records(self, installed, overrides, records):
        if any(record.get('reloading') for record in records.values()):
            raise Stale()
        committed = {module_id: record['committed_image'] for module_id, record in records.items()
                     if record.get('committed_image')}
        self.merge_committed(installed, overrides, committed)
        return committed

    def verify_candidate_bases(self, installed, bases, committed):
        for module_id, base in bases.items():
            if installed[module_id].image == self.installed_images.get(module_id) and module_id in committed and committed[module_id] != base:
                raise Stale()

    def apply(self, paths):
        generation = self.changes.generation
        installed, grace, startup, secret_environment = load_config(self.config, self.excluded_paths)
        for name in secret_environment:
            self.runner.env.pop(name, None)
        # Approval/config changes are consumed only by a whole-runtime restart.
        # Drop successful overrides only when the operator deliberately changes
        # that installed image or removes its installed ID.
        overrides = {key: image for key, image in self.overrides.items()
                     if key in installed and installed[key].image == self.installed_images.get(key)}
        if self.runtime.process is not None and not self.runtime.alive():
            self.fatal = True
            raise DevelopmentError('runtime exited unexpectedly; automatic restart refused')
        client = Client(self.control, grace + startup + 5, self.identity)
        records = client.modules() if self.runtime.alive() else {}
        self.reconcile_records(installed, overrides, records)
        sources = discover(self.root, self.runner)
        bindings = bind(installed, sources, self.publisher, overrides)
        rebuild_runtime, affected = classify(paths, sources)
        rebuild_runtime = rebuild_runtime or self.runtime.process is None
        artifact = None
        try:
            if rebuild_runtime:
                note('building runtime candidate')
                artifact = self.prepare_runtime()
            candidates = {}
            candidate_bases = {}
            for module_id, binding in bindings.items():
                if binding.source.directory not in affected and self.runtime.process is not None:
                    continue
                self.stable(generation)
                configured_changed = binding.installed.image != self.installed_images.get(module_id)
                if configured_changed:
                    # A full restart consumes the operator's authoritative new
                    # base, not the old instance's image or a dropped override.
                    base = binding.installed.image
                else:
                    base = overrides.get(module_id, records[module_id]['image'] if module_id in records else binding.installed.image)
                if not rebuild_runtime and repository(base) != repository(binding.installed.image):
                    raise DevelopmentError('runtime and installed image repositories differ')
                note('building and publishing mapped module candidate')
                candidates[module_id] = self.publisher.publish(binding, base)
                candidate_bases[module_id] = base
                # Root preparation must commit a complete candidate before the
                # nonroot reload controller can stop a healthy module.
                self.identity.manage(['prepare-image', *self.args,
                                      '--module-id', module_id, '--image', candidates[module_id]])
            self.stable(generation)
            if rebuild_runtime:
                # All candidates exist before the healthy runtime is disturbed.
                if self.runtime.process is not None:
                    latest = self.reconcile_records(installed, overrides, client.modules())
                    self.verify_candidate_bases(installed, candidate_bases, latest)
                    self.stable(generation)
                    try:
                        frozen = self.runtime.stop(self.grace)
                    except (DevelopmentError, ExecutionError, OSError):
                        self.fatal = True
                        raise
                    self.merge_committed(installed, overrides, frozen)
                    self.verify_candidate_bases(installed, candidate_bases, frozen)
                self.stable(generation)
                overrides.update(candidates)
                self.grace, self.startup = grace, startup
                self.installed_images = {key: item.image for key, item in installed.items()}
                self.overrides = overrides
                self.ready = False
                self.runtime.environment = dict(self.identity.safe_env, **secret_environment)
                self.runtime.expected_repositories = {module_id: repository(overrides.get(module_id, module.image))
                                                      for module_id, module in installed.items()}
                try:
                    self.runtime.start(artifact, overrides)
                except (DevelopmentError, ExecutionError, OSError):
                    self.fatal = True
                    raise
                artifact = None
                self.await_ready()
                try:
                    self.runtime.discard_superseded(self.runtime.artifact)
                except (DevelopmentError, ExecutionError, OSError):
                    self.fatal = True
                    raise
                note('runtime candidate active')
            else:
                for module_id, image in candidates.items():
                    self.stable(generation)
                    # Fetch immediately before replacement, not before building.
                    current = client.modules()[module_id]
                    if current['reloading'] or current['image'] != records[module_id]['image']:
                        raise DevelopmentError('module changed while candidate was building')
                    client.reload(module_id, current['instance_id'], image)
                    self.overrides[module_id] = image
                    note('module candidate active')
        finally:
            if artifact is not None and not self.fatal and (self.runtime.artifact != artifact or not self.runtime.alive()):
                try:
                    self.runtime.discard_candidate(artifact)
                except (DevelopmentError, ExecutionError, OSError):
                    self.fatal = True
                    raise

    def run(self):
        previous = {}
        failed_paths = set()
        def cancel(_number, _frame):
            self.cancelled = True
        for number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            previous[number] = signal.signal(number, cancel)
        try:
            while not self.cancelled:
                self.tick()
                if self.runtime.process is not None and not self.runtime.alive():
                    raise DevelopmentError('runtime exited unexpectedly; automatic restart refused')
                paths = self.changes.take()
                if paths:
                    paths.update(failed_paths)
                    failed_paths.clear()
                    try:
                        self.apply(paths)
                    except Stale:
                        # Retain the entire uncommitted batch, including runtime
                        # edits, and coalesce it with edits observed mid-build.
                        self.changes.pending.update(paths)
                        note('candidate superseded; coalescing source changes')
                    except (DevelopmentError, ExecutionError, OSError) as error:
                        if self.fatal:
                            raise
                        failed_paths.update(paths)
                        diagnostic = str(error) if isinstance(error, (DevelopmentError, ExecutionError)) else 'development filesystem or process operation failed'
                        note(diagnostic + '; waiting for an edit before retrying')
                time.sleep(self.poll_interval)
        except Cancelled:
            pass
        finally:
            try:
                self.runtime.join_on_exit(self.grace, retain=self.fatal)
            finally:
                for number, handler in previous.items():
                    signal.signal(number, handler)
                # Remove only session-owned runtime snapshots after children join.
                if self.runtime.process is None or self.runtime.process.poll() is not None:
                    shutil.rmtree(self.work)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', required=True, help='verified, already installed v1 launcher')
    parser.add_argument('--socket', required=True)
    parser.add_argument('--installation-id', required=True)
    args = parser.parse_args(argv)
    if os.environ.get('DEV_MODE') != '1':
        raise DevelopmentError('watching requires explicit DEV_MODE=1')
    if os.geteuid() == 0:
        raise DevelopmentError('refusing to execute writable checkout builds as root')
    root = Path(__file__).resolve().parents[2]
    identity = Identity(root, os.environ.get('DEV_RUNTIME_USER', ''))
    lock = None
    watcher = None
    try:
        identity.check_inputs(args.runtime)
        os.environ['LEGACY_RUNTIME'] = args.runtime
        config = inspect_config(identity, ['--installation-id', args.installation_id])
        load_config(config)
        # All source/compiler/native work stays under /home. Public execution
        # generations contain no secrets and require no home permission changes.
        tools = root / '.tools'
        no_symlinks(tools)
        tools.mkdir(exist_ok=True)
        private_directory(tools / 'dev')
        control = identity.socket(args.socket, management_directory(config))
        if len(os.fsencode(control)) >= 108:
            raise DevelopmentError('development socket path exceeds Unix socket limit')
        metadata = inspect_dev_lock(identity, ['--installation-id', args.installation_id])
        lock = SessionLock(metadata, identity)
        watcher = Watcher(root, config, control,
                          ['--installation-id', args.installation_id], identity)
        watcher.run()
    finally:
        if lock is not None:
            lock.close()
        # Uncertain cleanup must retain executable generations; never pretend
        # an unjoined cross-user process is gone by removing its artifacts.
        if watcher is None or not watcher.runtime.alive():
            identity.close()
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        note('cancelled before runtime startup')
        sys.exit(130)
    except BuildCleanupError:
        note('build process cleanup failed; watcher stopped without replacement')
        sys.exit(1)
    except (DevelopmentError, ExecutionError, OSError) as error:
        note(str(error) if isinstance(error, (DevelopmentError, ExecutionError)) else 'development filesystem or process operation failed')
        sys.exit(1)
