"""Existing-account run-as and public, secret-free development generations."""
import grp
import json
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import tempfile


class ExecutionError(Exception):
    pass


def trusted(name):
    path = Path('/usr/bin') / name
    resolved = path.resolve(strict=True)
    for candidate in (path, resolved, *resolved.parents):
        info = candidate.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ExecutionError('trusted OS tool ownership prerequisite failed')
    if not os.access(resolved, os.X_OK):
        raise ExecutionError('required trusted OS tool unavailable')
    return str(path)


def docker_authority(uid, groups, home, environment):
    try:
        if grp.getgrnam('docker').gr_gid in groups:
            return True
    except KeyError:
        pass
    if any(key.startswith('DOCKER_') for key in environment):
        return True
    # Do not inspect credential contents. A Docker configuration is authority,
    # even when the caller has selected a remote/rootless daemon context.
    if (Path(home) / '.docker').exists():
        return True
    paths = [Path('/var/run/docker.sock'), Path(f'/run/user/{uid}/docker.sock')]
    runtime_dir = environment.get('XDG_RUNTIME_DIR')
    if runtime_dir:
        paths.append(Path(runtime_dir) / 'docker.sock')
    for path in paths:
        try:
            info = path.stat()
        except FileNotFoundError:
            continue
        # Mode bits miss named-user ACLs. Only query effective access for this
        # process's UID; another account is checked through actual run-as below.
        if uid == os.geteuid() and os.access(path, os.W_OK, effective_ids=True):
            return True
        # AF_UNIX connect requires write permission, not read permission.
        if (info.st_uid == uid and info.st_mode & 0o200 or
                info.st_gid in groups and info.st_mode & 0o020 or
                info.st_mode & 0o002):
            return True
    return False


class Identity:
    def __init__(self, root, username):
        try:
            self.account = pwd.getpwnam(username) if username else pwd.getpwuid(os.geteuid())
        except KeyError:
            raise ExecutionError('DEV_RUNTIME_USER must name an existing account') from None
        if self.account.pw_uid == 0:
            raise ExecutionError('DEV_RUNTIME_USER must be non-root')
        self.cross_user = self.account.pw_uid != os.geteuid()
        current = pwd.getpwuid(os.geteuid())
        if not self.cross_user and docker_authority(os.geteuid(), set(os.getgroups()) | {os.getegid()}, current.pw_dir, os.environ):
            raise ExecutionError('Docker builder requires a distinct preauthorized DEV_RUNTIME_USER')
        groups = set(os.getgrouplist(self.account.pw_name, self.account.pw_gid))
        if docker_authority(self.account.pw_uid, groups, self.account.pw_dir, {}):
            raise ExecutionError('runtime account has Docker authority')
        self.sudo = trusted('sudo') if self.cross_user else None
        self.python = trusted('python3')
        self.directory = None
        self.launcher = None
        self.safe_env = {'PATH': '/usr/bin:/bin', 'HOME': self.account.pw_dir,
                         'USER': self.account.pw_name, 'LOGNAME': self.account.pw_name,
                         'LANG': 'C.UTF-8'}
        # Ensure neither the target nor sudo silently retains builder groups.
        if self.cross_user:
            actual = set(int(value) for value in self.command([trusted('id'), '-G']).split())
            try:
                if grp.getgrnam('docker').gr_gid in actual:
                    raise ExecutionError('run-as retains Docker group authority')
            except KeyError:
                pass
            for path in [Path('/var/run/docker.sock'), Path(f'/run/user/{self.account.pw_uid}/docker.sock')]:
                if self.test('-w', path):
                    raise ExecutionError('runtime account can access Docker socket')
            if self.test('-e', Path(self.account.pw_dir) / '.docker'):
                raise ExecutionError('runtime account has Docker configuration authority')
        # /var/tmp must be an existing root-owned sticky directory. Never alter
        # home/checkout permissions or provision a user, sudoers rule or mount.
        staging = Path('/var/tmp')
        info = staging.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or not info.st_mode & stat.S_ISVTX:
            raise ExecutionError('root-owned sticky /var/tmp staging prerequisite unavailable')
        self.directory = Path(tempfile.mkdtemp(prefix='chatanium-dev-public-', dir=staging))
        try:
            shutil.copyfile(root / 'tools/dev/control.py', self.directory / 'control.py')
            (self.directory / 'control.py').chmod(0o444)
            self.directory.chmod(0o555)
        except BaseException:
            self.close()
            raise

    def argv(self, command, secrets=()):
        if not self.cross_user:
            return list(command)
        names = sorted(secrets)
        return [self.sudo, '-n', '-u', self.account.pw_name,
                *(['--preserve-env=' + ','.join(names)] if names else []), '--', *map(str, command)]

    def command(self, command, payload=None, timeout=15, secrets=None):
        environment = dict(self.safe_env)
        environment.update(secrets or {})
        try:
            result = subprocess.run(self.argv(command, secrets or ()), input=payload,
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    env=environment, cwd='/', timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise ExecutionError('preauthorized noninteractive runtime run-as prerequisite unavailable') from None
        if result.returncode != 0 or len(result.stdout) > (2 << 20):
            raise ExecutionError('runtime account operation failed; check preauthorized run-as and permissions')
        return result.stdout

    def test(self, operator, path):
        try:
            result = subprocess.run(self.argv([trusted('test'), operator, str(path)]),
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    env=self.safe_env, timeout=10, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise ExecutionError('runtime permission preflight failed') from None
        if result.returncode not in (0, 1):
            raise ExecutionError('runtime permission preflight unavailable')
        return result.returncode == 0

    def control(self, path, operation, timeout=60, payload=None):
        return self.command([self.python, '-I', str(self.directory / 'control.py'),
                             '--socket', str(path), '--timeout', str(timeout), operation],
                            payload=payload, timeout=timeout + 5)

    def socket(self, supplied, management_directory):
        native = Path(management_directory) / 'native'
        path = Path(supplied) if supplied else native / 'control.sock'
        if (not path.is_absolute() or path.parent != native or
                supplied and str(path) != supplied or
                any(ord(char) < 32 for char in str(path))):
            raise ExecutionError('development socket must be a canonical direct child of installed app/native')
        return path

    def check_inputs(self, launcher):
        path = Path(launcher)
        if not path.is_absolute() or path.resolve(strict=True) != path:
            raise ExecutionError('existing v1 launcher must have an absolute canonical path')
        for node in (path, *path.parents):
            info = node.lstat()
            if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise ExecutionError('installed launcher requires protected root-owned ancestry')
        if not path.is_file() or not os.access(path, os.X_OK):
            raise ExecutionError('installed self-managed launcher unavailable')
        self.launcher = path

    def management_argv(self, arguments, secrets=()):
        if self.launcher is None:
            raise ExecutionError('explicit legacy launcher must be verified before management')
        names = sorted(secrets)
        return [trusted('sudo'), '-n',
                *(['--preserve-env=' + ','.join(names)] if names else []),
                '--', str(self.launcher), *map(str, arguments)]

    def manage(self, arguments, timeout=300, input_file=None, max_output_bytes=2 << 20):
        try:
            result = subprocess.run(self.management_argv(arguments),
                                    stdin=input_file if input_file is not None else subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    env=self.safe_env, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise ExecutionError('installed root-management operation unavailable') from None
        if result.returncode != 0 or len(result.stdout) > max_output_bytes:
            raise ExecutionError('installed root-management operation failed')
        return result.stdout

    def stage(self, artifact):
        # Only executable/native artifacts and the small public client are
        # staged. No source checkout, config, .env, or credentials are copied.
        self.directory.chmod(0o755)
        directory = Path(tempfile.mkdtemp(prefix='generation-', dir=self.directory))
        try:
            shutil.copy2(artifact / 'chatanium-worker', directory / 'chatanium-worker')
            native = artifact / 'voice-runtime'
            if native.exists():
                for path in native.rglob('*'):
                    if path.is_symlink():
                        try:
                            path.resolve().relative_to(native.resolve())
                        except ValueError:
                            raise ExecutionError('native bundle symlink escapes public generation') from None
                shutil.copytree(native, directory / 'voice-runtime')
            for parent, dirs, files in os.walk(directory, followlinks=False):
                for name in files:
                    path = Path(parent) / name
                    if not path.is_symlink():
                        path.chmod(0o555 if path.stat().st_mode & 0o111 else 0o444)
                for name in dirs:
                    path = Path(parent) / name
                    if not path.is_symlink():
                        path.chmod(0o555)
            directory.chmod(0o555)
            return directory
        finally:
            self.directory.chmod(0o555)

    def remove_generation(self, directory):
        self.directory.chmod(0o755)
        try:
            for parent, dirs, _ in os.walk(directory):
                Path(parent).chmod(0o755)
            shutil.rmtree(directory)
        finally:
            self.directory.chmod(0o555)

    def abort(self, process):
        # This path only aborts a failed cleanup; it never authorizes restart.
        # sudo may supervise a different-UID child that the builder cannot kill.
        descendants = []
        todo = [process.pid]
        while todo:
            parent = todo.pop()
            try:
                children = Path(f'/proc/{parent}/task/{parent}/children').read_text().split()
            except FileNotFoundError:
                continue
            for child in children:
                pid = int(child)
                todo.append(pid)
                try:
                    if Path(f'/proc/{pid}').stat().st_uid == self.account.pw_uid:
                        descendants.append(str(pid))
                except FileNotFoundError:
                    pass
        if descendants:
            self.command([trusted('kill'), '-KILL', '--', *descendants])
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)

    def close(self):
        if self.directory is not None and self.directory.exists():
            for parent, dirs, _ in os.walk(self.directory):
                Path(parent).chmod(0o755)
            shutil.rmtree(self.directory)
            self.directory = None
