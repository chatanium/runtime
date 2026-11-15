"""Linux build-process ownership and bounded, fail-closed cancellation."""
import errno
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


class BuildCleanupError(Exception):
    """Build ownership or cleanup is uncertain; another build must not start."""


_LAUNCHER = '''import os
import signal
import sys

gate = int(sys.argv[1])
released = os.read(gate, 1)
os.close(gate)
if released != b'1':
    raise SystemExit(125)
if sys.argv[2] == '1':
    for name in ('SIGPIPE', 'SIGXFZ', 'SIGXFSZ'):
        sig = getattr(signal, name, None)
        if sig is not None:
            signal.signal(sig, signal.SIG_DFL)
os.execvpe(sys.argv[3], sys.argv[3:], os.environ)
'''


def spawn_owned(args, **popen_kwargs):
    """Capture the live root before a synchronous command can execute.

    The isolated stdlib launcher blocks on a private pipe, then execs argv in
    the same PID. Closing the gate before release never executes the command.
    Shell execution, executable overrides and pre-exec hooks would bypass this
    boundary and are deliberately unsupported.
    """
    if (popen_kwargs.get('shell') or popen_kwargs.get('executable') is not None
            or popen_kwargs.get('preexec_fn') is not None):
        raise ValueError('owned launch requires direct execution without pre-exec hooks')
    if isinstance(args, (str, bytes, os.PathLike)):
        raise TypeError('owned launch requires an argument sequence')
    command = [os.fsdecode(arg) for arg in args]
    if not command:
        raise ValueError('owned launch requires a command')
    inherited = tuple(popen_kwargs.pop('pass_fds', ()))
    read_gate, write_gate = os.pipe()
    process = None
    releasing = False
    try:
        restore = '1' if popen_kwargs.get('restore_signals', True) else '0'
        process = subprocess.Popen(
            [sys.executable, '-I', '-S', '-c', _LAUNCHER, str(read_gate), restore, *command],
            pass_fds=(*inherited, read_gate), **popen_kwargs)
        os.close(read_gate)
        read_gate = None
        capture_tree(process)
        # An exception during write may occur after delivery. From this point
        # cleanup must join the captured command tree, not just the launcher.
        releasing = True
        if os.write(write_gate, b'1') != 1:
            raise BuildCleanupError('cannot release owned command launch gate')
        return process
    except BaseException:
        os.close(write_gate)
        write_gate = None
        if process is not None:
            if releasing:
                terminate_tree(process)
            else:
                try:
                    try:
                        process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        try:
                            process.wait(timeout=1)
                        except subprocess.TimeoutExpired as error:
                            raise BuildCleanupError('owned launcher cleanup is unconfirmed') from error
                        raise BuildCleanupError('owned launcher required forced cleanup')
                finally:
                    tree = getattr(process, '_chatanium_build_tree', None)
                    if tree is not None:
                        tree.close()
        raise
    finally:
        if read_gate is not None:
            os.close(read_gate)
        if write_gate is not None:
            os.close(write_gate)


def _stat(pid):
    try:
        # comm may contain spaces and parentheses; the final ')' ends it.
        fields = Path(f'/proc/{pid}/stat').read_text().rpartition(') ')[2].split()
        return fields[0], int(fields[1]), int(fields[19])
    except (FileNotFoundError, ProcessLookupError):
        return None
    except (OSError, ValueError, IndexError) as error:
        raise BuildCleanupError('cannot establish build process identity') from error


class _Member:
    def __init__(self, pid, start):
        self.pid, self.start, self.fd = pid, start, None
        if hasattr(os, 'pidfd_open') and hasattr(signal, 'pidfd_send_signal'):
            try:
                self.fd = os.pidfd_open(pid)
            except ProcessLookupError:
                pass
            except OSError as error:
                if error.errno not in (errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP):
                    raise BuildCleanupError('cannot pin build process identity') from error

    def live(self):
        state = _stat(self.pid)
        return state is not None and state[2] == self.start and state[0] not in ('Z', 'X')

    def send(self, sig):
        if not self.live():
            return
        try:
            if self.fd is not None:
                signal.pidfd_send_signal(self.fd, sig)
            else:
                # Older kernels lack pidfds. Recheck starttime immediately before
                # signalling rather than treating a reused PID as owned work.
                state = _stat(self.pid)
                if state is not None and state[2] == self.start:
                    os.kill(self.pid, sig)
        except ProcessLookupError:
            pass
        except OSError as error:
            raise BuildCleanupError('cannot signal owned build process') from error


class _Tree:
    def __init__(self):
        self.members = {}
        self.uncertain = False

    def close(self):
        for member in self.members.values():
            if member.fd is not None:
                os.close(member.fd)
                member.fd = None


def capture_tree(process, *, allow_completed=False):
    """Retain identities just after Popen and before each build poll.

    A retained descendant remains owned after reparenting or setsid(). A /proc
    snapshot cannot recover descendants that forked and reparented before any
    observation; callers must capture while the build root is still alive.

    allow_completed is only for the caller's cooperative synchronous commands,
    before cancellation/timeout was requested. It accepts an already successful
    root, not a claim that arbitrary never-observed daemonized work was joined.
    """
    tree = getattr(process, '_chatanium_build_tree', None)
    if tree is None:
        tree = _Tree()
        process._chatanium_build_tree = tree
    try:
        if not tree.members:
            state = _stat(process.pid)
            if state is None or state[0] in ('Z', 'X'):
                if allow_completed and not tree.uncertain and process.poll() == 0:
                    return
                raise BuildCleanupError('build exited before ownership was captured')
            tree.members[(process.pid, state[2])] = _Member(process.pid, state[2])
        todo = list(tree.members.values())
        visited = set()
        while todo:
            member = todo.pop()
            key = member.pid, member.start
            if key in visited or not member.live():
                continue
            visited.add(key)
            try:
                children = set()
                for task in Path(f'/proc/{member.pid}/task').iterdir():
                    try:
                        children.update((task / 'children').read_text().split())
                    except (FileNotFoundError, ProcessLookupError):
                        continue
            except (FileNotFoundError, ProcessLookupError):
                if member.live():
                    raise BuildCleanupError('cannot capture build descendants')
                continue
            except OSError as error:
                raise BuildCleanupError('cannot capture build descendants') from error
            for text in children:
                pid = int(text)
                state = _stat(pid)
                if state is None:
                    continue
                key = pid, state[2]
                if key not in tree.members:
                    if state[1] != member.pid:
                        raise BuildCleanupError('build descendant changed owner before capture')
                    child = _Member(pid, state[2])
                    # Do not accept a pidfd opened after PID reuse.
                    try:
                        current = _stat(pid)
                    except BuildCleanupError:
                        if child.fd is not None:
                            os.close(child.fd)
                        raise
                    if current is None or current[2] != state[2]:
                        if child.fd is not None:
                            os.close(child.fd)
                        continue
                    tree.members[key] = child
                todo.append(tree.members[key])
    except (BuildCleanupError, ValueError) as error:
        tree.uncertain = True
        raise BuildCleanupError('build process ownership is uncertain') from error


def terminate_tree(process, grace=30, *, allow_completed=False):
    """TERM, join root and captured descendants, then fail closed on escalation.

    Zombies are terminal. New trap/cleanup children are observed and joined, not
    signalled during the grace period. Any forced or uncertain teardown raises
    BuildCleanupError even when SIGKILL subsequently succeeds.
    allow_completed has the same restricted normal-completion contract as
    capture_tree; it never clears an earlier ownership failure.
    """
    if not math.isfinite(grace) or grace < 0:
        raise ValueError('grace must be finite and nonnegative')
    try:
        capture_tree(process, allow_completed=allow_completed)
    except BuildCleanupError:
        process._chatanium_build_tree.uncertain = True
    tree = process._chatanium_build_tree
    try:
        if not tree.members and process.poll() is None:
            # Popen still owns its unreaped child even when /proc is inaccessible.
            try:
                process.terminate()
            except OSError:
                tree.uncertain = True
        # Children first: shells waiting for foreground commands can then run
        # their EXIT traps, including the daemon-owned native-container barrier.
        for member in reversed(list(tree.members.values())):
            try:
                member.send(signal.SIGTERM)
            except BuildCleanupError:
                tree.uncertain = True
        deadline = time.monotonic() + grace
        forced = False
        while True:
            try:
                capture_tree(process, allow_completed=allow_completed)
                live = [member for member in tree.members.values() if member.live()]
            except BuildCleanupError:
                tree.uncertain = True
                live = list(tree.members.values())
            root_done = process.poll() is not None
            if root_done and not live:
                break
            if time.monotonic() >= deadline:
                forced = True
                for member in reversed(live):
                    try:
                        member.send(signal.SIGKILL)
                    except BuildCleanupError:
                        tree.uncertain = True
                if process.poll() is None:
                    try:
                        process.kill()
                    except OSError:
                        tree.uncertain = True
                try:
                    process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    tree.uncertain = True
                # Give killed descendants a finite opportunity to become zombies;
                # their new parent, not this watcher, owns waitpid after orphaning.
                end = time.monotonic() + 1
                while time.monotonic() < end:
                    try:
                        if not any(member.live() for member in tree.members.values()):
                            break
                    except BuildCleanupError:
                        tree.uncertain = True
                        break
                    time.sleep(.02)
                break
            time.sleep(.02)
        if forced or tree.uncertain:
            raise BuildCleanupError('build cleanup was forced or uncertain; development session must stop')
        process.wait(timeout=0)
    finally:
        tree.close()
