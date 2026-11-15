"""Finite real subprocess regressions; no Docker daemon or native compiler."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import processes


class ProcessCleanupTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.children = []
        self.addCleanup(self.reap)

    def reap(self):
        # Tests must not strand a child even if an assertion fails.
        for process in self.children:
            tree = getattr(process, '_chatanium_build_tree', None)
            if tree is not None:
                for member in tree.members.values():
                    try:
                        member.send(signal.SIGKILL)
                    except processes.BuildCleanupError:
                        pass
                tree.close()
            if process.poll() is None:
                process.kill()
            process.wait(timeout=3)
        for path in self.root.glob('*.pid'):
            pid = int(path.read_text())
            state = processes._stat(pid)
            if state is not None and state[0] not in ('Z', 'X'):
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def start(self, args):
        process = subprocess.Popen(args, cwd=self.root, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   start_new_session=True)
        self.children.append(process)
        return process

    def ready(self, *names):
        deadline = time.monotonic() + 3
        while not all((self.root / name).exists() for name in names):
            if time.monotonic() >= deadline:
                self.fail('finite subprocess did not become ready')
            time.sleep(.01)

    def slow_child(self):
        child = self.root / 'child.py'
        child.write_text('''import os
from pathlib import Path
import signal
import time

def finish(signum, frame):
    time.sleep(.25)
    Path('child.done').write_text('joined')
    raise SystemExit(0)

signal.signal(signal.SIGTERM, finish)
Path('child.pid').write_text(str(os.getpid()))
Path('child.ready').touch()
while True:
    time.sleep(1)
''')
        return child

    def test_graceful_shell_exit_trap_and_nested_session_child_are_joined(self):
        child = self.slow_child()
        shell = self.root / 'build.sh'
        shell.write_text('''#!/bin/bash
trap 'exit 0' TERM
trap 'sleep .08; printf cleaned > shell.done' EXIT
setsid "$1" "$2" &
printf ready > shell.ready
wait
''')
        process = self.start(['/bin/bash', str(shell), sys.executable, str(child)])
        self.ready('shell.ready', 'child.ready')
        processes.capture_tree(process)
        processes.terminate_tree(process, grace=2)
        self.assertEqual(process.returncode, 0)
        self.assertEqual((self.root / 'shell.done').read_text(), 'cleaned')
        self.assertEqual((self.root / 'child.done').read_text(), 'joined')
        self.assertFalse(any(member.live() for member in process._chatanium_build_tree.members.values()))

    def test_captured_descendant_is_joined_after_root_exits_and_reparents_it(self):
        child = self.slow_child()
        parent = self.root / 'parent.py'
        parent.write_text('''from pathlib import Path
import subprocess
import sys
import time
subprocess.Popen([sys.executable, sys.argv[1]], start_new_session=True)
Path('parent.ready').touch()
while not Path('release').exists():
    time.sleep(.01)
''')
        process = self.start([sys.executable, str(parent), str(child)])
        self.ready('parent.ready', 'child.ready')
        processes.capture_tree(process)
        (self.root / 'release').touch()
        process.wait(timeout=3)
        self.assertFalse((self.root / 'child.done').exists())
        processes.terminate_tree(process, grace=2, allow_completed=True)
        self.assertEqual((self.root / 'child.done').read_text(), 'joined')

    def test_forced_kill_is_fatal_even_when_root_and_child_become_terminal(self):
        child = self.root / 'ignore.py'
        child.write_text('''import os
from pathlib import Path
import signal
import time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
Path('child.pid').write_text(str(os.getpid()))
Path('child.ready').touch()
while True:
    time.sleep(1)
''')
        parent = self.root / 'parent.py'
        parent.write_text('''from pathlib import Path
import signal
import subprocess
import sys
import time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
subprocess.Popen([sys.executable, sys.argv[1]], start_new_session=True)
Path('parent.ready').touch()
while True:
    time.sleep(1)
''')
        process = self.start([sys.executable, str(parent), str(child)])
        self.ready('parent.ready', 'child.ready')
        processes.capture_tree(process)
        began = time.monotonic()
        with self.assertRaisesRegex(processes.BuildCleanupError, 'forced or uncertain'):
            processes.terminate_tree(process, grace=.05)
        self.assertLess(time.monotonic() - began, 3)
        self.assertEqual(process.returncode, -signal.SIGKILL)
        self.assertFalse(any(member.live() for member in process._chatanium_build_tree.members.values()))

    def test_capture_failure_remains_fatal_after_successful_termination(self):
        process = self.start([sys.executable, '-c',
                              "from pathlib import Path; import time; Path('ready').touch(); time.sleep(30)"])
        self.ready('ready')
        processes.capture_tree(process)
        original = Path.read_text
        def deny_children(path, *args, **kwargs):
            if str(path).startswith(f'/proc/{process.pid}/task/') and path.name == 'children':
                raise PermissionError('isolated ownership failure')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'read_text', deny_children):
            with self.assertRaises(processes.BuildCleanupError):
                processes.capture_tree(process)
        with self.assertRaisesRegex(processes.BuildCleanupError, 'forced or uncertain'):
            processes.terminate_tree(process, grace=2)
        self.assertEqual(process.returncode, -signal.SIGTERM)

    def test_zombie_descendant_is_terminal_without_waiting_for_its_parent(self):
        parent = self.root / 'parent.py'
        parent.write_text('''import os
from pathlib import Path
import signal
import time
signal.signal(signal.SIGTERM, lambda signum, frame: None)
pid = os.fork()
if pid == 0:
    Path('child.ready').touch()
    while not Path('release').exists():
        time.sleep(.01)
    os._exit(0)
Path('child.pid').write_text(str(pid))
Path('parent.ready').touch()
while True:
    time.sleep(1)
''')
        process = self.start([sys.executable, str(parent)])
        self.ready('parent.ready', 'child.ready')
        processes.capture_tree(process)
        pid = int((self.root / 'child.pid').read_text())
        (self.root / 'release').touch()
        deadline = time.monotonic() + 3
        while processes._stat(pid)[0] != 'Z':
            if time.monotonic() >= deadline:
                self.fail('child did not become a zombie')
            time.sleep(.01)
        member = next(member for member in process._chatanium_build_tree.members.values() if member.pid == pid)
        self.assertFalse(member.live())
        # The still-live parent deliberately ignores TERM; its escalation remains
        # fatal, but the zombie itself must never be signalled as live work.
        with patch.object(member, 'send', wraps=member.send) as send:
            with self.assertRaises(processes.BuildCleanupError):
                processes.terminate_tree(process, grace=.05)
            self.assertNotIn(unittest.mock.call(signal.SIGKILL), send.call_args_list)

    def test_children_started_by_nonleader_thread_are_captured(self):
        child = self.slow_child()
        parent = self.root / 'threaded.py'
        parent.write_text('''from pathlib import Path
import subprocess
import sys
import threading
import time
def worker():
    subprocess.Popen([sys.executable, sys.argv[1]], start_new_session=True)
    while True:
        time.sleep(1)
threading.Thread(target=worker, daemon=True).start()
Path('parent.ready').touch()
while True:
    time.sleep(1)
''')
        process = self.start([sys.executable, str(parent), str(child)])
        self.ready('parent.ready', 'child.ready')
        processes.capture_tree(process)
        processes.terminate_tree(process, grace=2)
        self.assertEqual((self.root / 'child.done').read_text(), 'joined')

    def test_normally_exited_captured_root_requires_no_forced_cleanup(self):
        process = self.start([sys.executable, '-c',
                              "from pathlib import Path; import time; Path('ready').touch(); "
                              "exec(\"while not Path('release').exists(): time.sleep(.01)\")"])
        self.ready('ready')
        processes.capture_tree(process)
        (self.root / 'release').touch()
        process.wait(timeout=3)
        processes.terminate_tree(process, grace=.1)
        self.assertEqual(process.returncode, 0)

    def test_reused_pid_identity_is_not_signalled(self):
        member = processes._Member.__new__(processes._Member)
        member.pid, member.start, member.fd = 12345, 10, None
        with patch.object(processes, '_stat', return_value=('S', 1, 11)), patch.object(processes.os, 'kill') as kill:
            self.assertFalse(member.live())
            member.send(signal.SIGKILL)
        kill.assert_not_called()

    def test_spawn_owned_fast_success_captures_before_same_pid_exec(self):
        marker = self.root / 'executed'
        original = processes.capture_tree
        captured = []
        def observe(process, **kwargs):
            self.assertFalse(marker.exists())
            self.assertIsNone(process.poll())
            original(process, **kwargs)
            captured.append(process.pid)
        with patch.object(processes, 'capture_tree', side_effect=observe):
            process = processes.spawn_owned(
                [sys.executable, '-c',
                 "import os; from pathlib import Path; "
                 "Path('executed').write_text(os.environ['OWNED_TEST']); print(os.getpid())"],
                cwd=self.root, env={'PATH': os.defpath, 'OWNED_TEST': 'preserved'},
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=True)
        self.children.append(process)
        stdout, stderr = process.communicate(timeout=3)
        self.assertEqual(captured, [process.pid])
        self.assertEqual(int(stdout), process.pid)
        self.assertEqual(stderr, b'')
        self.assertEqual(marker.read_text(), 'preserved')
        processes.capture_tree(process)
        processes.terminate_tree(process, grace=.1)
        self.assertEqual(process.returncode, 0)

    def test_spawn_owned_fast_nonzero_remains_an_ordinary_completed_command(self):
        process = processes.spawn_owned(
            [sys.executable, '-c', 'raise SystemExit(7)'], cwd=self.root,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True)
        self.children.append(process)
        process.wait(timeout=3)
        processes.capture_tree(process)
        processes.terminate_tree(process, grace=.1)
        self.assertEqual(process.returncode, 7)

    def test_spawn_owned_capture_failure_joins_launcher_without_executing_command(self):
        real_popen = subprocess.Popen
        spawned = []
        def record(*args, **kwargs):
            process = real_popen(*args, **kwargs)
            self.children.append(process)
            spawned.append(process)
            return process
        with patch.object(processes.subprocess, 'Popen', side_effect=record), patch.object(
                processes, 'capture_tree', side_effect=processes.BuildCleanupError('isolated capture failure')):
            with self.assertRaisesRegex(processes.BuildCleanupError, 'isolated capture failure'):
                processes.spawn_owned(
                    [sys.executable, '-c', "from pathlib import Path; Path('executed').touch()"],
                    cwd=self.root, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, start_new_session=True)
        self.assertEqual(len(spawned), 1)
        self.assertEqual(spawned[0].returncode, 125)
        self.assertFalse((self.root / 'executed').exists())

    def test_fast_success_before_first_capture_is_allowed_only_explicitly(self):
        process = self.start([sys.executable, '-c', 'pass'])
        process.wait(timeout=3)
        processes.capture_tree(process, allow_completed=True)
        with patch.object(process, 'terminate', wraps=process.terminate) as terminate:
            processes.terminate_tree(process, grace=.1, allow_completed=True)
        terminate.assert_not_called()
        self.assertEqual(process.returncode, 0)

    def test_completed_nonzero_is_fatal_even_with_completion_permission(self):
        process = self.start([sys.executable, '-c', 'raise SystemExit(7)'])
        process.wait(timeout=3)
        with self.assertRaisesRegex(processes.BuildCleanupError, 'forced or uncertain'):
            processes.terminate_tree(process, grace=.1, allow_completed=True)
        self.assertEqual(process.returncode, 7)

    def test_completion_permission_cannot_erase_earlier_capture_uncertainty(self):
        process = self.start([sys.executable, '-c', 'pass'])
        process.wait(timeout=3)
        with self.assertRaises(processes.BuildCleanupError):
            processes.capture_tree(process)
        with self.assertRaisesRegex(processes.BuildCleanupError, 'forced or uncertain'):
            processes.terminate_tree(process, grace=.1, allow_completed=True)

    def test_missing_initial_ownership_is_fatal(self):
        process = self.start([sys.executable, '-c', 'pass'])
        process.wait(timeout=3)
        with self.assertRaisesRegex(processes.BuildCleanupError, 'forced or uncertain'):
            processes.terminate_tree(process, grace=.1)

    def test_grace_must_remain_finite(self):
        for grace in (-1, float('inf'), float('nan')):
            with self.subTest(grace=grace), self.assertRaises(ValueError):
                processes.terminate_tree(None, grace=grace)


if __name__ == '__main__':
    unittest.main()
