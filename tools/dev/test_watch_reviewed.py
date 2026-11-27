import json
import os
import stat
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import Mock, patch

import watch
import control
from test_watch import TemporaryTree, OLD, NEW, OTHER

LATER = watch.repository(OLD) + '@sha256:' + '4' * 64


def records(image=OLD, committed=None, reloading=False, state='RUNNING'):
    return {'approved': {'module_id': 'approved', 'instance_id': image[-8:] + '-instance',
                         'image': image, 'committed_image': image if committed is None else committed,
                         'state': state, 'reloading': reloading, 'cleanup_complete': state == 'FAILED'}}


class ConfigIdentityTests(TemporaryTree):
    def test_installed_root_response_needs_no_local_file_read(self):
        raw = self.config.read_bytes()
        self.identity.manage.side_effect = None
        self.identity.manage.return_value = raw
        with patch.object(watch.os, 'open', side_effect=PermissionError) as local_open:
            inspected = watch.inspect_config(self.identity, ['--installation-id', 'fixture-installation'])
            installed, _, _, _ = watch.load_config(inspected)
        self.assertIn('approved', installed)
        self.assertEqual(inspected, raw)
        local_open.assert_not_called()
        self.identity.manage.assert_called_once_with(
            ['inspect-config', '--installation-id', 'fixture-installation'], max_output_bytes=watch.MAX_JSON)

    def test_installed_config_response_is_bounded_and_binary(self):
        self.identity.manage.side_effect = None
        for invalid in (b'', b'x' * (watch.MAX_JSON + 1), '{}'):
            with self.subTest(kind=type(invalid), length=len(invalid)):
                self.identity.manage.return_value = invalid
                with self.assertRaises(watch.DevelopmentError):
                    watch.inspect_config(self.identity, ['--installation-id', 'fixture-installation'])

    def test_denied_root_inspection_never_falls_back_to_local_files(self):
        self.identity.manage.side_effect = watch.ExecutionError('root inspection denied')
        with patch.object(watch.os, 'open') as local_open:
            with self.assertRaises(watch.ExecutionError):
                watch.inspect_config(self.identity, ['--installation-id', 'fixture-installation'])
        local_open.assert_not_called()

    def test_canonical_quota_backed_app_path_rejects_installation_alias(self):
        raw = self.config.read_bytes()
        self.assertEqual(watch.management_directory(raw), self.management)
        document = json.loads(raw)
        document['host']['management_directory'] = str(self.root / 'installation/app')
        with self.assertRaises(watch.DevelopmentError):
            watch.management_directory(json.dumps(document).encode())

    def test_dev_socket_is_inside_native_without_builder_traversal(self):
        identity = watch.Identity.__new__(watch.Identity)
        identity.control = Mock()
        with patch.object(Path, 'stat', side_effect=PermissionError), patch.object(Path, 'lstat', side_effect=PermissionError):
            selected = identity.socket('', self.management)
            self.assertEqual(selected, self.native / 'control.sock')
            for outside in (str(self.root / 'control.sock'), str(self.native / 'nested/control.sock')):
                with self.assertRaises(watch.ExecutionError):
                    identity.socket(outside, self.management)
        identity.control.assert_not_called()

    def test_identity_and_config_validation_precede_any_build_or_socket(self):
        identity = Mock()
        identity.check_inputs.side_effect = lambda path: events.append('launcher')
        events = []
        def select_identity(*_args):
            events.append('identity')
            return identity
        raw = self.config.read_bytes()
        def inspect(arguments, **kwargs):
            events.append('inspect')
            self.assertEqual(arguments, ['inspect-config', '--installation-id', 'fixture-installation'])
            self.assertEqual(kwargs, {'max_output_bytes': watch.MAX_JSON})
            return raw
        identity.manage.side_effect = inspect
        def reject_config(inspected):
            events.append('config')
            self.assertEqual(inspected, raw)
            raise watch.DevelopmentError('invalid installed config prerequisite')
        args = ['--runtime', '/usr/local/bin/chatanium-v1', '--socket', '', '--installation-id', 'fixture-installation']
        with patch.dict(os.environ, {'DEV_MODE': '1'}), patch.object(watch.os, 'geteuid', return_value=1000), patch.object(watch, 'Identity', side_effect=select_identity), patch.object(watch, 'load_config', side_effect=reject_config), patch.object(watch, 'Watcher') as start:
            with self.assertRaises(watch.DevelopmentError):
                watch.main(args)
        self.assertEqual(events, ['identity', 'launcher', 'inspect', 'config'])
        start.assert_not_called()
        identity.socket.assert_not_called()
        identity.close.assert_called_once()


class CoordinationLockTests(TemporaryTree):
    def metadata(self):
        return {'version': 1, 'path': '/var/lib/chatanium/installations/fixture-installation/dev-watch.lock',
                'device': 7, 'inode': 12, 'uid': 0, 'gid': 4000, 'mode': 0o440}

    def test_coordination_metadata_rejects_ambiguous_or_inexact_fields(self):
        valid = self.metadata()
        raw = json.dumps(valid).encode()
        self.assertEqual(control.coordination_metadata(raw), valid)
        malformed = [raw + b'{}', raw[:-1] + b',"version":1}', b'x' * (control.MAX_LOCK_JSON + 1)]
        for field, value in (('version', True), ('uid', 1000), ('inode', 0),
                             ('gid', 0), ('mode', 0o640), ('device', -1),
                             ('path', '/var/lib/chatanium/../dev-watch.lock'), ('extra', 1)):
            changed = dict(valid)
            changed[field] = value
            malformed.append(json.dumps(changed).encode())
        for payload in malformed:
            with self.subTest(payload=payload[:80]), self.assertRaises(control.ControlError):
                control.coordination_metadata(payload)

    def test_orphaned_lock_inode_is_rejected_after_flock(self):
        metadata = self.metadata()
        opened = SimpleNamespace(st_mode=stat.S_IFREG | 0o440, st_uid=0, st_gid=4000,
                                 st_dev=7, st_ino=12, st_nlink=1, st_size=0)
        reads = [0]
        def lstat(path):
            if str(path) == metadata['path']:
                reads[0] += 1
                result = SimpleNamespace(**vars(opened))
                if reads[0] > 1:
                    result.st_ino = 13
                return result
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        with patch.object(Path, 'lstat', lstat), patch.object(control.os, 'getegid', return_value=4000), patch.object(control.os, 'open', return_value=97) as open_file, patch.object(control.os, 'fstat', return_value=opened), patch.object(control.os, 'close') as close_file, patch.object(control.fcntl, 'flock') as flock, patch('builtins.print') as ready:
            with self.assertRaisesRegex(control.ControlError, 'unsafe installed metadata'):
                control.hold_coordination_lock(metadata)
        self.assertEqual(reads[0], 2)
        flags = open_file.call_args.args[1]
        self.assertEqual(flags & os.O_ACCMODE, os.O_RDONLY)
        self.assertFalse(flags & os.O_CREAT)
        flock.assert_called_once_with(97, control.fcntl.LOCK_EX | control.fcntl.LOCK_NB)
        close_file.assert_called_once_with(97)
        ready.assert_not_called()


class CommittedImageTests(TemporaryTree):
    def prepared(self):
        watcher = self.watcher()
        artifact = self.root / 'candidate'
        artifact.mkdir()
        watcher.prepare_runtime = Mock(return_value=artifact)
        watcher.await_ready = Mock()
        return watcher, artifact

    def test_manual_success_survives_runtime_only_restart(self):
        watcher, artifact = self.prepared()
        client = Mock()
        client.modules.return_value = records(NEW)
        watcher.runtime.stop.return_value = {'approved': NEW}
        with patch.object(watch, 'Client', return_value=client), patch.object(watch, 'discover', return_value=[self.source]):
            watcher.apply({'internal/runtime/change.go'})
        watcher.publisher.manifest_name.assert_called_once_with(NEW)
        watcher.publisher.publish.assert_not_called()
        watcher.runtime.start.assert_called_once_with(artifact, {'approved': NEW})
        self.assertEqual(watcher.overrides, {'approved': NEW})

    def test_committed_image_survives_failed_current_attempt(self):
        watcher, artifact = self.prepared()
        client = Mock()
        client.modules.return_value = records(LATER, committed=NEW, state='FAILED')
        watcher.runtime.stop.return_value = {'approved': NEW}
        with patch.object(watch, 'Client', return_value=client), patch.object(watch, 'discover', return_value=[self.source]):
            watcher.apply({'internal/runtime/change.go'})
        watcher.runtime.start.assert_called_once_with(artifact, {'approved': NEW})

    def test_manual_success_during_runtime_build_is_rechecked_before_stop(self):
        watcher, artifact = self.prepared()
        client = Mock()
        client.modules.side_effect = [records(OLD), records(NEW)]
        watcher.runtime.stop.return_value = {'approved': NEW}
        with patch.object(watch, 'Client', return_value=client), patch.object(watch, 'discover', return_value=[self.source]):
            watcher.apply({'internal/runtime/change.go'})
        watcher.runtime.start.assert_called_once_with(artifact, {'approved': NEW})

    def test_in_progress_manual_reload_defers_build_and_stop(self):
        watcher, _ = self.prepared()
        client = Mock()
        client.modules.return_value = records(reloading=True)
        with patch.object(watch, 'Client', return_value=client), patch.object(watch, 'discover') as discover:
            with self.assertRaises(watch.Stale):
                watcher.apply({'internal/runtime/change.go'})
        discover.assert_not_called()
        watcher.prepare_runtime.assert_not_called()
        watcher.runtime.stop.assert_not_called()

    def test_changed_committed_candidate_base_is_discarded_before_stop(self):
        watcher, artifact = self.prepared()
        client = Mock()
        client.modules.side_effect = [records(OLD), records(LATER)]
        with patch.object(watch, 'Client', return_value=client), patch.object(watch, 'discover', return_value=[self.source]):
            with self.assertRaises(watch.Stale):
                watcher.apply({'shared/core-v2/change.go'})
        watcher.publisher.publish.assert_called_once_with(self.binding, OLD)
        watcher.runtime.stop.assert_not_called()
        watcher.runtime.start.assert_not_called()
        self.assertFalse(artifact.exists())
        self.assertEqual(watcher.overrides['approved'], LATER)

    def test_frozen_receipt_detects_manual_commit_after_final_get(self):
        watcher, artifact = self.prepared()
        client = Mock()
        client.modules.return_value = records(OLD)
        def clean_stop(_grace):
            watcher.runtime.process = None
            watcher.runtime.alive.return_value = False
            return {'approved': LATER}
        watcher.runtime.stop.side_effect = clean_stop
        with patch.object(watch, 'Client', return_value=client), patch.object(watch, 'discover', return_value=[self.source]):
            with self.assertRaises(watch.Stale):
                watcher.apply({'shared/core-v2/change.go'})
        watcher.runtime.start.assert_not_called()
        self.assertIsNone(watcher.runtime.process)
        self.assertFalse(artifact.exists())
        self.assertEqual(watcher.overrides['approved'], LATER)

    def test_operator_config_change_wins_over_live_and_frozen_manual_images(self):
        watcher, artifact = self.prepared()
        document = json.loads(self.config.read_text())
        document['modules'][0]['image'] = OTHER
        self.config.write_text(json.dumps(document))
        watcher.tick()
        candidate = watch.repository(OTHER) + '@sha256:' + '5' * 64
        watcher.publisher.publish.return_value = candidate
        client = Mock()
        client.modules.return_value = records(NEW)
        watcher.runtime.stop.return_value = {'approved': NEW}
        with patch.object(watch, 'Client', return_value=client), patch.object(watch, 'discover', return_value=[self.source]):
            watcher.apply({'@config'})
        self.assertEqual(watcher.publisher.publish.call_args.args[1], OTHER)
        watcher.runtime.start.assert_called_once_with(artifact, {'approved': candidate})

    def test_lost_reload_ack_is_reconciled_without_assuming_rollback(self):
        watcher, artifact = self.prepared()
        client = Mock()
        client.modules.return_value = records(OLD)
        client.reload.side_effect = watch.DevelopmentError('ack unavailable; outcome unresolved')
        with patch.object(watch, 'Client', return_value=client), patch.object(watch, 'discover', return_value=[self.source]):
            with self.assertRaises(watch.DevelopmentError):
                watcher.apply({self.source.directory + '/main.go'})
            client.modules.return_value = records(NEW)
            watcher.runtime.stop.return_value = {'approved': NEW}
            watcher.apply({'internal/runtime/change.go'})
        watcher.runtime.start.assert_called_once_with(artifact, {'approved': NEW})


class StopReceiptTests(TemporaryTree):
    def runtime(self, code, receipt):
        runtime = watch.RuntimeProcess(self.root, self.native / 'control.sock',
                                       ['--installation-id', 'fixture-installation'], lambda: False, lambda: None, self.identity)
        process = Mock()
        process.poll.side_effect = [None, code, code]
        process.returncode = code
        runtime.process = process
        runtime.observations = Mock()
        runtime.observations.finish.return_value = receipt
        return runtime, process

    def test_nonzero_logical_failure_with_cleanup_receipt_allows_replacement(self):
        runtime, process = self.runtime(1, {'approved': NEW})
        self.assertEqual(runtime.stop(5), {'approved': NEW})
        self.assertIsNone(runtime.process)
        runtime.observations.finish.assert_called_once()

    def test_arbitrary_zero_or_nonzero_exit_without_receipt_is_not_clean(self):
        for code in (0, 1):
            with self.subTest(code=code):
                runtime, process = self.runtime(code, None)
                with self.assertRaisesRegex(watch.DevelopmentError, 'receipt missing or invalid'):
                    runtime.stop(5)
                self.assertIs(runtime.process, process)
                runtime.observations.finish.assert_called_once()


class OwnedSpawnPolicyTests(TemporaryTree):
    def test_natural_success_allows_completed_capture_and_cleanup(self):
        runner = watch.Runner(self.root, lambda: None, lambda: False)
        process = Mock()
        process.poll.return_value = 0
        process.returncode = 0
        with patch.object(watch, 'spawn_owned', return_value=process), patch.object(watch, 'capture_tree') as capture, patch.object(watch, 'terminate_tree') as terminate:
            runner.run(['synchronous-tool'])
        self.assertTrue(all(call.kwargs == {'allow_completed': True} for call in capture.call_args_list))
        terminate.assert_called_once_with(process, allow_completed=True)

    def test_cancellation_never_allows_unobserved_completed_root(self):
        cancelled = Mock(side_effect=[False, True])
        runner = watch.Runner(self.root, lambda: None, cancelled)
        process = Mock()
        process.poll.return_value = 0
        process.returncode = 0
        with patch.object(watch, 'spawn_owned', return_value=process), patch.object(watch, 'capture_tree') as capture, patch.object(watch, 'terminate_tree') as terminate:
            with self.assertRaises(watch.Cancelled):
                runner.run(['synchronous-tool'])
        capture.assert_called_once_with(process, allow_completed=False)
        terminate.assert_called_once_with(process, allow_completed=False)
