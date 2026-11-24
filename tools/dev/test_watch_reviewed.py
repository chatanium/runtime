import json
import os
from pathlib import Path
import stat
from types import SimpleNamespace
from unittest.mock import Mock, patch

import watch
from test_watch import TemporaryTree, OLD, NEW, OTHER

LATER = watch.repository(OLD) + '@sha256:' + '4' * 64


def records(image=OLD, committed=None, reloading=False, state='RUNNING'):
    return {'approved': {'module_id': 'approved', 'instance_id': image[-8:] + '-instance',
                         'image': image, 'committed_image': image if committed is None else committed,
                         'state': state, 'reloading': reloading, 'cleanup_complete': state == 'FAILED'}}


class ConfigIdentityTests(TemporaryTree):
    def metadata(self, uid):
        info = self.config.stat()
        return SimpleNamespace(st_uid=uid, st_mode=stat.S_IFREG | 0o640, st_size=info.st_size)

    def test_runtime_owned_builder_readable_config_is_accepted(self):
        metadata = self.metadata(2000)
        with patch.object(watch.os, 'geteuid', return_value=1000), patch.object(watch.os, 'fstat', return_value=metadata):
            installed, _, _, _ = watch.load_config(self.config, runtime_uid=2000)
        self.assertIn('approved', installed)

    def test_builder_owned_config_is_rejected_for_distinct_runtime(self):
        metadata = self.metadata(1000)
        with patch.object(watch.os, 'geteuid', return_value=1000), patch.object(watch.os, 'fstat', return_value=metadata):
            with self.assertRaisesRegex(watch.DevelopmentError, 'root/runtime-owned'):
                watch.load_config(self.config, runtime_uid=2000)

    def test_builder_read_access_is_an_explicit_prerequisite(self):
        with patch.object(watch.os, 'open', side_effect=PermissionError):
            with self.assertRaisesRegex(watch.DevelopmentError, 'readable by builder'):
                watch.load_config(self.config, runtime_uid=2000)

    def test_identity_and_config_validation_precede_any_build_or_socket(self):
        identity = Mock()
        identity.account = SimpleNamespace(pw_uid=2000)
        events = []
        def select_identity(*_args):
            events.append('identity')
            return identity
        def reject_config(path, **kwargs):
            events.append('config')
            self.assertEqual(path, self.config)
            self.assertEqual(kwargs, {'runtime_uid': 2000})
            raise watch.DevelopmentError('root/runtime-owned prerequisite')
        args = ['--config', str(self.config), '--socket', '', '--supervisor-socket', '/supervisor/socket',
                '--supervisor-uid', '0', '--supervisor-max-bytes', '65536']
        args = ['--runtime', '/usr/local/bin/chatanium-v1', '--socket', '', '--installation-id', 'fixture-installation']
        with patch.dict(os.environ, {'DEV_MODE': '1'}), patch.object(watch.os, 'geteuid', return_value=1000), patch.object(watch, 'Identity', side_effect=select_identity), patch.object(watch, 'load_config', side_effect=reject_config), patch.object(watch, 'Watcher') as start:
            with self.assertRaises(watch.DevelopmentError):
                watch.main(args)
        self.assertEqual(events, ['identity', 'config'])
        start.assert_not_called()
        identity.socket.assert_not_called()
        identity.close.assert_called_once()


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
        runtime = watch.RuntimeProcess(self.root, self.config, self.root / '.tools/dev/control.sock',
                                       [], lambda: False, lambda: None, self.identity)
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
