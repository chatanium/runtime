"""Isolated regressions; no Docker daemon, compiler or host provisioning needed."""
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import control
import execution
import watch

OLD = 'registry.example:5000/team/module@sha256:' + '1' * 64
NEW = 'registry.example:5000/team/module@sha256:' + '2' * 64
OTHER = 'registry.example:5000/team/other@sha256:' + '3' * 64


class TemporaryTree(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / '.tools/dev').mkdir(parents=True, mode=0o700)
        self.config = self.root / 'operator.json'
        self.config.write_text(json.dumps({
            'modules': [{'module_id': 'approved', 'image': OLD,
                         'entrypoint': ['/custom/bin/real-player'],
                         'config': {'unchanged': True}, 'approval': {'unchanged': True}}],
            'limits': {'termination_deadline': '2s'},
            'defaults': {'drain_deadline': '1.5s'}, 'backends': {}}))
        self.config.chmod(0o600)
        self.source = watch.Source('modules/source-folder', 'modules/source-folder',
                                   'bin/modules/source-folder/module', 'ActualImageName')
        self.binding = watch.Binding(watch.Installed('approved', OLD, '/custom/bin/real-player'), self.source)
        self.identity = Mock()
        self.identity.account = SimpleNamespace(pw_uid=os.geteuid())
        self.identity.safe_env = {'PATH': '/usr/bin:/bin', 'HOME': '/non-docker-runtime'}
        self.identity.argv.side_effect = lambda command, secrets=(): list(command)
        self.identity.remove_generation.side_effect = lambda directory: shutil.rmtree(directory)

    def watcher(self):
        result = watch.Watcher(self.root, self.config, self.root / '.tools/dev/control.sock',
                               ['--supervisor-socket', '/supervisor/socket'], self.identity, debounce=0)
        self.addCleanup(lambda: shutil.rmtree(result.work, ignore_errors=True))
        result.runner = Mock()
        result.runner.env = {}
        result.publisher = Mock()
        result.publisher.manifest_name.return_value = self.source.name
        result.publisher.publish.return_value = NEW
        result.runtime = Mock()
        result.runtime.process = Mock(spec=watch.subprocess.Popen)
        result.runtime.process.poll.return_value = None
        result.runtime.process.returncode = None
        result.runtime.alive.return_value = True
        result.runtime.stop.return_value = {}
        result.overrides = {'approved': OLD}
        result.installed_images = {'approved': OLD}
        return result


class ChangeTests(TemporaryTree):
    def test_atomic_replace_add_delete_and_ignored_outputs(self):
        source = self.root / 'main.go'
        source.write_text('old')
        previous = watch.snapshot(self.root, self.config)
        replacement = self.root / 'main.go.tmp'
        replacement.write_text('new')
        replacement.replace(source)
        (self.root / 'new.go').write_text('new')
        (self.root / '.tools/dev/generated').write_text('ignored')
        (self.root / '.env').write_text('MUST_NOT_BE_READ=secret')
        current = watch.snapshot(self.root, self.config)
        self.assertNotEqual(previous['main.go'], current['main.go'])
        self.assertIn('new.go', current)
        self.assertNotIn('.env', current)
        self.assertNotIn('.tools/dev/generated', current)
        source.unlink()
        self.assertNotIn('main.go', watch.snapshot(self.root, self.config))

    def test_debounce_coalesces_and_tracks_edits_during_build(self):
        clock = [0.0]
        state = {'a.go': (1,)}
        changes = watch.Changes(lambda: dict(state), debounce=.5, clock=lambda: clock[0])
        self.assertEqual(changes.take(), {'@initial'})
        state['a.go'] = (2,)
        changes.poll()
        clock[0] = .2
        state['b.go'] = (1,)
        changes.poll()
        clock[0] = .6
        self.assertEqual(changes.take(), set())
        clock[0] = .8
        self.assertEqual(changes.take(), {'a.go', 'b.go'})
        generation = changes.generation
        state.pop('a.go')
        changes.poll()
        self.assertGreater(changes.generation, generation)
        self.assertIn('a.go', changes.pending)

    def test_module_only_never_restarts_runtime_or_other_module(self):
        second = watch.Source('modules/other', 'modules/other', 'bin/other', 'Other')
        runtime, affected = watch.classify({'modules/source-folder/new-asset.txt'}, [self.source, second])
        self.assertFalse(runtime)
        self.assertEqual(affected, {self.source.directory})
        self.assertEqual(watch.classify({'modules/uninstalled/main.go'}, [self.source]), (False, set()))

    def test_runtime_shared_dependency_native_embed_inputs(self):
        for path in ['shared/core-v2/x.go', 'proto/core-v2/x.proto', 'go.mod',
                     'go.sum', '.go-version', 'tools/native/patch.diff', 'Makefile']:
            with self.subTest(path=path):
                runtime, affected = watch.classify({path}, [self.source])
                self.assertTrue(runtime)
                self.assertEqual(affected, {self.source.directory})
        self.assertEqual(watch.classify({'database/query.sql'}, [self.source]),
                         (True, {self.source.directory}))
        self.assertEqual(watch.classify({'internal/runtime/manager.go'}, [self.source]), (True, set()))


class BindingTests(TemporaryTree):
    def test_binding_uses_real_image_label_not_folder_or_installed_id(self):
        publisher = Mock()
        publisher.manifest_name.return_value = 'ActualImageName'
        installed = {'approved': self.binding.installed}
        result = watch.bind(installed, [self.source], publisher, {})
        self.assertEqual(result['approved'].source, self.source)
        publisher.manifest_name.assert_called_once_with(OLD)

    def test_ambiguous_name_rejected_and_uninstalled_source_not_installed(self):
        publisher = Mock()
        publisher.manifest_name.return_value = self.source.name
        duplicate = watch.Source('modules/another', '.', 'bin/another', self.source.name)
        with self.assertRaises(watch.DevelopmentError):
            watch.bind({'approved': self.binding.installed}, [self.source, duplicate], publisher, {})
        self.assertEqual(watch.bind({}, [self.source], publisher, {}), {})
        publisher.manifest_name.return_value = 'NoLocalSource'
        self.assertEqual(watch.bind({'approved': self.binding.installed}, [self.source], publisher, {}), {})

    def test_image_repository_is_exact_immutable_not_tag_or_id(self):
        self.assertEqual(watch.repository(OLD), 'registry.example:5000/team/module')
        for value in ['sha256:' + 'a' * 64, 'repo:latest', 'repo:tag@sha256:' + 'a' * 64, 'repo@sha256:fake']:
            with self.subTest(value=value), self.assertRaises(watch.DevelopmentError):
                watch.repository(value)


class OverlayTests(TemporaryTree):
    def fake_publisher(self, digests=None):
        module = self.root / self.source.directory
        module.mkdir(parents=True)
        declaration = '{"protocolMajor":2,"name":"ActualImageName"}\n'
        (module / 'manifest.json').write_text(declaration)
        binary = self.root / self.source.binary
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b'actual-new-executable')
        runner = Mock()
        inspected = {'Id': 'sha256:actual-local-id', 'RepoDigests': digests if digests is not None else [NEW],
                     'Config': {'Labels': {watch.LABEL: declaration}, 'Env': ['MEDIA_TOOLS=preserved']}}
        commands = []
        def run(args, **kwargs):
            commands.append(args)
            if args[:2] == ['docker', 'build']:
                context = Path(args[-1])
                commands.append(('dockerfile', (context / 'Dockerfile').read_text()))
                self.assertEqual((context / 'module').read_bytes(), b'actual-new-executable')
                self.assertEqual((context / 'manifest.json').read_text(), declaration)
            if args[:3] == ['docker', 'image', 'inspect']:
                return json.dumps([inspected]).encode()
            return b''
        runner.run.side_effect = run
        publisher = watch.Publisher(self.root, self.root / '.tools/dev', runner)
        publisher.inspect = Mock(return_value=inspected)
        return publisher, runner, commands

    def test_overlay_preserves_base_replaces_configured_path_and_pushes_real_digest(self):
        publisher, runner, commands = self.fake_publisher()
        image = publisher.publish(self.binding, OLD)
        self.assertEqual(image, NEW)
        dockerfile = next(command[1] for command in commands if command[0] == 'dockerfile')
        self.assertIn('FROM ' + OLD + '\n', dockerfile)
        self.assertIn('["module", "/custom/bin/real-player"]', dockerfile)
        self.assertIn('/opt/flexmodule/manifest.json', dockerfile)
        self.assertNotIn('ENV ', dockerfile)
        self.assertNotIn('ENTRYPOINT ', dockerfile)
        self.assertNotIn('RUN ', dockerfile)
        builds = [command for command in commands if command[:2] == ['docker', 'build']]
        pushes = [command for command in commands if command[:2] == ['docker', 'push']]
        self.assertEqual(len(pushes), 1)
        tag = builds[0][builds[0].index('--tag') + 1]
        self.assertTrue(tag.startswith(watch.repository(OLD) + ':dev-'))
        self.assertEqual(pushes[0][-1], tag)
        self.assertIn(['make', '--no-print-directory', 'build-module', self.source.directory], commands)
        publisher.inspect.assert_any_call(NEW)

    def test_local_id_wrong_repository_and_missing_real_digest_never_fallback(self):
        for digests in [[], [OTHER], ['sha256:' + '0' * 64], [NEW, OLD]]:
            with self.subTest(digests=digests):
                with tempfile.TemporaryDirectory() as nested:
                    old_root = self.root
                    self.root = Path(nested)
                    (self.root / '.tools/dev').mkdir(parents=True)
                    try:
                        publisher, _, _ = self.fake_publisher(digests)
                        with self.assertRaises(watch.DevelopmentError):
                            publisher.publish(self.binding, OLD)
                    finally:
                        self.root = old_root


class ApplyTests(TemporaryTree):
    def records(self):
        return {'approved': {'module_id': 'approved', 'instance_id': 'old-instance',
                             'image': OLD, 'committed_image': OLD, 'state': 'RUNNING', 'reloading': False}}

    def test_failed_build_keeps_runtime_and_active_override(self):
        watcher = self.watcher()
        watcher.publisher.publish.side_effect = watch.DevelopmentError('build failed')
        client = Mock()
        client.modules.return_value = self.records()
        with patch.object(watch, 'discover', return_value=[self.source]), patch.object(watch, 'Client', return_value=client):
            with self.assertRaises(watch.DevelopmentError):
                watcher.apply({self.source.directory + '/main.go'})
        watcher.runtime.stop.assert_not_called()
        watcher.runtime.start.assert_not_called()
        client.reload.assert_not_called()
        self.assertEqual(watcher.overrides, {'approved': OLD})

    def test_only_requested_module_reloads_and_override_changes_after_ack(self):
        watcher = self.watcher()
        client = Mock()
        client.modules.return_value = self.records()
        with patch.object(watch, 'discover', return_value=[self.source]), patch.object(watch, 'Client', return_value=client):
            watcher.apply({self.source.directory + '/main.go'})
        watcher.runtime.stop.assert_not_called()
        watcher.runtime.start.assert_not_called()
        client.reload.assert_called_once_with('approved', 'old-instance', NEW)
        self.assertEqual(watcher.overrides, {'approved': NEW})

    def test_reload_failure_never_records_candidate_as_active(self):
        watcher = self.watcher()
        client = Mock()
        client.modules.return_value = self.records()
        client.reload.side_effect = watch.DevelopmentError('stale instance')
        with patch.object(watch, 'discover', return_value=[self.source]), patch.object(watch, 'Client', return_value=client):
            with self.assertRaises(watch.DevelopmentError):
                watcher.apply({self.source.directory + '/main.go'})
        self.assertEqual(watcher.overrides, {'approved': OLD})

    def test_edit_during_build_discards_stale_candidate_before_reload(self):
        watcher = self.watcher()
        def publish(*args):
            (self.root / 'new.go').write_text('edit during build')
            return NEW
        watcher.publisher.publish.side_effect = publish
        client = Mock()
        client.modules.return_value = self.records()
        with patch.object(watch, 'discover', return_value=[self.source]), patch.object(watch, 'Client', return_value=client):
            with self.assertRaises(watch.Stale):
                watcher.apply({self.source.directory + '/main.go'})
        client.reload.assert_not_called()
        watcher.runtime.stop.assert_not_called()
        self.assertIn('new.go', watcher.changes.pending)

    def test_runtime_restart_waits_for_clean_stop_and_preserves_overrides(self):
        watcher = self.watcher()
        artifact = self.root / 'candidate'
        artifact.mkdir()
        watcher.prepare_runtime = Mock(return_value=artifact)
        watcher.await_ready = Mock()
        events = []
        watcher.runtime.stop.side_effect = lambda grace: events.append('stop-joined') or {}
        watcher.runtime.start.side_effect = lambda artifact, overrides: events.append(('start', dict(overrides)))
        client = Mock()
        client.modules.return_value = self.records()
        with patch.object(watch, 'discover', return_value=[self.source]), patch.object(watch, 'Client', return_value=client):
            watcher.apply({'internal/runtime/manager.go'})
        self.assertEqual(events, ['stop-joined', ('start', {'approved': OLD})])
        watcher.publisher.publish.assert_not_called()

    def assert_operator_image_upgrade(self, configured_image, candidate_image):
        watcher = self.watcher()
        document = json.loads(self.config.read_text())
        document['modules'][0]['image'] = configured_image
        self.config.write_text(json.dumps(document))
        configuration_bytes = self.config.read_bytes()
        watcher.tick()
        artifact = self.root / 'candidate'
        artifact.mkdir()
        watcher.prepare_runtime = Mock(return_value=artifact)
        watcher.await_ready = Mock()
        events = []
        def publish(binding, base):
            self.assertEqual(base, configured_image)
            watcher.runtime.stop.assert_not_called()
            events.append('published')
            return candidate_image
        watcher.publisher.publish.side_effect = publish
        watcher.runtime.stop.side_effect = lambda grace: events.append('stop-joined') or {}
        watcher.runtime.start.side_effect = lambda artifact, overrides: events.append(('start', dict(overrides)))
        client = Mock()
        client.modules.return_value = self.records()
        with patch.object(watch, 'discover', return_value=[self.source]), patch.object(watch, 'Client', return_value=client):
            watcher.apply({'@config'})
        watcher.publisher.manifest_name.assert_called_once_with(configured_image)
        self.assertEqual(events, ['published', 'stop-joined', ('start', {'approved': candidate_image})])
        self.assertEqual(watcher.installed_images, {'approved': configured_image})
        self.assertEqual(watcher.overrides, {'approved': candidate_image})
        self.assertEqual(self.config.read_bytes(), configuration_bytes)
        client.reload.assert_not_called()

    def test_operator_same_repository_upgrade_uses_new_configured_base(self):
        self.assert_operator_image_upgrade(watch.repository(OLD) + '@sha256:' + '4' * 64, NEW)

    def test_operator_repository_change_uses_new_configured_base(self):
        self.assert_operator_image_upgrade(OTHER, watch.repository(OTHER) + '@sha256:' + '4' * 64)

    def test_cleanup_failure_never_starts_replacement(self):
        watcher = self.watcher()
        artifact = self.root / 'candidate'
        artifact.mkdir()
        watcher.prepare_runtime = Mock(return_value=artifact)
        watcher.runtime.stop.side_effect = watch.DevelopmentError('cleanup incomplete')
        client = Mock()
        client.modules.return_value = self.records()
        with patch.object(watch, 'discover', return_value=[self.source]), patch.object(watch, 'Client', return_value=client):
            with self.assertRaises(watch.DevelopmentError):
                watcher.apply({'internal/runtime/manager.go'})
        self.assertTrue(watcher.fatal)
        watcher.runtime.start.assert_not_called()
        self.assertFalse(artifact.exists())

    def test_failed_runtime_edit_is_retained_until_next_edit_without_busy_retry(self):
        watcher = self.watcher()
        watcher.runtime.process = None
        batches = iter([{'runtime.go'}, set(), {'module.go'}])
        watcher.changes.take = lambda: next(batches)
        applied = []
        def apply(paths):
            applied.append(set(paths))
            if len(applied) == 1:
                raise watch.DevelopmentError('compile failed')
            watcher.cancelled = True
        watcher.apply = apply
        with patch.object(watch.signal, 'signal', return_value=signal.SIG_DFL), patch.object(watch.time, 'sleep'):
            watcher.run()
        self.assertEqual(applied, [{'runtime.go'}, {'runtime.go', 'module.go'}])
        watcher.runtime.join_on_exit.assert_called_once()


class RuntimeProcessTests(TemporaryTree):
    def runtime(self):
        return watch.RuntimeProcess(self.root, self.config, self.root / '.tools/dev/control.sock',
                                    ['--supervisor-uid', '0'], lambda: False, lambda: None, self.identity)

    def test_runtime_has_only_safe_env_and_explicit_secret_names(self):
        runtime = self.runtime()
        runtime.environment['EXPLICIT_TOKEN'] = 'secret-not-in-argv'
        process = Mock()
        process.poll.return_value = None
        with patch.object(watch, 'trusted', return_value='/usr/bin/env'), patch.object(watch, 'RuntimeObservations'), patch.object(watch.subprocess, 'Popen', return_value=process) as spawn:
            runtime.start(self.root / 'generation', {'approved': NEW})
        command = spawn.call_args.args[0]
        self.assertNotIn('secret-not-in-argv', ' '.join(command))
        self.assertIn('--dev-mode', command)
        self.assertEqual(command[command.index('--dev-module-image') + 1], 'approved=' + NEW)
        self.assertEqual(spawn.call_args.kwargs['env']['EXPLICIT_TOKEN'], 'secret-not-in-argv')
        self.assertNotIn('DOCKER_HOST', spawn.call_args.kwargs['env'])
        with self.assertRaises(watch.DevelopmentError):
            runtime.start(self.root / 'generation', {})

    def test_positive_cleanup_barrier_required_before_clearing_process(self):
        runtime = self.runtime()
        process = Mock()
        process.poll.side_effect = [None, 0, 0]
        process.returncode = 0
        runtime.process = process
        runtime.observations = Mock()
        runtime.observations.finish.return_value = {'approved': OLD}
        runtime.stop(5)
        process.send_signal.assert_called_once_with(signal.SIGTERM)
        self.assertIsNone(runtime.process)

    def test_nonzero_and_spontaneous_exit_are_not_clean_restart_barriers(self):
        for spontaneous in (False, True):
            with self.subTest(spontaneous=spontaneous):
                runtime = self.runtime()
                process = Mock()
                process.poll.side_effect = [1] if spontaneous else [None, 1, 1]
                process.returncode = 1
                runtime.process = process
                with self.assertRaises(watch.DevelopmentError):
                    runtime.stop(5)
                self.assertIs(runtime.process, process)


class SecurityTests(TemporaryTree):
    def test_config_permissions_duplicates_and_bytes_preserved(self):
        before = self.config.read_bytes()
        installed, grace, startup, secrets = watch.load_config(self.config)
        self.assertEqual(installed['approved'].entrypoint, '/custom/bin/real-player')
        self.assertEqual(grace, 8.5)
        self.assertEqual(secrets, {})
        self.assertEqual(self.config.read_bytes(), before)
        self.config.chmod(0o666)
        with self.assertRaises(watch.DevelopmentError):
            watch.load_config(self.config)
        with self.assertRaises(watch.DevelopmentError):
            watch.decode('{"x":1,"x":2}')

    def test_runtime_secrets_are_explicit_exports_not_dotenv_or_build_env(self):
        doc = json.loads(self.config.read_text())
        doc['backends'] = {'discord': {'secret_sources': {'bot_token': 'env:EXPLICIT_TOKEN'}}}
        self.config.write_text(json.dumps(doc))
        (self.root / '.env').write_text('EXPLICIT_TOKEN=must-not-load')
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(watch.DevelopmentError):
            watch.load_config(self.config)
        with patch.dict(os.environ, {'EXPLICIT_TOKEN': 'exported', 'UNRELATED_TOKEN': 'not-forwarded'}):
            _, _, _, secrets = watch.load_config(self.config)
            runner = watch.Runner(self.root, lambda: None, lambda: False)
        self.assertEqual(secrets, {'EXPLICIT_TOKEN': 'exported'})
        self.assertNotIn('EXPLICIT_TOKEN', runner.env)
        self.assertNotIn('UNRELATED_TOKEN', runner.env)

    def test_public_generation_contains_no_env_config_or_writable_files(self):
        identity = execution.Identity.__new__(execution.Identity)
        identity.directory = self.root / 'public'
        identity.directory.mkdir(mode=0o555)
        identity.generated_socket_directory = None
        artifact = self.root / 'artifact'
        artifact.mkdir()
        (artifact / 'chatanium').write_bytes(b'executable')
        (artifact / 'chatanium').chmod(0o755)
        (artifact / '.env').write_text('NEVER_COPY=secret')
        (artifact / 'config.json').write_text('NEVER_COPY')
        (artifact / 'voice-runtime/lib').mkdir(parents=True)
        (artifact / 'voice-runtime/lib/libvoice.so').write_bytes(b'library')
        generation = identity.stage(artifact)
        self.assertEqual(set(path.name for path in generation.iterdir()), {'chatanium', 'voice-runtime'})
        for path in generation.rglob('*'):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode) & 0o222, 0)
        identity.remove_generation(generation)
        identity.close()

    def test_cross_user_command_preserves_names_not_secret_values(self):
        identity = execution.Identity.__new__(execution.Identity)
        identity.cross_user = True
        identity.account = SimpleNamespace(pw_name='existing-runtime')
        identity.sudo = '/usr/bin/sudo'
        command = identity.argv(['/public/chatanium', 'start'], {'TOKEN': 'never-argv'})
        self.assertEqual(command[:4], ['/usr/bin/sudo', '-n', '-u', 'existing-runtime'])
        self.assertIn('--preserve-env=TOKEN', command)
        self.assertNotIn('never-argv', ' '.join(command))

    def test_same_builder_docker_authority_requires_distinct_account(self):
        account = SimpleNamespace(pw_uid=1000, pw_gid=1000, pw_name='builder', pw_dir='/home/builder')
        with patch.object(execution.pwd, 'getpwnam', return_value=account), patch.object(execution.pwd, 'getpwuid', return_value=account), patch.object(execution.os, 'geteuid', return_value=1000), patch.object(execution, 'docker_authority', return_value=True):
            with self.assertRaisesRegex(execution.ExecutionError, 'distinct'):
                execution.Identity(self.root, 'builder')

    def test_current_user_effective_acl_docker_socket_authority(self):
        metadata = SimpleNamespace(st_uid=0, st_gid=0, st_mode=stat.S_IFSOCK | 0o600)
        with patch.object(execution.grp, 'getgrnam', side_effect=KeyError), patch.object(execution.Path, 'exists', return_value=False), patch.object(execution.Path, 'stat', return_value=metadata), patch.object(execution.os, 'geteuid', return_value=1000), patch.object(execution.os, 'access', return_value=True) as access:
            self.assertTrue(execution.docker_authority(1000, {1000}, '/home/builder', {}))
        access.assert_called_once_with(Path('/var/run/docker.sock'), os.W_OK, effective_ids=True)

    def test_target_socket_authority_does_not_use_builder_access(self):
        metadata = SimpleNamespace(st_uid=0, st_gid=0, st_mode=stat.S_IFSOCK | 0o600)
        with patch.object(execution.grp, 'getgrnam', side_effect=KeyError), patch.object(execution.Path, 'exists', return_value=False), patch.object(execution.Path, 'stat', return_value=metadata), patch.object(execution.os, 'geteuid', return_value=1000), patch.object(execution.os, 'access', return_value=True) as access:
            self.assertFalse(execution.docker_authority(2000, {2000}, '/home/runtime', {}))
        access.assert_not_called()

    def test_write_only_docker_socket_is_authority(self):
        for owner, group, mode in [(2000, 999, 0o200), (0, 2000, 0o020), (0, 0, 0o002)]:
            with self.subTest(mode=mode):
                metadata = SimpleNamespace(st_uid=owner, st_gid=group, st_mode=stat.S_IFSOCK | mode)
                with patch.object(execution.grp, 'getgrnam', side_effect=KeyError), patch.object(execution.Path, 'exists', return_value=False), patch.object(execution.Path, 'stat', return_value=metadata), patch.object(execution.os, 'geteuid', return_value=1000), patch.object(execution.os, 'access') as access:
                    self.assertTrue(execution.docker_authority(2000, {2000}, '/home/runtime', {}))
                access.assert_not_called()

    def test_builder_env_does_not_forward_ssh_agent(self):
        with patch.dict(os.environ, {'SSH_AUTH_SOCK': '/private/agent.sock'}):
            runner = watch.Runner(self.root, lambda: None, lambda: False)
        self.assertNotIn('SSH_AUTH_SOCK', watch.BUILD_ENV)
        self.assertNotIn('SSH_AUTH_SOCK', runner.env)

    def test_control_parent_mode_and_symlink_are_not_repaired(self):
        directory = self.root / 'control'
        directory.mkdir(mode=0o755)
        with self.assertRaises(control.ControlError):
            control.private_directory(directory)
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o755)
        directory.chmod(0o700)
        link = self.root / 'link'
        link.symlink_to(directory, target_is_directory=True)
        with self.assertRaises(control.ControlError):
            control.private_directory(link)


class InitialPublicationTests(TemporaryTree):
    def test_initial_source_images_are_published_before_runtime_start(self):
        watcher = self.watcher()
        watcher.runtime.process = None
        watcher.runtime.alive.return_value = False
        artifact = self.root / 'candidate'
        artifact.mkdir()
        watcher.prepare_runtime = Mock(return_value=artifact)
        watcher.await_ready = Mock()
        events = []
        watcher.publisher.publish.side_effect = lambda *_args: events.append('published') or NEW
        watcher.runtime.start.side_effect = lambda _artifact, overrides: events.append(('start', dict(overrides)))
        with patch.object(watch, 'discover', return_value=[self.source]):
            watcher.apply({'@initial'})
        self.assertEqual(events, ['published', ('start', {'approved': NEW})])
        watcher.runtime.stop.assert_not_called()

    def test_shared_candidate_build_failure_happens_before_stopping_runtime(self):
        watcher = self.watcher()
        artifact = self.root / 'candidate'
        artifact.mkdir()
        watcher.prepare_runtime = Mock(return_value=artifact)
        watcher.publisher.publish.side_effect = watch.DevelopmentError('publication failed')
        client = Mock()
        client.modules.return_value = {'approved': {'image': OLD}}
        with patch.object(watch, 'discover', return_value=[self.source]), patch.object(watch, 'Client', return_value=client):
            with self.assertRaises(watch.DevelopmentError):
                watcher.apply({'shared/core-v2/change.go'})
        watcher.runtime.stop.assert_not_called()
        watcher.runtime.start.assert_not_called()
        self.assertFalse(artifact.exists())

    def test_configured_runtime_storage_is_excluded_without_reading_contents(self):
        storage = self.root / 'operator-named-state'
        storage.mkdir()
        (storage / 'a.go').write_text('not source')
        doc = json.loads(self.config.read_text())
        doc['host'] = {'storage_root': str(storage)}
        self.config.write_text(json.dumps(doc))
        exclusions = set()
        watch.load_config(self.config, exclusions)
        state = watch.snapshot(self.root, self.config, exclusions)
        self.assertNotIn('operator-named-state/a.go', state)
        self.assertIn('@config', state)


class CancellationTests(TemporaryTree):
    def test_build_cleanup_failure_bypasses_retry_and_joins_runtime(self):
        watcher = self.watcher()
        watcher.changes.take = lambda: {'@initial'}
        watcher.apply = Mock(side_effect=watch.BuildCleanupError('cleanup incomplete'))
        with patch.object(watch.signal, 'signal', return_value=signal.SIG_DFL):
            with self.assertRaises(watch.BuildCleanupError):
                watcher.run()
        watcher.apply.assert_called_once_with({'@initial'})
        watcher.runtime.join_on_exit.assert_called_once_with(watcher.grace)

    def test_cancelling_build_terminates_and_joins_compiler_tree(self):
        cancelled = Mock(side_effect=[False, True])
        runner = watch.Runner(self.root, lambda: None, cancelled)
        process = Mock()
        process.poll.return_value = None
        with patch.object(watch, 'spawn_owned', return_value=process), patch.object(watch, 'capture_tree'), patch.object(watch, 'terminate_tree') as terminate:
            with self.assertRaises(watch.Cancelled):
                runner.run(['compiler'])
        terminate.assert_called_once_with(process, allow_completed=False)
        self.assertIsNone(runner.process)

    def test_runner_captures_before_poll_and_cleans_after_root_exit(self):
        events = []
        runner = watch.Runner(self.root, lambda: events.append('tick'), lambda: False)
        process = Mock(spec=watch.subprocess.Popen)
        results = iter([None, 0])
        def poll():
            events.append('poll')
            return next(results)
        process.poll.side_effect = poll
        process.returncode = 0
        with patch.object(watch, 'spawn_owned', return_value=process), patch.object(watch, 'capture_tree', side_effect=lambda child, **policy: events.append('capture')), patch.object(watch, 'terminate_tree', side_effect=lambda child, **policy: events.append('terminate')), patch.object(watch.time, 'sleep'):
            runner.run(['compiler'])
        self.assertEqual(events, ['capture', 'poll', 'tick', 'capture', 'poll', 'capture', 'terminate'])
        self.assertIsNone(runner.process)

    def test_stale_batch_is_coalesced_with_new_edit_not_dropped(self):
        watcher = self.watcher()
        watcher.runtime.process = None
        applied = []
        def apply(paths):
            applied.append(set(paths))
            if len(applied) == 1:
                watcher.changes.pending.add('new.go')
                raise watch.Stale()
            watcher.cancelled = True
        watcher.apply = apply
        with patch.object(watch.signal, 'signal', return_value=signal.SIG_DFL), patch.object(watch.time, 'sleep'):
            watcher.run()
        self.assertEqual(applied, [{'@initial'}, {'@initial', 'new.go'}])

    def test_cancellation_still_joins_active_runtime(self):
        watcher = self.watcher()
        process = watch.subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(0.05)'])
        def reap_child():
            if process.poll() is None:
                process.terminate()
            process.wait()
        self.addCleanup(reap_child)
        watcher.runtime.process = process
        watcher.runtime.join_on_exit.side_effect = lambda grace: process.wait(timeout=grace)
        watcher.changes.take = lambda: {'@initial'}
        watcher.apply = Mock(side_effect=watch.Cancelled())
        with patch.object(watch.signal, 'signal', return_value=signal.SIG_DFL):
            watcher.run()
        watcher.runtime.join_on_exit.assert_called_once_with(watcher.grace)
        self.assertEqual(process.poll(), 0)

    def test_timeout_is_abort_only_and_cannot_authorize_replacement(self):
        runtime = watch.RuntimeProcess(self.root, self.config, self.root / '.tools/dev/control.sock',
                                       [], lambda: False, lambda: None, self.identity)
        process = Mock()
        process.poll.return_value = None
        runtime.process = process
        with self.assertRaisesRegex(watch.DevelopmentError, 'replacement refused'):
            runtime.stop(0)
        self.identity.abort.assert_called_once_with(process)
        self.assertIs(runtime.process, process)


if __name__ == '__main__':
    unittest.main()
