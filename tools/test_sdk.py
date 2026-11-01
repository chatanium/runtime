"""SDK cache safety tests with local archives and real patch application.

Run: python3 -I -m unittest discover -s tools -p 'test_sdk.py'
No network or shared module cache is used. Go's process boundary is supplied
with synthetic manifest/download metadata; checksum, filesystem, patching,
publication and read-only validation are exercised by the real implementation.
"""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
import zipfile

SPEC = importlib.util.spec_from_file_location('sdk', Path(__file__).with_name('sdk.py'))
sdk = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sdk)


def checksum(files):
    summary = ''.join(hashlib.sha256(content).hexdigest() + '  ' + name + '\n'
                      for name, content in sorted(files.items()))
    return 'h1:' + base64.b64encode(hashlib.sha256(summary.encode()).digest()).decode()


class SDKPreparationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.target = self.root / '.tools/deps/discordgo'
        self.patch_dir = self.root / 'third_party/discordgo/patches'
        self.patch_dir.mkdir(parents=True)
        self.version = 'v0.29.1-0.20260214123928-f43dd94faaac'
        self.go_mod = f'module {sdk.MODULE}\n\ngo 1.27.0\n'.encode()
        self.files = {'go.mod': self.go_mod, 'sdk.go': b'package discordgo\n\nconst Value = "upstream"\n'}
        self.prefix = sdk.MODULE + '@' + self.version + '/'
        self.archive = self.root / 'upstream.zip'
        self.write_archive(self.files)
        self.sum = checksum({self.prefix + key: value for key, value in self.files.items()})
        self.mod_sum = checksum({'go.mod': self.go_mod})
        self.mod_file = self.root / 'upstream.mod'
        self.mod_file.write_bytes(self.go_mod)
        # This is deliberately not the source encoded by the verified archive.
        self.cache_dir = self.root / 'mutated-cache'
        self.cache_dir.mkdir()
        (self.cache_dir / 'sdk.go').write_text('untrusted extracted cache\n')
        (self.root / 'third_party/discordgo/upstream.sum').write_text(
            f'{sdk.MODULE} {self.version} {self.sum}\n'
            f'{sdk.MODULE} {self.version}/go.mod {self.mod_sum}\n')
        self.manifests = {self.root: self.consumer_manifest('./.tools/deps/discordgo')}
        self.write_patch('patched')
        self.root_patch = mock.patch.object(sdk, 'ROOT', self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        environment = mock.patch.object(
            sdk, '_go_environment', return_value=('synthetic-go', dict(os.environ, GOWORK='off')))
        environment.start()
        self.addCleanup(environment.stop)
        manifests = mock.patch.object(sdk, '_manifest', side_effect=self.manifest)
        manifests.start()
        self.addCleanup(manifests.stop)
        download = mock.patch.object(sdk.subprocess, 'check_output', side_effect=self.download)
        self.download_mock = download.start()
        self.addCleanup(download.stop)

    def consumer_manifest(self, replacement):
        return {'Require': [{'Path': sdk.MODULE, 'Version': self.version}],
                'Replace': [{'Old': {'Path': sdk.MODULE}, 'New': {'Path': replacement}}]}

    def manifest(self, go, env, directory):
        directory = Path(directory)
        if directory in self.manifests:
            return self.manifests[directory]
        directive = (directory / 'go.mod').read_text().splitlines()[0].split()
        return {'Module': {'Path': directive[1]}}

    def download(self, command, *, env, text):
        self.assertEqual(command[-3:-1], ['download', '-json'])
        self.assertEqual(command[-1], sdk.MODULE + '@' + self.version)
        self.assertEqual(Path(env['GOMODCACHE']), self.root / '.tools/deps/download-cache')
        self.assertEqual(env['GOWORK'] if 'GOWORK' in env else 'off', 'off')
        return json.dumps({'Path': sdk.MODULE, 'Version': self.version,
                           'Sum': self.sum, 'GoModSum': self.mod_sum,
                           'Zip': str(self.archive), 'GoMod': str(self.mod_file),
                           'Dir': str(self.cache_dir)})

    def write_archive(self, files):
        with zipfile.ZipFile(self.archive, 'w') as archive:
            for name, content in files.items():
                archive.writestr(self.prefix + name, content)

    def write_patch(self, value):
        self.patch_dir.joinpath('0001-value.patch').write_text(
            'diff --git a/sdk.go b/sdk.go\n'
            '--- a/sdk.go\n+++ b/sdk.go\n@@ -1,3 +1,3 @@\n'
            ' package discordgo\n \n'
            '-const Value = "upstream"\n'
            f'+const Value = "{value}"\n')

    def resolve(self, **kwargs):
        return sdk.resolve(module_dir=self.root, **kwargs)

    def snapshot(self):
        return {str(path.relative_to(self.target)): (path.read_bytes(), path.stat().st_mtime_ns)
                for path in self.target.rglob('*') if path.is_file()}

    def test_bootstrap_verifies_archive_not_mutated_extracted_cache(self):
        self.assertFalse(self.target.exists())
        metadata = self.resolve()
        self.assertTrue(self.target.is_symlink())
        self.assertEqual(self.target.resolve(), Path(metadata['Dir']))
        self.assertFalse(Path(metadata['Dir']).is_symlink())
        self.assertIn('"patched"', (self.target / 'sdk.go').read_text())
        self.assertNotIn('Dir', sdk.provenance(metadata))
        self.assertEqual(metadata['Sum'], self.sum)
        self.assertEqual(metadata['GoModSum'], self.mod_sum)
        self.assertEqual((self.cache_dir / 'sdk.go').read_text(), 'untrusted extracted cache\n')

    def test_patch_application_below_enclosing_repository_changes_real_source(self):
        subprocess.run(['git', 'init', '--quiet', str(self.root)], check=True)
        environment = dict(os.environ, GOWORK='off', GIT_DIR=str(self.root / '.git'))
        with mock.patch.object(sdk, '_go_environment', return_value=('synthetic-go', environment)):
            self.resolve()
        self.assertIn('"patched"', (self.target / 'sdk.go').read_text())
        self.assertFalse((self.target / '.git').exists())

    def test_unsafe_patch_cannot_escape_staging(self):
        (self.patch_dir / '0001-value.patch').write_text(
            'diff --git a/../../escaped b/../../escaped\n'
            'new file mode 100644\n--- /dev/null\n+++ b/../../escaped\n'
            '@@ -0,0 +1 @@\n+escaped\n')
        with self.assertRaises(subprocess.CalledProcessError):
            self.resolve()
        self.assertFalse((self.root / '.tools/deps/escaped').exists())
        self.assertFalse(self.target.exists())

    def test_repeat_reuses_untouched_source_without_download(self):
        first = self.resolve()
        before = self.snapshot()
        with mock.patch.object(sdk, '_download', side_effect=AssertionError('unexpected download')):
            second = self.resolve()
        self.assertEqual(first, second)
        self.assertEqual(before, self.snapshot())

    def test_changed_patch_rebuilds_from_clean_upstream(self):
        first = self.resolve()
        self.write_patch('different')
        second = self.resolve()
        self.assertNotEqual(first['PatchSHA256'], second['PatchSHA256'])
        self.assertNotEqual(first['SourceSHA256'], second['SourceSHA256'])
        self.assertIn('"different"', (self.target / 'sdk.go').read_text())
        self.assertNotIn('"patched"', (self.target / 'sdk.go').read_text())
        self.assertNotEqual(first['Dir'], second['Dir'])
        self.assertIn('"patched"', (Path(first['Dir']) / 'sdk.go').read_text())
        self.assertEqual(self.target.resolve(), Path(second['Dir']))

    def test_failed_patch_preserves_previous_ready_tree(self):
        first = self.resolve()
        before = self.snapshot()
        self.write_patch('bad')
        path = self.patch_dir / '0001-value.patch'
        path.write_text(path.read_text().replace('-const Value = "upstream"', '-const Value = "absent"'))
        with self.assertRaises(subprocess.CalledProcessError):
            self.resolve()
        self.assertEqual(before, self.snapshot())
        self.assertEqual(sdk._existing(Path(first['Dir'])), sdk.provenance(first))

    def test_reported_checksum_cannot_hide_corrupted_archive(self):
        self.resolve()
        before = self.snapshot()
        self.write_patch('next')
        self.write_archive({**self.files, 'sdk.go': b'corrupted original\n'})
        with self.assertRaisesRegex(RuntimeError, 'archive checksum mismatch'):
            self.resolve()
        self.assertEqual(before, self.snapshot())

    def test_download_failure_preserves_previous_ready_tree(self):
        self.resolve()
        before = self.snapshot()
        self.write_patch('next')
        with mock.patch.object(sdk.subprocess, 'check_output', side_effect=subprocess.CalledProcessError(1, 'download')):
            with self.assertRaises(subprocess.CalledProcessError):
                self.resolve()
        self.assertEqual(before, self.snapshot())

    def test_publication_failure_restores_previous_ready_tree(self):
        first = self.resolve()
        before = self.snapshot()
        self.write_patch('next')
        replace = Path.replace

        def fail_publish(path, destination):
            self.assertTrue(self.target.is_symlink())
            self.assertEqual(self.target.resolve(), Path(first['Dir']))
            if path.name == 'alias' and Path(destination) == self.target:
                raise OSError('synthetic publication failure')
            return replace(path, destination)

        with mock.patch.object(Path, 'replace', fail_publish):
            with self.assertRaisesRegex(OSError, 'publication failure'):
                self.resolve()
        self.assertEqual(before, self.snapshot())

    def test_modified_ready_source_is_never_overwritten(self):
        self.resolve()
        (self.target / 'sdk.go').write_text('user edit\n')
        self.write_patch('next')
        for prepare in (True, False):
            with self.subTest(prepare=prepare), self.assertRaisesRegex(RuntimeError, 'source was modified'):
                self.resolve(prepare=prepare)
        self.assertEqual((self.target / 'sdk.go').read_text(), 'user edit\n')

    def test_readonly_returns_host_provenance_without_any_write_or_download(self):
        first = self.resolve()
        before = self.snapshot()
        # Verification must not even open a lock file; existing source and patch
        # inputs remain readable while every filesystem write entry point fails.
        original_open = Path.open

        def readonly_open(path, mode='r', *args, **kwargs):
            if any(flag in mode for flag in 'wax+'):
                raise AssertionError('write attempted during readonly resolution')
            return original_open(path, mode, *args, **kwargs)

        with mock.patch.object(Path, 'open', readonly_open), \
                mock.patch.object(Path, 'mkdir', side_effect=AssertionError('mkdir attempted')), \
                mock.patch.object(sdk.fcntl, 'flock', side_effect=AssertionError('lock attempted')), \
                mock.patch.object(sdk, '_download', side_effect=AssertionError('download attempted')):
            second = self.resolve(prepare=False)
        self.assertEqual(sdk.provenance(first), sdk.provenance(second))
        self.assertEqual(before, self.snapshot())

    def test_readonly_missing_and_stale_trees_fail_without_creating_output(self):
        with self.assertRaisesRegex(RuntimeError, 'missing or stale'):
            self.resolve(prepare=False)
        self.assertFalse((self.root / '.tools').exists())
        self.resolve()
        self.write_patch('next')
        with self.assertRaisesRegex(RuntimeError, 'missing or stale'):
            self.resolve(prepare=False)

    def test_consumer_sums_may_omit_upstream_records_after_tidy(self):
        consumer = self.root / 'modules/example'
        consumer.mkdir(parents=True)
        self.manifests[consumer] = self.consumer_manifest('../../.tools/deps/discordgo')
        # Local replaces mean tidy need not retain original module checksums.
        (self.root / 'go.sum').write_text('')
        (consumer / 'go.sum').write_text('')
        host = self.resolve()
        readonly = sdk.resolve(module_dir=consumer, prepare=False)
        self.assertEqual(sdk.provenance(host), sdk.provenance(readonly))
        self.assertEqual((self.root / 'go.sum').read_text(), '')
        self.assertEqual((consumer / 'go.sum').read_text(), '')

    def test_upstream_checksum_authority_requires_exact_matching_records(self):
        path = self.root / 'third_party/discordgo/upstream.sum'
        original = path.read_text()
        invalid = (
            original.splitlines()[0] + '\n',
            original + original.splitlines()[0] + '\n',
            original.replace(self.version, 'v0.1.0'),
            original.replace(sdk.MODULE, 'example.org/unrelated'),
            original.replace(self.sum, 'h1:invalid'),
        )
        for content in invalid:
            with self.subTest(content=content):
                path.write_text(content)
                with self.assertRaisesRegex(RuntimeError, 'upstream.sum'):
                    self.resolve(prepare=False)
        self.assertFalse(self.target.exists())

    def test_consumer_must_share_exact_version_and_owned_replacement(self):
        consumer = self.root / 'modules/example'
        consumer.mkdir(parents=True)
        self.manifests[consumer] = self.consumer_manifest('../../.tools/deps/discordgo')
        self.resolve()
        sdk.resolve(module_dir=consumer, prepare=False)
        for key, value in (('version', 'v0.1.0'), ('replacement', '../../unpatched')):
            self.manifests[consumer] = self.consumer_manifest('../../.tools/deps/discordgo')
            manifest = self.manifests[consumer]
            if key == 'version':
                manifest['Require'][0]['Version'] = value
            else:
                manifest['Replace'][0]['New']['Path'] = value
            with self.subTest(key=key), self.assertRaisesRegex(RuntimeError, 'must require|must replace'):
                sdk.resolve(module_dir=consumer, prepare=False)

    def test_unsafe_archive_paths_are_rejected_even_with_matching_checksum(self):
        self.files['../outside.go'] = b'escape\n'
        self.write_archive(self.files)
        self.sum = checksum({self.prefix + key: value for key, value in self.files.items()})
        metadata = {'Version': self.version, 'Sum': self.sum}
        with self.assertRaisesRegex(RuntimeError, 'Unsafe upstream archive entry'):
            sdk._archive_entries(self.archive, metadata)
        self.assertFalse((self.root / 'outside.go').exists())

    def test_unknown_direct_source_directory_is_preserved(self):
        self.target.mkdir(parents=True)
        (self.target / 'user.go').write_text('user source\n')
        with self.assertRaisesRegex(RuntimeError, 'move .* aside explicitly'):
            self.resolve()
        self.assertEqual((self.target / 'user.go').read_text(), 'user source\n')

    def test_alias_rejects_absolute_and_unaddressed_targets(self):
        first = self.resolve()
        original = Path(first['Dir'])
        before = (original / 'sdk.go').read_bytes()
        for target in (str(original), 'discordgo-generations/' + '0' * 64):
            with self.subTest(target=target):
                self.target.unlink()
                self.target.symlink_to(target)
                with self.assertRaisesRegex(RuntimeError, 'Unsafe prepared SDK alias|does not match its address'):
                    self.resolve(prepare=False)
        self.assertEqual((original / 'sdk.go').read_bytes(), before)

    def test_prepared_symlinks_are_rejected(self):
        self.resolve()
        (self.target / 'linked.go').symlink_to(self.cache_dir / 'sdk.go')
        with self.assertRaisesRegex(RuntimeError, 'Unsafe SDK source entry'):
            self.resolve(prepare=False)

    def test_symlink_and_misnamed_patch_inputs_are_rejected(self):
        path = self.patch_dir / '0001-value.patch'
        content = path.read_bytes()
        path.unlink()
        original = self.root / 'external.patch'
        original.write_bytes(content)
        path.symlink_to(original)
        with self.assertRaisesRegex(RuntimeError, 'Invalid SDK patch file'):
            self.resolve()
        path.unlink()
        (self.patch_dir / 'unordered.patch').write_bytes(content)
        with self.assertRaisesRegex(RuntimeError, 'Invalid SDK patch entry'):
            self.resolve()


class ReadonlyToolchainTests(unittest.TestCase):
    def test_implicit_toolchain_selection_neutralizes_goroot_without_probe_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'tools').mkdir()
            (root / 'tools/versions.mk').write_text('GO_TOOLCHAIN := go1.27.3\n')
            binary = root / '.tools/go/bin/go'
            binary.parent.mkdir(parents=True)
            binary.write_text(
                '#!/bin/sh\n'
                'test "$GOTOOLCHAIN" = local || exit 91\n'
                'test "${GOROOT+x}" != x || exit 92\n'
                'test "$GOWORK" = off || exit 93\n'
                'test -z "$GOFLAGS" || exit 94\n'
                'test "$1 $2" = "env GOVERSION" || exit 95\n'
                'test "$TEST_TELEMETRY_DIR" = /dev/null || exit 96\n'
                'printf "go1.27.3\\n"\n')
            binary.chmod(0o755)
            before = {str(path.relative_to(root)): path.stat().st_mtime_ns for path in root.rglob('*')}
            with mock.patch.object(sdk, 'ROOT', root), \
                    mock.patch.dict(os.environ, {'BOOTSTRAP_GO': '', 'GOROOT': '/wrong/compiler'}), \
                    mock.patch.object(Path, 'mkdir', side_effect=AssertionError('readonly mkdir')), \
                    mock.patch.object(sdk.tempfile, 'mkstemp', side_effect=AssertionError('readonly probe')):
                selected, _ = sdk._go_environment(None, True)
            self.assertEqual(selected, str(binary))
            after = {str(path.relative_to(root)): path.stat().st_mtime_ns for path in root.rglob('*')}
            self.assertEqual(before, after)


if __name__ == '__main__':
    unittest.main()
