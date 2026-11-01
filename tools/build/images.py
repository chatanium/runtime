#!/usr/bin/env python3
"""Build OCI images from allowlisted executables and their canonical manifests."""
import fcntl
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

from artifacts import capture, digest, inventory, run, write_json

root = Path(__file__).resolve().parents[2]
os.chdir(root)
sys.path.insert(0, str(root / 'tools'))
from sdk import resolve as resolve_sdk
if not str(root).startswith('/home/'):
    raise RuntimeError('Image build workspace must be on /home, never /tmp or Docker build layers')
work = root / '.tools/images'
work.mkdir(parents=True, exist_ok=True)
lockfile = (work / 'build.lock').open('w')
fcntl.flock(lockfile, fcntl.LOCK_EX)
mode = sys.argv[1]
go = os.environ['GO_BINARY']
# Direct Python entrypoints enforce preparation too, before any compilation
# (including the manifest parser) or image construction.
sdk_modules = [root]
if mode == 'media':
    sdk_modules += [root / 'modules/music-bot', root / 'modules/audio-player']
for module in sdk_modules:
    resolve_sdk(go, module)
# A concurrent preparer cannot replace the go.mod alias while Go compiles the
# parser or while image artifacts/evidence are being assembled.
sdk_lease = (root / '.tools/deps/discordgo.lock').open('rb')
fcntl.flock(sdk_lease, fcntl.LOCK_SH)
for module in sdk_modules:
    resolve_sdk(go, module, prepare=False)
label_key = 'org.chatanium.flexmodule.manifest.v2'


def build_image(module_dir, binary, image, dockerfile, base=None):
    if not image or '@' in image or any(c.isspace() for c in image):
        raise RuntimeError('Explicit writable OCI tag required')
    manifest = root / module_dir / 'manifest.json'
    # Execute the actual generated strict protobuf parser; retain original bytes.
    with open(os.devnull, 'w') as discard:
        run(go, 'run', '-mod=readonly', './tools/build/manifest', manifest, stdout=discard)
    declaration = manifest.read_bytes().decode('utf-8')
    with tempfile.TemporaryDirectory(prefix='context-', dir=work) as directory:
        context = Path(directory)
        shutil.copy2(root / binary, context / 'module')
        shutil.copy2(manifest, context / 'manifest.json')
        shutil.copy2(root / dockerfile, context / 'Dockerfile')
        args = ['docker', 'build', '--platform', 'linux/amd64', '--network=none', '--iidfile', context / 'image-id',
                '--label', label_key + '=' + declaration,
                '--label', 'org.chatanium.flexmodule.manifest.sha256=' + digest(manifest)]
        if base:
            args += ['--build-arg', 'MEDIA_BASE=' + base]
        run(*args, context)
        image_id = (context / 'image-id').read_text().strip()
        metadata = json.loads(capture('docker', 'image', 'inspect', image_id))[0]
        if metadata['Config']['Labels'].get(label_key) != declaration:
            raise RuntimeError('OCI manifest label differs from canonical embedded source')
        evidence = {'image_tag': image, 'local_image_id': image_id, 'registry_digest': None,
                    'registry_digest_note': 'Publish to a registry, then use its real RepoDigest for installation.',
                    'manifest_source': str(manifest.relative_to(root)), 'manifest_sha256': digest(manifest),
                    'executable_sha256': digest(root / binary), 'media_base_local_tag': base,
                    'build_context_sha256': inventory(context)}
        return work / (Path(binary).name + '-image.json'), evidence


def publish_images(results):
    # Build every image first. Roll back public tags/evidence if publication
    # fails; unrelated images are never pruned or overwritten.
    previous = []
    try:
        for output, evidence in results:
            image = evidence['image_tag']
            old_ids = capture('docker', 'image', 'ls', '--no-trunc', '--quiet', image).splitlines()
            old = old_ids[0] if old_ids else None
            previous.append((image, old, output, output.read_bytes() if output.exists() else None))
            temporary = output.with_suffix('.json.partial')
            write_json(temporary, evidence)
            run('docker', 'image', 'tag', evidence['local_image_id'], image)
            os.replace(temporary, output)
    except BaseException:
        for image, old, output, data in reversed(previous):
            if old:
                run('docker', 'image', 'tag', old, image)
            else:
                run('docker', 'image', 'rm', '--no-prune', image)
            if data is None:
                output.unlink(missing_ok=True)
            else:
                output.write_bytes(data)
        raise
    for _, evidence in results:
        print(json.dumps(evidence, indent=2))


if mode == 'module':
    base = json.loads((root / 'tools/native/native-lock.json').read_text())['builder_base']
    if f'FROM {base} AS trust' not in (root / 'tools/build/Module.Dockerfile').read_text().splitlines():
        raise RuntimeError('Module trust source must match tools/native/native-lock.json builder_base')
    kind = os.environ.get('MODULE_KIND', 'general')
    choices = {'general': ('examples/general-bot', 'bin/test-module'),
               'sandbox': ('tests/integration/fixtures/sandbox', 'bin/sandbox-module')}
    if kind not in choices:
        raise RuntimeError('MODULE_KIND must be general or sandbox')
    directory, binary = choices[kind]
    publish_images([build_image(directory, binary, os.environ['MODULE_IMAGE'], 'tools/build/Module.Dockerfile')])
elif mode == 'media':
    jobs = os.environ.get('BUILD_JOBS', '2')
    if not jobs.isdecimal() or int(jobs) < 1:
        raise RuntimeError('BUILD_JOBS must be positive')
    workspace = root / '.tools/media'
    workspace.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='builder-', dir=work) as directory:
        iid = Path(directory) / 'image-id'
        run('docker', 'build', '--platform', 'linux/amd64', '--iidfile', iid,
            '-f', 'tools/media/Builder.Dockerfile', 'tools/media')
        builder = iid.read_text().strip()
        run('docker', 'run', '--rm', '--init', '--user', f'{os.getuid()}:{os.getgid()}',
            '--mount', f'type=bind,src={root},dst=/source,readonly',
            '--mount', f'type=bind,src={workspace},dst=/work',
            '-e', 'BUILD_JOBS=' + jobs, '-e', 'TMPDIR=/work/tmp',
            builder, 'python3', '/source/tools/media/build.py')
        stage = workspace / 'stage'
        shutil.copy2(root / 'tools/media/Tools.Dockerfile', stage / 'Dockerfile')
        tools_id = Path(directory) / 'tools-id'
        # This tag names a real local build result, not an invented registry digest.
        base = 'flexmodule/media-tools:sha256-' + digest(stage / 'rootfs/opt/flexmodule/provenance/files-sha256.json')
        (stage / 'rootfs/opt/flexmodule/provenance/builder-image-id.txt').write_text(builder + '\n')
        run('docker', 'build', '--platform', 'linux/amd64', '--network=none', '--iidfile', tools_id, '-t', base, stage)
        results = [
            build_image('modules/music-bot', 'bin/chatanium-musicbot', os.environ['MUSIC_IMAGE'], 'tools/media/Module.Dockerfile', base),
            build_image('modules/audio-player', 'bin/voice-player-module', os.environ['PLAYER_IMAGE'], 'tools/media/Module.Dockerfile', base),
        ]
        publish_images(results)
else:
    raise RuntimeError('Expected module or media image build')
