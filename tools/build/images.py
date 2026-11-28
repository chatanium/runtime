#!/usr/bin/env python3
"""Build OCI images from selected executables and their canonical manifests."""
import fcntl
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

root = Path(__file__).resolve().parents[2]
os.chdir(root)
sys.path.insert(0, str(root / 'tools'))
from buildlib.artifacts import capture, digest, inventory, run, write_json
from sdk import resolve as resolve_sdk
if not str(root).startswith('/home/'):
    raise RuntimeError('Image build workspace must be on /home, never /tmp or Docker build layers')
work = root / '.tools/images'
work.mkdir(parents=True, exist_ok=True)
lockfile = (work / 'build.lock').open('w')
fcntl.flock(lockfile, fcntl.LOCK_EX)
go = os.environ['GO_BINARY']
arch = os.environ.get('GOARCH', 'amd64')
if arch not in ('amd64', 'arm64'):
    raise RuntimeError('Module images support Linux amd64/arm64 only')
host_os, host_arch = capture(go, 'env', 'GOHOSTOS', 'GOHOSTARCH').splitlines()
parser_env = dict(os.environ, GOOS=host_os, GOARCH=host_arch, CGO_ENABLED='0')
# Direct Python entrypoints enforce preparation too, before any compilation
# (including the manifest parser) or image construction.
sdk_modules = list(dict.fromkeys([root, root / os.environ['MODULE_GO_DIRECTORY']]))
for module in sdk_modules:
    resolve_sdk(go, module)
# A concurrent preparer cannot replace the go.mod alias while Go compiles the
# parser or while image artifacts/evidence are being assembled.
sdk_lease = (root / '.tools/deps/discordgo.lock').open('rb')
fcntl.flock(sdk_lease, fcntl.LOCK_SH)
for module in sdk_modules:
    resolve_sdk(go, module, prepare=False)
label_key = 'org.chatanium.flexmodule.manifest.v2'
resource_label = 'org.chatanium.flexmodule.resources.v2'
dockerfile = 'tools/build/Module.Dockerfile'
portable_module_sources = {'examples/general-bot', 'tests/integration/legacy/fixtures/sandbox'}


def build_image(module_dir, binary, image):
    if not image or '@' in image or any(c.isspace() for c in image):
        raise RuntimeError('Explicit writable OCI tag required')
    manifest = root / module_dir / 'manifest.json'
    build_info = capture(go, 'version', '-m', root / binary).splitlines()
    settings = {line.strip().removeprefix('build\t') for line in build_info if line.startswith('\tbuild\t')}
    if not {'CGO_ENABLED=0', 'GOOS=linux', 'GOARCH=' + arch}.issubset(settings):
        raise RuntimeError('Selected module executable does not match the requested Linux guest target')
    # Execute the actual generated strict protobuf parser; retain original bytes.
    with open(os.devnull, 'w') as discard:
        run(go, 'run', '-mod=readonly', './tools/build/manifest', manifest, stdout=discard, env=parser_env)
    declaration = manifest.read_bytes().decode('utf-8')
    resources = 'portable-v2' if module_dir in portable_module_sources else None
    with tempfile.TemporaryDirectory(prefix='context-', dir=work) as directory:
        context = Path(directory)
        shutil.copy2(root / binary, context / 'module')
        shutil.copy2(manifest, context / 'manifest.json')
        shutil.copy2(root / dockerfile, context / 'Dockerfile')
        args = ['docker', 'build', '--platform', 'linux/' + arch, '--network=none', '--iidfile', context / 'image-id',
                '--label', label_key + '=' + declaration,
                '--label', 'org.chatanium.flexmodule.manifest.sha256=' + digest(manifest)]
        if resources:
            args += ['--label', resource_label + '=' + resources]
        run(*args, context)
        image_id = (context / 'image-id').read_text().strip()
        metadata = json.loads(capture('docker', 'image', 'inspect', image_id))[0]
        if (metadata['Os'], metadata['Architecture']) != ('linux', arch):
            raise RuntimeError('Built OCI image does not match the requested Linux guest target')
        labels = metadata['Config']['Labels']
        if labels.get(label_key) != declaration or labels.get(resource_label) != resources:
            raise RuntimeError('OCI resource format or manifest label differs from the build inputs')
        evidence = {'image_tag': image, 'local_image_id': image_id, 'registry_digest': None,
                    'registry_digest_note': 'Publish to a registry, then use its real RepoDigest for installation.',
                    'manifest_source': str(manifest.relative_to(root)), 'manifest_sha256': digest(manifest),
                    'executable_sha256': digest(root / binary),
                    'platform': 'linux/' + arch, 'build_context_sha256': inventory(context)}
        if resources:
            evidence['resource_format'] = resources
        return work / module_dir / 'image.json', evidence


def publish_images(results):
    # Build every image first. Roll back public tags/evidence if publication
    # fails; unrelated images are never pruned or overwritten.
    previous = []
    try:
        for output, evidence in results:
            image = evidence['image_tag']
            output.parent.mkdir(parents=True, exist_ok=True)
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


base = json.loads((root / 'tools/native/native-lock.json').read_text())['builder_base']
if f'FROM --platform=linux/amd64 {base} AS trust' not in (root / dockerfile).read_text().splitlines():
    raise RuntimeError('Module trust source must match tools/native/native-lock.json builder_base')
publish_images([build_image(os.environ['MODULE_DIRECTORY'], os.environ['MODULE_BINARY'], os.environ['MODULE_IMAGE'])])
