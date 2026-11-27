"""Pack a static Linux module into a portable-v2 OCI image archive."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile

OCI = 'application/vnd.oci.image.'
ROOTFS_DIRS = (
    'bin', 'dev', 'etc', 'proc', 'sys', 'tmp', 'var', 'var/lib', 'var/lib/flexmodule',
    'var/lib/flexmodule/data', 'var/lib/flexmodule/scratch', 'work',
)


def json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def entry(archive, name, mode, source=None, size=0):
    info = tarfile.TarInfo(name)
    info.mode = mode
    if source is None:
        info.type = tarfile.DIRTYPE
    else:
        info.size = size
    archive.addfile(info, source)


class LayerWriter:
    def __init__(self, compressed):
        self.compressed = compressed
        self.digest = hashlib.sha256()

    def write(self, block):
        self.digest.update(block)
        return self.compressed.write(block)


def pack(arch, program, manifest, output, *, executable='module', include_manifest=True):
    declaration = manifest.read_bytes()
    contents = {}

    def blob(media, hash_value, size, source):
        contents['blobs/sha256/' + hash_value] = (source, size)
        return {'mediaType': OCI + media, 'digest': 'sha256:' + hash_value, 'size': size}

    def json_blob(media, value):
        data = json_bytes(value)
        return blob(media, hashlib.sha256(data).hexdigest(), len(data), io.BytesIO(data))

    with tempfile.TemporaryFile(dir=output.parent) as layer:
        with gzip.GzipFile(fileobj=layer, filename='', mode='wb', mtime=0) as compressed:
            writer = LayerWriter(compressed)
            with tarfile.open(fileobj=writer, mode='w|', format=tarfile.USTAR_FORMAT) as rootfs:
                for name in ROOTFS_DIRS:
                    entry(rootfs, name, 0o1777 if name == 'tmp' else 0o755)
                with program.open('rb') as binary:
                    entry(rootfs, 'bin/' + executable, 0o555, binary, os.fstat(binary.fileno()).st_size)
                if include_manifest:
                    entry(rootfs, 'work/manifest.json', 0o444, io.BytesIO(declaration), len(declaration))
        size = layer.tell()
        layer.seek(0)
        layer_desc = blob('layer.v1.tar+gzip', hashlib.file_digest(layer, 'sha256').hexdigest(), size, layer)
        layer.seek(0)
        config = json_blob('config.v1+json', {
            'architecture': arch,
            'os': 'linux',
            'rootfs': {'type': 'layers', 'diff_ids': ['sha256:' + writer.digest.hexdigest()]},
            'config': {
                'User': '1000:1000',
                'WorkingDir': '/work',
                'Entrypoint': ['/bin/' + executable],
                'Labels': {
                    'org.chatanium.flexmodule.manifest.v2': declaration.decode('utf-8'),
                    'org.chatanium.flexmodule.resources.v2': 'portable-v2',
                },
            },
        })
        image = json_blob('manifest.v1+json', {
            'schemaVersion': 2, 'mediaType': OCI + 'manifest.v1+json', 'config': config, 'layers': [layer_desc],
        })
        image['platform'] = {'architecture': arch, 'os': 'linux'}
        layout = json_bytes({'imageLayoutVersion': '1.0.0'})
        index = json_bytes({'schemaVersion': 2, 'mediaType': OCI + 'index.v1+json', 'manifests': [image]})
        contents['oci-layout'] = (io.BytesIO(layout), len(layout))
        contents['index.json'] = (io.BytesIO(index), len(index))
        with tarfile.open(output, 'x', format=tarfile.USTAR_FORMAT) as archive:
            for name, (source, size) in sorted(contents.items()):
                entry(archive, name, 0o444, source, size)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('arch', choices=['amd64', 'arm64'])
    parser.add_argument('program', type=Path)
    parser.add_argument('manifest', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    try:
        pack(args.arch, args.program, args.manifest, args.output)
    except (OSError, ValueError, tarfile.TarError) as error:
        parser.exit(1, f'{error}\n')
