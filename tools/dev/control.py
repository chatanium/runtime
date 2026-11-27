#!/usr/bin/env python3
"""Bounded same-UID Unix HTTP client, also runnable under a runtime account."""
import argparse
import fcntl
import http.client
import json
import os
from pathlib import Path
import socket
import stat
import struct
import sys

MAX_JSON = 2 << 20
MAX_LOCK_JSON = 16 << 10


class ControlError(Exception):
    pass


def private_directory(path):
    if not path.is_absolute() or '..' in path.parts:
        raise ControlError('canonical control directory required')
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        if current.is_symlink():
            raise ControlError('control symlink traversal refused')
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_gid != os.getegid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ControlError('control directory must be runtime UID/GID-owned mode 0700')


class UnixHTTP(http.client.HTTPConnection):
    def __init__(self, path, timeout):
        super().__init__('localhost', timeout=timeout)
        self.path = path

    def connect(self):
        private_directory(self.path.parent)
        info = self.path.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600:
            raise ControlError('unsafe development control socket')
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(str(self.path))
        _, uid, _ = struct.unpack('3i', self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid != os.geteuid():
            self.close()
            raise ControlError('development control peer UID differs')


def request(path, timeout, method, route, payload=None):
    connection = UnixHTTP(path, timeout)
    try:
        body = json.dumps(payload).encode() if payload is not None else None
        connection.request(method, route, body, {'Content-Type': 'application/json'} if body else {})
        response = connection.getresponse()
        raw = response.read(MAX_JSON + 1)
        if len(raw) > MAX_JSON or response.status != 200:
            raise ControlError('development control request rejected')
        return json.loads(raw)
    except (OSError, ValueError, http.client.HTTPException):
        raise ControlError('development control connection or response failed') from None
    finally:
        connection.close()


def coordination_metadata(raw):
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_LOCK_JSON:
        raise ControlError('invalid coordination metadata bound')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ControlError('duplicate coordination metadata')
            result[key] = value
        return result
    try:
        data = json.loads(raw.decode('utf-8'), object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError):
        raise ControlError('invalid coordination metadata JSON') from None
    keys = {'version', 'path', 'device', 'inode', 'uid', 'gid', 'mode'}
    if not isinstance(data, dict) or set(data) != keys:
        raise ControlError('invalid coordination metadata fields')
    for name in keys - {'path'}:
        if type(data[name]) is not int or not 0 <= data[name] < 1 << 64:
            raise ControlError('invalid coordination metadata integer')
    if (data['version'] != 1 or data['uid'] != 0 or
            not 0 < data['gid'] < 1 << 32 or not data['inode'] or data['mode'] != 0o440):
        raise ControlError('invalid coordination metadata identity')
    value = data['path']
    if not isinstance(value, str):
        raise ControlError('invalid coordination metadata path')
    path = Path(value)
    if (not path.is_absolute() or str(path) != value or value.startswith('//') or
            '..' in path.parts or path.name != 'dev-watch.lock' or
            any(ord(char) < 32 for char in value)):
        raise ControlError('noncanonical coordination metadata path')
    return data


def coordination_file(data):
    path = Path(data['path'])
    for parent in reversed(path.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ControlError('coordination lock requires protected root-owned ancestry')
    info = path.lstat()
    expected = (data['device'], data['inode'], data['uid'], data['gid'], data['mode'])
    actual = (info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode))
    if (not stat.S_ISREG(info.st_mode) or actual != expected or
            info.st_gid != os.getegid() or info.st_nlink != 1 or info.st_size != 0):
        raise ControlError('unsafe installed metadata coordination lock')
    return info


def hold_coordination_lock(data):
    before = coordination_file(data)
    fd = os.open(data['path'], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ControlError('coordination lock changed while opening')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        # Purge may have won after open but before flock. Never authorize an
        # orphaned inode even though its old descriptor accepted the lock.
        current = coordination_file(data)
        if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
            raise ControlError('coordination lock changed while acquiring')
        print('READY', flush=True)
        sys.stdin.buffer.read(1)
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket')
    parser.add_argument('--timeout', type=float, default=60)
    parser.add_argument('operation', choices=['directory', 'available', 'lock', 'modules', 'reload'])
    args = parser.parse_args()
    if args.operation == 'lock':
        if args.socket:
            raise ControlError('coordination lock does not accept a native socket path')
        raw = sys.stdin.buffer.readline(MAX_LOCK_JSON + 1)
        if not raw.endswith(b'\n'):
            raise ControlError('coordination metadata framing required')
        hold_coordination_lock(coordination_metadata(raw))
        return
    if not args.socket:
        raise ControlError('native control operation requires a socket')
    path = Path(args.socket)
    private_directory(path.parent)
    if args.operation == 'directory':
        return
    if args.operation == 'available':
        if path.exists() or path.is_symlink():
            raise ControlError('development control socket already exists')
        return
    if args.operation == 'modules':
        result = request(path, args.timeout, 'GET', '/v1/modules')
    else:
        raw = sys.stdin.buffer.read(MAX_JSON + 1)
        if len(raw) > MAX_JSON:
            raise ControlError('oversized development request')
        result = request(path, args.timeout, 'POST', '/v1/modules/reload', json.loads(raw))
    sys.stdout.write(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except (ControlError, OSError, ValueError):
        # No raw peer/config/process errors cross privilege boundaries.
        print('development control operation failed', file=sys.stderr)
        sys.exit(1)
