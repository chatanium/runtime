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
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ControlError('control directory must be runtime-owned mode 0700')


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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket', required=True)
    parser.add_argument('--timeout', type=float, default=60)
    parser.add_argument('operation', choices=['directory', 'available', 'lock', 'modules', 'reload'])
    args = parser.parse_args()
    path = Path(args.socket)
    private_directory(path.parent)
    if args.operation == 'directory':
        return
    if args.operation == 'lock':
        lock = path.parent / (path.name + '.watch.lock')
        fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
                raise ControlError('unsafe development session lock')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if path.exists() or path.is_symlink():
                raise ControlError('development socket already exists')
            print('READY', flush=True)
            # Parent closing this pipe releases the per-socket session lock.
            sys.stdin.buffer.read()
        finally:
            os.close(fd)
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
