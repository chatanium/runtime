import json
import os
from pathlib import Path
import socketserver
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch
from http.server import BaseHTTPRequestHandler

import control
import watch

IMAGE = 'registry.example/test/module@sha256:' + 'a' * 64


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({'modules': [{'module_id': 'installed', 'instance_id': 'old',
                                       'image': IMAGE, 'committed_image': IMAGE, 'state': 'RUNNING', 'reloading': False,
                                       'cleanup_complete': False}]}).encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        self.server.requests.append(request)
        body = json.dumps({'module_id': request['module_id'], 'instance_id': 'new',
                           'image': request['image'], 'committed_image': request['image'], 'state': 'RUNNING',
                           'reloading': False, 'cleanup_complete': False}).encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class ControlTests(unittest.TestCase):
    def test_actual_unix_http_uses_optimistic_identity_and_real_image(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'control.sock'
            with socketserver.UnixStreamServer(str(path), Handler) as server:
                path.chmod(0o600)
                server.requests = []
                thread = threading.Thread(target=server.serve_forever)
                thread.start()
                try:
                    client = watch.Client(path, 2)
                    self.assertEqual(client.modules()['installed']['instance_id'], 'old')
                    result = client.reload('installed', 'old', IMAGE)
                    self.assertEqual(result['instance_id'], 'new')
                    self.assertEqual(server.requests, [{'module_id': 'installed',
                                                       'expected_instance_id': 'old', 'image': IMAGE}])
                finally:
                    server.shutdown()
                    thread.join()

    def test_refuses_existing_socket_path_without_unlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'control.sock'
            path.write_bytes(b'operator-owned-content')
            with patch('sys.argv', ['control.py', '--socket', str(path), 'available']):
                with self.assertRaises(control.ControlError):
                    control.main()
            self.assertEqual(path.read_bytes(), b'operator-owned-content')

    def test_session_lock_is_private_and_duplicate_lock_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'control.sock'
            lock = path.parent / (path.name + '.watch.lock')
            fd = os.open(lock, os.O_CREAT | os.O_RDWR, 0o600)
            try:
                control.fcntl.flock(fd, control.fcntl.LOCK_EX | control.fcntl.LOCK_NB)
                with patch('sys.argv', ['control.py', '--socket', str(path), 'lock']):
                    with self.assertRaises(BlockingIOError):
                        control.main()
            finally:
                os.close(fd)
            self.assertFalse(path.exists())

    def test_protocol_errors_never_dump_peer_details(self):
        connection = Mock()
        connection.getresponse.side_effect = OSError('SECRET_FROM_PEER')
        with patch.object(control, 'UnixHTTP', return_value=connection):
            with self.assertRaises(control.ControlError) as raised:
                control.request(Path('/private/control.sock'), 1, 'GET', '/v1/modules')
        self.assertNotIn('SECRET_FROM_PEER', str(raised.exception))
        connection.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
