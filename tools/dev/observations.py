"""Bounded per-generation stdout draining and explicit development stop receipts."""
import json
import os
import re
import select
import sys
import threading

MAX_OBSERVATION = 2 << 20
IMAGE = re.compile(r'^([a-z0-9][a-z0-9._:/-]*)@sha256:[0-9a-f]{64}$')


class ObservationError(Exception):
    pass


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate field')
        result[key] = value
    return result


def stop_receipt(raw, repositories):
    try:
        value = json.loads(raw, object_pairs_hook=unique_object)
        if not isinstance(value, dict) or value.get('phase') != 'DEVELOPMENT_STOPPED':
            return None
        if set(value) != {'phase', 'modules', 'voice', 'development_stop'}:
            raise ValueError()
        if type(value['modules']) is not int or value['modules'] != len(repositories) or type(value['voice']) is not bool:
            raise ValueError()
        stop = value['development_stop']
        if not isinstance(stop, dict) or set(stop) != {'cleanup_complete', 'committed_images'} or stop['cleanup_complete'] is not True:
            raise ValueError()
        images = stop['committed_images']
        if not isinstance(images, dict):
            raise ValueError()
        for module_id, image in images.items():
            match = IMAGE.fullmatch(image) if isinstance(image, str) else None
            if module_id not in repositories or not match or match[1] != repositories[module_id]:
                raise ValueError()
        return images
    except (ValueError, TypeError, UnicodeError):
        return None


class RuntimeObservations:
    def __init__(self, stream, repositories, output=None):
        self.stream = stream
        self.repositories = dict(repositories)
        self.output = sys.stdout.buffer if output is None else output
        self.receipt = None
        self.failed = False
        self.cancelled = threading.Event()
        self.thread = threading.Thread(target=self.read, name='development-runtime-observations')
        os.set_blocking(stream.fileno(), False)
        self.thread.start()

    def observe(self, line):
        if not line.strip():
            return
        # The cleanup receipt must be the final nonempty stdout observation.
        self.receipt = stop_receipt(line, self.repositories)

    def read(self):
        pending = bytearray()
        oversized = False
        try:
            while not self.cancelled.is_set():
                ready, _, _ = select.select([self.stream], [], [], .2)
                if not ready:
                    continue
                try:
                    chunk = os.read(self.stream.fileno(), 4096)
                except BlockingIOError:
                    continue
                if not chunk:
                    if pending and not oversized:
                        self.observe(bytes(pending))
                    return
                if self.output is not None:
                    try:
                        self.output.write(chunk)
                        self.output.flush()
                    except (OSError, ValueError):
                        self.failed = True
                        self.output = None
                for part in chunk.splitlines(keepends=True):
                    ended = part.endswith(b'\n')
                    if not oversized:
                        if len(pending) + len(part) > MAX_OBSERVATION:
                            pending.clear()
                            oversized = True
                            self.receipt = None
                        else:
                            pending.extend(part)
                    if ended:
                        if not oversized:
                            self.observe(bytes(pending))
                        pending.clear()
                        oversized = False
        except (OSError, ValueError):
            self.failed = True
        finally:
            self.stream.close()

    def finish(self):
        # The process has exited. A retained writer must not leave a reader
        # goroutine/thread alive or be mistaken for a completed generation.
        self.thread.join(timeout=2)
        if self.thread.is_alive():
            self.failed = True
            self.cancelled.set()
            self.thread.join()
        if self.failed:
            raise ObservationError('runtime stdout ownership or forwarding failed')
        return self.receipt
