import io
import json
import os
import unittest

from observations import MAX_OBSERVATION, RuntimeObservations, stop_receipt

OLD = 'registry.example/team/module@sha256:' + '1' * 64
NEW = 'registry.example/team/module@sha256:' + '2' * 64
REPOSITORIES = {'approved': 'registry.example/team/module'}


def receipt(image=NEW):
    return {'phase': 'DEVELOPMENT_STOPPED', 'modules': 1, 'voice': False,
            'development_stop': {'cleanup_complete': True, 'committed_images': {'approved': image}}}


class ObservationTests(unittest.TestCase):
    def drain(self, chunks):
        reader_fd, writer_fd = os.pipe()
        output = io.BytesIO()
        reader = RuntimeObservations(os.fdopen(reader_fd, 'rb'), REPOSITORIES, output=output)
        try:
            for chunk in chunks:
                view = memoryview(chunk)
                while view:
                    count = os.write(writer_fd, view)
                    view = view[count:]
        finally:
            os.close(writer_fd)
        result = reader.finish()
        self.assertFalse(reader.thread.is_alive())
        return result, output.getvalue()

    def test_fragmented_receipt_and_existing_observations_are_drained_and_forwarded(self):
        raw = json.dumps(receipt()).encode() + b'\n'
        visible = b'{"phase":"STOPPING","modules":1,"voice":false}\n'
        result, forwarded = self.drain([visible, raw[:17], raw[17:]])
        self.assertEqual(result, {'approved': NEW})
        self.assertEqual(forwarded, visible + raw)

    def test_invalid_or_wrong_generation_identity_receipt_is_rejected(self):
        values = []
        missing_cleanup = receipt()
        missing_cleanup['development_stop']['cleanup_complete'] = False
        values.append(missing_cleanup)
        wrong_repository = receipt('other.example/module@sha256:' + '3' * 64)
        values.append(wrong_repository)
        unknown_module = receipt()
        unknown_module['development_stop']['committed_images'] = {'uninstalled': NEW}
        values.append(unknown_module)
        wrong_count = receipt()
        wrong_count['modules'] = 2
        values.append(wrong_count)
        wrong_type = receipt()
        wrong_type['modules'] = True
        values.append(wrong_type)
        for value in values:
            with self.subTest(value=value):
                self.assertIsNone(stop_receipt(json.dumps(value).encode(), REPOSITORIES))

    def test_duplicate_fields_and_nonfinal_receipts_are_rejected(self):
        raw = json.dumps(receipt()).encode()
        duplicate = raw.replace(b'"cleanup_complete": true', b'"cleanup_complete": true, "cleanup_complete": true')
        self.assertIsNone(stop_receipt(duplicate, REPOSITORIES))
        result, _ = self.drain([raw + b'\n', b'{"phase":"UNEXPECTED_AFTER_STOP"}\n'])
        self.assertIsNone(result)

    def test_oversized_lines_do_not_hide_a_later_bounded_receipt(self):
        oversized = b'x' * (MAX_OBSERVATION + 4096) + b'\n'
        raw = json.dumps(receipt()).encode() + b'\n'
        result, forwarded = self.drain([oversized, raw])
        self.assertEqual(result, {'approved': NEW})
        self.assertEqual(len(forwarded), len(oversized) + len(raw))

    def test_receipts_cannot_carry_between_runtime_generations(self):
        raw = json.dumps(receipt()).encode() + b'\n'
        first, _ = self.drain([raw])
        second, _ = self.drain([b'{"phase":"STOPPING"}\n'])
        self.assertEqual(first, {'approved': NEW})
        self.assertIsNone(second)

    def test_empty_committed_set_is_valid_when_no_module_ever_started(self):
        value = receipt()
        value['development_stop']['committed_images'] = {}
        self.assertEqual(stop_receipt(json.dumps(value).encode(), REPOSITORIES), {})


if __name__ == '__main__':
    unittest.main()
