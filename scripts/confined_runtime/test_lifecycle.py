import json
import socket
import tempfile
import unittest
from pathlib import Path
from uuid import uuid4

from .lifecycle import Lifecycle


class LifecycleTests(unittest.TestCase):
    def test_fragmented_result_consumes_one_channel_and_waits_for_eof(self):
        with tempfile.TemporaryDirectory() as directory:
            run = str(uuid4())
            listener = Lifecycle(Path(directory) / "control.sock", run, timeout=2)
            client = socket.socket(socket.AF_UNIX)
            self.addCleanup(client.close)
            try:
                client.connect(str(listener.path))
                self.assertEqual(client.recv(6), b"ready\n")
                value = json.dumps({"run_id": run, "state": "completed"}).encode()
                for byte in value:
                    client.sendall(bytes([byte]))
                with self.assertRaises(RuntimeError):
                    listener.await_outcome(.01)
                with socket.socket(socket.AF_UNIX) as second, self.assertRaises(ConnectionRefusedError):
                    second.connect(str(listener.path))
                client.close()
                self.assertEqual(listener.await_outcome(), "completed")
            finally:
                listener.close()

    def test_missing_foreign_and_malformed_results_are_uncertain(self):
        for content in (b"", b'{"run_id":"foreign","state":"completed"}', b"x" * 4097,
                        b'{"run_id":"foreign","state":[]}'):
            with self.subTest(content=content[:30]), tempfile.TemporaryDirectory() as directory:
                listener = Lifecycle(Path(directory) / "control.sock", str(uuid4()), timeout=2)
                try:
                    with socket.socket(socket.AF_UNIX) as client:
                        client.connect(str(listener.path))
                        self.assertEqual(client.recv(6), b"ready\n")
                        client.sendall(content)
                    with self.assertRaises(RuntimeError):
                        listener.await_outcome()
                finally:
                    listener.close()

    def test_trusted_bootstrap_rejection_keeps_bounded_diagnostic_without_ack(self):
        from .admission import Rejected

        def reject():
            raise Rejected('stale_guidance')

        with tempfile.TemporaryDirectory() as directory:
            listener = Lifecycle(Path(directory) / 'control.sock', str(uuid4()), timeout=2, authorize=reject)
            try:
                with socket.socket(socket.AF_UNIX) as client:
                    client.connect(str(listener.path))
                    self.assertEqual(client.recv(6), b'')
                with self.assertRaisesRegex(RuntimeError, 'engine_outcome_uncertain'):
                    listener.await_outcome()
                self.assertEqual(listener.rejection, 'stale_guidance')
                self.assertIsNone(listener.outcome)
            finally:
                listener.close()
