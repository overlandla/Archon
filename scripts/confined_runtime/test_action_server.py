import http.client
import socket
import threading
import unittest
from pathlib import Path

from . import test_actions
from .action_server import Server
from .https_transport import parse_json
from .journal import canonical


class ActionServerTests(unittest.TestCase):
    def setUp(self):
        fixture = test_actions.ActionTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.temp, self.actions, self.calls = fixture.temp, fixture.actions, fixture.calls
        self.socket = Path(self.temp.name) / "actions.sock"
        self.server = Server(self.socket, self.actions)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)

    def stop_server(self):
        self.server.seal_and_drain()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)

    def post(self, path, body):
        connection = http.client.HTTPConnection("localhost", timeout=2)
        connection.sock = socket.socket(socket.AF_UNIX)
        connection.sock.settimeout(2)
        connection.sock.connect(str(self.socket))
        try:
            connection.request("POST", path, body, {"Content-Type": "application/json"})
            response = connection.getresponse()
            return response.status, parse_json(response.read())
        finally:
            connection.close()

    def test_raw_socket_cannot_bypass_typed_actions_or_spoof_completion(self):
        for path in ("/merge", "/deploy", "/worker-result", "/actions?kind=publish"):
            status, _ = self.post(path, b'{}')
            self.assertEqual(status, 403)
        status, _ = self.post("/actions", b'{"kind":"progress","kind":"publish"}')
        self.assertEqual(status, 403)
        self.assertEqual(self.calls, [])

    def test_typed_progress_roundtrip_and_replay(self):
        body = canonical({"kind": "progress", "operation_id": "one", "request": {"progress": "blocked"}})
        self.assertEqual(self.post("/actions", body), (200, {"receipt": "trusted-project-task-scope-unit"}))
        self.assertEqual(self.post("/actions", body), (200, {"receipt": "trusted-project-task-scope-unit"}))
        self.assertEqual(self.calls, [("progress", "one")])

    def test_conflicting_lengths_and_chunked_requests_are_denied(self):
        for headers in (b"Content-Length: 2\r\nContent-Length: 3\r\n", b"Transfer-Encoding: chunked\r\n"):
            with socket.socket(socket.AF_UNIX) as client:
                client.settimeout(2)
                client.connect(str(self.socket))
                client.sendall(b"POST /actions HTTP/1.0\r\nContent-Type: application/json\r\n" + headers + b"\r\n{}")
                self.assertIn(b"403", client.recv(1024).split(b"\r\n")[0])
        self.assertEqual(self.calls, [])
