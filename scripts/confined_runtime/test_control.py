import http.client
import json
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .admission import Release, Supervisor
from .control import Server
from .journal import Journal


class ControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.release = Release("fixture", *("a" * 64 for _ in range(7)))
        self.calls = []
        calls = self.calls
        release = self.release
        class Policy:
            def capture(self, run_id, selection):
                calls.append("capture")
                return release.closure_revision
            def validate_authority(self, run_id, selection):
                calls.append("authority")
            def refresh_and_create_worktree(self, run_id, selection):
                calls.append("repository")
            def invoke(self, run_id, selection):
                calls.append("invoke")
                return "completed"
        self.journal = Journal(Path(self.temp.name) / "journal.sqlite")
        self.supervisor = Supervisor(self.journal, self.release, Policy())
        self.server = Server(0, self.supervisor, "https://source.invalid", 1000, "synthetic-private-key-" * 3)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop)
        self.selection = {"release": self.release.selection(), "source": self.server.source}

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)

    def request(self, path, value, authorized=True, read=True):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        headers = {"Content-Type": "application/json"}
        if authorized:
            headers["Authorization"] = "Bearer " + "synthetic-private-key-" * 3
        try:
            connection.request("POST", path, json.dumps(value), headers)
            if not read:
                return None
            response = connection.getresponse()
            return response.status, json.loads(response.read())
        finally:
            connection.close()

    def wait_finished(self, correlation):
        for _ in range(100):
            _, value = self.request("/v1/lookup", {"source": self.server.source, "correlation_id": correlation})
            if value["runs"] and value["runs"][0]["state"] == "finished":
                return value["runs"][0]
            time.sleep(.02)
        self.fail("controlled queue did not finish")

    def test_lost_http_ack_and_concurrent_replay_invoke_once(self):
        body = {"source": self.server.source, "correlation_id": "correlation", "selection": self.selection}
        self.request("/v1/admissions", body, read=False)
        with ThreadPoolExecutor(max_workers=4) as pool:
            responses = list(pool.map(lambda _: self.request("/v1/admissions", body), range(4)))
        record = self.wait_finished("correlation")
        self.assertEqual({response[1]["run_id"] for response in responses}, {record["run_id"]})
        self.assertEqual(self.calls, ["capture", "authority", "repository", "invoke"])
        self.assertEqual(record["execution"]["engine"], {"outcome": "completed"})
        self.assertEqual(record["effects"], [])
        self.assertEqual(self.request("/v1/admissions", dict(body, selection={**self.selection, "changed": True}))[0], 409)

    def test_unknown_release_is_inspectably_rejected_and_foreign_source_cannot_launch(self):
        body = {"source": self.server.source, "correlation_id": "unsupported", "selection": {**self.selection, "release": {}}}
        _, record = self.request("/v1/admissions", body)
        self.assertEqual(record["state"], "rejected")
        self.assertEqual(record["diagnostic"], "unsupported")
        self.assertEqual(self.request("/v1/admissions", body, authorized=False)[0], 401)
        self.assertEqual(self.request("/v1/admissions", dict(body, source={"deployment": "https://foreign.invalid", "project": 1000}))[0], 400)
        self.assertEqual(self.calls, [])
