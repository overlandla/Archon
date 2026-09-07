import unittest
from uuid import uuid4

from .progress import Binding, Reporter


class ProgressTests(unittest.TestCase):
    def setUp(self):
        self.binding = Binding(1000, 42, str(uuid4()), str(uuid4()), str(uuid4()), "source-correlation", str(uuid4()))
        self.calls = []
        self.reporter = Reporter(self.binding, self.request, lambda: None)

    def request(self, method, path, body):
        self.calls.append((method, path, body))
        return {"created": True, "report": {**body, "id": str(uuid4()), "project_id": 1000,
                "task_id": 42, "graph_revision_id": self.binding.graph_revision_id}}

    def test_progress_binds_source_scope_unit_and_stable_submission(self):
        request = {"progress": "complete"}
        receipt = self.reporter.report("one", request)
        self.reporter.validate_receipt("one", request, receipt)
        self.assertEqual(self.calls[0][1], "/api/projects/1000/tasks/42/implementation-reports")
        self.assertEqual(receipt["submission_id"], self.binding.submission("one"))
        self.assertNotEqual(receipt["submission_id"], self.binding.submission("two"))
        self.assertEqual(set(self.calls[0][2]), {"scope_revision_id", "work_unit_id", "submission_id", "correlation_id", "progress", "code_artifacts", "diagnostics"})
        with self.assertRaises(RuntimeError):
            self.reporter.validate_receipt("two", request, receipt)

    def test_unknown_progress_or_worker_routing_never_writes(self):
        for request in ({"progress": "verified"}, {"progress": "complete", "task_id": 999},
                        {"progress": "complete", "code_artifacts": [{"revision": "untrusted"}]}):
            with self.assertRaises(ValueError):
                self.reporter.report("one", request)
        self.assertEqual(self.calls, [])

    def test_foreign_receipts_fail(self):
        original = self.reporter.request
        for field, value in (("task_id", 99), ("project_id", 1), ("scope_revision_id", str(uuid4())),
                             ("work_unit_id", str(uuid4())), ("submission_id", "other"), ("progress", "blocked")):
            def changed(method, path, body):
                response = original(method, path, body)
                response["report"][field] = value
                return response
            self.reporter.request = changed
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                self.reporter.report("one", {"progress": "complete"})
