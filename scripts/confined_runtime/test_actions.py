import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .actions import ActionDenied, Actions, ActionUncertain
from .exports import validate
from .journal import AdmissionConflict, Journal
from .test_exports import file


class ActionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "journal.sqlite"
        self.journal = Journal(self.path)
        row = self.journal.admit("https://source.invalid", 1000, "correlation", {})
        self.run = row["run_id"]
        self.journal.transition(self.run, 0, "check")
        self.journal.transition(self.run, 1, "invoke")
        self.calls = []
        self.actions = Actions(self.journal, self.run, export=self.export, publish=self.publish, progress=self.progress, validate_receipt=self.validate_receipt)

    def validate_receipt(self, kind, operation_id, request, response):
        expected = {"export": {"export_id": validate(request).digest} if kind == "export" else {},
                    "publish": {"receipt": "trusted-repository-branch-and-draft-pr"},
                    "progress": {"receipt": "trusted-project-task-scope-unit"}}
        if response != expected[kind]:
            raise ActionUncertain("invalid_bound_receipt")

    def export(self, operation_id, request):
        self.calls.append(("export", operation_id))
        return {"export_id": validate(request).digest}

    def publish(self, operation_id, request):
        self.calls.append(("publish", operation_id))
        return {"receipt": "trusted-repository-branch-and-draft-pr"}

    def progress(self, operation_id, request):
        self.calls.append(("progress", operation_id))
        return {"receipt": "trusted-project-task-scope-unit"}

    def retained_export(self):
        request = {"files": [file()], "deletions": []}
        return self.actions.perform({"kind": "export", "operation_id": "output", "request": request})

    def test_publication_is_run_bound_single_and_replay_returns_retained_receipt(self):
        export = self.retained_export()
        command = {"kind": "publish", "operation_id": "publish", "request": export}
        result = self.actions.perform(command)
        self.assertEqual(self.actions.perform(command), result)
        self.assertEqual(self.calls, [("export", "output"), ("publish", "publish")])
        with self.assertRaises(AdmissionConflict):
            self.actions.perform(dict(command, operation_id="second-publication"))
        other = self.journal.admit("https://source.invalid", 1000, "other", {})["run_id"]
        self.journal.transition(other, 0, "check")
        self.journal.transition(other, 1, "invoke")
        other_actions = Actions(self.journal, other, export=self.export, publish=self.publish, progress=self.progress, validate_receipt=self.validate_receipt)
        with self.assertRaises(ActionDenied):
            other_actions.perform(command)

    def test_lost_ack_and_supervisor_restart_never_repeat_effect(self):
        count = []
        def lost_ack(operation_id, request):
            count.append(operation_id)
            raise ConnectionError("response lost after external write")
        self.actions.callbacks["progress"] = lost_ack
        command = {"kind": "progress", "operation_id": "report", "request": {"progress": "in-progress"}}
        with self.assertRaises(ActionUncertain):
            self.actions.perform(command)
        restarted = Actions(Journal(self.path), self.run, export=self.export, publish=self.publish, progress=lost_ack, validate_receipt=self.validate_receipt)
        with self.assertRaises(ActionUncertain):
            restarted.perform(command)
        self.assertEqual(count, ["report"])
        with self.assertRaises(AdmissionConflict):
            restarted.perform(dict(command, request={"progress": "complete"}))

    def test_crash_after_fence_before_ack_is_blocked_after_reopen(self):
        request = {"progress": "complete"}
        self.journal.begin_effect(self.run, "progress", "crash", request)
        restarted = Actions(Journal(self.path), self.run, export=self.export, publish=self.publish, progress=self.progress, validate_receipt=self.validate_receipt)
        with self.assertRaises(ActionUncertain):
            restarted.perform({"kind": "progress", "operation_id": "crash", "request": request})
        self.assertEqual(self.calls, [])

    def test_concurrent_duplicate_has_one_callback(self):
        entered, release = threading.Event(), threading.Event()
        def paused(operation_id, request):
            self.calls.append(operation_id)
            entered.set()
            self.assertTrue(release.wait(5))
            return {"receipt": "trusted-project-task-scope-unit"}
        self.actions.callbacks["progress"] = paused
        command = {"kind": "progress", "operation_id": "same", "request": {"progress": "blocked"}}
        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(self.actions.perform, command)
            self.assertTrue(entered.wait(5))
            try:
                with self.assertRaises(ActionUncertain):
                    pool.submit(self.actions.perform, command).result(timeout=5)
            finally:
                release.set()
            self.assertEqual(first.result(timeout=5), {"receipt": "trusted-project-task-scope-unit"})
        self.assertEqual(self.calls, ["same"])

    def test_privileged_and_worker_routed_requests_never_reach_callbacks(self):
        for kind, request in [("merge", {}), ("approve", {}), ("deploy", {}), ("secrets", {}),
                              ("verification", {}), ("release-ready", {}),
                              ("publish", {"export_id": "a" * 64, "base": "main"}),
                              ("publish", {"export_id": "a" * 64}),
                              ("progress", {"progress": "complete", "task_id": 2}),
                              ("progress", {"progress": "verified"}),
                              ("progress", {"progress": []})]:
            with self.subTest(kind=kind, request=request), self.assertRaises(ActionDenied):
                self.actions.perform({"kind": kind, "operation_id": "request", "request": request})
        self.assertEqual(self.calls, [])

    def test_terminal_run_allows_receipt_read_but_no_new_effect(self):
        command = {"kind": "progress", "operation_id": "report", "request": {"progress": "complete"}}
        receipt = self.actions.perform(command)
        self.journal.transition(self.run, 2, "finish")
        self.assertEqual(self.actions.perform(command), receipt)
        with self.assertRaises(AdmissionConflict):
            self.actions.perform(dict(command, operation_id="late"))

    def test_unknown_receipt_and_new_identity_cannot_clear_uncertainty(self):
        self.actions.callbacks["progress"] = lambda *_: {}
        command = {"kind": "progress", "operation_id": "first", "request": {"progress": "complete"}}
        with self.assertRaises(ActionUncertain):
            self.actions.perform(command)
        with self.assertRaises(AdmissionConflict):
            self.actions.perform(dict(command, operation_id="new-identity"))
        with self.assertRaises(AdmissionConflict):
            self.journal.transition(self.run, 2, "finish")

    def test_completion_cannot_race_a_started_effect(self):
        self.journal.begin_effect(self.run, "progress", "pending", {"progress": "complete"})
        with self.assertRaises(AdmissionConflict):
            self.journal.transition(self.run, 2, "finish")
