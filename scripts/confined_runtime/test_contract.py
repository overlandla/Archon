"""Controlled component checks. These are not runtime conformance evidence."""
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import tempfile
import unittest

from .journal import AdmissionConflict, Journal
from .model_broker import validate_body
from .admission import Rejected, Release, Supervisor
from .staging import stage


class JournalTests(unittest.TestCase):
    def test_concurrent_admission_and_lost_ack_never_reinvoke(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "journal.sqlite"
            journal = Journal(path)
            with ThreadPoolExecutor(max_workers=8) as pool:
                rows = list(pool.map(lambda _: journal.admit("https://source.invalid", 1000, "claim-1", {"revision": "a"}), range(16)))
            self.assertEqual(len({row["run_id"] for row in rows}), 1)
            run = journal.transition(rows[0]["run_id"], 0, "check")
            run = journal.transition(run["run_id"], run["revision"], "invoke")
            # A reopened journal sees the start fence, even with no finish/ack.
            reopened = Journal(path)
            replay = reopened.admit("https://source.invalid", 1000, "claim-1", {"revision": "a"})
            self.assertEqual(replay, run)
            with self.assertRaises(AdmissionConflict):
                reopened.transition(run["run_id"], run["revision"], "invoke")
            self.assertEqual(reopened.interrupted(), [run])
            self.assertEqual(reopened.find("https://foreign.invalid", 1000, "claim-1"), [])
            self.assertEqual(reopened.find("https://source.invalid", 999, "claim-1"), [])
            with self.assertRaises(AdmissionConflict):
                reopened.admit("https://source.invalid", 1000, "claim-1", {"revision": "b"})

    def test_only_one_dequeue_wins_and_rejection_is_terminal(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = Journal(Path(directory) / "journal.sqlite")
            row = journal.admit("source", 1, "correlation", {})
            def dequeue(_):
                try:
                    return journal.transition(row["run_id"], 0, "check")
                except AdmissionConflict:
                    return None
            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(dequeue, range(8)))
            self.assertEqual(sum(value is not None for value in results), 1)
            rejected = journal.transition(row["run_id"], 1, "stale_scope")
            self.assertEqual(rejected["state"], "rejected")
            with self.assertRaises(AdmissionConflict):
                journal.transition(row["run_id"], 2, "invoke")
            self.assertEqual(journal.interrupted(), [])


class StagingTests(unittest.TestCase):
    def test_complete_regular_source_and_executable_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source/scripts").mkdir(parents=True)
            script = root / "source/scripts/test.sh"
            script.write_text("exit 0\n")
            script.chmod(0o700)
            stage(root / "source", root / "staged")
            self.assertEqual((root / "staged/scripts/test.sh").read_text(), "exit 0\n")
            self.assertEqual((root / "staged/scripts/test.sh").stat().st_mode & 0o777, 0o500)

    def test_links_special_files_and_oversize_fail_without_retained_partial_tree(self):
        for kind in ("symlink", "hardlink", "fifo", "oversize"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "source").mkdir()
                (root / "private").write_text("test-only canary")
                target = root / "source/entry"
                if kind == "symlink":
                    target.symlink_to(root / "private")
                elif kind == "hardlink":
                    os.link(root / "private", target)
                elif kind == "fifo":
                    os.mkfifo(target)
                else:
                    with target.open("wb") as stream:
                        stream.truncate(16 * 1024 * 1024 + 1)
                with self.assertRaises((ValueError, OSError)):
                    stage(root / "source", root / "staged")
                self.assertFalse((root / "staged").exists())
                self.assertEqual((root / "private").read_text(), "test-only canary")


class ModelBoundaryTests(unittest.TestCase):
    def test_local_function_tools_allowed(self):
        validate_body(json.dumps({"model": "fixture", "stream": True, "store": False,
                                 "tools": [{"type": "function", "name": "exec_command"}]}).encode(), "fixture")

    def test_external_actions_model_override_and_ambiguous_json_denied(self):
        for change in ({"model": "other"}, {"store": True}, {"background": True},
                       {"conversation": "other"}, {"previous_response_id": "other"},
                       {"tools": [{"type": "mcp", "server_url": "https://foreign.invalid"}]},
                       {"tools": [{"type": "web_search"}]}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_body(json.dumps({"model": "fixture", "stream": True, **change}).encode(), "fixture")
        with self.assertRaises(ValueError):
            validate_body(b'{"model":"fixture","model":"other","stream":true}', "fixture")

    def test_unknown_fields_and_external_references_denied_storage_explicit(self):
        base = {"model": "fixture", "stream": True}
        normalized = json.loads(validate_body(json.dumps(base).encode(), "fixture"))
        self.assertIs(normalized["store"], False)
        for change in ({"new_capability": {}}, {"input": [{"type": "item_reference", "id": "external"}]},
                       {"input": [{"role": "user", "content": [{"type": "input_image", "image_url": "https://foreign.invalid"}]}]},
                       {"input": [{"role": "user", "content": [{"type": "input_file", "file_id": "file-other"}]}]},
                       {"tools": [{"type": "namespace", "tools": [{"type": "web_search"}]}]}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                validate_body(json.dumps({**base, **change}).encode(), "fixture")


class AdmissionOrderTests(unittest.TestCase):
    def test_queued_staleness_and_capture_mismatch_precede_every_repository_operation(self):
        release = Release("fixture", *("a" * 64 for _ in range(5)))
        for rejection in ("stale_scope", "stale_guidance", "source_mismatch", "unreachable"):
            with self.subTest(rejection=rejection), tempfile.TemporaryDirectory() as directory:
                events = []
                class Policy:
                    def capture(self, run_id, selection):
                        events.append("capture")
                        return "b" * 64 if rejection == "source_mismatch" else release.closure_revision
                    def validate_authority(self, selection):
                        events.append("authority")
                        if rejection == "unreachable":
                            raise OSError("unreachable")
                        raise Rejected(rejection)
                    def refresh_and_create_worktree(self, run_id, selection):
                        events.append("repository")
                    def invoke(self, run_id, selection):
                        events.append("invoke")
                supervisor = Supervisor(Journal(Path(directory) / "journal.sqlite"), release, Policy())
                row = supervisor.admit("source", 1000, "correlation", {
                    "release": release.selection(), "source": {"deployment": "source", "project": 1000}})
                self.assertEqual(events, [])
                result = supervisor.dequeue(row["run_id"], 0)
                self.assertEqual(result["state"], "uncertain" if rejection == "unreachable" else "rejected")
                self.assertNotIn("repository", events)
                self.assertNotIn("invoke", events)
                with self.assertRaises(AdmissionConflict):
                    supervisor.dequeue(row["run_id"], result["revision"])

    def test_invocation_failure_and_replay_do_not_repeat_worktree_or_worker(self):
        release = Release("fixture", *("a" * 64 for _ in range(5)))
        with tempfile.TemporaryDirectory() as directory:
            events = []
            class Policy:
                def capture(self, run_id, selection):
                    events.append("capture")
                    return release.closure_revision
                def validate_authority(self, selection):
                    events.append("authority")
                def refresh_and_create_worktree(self, run_id, selection):
                    events.append("repository")
                def invoke(self, run_id, selection):
                    events.append("invoke")
                    raise OSError("acknowledgement_lost")
            journal = Journal(Path(directory) / "journal.sqlite")
            supervisor = Supervisor(journal, release, Policy())
            selection = {"release": release.selection(), "source": {"deployment": "source", "project": 1000}}
            row = supervisor.admit("source", 1000, "correlation", selection)
            result = supervisor.dequeue(row["run_id"], 0)
            self.assertEqual(result["state"], "uncertain")
            self.assertEqual(supervisor.admit("source", 1000, "correlation", selection), result)
            self.assertEqual(events, ["capture", "authority", "repository", "invoke"])
            with self.assertRaises(AdmissionConflict):
                supervisor.dequeue(row["run_id"], result["revision"])


if __name__ == "__main__":
    unittest.main()
