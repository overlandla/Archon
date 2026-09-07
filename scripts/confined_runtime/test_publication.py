import unittest
from dataclasses import replace
from uuid import uuid4

from .exports import validate
from .publication import Policy, PublicationRejected, Publisher
from .test_exports import file


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.policy = Policy("owner", "repo", 42, str(uuid4()), "main", "a" * 40, "b" * 40,
                             frozenset({"src/app.py", "obsolete.py"}), "a" * 40, "operator-isolated-actions-disabled")
        self.calls = []
        self.checks = []
        self.candidates = []
        self.publisher = Publisher(self.policy, self.request, lambda: self.checks.append(len(self.calls)), self.candidates.append)
        self.export = validate({"files": [file()], "deletions": ["obsolete.py"]})

    def request(self, method, path, body):
        self.calls.append((method, path, body))
        p = self.policy
        if method == "GET" and path == p.root:
            return {"id": 42, "full_name": "owner/repo", "archived": False}
        if method == "GET" and path.endswith("/git/ref/heads/main"):
            return {"ref": "refs/heads/main", "object": {"type": "commit", "sha": p.base_commit}}
        if method == "GET" and path.endswith("/git/commits/" + p.base_commit):
            return {"sha": p.base_commit, "tree": {"sha": p.base_tree}}
        if method == "GET" and path.endswith("/actions/permissions"):
            return {"enabled": False}
        if method == "GET" and "/git/trees/" in path:
            revision = path.split("/git/trees/")[1].split("?")[0]
            tree = ([{"path": "obsolete.py", "type": "blob", "mode": "100644", "sha": "f" * 40}]
                    if revision == p.base_tree else [{"path": "src", "type": "tree", "mode": "040000", "sha": "f" * 40},
                        {"path": "src/app.py", "type": "blob", "mode": "100644", "sha": "c" * 40}])
            return {"sha": revision, "truncated": False, "tree": tree}
        if method == "POST" and path.endswith("/git/blobs"):
            return {"sha": "c" * 40}
        if method == "POST" and path.endswith("/git/trees"):
            return {"sha": "d" * 40}
        if method == "POST" and path.endswith("/git/commits"):
            return {"sha": "e" * 40, "tree": {"sha": "d" * 40}, "parents": [{"sha": p.base_commit}]}
        if method == "POST" and path.endswith("/git/refs"):
            return {"ref": body["ref"], "object": {"sha": body["sha"]}}
        if method == "POST" and path.endswith("/pulls"):
            return {"number": 123, "html_url": "https://github.com/owner/repo/pull/123", "draft": True, "state": "open",
                    "head": {"ref": p.branch, "sha": "e" * 40, "repo": {"id": 42}},
                    "base": {"ref": p.base, "sha": p.base_commit, "repo": {"id": 42}}}
        self.fail((method, path, body))

    def test_regular_export_creates_only_new_run_branch_and_fixed_draft_pr(self):
        receipt = self.publisher.publish(self.export)
        self.publisher.validate_receipt({"export_id": self.export.digest}, receipt)
        self.assertEqual(self.candidates[0]["commit"], "e" * 40)
        self.assertEqual(receipt["commit"], "e" * 40)
        self.assertEqual(receipt["export_id"], self.export.digest)
        self.assertEqual(self.checks, [0, 9])
        self.assertTrue(all(method in {"GET", "POST"} for method, _, _ in self.calls))
        tree = next(body for method, path, body in self.calls if method == "POST" and path.endswith("/git/trees"))
        self.assertEqual(tree["base_tree"], self.policy.base_tree)
        self.assertEqual(tree["tree"][0]["mode"], "100644")
        self.assertIsNone(tree["tree"][1]["sha"])
        self.assertEqual(next(body for method, path, body in self.calls if method == "POST" and path.endswith("/git/refs")), {"ref": "refs/heads/" + self.policy.branch, "sha": "e" * 40})
        pr = self.calls[-1][2]
        self.assertTrue(pr["draft"])
        self.assertFalse(pr["maintainer_can_modify"])
        self.assertEqual(pr["base"], "main")

    def test_unreviewed_automation_and_unapproved_paths_fail_before_network(self):
        for policy in (replace(self.policy, automation_base="f" * 40),
                       replace(self.policy, allowed_paths=frozenset({".github/workflows/deploy.yml"})),
                       replace(self.policy, allowed_paths=frozenset({".gitmodules"}))):
            with self.subTest(policy=policy), self.assertRaises(PublicationRejected):
                Publisher(policy, self.request, lambda: None, self.candidates.append)
        with self.assertRaises(PublicationRejected):
            self.publisher.publish(validate({"files": [file("unapproved.py")], "deletions": []}))
        self.assertEqual(self.calls, [])

    def test_stale_base_or_authority_causes_no_object_or_reference_write(self):
        original = self.publisher.request
        def changed(method, path, body):
            value = original(method, path, body)
            if "/git/ref/" in path:
                value["object"]["sha"] = "f" * 40
            return value
        self.publisher.request = changed
        with self.assertRaises(PublicationRejected):
            self.publisher.publish(self.export)
        self.assertTrue(all(method == "GET" for method, _, _ in self.calls))
        self.calls.clear()
        def stale():
            raise PublicationRejected("stale_scope")
        self.publisher.check_authority = stale
        with self.assertRaises(PublicationRejected):
            self.publisher.publish(self.export)
        self.assertEqual(self.calls, [])

    def test_second_freshness_check_precedes_reference_creation(self):
        def stale_at_publish():
            if self.calls:
                raise PublicationRejected("stale_scope")
        self.publisher.check_authority = stale_at_publish
        with self.assertRaises(PublicationRejected):
            self.publisher.publish(self.export)
        self.assertFalse(any(path.endswith("/git/refs") or path.endswith("/pulls") for _, path, _ in self.calls))

    def test_foreign_or_non_draft_pr_receipt_is_uncertain(self):
        original = self.publisher.request
        for field, bad in (("draft", False), ("html_url", "https://foreign.invalid/pr"), ("number", True)):
            def altered(method, path, body):
                value = original(method, path, body)
                if path.endswith("/pulls"):
                    value[field] = bad
                return value
            self.publisher.request = altered
            with self.subTest(field=field), self.assertRaises(PublicationRejected):
                self.publisher.publish(self.export)

    def test_directory_replacement_and_unrelated_tree_changes_are_blocked(self):
        original = self.publisher.request
        for malicious_base in (True, False):
            def changed(method, path, body, malicious_base=malicious_base):
                value = original(method, path, body)
                if method == "GET" and "/git/trees/" in path:
                    if malicious_base and self.policy.base_tree in path:
                        value["tree"].extend([
                            {"path": "src/app.py", "mode": "040000", "type": "tree", "sha": "f" * 40},
                            {"path": "src/app.py/protected", "mode": "100644", "type": "blob", "sha": "f" * 40}])
                    elif not malicious_base and self.policy.base_tree not in path:
                        value["tree"].append({"path": "unauthorized", "mode": "100644", "type": "blob", "sha": "f" * 40})
                return value
            self.publisher.request = changed
            self.calls.clear()
            with self.subTest(malicious_base=malicious_base), self.assertRaises(PublicationRejected):
                self.publisher.publish(self.export)
            self.assertFalse(any(path.endswith("/git/refs") for _, path, _ in self.calls))
            if malicious_base:
                self.assertTrue(all(method == "GET" for method, _, _ in self.calls))

    def test_enabled_actions_and_changed_base_at_publication_are_blocked(self):
        original = self.publisher.request
        for enabled_actions in (True, False):
            base_reads = []
            def changed(method, path, body, enabled_actions=enabled_actions):
                value = original(method, path, body)
                if path.endswith("/actions/permissions") and enabled_actions:
                    value["enabled"] = True
                if path.endswith("/git/ref/heads/main"):
                    base_reads.append(path)
                    if len(base_reads) == 2:
                        value["object"]["sha"] = "f" * 40
                return value
            self.publisher.request = changed
            self.calls.clear()
            with self.subTest(enabled_actions=enabled_actions), self.assertRaises(PublicationRejected):
                self.publisher.publish(self.export)
            self.assertFalse(any(path.endswith("/git/refs") for _, path, _ in self.calls))
