"""Real confined Codex actions against trusted brokers and synthetic API replies.

Exercises the actual worker socket boundary, export identity and publication /
progress fences. Synthetic GitHub/Theseus replies are not live acceptance or
complete runtime admission conformance.
"""
import argparse
import json
import tempfile
from pathlib import Path
from uuid import uuid4

from .action_server import Handler, Server
from .actions import Actions
from .exports import retain, validate
from .journal import AdmissionConflict, Journal
from .oci_conformance import FixtureHandler, probe
from .progress import Binding, Reporter
from .publication import Policy, Publisher


class ProbeHandler(Handler):
    def do_POST(self):
        if self.path in {"/probe-tool", "/probe-test"}:
            return FixtureHandler.do_POST(self)
        return super().do_POST()


class ProbeServer(Server):
    def __init__(self, path, actions):
        self.reports = {}
        super().__init__(path, actions)
        self.RequestHandlerClass = ProbeHandler


def exercise(image: str, worker: Path, lost_ack=False):
    with tempfile.TemporaryDirectory(prefix="archon-action-probe-") as directory:
        root = Path(directory)
        journal = Journal(root / "journal.sqlite")
        run = journal.admit("https://source.invalid", 1000, "controlled-correlation", {"fixture": True})["run_id"]
        journal.transition(run, 0, "check")
        journal.transition(run, 1, "invoke")
        policy = Policy("fixture", "repo", 42, run, "main", "a" * 40, "b" * 40,
                        frozenset({"src/implementation.py"}), "a" * 40, "operator-isolated-actions-disabled")
        binding = Binding(1000, 42, str(uuid4()), str(uuid4()), str(uuid4()), "controlled-correlation", run)
        calls = []
        freshness = []
        def request(method, path, body):
            calls.append((method, path, body))
            if method == "GET" and path == policy.root:
                return {"id": 42, "full_name": "fixture/repo", "archived": False}
            if method == "GET" and path.endswith("/git/ref/heads/main"):
                return {"ref": "refs/heads/main", "object": {"type": "commit", "sha": policy.base_commit}}
            if method == "GET" and path.endswith("/git/commits/" + policy.base_commit):
                return {"sha": policy.base_commit, "tree": {"sha": policy.base_tree}}
            if method == "GET" and path.endswith("/actions/permissions"):
                return {"enabled": False}
            if method == "GET" and "/git/trees/" in path:
                revision = path.split("/git/trees/")[1].split("?")[0]
                tree = ([] if revision == policy.base_tree else [
                    {"path": "src", "mode": "040000", "type": "tree", "sha": "f" * 40},
                    {"path": "src/implementation.py", "mode": "100644", "type": "blob", "sha": "c" * 40}])
                return {"sha": revision, "truncated": False, "tree": tree}
            if method == "POST" and path.endswith("/git/blobs"):
                return {"sha": "c" * 40}
            if method == "POST" and path.endswith("/git/trees"):
                return {"sha": "d" * 40}
            if method == "POST" and path.endswith("/git/commits"):
                return {"sha": "e" * 40, "tree": {"sha": "d" * 40}, "parents": [{"sha": policy.base_commit}]}
            if method == "POST" and path.endswith("/git/refs"):
                return {"ref": body["ref"], "object": {"sha": body["sha"]}}
            if method == "POST" and path.endswith("/pulls"):
                if lost_ack:
                    raise ConnectionError("synthetic PR created, acknowledgement lost")
                return {"number": 7, "html_url": "https://github.com/fixture/repo/pull/7", "draft": True, "state": "open",
                        "head": {"ref": policy.branch, "sha": "e" * 40, "repo": {"id": 42}},
                        "base": {"ref": "main", "sha": policy.base_commit, "repo": {"id": 42}}}
            if method == "POST" and path == binding.path:
                return {"created": True, "report": {**body, "id": str(uuid4()), "project_id": 1000,
                        "task_id": 42, "graph_revision_id": binding.graph_revision_id}}
            raise AssertionError("unexpected broker request", method, path)
        publisher = Publisher(policy, request, lambda: freshness.append("publication"),
            lambda candidate: journal.retain_candidate(run, "publish", "publication", candidate))
        reporter = Reporter(binding, request, lambda: freshness.append("progress"))
        exports = {}
        def retain_export(operation_id, value):
            export = validate(value)
            retain(export, root / export.digest)
            exports[export.digest] = export
            return {"export_id": export.digest}
        def validate_receipt(kind, operation_id, request, response):
            if kind == "publish":
                publisher.validate_receipt(request, response)
            elif kind == "progress":
                reporter.validate_receipt(operation_id, request, response)
        actions = Actions(journal, run, export=retain_export,
            publish=lambda _, request: publisher.publish(exports[request["export_id"]]),
            progress=reporter.report, validate_receipt=validate_receipt)
        extension = '''
import base64, hashlib
content = b"answer = 42\\n"
def action(kind, identity, request):
    connection = http.client.HTTPConnection("localhost", timeout=10)
    connection.sock = socket.socket(socket.AF_UNIX)
    connection.sock.connect("/broker/actions.sock")
    connection.request("POST", "/actions", json.dumps({"kind": kind, "operation_id": identity, "request": request}),
                       {"Content-Type": "application/json"})
    response = connection.getresponse()
    result = (response.status, json.loads(response.read()))
    connection.close()
    return result
status, exported = action("export", "export", {"files": [{"path": "src/implementation.py", "size": len(content),
    "sha256": hashlib.sha256(content).hexdigest(), "content": base64.b64encode(content).decode(), "executable": False}], "deletions": []})
assert status == 200
status, receipt = action("publish", "publication", exported)
if LOST_ACK:
    assert status in (503, 409)
    assert action("publish", "publication", exported)[0] == 409
else:
    assert status == 200 and receipt["branch"].startswith("archon/handoff/")
    assert action("publish", "publication", exported) == (200, receipt)
    assert action("progress", "progress", {"progress": "complete"})[0] == 200
assert action("publish", "different-id", exported)[0] == 409
assert action("merge", "privileged", {})[0] == 403
'''.replace("LOST_ACK", repr(lost_ack))
        result = probe(image, worker, run_identity=run, actions_factory=lambda path: ProbeServer(path, actions), tool_extension=extension)
        # Both the native provider's tool and the workflow shell-test node made
        # the same requests; successful effects executed only once.
        assert sum(path.endswith("/pulls") for _, path, _ in calls) == 1
        assert journal.candidate(run, "publish", "publication")["commit"] == "e" * 40
        if lost_ack:
            try:
                journal.transition(run, 2, "finish")
            except AdmissionConflict:
                pass
            else:
                raise AssertionError("uncertain publication incorrectly completed")
            journal.transition(run, 2, "uncertain")
            # Reopened ownership/selection remains observable, never reinvoked.
            assert Journal(journal.path).find("https://source.invalid", 1000, "controlled-correlation")[0]["state"] == "uncertain"
        else:
            assert journal.transition(run, 2, "finish")["state"] == "finished"
            assert len(calls) == 14 and freshness == ["publication", "publication", "progress"]
        result.update(kind="controlled-oci-action-probe", publication_ack_lost=lost_ack,
                      publication_calls=1, trusted_api_calls=len(calls), durable_state="uncertain" if lost_ack else "finished")
        return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--worker", type=Path, required=True)
    parser.add_argument("--lost-ack", action="store_true")
    args = parser.parse_args()
    print(json.dumps(exercise(args.image, args.worker.resolve(), args.lost_ack), indent=2))
