"""Controlled composition: canonical authority reader, real Git/Archon/Codex/OCI.

Only external Theseus/GitHub/model replies are synthetic. No operator credentials,
real model calls, live source writes or verification dispositions are involved.
"""
import argparse
import base64
import copy
import hashlib
import json
import shlex
import subprocess
import tempfile
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import httpx
from archon_adapter.test_support import handoff_exchange
from archon_adapter.transport import JsonReader

from .admission import Release, Supervisor
from .closure import inspect as inspect_closure
from .conformance import SyntheticModel
from .git_conformance import SyntheticGit
from .journal import Journal
from .policy_identity import revision as policy_revision
from .runtime import NATIVE_CONFIG, Profile, Runtime
from .source_authority import TheseusAuthority


class SourceFixture:
    def __init__(self, exchange, events):
        self.exchange, self.events = copy.deepcopy(exchange), events
        self.failure = False

    def handle(self, request):
        self.events.append("authority")
        assert request.method == "GET"
        if self.failure:
            return httpx.Response(503)
        e = self.exchange
        path = request.url.path
        if path.endswith("/implementation-handoff"):
            return httpx.Response(200, json=e)
        if path.endswith("/agent-guidance"):
            return httpx.Response(200, json={"project_id": 1000, "revision": e["instructions"]["accepted_revision"], "instructions": "Controlled synthetic guidance."})
        if "/scope-revisions/" in path:
            return httpx.Response(200, json={"id": e["scope"]["selected"]["identity"], "project_id": 1000, "task_id": 42,
                "requirements": [{"description": "Controlled synthetic requirement."}], "verifications": []})
        if "/work-unit-graph-revisions/" in path:
            return httpx.Response(200, json={"id": e["work_unit_graph"]["identity"], "project_id": 1000, "task_id": 42,
                "scope_revision_id": e["scope"]["selected"]["identity"], "units": [{"id": e["work_unit"]["identity"]}]})
        return httpx.Response(200, json={"id": 42, "project_id": 1000})


class GitHubFixture:
    root = "/repos/overlandla/theseus"

    def __init__(self, repository, git_policy, events, exchange, lost_ack):
        self.repository, self.git_policy, self.events, self.exchange = repository, git_policy, events, exchange
        self.lost_ack = lost_ack
        self.calls, self.pulls = [], []
        self.env = {**git_policy.env, "GIT_AUTHOR_NAME": "Fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
                    "GIT_COMMITTER_NAME": "Fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid"}

    def git(self, *arguments, content=None, environment=None):
        return subprocess.run(["git", "-c", "core.hooksPath=/dev/null", *arguments], cwd=self.repository,
            env=environment or self.env, input=content, capture_output=True, check=True, timeout=10).stdout

    def tree(self, revision):
        tree = []
        for record in self.git("ls-tree", "-r", "-t", "-z", revision).split(b"\0"):
            if record:
                metadata, path = record.split(b"\t")
                mode, kind, sha = metadata.decode().split()
                tree.append({"path": path.decode(), "mode": mode, "type": kind, "sha": sha})
        return {"sha": revision, "truncated": False, "tree": tree}

    def __call__(self, method, path, body):
        self.events.append("repository")
        self.calls.append((method, path))
        if method == "GET" and path == self.root:
            return {"id": 42, "full_name": "overlandla/theseus", "archived": False}
        if method == "GET" and "/git/ref/heads/" in path:
            branch = path.split("/git/ref/heads/")[1]
            return {"ref": "refs/heads/" + branch, "object": {"type": "commit", "sha": self.git("rev-parse", "refs/heads/" + branch).decode().strip()}}
        if method == "GET" and "/git/commits/" in path:
            commit = path.rsplit("/", 1)[1]
            return {"sha": commit, "tree": {"sha": self.git("rev-parse", commit + "^{tree}").decode().strip()}}
        if method == "GET" and path.endswith("/actions/permissions"):
            return {"enabled": False}
        if method == "GET" and "/git/trees/" in path:
            return self.tree(path.split("/git/trees/")[1].split("?")[0])
        if method == "POST" and path.endswith("/git/blobs"):
            assert body["encoding"] == "base64"
            return {"sha": self.git("hash-object", "-w", "--stdin", content=base64.b64decode(body["content"], validate=True)).decode().strip()}
        if method == "POST" and path.endswith("/git/trees"):
            index = self.repository.parent / ("index-" + str(uuid4()))
            environment = {**self.env, "GIT_INDEX_FILE": str(index)}
            try:
                self.git("read-tree", body["base_tree"], environment=environment)
                for entry in body["tree"]:
                    if entry["sha"] is None:
                        self.git("update-index", "--force-remove", "--", entry["path"], environment=environment)
                    else:
                        self.git("update-index", "--add", "--cacheinfo", entry["mode"] + "," + entry["sha"] + "," + entry["path"], environment=environment)
                revision = self.git("write-tree", environment=environment).decode().strip()
            finally:
                index.unlink(missing_ok=True)
            return {"sha": revision}
        if method == "POST" and path.endswith("/git/commits"):
            assert body["parents"] == [self.git_policy.commit]
            commit = self.git("commit-tree", body["tree"], "-p", body["parents"][0], content=body["message"].encode()).decode().strip()
            return {"sha": commit, "tree": {"sha": body["tree"]}, "parents": [{"sha": self.git_policy.commit}]}
        if method == "POST" and path.endswith("/git/refs"):
            assert body["ref"].startswith("refs/heads/archon/handoff/")
            self.git("update-ref", body["ref"], body["sha"], "0" * 40)
            return {"ref": body["ref"], "object": {"sha": body["sha"]}}
        if method == "POST" and path.endswith("/pulls"):
            assert body["draft"] is True and body["maintainer_can_modify"] is False
            commit = self.git("rev-parse", "refs/heads/" + body["head"]).decode().strip()
            value = {"number": 1, "html_url": "https://github.com/overlandla/theseus/pull/1", "draft": True, "state": "open",
                     "head": {"ref": body["head"], "sha": commit, "repo": {"id": 42}},
                     "base": {"ref": body["base"], "sha": self.git_policy.commit, "repo": {"id": 42}}}
            self.pulls.append(value)
            if self.lost_ack:
                raise ConnectionError("synthetic PR acknowledgement lost")
            return value
        if method == "POST" and path == "/api/projects/1000/tasks/42/implementation-reports":
            return {"created": True, "report": {**body, "id": str(uuid4()), "project_id": 1000, "task_id": 42,
                    "graph_revision_id": self.exchange["work_unit_graph"]["identity"]}}
        raise AssertionError("unexpected trusted API operation", method, path)


def exercise(image: str, worker: Path, native: Path, case="current"):
    with tempfile.TemporaryDirectory(prefix="archon-runtime-proof-") as directory:
        root = Path(directory)
        source, repository = root / "source", root / "repository"
        (source / ".archon/workflows").mkdir(parents=True)
        workflow = source / ".archon/workflows/theseus-implementation.yaml"
        workflow.write_text("name: theseus-implementation\ndescription: Controlled fixture\nnodes:\n"
            "  - id: implement\n    provider: codex\n    model: fixture-model\n    prompt: Execute the controlled task.\n"
            "  - id: verify\n    depends_on: [implement]\n    bash: test -f src/implementation.py\n")
        environment = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(root), "ARCHON_HOME": str(root / "build-state"),
                       "DATABASE_URL": "", "LOG_LEVEL": "error", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
        initial, prepared = root / "initial.json", root / "prepared.json"
        initial.write_text(json.dumps({"runId": str(uuid4()), "cwd": "/workspace/repository", "sourceRoot": str(source),
            "workflowIdentity": "theseus-implementation", "model": "fixture-model", "codexBinary": "/runtime/codex"}))
        subprocess.run([str(worker), "prepare", str(initial), str(prepared)], env=environment, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)
        captured = json.loads(prepared.read_text())
        # Cross-language closure agreement precedes any repository operation.
        inspect_closure(Path(captured["captureRoot"]), "theseus-implementation", captured["executableRevision"])
        workflow.write_text("name: replaced\nnodes: []\n")
        repository.mkdir()
        subprocess.run(["git", "init", "-q", str(repository)], env=environment, check=True, timeout=10)
        (repository / "README.md").write_text("Synthetic base.\n")
        git_policy = SyntheticGit(repository)
        events = []
        original_send = git_policy.send
        def send(method, path, body):
            events.append("git-fetch")
            return original_send(method, path, body)
        git_policy.send = send
        exchange = handoff_exchange()
        source_fixture = SourceFixture(exchange, events)
        github = GitHubFixture(repository, git_policy, events, exchange, case == "lost-publication-ack")
        selected_repository = {"canonical_ref": "github:overlandla/theseus", "repository": str(repository),
                               "worktree_root": str(root / "worktrees"), "base": "main"}
        release = Release("theseus-implementation", captured["executableRevision"], hashlib.sha256(worker.read_bytes()).hexdigest(),
            hashlib.sha256(native.read_bytes()).hexdigest(), image.removeprefix("sha256:"), policy_revision(),
            hashlib.sha256(NATIVE_CONFIG.encode()).hexdigest(), "0" * 64)
        profile = Profile(release, image, Path(captured["captureRoot"]), "fixture-model",
            TheseusAuthority("https://reqtory.example.test", 1000, "synthetic-source-credential"), selected_repository,
            "overlandla", "theseus", 42, frozenset({"src/implementation.py"}), "operator-isolated-actions-disabled",
            "synthetic-github-credential", "https://model.example.test", "synthetic-model-credential")
        release = replace(release, authority_configuration_revision=profile.configuration_revision())
        profile = replace(profile, release=release)
        references = {key: copy.deepcopy(exchange[key]) for key in ("schema_version", "exchange_type", "source", "task", "work_unit_graph", "work_unit", "scope", "sources", "dependencies", "repositories", "authority")}
        references["instructions"] = {"accepted_revision": exchange["instructions"]["accepted_revision"]}
        selection = {"release": release.selection(), "source": {"deployment": profile.authority.deployment, "project": 1000},
                     "handoff": {"workflow_identity": release.identity, "workflow_revision": release.closure_revision,
                                 "workflow_revision_format": "archon-immutable-closure-v1", "runtime_release": release.selection(), "repository": selected_repository, "references": references}}
        journal = Journal(root / "journal.sqlite")
        runtime = Runtime(journal, profile)
        supervisor = Supervisor(journal, release, runtime)
        admitted = supervisor.admit(profile.authority.deployment, 1000, "controlled-correlation", selection)
        assert events == []
        if case == "stale-scope":
            source_fixture.exchange["scope"]["selected"]["identity"] = str(uuid4())
        elif case == "stale-guidance":
            source_fixture.exchange["instructions"]["accepted_revision"] = str(uuid4())
        elif case == "unavailable-authority":
            source_fixture.failure = True
        elif case == "changed-mode":
            next(Path(captured["captureRoot"]).rglob("theseus-implementation.yaml")).chmod(0o755)
        original_run = __import__("scripts.confined_runtime.oci", fromlist=["run"]).run
        def delayed_start(*args, **kwargs):
            if case == "bootstrap-stale-scope":
                source_fixture.exchange["scope"]["selected"]["identity"] = str(uuid4())
            elif case == "bootstrap-stale-guidance":
                source_fixture.exchange["instructions"]["accepted_revision"] = str(uuid4())
            return original_run(*args, **kwargs)
        script = '''import base64, hashlib, http.client, json, socket
from pathlib import Path
content = b"answer = 42\\n"
Path("src").mkdir(exist_ok=True)
Path("src/implementation.py").write_bytes(content)
def action(kind, identity, request):
    connection = http.client.HTTPConnection("localhost", timeout=30)
    connection.sock = socket.socket(socket.AF_UNIX)
    connection.sock.connect("/broker/actions.sock")
    connection.request("POST", "/actions", json.dumps({"kind":kind,"operation_id":identity,"request":request}), {"Content-Type":"application/json"})
    response = connection.getresponse()
    result = response.status, json.loads(response.read())
    connection.close()
    return result
status, export = action("export", "export", {"files":[{"path":"src/implementation.py","size":len(content),"sha256":hashlib.sha256(content).hexdigest(),"content":base64.b64encode(content).decode(),"executable":False}],"deletions":[]})
assert status == 200
status, receipt = action("publish", "publish", export)
if LOST_ACK:
    assert status == 409
    assert action("publish", "publish", export)[0] == 409
else:
    assert status == 200
    assert action("publish", "publish", export) == (200, receipt)
    assert action("progress", "progress", {"progress":"complete"})[0] == 200
assert action("merge", "merge", {})[0] == 403
'''.replace("LOST_ACK", repr(case == "lost-publication-ack"))
        model = SyntheticModel("python3 -c " + shlex.quote(script))
        model.close = lambda: None
        real_git_broker = __import__("scripts.confined_runtime.git_read", fromlist=["Broker"]).Broker
        def make_git_broker(*args, **kwargs):
            if case == "broker-start-failure":
                raise OSError("controlled broker acquisition failure")
            return real_git_broker(*args, **kwargs)
        with patch("scripts.confined_runtime.runtime.GitBroker", side_effect=make_git_broker), \
             patch("scripts.confined_runtime.runtime.run", side_effect=delayed_start), \
             patch("archon_adapter.transport.JsonReader", side_effect=lambda origin, token=None: JsonReader(origin, token=token, transport=httpx.MockTransport(source_fixture.handle))), \
             patch("scripts.confined_runtime.runtime.RepositoryHTTPS", return_value=github), \
             patch("scripts.confined_runtime.runtime.GitPolicy", return_value=git_policy), \
             patch("scripts.confined_runtime.runtime.ModelPolicy", return_value=model), \
             patch("scripts.confined_runtime.runtime.HTTPS", return_value=github):
            result = supervisor.dequeue(admitted["run_id"], 0)
        expected = {"current": "finished", "lost-publication-ack": "uncertain", "stale-scope": "rejected",
                    "stale-guidance": "rejected", "unavailable-authority": "uncertain", "changed-mode": "rejected", "bootstrap-stale-scope": "uncertain", "bootstrap-stale-guidance": "uncertain", "broker-start-failure": "uncertain"}[case]
        assert result["state"] == expected, (result, events, journal.effect_projection(admitted["run_id"]))
        if case in {"current", "lost-publication-ack"}:
            assert events.index("authority") < events.index("repository") < events.index("git-fetch")
            assert model.calls == 2 and len(github.pulls) == 1
            assert github.git("show", github.pulls[0]["head"]["sha"] + ":src/implementation.py") == b"answer = 42\n"
            assert journal.facts(admitted["run_id"])["container"]["image"] == image
        elif case == "broker-start-failure":
            assert "repository" in events and "git-fetch" not in events and model.calls == 0
        elif case.startswith("bootstrap-stale-"):
            assert "repository" in events and "git-fetch" not in events and model.calls == 0
            assert journal.facts(admitted["run_id"])["bootstrap"] == {"rejection": case.removeprefix("bootstrap-").replace("-", "_")}
        else:
            assert "repository" not in events and "git-fetch" not in events and model.calls == 0
        before = list(events)
        assert supervisor.admit(profile.authority.deployment, 1000, "controlled-correlation", selection) == result
        assert events == before
        assert not runtime.pending
        return {"kind": "controlled-runtime-composition", "case": case, "full_runtime_conformance": False,
                "live_acceptance": False, "image": image, "executable_revision": release.closure_revision,
                "state": result["state"], "model_calls": model.calls, "publication_count": len(github.pulls),
                "effects": journal.effect_projection(admitted["run_id"])}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--worker", type=Path, required=True)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--case", default="current", choices=["current", "lost-publication-ack", "stale-scope", "stale-guidance", "unavailable-authority", "changed-mode", "bootstrap-stale-scope", "bootstrap-stale-guidance", "broker-start-failure"])
    args = parser.parse_args()
    print(json.dumps(exercise(args.image, args.worker.resolve(), args.native.resolve(), args.case), indent=2))
