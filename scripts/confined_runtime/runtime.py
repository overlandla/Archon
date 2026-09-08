"""Concrete confined runtime policy; operator packaging is a separate authority.

A validated profile is trusted supervisor configuration. Launch requests contain
only the exact approved release and reference-only #524 selection. The stock
Archon server, provider configuration and connection settings are not modified.
"""
import hashlib
import json
import re
import tempfile
import threading
from dataclasses import dataclass, field, replace
from pathlib import Path
from urllib.parse import urlsplit

from .action_server import Server as ActionServer
from .actions import Actions
from .admission import Rejected, Release
from .closure import inspect as inspect_closure
from .children import Children, ObservationSink
from .exports import retain, validate
from .git_read import Broker as GitBroker
from .git_read import Policy as GitPolicy
from .https_transport import HTTPS, Origin
from .journal import Journal, canonical
from .lifecycle import Lifecycle
from .model_broker import Broker as ModelBroker
from .model_broker import ModelPolicy
from .oci import Inputs, run, seccomp_policy, tmpfs
from .policy_identity import revision as policy_revision
from .progress import Binding, Reporter
from .publication import Policy as PublicationPolicy
from .publication import Publisher
from .repository_transport import RepositoryHTTPS
from .source_authority import TheseusAuthority
from .staging import stage

NATIVE_CONFIG = ('model_provider = "archon"\nweb_search = "disabled"\n'
                 '[model_providers.archon]\nname = "archon"\n'
                 'base_url = "http://127.0.0.1:8765/v1"\nwire_api = "responses"\nrequires_openai_auth = false\n')


@dataclass(frozen=True)
class Profile:
    release: Release
    image: str
    capture: Path
    model: str
    authority: TheseusAuthority
    selected_repository: dict
    owner: str
    repository: str
    repository_id: int
    allowed_paths: frozenset[str]
    automation_mode: str
    github_credential: str = field(repr=False)
    model_origin: str
    model_credential: str = field(repr=False)

    def configuration_revision(self):
        return hashlib.sha256(canonical({"model": self.model, "model_origin": self.model_origin,
            "source": {"deployment": self.authority.deployment, "project": self.authority.project},
            "selected_repository": self.selected_repository, "owner": self.owner, "repository": self.repository,
            "repository_id": self.repository_id, "allowed_paths": sorted(self.allowed_paths),
            "automation_mode": self.automation_mode, "image": self.image}).encode()).hexdigest()

    def validate(self):
        self.release.selection()
        if self.configuration_revision() != self.release.authority_configuration_revision:
            raise Rejected("unsupported")
        if policy_revision() != self.release.policy_revision:
            raise Rejected("unsupported")
        if self.image != "sha256:" + self.release.confinement_revision:
            raise Rejected("unsupported")
        if hashlib.sha256(NATIVE_CONFIG.encode()).hexdigest() != self.release.native_configuration_revision:
            raise Rejected("unsupported")
        if not self.capture.is_absolute() or not self.capture.is_dir() or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", self.model):
            raise Rejected("unsupported")
        if (set(self.selected_repository) != {"canonical_ref", "repository", "worktree_root", "base"}
                or not all(isinstance(value, str) and value for value in self.selected_repository.values())):
            raise Rejected("unsupported")
        if self.selected_repository["canonical_ref"] != f"github:{self.owner}/{self.repository}":
            raise Rejected("unsupported")
        if self.automation_mode != "operator-isolated-actions-disabled":
            raise Rejected("unsupported")


class Runtime:
    def __init__(self, journal: Journal, profile: Profile):
        profile = replace(profile, selected_repository=json.loads(canonical(profile.selected_repository)),
                          allowed_paths=frozenset(profile.allowed_paths))
        profile.validate()
        self.journal, self.profile = journal, profile
        # One dequeue owner per Runtime instance. Durable journal fences still
        # protect correlation when multiple service processes receive requests.
        self.pending = {}
        self.children = Children(self)

    def capture(self, run_id, selection):
        p = self.profile
        p.validate()
        chosen = self.children.validate_selection(selection["child"]) if "child" in selection else None
        expected_repository = {**p.selected_repository, "base": chosen["commit"]} if chosen else p.selected_repository
        if chosen:
            self.children.initialize(run_id)
            selection = {**selection, "handoff": self.children.handoff(run_id, selection["handoff"])}
        if (set(selection) != ({"release", "source", "handoff", "child"} if chosen else {"release", "source", "handoff"})
                or selection["release"] != p.release.selection()
                or selection["source"] != {"deployment": p.authority.deployment, "project": p.authority.project}
                or not isinstance(selection["handoff"], dict)
                or set(selection["handoff"]) != {"workflow_identity", "workflow_revision", "workflow_revision_format", "runtime_release", "repository", "references"}
                or selection["handoff"].get("runtime_release") != p.release.selection()
                or selection["handoff"].get("workflow_revision_format") != "archon-immutable-closure-v1"
                or selection["handoff"].get("workflow_revision") != p.release.closure_revision
                or selection["handoff"].get("repository") != expected_repository
                or selection["handoff"].get("workflow_identity") != p.release.identity):
            raise Rejected("unsupported")
        references = selection["handoff"].get("references")
        repositories = references.get("repositories") if isinstance(references, dict) else None
        if (not isinstance(repositories, list) or (not chosen and len(repositories) != 1)
                or sum(isinstance(r, dict) and r.get("canonical_ref") == p.selected_repository["canonical_ref"] for r in repositories) != 1):
            raise Rejected("unsupported")
        temporary = tempfile.TemporaryDirectory(prefix="archon-confined-run-")
        root = Path(temporary.name).resolve()
        state = root / "state"
        cwd = chosen["workspace"] if chosen else "/workspace/repository"
        capture = state / "workspaces/_cwd" / Path(cwd).name / "artifacts/runs" / run_id / "workflow-source"
        capture.parent.mkdir(parents=True)
        try:
            stage(p.capture, capture)
            closure = inspect_closure(capture, p.release.identity, p.release.closure_revision)
        except Exception:
            temporary.cleanup()
            raise Rejected("source_mismatch") from None
        self.pending[run_id] = {"temporary": temporary, "root": root, "state": state, "capture": capture,
                                "finished": threading.Event(), "cwd": cwd, "child": chosen,
                                "sealed": {**closure, "runId": run_id, "cwd": cwd,
                                    "sourceRoot": "/input/approved-source", "captureRoot": str(capture),
                                    "workflowIdentity": p.release.identity, "model": p.model, "codexBinary": "/runtime/codex"}}
        self.journal.record_fact(run_id, "source", {"release": p.release.selection(), "native_digest": closure["workflowRevision"],
                                "image": p.image, "workflow_identity": p.release.identity})
        return closure["executableRevision"]

    def validate_authority(self, run_id, selection):
        context = self.profile.authority.check(self.children.handoff(run_id, selection["handoff"]) if "child" in selection else selection["handoff"])
        # Only the private context definition is transient. Selection and journal
        # retain references; neither persists copied mutable procedure text.
        self.pending[run_id]["context"] = context

    def _row(self, run_id):
        with self.journal.connect() as connection:
            row = connection.execute("SELECT * FROM confined_admissions WHERE run_id=?", (run_id,)).fetchone()
            if row is None:
                raise Rejected("unsupported")
            return dict(row)

    def refresh_and_create_worktree(self, run_id, selection):
        p = self.profile
        pending = self.pending[run_id]
        if "context" not in pending:
            raise Rejected("stale_scope")
        if "child" in selection:
            self.children.handoff(run_id, selection["handoff"])
            self.children.reserve(run_id, selection["child"])
        client = RepositoryHTTPS(p.owner, p.repository, p.github_credential)
        repository = client("GET", client.root, None)
        if repository.get("id") != p.repository_id or repository.get("full_name") != f"{p.owner}/{p.repository}":
            raise Rejected("unsupported")
        base = p.selected_repository["base"]
        if "child" in selection:
            commit = selection["child"]["allocation"]["children"]
            commit = next(c["commit"] for c in commit if c["child_id"] == selection["child"]["child_id"])
        else:
            reference = client("GET", client.root + "/git/ref/heads/" + base, None)
            commit = reference.get("object", {}).get("sha")
            if reference.get("ref") != "refs/heads/" + base or reference.get("object", {}).get("type") != "commit" or not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
                raise Rejected("unsupported")
        definition = client("GET", client.root + "/git/commits/" + commit, None)
        tree = definition.get("tree", {}).get("sha")
        if definition.get("sha") != commit or not isinstance(tree, str) or not re.fullmatch(r"[0-9a-f]{40}", tree):
            raise Rejected("unsupported")
        pending.update(commit=commit, tree=tree, client=client)
        self.journal.record_fact(run_id, "repository", {"repository_id": p.repository_id, "base": base, "commit": commit, "tree": tree})
        # Actual fetch and detached checkout happen inside OCI after the durable
        # invocation fence; no host Git process parses repository data.

    def invoke(self, run_id, selection):
        p = self.profile
        pending = self.pending[run_id]
        root, state, capture = (pending[key] for key in ("root", "state", "capture"))
        context = pending.pop("context")
        row = self._row(run_id)
        handoff = self.children.handoff(run_id, selection["handoff"]) if "child" in selection else selection["handoff"]
        references = handoff["references"]
        task_id = int(references["task"]["path"].rsplit("/", 1)[1])
        binding = Binding(p.authority.project, task_id, references["scope"]["selected"]["identity"],
                          references["work_unit"]["identity"], references["work_unit_graph"]["identity"], row["correlation"], run_id)
        def check():
            return p.authority.check(self.children.handoff(run_id, selection["handoff"]) if "child" in selection else selection["handoff"])
        publication_policy = PublicationPolicy(p.owner, p.repository, p.repository_id, run_id,
            p.selected_repository["base"], pending["commit"], pending["tree"], p.allowed_paths, pending["commit"], p.automation_mode)
        publisher = Publisher(publication_policy, pending["client"], check,
            lambda candidate: self.journal.retain_candidate(run_id, "publish", publication_operation[0], candidate))
        if "child" in selection:
            reporter = ObservationSink(self.journal, run_id, check)
        else:
            progress_client = HTTPS(Origin(urlsplit(p.authority.deployment).hostname, p.authority.credential), frozenset({("POST", binding.path)}))
            reporter = Reporter(binding, progress_client, check)
        exports = {}
        publication_operation = []
        def export(operation_id, request):
            output = validate(request)
            retain(output, root / output.digest)
            exports[output.digest] = output
            return {"export_id": output.digest}
        def publish(operation_id, request):
            publication_operation.append(operation_id)
            return publisher.publish(exports[request["export_id"]])
        def validate_receipt(kind, operation_id, request, response):
            if kind == "publish":
                publisher.validate_receipt(request, response)
            elif kind == "progress":
                reporter.validate_receipt(operation_id, request, response)
        actions = Actions(self.journal, run_id, export=export, publish=publish, progress=reporter.report,
                          validate_receipt=validate_receipt)
        repository = root / "empty-repository"
        repository.mkdir()
        config, request, seccomp = (root / name for name in ("native.toml", "request.json", "seccomp.json"))
        config.write_text(NATIVE_CONFIG)
        request.write_text(canonical({**pending["sealed"], "authoritativeContext": canonical(context),
                                     "repositorySelection": {"base": p.selected_repository["base"], "commit": pending["commit"],
                                         **({"workspace": pending["cwd"], "pinned": True} if "child" in selection else {})},
                                     **({"scopeReceipt": references["scope"]["selected"]} if "child" in selection else {}),
                                     "runtimeIdentity": {"workerRevision": p.release.worker_revision, "providerRevision": p.release.provider_revision,
                                         "nativeConfigurationRevision": p.release.native_configuration_revision}}))
        del context
        seccomp.write_text(canonical(seccomp_policy()))
        for target in tmpfs(state, capture, pending["cwd"] if "child" in selection else None):
            if Path(target).is_relative_to(state):
                Path(target).mkdir(parents=True, exist_ok=True)
        for entry in [state, *state.rglob("*"), repository, config, request]:
            entry.chmod(0o555 if entry.is_dir() or entry.stat().st_mode & 0o111 else 0o444)
        sockets = root / "sockets"
        sockets.mkdir(mode=0o700)
        lifecycle, model = None, None
        servers, started = [], []
        cleanup_errors = []
        try:
            lifecycle = Lifecycle(sockets / "lifecycle.sock", run_id, authorize=check,
                consume=(lambda scope: self.children.consumed(run_id, scope)) if "child" in selection else None)
            model = ModelPolicy(p.model_origin, p.model, p.model_credential)
            servers.append(ModelBroker(sockets / "model.sock", model))
            servers.append(ActionServer(sockets / "actions.sock", actions))
            pending["actions"] = servers[1]
            servers.append(GitBroker(sockets / "git.sock", GitPolicy(p.owner, p.repository, pending["commit"], p.github_credential)))
            for name in ("model.sock", "actions.sock", "git.sock"):
                (sockets / name).chmod(0o666)
            for server in servers:
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                started.append((server, thread))
            result = run(Inputs(p.image, request, repository, state, capture, config,
                sockets / "model.sock", sockets / "actions.sock", sockets / "lifecycle.sock", seccomp, sockets / "git.sock", pending["cwd"] if "child" in selection else None),
                retain_owner=lambda owner: self.journal.record_fact(run_id, "container", owner),
                authorize_start=check)
            servers[1].seal_and_drain()
            outcome = lifecycle.await_outcome()
            if result.returncode != 0 or result.timed_out:
                raise RuntimeError("container_outcome_uncertain")
            return outcome
        finally:
            # Every acquired resource participates even when later construction,
            # container start, attach or cleanup fails. Stop new effects first.
            for server in servers:
                if hasattr(server, "seal_and_drain"):
                    try:
                        server.seal_and_drain()
                    except Exception:
                        cleanup_errors.append("callbacks_not_drained")
            if model is not None:
                model.close()
            for server, thread in started:
                server.shutdown()
                thread.join(5)
                if thread.is_alive():
                    cleanup_errors.append("broker_not_stopped")
            for server in servers:
                server.server_close()
            if lifecycle is not None:
                lifecycle.close()
                if not lifecycle.finished.wait(5):
                    cleanup_errors.append("lifecycle_not_stopped")
                elif lifecycle.rejection is not None:
                    self.journal.record_fact(run_id, "bootstrap", {"rejection": lifecycle.rejection})
            if cleanup_errors:
                pending["cleanup_blocked"] = True
                raise RuntimeError("runtime_cleanup_uncertain")

    def cleanup(self, run_id):
        pending = self.pending.get(run_id)
        if pending is None:
            return
        if pending.get("cleanup_blocked"):
            raise RuntimeError("runtime_cleanup_uncertain")
        self.pending.pop(run_id)
        state = pending["state"]
        for entry in [state, *state.rglob("*")]:
            entry.chmod(0o700 if entry.is_dir() else 0o600)
        pending["temporary"].cleanup()
        pending["finished"].set()
