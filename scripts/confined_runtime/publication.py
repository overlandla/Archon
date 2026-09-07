"""Construct a commit and a new draft-PR branch from retained regular files.

The worker supplies no Git commands, repository, ref, commit metadata or PR text.
Only a trusted per-run integration invokes this publisher, after Actions has
persisted its irreversible publication fence. Any partial failure is uncertain;
calling publish again is never a recovery mechanism.
"""
import base64
import re
from collections.abc import Callable
from dataclasses import dataclass
from uuid import UUID

from .exports import Export, relative_path


class PublicationRejected(RuntimeError):
    pass


def sha(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
        raise PublicationRejected("unsupported_git_object_identity")
    return value


@dataclass(frozen=True)
class Policy:
    owner: str
    repository: str
    repository_id: int
    run_id: str
    base: str
    base_commit: str
    base_tree: str
    # Explicit reviewed publication paths. Authorization to push requires an
    # operator-owned automation assessment for this exact refreshed base.
    allowed_paths: frozenset[str]
    automation_base: str
    automation_mode: str = "unsupported"

    def validate(self):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,99}", self.owner):
            raise PublicationRejected("invalid_repository")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", self.repository):
            raise PublicationRejected("invalid_repository")
        if type(self.repository_id) is not int or self.repository_id <= 0 or str(UUID(self.run_id)) != self.run_id:
            raise PublicationRejected("invalid_publication_identity")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_/-]{0,199}", self.base) or "//" in self.base:
            raise PublicationRejected("unsupported_base_ref")
        sha(self.base_commit)
        sha(self.base_tree)
        if self.automation_base != self.base_commit or self.automation_mode != "operator-isolated-actions-disabled":
            raise PublicationRejected("unreviewed_repository_automation")
        for path in self.allowed_paths:
            relative_path(path)
            if any(part.casefold() in {".github", ".gitlab", ".buildkite", ".circleci", ".githooks"}
                   for part in path.split("/")) or path.split("/")[-1].casefold() in {
                       ".gitmodules", ".gitattributes", ".gitlab-ci.yml", "jenkinsfile", ".drone.yml"}:
                raise PublicationRejected("automation_path_not_publishable")

    @property
    def branch(self):
        return "archon/handoff/" + self.run_id

    @property
    def root(self):
        return f"/repos/{self.owner}/{self.repository}"


class Publisher:
    def __init__(self, policy: Policy, request: Callable[[str, str, dict | None], dict],
                 check_authority: Callable[[], None], retain_candidate: Callable[[dict], None]):
        policy.validate()
        self.policy, self.request, self.check_authority = policy, request, check_authority
        self.retain_candidate = retain_candidate

    def publish(self, export: Export) -> dict:
        policy = self.policy
        paths = {file.path for file in export.files} | set(export.deletions)
        if not paths or not paths <= policy.allowed_paths:
            raise PublicationRejected("export_outside_publication_authority")
        self.check_authority()
        repository = self.request("GET", policy.root, None)
        if repository.get("id") != policy.repository_id or repository.get("full_name") != f"{policy.owner}/{policy.repository}" or repository.get("archived") is not False:
            raise PublicationRejected("repository_identity_changed")
        base = self.request("GET", policy.root + "/git/ref/heads/" + policy.base, None)
        if base.get("ref") != "refs/heads/" + policy.base or (base.get("object", {}).get("type") != "commit" or base.get("object", {}).get("sha") != policy.base_commit):
            raise PublicationRejected("refreshed_base_changed")
        commit = self.request("GET", policy.root + "/git/commits/" + policy.base_commit, None)
        if commit.get("sha") != policy.base_commit or commit.get("tree", {}).get("sha") != policy.base_tree:
            raise PublicationRejected("base_tree_mismatch")
        self.check_automation()
        base_entries = self.tree_entries(policy.base_tree)
        for path in paths:
            entry = base_entries.get(path)
            if entry is not None and (entry["type"] != "blob" or entry["mode"] not in {"100644", "100755"}):
                raise PublicationRejected("non_regular_base_path")
            if path in export.deletions and entry is None:
                raise PublicationRejected("missing_deletion_path")
            pieces = path.split("/")
            for depth in range(1, len(pieces)):
                ancestor = base_entries.get("/".join(pieces[:depth]))
                if ancestor is not None and ancestor["type"] != "tree":
                    raise PublicationRejected("non_directory_base_ancestor")
        tree = []
        for file in sorted(export.files, key=lambda file: file.path):
            blob = self.request("POST", policy.root + "/git/blobs", {
                "content": base64.b64encode(file.data).decode(), "encoding": "base64"})
            tree.append({"path": file.path, "mode": "100755" if file.executable else "100644", "type": "blob", "sha": sha(blob.get("sha"))})
        tree.extend({"path": path, "mode": "100644", "type": "blob", "sha": None} for path in sorted(export.deletions))
        built_tree = self.request("POST", policy.root + "/git/trees", {"base_tree": policy.base_tree, "tree": tree})
        tree_sha = sha(built_tree.get("sha"))
        actual_entries = self.tree_entries(tree_sha)
        expected_leaves = {path: entry for path, entry in base_entries.items() if entry["type"] != "tree"}
        for entry in tree:
            if entry["sha"] is None:
                expected_leaves.pop(entry["path"])
            else:
                expected_leaves[entry["path"]] = {key: entry[key] for key in ("mode", "type", "sha")}
        if {path: entry for path, entry in actual_entries.items() if entry["type"] != "tree"} != expected_leaves:
            raise PublicationRejected("constructed_tree_exceeds_authority")
        for path in set(base_entries) | set(actual_entries):
            if base_entries.get(path) != actual_entries.get(path) and path not in paths and not any(name.startswith(path + "/") for name in paths):
                raise PublicationRejected("constructed_tree_exceeds_authority")
        built_commit = self.request("POST", policy.root + "/git/commits", {
            "message": "Implement confined handoff " + policy.run_id,
            "tree": tree_sha, "parents": [policy.base_commit]})
        commit_sha = sha(built_commit.get("sha"))
        if built_commit.get("tree", {}).get("sha") != tree_sha or [parent.get("sha") for parent in built_commit.get("parents", [])] != [policy.base_commit]:
            raise PublicationRejected("constructed_commit_mismatch")
        # Revalidation also bounds the publication phase. No reference mutation
        # occurs until it succeeds. The new-ref endpoint cannot overwrite a ref.
        self.retain_candidate({"repository_id": policy.repository_id, "commit": commit_sha,
                               "branch": policy.branch, "base": policy.base, "export_id": export.digest})
        self.check_authority()
        self.check_automation()
        current = self.request("GET", policy.root + "/git/ref/heads/" + policy.base, None)
        if current.get("ref") != "refs/heads/" + policy.base or current.get("object", {}).get("sha") != policy.base_commit:
            raise PublicationRejected("refreshed_base_changed")
        ref = "refs/heads/" + policy.branch
        created = self.request("POST", policy.root + "/git/refs", {"ref": ref, "sha": commit_sha})
        if created.get("ref") != ref or created.get("object", {}).get("sha") != commit_sha:
            raise PublicationRejected("publication_ref_uncertain")
        pull = self.request("POST", policy.root + "/pulls", {
            "title": "Implement confined handoff " + policy.run_id,
            "body": "Runtime correlation: `" + policy.run_id + "`\n\nExport SHA-256: `" + export.digest + "`",
            "head": policy.branch, "base": policy.base, "draft": True, "maintainer_can_modify": False})
        self.validate_pull(pull, commit_sha)
        return {"repository_id": policy.repository_id, "commit": commit_sha, "branch": policy.branch,
                "pull_request": pull["number"], "url": pull["html_url"], "export_id": export.digest}

    def validate_pull(self, pull: dict, commit: str):
        policy = self.policy
        number = pull.get("number")
        if type(number) is not int or number <= 0 or pull.get("draft") is not True or pull.get("state") != "open":
            raise PublicationRejected("publication_pr_uncertain")
        if pull.get("html_url") != f"https://github.com/{policy.owner}/{policy.repository}/pull/{number}":
            raise PublicationRejected("publication_pr_uncertain")
        head, base = pull.get("head", {}), pull.get("base", {})
        if head.get("ref") != policy.branch or head.get("sha") != commit or base.get("ref") != policy.base or base.get("sha") != policy.base_commit:
            raise PublicationRejected("publication_pr_uncertain")
        if any(side.get("repo", {}).get("id") != policy.repository_id for side in (head, base)):
            raise PublicationRejected("publication_pr_uncertain")

    def validate_receipt(self, request, response):
        p = self.policy
        if set(response) != {"repository_id", "commit", "branch", "pull_request", "url", "export_id"}:
            raise PublicationRejected("invalid_publication_receipt")
        sha(response["commit"])
        number = response["pull_request"]
        if (type(number) is not int or number <= 0 or response["repository_id"] != p.repository_id
                or response["branch"] != p.branch or response["export_id"] != request["export_id"]
                or response["url"] != f"https://github.com/{p.owner}/{p.repository}/pull/{number}"):
            raise PublicationRejected("invalid_publication_receipt")

    def inspect_candidate(self, candidate: dict, pulls: list[dict], retained_request: dict) -> dict:
        """Read-only recovery. Missing/foreign/multiple results remain blocked.

        The caller must retrieve a complete bounded list of PRs for this exact
        source repository/head/base; truncation is not absence. No write or
        journal disposition occurs here.
        """
        p = self.policy
        if (set(candidate) != {"repository_id", "commit", "branch", "base", "export_id"}
                or candidate["repository_id"] != p.repository_id or candidate["branch"] != p.branch
                or candidate["base"] != p.base):
            raise PublicationRejected("foreign_publication_candidate")
        if (retained_request != {"export_id": candidate["export_id"]}
                or not isinstance(candidate["export_id"], str) or not re.fullmatch(r"[0-9a-f]{64}", candidate["export_id"])):
            raise PublicationRejected("foreign_publication_candidate")
        commit = sha(candidate["commit"])
        ref = self.request("GET", p.root + "/git/ref/heads/" + p.branch, None)
        if ref.get("ref") != "refs/heads/" + p.branch or ref.get("object", {}).get("sha") != commit:
            raise PublicationRejected("publication_recovery_ambiguous")
        if len(pulls) != 1:
            raise PublicationRejected("publication_recovery_ambiguous")
        self.validate_pull(pulls[0], commit)
        response = {"repository_id": p.repository_id, "commit": commit, "branch": p.branch,
                    "pull_request": pulls[0]["number"], "url": pulls[0]["html_url"], "export_id": candidate["export_id"]}
        self.validate_receipt({"export_id": candidate["export_id"]}, response)
        return response

    def check_automation(self):
        # The operator-owned profile must separately isolate all external event
        # consumers for the run lifetime. This API check enforces GitHub Actions
        # denial; base-SHA checks alone cannot constrain concurrent automation.
        response = self.request("GET", self.policy.root + "/actions/permissions", None)
        if response.get("enabled") is not False:
            raise PublicationRejected("repository_actions_not_disabled")

    def tree_entries(self, revision):
        response = self.request("GET", self.policy.root + "/git/trees/" + revision + "?recursive=1", None)
        if response.get("sha") != revision or response.get("truncated") is not False or not isinstance(response.get("tree"), list) or len(response["tree"]) > 100000:
            raise PublicationRejected("incomplete_publication_tree")
        result = {}
        for entry in response["tree"]:
            if not isinstance(entry, dict) or not isinstance(entry.get("path"), str) or entry["path"] in result:
                raise PublicationRejected("ambiguous_publication_tree")
            kind, mode = entry.get("type"), entry.get("mode")
            if (kind, mode) not in {("blob", "100644"), ("blob", "100755"), ("blob", "120000"), ("tree", "040000"), ("commit", "160000")}:
                raise PublicationRejected("unsupported_publication_tree")
            result[entry["path"]] = {"type": kind, "mode": mode, "sha": sha(entry.get("sha"))}
        return result
