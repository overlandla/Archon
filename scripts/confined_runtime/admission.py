"""Experimental trusted admission sequence, separate from model/tool execution.

No deployment is supported by this module alone. Policy implementations are
trusted supervisor code, never callbacks supplied in a launch request. A release
must validate and pin those implementations along with the worker and provider.
"""
from dataclasses import dataclass
import json
import re
from typing import Protocol

from .journal import Journal, canonical


class Rejected(RuntimeError):
    def __init__(self, diagnostic):
        if diagnostic not in {"stale_scope", "stale_guidance", "source_mismatch", "unsupported"}:
            raise ValueError("unbounded_rejection_diagnostic")
        self.diagnostic = diagnostic
        super().__init__(diagnostic)


@dataclass(frozen=True)
class Release:
    identity: str
    closure_revision: str
    worker_revision: str
    provider_revision: str
    confinement_revision: str
    policy_revision: str

    def selection(self):
        values = vars(self)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", self.identity):
            raise ValueError("invalid_release_identity")
        if any(not re.fullmatch(r"[0-9a-f]{64}", value) for key, value in values.items() if key != "identity"):
            raise ValueError("invalid_release_revision")
        return {"format": "archon-confined-experimental-v1", **values}


class TrustedPolicy(Protocol):
    def capture(self, run_id: str, selection: dict) -> str:
        """Stage a bounded complete closure without repository mutation; return its digest."""
    def validate_authority(self, selection: dict) -> None:
        """Retrieve current source authority after dequeue, fail closed on every read error."""
    def refresh_and_create_worktree(self, run_id: str, selection: dict) -> None:
        """Refresh only approved base and create a private worktree; retain resolved commit."""
    def invoke(self, run_id: str, selection: dict) -> None:
        """Invoke the sealed engine once under independently enforced confinement."""


class Supervisor:
    def __init__(self, journal: Journal, release: Release, policy: TrustedPolicy):
        self.journal, self.release, self.policy = journal, release, policy

    def admit(self, deployment: str, project: int, correlation: str, selection: dict) -> dict:
        # Requests cannot choose an executable, model binary, enforcement policy
        # or closure format through a version string/capability advertisement.
        if selection.get("release") != self.release.selection():
            raise Rejected("unsupported")
        if selection.get("source") != {"deployment": deployment, "project": project}:
            raise Rejected("unsupported")
        return self.journal.admit(deployment, project, correlation, selection)

    def dequeue(self, run_id: str, expected_revision: int) -> dict:
        # Durable exclusive ownership precedes even repository refresh. Any
        # interrupted checking state stays blocked; restart is not a retry lease.
        row = self.journal.transition(run_id, expected_revision, "check")
        selection = json.loads(row["selection"])
        try:
            if canonical(selection.get("release")) != canonical(self.release.selection()):
                raise Rejected("unsupported")
            captured = self.policy.capture(run_id, selection)
            if captured != self.release.closure_revision:
                raise Rejected("source_mismatch")
            self.policy.validate_authority(selection)
            self.policy.refresh_and_create_worktree(run_id, selection)
            row = self.journal.transition(run_id, row["revision"], "invoke")
            self.policy.invoke(run_id, selection)
            return self.journal.transition(run_id, row["revision"], "finish")
        except Rejected as exc:
            if row["state"] != "checking":
                return self.journal.transition(run_id, row["revision"], "uncertain")
            return self.journal.transition(run_id, row["revision"], exc.diagnostic)
        except Exception:
            # Includes partial worktree preparation, launch failure and a lost
            # worker result. Never infer from an exception that invocation is safe.
            return self.journal.transition(run_id, row["revision"], "uncertain")
