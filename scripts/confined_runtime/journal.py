"""Durable admission identity and irreversible invocation fences.

Owned by the supervisor outside the worker mounts. No timer, replay or restart
authorizes a second invocation. A deployment must protect this database from
workers and from other identities that can modify its filesystem.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4


class AdmissionConflict(RuntimeError):
    pass


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


class Journal:
    def __init__(self, path: Path):
        self.path = path
        with self.connect() as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            existing = connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall()
            if version not in (0, 1) or (version == 0 and existing):
                raise ValueError("unsupported_journal_schema")
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS confined_admissions (
                    run_id TEXT PRIMARY KEY, deployment TEXT NOT NULL,
                    project INTEGER NOT NULL, correlation TEXT NOT NULL,
                    selection TEXT NOT NULL, selection_digest TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'admitted', revision INTEGER NOT NULL DEFAULT 0,
                    diagnostic TEXT NOT NULL DEFAULT 'admitted',
                    UNIQUE(deployment, project, correlation)
                );
                CREATE TABLE IF NOT EXISTS confined_child_control (
                    run_id TEXT PRIMARY KEY REFERENCES confined_admissions(run_id), revision INTEGER NOT NULL DEFAULT 0,
                    stopped INTEGER NOT NULL DEFAULT 0, blocked INTEGER NOT NULL DEFAULT 0, notice_ack INTEGER NOT NULL DEFAULT 0, successor TEXT, consumed TEXT,
                    handoff TEXT, notice TEXT, decision TEXT, stop_intent TEXT
                );
                CREATE TABLE IF NOT EXISTS confined_child_observations (
                    run_id TEXT PRIMARY KEY REFERENCES confined_admissions(run_id), revision INTEGER NOT NULL, value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS confined_run_facts (
                    run_id TEXT NOT NULL REFERENCES confined_admissions(run_id),
                    name TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY(run_id, name)
                );
                CREATE TABLE IF NOT EXISTS confined_transitions (
                    run_id TEXT NOT NULL REFERENCES confined_admissions(run_id),
                    revision INTEGER NOT NULL, state TEXT NOT NULL, diagnostic TEXT NOT NULL,
                    PRIMARY KEY(run_id, revision)
                );
                CREATE TABLE IF NOT EXISTS confined_effect_candidates (
                    run_id TEXT NOT NULL, kind TEXT NOT NULL, operation_id TEXT NOT NULL,
                    candidate TEXT NOT NULL, PRIMARY KEY(run_id, kind, operation_id),
                    FOREIGN KEY(run_id, kind, operation_id) REFERENCES confined_effects(run_id, kind, operation_id)
                );
                CREATE TABLE IF NOT EXISTS confined_effects (
                    run_id TEXT NOT NULL REFERENCES confined_admissions(run_id),
                    kind TEXT NOT NULL, operation_id TEXT NOT NULL,
                    request TEXT NOT NULL, request_digest TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'started', response TEXT,
                    PRIMARY KEY(run_id, kind, operation_id)
                );
            """)
            connection.execute("PRAGMA user_version=1")

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        if connection.execute("PRAGMA page_size").fetchone()[0] != 4096:
            connection.close()
            raise ValueError("unsupported_journal_page_size")
        connection.execute("PRAGMA max_page_count=131072")  # 512 MiB durable state budget
        connection.execute("PRAGMA journal_size_limit=16777216")
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def admit(self, deployment: str, project: int, correlation: str, selection: dict) -> dict:
        if not deployment or type(project) is not int or project <= 0 or not 0 < len(correlation) <= 200:
            raise ValueError("invalid_admission_identity")
        encoded = canonical(selection)
        if len(encoded) > 1024 * 1024:
            raise ValueError("selection_too_large")
        digest = hashlib.sha256(encoded.encode()).hexdigest()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            run_id = str(uuid4())
            inserted = connection.execute(
                """INSERT INTO confined_admissions
                (run_id, deployment, project, correlation, selection, selection_digest)
                VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(deployment, project, correlation) DO NOTHING""",
                (run_id, deployment, project, correlation, encoded, digest),
            ).rowcount
            row = connection.execute(
                "SELECT * FROM confined_admissions WHERE deployment=? AND project=? AND correlation=?",
                (deployment, project, correlation),
            ).fetchone()
            if row["selection"] != encoded:
                raise AdmissionConflict("correlation_selection_conflict")
            if inserted and "child" in selection:
                connection.execute("INSERT INTO confined_child_control(run_id) VALUES (?)", (run_id,))
            if inserted:
                connection.execute("INSERT INTO confined_transitions VALUES (?, 0, 'admitted', 'admitted')", (run_id,))
            return dict(row)

    def find(self, deployment: str, project: int, correlation: str) -> list[dict]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM confined_admissions WHERE deployment=? AND project=? AND correlation=?",
                (deployment, project, correlation),
            ).fetchall()
            return [dict(row) for row in rows]

    def transition(self, run_id: str, revision: int, event: str) -> dict:
        transitions = {
            "check": ({"admitted"}, "checking"),
            "invoke": ({"checking"}, "invoking"),
            "finish": ({"invoking"}, "finished"),
            "stale_scope": ({"checking"}, "rejected"),
            "stale_guidance": ({"checking"}, "rejected"),
            "source_mismatch": ({"checking"}, "rejected"),
            "unsupported": ({"checking"}, "rejected"),
            "uncertain": ({"checking", "invoking"}, "uncertain"),
        }
        if event not in transitions:
            raise ValueError("unsupported_admission_transition")
        allowed, state = transitions[event]
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM confined_admissions WHERE run_id=?", (run_id,)).fetchone()
            if row is None or row["revision"] != revision or row["state"] not in allowed:
                raise AdmissionConflict("stale_admission_transition")
            if event in {"check", "invoke", "finish"}:
                control = connection.execute("SELECT stopped, blocked FROM confined_child_control WHERE run_id=?", (run_id,)).fetchone()
                if control and (control["stopped"] or control["blocked"]):
                    raise AdmissionConflict("child_execution_fenced")
            if event == "finish" and connection.execute(
                "SELECT 1 FROM confined_effects WHERE run_id=? AND state IN ('started', 'uncertain') LIMIT 1",
                (run_id,),
            ).fetchone() is not None:
                raise AdmissionConflict("unresolved_effects_block_completion")
            connection.execute(
                "UPDATE confined_admissions SET state=?, revision=revision+1, diagnostic=? WHERE run_id=?",
                (state, event, run_id),
            )
            connection.execute("INSERT INTO confined_transitions VALUES (?, ?, ?, ?)",
                               (run_id, revision + 1, state, event))
            return dict(connection.execute("SELECT * FROM confined_admissions WHERE run_id=?", (run_id,)).fetchone())

    def interrupted(self) -> list[dict]:
        """Observe uncertain ownership without guessing whether another process is alive."""
        with self.connect() as connection:
            return [dict(row) for row in connection.execute(
                "SELECT * FROM confined_admissions WHERE state IN ('checking', 'invoking', 'uncertain')"
            ).fetchall()]

    def begin_effect(self, run_id: str, kind: str, operation_id: str, request: dict) -> tuple[dict, bool]:
        limits = {"export": 8, "publish": 1, "progress": 8}
        if kind not in limits or not isinstance(operation_id, str) or not 0 < len(operation_id) <= 100:
            raise ValueError("invalid_effect_identity")
        encoded = canonical(request)
        if len(encoded) > 12 * 1024 * 1024:
            raise ValueError("effect_request_too_large")
        digest = hashlib.sha256(encoded.encode()).hexdigest()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            previous = connection.execute(
                "SELECT * FROM confined_effects WHERE run_id=? AND kind=? AND operation_id=?",
                (run_id, kind, operation_id),
            ).fetchone()
            if previous is not None:
                if previous["request"] != encoded:
                    raise AdmissionConflict("effect_identity_conflict")
                return dict(previous), False
            control = connection.execute("SELECT stopped, blocked FROM confined_child_control WHERE run_id=?", (run_id,)).fetchone()
            if control and (control["stopped"] or control["blocked"]):
                raise AdmissionConflict("child_effect_fenced")
            row = connection.execute("SELECT state FROM confined_admissions WHERE run_id=?", (run_id,)).fetchone()
            if row is None or row["state"] != "invoking":
                raise AdmissionConflict("effect_outside_invocation")
            if connection.execute(
                "SELECT 1 FROM confined_effects WHERE run_id=? AND kind=? AND state IN ('started', 'uncertain') LIMIT 1",
                (run_id, kind),
            ).fetchone() is not None:
                raise AdmissionConflict("unresolved_predecessor_effect")
            count = connection.execute("SELECT count(*) FROM confined_effects WHERE run_id=? AND kind=?", (run_id, kind)).fetchone()[0]
            if count >= limits[kind]:
                raise AdmissionConflict("effect_limit_exceeded")
            connection.execute("INSERT INTO confined_effects (run_id, kind, operation_id, request, request_digest) VALUES (?, ?, ?, ?, ?)",
                               (run_id, kind, operation_id, encoded, digest))
            return dict(connection.execute("SELECT * FROM confined_effects WHERE run_id=? AND kind=? AND operation_id=?",
                                           (run_id, kind, operation_id)).fetchone()), True

    def finish_effect(self, run_id: str, kind: str, operation_id: str, state: str, response: dict | None = None) -> dict:
        if state not in {"acknowledged", "uncertain", "rejected"}:
            raise ValueError("invalid_effect_state")
        encoded = canonical(response) if response is not None else None
        if encoded is not None and len(encoded) > 16384:
            raise ValueError("effect_response_too_large")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            changed = connection.execute("UPDATE confined_effects SET state=?, response=? WHERE run_id=? AND kind=? AND operation_id=? AND state='started'",
                                         (state, encoded, run_id, kind, operation_id)).rowcount
            if changed != 1:
                raise AdmissionConflict("effect_completion_conflict")
            return dict(connection.execute("SELECT * FROM confined_effects WHERE run_id=? AND kind=? AND operation_id=?",
                                           (run_id, kind, operation_id)).fetchone())

    def has_acknowledged_export(self, run_id: str, export_id: str) -> bool:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT response FROM confined_effects WHERE run_id=? AND kind='export' AND state='acknowledged'",
                (run_id,),
            ).fetchall()
            return any(json.loads(row["response"]) == {"export_id": export_id} for row in rows)

    def retain_candidate(self, run_id: str, kind: str, operation_id: str, candidate: dict) -> None:
        encoded = canonical(candidate)
        if len(encoded) > 16384:
            raise ValueError("effect_candidate_too_large")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            effect = connection.execute("SELECT state FROM confined_effects WHERE run_id=? AND kind=? AND operation_id=?",
                                        (run_id, kind, operation_id)).fetchone()
            if effect is None or effect["state"] != "started":
                raise AdmissionConflict("candidate_outside_effect")
            connection.execute("INSERT INTO confined_effect_candidates VALUES (?, ?, ?, ?)",
                               (run_id, kind, operation_id, encoded))

    def candidate(self, run_id: str, kind: str, operation_id: str) -> dict | None:
        with self.connect() as connection:
            row = connection.execute("SELECT candidate FROM confined_effect_candidates WHERE run_id=? AND kind=? AND operation_id=?",
                                     (run_id, kind, operation_id)).fetchone()
            return json.loads(row["candidate"]) if row is not None else None

    def record_fact(self, run_id: str, name: str, value: dict) -> None:
        child_progress = name.startswith("child_progress:") and 0 < len(name.removeprefix("child_progress:")) <= 100
        if (name not in {"source", "repository", "engine", "container", "bootstrap", "child_workspace", "owner_drained"} and not child_progress) or len(canonical(value)) > 16384:
            raise ValueError("invalid_runtime_fact")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT state FROM confined_admissions WHERE run_id=?", (run_id,)).fetchone()
            allowed = {"invoking"} if name in {"engine", "container", "bootstrap"} or child_progress else {"checking"}
            if name == "owner_drained":
                allowed = {"finished", "uncertain", "rejected"}
                if value != {"drained": True}:
                    raise ValueError("invalid_owner_drain_fact")
            if row is None or row["state"] not in allowed:
                raise AdmissionConflict("fact_outside_admission_phase")
            connection.execute("INSERT INTO confined_run_facts VALUES (?, ?, ?)", (run_id, name, canonical(value)))

    def facts(self, run_id: str) -> dict:
        with self.connect() as connection:
            return {row["name"]: json.loads(row["value"]) for row in connection.execute(
                "SELECT name, value FROM confined_run_facts WHERE run_id=?", (run_id,)).fetchall()}

    def inspect_run(self, run_id: str) -> tuple[dict, dict]:
        with self.connect() as connection:
            connection.execute("BEGIN")
            row = connection.execute("SELECT * FROM confined_admissions WHERE run_id=?", (run_id,)).fetchone()
            if row is None:
                raise ValueError("run_not_found")
            facts = {fact["name"]: json.loads(fact["value"]) for fact in connection.execute(
                "SELECT name, value FROM confined_run_facts WHERE run_id=?", (run_id,)).fetchall()}
            return dict(row), facts

    def effect_projection(self, run_id: str) -> list[dict]:
        with self.connect() as connection:
            rows = connection.execute("SELECT e.kind, e.operation_id, e.request_digest, e.state, e.response, c.candidate FROM confined_effects e LEFT JOIN confined_effect_candidates c USING(run_id, kind, operation_id) WHERE e.run_id=? ORDER BY e.kind, e.operation_id", (run_id,)).fetchall()
            return [{**{key: row[key] for key in ("kind", "operation_id", "request_digest", "state")},
                     "receipt": json.loads(row["response"]) if row["response"] else None,
                     "candidate": json.loads(row["candidate"]) if row["candidate"] else None} for row in rows]
