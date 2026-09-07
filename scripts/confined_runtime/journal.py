"""Durable admission identity and irreversible invocation fences.

Owned by the supervisor outside the worker mounts. No timer, replay or restart
authorizes a second invocation. A deployment must protect this database from
workers and from other identities that can modify its filesystem.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import sqlite3
from uuid import uuid4


class AdmissionConflict(RuntimeError):
    pass


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


class Journal:
    def __init__(self, path: Path):
        self.path = path
        with self.connect() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS confined_admissions (
                    run_id TEXT PRIMARY KEY, deployment TEXT NOT NULL,
                    project INTEGER NOT NULL, correlation TEXT NOT NULL,
                    selection TEXT NOT NULL, selection_digest TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'admitted', revision INTEGER NOT NULL DEFAULT 0,
                    diagnostic TEXT NOT NULL DEFAULT 'admitted',
                    UNIQUE(deployment, project, correlation)
                );
                CREATE TABLE IF NOT EXISTS confined_transitions (
                    run_id TEXT NOT NULL REFERENCES confined_admissions(run_id),
                    revision INTEGER NOT NULL, state TEXT NOT NULL, diagnostic TEXT NOT NULL,
                    PRIMARY KEY(run_id, revision)
                );
            """)

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
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
