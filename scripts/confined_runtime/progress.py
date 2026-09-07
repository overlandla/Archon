"""Task-bound implementation progress, independent of verification and readiness."""
import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True)
class Binding:
    project_id: int
    task_id: int
    scope_revision_id: str
    work_unit_id: str
    graph_revision_id: str
    correlation_id: str
    run_id: str

    def __post_init__(self):
        if any(type(value) is not int or value <= 0 for value in (self.project_id, self.task_id)):
            raise ValueError("invalid_progress_source")
        for value in (self.scope_revision_id, self.work_unit_id, self.graph_revision_id, self.run_id):
            if str(UUID(value)) != value:
                raise ValueError("invalid_progress_identity")
        if not isinstance(self.correlation_id, str) or not 0 < len(self.correlation_id) <= 200:
            raise ValueError("invalid_progress_correlation")

    @property
    def path(self):
        return f"/api/projects/{self.project_id}/tasks/{self.task_id}/implementation-reports"

    def submission(self, operation_id):
        return "archon:" + hashlib.sha256((self.run_id + "\0" + operation_id).encode()).hexdigest()


class Reporter:
    def __init__(self, binding: Binding, request: Callable[[str, str, dict], dict],
                 check_authority: Callable[[], None]):
        self.binding, self.request, self.check_authority = binding, request, check_authority

    def report(self, operation_id: str, value: dict) -> dict:
        if set(value) != {"progress"} or value["progress"] not in ("not-started", "in-progress", "blocked", "complete"):
            raise ValueError("unsupported_progress")
        self.check_authority()
        b = self.binding
        body = {"scope_revision_id": b.scope_revision_id, "work_unit_id": b.work_unit_id,
                "submission_id": b.submission(operation_id), "correlation_id": b.correlation_id,
                "progress": value["progress"], "code_artifacts": [], "diagnostics": []}
        response = self.request("POST", b.path, body)
        report = response.get("report")
        if type(response.get("created")) is not bool or not isinstance(report, dict):
            raise RuntimeError("progress_acknowledgement_uncertain")
        expected = {**body, "project_id": b.project_id, "task_id": b.task_id, "graph_revision_id": b.graph_revision_id}
        if any(report.get(key) != value for key, value in expected.items()):
            raise RuntimeError("progress_acknowledgement_uncertain")
        report_id = report.get("id")
        if not isinstance(report_id, str) or str(UUID(report_id)) != report_id:
            raise RuntimeError("progress_acknowledgement_uncertain")
        return {"report_id": report_id, **expected}

    def validate_receipt(self, operation_id, request, response):
        b = self.binding
        expected = {"scope_revision_id": b.scope_revision_id, "work_unit_id": b.work_unit_id,
                    "submission_id": b.submission(operation_id), "correlation_id": b.correlation_id,
                    "progress": request["progress"], "code_artifacts": [], "diagnostics": [],
                    "project_id": b.project_id, "task_id": b.task_id, "graph_revision_id": b.graph_revision_id}
        if set(response) != {*expected, "report_id"} or any(response[key] != value for key, value in expected.items()):
            raise RuntimeError("progress_receipt_mismatch")
        if str(UUID(response["report_id"])) != response["report_id"]:
            raise RuntimeError("progress_receipt_mismatch")
