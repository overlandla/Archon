"""Typed action dispatch outside the worker, with durable no-retry fences.

Callbacks are trusted integrations, never worker supplied commands. A callback
must return only after an external acknowledgement; an exception, cancellation,
process death or invalid receipt leaves the durable operation blocked. This
module does not turn an unimplemented publisher into a supported capability.
"""
import json
import re
from collections.abc import Callable

from .exports import validate
from .journal import AdmissionConflict, Journal, canonical


class ActionDenied(ValueError):
    pass


class ActionUncertain(RuntimeError):
    pass


class Actions:
    def __init__(self, journal: Journal, run_id: str, *,
                 export: Callable[[str, dict], dict],
                 publish: Callable[[str, dict], dict],
                 progress: Callable[[str, dict], dict],
                 validate_receipt: Callable[[str, str, dict, dict], None]):
        self.journal = journal
        self.run_id = run_id
        self.validate_receipt = validate_receipt
        self.callbacks = {"export": export, "publish": publish, "progress": progress}

    def perform(self, value: object) -> dict:
        if not isinstance(value, dict) or set(value) != {"operation_id", "kind", "request"}:
            raise ActionDenied("invalid_action")
        operation_id, kind, request = value["operation_id"], value["kind"], value["request"]
        if not isinstance(operation_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", operation_id):
            raise ActionDenied("invalid_action_identity")
        if not isinstance(kind, str) or kind not in self.callbacks or not isinstance(request, dict):
            raise ActionDenied("unsupported_action")
        # Copy through canonical JSON before validation and the durable fence so
        # another caller cannot mutate the object being executed after admission.
        request = json.loads(canonical(request))
        if kind == "export":
            validate(request)
        elif kind == "publish":
            if set(request) != {"export_id"} or not isinstance(request["export_id"], str) or not re.fullmatch(r"[0-9a-f]{64}", request["export_id"]):
                raise ActionDenied("invalid_publication")
            # A worker cannot name another run's export, including a guessed hash.
            if not self.journal.has_acknowledged_export(self.run_id, request["export_id"]):
                raise ActionDenied("unknown_export")
        elif set(request) != {"progress"} or request["progress"] not in ("not-started", "in-progress", "blocked", "complete"):
            raise ActionDenied("invalid_progress")
        row, fresh = self.journal.begin_effect(self.run_id, kind, operation_id, request)
        if not fresh:
            if row["state"] == "acknowledged":
                return json.loads(row["response"])
            raise ActionUncertain("action_requires_reconciliation")
        try:
            response = self.callbacks[kind](operation_id, request)
            if not isinstance(response, dict) or len(canonical(response)) > 16384:
                raise ActionUncertain("invalid_action_receipt")
            if kind == "export" and response != {"export_id": validate(request).digest}:
                raise ActionUncertain("invalid_export_receipt")
            self.validate_receipt(kind, operation_id, request, response)
            self.journal.finish_effect(self.run_id, kind, operation_id, "acknowledged", response)
            return response
        except BaseException as exc:
            # Never convert a failed call to a retryable operation. If recording
            # uncertainty also fails, the prior 'started' fence remains blocking.
            try:
                self.journal.finish_effect(self.run_id, kind, operation_id, "uncertain")
            except (AdmissionConflict, OSError):
                pass
            if isinstance(exc, Exception):
                raise ActionUncertain("action_requires_reconciliation") from None
            raise
