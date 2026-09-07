"""Authenticated literal-loopback ingress and complete source-scoped inspection.

This endpoint is separate from stock Archon HTTP launch. The #524 adapter is its
sole authorized caller. It never accepts shell text, credentials, callbacks,
transport overrides or provider configuration from a request.
"""
import hmac
import http.server
import re
import socket
import socketserver
import threading
from uuid import UUID

from .admission import Supervisor
from .https_transport import parse_json
from .journal import AdmissionConflict, canonical


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

    def __init__(self, port: int, supervisor: Supervisor, deployment: str, project: int, credential: str):
        if not credential or len(credential) < 32 or any(ord(c) < 33 or ord(c) > 126 for c in credential):
            raise ValueError("invalid_private_ingress_credential")
        self.supervisor, self.source = supervisor, {"deployment": deployment, "project": project}
        self._credential = credential
        self.slots = threading.BoundedSemaphore(8)
        self.changed, self.stopped = threading.Event(), threading.Event()
        super().__init__(("127.0.0.1", port), Handler)
        self.worker = threading.Thread(target=self.dequeue, daemon=True)
        self.worker.start()

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        def expire():
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        timer = threading.Timer(15, expire)
        timer.daemon = True
        timer.start()
        try:
            request.settimeout(10)
            super().process_request_thread(request, client_address)
        finally:
            timer.cancel()
            self.slots.release()

    def handle_error(self, request, client_address):
        pass

    def dequeue(self):
        while not self.stopped.is_set():
            self.changed.clear()
            with self.supervisor.journal.connect() as connection:
                row = connection.execute("SELECT run_id, revision FROM confined_admissions WHERE deployment=? AND project=? AND state='admitted' ORDER BY rowid LIMIT 1",
                                         (self.source["deployment"], self.source["project"])).fetchone()
            if row is None:
                self.changed.wait(1)
                continue
            try:
                self.supervisor.dequeue(row["run_id"], row["revision"])
            except Exception:
                # A competing owner, cleanup failure or DB failure grants no
                # retry authority. Checking/invoking rows are never selected.
                self.changed.wait(1)

    def server_close(self):
        self.stopped.set()
        self.changed.set()
        super().server_close()
        self.worker.join(5)
        if self.worker.is_alive():
            raise RuntimeError("runtime_owner_still_active")

    def projection(self, row):
        row, facts = self.supervisor.journal.inspect_run(row["run_id"])
        return {"format": "archon-confined-record-v1", "source": self.source,
                "run_id": row["run_id"], "correlation_id": row["correlation"], "selection_digest": row["selection_digest"],
                "state": row["state"], "revision": row["revision"], "diagnostic": row["diagnostic"],
                "execution": facts, "effects": self.supervisor.journal.effect_projection(row["run_id"])}


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, result):
        content = canonical(result).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(content)
        self.close_connection = True

    def do_POST(self):
        try:
            auth = self.headers.get_all("Authorization", [])
            if len(auth) != 1 or not hmac.compare_digest(auth[0], "Bearer " + self.server._credential):
                self.reply(401, {"diagnostic": "unauthorized"})
                return
            if self.headers.get_all("Origin") or self.headers.get_all("Transfer-Encoding") or self.headers.get_all("Expect"):
                raise ValueError("unsupported_ingress_transport")
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,7}", lengths[0]) or not 0 < int(lengths[0]) <= 1024 * 1024:
                raise ValueError("invalid_ingress_length")
            if self.headers.get_all("Content-Type", []) != ["application/json"]:
                raise ValueError("invalid_ingress_content_type")
            value = parse_json(self.rfile.read(int(lengths[0])))
            if not isinstance(value, dict) or value.get("source") != self.server.source:
                raise ValueError("foreign_ingress_source")
            if self.path == "/v1/contract" and set(value) == {"source"}:
                self.reply(200, {"format": "archon-confined-control-v1", "source": self.server.source,
                                "release": self.server.supervisor.release.selection()})
            elif self.path == "/v1/admissions" and set(value) == {"source", "correlation_id", "selection"}:
                if not isinstance(value["selection"], dict) or not isinstance(value["correlation_id"], str):
                    raise ValueError("invalid_ingress_identity")
                row = self.server.supervisor.admit(self.server.source["deployment"], self.server.source["project"], value["correlation_id"], value["selection"])
                self.server.changed.set()
                self.reply(202, self.server.projection(row))
            elif self.path == "/v1/lookup" and set(value) == {"source", "correlation_id"}:
                if not isinstance(value["correlation_id"], str) or not 0 < len(value["correlation_id"]) <= 200:
                    raise ValueError("invalid_ingress_correlation")
                rows = self.server.supervisor.journal.find(self.server.source["deployment"], self.server.source["project"], value["correlation_id"])
                self.reply(200, {"format": "archon-confined-lookup-v1", "source": self.server.source,
                                "complete": True, "runs": [self.server.projection(row) for row in rows]})
            elif self.path == "/v1/inspect" and set(value) == {"source", "run_id"}:
                run_id = str(UUID(value["run_id"]))
                with self.server.supervisor.journal.connect() as connection:
                    row = connection.execute("SELECT * FROM confined_admissions WHERE run_id=? AND deployment=? AND project=?",
                                             (run_id, self.server.source["deployment"], self.server.source["project"])).fetchone()
                if row is None:
                    self.reply(404, {"diagnostic": "run_not_found"})
                else:
                    self.reply(200, self.server.projection(row))
            else:
                raise ValueError("unsupported_ingress_operation")
        except (ValueError, TypeError, AttributeError):
            self.reply(400, {"diagnostic": "invalid_request"})
        except AdmissionConflict:
            self.reply(409, {"diagnostic": "identity_conflict"})
        except Exception:
            self.reply(503, {"diagnostic": "runtime_unavailable"})
