"""Per-run untrusted HTTP boundary exposing only typed export/publish/progress."""
import http.server
import socket
import socketserver
import threading
import time
from pathlib import Path

from .actions import ActionDenied, Actions, ActionUncertain
from .https_transport import parse_json
from .journal import AdmissionConflict, canonical

MAX_BODY = 12 * 1024 * 1024


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(self, path: Path, actions: Actions, lifetime=300):
        if not 0 < lifetime <= 900:
            raise ValueError("invalid_action_lifetime")
        self.actions = actions
        self.deadline = time.monotonic() + lifetime
        self.slots = threading.BoundedSemaphore(4)
        self.lock = threading.Lock()
        self.requests = 0
        self.closed = False
        self.active = 0
        self.drained = threading.Event()
        self.drained.set()
        super().__init__(str(path), Handler)

    def process_request(self, request, client_address):
        with self.lock:
            if self.closed or time.monotonic() >= self.deadline or self.requests >= 128 or not self.slots.acquire(blocking=False):
                self.shutdown_request(request)
                return
            self.requests += 1
            self.active += 1
            self.drained.clear()
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.finished_request()
            raise

    def finished_request(self):
        with self.lock:
            self.active -= 1
            self.slots.release()
            if self.active == 0:
                self.drained.set()

    def process_request_thread(self, request, client_address):
        def expire():
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        timer = threading.Timer(min(30, max(.001, self.deadline - time.monotonic())), expire)
        timer.daemon = True
        timer.start()
        try:
            request.settimeout(min(10, max(.001, self.deadline - time.monotonic())))
            super().process_request_thread(request, client_address)
        finally:
            timer.cancel()
            self.finished_request()

    def seal_and_drain(self, timeout=30):
        with self.lock:
            self.closed = True
        if not 0 < timeout <= 30 or not self.drained.wait(timeout):
            raise ActionUncertain("action_callbacks_not_drained")

    def handle_error(self, request, client_address):
        # Do not log request text, transient definitions or credential-bearing
        # callback exceptions through socketserver's default traceback handler.
        pass


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *args):
        pass

    def reply(self, status, value):
        content = canonical(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(content)
        self.close_connection = True

    def do_POST(self):
        try:
            if self.path != "/actions" or self.headers.get_all("Transfer-Encoding") or self.headers.get_all("Expect"):
                raise ActionDenied("unsupported_action_transport")
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit():
                raise ActionDenied("invalid_action_length")
            length = int(lengths[0])
            if not 0 < length <= MAX_BODY or self.headers.get_all("Content-Type", []) != ["application/json"]:
                raise ActionDenied("invalid_action_content")
            content = bytearray()
            while len(content) < length:
                remaining = self.server.deadline - time.monotonic()
                if remaining <= 0:
                    raise ActionDenied("action_lifetime_expired")
                self.connection.settimeout(min(10, remaining))
                chunk = self.rfile.read1(min(65536, length - len(content)))
                if not chunk:
                    raise ActionDenied("incomplete_action")
                content.extend(chunk)
            result = self.server.actions.perform(parse_json(content))
            self.reply(200, result)
        except (ValueError, TypeError):
            self.reply(403, {"diagnostic": "action_denied"})
        except (AdmissionConflict, ActionUncertain):
            self.reply(409, {"diagnostic": "action_blocked"})
        except Exception:
            # The effect fence, when one exists, remains uncertain. No exception
            # detail may travel back to model tools, especially from HTTPS auth.
            self.reply(503, {"diagnostic": "action_unavailable"})
