"""One-shot engine lifecycle channel, consumed before any model process exists.

The pinned image entry opens this channel, passes its descriptor to the engine
and closes its own copy. The engine disables dumping and marks the descriptor
CLOEXEC before launching descendants. Later socket connections are refused.
This channel conveys execution outcome only, never verification disposition.
"""
import json
import socket
import threading
from pathlib import Path

from .admission import Rejected


class Lifecycle:
    def __init__(self, path: Path, run_id: str, timeout=360, authorize=None):
        self.path, self.run_id = path, run_id
        self.authorize = authorize
        self.outcome = None
        self.error = None
        self.rejection = None
        self.connection = None
        self.stopped = threading.Event()
        self.finished = threading.Event()
        self.listener = socket.socket(socket.AF_UNIX)
        self.listener.settimeout(timeout)
        self.listener.bind(str(path))
        path.chmod(0o666)  # containing supervisor directory is private
        self.listener.listen(1)
        self.timeout = timeout
        self.thread = threading.Thread(target=self.receive, daemon=True)
        self.thread.start()

    def receive(self):
        connection = None
        try:
            connection, _ = self.listener.accept()
            self.connection = connection
            if self.stopped.is_set():
                raise OSError("lifecycle_stopped")
            # Bootstrap consumes the capability; a model tool cannot reconnect.
            self.listener.close()
            connection.settimeout(self.timeout)
            if self.authorize is not None:
                self.authorize()
            connection.sendall(b"ready\n")
            content = bytearray()
            while chunk := connection.recv(4097 - len(content)):
                content.extend(chunk)
                if len(content) > 4096:
                    raise ValueError("engine_outcome_too_large")
            value = json.loads(content)
            if (not isinstance(value, dict) or set(value) != {"run_id", "state"}
                    or value["run_id"] != self.run_id or value["state"] not in ("completed", "failed", "paused")):
                raise ValueError("engine_outcome_mismatch")
            self.outcome = value["state"]
        except Rejected as error:
            self.rejection = error.diagnostic
            self.error = "engine_outcome_uncertain"
        except Exception:
            self.error = "engine_outcome_uncertain"
        finally:
            self.listener.close()
            if connection is not None:
                connection.close()
            self.finished.set()

    def await_outcome(self, timeout=5):
        if not 0 < timeout <= 30 or not self.finished.wait(timeout):
            raise RuntimeError("engine_outcome_uncertain")
        if self.error is not None or self.outcome is None:
            raise RuntimeError("engine_outcome_uncertain")
        return self.outcome

    def close(self):
        self.stopped.set()
        for stream in (self.listener, self.connection):
            if stream is not None:
                try:
                    stream.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
        self.listener.close()
        self.thread.join(timeout=1)
