"""Capability-specific model broker; network access and keys stay outside the worker.

No generic proxy, credential endpoint, URL override, redirect following or
publication API is exposed. Operator policy chooses the fixed Responses origin.
"""
from __future__ import annotations

import http.client
import http.server
import json
from pathlib import Path
import socketserver
import ssl
import threading
import time
from urllib.parse import urlsplit

from .gateway import MAX_REQUEST


class ModelPolicy:
    def __init__(self, origin: str, model: str, credential: str):
        parsed = urlsplit(origin)
        if parsed.scheme != "https" or not parsed.hostname or parsed.path not in ("", "/") or any(
            (parsed.username, parsed.password, parsed.query, parsed.fragment)
        ):
            raise ValueError("model_broker_requires_https_origin")
        if not model or not credential or any(char in credential for char in "\r\n"):
            raise ValueError("invalid_model_policy")
        self.hostname, self.port, self.model = parsed.hostname, parsed.port or 443, model
        self._credential = credential

    def send(self, body: bytes) -> tuple[int, bytes]:
        connection = http.client.HTTPSConnection(self.hostname, self.port, timeout=60,
                                                context=ssl.create_default_context())
        try:
            connection.request("POST", "/v1/responses", body, {
                "Content-Type": "application/json", "Authorization": f"Bearer {self._credential}",
            })
            response = connection.getresponse()
            # Unknown/redirect/error bodies may contain upstream content; return
            # a controlled error rather than forwarding arbitrary headers or text.
            if response.status != 200:
                return 502, b'{"error":"model_upstream_failed"}'
            result = response.read(16 * 1024 * 1024 + 1)
            if len(result) > 16 * 1024 * 1024:
                return 502, b'{"error":"model_response_too_large"}'
            return 200, result
        finally:
            connection.close()


def validate_body(body: bytes, model: str) -> bytes:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_model_key")
            result[key] = value
        return result

    value = json.loads(body, object_pairs_hook=unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite_json")))
    if not isinstance(value, dict) or value.get("model") != model or value.get("stream") is not True:
        raise ValueError("model_request_denied")
    allowed = {"model", "stream", "store", "input", "instructions", "tools", "tool_choice",
               "parallel_tool_calls", "reasoning", "include", "prompt_cache_key", "client_metadata"}
    if value.keys() - allowed:
        raise ValueError("unknown_model_fields")
    # Server-side tools could introduce external effects beyond model inference.
    # Only tools executed locally by the already-confined Codex are permitted.
    def local_tools(tools, depth=0):
        if depth > 1 or not isinstance(tools, list) or len(tools) > 64:
            raise ValueError("model_tools_denied")
        for tool in tools:
            if not isinstance(tool, dict):
                raise ValueError("model_tools_denied")
            kind = tool.get("type")
            fields = {
                "function": {"type", "name", "description", "parameters", "strict"},
                "custom": {"type", "name", "description", "format"},
                "namespace": {"type", "name", "description", "tools"},
            }.get(kind)
            if fields is None or tool.keys() - fields:
                raise ValueError("model_tools_denied")
            if kind == "namespace":
                local_tools(tool.get("tools"), depth + 1)
    local_tools(value.get("tools", []))
    if value.get("store", False) is not False:
        raise ValueError("model_storage_denied")
    value["store"] = False
    items = value.get("input", [])
    if not isinstance(items, list):
        raise ValueError("model_input_denied")
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("model_input_denied")
        kind = item.get("type", "message")
        fields = {
            "message": {"type", "role", "content", "id", "status"},
            "function_call": {"type", "id", "call_id", "name", "arguments", "status"},
            "function_call_output": {"type", "id", "call_id", "output", "status"},
            "custom_tool_call": {"type", "id", "call_id", "name", "input", "status"},
            "custom_tool_call_output": {"type", "id", "call_id", "output", "status"},
            "reasoning": {"type", "id", "summary", "encrypted_content", "status"},
        }.get(kind)
        if fields is None or item.keys() - fields:
            raise ValueError("model_input_denied")
        if kind == "message":
            if item.get("role") not in {"system", "developer", "user", "assistant"}:
                raise ValueError("model_role_denied")
            content = item.get("content")
            if not isinstance(content, str):
                if not isinstance(content, list):
                    raise ValueError("model_content_denied")
                for part in content:
                    if (not isinstance(part, dict) or part.keys() - {"type", "text"}
                            or part.get("type") not in {"input_text", "output_text"}
                            or not isinstance(part.get("text"), str)):
                        raise ValueError("model_external_content_denied")
        elif kind in {"function_call_output", "custom_tool_call_output"} and not isinstance(item.get("output"), str):
            raise ValueError("model_tool_output_denied")
    if value.get("include", []) not in ([], ["reasoning.encrypted_content"]):
        raise ValueError("model_include_denied")
    return json.dumps(value, separators=(",", ":"), allow_nan=False).encode()


class Broker(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True

    def __init__(self, path: Path, policy: ModelPolicy):
        self.policy = policy
        self._slots = threading.BoundedSemaphore(4)
        self._quota_lock = threading.Lock()
        self._remaining = 64
        self._deadline = time.monotonic() + 900
        super().__init__(str(path), Handler)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def consume(self):
        with self._quota_lock:
            if self._remaining <= 0 or time.monotonic() >= self._deadline:
                return False
            self._remaining -= 1
            return True


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def setup(self):
        super().setup()
        self.connection.settimeout(60)

    def do_POST(self):
        if not self.server.consume():
            self.send_error(429)
            return
        if self.path != "/v1/responses" or self.headers.get("Transfer-Encoding"):
            self.send_error(403)
            return
        try:
            lengths = self.headers.get_all("Content-Length", [])
            if len(lengths) != 1:
                raise ValueError("ambiguous_model_length")
            length = int(lengths[0])
            if not 0 < length <= MAX_REQUEST:
                raise ValueError("model_request_too_large")
            body = self.rfile.read(length)
            if len(body) != length:
                raise ValueError("model_request_truncated")
            body = validate_body(body, self.server.policy.model)
        except (ValueError, UnicodeError, OSError):
            self.send_error(400)
            return
        try:
            status, result = self.server.policy.send(body)
        except (OSError, http.client.HTTPException):
            status, result = 502, b'{"error":"model_upstream_failed"}'
        self.send_response(status)
        self.send_header("Content-Type", "text/event-stream" if status == 200 else "application/json")
        self.send_header("Content-Length", str(len(result)))
        self.end_headers()
        self.wfile.write(result)
