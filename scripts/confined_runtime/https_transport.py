"""Bounded fixed-origin HTTPS for trusted brokers; no redirects or retries."""
import http.client
import json
import re
import ssl
import threading
import time
from dataclasses import dataclass, field

from .journal import canonical


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("ambiguous_json")
        result[key] = value
    return result


def parse_json(content):
    return json.loads(content, object_pairs_hook=unique_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite_json")))


@dataclass(frozen=True)
class Origin:
    hostname: str
    credential: str = field(repr=False)

    def __post_init__(self):
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", self.hostname) or ".." in self.hostname:
            raise ValueError("invalid_broker_origin")
        if not self.credential or any(ord(char) < 33 or ord(char) > 126 for char in self.credential):
            raise ValueError("invalid_broker_credential")


class HTTPS:
    def __init__(self, origin: Origin, allowed: frozenset[tuple[str, str]], *, lifetime=300, request_limit=300):
        if not 0 < lifetime <= 900 or not 0 < request_limit <= 1024:
            raise ValueError("invalid_transport_budget")
        self.origin, self.allowed = origin, allowed
        self.deadline = time.monotonic() + lifetime
        self.remaining = request_limit
        self.bytes_remaining = 64 * 1024 * 1024
        self.lock = threading.Lock()
        self.context = ssl.create_default_context()

    def __call__(self, method: str, path: str, body: dict | None) -> dict:
        if (method, path) not in self.allowed or not path.startswith("/") or path.startswith("//") or any(c in path for c in "\r\n#"):
            raise ValueError("unsupported_broker_request")
        encoded = canonical(body).encode() if body is not None else None
        if encoded is not None and len(encoded) > 2 * 1024 * 1024:
            raise ValueError("broker_request_too_large")
        # Serialize this per-run broker: concurrency cannot multiply response
        # budgets or race lifetime accounting. No automatic retry at any layer.
        with self.lock:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0 or self.remaining <= 0 or self.bytes_remaining <= 0:
                raise RuntimeError("broker_budget_exhausted")
            self.remaining -= 1
            self.bytes_remaining -= len(encoded or b"")
            if self.bytes_remaining < 0:
                raise RuntimeError("broker_budget_exhausted")
            connection = http.client.HTTPSConnection(self.origin.hostname, 443,
                timeout=min(15, remaining), context=self.context)
            try:
                connection.request(method, path, encoded, {
                    "Authorization": "Bearer " + self.origin.credential,
                    "Accept": "application/vnd.github+json", "Content-Type": "application/json",
                    "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "archon-confined-experimental"})
                response = connection.getresponse()
                if response.status not in ({200} if method == "GET" else {200, 201}):
                    raise RuntimeError("broker_upstream_not_acknowledged")
                content = bytearray()
                while True:
                    remaining = self.deadline - time.monotonic()
                    if remaining <= 0:
                        raise RuntimeError("broker_budget_exhausted")
                    if connection.sock is not None:
                        connection.sock.settimeout(min(15, remaining))
                    chunk = response.read1(min(65536, 2 * 1024 * 1024 + 1 - len(content)))
                    if not chunk:
                        break
                    content.extend(chunk)
                    self.bytes_remaining -= len(chunk)
                    if len(content) > 2 * 1024 * 1024 or self.bytes_remaining < 0:
                        raise RuntimeError("broker_response_too_large")
                value = parse_json(content)
                if not isinstance(value, dict):
                    raise RuntimeError("broker_response_not_object")
                return value
            finally:
                connection.close()
