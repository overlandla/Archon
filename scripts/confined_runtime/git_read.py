"""Read-only fixed-repository/commit Git HTTP broker; credentials stay outside.

Protocol v0 only. A fresh depth-one fetch can request only the supervisor's
refreshed base commit. Receive-pack, other objects, protocol overrides, arbitrary
URLs, redirects and worker credentials are never forwarded.
"""
import base64
import http.client
import http.server
import re
import ssl
import time
from dataclasses import dataclass, field

from .action_server import Server


def validate_upload(body: bytes, commit: str):
    if not body or len(body) > 1024 * 1024:
        raise ValueError("git_request_limit")
    offset, wants, done, depth = 0, 0, 0, 0
    while offset < len(body):
        header = body[offset:offset + 4]
        if len(header) != 4 or not re.fullmatch(b"[0-9a-f]{4}", header):
            raise ValueError("invalid_git_packet")
        length = int(header, 16)
        offset += 4
        if length == 0:
            continue
        if length < 4 or length > 65520 or offset + length - 4 > len(body):
            raise ValueError("invalid_git_packet")
        line = body[offset:offset + length - 4].removesuffix(b"\n")
        offset += length - 4
        if line.startswith(b"want "):
            parts = line.split(b" ")
            if wants or done or parts[1] != commit.encode():
                raise ValueError("git_object_not_authorized")
            allowed = {b"multi_ack_detailed", b"multi_ack", b"side-band-64k", b"thin-pack", b"ofs-delta",
                       b"no-progress", b"include-tag", b"no-done", b"object-format=sha1", b"deepen-since", b"deepen-not"}
            if any(part not in allowed and not re.fullmatch(b"agent=git/[A-Za-z0-9.()+_-]{1,100}", part) for part in parts[2:]):
                raise ValueError("git_capability_not_authorized")
            wants += 1
        elif line == b"deepen 1" and wants and not done:
            depth += 1
        elif line == b"done" and wants:
            done += 1
        else:
            raise ValueError("unsupported_git_negotiation")
    if wants != 1 or depth != 1 or done > 1:
        raise ValueError("unsupported_git_fetch")


@dataclass(frozen=True)
class Policy:
    owner: str
    repository: str
    commit: str
    credential: str = field(repr=False)

    def __post_init__(self):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{0,99}", self.owner) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", self.repository):
            raise ValueError("invalid_git_repository")
        if not re.fullmatch(r"[0-9a-f]{40}", self.commit) or not self.credential or any(ord(c) < 33 or ord(c) > 126 for c in self.credential):
            raise ValueError("invalid_git_read_policy")

    def send(self, method, suffix, body):
        # The request handler has already limited the suffix and negotiation;
        # this method also validates to avoid an internal generic-proxy surface.
        if (method, suffix) not in {("GET", "/info/refs?service=git-upload-pack"), ("POST", "/git-upload-pack")}:
            raise ValueError("git_operation_denied")
        if method == "POST":
            validate_upload(body, self.commit)
        connection = http.client.HTTPSConnection("github.com", 443, timeout=15, context=ssl.create_default_context())
        deadline = time.monotonic() + 30
        try:
            authorization = base64.b64encode(("x-access-token:" + self.credential).encode()).decode()
            connection.request(method, f"/{self.owner}/{self.repository}.git" + suffix, body, {
                "Authorization": "Basic " + authorization,
                "Content-Type": "application/x-git-upload-pack-request", "User-Agent": "archon-confined-git"})
            response = connection.getresponse()
            if response.status != 200:
                raise RuntimeError("git_upstream_not_acknowledged")
            content = bytearray()
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("git_read_timeout")
                if connection.sock is not None:
                    connection.sock.settimeout(min(15, remaining))
                chunk = response.read1(min(65536, 64 * 1024 * 1024 + 1 - len(content)))
                if not chunk:
                    break
                content.extend(chunk)
                if len(content) > 64 * 1024 * 1024:
                    raise RuntimeError("git_response_too_large")
            return bytes(content)
        finally:
            connection.close()


class Broker(Server):
    def __init__(self, path, policy):
        super().__init__(path, None)
        self.policy = policy
        self.bytes_remaining = 256 * 1024 * 1024
        self.RequestHandlerClass = Handler


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.forward()

    def do_POST(self):
        self.forward()

    def forward(self):
        try:
            if (self.command, self.path) not in {("GET", "/repository.git/info/refs?service=git-upload-pack"),
                                               ("POST", "/repository.git/git-upload-pack")}:
                raise ValueError("git_operation_denied")
            if self.headers.get_all("Transfer-Encoding") or self.headers.get_all("Git-Protocol") or self.headers.get_all("Expect"):
                raise ValueError("unsupported_git_transport")
            lengths = self.headers.get_all("Content-Length", [])
            if self.command == "POST":
                if len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit() or not 0 < int(lengths[0]) <= 1024 * 1024:
                    raise ValueError("git_request_limit")
                body = self.rfile.read(int(lengths[0]))
                if len(body) != int(lengths[0]):
                    raise ValueError("truncated_git_request")
                validate_upload(body, self.server.policy.commit)
            else:
                if lengths and lengths != ["0"]:
                    raise ValueError("unexpected_git_body")
                body = None
            with self.server.lock:
                # Reserve the maximum before a request: parallel calls cannot
                # multiply the aggregate upstream transfer authority.
                if self.server.bytes_remaining < 64 * 1024 * 1024:
                    raise ValueError("git_budget_exhausted")
                self.server.bytes_remaining -= 64 * 1024 * 1024
            result = self.server.policy.send(self.command, self.path.removeprefix("/repository.git"), body)
            with self.server.lock:
                self.server.bytes_remaining += 64 * 1024 * 1024 - len(result)
            self.send_response(200)
            self.send_header("Content-Type", "application/x-git-upload-pack-advertisement" if self.command == "GET" else "application/x-git-upload-pack-result")
            self.send_header("Content-Length", str(len(result)))
            self.end_headers()
            self.wfile.write(result)
        except ValueError:
            self.send_error(403)
        except Exception:
            self.send_error(503)
