"""Independent worker expiry, detached from the admission supervisor's lifetime.

Only trusted code starts this process. It receives a unique pre-recorded
container name and bounded lifetime, no credentials or worker commands. Docker
and this trusted process are part of the operator's enforcement service (#531).
"""
import http.client
import json
import os
import re
import selectors
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

REQUEST_DEADLINE = 15
OWNER_LABEL = "org.archon.confined.owner"
ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin"}


def start(name: str, lifetime: float, image: str):
    if (not re.fullmatch(r"archon-confined-[0-9a-f-]{36}", name) or not 0 < lifetime <= 900
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", image)):
        raise ValueError("invalid_watchdog_identity")
    process = subprocess.Popen([sys.executable, "-I", str(Path(__file__).resolve()), name, str(lifetime), image],
        env=ENV, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        start_new_session=True, close_fds=True)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            if not selector.select(5) or process.stdout.readline(32) != b"ready\n":
                raise RuntimeError("watchdog_not_ready")
    except BaseException:
        process.kill()
        process.wait(timeout=5)
        raise
    finally:
        process.stdout.close()
    return process


class DockerConnection(http.client.HTTPConnection):
    def __init__(self):
        super().__init__("localhost", timeout=15)

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(self.timeout)
        self.sock.connect("/var/run/docker.sock")


def request(method, path):
    connection = DockerConnection()
    timer = None
    try:
        connection.connect()
        connection.auto_open = False
        stream = connection.sock
        def expire():
            try:
                stream.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        timer = threading.Timer(REQUEST_DEADLINE, expire)
        timer.daemon = True
        timer.start()
        connection.request(method, path)
        response = connection.getresponse()
        content = response.read(1024 * 1024 + 1)
        if len(content) > 1024 * 1024:
            raise ValueError("watchdog_inspection_too_large")
        return response.status, content
    finally:
        if timer is not None:
            timer.cancel()
        connection.close()


def remove_owned(name, image):
    status, content = request("GET", "/containers/" + name + "/json")
    if status == 404:
        return True
    if status != 200:
        return False
    container = json.loads(content)
    identity = container.get("Id", "")
    if (not isinstance(identity, str) or not re.fullmatch(r"[0-9a-f]{64}", identity)
            or container.get("Name") != "/" + name or container.get("Image") != image
            or container.get("Config", {}).get("Labels", {}).get(OWNER_LABEL) != name):
        # Never remove a replacement object. Retain ownership and uncertainty;
        # only the operator may resolve an identity disagreement.
        return False
    # Delete the immutable ID inspected above, never its reusable name.
    status, _ = request("DELETE", "/containers/" + identity + "?force=1&v=0")
    return status in (204, 404)


def guard(name, lifetime, image):
    if (not re.fullmatch(r"archon-confined-[0-9a-f-]{36}", name) or not 0 < lifetime <= 900
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", image)):
        raise ValueError("invalid_watchdog_identity")
    deadline = time.monotonic() + lifetime
    os.write(1, b"ready\n")
    # Creation may still be in flight or its acknowledgement may have been lost.
    while time.monotonic() < deadline:
        time.sleep(max(0, min(1, deadline - time.monotonic())))
    backoff = 1
    while True:
        try:
            if remove_owned(name, image):
                return 0
        except (OSError, TimeoutError, http.client.HTTPException, ValueError, TypeError, AttributeError):
            # Daemon outage, malformed inspection and individual timeouts do not
            # surrender cleanup ownership. No unbounded subprocess can survive.
            pass
        time.sleep(backoff)
        backoff = min(15, backoff * 2)


if __name__ == "__main__":
    raise SystemExit(guard(sys.argv[1], float(sys.argv[2]), sys.argv[3]))
