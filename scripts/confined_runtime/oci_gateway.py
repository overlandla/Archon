"""Untrusted-side transport and bounded initialization for an OCI worker."""
import ctypes
import hashlib
import http.server
import importlib.util
import json
import os
import re
import shutil
import socket
import stat
import subprocess
import threading
from pathlib import Path


def copy_repository():
    source = Path("/input/repository")
    target = Path("/workspace/repository")
    count, size = 0, 0
    target.mkdir(mode=0o700)
    for directory, dirs, files in os.walk(source, followlinks=False):
        relative = Path(directory).relative_to(source)
        if len(relative.parts) > 32:
            raise ValueError("repository_depth_exceeded")
        for name in dirs + files:
            entry = Path(directory) / name
            info = entry.lstat()
            count += 1
            if count > 100000 or stat.S_ISLNK(info.st_mode):
                raise ValueError("repository_entry_unsupported")
            destination = target / relative / name
            if stat.S_ISDIR(info.st_mode):
                destination.mkdir(mode=0o700)
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                size += info.st_size
                if size > 256 * 1024 * 1024:
                    raise ValueError("repository_input_too_large")
                # Input is a supervisor-owned immutable tree, not a live checkout.
                with entry.open("rb") as input_stream, destination.open("xb") as output:
                    shutil.copyfileobj(input_stream, output, 65536)
                destination.chmod(0o700 if info.st_mode & 0o111 else 0o600)
            else:
                raise ValueError("repository_entry_unsupported")



def validate_runtime(identity):
    files = {"workerRevision": "/runtime/worker", "providerRevision": "/runtime/codex",
             "nativeConfigurationRevision": "/home/worker/.codex/config.toml"}
    if not isinstance(identity, dict) or set(identity) != set(files):
        raise ValueError("unsupported_runtime_identity")
    for key, path in files.items():
        digest = hashlib.sha256()
        with open(path, "rb") as stream:
            while chunk := stream.read(65536):
                digest.update(chunk)
        if digest.hexdigest() != identity[key]:
            raise RuntimeError("runtime_artifact_mismatch")


def prepare_repository(selection):
    if (not isinstance(selection, dict) or set(selection) not in ({"base", "commit"}, {"base", "commit", "workspace", "pinned"})
            or not isinstance(selection["base"], str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_/-]{0,199}", selection["base"])
            or "//" in selection["base"] or not isinstance(selection["commit"], str)
            or not re.fullmatch(r"[0-9a-f]{40}", selection["commit"])):
        raise ValueError("unsupported_repository_selection")
    spec = importlib.util.spec_from_file_location("git_gateway", "/runtime/git_gateway.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 8766), module.GitGateway)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    target = Path(selection.get("workspace", "/workspace/repository"))
    if "workspace" in selection:
        if selection["pinned"] is not True or not target.is_absolute() or target.resolve() != target or not target.is_dir() or any(target.iterdir()):
            raise ValueError("invalid_allocated_workspace")
    else:
        target.mkdir(mode=0o700)
    environment = {"PATH": "/usr/bin:/bin", "HOME": "/home/worker", "GIT_CONFIG_NOSYSTEM": "1",
                   "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0"}
    git = ["git", "-c", "core.hooksPath=/dev/null", "-c", "credential.helper=",
           "-c", "protocol.version=0", "-c", "protocol.allow=never", "-c", "protocol.http.allow=always",
           "-c", "submodule.recurse=false", "-c", "fetch.recurseSubmodules=false", "-c", "gc.auto=0"]
    try:
        for arguments in (["init", "--template=/runtime/empty-template", "-q"],
                          ["fetch", "--depth=1", "--no-tags", "--no-recurse-submodules", "--no-auto-maintenance",
                           "http://127.0.0.1:8766/repository.git", selection["commit"] if selection.get("pinned") else "refs/heads/" + selection["base"]]):
            subprocess.run(git + arguments, cwd=target, env=environment, check=True, timeout=45,
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        actual = subprocess.check_output(git + ["rev-parse", "--verify", "FETCH_HEAD"], cwd=target, env=environment, timeout=5).decode().strip()
        if actual != selection["commit"]:
            raise RuntimeError("refreshed_repository_changed")
        subprocess.run(git + ["checkout", "--detach", "--force", selection["commit"]], cwd=target,
                       env=environment, check=True, timeout=30, stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except BaseException:
        server.shutdown()
        server.server_close()
        raise
    return server


if __name__ == "__main__":
    # Git parses repository bytes before the engine starts. Protect this parent
    # and its bootstrap descriptor even from a compromised same-UID descendant.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(4, 0, 0, 0, 0) != 0:  # PR_SET_DUMPABLE
        raise RuntimeError("bootstrap_process_protection_failed")
    # Import only the immutable image module, never cwd, user site or PYTHONPATH.
    spec = importlib.util.spec_from_file_location("gateway", "/runtime/gateway.py")
    gateway = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gateway)
    request = json.loads(Path("/input/request.json").read_text())
    if "runtimeIdentity" in request:
        validate_runtime(request["runtimeIdentity"])
    control = socket.socket(socket.AF_UNIX)
    control.settimeout(65)
    control.connect("/broker/lifecycle.sock")
    handshake = bytearray()
    while len(handshake) < 6:
        chunk = control.recv(6 - len(handshake))
        if not chunk:
            break
        handshake.extend(chunk)
    if handshake != b"ready\n":
        raise RuntimeError("lifecycle_bootstrap_not_sealed")
    control.settimeout(None)
    git_server = None
    if "repositorySelection" in request:
        git_server = prepare_repository(request["repositorySelection"])
    else:
        copy_repository()
    # The final captured root is bound directly at the engine's computed path by
    # the container launch policy; this request is not rewritten from live files.
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 8765), gateway.Gateway)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        environment = os.environ.copy()
        environment["ARCHON_CONTROL_FD"] = str(control.fileno())
        process = subprocess.Popen(["/runtime/worker", "run", "/input/request.json", "/workspace/result.json"],
            stdin=subprocess.DEVNULL, env=environment, pass_fds=(control.fileno(),))
        control.close()
        process.wait()
    finally:
        control.close()
        server.shutdown()
        server.server_close()
        if git_server is not None:
            git_server.shutdown()
            git_server.server_close()
    raise SystemExit(process.returncode)
