"""Actual engine/native-Codex OCI resource probe with test-only broker responses."""
import argparse
import http.server
import json
import socketserver
import subprocess
import tempfile
import threading
from pathlib import Path
from uuid import uuid4

from .conformance import SyntheticModel, git
from .lifecycle import Lifecycle
from .model_broker import Broker
from .oci import Inputs, run, seccomp_policy, tmpfs


class FixtureActions(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    def __init__(self, path):
        self.reports = {}
        super().__init__(str(path), FixtureHandler)


class FixtureHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass
    def do_POST(self):
        if self.path not in {"/probe-tool", "/probe-test", "/worker-result"}:
            self.send_error(403)
            return
        size = int(self.headers.get("Content-Length", "0"))
        if not 0 < size < 4096:
            self.send_error(413)
            return
        self.server.reports[self.path] = json.loads(self.rfile.read(size))
        self.send_response(202)
        self.send_header("Content-Length", "0")
        self.end_headers()


def probe(image, worker, interrupt=False, *, run_identity=None, actions_factory=None, tool_extension="", repository_factory=None, worker_timeout=120, owner_hook=None):
    with tempfile.TemporaryDirectory(prefix="archon-oci-probe-") as directory:
        root = Path(directory).resolve()
        repository, source, state, sockets = (root / name for name in ("repository", "source", "state", "sockets"))
        repository.mkdir()
        sockets.mkdir()
        (source / ".archon/workflows").mkdir(parents=True)
        (source / ".archon/workflows/probe.yaml").write_text(
            "name: probe\ndescription: Controlled OCI fixture\nnodes:\n"
            "  - id: implement\n    provider: codex\n    model: fixture-model\n    prompt: Execute the controlled probe.\n"
            "  - id: verify\n    depends_on: [implement]\n    bash: python3 /workspace/repository/attack.py test\n")
        env = dict(PATH="/usr/local/bin:/usr/bin:/bin", HOME=str(root), ARCHON_HOME=str(state),
                   DATABASE_URL="", LOG_LEVEL="error", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null")
        git("init", "-q", cwd=repository, env=env)
        git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--allow-empty", "-qm", "base", cwd=repository, env=env)
        initial, request = root / "initial.json", root / "request.json"
        initial.write_text(json.dumps(dict(runId=run_identity or str(uuid4()), cwd="/workspace/repository", sourceRoot=str(source),
            workflowIdentity="probe", model="fixture-model", codexBinary="/runtime/codex")))
        subprocess.run([str(worker), "prepare", str(initial), str(request)], env=env, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)
        sealed = json.loads(request.read_text())
        sealed["authoritativeContext"] = "Synthetic current authority for the controlled confinement probe."
        request.write_text(json.dumps(sealed))
        capture = Path(sealed["captureRoot"])
        for target in tmpfs(state, capture):
            if Path(target).is_relative_to(state):
                Path(target).mkdir(parents=True, exist_ok=True)
        for entry in [state, *state.rglob("*")]:
            entry.chmod(0o555 if entry.is_dir() else 0o444)
        captured_workflow = next(capture.rglob("probe.yaml"))
        before = captured_workflow.read_bytes()
        (root / "host-private").mkdir()
        canary = root / "host-private/canary"
        canary.write_text("host-only synthetic canary")
        attack = '''import ctypes, errno, http.client, json, os, socket, subprocess, sys
from pathlib import Path
phase = sys.argv[1]
checks = []
def denied(name, action):
    try: action()
    except OSError: checks.append(name)
    else: raise AssertionError(name + " was permitted")
assert not Path(CANARY).exists()
assert not Path("/var/run/docker.sock").exists()
assert Path("/sys/fs/cgroup/memory.max").read_text().strip() == "1073741824"
assert Path("/sys/fs/cgroup/pids.max").read_text().strip() == "128"
assert Path("/sys/fs/cgroup/cpu.max").read_text().split() == ["200000", "100000"]
assert os.getuid() == 65532
checks.append("kernel-resource-limits")
pid = int(os.environ["ARCHON_CONFINED_ENGINE_PID"])
denied("engine-memory", lambda: open(f"/proc/{pid}/mem", "rb"))
denied("engine-environment", lambda: Path(f"/proc/{pid}/environ").read_bytes())
control_inode = int(os.environ["ARCHON_CONTROL_INODE"])
for descriptor in Path("/proc/self/fd").iterdir():
    try: assert descriptor.stat().st_ino != control_inode
    except FileNotFoundError: pass
checks.append("control-descriptor-not-inherited")
connection = socket.socket(socket.AF_UNIX)
denied("control-reconnect", lambda: connection.connect("/broker/lifecycle.sock"))
connection.close()
denied("capture-write", lambda: Path(CAPTURE).write_text("mutated"))
denied("root-write", lambda: Path("/root-file").write_text("mutated"))
library = ctypes.CDLL(None, use_errno=True)
assert library.unshare(0x10000000) == -1 and ctypes.get_errno() == errno.EPERM
checks.append("nested-namespace")
conn = socket.socket()
conn.settimeout(1)
denied("network", lambda: conn.connect(("192.0.2.1", 443)))
conn.close()
children = []
try:
    for _ in range(256):
        try: children.append(subprocess.Popen(["/bin/sleep", "60"]))
        except OSError as error:
            assert error.errno == errno.EAGAIN
            checks.append("process-exhaustion-bounded")
            break
    else: raise AssertionError("process limit not enforced")
finally:
    for child in children: child.kill()
    for child in children: child.wait()
fill = Path("/tmp/fill")
try:
    try:
        with fill.open("wb") as output:
            for _ in range(1200): output.write(b"x" * 65536)
    except OSError as error:
        assert error.errno == errno.ENOSPC
        checks.append("disk-exhaustion-bounded")
    else: raise AssertionError("tmpfs size not enforced")
finally: fill.unlink(missing_ok=True)
for path in ("/merge", "/approve", "/deploy", "/secrets", "/verification"):
    conn = http.client.HTTPConnection("localhost", timeout=3)
    conn.sock = socket.socket(socket.AF_UNIX)
    conn.sock.connect("/broker/actions.sock")
    conn.request("POST", path, "{}")
    response = conn.getresponse()
    assert response.status == 403
    response.read()
    conn.close()
    checks.append("denied:" + path)
conn = http.client.HTTPConnection("localhost", timeout=3)
conn.sock = socket.socket(socket.AF_UNIX)
conn.sock.connect("/broker/actions.sock")
conn.request("POST", "/probe-" + phase, json.dumps(checks))
response = conn.getresponse()
assert response.status == 202
response.read()
conn.close()
'''.replace("CANARY", repr(str(canary))).replace("CAPTURE", repr(str(captured_workflow)))
        (repository / "attack.py").write_text(attack + "\n" + tool_extension)
        (repository / "interrupt.py").write_text('''import http.client, json, os, signal, socket
connection = http.client.HTTPConnection("localhost", timeout=3)
connection.sock = socket.socket(socket.AF_UNIX)
connection.sock.connect("/broker/actions.sock")
connection.request("POST", "/worker-result", json.dumps({"status": "completed"}))
response = connection.getresponse()
assert response.status == 202
response.read()
connection.close()
os.kill(int(os.environ["ARCHON_CONFINED_ENGINE_PID"]), signal.SIGKILL)
''')
        git_broker = None
        if repository_factory:
            selection, git_broker = repository_factory(repository, sockets / "git.sock")
            sealed["repositorySelection"] = selection
            request.write_text(json.dumps(sealed))
        config = root / "config.toml"
        config.write_text('model_provider = "fixture"\nweb_search = "disabled"\n[model_providers.fixture]\nname = "fixture"\nbase_url = "http://127.0.0.1:8765/v1"\nwire_api = "responses"\nrequires_openai_auth = false\n')
        seccomp = root / "seccomp.json"
        seccomp.write_text(json.dumps(seccomp_policy()))
        model = SyntheticModel("python3 /workspace/repository/interrupt.py" if interrupt else "python3 /workspace/repository/attack.py tool")
        lifecycle = Lifecycle(sockets / "lifecycle.sock", sealed["runId"])
        servers = [Broker(sockets / "model.sock", model), (actions_factory(sockets / "actions.sock") if actions_factory else FixtureActions(sockets / "actions.sock"))]
        if git_broker is not None:
            servers.append(git_broker)
            (sockets / "git.sock").chmod(0o666)
        threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in servers]
        for path in (sockets / "model.sock", sockets / "actions.sock"):
            path.chmod(0o666)  # individually mounted; host parent remains private
        for path in [repository, capture]:
            for entry in [path, *path.rglob("*")]:
                entry.chmod(0o555 if entry.is_dir() or entry.stat().st_mode & 0o111 else 0o444)
        request.chmod(0o444)
        config.chmod(0o444)
        for thread in threads:
            thread.start()
        try:
            result = run(Inputs(image, request, repository, state, capture, config,
                                sockets / "model.sock", sockets / "actions.sock", sockets / "lifecycle.sock", seccomp, sockets / "git.sock" if git_broker else None), timeout=worker_timeout,
                         retain_owner=(lambda owner: owner_hook({**owner, "fixture_root": str(root)})) if owner_hook else None)
        finally:
            for server in servers:
                if hasattr(server, "seal_and_drain"):
                    server.seal_and_drain()
                server.shutdown()
                server.server_close()
            for thread in threads:
                thread.join()
            if not lifecycle.finished.wait(5):
                lifecycle.close()
                raise RuntimeError("lifecycle_receiver_did_not_finish", locals().get("result"))
            lifecycle.close()
            # Restore private test trees for tempfile cleanup.
            for path in (repository, state):
                for entry in [path, *path.rglob("*")]:
                    entry.chmod(0o700 if entry.is_dir() else 0o600)
        reports = servers[1].reports
        if interrupt:
            assert lifecycle.outcome is None and lifecycle.error == "engine_outcome_uncertain"
            assert reports.get("/worker-result") == {"status": "completed"}
            assert result.returncode != 0
            return {"kind": "controlled-oci-interruption-probe", "full_runtime_conformance": False,
                    "live_acceptance": False, "image": image, "forged_worker_result_ignored": True,
                    "protected_engine_outcome": "uncertain", "model_calls": model.calls}
        assert lifecycle.outcome == "completed", lifecycle.error
        if result.returncode or result.timed_out:
            raise RuntimeError("oci_probe_failed", result, reports)
        assert reports["/probe-tool"] == reports["/probe-test"]
        assert captured_workflow.read_bytes() == before
        assert canary.read_text() == "host-only synthetic canary"
        return {"kind": "controlled-oci-worker-probe", "full_runtime_conformance": False,
                "live_acceptance": False, "image": image, "reports": reports,
                "closure": sealed["workflowRevision"], "model_calls": model.calls}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--worker", type=Path, required=True)
    parser.add_argument("--interrupt-engine", action="store_true")
    args = parser.parse_args()
    print(json.dumps(probe(args.image, args.worker.resolve(), args.interrupt_engine), indent=2))
