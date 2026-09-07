"""Experimental engine/Codex boundary probe, using synthetic model responses.

Run only in a disposable test account with the locally built worker. No operator
credentials, live model requests, deployment or accepted verification are used.
This covers worker isolation; it does NOT establish the complete runtime contract.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import threading
from uuid import uuid4

from .linux import WorkerMounts, arguments, run
from .model_broker import Broker
from .staging import stage


class SyntheticModel:
    model = "fixture-model"

    def __init__(self, command: str):
        self.command = command
        self.calls = 0
        self.request_shapes = []

    def send(self, body: bytes) -> tuple[int, bytes]:
        request = json.loads(body)
        self.request_shapes.append({"keys": sorted(request), "input_types": sorted({str(item.get("type")) for item in request.get("input", [])})})
        self.calls += 1
        if self.calls == 1:
            item = {"id": "fc_1", "type": "function_call", "call_id": "call_1", "name": "exec_command",
                    "arguments": json.dumps({"cmd": self.command, "yield_time_ms": 1000})}
        else:
            item = {"id": "msg_1", "type": "message", "role": "assistant",
                    "content": [{"type": "output_text", "text": "controlled fixture finished"}]}
        identity = f"response_{self.calls}"
        events = [
            ("response.created", {"response": {"id": identity}}),
            ("response.output_item.done", {"item": item}),
            ("response.completed", {"response": {"id": identity, "output": [item], "usage": {
                "input_tokens": 0, "output_tokens": 0, "total_tokens": 0,
                "input_tokens_details": {"cached_tokens": 0}}}}),
        ]
        return 200, "".join(f"event: {kind}\ndata: {json.dumps(dict(type=kind, **value))}\n\n" for kind, value in events).encode()


def git(*args: str, cwd: Path, env: dict):
    subprocess.run(["git", "-c", "core.hooksPath=/dev/null", *args], cwd=cwd, env=env,
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def probe(executable: Path, node: Path) -> dict:
    with tempfile.TemporaryDirectory(prefix="archon-confined-test-") as directory:
        root = Path(directory).resolve()
        state, workspace, source, broker = (root / name for name in ("state", "workspace", "source", "broker"))
        workspace.mkdir()
        broker.mkdir()
        authoring = root / "authoring"
        (authoring / ".archon/workflows").mkdir(parents=True)
        source_yaml = authoring / ".archon/workflows/confined-proof.yaml"
        source_yaml.write_text("name: confined-proof\ndescription: Controlled fixture\nnodes:\n"
                               "  - id: implement\n    provider: codex\n    model: fixture-model\n    prompt: Exercise the controlled fixture.\n"
                               "  - id: verify\n    depends_on: [implement]\n    bash: python3 /workspace/attack.py verify\n")
        stage(authoring, source)
        env = dict(PATH="/usr/local/bin:/usr/bin:/bin", HOME=str(root), ARCHON_HOME=str(state), DATABASE_URL="", LOG_LEVEL="error",
                   GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null")
        # Entire git repository is private disposable data, including .git. No
        # operator repository metadata or credential helpers are exposed.
        git("init", "-q", cwd=workspace, env=env)
        git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--allow-empty", "-qm", "base", cwd=workspace, env=env)
        native_config = root / "native-config.toml"
        native_config.write_text('model_provider = "fixture"\nweb_search = "disabled"\n[model_providers.fixture]\nname = "fixture"\nbase_url = "http://127.0.0.1:8765/v1"\nwire_api = "responses"\nrequires_openai_auth = false\n')
        invocation = dict(runId=str(uuid4()), cwd="/workspace", sourceRoot=str(source), workflowIdentity="confined-proof",
                          model="fixture-model", codexBinary="/usr/local/bin/codex")
        initial, sealed = root / "input.json", root / "request.json"
        initial.write_text(json.dumps(invocation))
        prepared = subprocess.run([str(executable), "prepare", str(initial), str(sealed)], env=env, capture_output=True, timeout=30)
        if prepared.returncode:
            raise RuntimeError("fixture_prepare_failed", prepared.stderr[-2048:])
        request = json.loads(sealed.read_text())
        capture = Path(request["captureRoot"])
        captured_yaml = next(capture.rglob("confined-proof.yaml"))
        expected_bytes = captured_yaml.read_bytes()
        # A source replacement after capture must not change the executed graph.
        source_yaml.write_text("name: replaced\nnodes: []\n")
        (root / "host-private").mkdir()
        canary = root / "host-private/host-canary"
        canary.write_text("synthetic host-only content")
        attack = '''import ctypes, errno, http.client, json, os, socket, subprocess, sys
from pathlib import Path
capture, canary = CAPTURE, CANARY
checks = []
def denied(name, action):
    try: action()
    except OSError: checks.append(name)
    else: raise AssertionError(name + " was permitted")
assert not Path(canary).exists()
assert not os.environ.get("HOST_SECRET")
assert not Path("/opt/archon-data").exists()
assert not Path("/var/run/docker.sock").exists()
denied("source-write", lambda: Path(capture).write_text("mutated"))
link = Path("/workspace/escape")
link.unlink(missing_ok=True)
link.symlink_to(canary)
denied("symlink-host-write", lambda: link.write_text("mutated"))
lib = ctypes.CDLL(None, use_errno=True)
assert lib.unshare(0x10000000) == -1 and ctypes.get_errno() == errno.EPERM
checks.append("nested-namespace")
connection = socket.socket()
connection.settimeout(1)
denied("network", lambda: connection.connect(("192.0.2.1", 443)))
connection.close()
for path in ("/merge", "/secrets", "/deploy", "/verification", "/progress", "/v1/responses?override=1"):
    connection = http.client.HTTPConnection("localhost", timeout=3)
    connection.sock = socket.socket(socket.AF_UNIX)
    connection.sock.connect("/broker/model.sock")
    connection.request("POST", path, b"{}", {"Content-Type": "application/json"})
    response = connection.getresponse()
    assert response.status == 403, (path, response.status)
    response.read()
    connection.close()
    checks.append("denied:" + path)
if len(sys.argv) == 1:
    Path("/workspace/implementation.txt").write_text("controlled implementation")
    subprocess.run(["git", "add", "implementation.txt"], check=True)
    subprocess.run(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "implementation"], check=True)
    Path("/workspace/tool-proof.json").write_text(json.dumps(checks))
else:
    assert Path("/workspace/tool-proof.json").is_file()
    assert Path("/workspace/implementation.txt").read_text() == "controlled implementation"
    Path("/workspace/test-proof.json").write_text(json.dumps(checks))
'''.replace("CAPTURE", repr(str(captured_yaml))).replace("CANARY", repr(str(canary)))
        (workspace / "attack.py").write_text(attack)
        model = SyntheticModel("python3 /workspace/attack.py")
        from . import model_broker
        original_validate = model_broker.validate_body
        def record_validation(body, selected_model):
            value = json.loads(body)
            model.request_shapes.append({"keys": sorted(value), "stream": value.get("stream"),
                                         "tools": [tool.get("type") for tool in value.get("tools", [])],
                                         "store": value.get("store"), "model": value.get("model")})
            return original_validate(body, selected_model)
        model_broker.validate_body = record_validation
        server = Broker(broker / "model.sock", model)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        mounts = WorkerMounts(executable, sealed, workspace, state, capture, native_config, broker,
                              Path(__file__).with_name("gateway.py").resolve(), node)
        try:
            # Duplicate writable roots must fail before bwrap can expose aliases.
            from dataclasses import replace
            try:
                arguments(replace(mounts, workspace=state), 0)
            except ValueError:
                pass
            else:
                raise AssertionError("writable alias accepted")
            result = run(mounts, timeout=60)
        finally:
            server.shutdown()
            server.server_close()
            thread.join()
            model_broker.validate_body = original_validate
        if result.returncode or result.timed_out:
            raise RuntimeError("fixture_worker_failed", result.returncode, result.stderr[-2048:], result.stdout[-2048:])
        if json.loads((workspace / "result.json").read_text()) != {"status": "completed"}:
            raise RuntimeError("engine_fixture_failed", result.stderr[-4096:], result.stdout[-4096:], model.request_shapes)
        tool_checks = json.loads((workspace / "tool-proof.json").read_text())
        test_checks = json.loads((workspace / "test-proof.json").read_text())
        assert captured_yaml.read_bytes() == expected_bytes
        assert canary.read_text() == "synthetic host-only content"
        assert not list(state.rglob("archon.db"))
        def digest(path):
            with path.open("rb") as stream:
                return hashlib.file_digest(stream, "sha256").hexdigest()
        native_candidates = list(Path("/usr/local/lib/node_modules/@openai/codex/node_modules").glob(
            "@openai/codex-linux-x64/vendor/*/bin/codex"))
        if len(native_candidates) != 1:
            raise RuntimeError("native_codex_identity_unresolved")
        return {"kind": "experimental-worker-probe", "full_runtime_conformance": False,
                "worker_sha256": digest(executable),
                "worker_build": json.loads(subprocess.check_output([str(executable), "identity"], env=env)),
                "codex_version": subprocess.check_output(["/usr/local/bin/codex", "--version"], text=True).strip(),
                "native_codex_sha256": digest(native_candidates[0]), "node_sha256": digest(node / "bin/node"),
                "probe_files": {name: digest(Path(__file__).with_name(name)) for name in
                                ("conformance.py", "linux.py", "model_broker.py", "gateway.py", "staging.py")},
                "closure_sha256": request["workflowRevision"], "model_calls": model.calls,
                "request_shapes": model.request_shapes, "tool_checks": tool_checks, "test_checks": test_checks,
                "source_replacement_ignored": True, "host_canary_unchanged": True, "engine_database_in_memory": True,
                "publication_supported": False, "live_acceptance": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--worker", type=Path, required=True)
    parser.add_argument("--node-distribution", type=Path, required=True)
    options = parser.parse_args()
    print(json.dumps(probe(options.worker.resolve(), options.node_distribution.resolve()), indent=2))
