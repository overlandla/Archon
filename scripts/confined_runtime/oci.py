"""Immutable-image worker with finite resource authority and read-only host inputs.

Only the trusted supervisor may instantiate this boundary. Launch callers cannot
provide Docker arguments, image names, mount destinations or resource overrides.
"""
import json
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from .linux import WorkerExit
from .watchdog import OWNER_LABEL
from .watchdog import start as start_watchdog

DOCKER_CONFIG = Path(__file__).resolve().parent / "packaging/docker-client"
DOCKER = ["/usr/bin/docker", "--config", str(DOCKER_CONFIG), "--host", "unix:///var/run/docker.sock"]
ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin"}
MEMORY = 1024 * 1024 * 1024
def tmpfs(state: Path, capture: Path, workspace: str | None = None):
    project = capture.parents[3]
    # Legacy Docker graph drivers preserve private host ancestor modes when
    # creating nested mount targets. Supply root-owned, traversable container-only
    # ancestors; never make the supervisor's host staging directories public.
    ancestors = {str(parent): "rw,nosuid,nodev,size=1m,mode=0555,uid=0,gid=0"
                 for parent in state.parents if parent.is_relative_to('/tmp') and parent != Path('/tmp')}
    return {
        **ancestors,
        **({workspace: "rw,nosuid,nodev,size=512m,mode=0700,uid=65532,gid=65532"} if workspace else {}),
        "/workspace": "rw,nosuid,nodev,size=512m,mode=0700,uid=65532,gid=65532",
        str(capture.parent): "rw,nosuid,nodev,size=128m,mode=0700,uid=65532,gid=65532",
        str(project / "state"): "rw,nosuid,nodev,size=32m,mode=0700,uid=65532,gid=65532",
        str(project / "logs"): "rw,nosuid,nodev,size=32m,mode=0700,uid=65532,gid=65532",
        str(state / "logs"): "rw,nosuid,nodev,size=8m,mode=0700,uid=65532,gid=65532",
        "/home/worker/.codex": "rw,nosuid,nodev,size=32m,mode=0700,uid=65532,gid=65532",
        "/tmp": "rw,nosuid,nodev,size=64m,mode=1777",
    }


def seccomp_policy() -> dict:
    denied = ["unshare", "setns", "mount", "umount2", "pivot_root", "chroot",
              "fsopen", "fsconfig", "fsmount", "move_mount", "open_tree", "mount_setattr",
              "open_by_handle_at", "ptrace", "process_vm_readv", "process_vm_writev", "bpf",
              "io_uring_setup", "userfaultfd", "kexec_load", "kexec_file_load", "init_module",
              "finit_module", "delete_module", "reboot"]
    rules = [{"names": denied, "action": "SCMP_ACT_ERRNO", "errnoRet": 1},
             {"names": ["clone3"], "action": "SCMP_ACT_ERRNO", "errnoRet": 38}]
    for flag in (0x20000, 0x2000000, 0x4000000, 0x8000000, 0x10000000, 0x20000000, 0x40000000, 0x80):
        rules.append({"names": ["clone"], "action": "SCMP_ACT_ERRNO", "errnoRet": 1,
                      "args": [{"index": 0, "value": flag, "valueTwo": flag, "op": "SCMP_CMP_MASKED_EQ"}]})
    return {"defaultAction": "SCMP_ACT_ALLOW", "architectures": ["SCMP_ARCH_X86_64"], "syscalls": rules}


@dataclass(frozen=True)
class Inputs:
    image: str
    request: Path
    repository: Path
    state: Path
    capture: Path
    native_config: Path
    model_socket: Path
    action_socket: Path
    lifecycle_socket: Path
    seccomp: Path
    git_socket: Path | None = None
    workspace: str | None = None

    def mounts(self):
        mounts = {
            "/input/request.json": self.request,
            "/input/repository": self.repository,
            str(self.state): self.state,
            str(self.capture): self.capture,
            "/home/worker/.codex/config.toml": self.native_config,
            "/broker/model.sock": self.model_socket,
            "/broker/actions.sock": self.action_socket,
            "/broker/lifecycle.sock": self.lifecycle_socket,
        }
        if self.git_socket is not None:
            mounts["/broker/git.sock"] = self.git_socket
        return mounts


def create_arguments(inputs: Inputs, name: str) -> list[str]:
    if json.loads((DOCKER_CONFIG / "config.json").read_bytes()) != {}:
        raise ValueError("unsupported_docker_client_configuration")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", inputs.image):
        raise ValueError("oci_image_must_be_immutable")
    for path in [*inputs.mounts().values(), inputs.seccomp, inputs.state]:
        if not path.is_absolute() or path.resolve(strict=True) != path or "," in str(path):
            raise ValueError("oci_mount_not_canonical")
    if (not inputs.capture.is_relative_to(inputs.state) or inputs.capture.name != "workflow-source"
            or inputs.capture.parents[1].name != "runs" or inputs.capture.parents[2].name != "artifacts"):
        raise ValueError("oci_capture_outside_state")
    if not str(inputs.state).startswith("/tmp/"):
        raise ValueError("oci_state_target_unsupported")
    actual = json.loads(inputs.seccomp.read_bytes())
    if actual != seccomp_policy():
        raise ValueError("oci_seccomp_policy_mismatch")
    args = DOCKER + ["create", "--name", name, "--label", f"{OWNER_LABEL}={name}", "--pull", "never", "--network", "none", "--read-only",
        "--user", "65532:65532", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--security-opt", f"seccomp={inputs.seccomp}", "--ipc", "private", "--cgroupns", "private",
        "--pids-limit", "128", "--memory", str(MEMORY), "--memory-swap", str(MEMORY), "--cpus", "2",
        "--shm-size", str(16 * 1024 * 1024), "--log-driver", "none", "--no-healthcheck",
        "--ulimit", "nofile=256:256", "--ulimit", "core=0:0", "--workdir", "/workspace",
        "--env", "HOME=/home/worker", "--env", "CODEX_HOME=/home/worker/.codex",
        "--env", f"ARCHON_HOME={inputs.state}", "--env", "DATABASE_URL=", "--env", "LOG_LEVEL=error",
        "--env", "GIT_CONFIG_NOSYSTEM=1", "--env", "GIT_CONFIG_GLOBAL=/dev/null"]
    for target, options in tmpfs(inputs.state, inputs.capture, inputs.workspace).items():
        args += ["--tmpfs", f"{target}:{options}"]
    for target, source in inputs.mounts().items():
        args += ["--mount", f"type=bind,source={source},target={target},readonly"]
    return args + [inputs.image]


def inspect_created(container: dict, inputs: Inputs) -> None:
    host = container["HostConfig"]
    config = container["Config"]
    expected = {"NetworkMode": "none", "ReadonlyRootfs": True, "Privileged": False,
                "Memory": MEMORY, "MemorySwap": MEMORY, "NanoCpus": 2_000_000_000,
                "PidsLimit": 128, "ShmSize": 16 * 1024 * 1024, "IpcMode": "private",
                "CgroupnsMode": "private", "PidMode": "", "UTSMode": "", "Tmpfs": tmpfs(inputs.state, inputs.capture, inputs.workspace)}
    if any(host.get(key) != value for key, value in expected.items()):
        raise RuntimeError("oci_enforcement_mismatch")
    if host.get("CapDrop") != ["ALL"] or host.get("CapAdd") or host.get("Devices") or host.get("DeviceRequests"):
        raise RuntimeError("oci_privilege_mismatch")
    if container["Image"] != inputs.image or config.get("User") != "65532:65532":
        raise RuntimeError("oci_identity_mismatch")
    security = host.get("SecurityOpt", [])
    seccomp = [value.removeprefix("seccomp=") for value in security if value.startswith("seccomp=")]
    if "no-new-privileges" not in security or len(seccomp) != 1 or json.loads(seccomp[0]) != seccomp_policy():
        raise RuntimeError("oci_security_policy_mismatch")
    mounts = container["Mounts"]
    if len(mounts) != len(inputs.mounts()) or any(
        value["Type"] != "bind" or value["RW"] or
        inputs.mounts().get(value["Destination"]) != Path(value["Source"]) for value in mounts
    ):
        raise RuntimeError("oci_mount_mismatch")
    if host.get("LogConfig", {}).get("Type") != "none":
        raise RuntimeError("oci_log_storage_unbounded")


def run(inputs: Inputs, *, timeout: float = 300, retain_owner=None, authorize_start=None) -> WorkerExit:
    if not 0 < timeout <= 900:
        raise ValueError("oci_timeout_out_of_range")
    name = "archon-confined-" + str(uuid4())
    created = False
    attempted = False
    watchdog = None
    deadline = time.monotonic() + timeout
    if retain_owner is not None:
        retain_owner({"name": name, "image": inputs.image, "expires_at": time.time() + timeout})
    try:
        arguments = create_arguments(inputs, name)
        watchdog = start_watchdog(name, timeout, inputs.image)
        attempted = True
        result = subprocess.run(arguments, env=ENV, capture_output=True, timeout=30)
        if result.returncode:
            raise RuntimeError("oci_create_failed")
        created = True
        value = subprocess.check_output(DOCKER + ["inspect", name], env=ENV, timeout=15)
        if len(value) > 1024 * 1024:
            raise RuntimeError("oci_inspection_too_large")
        inspect_created(json.loads(value)[0], inputs)
        if time.monotonic() >= deadline or watchdog.poll() is not None:
            raise RuntimeError("worker_lease_expired")
        # Attach before start. The daemon owns and limits the complete process
        # tree; the worker never receives the daemon socket or host descriptors.
        if authorize_start is not None:
            authorize_start()
        process = subprocess.Popen(DOCKER + ["start", "--attach", name], env=ENV,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        buffers = [bytearray(), bytearray()]
        def drain(stream, buffer):
            try:
                while chunk := stream.read(65536):
                    buffer.extend(chunk[:max(0, 65536 - len(buffer))])
            finally:
                stream.close()
        threads = [threading.Thread(target=drain, args=(stream, buffer))
                   for stream, buffer in zip((process.stdout, process.stderr), buffers)]
        for thread in threads:
            thread.start()
        timed_out = False
        try:
            process.wait(timeout=max(.001, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            timed_out = True
            subprocess.run(DOCKER + ["kill", name], env=ENV, capture_output=True, timeout=15, check=True)
            process.wait(timeout=15)
        finally:
            for thread in threads:
                thread.join(timeout=15)
            if any(thread.is_alive() for thread in threads):
                raise RuntimeError("oci_attachment_did_not_terminate")
        return WorkerExit(process.returncode, timed_out, bytes(buffers[0]), bytes(buffers[1]))
    finally:
        if attempted:
            result = subprocess.run(DOCKER + ["rm", "--force", name], env=ENV, capture_output=True, timeout=30)
            if result.returncode and created:
                raise RuntimeError("oci_cleanup_uncertain")
        if watchdog is not None and watchdog.poll() is None:
            # Normal cleanup removed the exact container. Detached watchdog is
            # stopped only after removal acknowledgement, never on create doubt.
            if attempted and result.returncode == 0:
                watchdog.terminate()
                watchdog.wait(timeout=5)
