"""Linux process boundary enclosing the engine, Codex and every descendant.

The caller supplies only supervisor-owned mounts. No credentials or host home
are forwarded. This primitive establishes confinement, not admission authority.
"""
from __future__ import annotations

import ctypes
import errno
import os
import platform
import signal
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path


class ConfinementUnavailable(RuntimeError):
    pass


class _Comparison(ctypes.Structure):
    _fields_ = [("arg", ctypes.c_uint), ("op", ctypes.c_int),
                ("a", ctypes.c_uint64), ("b", ctypes.c_uint64)]


def seccomp_filter() -> int:
    """Return an owned BPF fd; reject platforms not exercised by this policy.

    libseccomp rejects other syscall architectures by default. clone3 returns
    ENOSYS so runtimes can fall back to clone, whose namespace bits are denied.
    This closes the nested-userns remount path even when the LXC exposes the
    user namespace sysctl read-only and bwrap --disable-userns cannot run.
    """
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ConfinementUnavailable("confinement_platform_unsupported")
    try:
        lib = ctypes.CDLL("libseccomp.so.2")
    except OSError as exc:
        raise ConfinementUnavailable("confinement_seccomp_unavailable") from exc
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    lib.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int,
                                          ctypes.c_uint, ctypes.POINTER(_Comparison)]
    lib.seccomp_export_bpf.argtypes = [ctypes.c_void_p, ctypes.c_int]
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    context = lib.seccomp_init(0x7FFF0000)  # SCMP_ACT_ALLOW
    if not context:
        raise ConfinementUnavailable("confinement_seccomp_failed")
    fd = -1
    try:
        def number(name: str) -> int:
            value = lib.seccomp_syscall_resolve_name(name.encode("ascii"))
            if value < 0:
                raise ConfinementUnavailable("confinement_syscall_unsupported")
            return value

        def require(result: int) -> None:
            if result != 0:
                raise ConfinementUnavailable("confinement_seccomp_failed")

        denied = (
            "unshare", "setns", "mount", "umount2", "pivot_root", "chroot",
            "fsopen", "fsconfig", "fsmount", "move_mount", "open_tree", "mount_setattr",
            "open_by_handle_at", "ptrace", "process_vm_readv", "process_vm_writev",
            "bpf", "io_uring_setup", "userfaultfd", "kexec_load", "kexec_file_load",
            "init_module", "finit_module", "delete_module", "reboot",
        )
        for name in denied:
            require(lib.seccomp_rule_add(context, 0x50000 | errno.EPERM, number(name), 0))
        require(lib.seccomp_rule_add(context, 0x50000 | errno.ENOSYS, number("clone3"), 0))
        # CLONE_NEW{NS,CGROUP,UTS,IPC,USER,PID,NET,TIME}; ordinary threads remain allowed.
        for flag in (0x20000, 0x2000000, 0x4000000, 0x8000000,
                     0x10000000, 0x20000000, 0x40000000, 0x80):
            comparison = _Comparison(0, 7, flag, flag)  # SCMP_CMP_MASKED_EQ
            require(lib.seccomp_rule_add_array(context, 0x50000 | errno.EPERM,
                                               number("clone"), 1, ctypes.byref(comparison)))
        fd = os.memfd_create("archon-confinement-filter", os.MFD_CLOEXEC)
        require(lib.seccomp_export_bpf(context, fd))
        os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except BaseException:
        if fd >= 0:
            os.close(fd)
        raise
    finally:
        lib.seccomp_release(context)


@dataclass(frozen=True)
class WorkerMounts:
    executable: Path
    request: Path
    workspace: Path
    state: Path
    capture: Path
    native_config: Path
    broker: Path
    gateway: Path
    node_distribution: Path
    # A private bare repository only; never the operator's shared .git directory.
    git_directory: Path | None = None


def arguments(mounts: WorkerMounts, filter_fd: int) -> list[str]:
    paths = [mounts.executable, mounts.request, mounts.workspace, mounts.state,
             mounts.capture, mounts.native_config, mounts.broker, mounts.gateway,
             mounts.node_distribution]
    if mounts.git_directory is not None:
        paths.append(mounts.git_directory)
    for path in paths:
        if not path.is_absolute() or path.resolve(strict=True) != path:
            raise ValueError("confinement_mount_not_canonical")
    if not mounts.capture.is_relative_to(mounts.state) or mounts.capture == mounts.state:
        raise ValueError("confinement_capture_outside_state")
    # All three must be private siblings, otherwise a broader writable mount
    # would expose the original source, broker or supervisor state to the worker.
    writable = [mounts.workspace, mounts.state]
    if mounts.git_directory is not None:
        writable.append(mounts.git_directory)
    if len(set(writable)) != len(writable):
        raise ValueError("confinement_writable_mounts_alias")
    for left in writable:
        for right in writable:
            if left != right and (left.is_relative_to(right) or right.is_relative_to(left)):
                raise ValueError("confinement_writable_mounts_overlap")
        for private in (mounts.executable, mounts.request, mounts.native_config,
                        mounts.broker, mounts.gateway, mounts.node_distribution):
            if private.is_relative_to(left) or left.is_relative_to(private):
                raise ValueError("confinement_private_mount_overlap")
    args = [
        "bwrap", "--unshare-all", "--unshare-user", "--die-with-parent",
        "--new-session", "--cap-drop", "ALL", "--seccomp", str(filter_fd),
        "--clearenv", "--ro-bind", "/usr", "/usr",
        "--ro-bind", str(mounts.node_distribution), str(mounts.node_distribution),
        "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib",
        "--symlink", "usr/lib64", "/lib64", "--proc", "/proc", "--dev", "/dev",
        "--tmpfs", "/tmp", "--dir", "/home/worker/.codex",
        "--setenv", "HOME", "/home/worker", "--setenv", "CODEX_HOME", "/home/worker/.codex",
        "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
        "--setenv", "ARCHON_HOME", str(mounts.state), "--setenv", "LOG_LEVEL", "error",
        "--setenv", "DATABASE_URL", "", "--setenv", "GIT_CONFIG_NOSYSTEM", "1",
        "--setenv", "GIT_CONFIG_GLOBAL", "/dev/null",
        "--ro-bind", str(mounts.executable), "/runtime/worker",
        "--ro-bind", str(mounts.request), "/request.json",
        "--ro-bind", str(mounts.native_config), "/home/worker/.codex/config.toml",
        "--ro-bind", str(mounts.gateway), "/runtime/gateway.py",
        "--ro-bind", str(mounts.broker), "/broker",
        "--bind", str(mounts.workspace), "/workspace",
        "--bind", str(mounts.state), str(mounts.state),
        "--ro-bind", str(mounts.capture), str(mounts.capture),
    ]
    if mounts.git_directory is not None:
        args += ["--bind", str(mounts.git_directory), str(mounts.git_directory)]
    return args + ["--chdir", "/workspace", "/usr/bin/python3", "/runtime/gateway.py"]


@dataclass(frozen=True)
class WorkerExit:
    returncode: int
    timed_out: bool
    # Bounded test/debug output only; never persist these as lifecycle diagnostics.
    stdout: bytes
    stderr: bytes


def run(mounts: WorkerMounts, *, timeout: float = 60) -> WorkerExit:
    if not 0 < timeout <= 86400:
        raise ValueError("invalid_worker_timeout")
    fd = seccomp_filter()
    try:
        argv = arguments(mounts, fd)
        # Drain continuously, retaining only a bounded prefix. Neither memory nor
        # a temporary output file grows with hostile subprocess output.
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   pass_fds=(fd,), start_new_session=True, env={"PATH": "/usr/bin:/bin"})
        stdout, stderr = bytearray(), bytearray()
        def drain(stream, buffer):
            try:
                while chunk := stream.read(65536):
                    buffer.extend(chunk[:max(0, 65536 - len(buffer))])
            finally:
                stream.close()
        threads = [threading.Thread(target=drain, args=(process.stdout, stdout)),
                   threading.Thread(target=drain, args=(process.stderr, stderr))]
        for thread in threads:
            thread.start()
        timed_out = False
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        finally:
            for thread in threads:
                thread.join()
        return WorkerExit(process.returncode, timed_out, bytes(stdout), bytes(stderr))
    finally:
        os.close(fd)
