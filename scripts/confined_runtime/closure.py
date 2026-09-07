"""Inspect a staged Archon capture before authority checks/repository mutation.

Versioned release artifacts are captured offline by the actual pinned engine.
Runtime admission copies the capture using staging.stage; no YAML parser or
source program runs on the supervisor. The engine independently recomputes both
its native digest and this executable-closure revision before execution.
"""
import hashlib
import json
import re
import stat
from pathlib import Path

from .https_transport import parse_json

CONFIG = {"load_default_commands": False, "load_default_workflows": False}


def inspect(root: Path, identity: str, expected: str) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", identity) or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("invalid_closure_selection")
    # root must be the private, newly staged tree with no other writers.
    manifest_file = root / "manifest.json"
    if manifest_file.stat().st_size > 16384:
        raise ValueError("closure_manifest_too_large")
    manifest = parse_json(manifest_file.read_bytes())
    keys = {"version", "engine_version", "origin", "captured_at", "digest", "file_count", "byte_count", "scopes", "source_config", "workflow_name"}
    if (not isinstance(manifest, dict) or set(manifest) != keys or type(manifest["version"]) is not int
            or manifest["version"] != 1 or manifest["workflow_name"] != identity
            or manifest["source_config"] != CONFIG
            or not isinstance(manifest["source_config"], dict)
            or any(type(value) is not bool for value in manifest["source_config"].values())
            or any(not isinstance(manifest[key], str) for key in ("engine_version", "origin", "captured_at", "digest"))
            or any(type(manifest[key]) is not int or manifest[key] < 0 for key in ("file_count", "byte_count"))
            or not isinstance(manifest["scopes"], list)
            or any(scope not in ("project", "global", "bundled") for scope in manifest["scopes"])):
        raise ValueError("unsupported_closure_manifest")
    native = hashlib.sha256()
    complete = hashlib.sha256(b"archon-immutable-closure-v1\0" + identity.encode() + b"\0")
    complete.update(json.dumps(CONFIG, sort_keys=True, separators=(",", ":")).encode() + b"\0")
    files, size = 0, 0
    for path in sorted(root.rglob("*")):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("unsupported_closure_entry")
        relative = path.relative_to(root).as_posix()
        if relative == "manifest.json":
            continue
        if not re.fullmatch(r"[A-Za-z0-9_.@+/-]+", relative):
            raise ValueError("unsupported_closure_path")
        files += 1
        size += info.st_size
        if files > 10000 or size > 16 * 1024 * 1024:
            raise ValueError("closure_limit_exceeded")
        digest = hashlib.sha256(path.read_bytes()).hexdigest().encode()
        native.update(relative.encode() + b"\0" + digest + b"\n")
        complete.update(relative.encode() + b"\0" + (b"x" if info.st_mode & 0o111 else b"-") + b"\0" + digest + b"\n")
    if native.hexdigest() != manifest["digest"] or complete.hexdigest() != expected:
        raise ValueError("closure_revision_mismatch")
    # Native counts can include files in omitted/default scopes in v0.10; the
    # executable bytes themselves are authoritative and independently bounded.
    return {"workflowRevision": native.hexdigest(), "executableRevision": complete.hexdigest(), "sourceConfig": CONFIG}
