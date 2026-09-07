"""Closed regular-file export format; output data never grants publication authority."""
import base64
import hashlib
import re
import shutil
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

MAX_EXPORT_BYTES = 8 * 1024 * 1024
MAX_FILE_BYTES = 1024 * 1024


def relative_path(value) -> str:
    if not isinstance(value, str) or not 0 < len(value) <= 512:
        raise ValueError("invalid_export_path")
    if not re.fullmatch(r"[A-Za-z0-9_.@+/-]+", value) or value.startswith("/"):
        raise ValueError("invalid_export_path")
    parts = value.split("/")
    if len(parts) > 32 or any(
        part in ("", ".", "..") or part.endswith(".") or part.casefold() == ".git" for part in parts
    ):
        raise ValueError("invalid_export_path")
    if str(PurePosixPath(value)) != value:
        raise ValueError("invalid_export_path")
    return value


@dataclass(frozen=True)
class File:
    path: str
    data: bytes
    executable: bool


@dataclass(frozen=True)
class Export:
    files: tuple[File, ...]
    deletions: tuple[str, ...]
    digest: str


def validate(value) -> Export:
    if not isinstance(value, dict) or set(value) != {"files", "deletions"}:
        raise ValueError("invalid_export_shape")
    files, deletions = value["files"], value["deletions"]
    if not isinstance(files, list) or not isinstance(deletions, list) or len(files) + len(deletions) > 256:
        raise ValueError("export_entry_limit")
    result, names, total = [], [], 0
    digest = hashlib.sha256(b"archon-file-export-v1\0")
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "size", "sha256", "content", "executable"}:
            raise ValueError("invalid_export_file")
        path = relative_path(item["path"])
        if type(item["size"]) is not int or not 0 <= item["size"] <= MAX_FILE_BYTES or type(item["executable"]) is not bool:
            raise ValueError("invalid_export_file")
        if not isinstance(item["content"], str) or len(item["content"]) > 4 * ((MAX_FILE_BYTES + 2) // 3):
            raise ValueError("export_file_too_large")
        data = base64.b64decode(item["content"], validate=True)
        if len(data) != item["size"] or hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise ValueError("export_content_mismatch")
        total += len(data)
        if total > MAX_EXPORT_BYTES:
            raise ValueError("export_byte_limit")
        names.append(path)
        result.append(File(path, data, item["executable"]))
    removed = tuple(relative_path(path) for path in deletions)
    names.extend(removed)
    if len(set(names)) != len(names):
        raise ValueError("duplicate_export_path")
    for path in names:
        if any(str(parent) in names for parent in PurePosixPath(path).parents if str(parent) != "."):
            raise ValueError("export_path_conflict")
    for item in sorted(result, key=lambda item: item.path):
        digest.update(b"file\0" + item.path.encode() + b"\0" + str(len(item.data)).encode() + b"\0")
        digest.update(b"x\0" if item.executable else b"-\0")
        digest.update(item.data)
    for path in sorted(removed):
        digest.update(b"delete\0" + path.encode() + b"\0")
    return Export(tuple(result), removed, digest.hexdigest())


def retain(export: Export, destination: Path) -> None:
    """Write only into a fresh, supervisor-owned directory under a trusted parent.

    No worker has a mount or descriptor for this staging area. A failed export
    leaves no partial directory. Its identity is independent of model claims.
    """
    destination.mkdir(mode=0o700)
    try:
        for item in export.files:
            target = destination / item.path
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with target.open("xb") as stream:
                stream.write(item.data)
            target.chmod(0o500 if item.executable else 0o400)
    except BaseException:
        shutil.rmtree(destination)
        raise
