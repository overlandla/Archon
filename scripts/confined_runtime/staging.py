"""Bounded descriptor-relative copy into a new supervisor-owned release directory."""
import os
from pathlib import Path
import shutil
import stat


def stage(source: Path, destination: Path) -> None:
    """Reject links/special files and incomplete reads; never follow source links.

    The configured source and destination parents must be trusted. The destination
    must remain inaccessible to workers and other writers through capture and
    sealing. Concurrent source edits can produce rejection or a different closure
    digest; the supervisor must still compare that digest with the requested one.
    """
    if not source.is_absolute() or not destination.is_absolute():
        raise ValueError("staging_requires_absolute_paths")
    descriptor = os.open(source, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    created = False
    entries, total = 0, 0
    try:
        destination.mkdir(mode=0o700)
        created = True
        def visit(directory_fd, target, depth=0):
            nonlocal entries, total
            if depth > 32:
                raise ValueError("source_depth_exceeded")
            for name in os.listdir(directory_fd):
                entries += 1
                if entries > 10000:
                    raise ValueError("source_entries_exceeded")
                child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                                dir_fd=directory_fd)
                try:
                    info = os.fstat(child)
                    if stat.S_ISDIR(info.st_mode):
                        (target / name).mkdir(mode=0o700)
                        visit(child, target / name, depth + 1)
                    elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                        if info.st_size > 16 * 1024 * 1024 - total:
                            raise ValueError("source_bytes_exceeded")
                        size = 0
                        with (target / name).open("xb") as output:
                            while data := os.read(child, 65536):
                                size += len(data)
                                total += len(data)
                                if total > 16 * 1024 * 1024 or size > info.st_size:
                                    raise ValueError("source_changed_or_too_large")
                                output.write(data)
                        after = os.fstat(child)
                        if size != info.st_size or (info.st_mtime_ns, info.st_ctime_ns) != (after.st_mtime_ns, after.st_ctime_ns):
                            raise ValueError("source_changed_during_read")
                        (target / name).chmod(0o500 if info.st_mode & 0o111 else 0o400)
                    else:
                        raise ValueError("source_file_kind_unsupported")
                finally:
                    os.close(child)
        visit(descriptor, destination)
    except BaseException:
        if created:
            shutil.rmtree(destination)
        raise
    finally:
        os.close(descriptor)
