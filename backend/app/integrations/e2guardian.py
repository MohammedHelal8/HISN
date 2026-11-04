"""Safe, idempotent STAGING to a dedicated HISN-owned domain list.

STAGED / ALREADY_STAGED does not mean E2Guardian enforced the block. An
administrator must integrate the file as an approved list and validate/reload
E2Guardian. Destination IP policies require a different adapter.
"""
import fcntl
import os
import stat
from pathlib import Path
from app.security_engine.log_parser import normalize_destination


class PolicyWriteError(RuntimeError):
    pass


def stage_block(destination: str, managed_path: str) -> str:
    if not managed_path:
        raise PolicyWriteError('HISN_MANAGED_BLOCKLIST is unset')
    value = normalize_destination(destination)
    from ipaddress import ip_address
    try:
        ip_address(value)
    except ValueError:
        pass
    else:
        raise PolicyWriteError('Only domain destinations supported by this adapter')
    path = Path(managed_path)
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise PolicyWriteError('Managed list must be an existing regular absolute-path file')
    parent = path.parent
    if parent.is_symlink() or parent.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise PolicyWriteError('Managed list directory has unsafe permissions')
    # O_NOFOLLOW prevents replacing the file with a symlink between validation and open.
    fd = os.open(str(path), os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise PolicyWriteError('Unsafe managed list file ownership/permissions')
        with os.fdopen(fd, 'r+', encoding='utf-8') as handle:
            fd = -1
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            existing = {s.strip() for s in handle if s.strip() and not s.startswith('#')}
            if value in existing:
                return 'ALREADY_STAGED'
            handle.seek(0, os.SEEK_END)
            handle.write(value + '\n')
            handle.flush()
            os.fsync(handle.fileno())
    finally:
        if fd != -1:
            os.close(fd)
    return 'STAGED'
