"""Local state coordination; never executes repository-supplied code."""
from contextlib import contextmanager
import os
from pathlib import Path


class StateConflict(ValueError):
    pass


class StateCapacity(ValueError):
    pass


HISTORY_LIMIT_BYTES = 32 * 1024 * 1024
RETENTION_LIMITS = {
    "history": 100, "suppression_audit": 500, "remediation_audit": 200,
    "resolved_findings": 500, "monitor_events": 500,
}


@contextmanager
def state_lock(path: Path):
    """Nonblocking OS lock; process death releases it, leftover file is harmless."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as handle:
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise StateConflict("Another process is writing local state; retry after it finishes.") from error
        try:
            yield
        finally:
            if os.name == "nt":
                import msvcrt
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
