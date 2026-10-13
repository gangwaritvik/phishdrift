"""Single-run lock for the collector commands.

Two runs at the same time (the scheduled task plus a manual run) would both read the
first-seen index and the crawl attempts, then each write back its own version, and one
update would be lost. The lock is a file created with ``O_EXCL``. A lock file whose
modification time is older than ``stale_s`` counts as left behind by a killed run (for
example the task scheduler's time limit) and is replaced; long runs call ``touch()`` to
show they are alive.

The process id is only written for a human reading the file: it is never signalled
(``os.kill`` on Windows terminates the process).
"""

from __future__ import annotations

import contextlib
import logging
import os
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

log = logging.getLogger(__name__)


class AlreadyRunning(RuntimeError):
    """Another run holds the lock."""


class Lock:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def touch(self) -> None:
        try:
            os.utime(self.path)
        except OSError:  # the heartbeat must never stop a run
            log.debug("could not refresh %s", self.path)


@contextmanager
def run_lock(path: Path, stale_s: float):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    for attempt in (1, 2):
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            break
        except FileExistsError:
            try:
                age = time.time() - path.stat().st_mtime
            except FileNotFoundError:  # released between the two calls: try again
                continue
            if age <= stale_s:
                raise AlreadyRunning(
                    f"another run holds {path} (updated {age:.0f}s ago, stale after {stale_s:.0f}s)"
                ) from None
            log.warning("replacing a stale lock %s (%.0fs old)", path, age)
            with contextlib.suppress(FileNotFoundError):
                path.unlink()
            if attempt == 2:
                raise AlreadyRunning(f"could not take {path}") from None
    else:
        raise AlreadyRunning(f"could not take {path}")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(f"pid {os.getpid()} started {datetime.now(UTC).isoformat()}\n")
    try:
        yield Lock(path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            path.unlink()
