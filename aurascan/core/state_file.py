"""Atomic writes of private state files with an explicit permission mode.

State files that AuraScan owns (incident reports, autopilot policy, tray state)
must never be observable half-written or world-readable. This adapter owns that
single guarantee: write a temporary file in the destination directory, set the
requested mode on it, then replace the destination atomically.

It deliberately holds no schema and no policy: callers decide what data is
private and which mode it requires.
"""

import json
import os
import tempfile
from pathlib import Path


def atomic_write_json(path: Path, data: object, *, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent), text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
        os.chmod(path, mode)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
