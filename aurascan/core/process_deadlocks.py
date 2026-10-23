"""Bounded detection of wait-then-read pipe deadlocks in running processes.

This is a read-only ``/proc`` diagnostic.  It never signals, attaches to, or
executes an inspected process.  The detected shape is deliberately narrow: a
parent is sleeping in a wait syscall while its ``lsmod`` child is blocked
writing to a filled pipe.  That is the signature of a process that started but
cannot reach its event loop.
"""

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional


MAX_PROCESSES = 8192
MAX_PROC_READ = 64 * 1024
MAX_DEADLOCKS = 32


@dataclass(frozen=True)
class WaitReadDeadlock:
    parent_pid: int
    parent_comm: str
    parent_executable: str
    child_pid: int
    child_comm: str
    child_wchan: str
    age_seconds: float


@dataclass(frozen=True)
class _ProcessInfo:
    pid: int
    ppid: int
    comm: str
    state: str
    start_seconds: float


def _read_text(path: Path, *, max_chars: int = MAX_PROC_READ) -> str:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return handle.read(max_chars)
    except OSError:
        return ""


def _readlink(path: Path) -> str:
    try:
        return os.readlink(path)
    except OSError:
        return ""


def _process_info(proc_dir: Path) -> Optional[_ProcessInfo]:
    stat_text = _read_text(proc_dir / "stat")
    left = stat_text.find("(")
    right = stat_text.rfind(")")
    if left <= 0 or right <= left:
        return None
    comm = stat_text[left + 1:right]
    fields = stat_text[right + 2:].split()
    if len(fields) < 20:
        return None
    try:
        state = fields[0]
        ppid = int(fields[1])
        start_ticks = int(fields[19])
    except ValueError:
        return None
    try:
        ticks = os.sysconf("SC_CLK_TCK")
    except (OSError, ValueError):
        return None
    if ticks <= 0:
        return None
    return _ProcessInfo(
        pid=int(proc_dir.name),
        ppid=ppid,
        comm=comm,
        state=state,
        start_seconds=start_ticks / ticks,
    )


def detect_wait_then_read_deadlocks(
    *,
    proc_root: Path = Path("/proc"),
    min_age_seconds: float = 2.0,
    max_processes: int = MAX_PROCESSES,
) -> List[WaitReadDeadlock]:
    """Return bounded ``lsmod`` wait-then-read deadlock evidence."""

    uptime_text = _read_text(proc_root / "uptime", max_chars=128).split()
    try:
        uptime = float(uptime_text[0])
    except (IndexError, ValueError):
        return []
    try:
        entries = sorted(
            (entry for entry in proc_root.iterdir() if entry.name.isdigit()),
            key=lambda entry: int(entry.name),
        )
    except OSError:
        return []
    processes: Dict[int, _ProcessInfo] = {}
    for entry in entries[:max_processes]:
        info = _process_info(entry)
        if info is not None:
            processes[info.pid] = info
    deadlocks: List[WaitReadDeadlock] = []
    for info in processes.values():
        if info.comm != "lsmod":
            continue
        age = max(0.0, uptime - info.start_seconds)
        if age < min_age_seconds:
            continue
        child_wchan = _read_text(proc_root / str(info.pid) / "wchan", max_chars=256).strip()
        if "pipe_write" not in child_wchan:
            continue
        parent = processes.get(info.ppid)
        if parent is None or parent.comm == "lsmod":
            continue
        parent_wchan = _read_text(proc_root / str(parent.pid) / "wchan", max_chars=256).strip()
        if "wait" not in parent_wchan:
            continue
        executable = _readlink(proc_root / str(parent.pid) / "exe")
        deadlocks.append(
            WaitReadDeadlock(
                parent_pid=parent.pid,
                parent_comm=parent.comm,
                parent_executable=executable,
                child_pid=info.pid,
                child_comm=info.comm,
                child_wchan=child_wchan,
                age_seconds=age,
            )
        )
        if len(deadlocks) >= MAX_DEADLOCKS:
            break
    return sorted(deadlocks, key=lambda item: (item.parent_comm, item.parent_pid))


def cached_downgrade_path(
    *,
    package: str,
    installed_version: str,
    cache_root: Path = Path("/var/cache/pacman/pkg"),
    version_compare=None,
) -> Optional[Path]:
    """Return the newest cached regular archive older than ``installed_version``."""

    if not package or not installed_version:
        return None
    if version_compare is None:
        from aurascan.core.local_package_db import compare_versions_with_vercmp

        version_compare = compare_versions_with_vercmp
    prefix = f"{package}-"
    suffix = ".pkg.tar.zst"
    candidates = []
    try:
        entries = list(cache_root.glob(f"{package}-*{suffix}"))
    except OSError:
        return None
    for path in entries:
        name = path.name
        if not name.startswith(prefix) or not name.endswith(suffix):
            continue
        candidate_version = name[len(prefix):-len(suffix)].rsplit("-", 1)[0]
        if not candidate_version or candidate_version == installed_version:
            continue
        comparison = version_compare(installed_version, candidate_version)
        if comparison is None or comparison <= 0:
            continue
        try:
            metadata = path.lstat()
        except OSError:
            continue
        if not stat.S_ISREG(metadata.st_mode):
            continue
        candidates.append((metadata.st_mtime, path))
    if not candidates:
        return None
    return max(candidates, key=lambda item: item[0])[1]
