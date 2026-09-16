"""Trusted executable identity for upgrade and repair handoffs.

AuraScan hands control to system tools (``pacman``, ``sudo``, AUR helpers) and
runs privileged repair commands. Every one of those calls starts from a captured
executable identity rather than a bare name on ``PATH``.

A captured identity binds the absolute path, device, inode, owner, group and
mode observed at capture time. ``revalidate_trusted_executable`` re-observes
those values immediately before use, so a file replaced between the preflight
and the handoff is refused instead of executed.

The rules enforced here come from the repository contract:

* the path must be absolute and normalized;
* neither the final file nor any path component may be a symlink;
* every component and the final file must be root-owned and not group/world
  writable, and must not be writable by the current non-root user;
* the final file must be a regular executable file.

This module is a trust check, not a sandbox. A same-UID attacker can still
replace an executable after revalidation, and root can replace the tools
themselves. Treat the result as risk reduction and keep those limits explicit
in user-facing claims.
"""

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Sequence


TRUSTED_SUDO_PATH = "/usr/bin/sudo"
TRUSTED_PACMAN_PATH = "/usr/bin/pacman"


class UnsafeUpgradeExecutable(RuntimeError):
    """Raised when an upgrade executable cannot be bound to a trusted file."""


@dataclass(frozen=True)
class TrustedExecutable:
    name: str
    path: str
    device: int
    inode: int
    owner: int
    group: int
    mode: int

    def to_dict(self) -> Dict[str, object]:
        return {"name": self.name, "path": self.path}


def trusted_executable_stat(name: str, path: str, *, required_owner: int = 0) -> os.stat_result:
    candidate = Path(path)
    if not candidate.is_absolute() or ".." in candidate.parts:
        raise UnsafeUpgradeExecutable(f"{name} executable path must be absolute and normalized")

    try:
        final_stat = os.lstat(str(candidate))
    except OSError as exc:
        raise UnsafeUpgradeExecutable(f"trusted {name} executable is unavailable: {exc}")
    if stat.S_ISLNK(final_stat.st_mode):
        raise UnsafeUpgradeExecutable(f"trusted {name} executable must not be a symlink")
    if not stat.S_ISREG(final_stat.st_mode):
        raise UnsafeUpgradeExecutable(f"trusted {name} executable is not a regular file")
    if final_stat.st_uid != required_owner:
        raise UnsafeUpgradeExecutable(f"trusted {name} executable is not root-owned")
    if final_stat.st_mode & 0o022:
        raise UnsafeUpgradeExecutable(f"trusted {name} executable is group/world writable")
    if os.geteuid() != 0 and os.access(str(candidate), os.W_OK):
        raise UnsafeUpgradeExecutable(f"trusted {name} executable is writable by the current user")
    if not final_stat.st_mode & 0o111:
        raise UnsafeUpgradeExecutable(f"trusted {name} executable is not executable")

    current = Path(candidate.anchor)
    components = [current]
    for component in candidate.parts[1:-1]:
        current = current / component
        components.append(current)
    for component in components:
        try:
            component_stat = os.lstat(str(component))
        except OSError as exc:
            raise UnsafeUpgradeExecutable(f"trusted {name} path component is unavailable: {exc}")
        if stat.S_ISLNK(component_stat.st_mode):
            raise UnsafeUpgradeExecutable(f"trusted {name} path contains a symlink component")
        if not stat.S_ISDIR(component_stat.st_mode):
            raise UnsafeUpgradeExecutable(f"trusted {name} path component is not a directory")
        if component_stat.st_uid != 0:
            raise UnsafeUpgradeExecutable(f"trusted {name} path contains a non-root-owned component")
        if component_stat.st_mode & 0o022:
            raise UnsafeUpgradeExecutable(f"trusted {name} path contains a group/world-writable component")
        if os.geteuid() != 0 and os.access(str(component), os.W_OK):
            raise UnsafeUpgradeExecutable(f"trusted {name} path contains a current-user-writable component")
    return final_stat


def capture_trusted_executable(name: str, path: str) -> TrustedExecutable:
    metadata = trusted_executable_stat(name, path)
    return TrustedExecutable(
        name=name,
        path=str(Path(path)),
        device=int(metadata.st_dev),
        inode=int(metadata.st_ino),
        owner=int(metadata.st_uid),
        group=int(metadata.st_gid),
        mode=int(metadata.st_mode),
    )


def revalidate_trusted_executable(executable: TrustedExecutable) -> None:
    metadata = trusted_executable_stat(
        executable.name, executable.path, required_owner=executable.owner
    )
    observed = (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_uid),
        int(metadata.st_gid),
        int(metadata.st_mode),
    )
    expected = (
        executable.device,
        executable.inode,
        executable.owner,
        executable.group,
        executable.mode,
    )
    if observed != expected:
        raise UnsafeUpgradeExecutable(
            f"trusted {executable.name} executable changed after preflight; run a fresh preflight"
        )


def run_trusted_command(
    command: Sequence[str],
    executables: Sequence[TrustedExecutable],
    *,
    runner: Callable,
    **kwargs,
):
    """Revalidate every bound executable, then run the exact argument vector.

    The revalidation call intentionally resolves through this module's globals
    so callers (including tests) can substitute the trust check without
    replacing the execution helper itself.
    """
    for executable in executables:
        revalidate_trusted_executable(executable)
    return runner(list(command), **kwargs)
