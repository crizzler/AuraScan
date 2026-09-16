"""Privileged repair of local repository mirror configuration.

When :mod:`aurascan.core.repository_state` reports a mirrorlist with no active
servers whose companion backup still has servers, this module restores the
mirrorlist from that verified backup: it copies the current file into a run
backup directory first, installs the backup over the target, preserves owner and
mode, and writes a manifest describing every action. Copies and installs run
through a captured ``sudo`` identity when the targets need privilege.

Callers own authorization: this module never decides whether a repair should be
attempted, never prompts, and never verifies that the repair worked afterwards
(the incident workflow re-checks repository state and rolls back with its own
backup when verification fails). It does not use the network.
"""

import json
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

from aurascan.core.repository_state import (
    RepositoryHealthCheck,
    RepositoryMirrorIssue,
    count_active_servers,
)
from aurascan.core.trusted_executable import (
    TRUSTED_SUDO_PATH,
    TrustedExecutable,
    UnsafeUpgradeExecutable,
    capture_trusted_executable,
    run_trusted_command,
)

REPOSITORY_HEALTH_BACKUP_ROOT = Path("/var/lib/aurascan/repo-health")


@dataclass
class RepositoryRepairResult:
    success: bool
    applied: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    backup_dir: str = ""


def apply_repository_health_repairs(
    check: RepositoryHealthCheck,
    *,
    runner: Callable = subprocess.run,
    backup_root: Path = REPOSITORY_HEALTH_BACKUP_ROOT,
    sudo_executable: Optional[TrustedExecutable] = None,
) -> RepositoryRepairResult:
    issues = check.fixable_issues
    if not issues:
        return RepositoryRepairResult(success=True)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    backup_dir = backup_root / run_id
    result = RepositoryRepairResult(success=False, backup_dir=str(backup_dir))
    use_sudo = repository_repair_needs_sudo(issues, backup_root)
    manifest = {
        "run_id": run_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "pacman_conf_path": check.pacman_conf_path,
        "actions": [],
    }

    if use_sudo and sudo_executable is None:
        try:
            sudo_executable = capture_trusted_executable("sudo", TRUSTED_SUDO_PATH)
        except UnsafeUpgradeExecutable as exc:
            result.errors.append(f"repository repair executable trust check failed: {exc}")
            return result

    try:
        if use_sudo:
            command = [sudo_executable.path, "mkdir", "-p", str(backup_dir)]
            status = run_trusted_command(command, [sudo_executable], runner=runner, check=False)
            if int(getattr(status, "returncode", 0)) != 0:
                result.errors.append(f"failed to create backup directory: {' '.join(command)}")
                return result
        else:
            backup_dir.mkdir(parents=True, exist_ok=True)

        for issue in issues:
            target = Path(issue.include_path)
            source = Path(issue.backup_path)
            if not source.exists():
                result.errors.append(f"backup mirrorlist is missing: {source}")
                return result
            if count_active_servers(source) <= 0:
                result.errors.append(f"backup mirrorlist has no active servers: {source}")
                return result
            if target.exists():
                mode = target.stat().st_mode & 0o7777
                owner = target.stat().st_uid
                group = target.stat().st_gid
            else:
                mode = 0o644
                owner = 0
                group = 0
            backup_path = backup_dir / target.name
            if use_sudo:
                copy_status = run_trusted_command(
                    [sudo_executable.path, "cp", "-a", str(target), str(backup_path)],
                    [sudo_executable],
                    runner=runner,
                    check=False,
                )
                if int(getattr(copy_status, "returncode", 0)) != 0:
                    result.errors.append(f"failed to back up {target} to {backup_path}")
                    return result
                install_command = [
                    sudo_executable.path,
                    "install",
                    "-o",
                    str(owner),
                    "-g",
                    str(group),
                    "-m",
                    f"{mode & 0o777:o}",
                    str(source),
                    str(target),
                ]
                install_status = run_trusted_command(
                    install_command,
                    [sudo_executable],
                    runner=runner,
                    check=False,
                )
                if int(getattr(install_status, "returncode", 0)) != 0:
                    result.errors.append(f"failed to restore {target} from {source}")
                    return result
            else:
                if target.exists():
                    shutil.copy2(target, backup_path)
                shutil.copy2(source, target)
                try:
                    os.chmod(target, mode)
                    if os.geteuid() == 0:
                        current = target.stat()
                        if current.st_uid != owner or current.st_gid != group:
                            os.chown(target, owner, group)
                except OSError as exc:
                    result.errors.append(f"restored {target} but could not preserve ownership/mode: {exc}")
                    return result

            result.applied.append(str(target))
            manifest["actions"].append({
                "action": "restore_from_backup",
                "target": str(target),
                "source": str(source),
                "backup": str(backup_path),
                "repositories": list(issue.repositories),
                "mode": f"{mode & 0o777:o}",
                "owner": owner,
                "group": group,
            })

        manifest_path = backup_dir / "manifest.json"
        write_repository_repair_manifest(
            manifest_path,
            manifest,
            runner=runner,
            use_sudo=use_sudo,
            sudo_executable=sudo_executable,
        )
    except (OSError, UnsafeUpgradeExecutable) as exc:
        result.errors.append(str(exc))
        return result

    result.success = True
    return result


def repository_repair_needs_sudo(issues: List[RepositoryMirrorIssue], backup_root: Path) -> bool:
    if os.geteuid() == 0:
        return False
    paths = [Path(issue.include_path) for issue in issues] + [backup_root]
    return any(str(path).startswith(("/etc/", "/var/")) or str(path) in {"/etc", "/var"} for path in paths)


def write_repository_repair_manifest(
    manifest_path: Path,
    manifest: Dict[str, object],
    *,
    runner: Callable,
    use_sudo: bool,
    sudo_executable: Optional[TrustedExecutable] = None,
) -> None:
    text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    if not use_sudo:
        manifest_path.write_text(text, encoding="utf-8")
        return
    if sudo_executable is None:
        raise UnsafeUpgradeExecutable("trusted sudo identity is unavailable for repository repair")
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
        handle.write(text)
        tmp_path = Path(handle.name)
    try:
        status = run_trusted_command(
            [sudo_executable.path, "install", "-m", "0644", str(tmp_path), str(manifest_path)],
            [sudo_executable],
            runner=runner,
            check=False,
        )
        if int(getattr(status, "returncode", 0)) != 0:
            raise OSError(f"failed to write repair manifest to {manifest_path}")
    finally:
        try:
            tmp_path.unlink()
        except OSError:
            pass
