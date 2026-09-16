"""Repository state: interpret local pacman configuration into inert health values.

This module answers one question for any caller: *what do the local pacman
configuration and mirrorlists say right now?* It reads ``pacman.conf`` and the
mirrorlist files its ``Include`` directives point at, and returns plain
``RepositoryHealthCheck``/``RepositoryMirrorIssue`` values describing enabled
repositories, includes with no active servers and whether a companion backup
mirrorlist is usable.

It performs bounded local file reads and nothing else: no subprocess, no
network, no privilege check, no filesystem mutation, no AI. Repairing anything
it reports is a separate concern with its own authorization (see
:mod:`aurascan.core.repository_repair`).
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

REPO_HEADER_RE = re.compile(r"^\s*\[([^]]+)\]\s*$")
REPO_INCLUDE_RE = re.compile(r"^\s*Include\s*=\s*(.+?)\s*$")
REPO_SERVER_RE = re.compile(r"^\s*Server\s*=")


@dataclass
class RepositoryMirrorIssue:
    repositories: List[str]
    include_path: str
    active_servers: int = 0
    backup_path: str = ""
    backup_active_servers: int = 0
    repair_action: str = ""
    detail: str = ""

    @property
    def fixable(self) -> bool:
        return self.repair_action == "restore_from_backup" and bool(self.backup_path) and self.backup_active_servers > 0

    def to_dict(self) -> Dict[str, object]:
        return {
            "repositories": list(self.repositories),
            "include_path": self.include_path,
            "active_servers": self.active_servers,
            "backup_path": self.backup_path,
            "backup_active_servers": self.backup_active_servers,
            "repair_action": self.repair_action,
            "fixable": self.fixable,
            "detail": self.detail,
        }


@dataclass
class RepositoryHealthCheck:
    enabled_repositories: List[str] = field(default_factory=list)
    issues: List[RepositoryMirrorIssue] = field(default_factory=list)
    pacman_conf_path: str = ""
    status: str = "ok"

    @property
    def fixable_issues(self) -> List[RepositoryMirrorIssue]:
        return [issue for issue in self.issues if issue.fixable]

    @property
    def summary(self) -> str:
        if not self.issues:
            return "enabled repositories have active servers"
        if self.fixable_issues:
            count = len(self.fixable_issues)
            item = "mirrorlist" if count == 1 else "mirrorlists"
            return f"{count} disabled {item} can be restored from backup"
        count = len(self.issues)
        item = "repository include" if count == 1 else "repository includes"
        return f"{count} {item} have no active servers"

    def to_dict(self) -> Dict[str, object]:
        return {
            "enabled_repositories": list(self.enabled_repositories),
            "issues": [issue.to_dict() for issue in self.issues],
            "pacman_conf_path": self.pacman_conf_path,
            "status": self.status,
            "summary": self.summary,
        }


@dataclass
class _RepositoryEntry:
    name: str
    includes: List[Path] = field(default_factory=list)
    server_count: int = 0


def preview_error_indicates_no_servers(error: str) -> bool:
    return "no servers configured for repository" in error.lower()


def build_repository_health_check(pacman_conf_path: Path = Path("/etc/pacman.conf")) -> RepositoryHealthCheck:
    check = RepositoryHealthCheck(pacman_conf_path=str(pacman_conf_path))
    try:
        text = pacman_conf_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        check.status = "error"
        check.issues.append(RepositoryMirrorIssue(
            repositories=[],
            include_path=str(pacman_conf_path),
            detail=f"could not read pacman.conf: {exc}",
        ))
        return check

    entries = parse_pacman_repository_entries(text, base_dir=pacman_conf_path.parent)
    check.enabled_repositories = [entry.name for entry in entries]
    include_repos: Dict[Path, List[str]] = {}
    include_counts: Dict[Path, int] = {}
    for entry in entries:
        if entry.server_count > 0:
            continue
        if not entry.includes:
            check.issues.append(RepositoryMirrorIssue(
                repositories=[entry.name],
                include_path="",
                detail=f"repository {entry.name} has no Server or Include directives",
            ))
            continue
        for include_path in entry.includes:
            count = include_counts.setdefault(include_path, count_active_servers(include_path))
            if count == 0:
                include_repos.setdefault(include_path, []).append(entry.name)

    for include_path, repos in sorted(include_repos.items(), key=lambda item: str(item[0])):
        backup_path = include_path.with_name(include_path.name + "-backup")
        backup_count = count_active_servers(backup_path)
        action = "restore_from_backup" if backup_count > 0 else ""
        detail = (
            "included mirrorlist has no active Server entries; companion backup has active servers"
            if action
            else "included mirrorlist has no active Server entries and no usable companion backup was found"
        )
        check.issues.append(RepositoryMirrorIssue(
            repositories=sorted(set(repos)),
            include_path=str(include_path),
            active_servers=0,
            backup_path=str(backup_path) if backup_path.exists() else "",
            backup_active_servers=backup_count,
            repair_action=action,
            detail=detail,
        ))

    if check.issues:
        check.status = "repair_available" if check.fixable_issues else "broken"
    return check


def parse_pacman_repository_entries(text: str, *, base_dir: Path = Path("/etc")) -> List[_RepositoryEntry]:
    entries: List[_RepositoryEntry] = []
    current: Optional[_RepositoryEntry] = None
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        header = REPO_HEADER_RE.match(raw)
        if header:
            if current and current.name.lower() != "options":
                entries.append(current)
            current = _RepositoryEntry(name=header.group(1).strip())
            continue
        if current is None:
            continue
        include = REPO_INCLUDE_RE.match(raw)
        if include:
            current.includes.append(resolve_pacman_include_path(include.group(1), base_dir=base_dir))
            continue
        if REPO_SERVER_RE.match(raw):
            current.server_count += 1
    if current and current.name.lower() != "options":
        entries.append(current)
    return entries


def resolve_pacman_include_path(value: str, *, base_dir: Path = Path("/etc")) -> Path:
    raw = value.strip().strip('"').strip("'")
    path = Path(raw)
    if not path.is_absolute():
        path = base_dir / path
    return path


def count_active_servers(path: Path) -> int:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return 0
    return sum(1 for line in lines if REPO_SERVER_RE.match(line) and not line.lstrip().startswith("#"))
