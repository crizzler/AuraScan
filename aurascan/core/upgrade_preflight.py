import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen as urllib_urlopen

from aurascan.core.ai_provider import call_ai_provider, resolve_ai_config
from aurascan.core.ai_provider import parse_bool as parse_config_bool
from aurascan.core.config_drift import (
    CONFIG_DRIFT_AI_DIFFS_ENV,
    CONFIG_DRIFT_ENABLED_ENV,
    resolve_config_drift_config,
    run_config_drift,
)
from aurascan.core.compatibility import detect_distro
from aurascan.core.kernel_module_autopilot import (
    KERNEL_MODULE_AUTOPILOT_ENV,
    KernelModuleCheck,
    build_kernel_module_check,
    issues_to_findings,
    kernel_module_fix_command,
)
from aurascan.core.models import SCANNER_VERSION, Severity


UPGRADE_PREFLIGHT_SCHEMA_VERSION = "1.2"
EXIT_PREFLIGHT_UNAVAILABLE = 20
EXIT_USER_DECLINED = 21
EXIT_PREFLIGHT_DISABLED = 22
EXIT_UPGRADE_VERIFICATION_FAILED = 23
EXIT_UPGRADE_COMMAND_FAILED_TO_START = 127
PACMAN_PRINT_FORMAT = "%n\t%v\t%r\t%s\t%D\t%H\t%R"
HIGH_RISK = {Severity.HIGH, Severity.CRITICAL}
SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
UPGRADE_PREFLIGHT_ENABLED_ENV = "AURASCAN_UPGRADE_PREFLIGHT_ENABLED"
UPGRADE_PREFLIGHT_AUR_HELPER_ENV = "AURASCAN_UPGRADE_AUR_HELPER"
UPGRADE_PREFLIGHT_AI_ENV = "AURASCAN_UPGRADE_PREFLIGHT_AI"
UPGRADE_TRUSTED_HANDOFF_ENV = "AURASCAN_UPGRADE_TRUSTED_HANDOFF"
UPGRADE_AUR_HELPERS = {"auto", "paru", "yay", "shelly", "none"}
REPOSITORY_HEALTH_BACKUP_ROOT = Path("/var/lib/aurascan/repo-health")

KERNEL_PACKAGE_RE = re.compile(r"^(linux($|-)|linux-cachyos($|-)|linux-lts($|-)|linux-zen($|-)|linux-hardened($|-))")
INITRAMFS_BOOT_PACKAGES = {
    "mkinitcpio",
    "dracut",
    "grub",
    "systemd",
    "systemd-boot",
    "efibootmgr",
    "booster",
}
ABI_SENSITIVE_PACKAGES = {
    "glibc",
    "gcc-libs",
    "openssl",
    "openssl-1.1",
    "icu",
    "python",
    "perl",
    "ruby",
    "nodejs",
    "electron",
    "qt5-base",
    "qt6-base",
}

REPO_HEADER_RE = re.compile(r"^\s*\[([^]]+)\]\s*$")
REPO_INCLUDE_RE = re.compile(r"^\s*Include\s*=\s*(.+?)\s*$")
REPO_SERVER_RE = re.compile(r"^\s*Server\s*=")
ProgressReporter = Callable[[str], None]


@dataclass
class UpgradePackage:
    name: str
    new_version: str = ""
    old_version: str = ""
    repo: str = ""
    package_type: str = "repo"
    size: str = ""
    depends: List[str] = field(default_factory=list)
    conflicts: List[str] = field(default_factory=list)
    replaces: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "old_version": self.old_version,
            "new_version": self.new_version,
            "repo": self.repo,
            "package_type": self.package_type,
            "size": self.size,
            "depends": list(self.depends),
            "conflicts": list(self.conflicts),
            "replaces": list(self.replaces),
        }


@dataclass
class ForeignPackageInfo:
    name: str
    version: str = ""
    depends: List[str] = field(default_factory=list)
    provides: List[str] = field(default_factory=list)
    conflicts: List[str] = field(default_factory=list)
    missing_depends: List[str] = field(default_factory=list)
    install_script: bool = False

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "version": self.version,
            "depends": list(self.depends),
            "provides": list(self.provides),
            "conflicts": list(self.conflicts),
            "missing_depends": list(self.missing_depends),
            "install_script": self.install_script,
        }


@dataclass
class UpgradePlan:
    repo_packages: List[UpgradePackage] = field(default_factory=list)
    aur_packages: List[UpgradePackage] = field(default_factory=list)
    removals: List[str] = field(default_factory=list)
    replacements: List[str] = field(default_factory=list)
    conflicts: List[str] = field(default_factory=list)
    selected_helper: str = "none"
    helper_error: str = ""
    preview_error: str = ""
    preview_command: List[str] = field(default_factory=list)
    final_command: List[str] = field(default_factory=list)
    command_source: str = "pacman"

    @property
    def available(self) -> bool:
        return not self.preview_error

    def package_names(self) -> List[str]:
        return [pkg.name for pkg in self.repo_packages + self.aur_packages]

    def to_dict(self) -> Dict[str, object]:
        return {
            "repo_packages": [pkg.to_dict() for pkg in self.repo_packages],
            "aur_packages": [pkg.to_dict() for pkg in self.aur_packages],
            "removals": list(self.removals),
            "replacements": list(self.replacements),
            "conflicts": list(self.conflicts),
            "selected_helper": self.selected_helper,
            "helper_error": self.helper_error,
            "preview_error": self.preview_error,
            "preview_command": list(self.preview_command),
            "final_command": list(self.final_command),
            "command_source": self.command_source,
        }


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
class RepositoryRepairResult:
    success: bool
    applied: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    backup_dir: str = ""


@dataclass
class UpgradeFailureDiagnosis:
    kind: str
    title: str
    summary: str
    likely_cause: str
    recommended_action: str
    evidence: List[str] = field(default_factory=list)

    def render_terminal(self) -> str:
        lines = [
            "\n[AuraScan] Upgrade failure diagnosis",
            f"{self.title}.",
            self.summary,
            f"Likely cause: {self.likely_cause}",
            f"Next step: {self.recommended_action}",
        ]
        if self.evidence:
            lines.append("Evidence:")
            for item in self.evidence[:6]:
                lines.append(f"- {item}")
        return "\n".join(lines)


@dataclass
class _RepositoryEntry:
    name: str
    includes: List[Path] = field(default_factory=list)
    server_count: int = 0


@dataclass
class SystemSnapshot:
    running_kernel: str = ""
    distro_info: Dict[str, object] = field(default_factory=dict)
    installed_packages: List[str] = field(default_factory=list)
    foreign_packages: List[str] = field(default_factory=list)
    foreign_package_info: List[ForeignPackageInfo] = field(default_factory=list)
    package_info: List[ForeignPackageInfo] = field(default_factory=list)
    ignored_packages: List[str] = field(default_factory=list)
    ignored_groups: List[str] = field(default_factory=list)
    root_free_mib: Optional[int] = None
    boot_free_mib: Optional[int] = None
    boot_paths: List[str] = field(default_factory=list)
    dkms_packages: List[str] = field(default_factory=list)
    nvidia_packages: List[str] = field(default_factory=list)
    zfs_packages: List[str] = field(default_factory=list)
    virtualbox_packages: List[str] = field(default_factory=list)
    pacnew_count: int = 0
    pacsave_count: int = 0
    pacnew_scan_truncated: bool = False

    @classmethod
    def collect(cls, runner: Callable = subprocess.run, etc_root: Path = Path("/etc")) -> "SystemSnapshot":
        installed_packages = _command_lines(runner, ["pacman", "-Qq"])
        foreign_packages = _command_lines(runner, ["pacman", "-Qqem"])
        ignored_packages = _command_lines(runner, ["pacman-conf", "IgnorePkg"])
        ignored_groups = _command_lines(runner, ["pacman-conf", "IgnoreGroup"])
        boot_paths = [str(path) for path in (Path("/boot"), Path("/boot/efi")) if path.exists()]
        pacnew_count, pacsave_count, truncated = count_pacnew_pacsave(etc_root)

        return cls(
            running_kernel=_command_text(runner, ["uname", "-r"]),
            distro_info=detect_distro().to_dict(),
            installed_packages=installed_packages,
            foreign_packages=foreign_packages,
            foreign_package_info=collect_foreign_package_info(foreign_packages, runner=runner),
            ignored_packages=ignored_packages,
            ignored_groups=ignored_groups,
            root_free_mib=_free_mib(Path("/")),
            boot_free_mib=_free_mib(Path("/boot")) if Path("/boot").exists() else None,
            boot_paths=boot_paths,
            dkms_packages=[name for name in installed_packages if "dkms" in name],
            nvidia_packages=[name for name in installed_packages if name.startswith("nvidia") or "nvidia" in name],
            zfs_packages=[name for name in installed_packages if name.startswith("zfs") or name.startswith("spl")],
            virtualbox_packages=[name for name in installed_packages if name.startswith("virtualbox")],
            pacnew_count=pacnew_count,
            pacsave_count=pacsave_count,
            pacnew_scan_truncated=truncated,
        )

    def to_dict(self) -> Dict[str, object]:
        return {
            "running_kernel": self.running_kernel,
            "distro": dict(self.distro_info),
            "installed_package_count": len(self.installed_packages),
            "foreign_packages": list(self.foreign_packages),
            "foreign_package_info": [item.to_dict() for item in self.foreign_package_info],
            "package_info": [item.to_dict() for item in self.package_info],
            "ignored_packages": list(self.ignored_packages),
            "ignored_groups": list(self.ignored_groups),
            "root_free_mib": self.root_free_mib,
            "boot_free_mib": self.boot_free_mib,
            "boot_paths": list(self.boot_paths),
            "dkms_packages": list(self.dkms_packages),
            "nvidia_packages": list(self.nvidia_packages),
            "zfs_packages": list(self.zfs_packages),
            "virtualbox_packages": list(self.virtualbox_packages),
            "pacnew_count": self.pacnew_count,
            "pacsave_count": self.pacsave_count,
            "pacnew_scan_truncated": self.pacnew_scan_truncated,
        }


@dataclass
class UpgradeFinding:
    rule_id: str
    severity: Severity
    title: str
    summary: str
    why_it_matters: str
    recommended_action: str
    evidence: str = ""
    source: str = "deterministic"

    def __post_init__(self) -> None:
        self.severity = Severity(self.severity.value if isinstance(self.severity, Severity) else str(self.severity))

    def to_dict(self) -> Dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "title": self.title,
            "summary": self.summary,
            "why_it_matters": self.why_it_matters,
            "recommended_action": self.recommended_action,
            "evidence": self.evidence,
            "source": self.source,
        }


@dataclass
class UpgradePreflightReport:
    plan: UpgradePlan
    snapshot: SystemSnapshot
    findings: List[UpgradeFinding] = field(default_factory=list)
    ai_review: Dict[str, object] = field(default_factory=dict)
    kernel_module_check: Optional[KernelModuleCheck] = None
    repository_health: Optional[RepositoryHealthCheck] = None
    schema_version: str = UPGRADE_PREFLIGHT_SCHEMA_VERSION
    scanner_version: str = SCANNER_VERSION

    @property
    def highest_severity(self) -> Severity:
        if not self.findings:
            return Severity.LOW
        return max((finding.severity for finding in self.findings), key=SEVERITY_ORDER.index)

    @property
    def requires_confirmation(self) -> bool:
        return self.highest_severity in HIGH_RISK

    @property
    def action(self) -> str:
        if not self.plan.available:
            return "unavailable"
        if self.requires_confirmation:
            return "confirm"
        return "continue"

    def risk_summary(self) -> Dict[str, object]:
        return {
            "severity": self.highest_severity.value,
            "action": self.action,
            "requires_confirmation": self.requires_confirmation,
            "blocks_upgrade": False,
            "reason": self._risk_reason(),
        }

    def _risk_reason(self) -> str:
        if not self.findings:
            return "No upgrade preflight findings were produced; this is not proof the upgrade is safe."
        return "highest preflight severity: " + self.highest_severity.value

    def transaction_change_count(self) -> int:
        return len(self.plan.removals) + len(applicable_replacements(self.plan, self.snapshot))

    def terminal_findings(self) -> List[UpgradeFinding]:
        indexed = list(enumerate(self.findings))
        indexed.sort(key=lambda item: (-SEVERITY_ORDER.index(item[1].severity), item[0]))
        return [finding for _, finding in indexed]

    def to_dict(self) -> Dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "scanner_version": self.scanner_version,
            "report_type": "upgrade_preflight",
            "risk_summary": self.risk_summary(),
            "plan": self.plan.to_dict(),
            "system_snapshot": self.snapshot.to_dict(),
            "kernel_module_check": self.kernel_module_check.to_dict() if self.kernel_module_check else {"enabled": False, "status": "not_run"},
            "repository_health": self.repository_health.to_dict() if self.repository_health else {"enabled": False, "status": "not_run"},
            "findings": [finding.to_dict() for finding in self.findings],
            "ai_review": dict(self.ai_review),
        }

    def to_json(self, *, indent: Optional[int] = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def render_terminal(self, *, use_color: bool = True, verbose: bool = False) -> str:
        reset = "\033[0m" if use_color else ""
        red = "\033[91m" if use_color else ""
        yellow = "\033[93m" if use_color else ""
        green = "\033[92m" if use_color else ""
        color = red if self.highest_severity == Severity.CRITICAL else yellow if self.requires_confirmation else green

        lines = [
            "\n[AuraScan] Upgrade Preflight",
            "=" * 50,
            f"Repo upgrades: {len(self.plan.repo_packages)} | AUR upgrades: {len(self.plan.aur_packages)} | Removals/Replacements: {self.transaction_change_count()}",
            f"Risk: {color}{self.highest_severity.value}{reset} | Action: {color}{self.action.upper()}{reset} | Helper: {self.plan.selected_helper}",
            f"Planned command: {' '.join(self.plan.final_command) if self.plan.final_command else '(none)'}",
            "-" * 50,
        ]
        lines.extend(self._check_summary_lines())

        if self.plan.preview_error:
            lines.append("Preflight unavailable.")
            lines.append(self.plan.preview_error)
        elif not self.findings:
            lines.append("[INFO] No upgrade preflight findings were produced. This is not proof the upgrade is safe.")

        terminal_findings = self.terminal_findings()
        visible = terminal_findings if verbose else terminal_findings[:3]
        if visible:
            lines.append("Upgrade risks:")
            for index, finding in enumerate(visible, start=1):
                lines.append(f"{index}. {finding.title} [{finding.severity.value}]")
                lines.append(finding.summary)
                if finding.why_it_matters:
                    lines.append(f"Why it matters: {finding.why_it_matters}")
                if finding.recommended_action:
                    lines.append(f"Before upgrading: {finding.recommended_action}")
                if verbose and finding.evidence:
                    lines.append(f"Technical details: {finding.rule_id}: {finding.evidence}")
                lines.append("")
            if lines[-1] == "":
                lines.pop()

        hidden = len(terminal_findings) - len(visible)
        if hidden > 0:
            note = "additional upgrade risk hidden" if hidden == 1 else "additional upgrade risks hidden"
            lines.append(f"{hidden} {note}. Use --verbose to show all.")

        if self.ai_review:
            status = str(self.ai_review.get("status") or "unknown")
            provider = str(self.ai_review.get("provider") or "")
            summary = str(self.ai_review.get("summary") or "")
            label = f"AI review: {status}" + (f" ({provider})" if provider else "")
            lines.append(label)
            if summary:
                lines.append(summary)

        if self.action == "confirm":
            lines.append("\nRecommended Action: Review the risks above before continuing.")
        elif self.action == "unavailable":
            lines.append("\nRecommended Action: Do not run the upgrade from AuraScan until the preview problem is resolved.")
        else:
            lines.append("\nRecommended Action: Continue only with normal package-manager judgment.")
        return "\n".join(lines)

    def _check_summary_lines(self) -> List[str]:
        lines: List[str] = []
        if self.repository_health and self.repository_health.issues:
            lines.append(f"Repository health: {self.repository_health.summary}.")
        if self.kernel_module_check and self.kernel_module_check.enabled:
            lines.append(f"Kernel/module check: {self.kernel_module_check.summary}.")
        if self.snapshot.foreign_packages:
            issue_count = sum(1 for finding in self.findings if finding.rule_id in {"UPG-AUR-DEPENDENCY-MISSING", "UPG-AUR-CONFLICTS"})
            if self.plan.selected_helper != "none" and not self.plan.helper_error:
                status = "dependency issues not detected" if issue_count == 0 else f"dependency/conflict issues={issue_count}"
                lines.append(f"Foreign package check: {len(self.snapshot.foreign_packages)} installed, {len(self.plan.aur_packages)} helper updates, {status}.")
            elif self.plan.helper_error:
                lines.append(f"Foreign package check: {len(self.snapshot.foreign_packages)} installed, helper query unavailable.")
            else:
                lines.append(f"Foreign package check: {len(self.snapshot.foreign_packages)} installed, helper updates not checked.")
        if self.snapshot.pacnew_count or self.snapshot.pacsave_count:
            lines.append(f"Config drift check: {self.snapshot.pacnew_count} .pacnew, {self.snapshot.pacsave_count} .pacsave files counted under /etc.")
        if lines:
            lines.append("-" * 50)
        return lines


@dataclass
class UpgradeConfig:
    preflight_enabled: bool = True
    aur_helper: str = "auto"
    ai_enabled: bool = True
    kernel_module_autopilot_enabled: bool = True
    trusted_handoff_enabled: bool = True
    error: str = ""


@dataclass
class UpgradeOptions:
    dry_run: bool = False
    json_output: bool = False
    verbose: bool = False
    yes: bool = False
    no_ai: bool = False
    aur_helper: str = "auto"
    preflight_enabled: bool = True
    config_drift_enabled: bool = True
    config_drift_ai_diffs: bool = False
    kernel_module_autopilot_enabled: bool = True
    trusted_handoff_enabled: bool = True
    config_error: str = ""
    config_drift_error: str = ""


def build_upgrade_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aurascan upgrade",
        description="Preview and preflight Arch-family upgrades before handing off to pacman or an AUR helper.",
    )
    parser.add_argument("--dry-run", action="store_true", help="show the preflight report without running the upgrade command")
    parser.add_argument("--json", action="store_true", dest="json_output", help="emit a structured JSON preflight report")
    parser.add_argument("--verbose", action="store_true", help="show all preflight findings and technical details")
    parser.add_argument("--yes", action="store_true", help="skip AuraScan's high-risk confirmation prompt")
    parser.add_argument("--no-ai", action="store_true", help="disable AI upgrade risk review for this run")
    parser.add_argument("--no-config-drift", action="store_true", help="skip the config drift assistant before and after the upgrade")
    parser.add_argument("--no-kernel-module-autopilot", action="store_true", help="skip deterministic kernel/module compatibility autopilot checks")
    parser.add_argument("--no-trusted-handoff", action="store_true", help="keep the package manager's own confirmation prompt even after a passing AuraScan preflight")
    parser.add_argument("--config-drift-ai-diffs", action="store_true", help="allow config drift assistant AI to inspect redacted bounded diffs")
    preflight = parser.add_mutually_exclusive_group()
    preflight.add_argument("--enable-preflight", action="store_true", help="run upgrade preflight even if disabled in config")
    preflight.add_argument("--disable-preflight", action="store_true", help="disable preflight for this invocation and do not run the upgrade")
    parser.add_argument("--aur-helper", choices=sorted(UPGRADE_AUR_HELPERS), default=None, help="AUR helper integration to use")
    return parser


def resolve_upgrade_config(env: Optional[Mapping[str, str]] = None) -> UpgradeConfig:
    source = env if env is not None else os.environ
    enabled_raw = source.get(UPGRADE_PREFLIGHT_ENABLED_ENV)
    preflight_enabled = parse_config_bool(enabled_raw)
    if enabled_raw is not None and preflight_enabled is None:
        return UpgradeConfig(error=f"invalid {UPGRADE_PREFLIGHT_ENABLED_ENV} value")
    if preflight_enabled is None:
        preflight_enabled = True

    ai_raw = source.get(UPGRADE_PREFLIGHT_AI_ENV)
    ai_enabled = parse_config_bool(ai_raw)
    if ai_raw is not None and ai_enabled is None:
        return UpgradeConfig(error=f"invalid {UPGRADE_PREFLIGHT_AI_ENV} value")
    if ai_enabled is None:
        ai_enabled = True

    autopilot_raw = source.get(KERNEL_MODULE_AUTOPILOT_ENV)
    autopilot_enabled = parse_config_bool(autopilot_raw)
    if autopilot_raw is not None and autopilot_enabled is None:
        return UpgradeConfig(error=f"invalid {KERNEL_MODULE_AUTOPILOT_ENV} value")
    if autopilot_enabled is None:
        autopilot_enabled = True

    handoff_raw = source.get(UPGRADE_TRUSTED_HANDOFF_ENV)
    handoff_enabled = parse_config_bool(handoff_raw)
    if handoff_raw is not None and handoff_enabled is None:
        return UpgradeConfig(error=f"invalid {UPGRADE_TRUSTED_HANDOFF_ENV} value")
    if handoff_enabled is None:
        handoff_enabled = True

    aur_helper = source.get(UPGRADE_PREFLIGHT_AUR_HELPER_ENV, "auto").strip().lower() or "auto"
    if aur_helper not in UPGRADE_AUR_HELPERS:
        return UpgradeConfig(error=f"invalid {UPGRADE_PREFLIGHT_AUR_HELPER_ENV} value")

    return UpgradeConfig(
        preflight_enabled=bool(preflight_enabled),
        aur_helper=aur_helper,
        ai_enabled=bool(ai_enabled),
        kernel_module_autopilot_enabled=bool(autopilot_enabled),
        trusted_handoff_enabled=bool(handoff_enabled),
    )


def options_from_args(args: argparse.Namespace, env: Optional[Mapping[str, str]] = None) -> UpgradeOptions:
    config = resolve_upgrade_config(env)
    drift_config = resolve_config_drift_config(env)
    preflight_enabled = config.preflight_enabled
    if bool(getattr(args, "enable_preflight", False)):
        preflight_enabled = True
    if bool(getattr(args, "disable_preflight", False)):
        preflight_enabled = False
    aur_helper = str(args.aur_helper or config.aur_helper)
    config_drift_enabled = bool(preflight_enabled and drift_config.enabled and not getattr(args, "no_config_drift", False))
    config_drift_ai_diffs = bool(getattr(args, "config_drift_ai_diffs", False) or drift_config.ai_diffs == "always")
    kernel_module_autopilot_enabled = bool(config.kernel_module_autopilot_enabled and not getattr(args, "no_kernel_module_autopilot", False))
    trusted_handoff_enabled = bool(config.trusted_handoff_enabled and not getattr(args, "no_trusted_handoff", False))
    return UpgradeOptions(
        dry_run=bool(args.dry_run),
        json_output=bool(args.json_output),
        verbose=bool(args.verbose),
        yes=bool(args.yes),
        no_ai=bool(args.no_ai) or not config.ai_enabled,
        aur_helper=aur_helper,
        preflight_enabled=preflight_enabled,
        config_drift_enabled=config_drift_enabled,
        config_drift_ai_diffs=config_drift_ai_diffs,
        kernel_module_autopilot_enabled=kernel_module_autopilot_enabled,
        trusted_handoff_enabled=trusted_handoff_enabled,
        config_error=config.error,
        config_drift_error=drift_config.error,
    )


def run_upgrade(
    argv: Optional[Sequence[str]] = None,
    *,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
    input_func: Callable[[str], str] = input,
    stdout=None,
    stderr=None,
    snapshot: Optional[SystemSnapshot] = None,
    urlopen: Optional[Callable] = None,
    config_drift_root: Optional[Path] = None,
    config_drift_runner: Callable = run_config_drift,
    modules_root: Path = Path("/usr/lib/modules"),
    pacman_conf_path: Path = Path("/etc/pacman.conf"),
    repository_repair_backup_root: Path = REPOSITORY_HEALTH_BACKUP_ROOT,
) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    args = build_upgrade_parser().parse_args(list(argv or []))
    options = options_from_args(args)

    if options.config_error:
        report = build_upgrade_unavailable_report(options.config_error)
        if options.json_output:
            print(report.to_json(), file=stdout)
        else:
            print(report.render_terminal(verbose=options.verbose), file=stdout)
        return EXIT_PREFLIGHT_UNAVAILABLE

    if not options.preflight_enabled:
        report = build_upgrade_unavailable_report("upgrade preflight is disabled by configuration or command-line option")
        if options.json_output:
            print(report.to_json(), file=stdout)
        else:
            print(report.render_terminal(verbose=options.verbose), file=stdout)
            print("[AuraScan] Upgrade command was not run. Use --enable-preflight or update AuraScan config to enable this feature.", file=stderr)
        return EXIT_PREFLIGHT_DISABLED

    progress = upgrade_progress_reporter(options, stdout)
    progress("Starting upgrade preflight.")
    report = run_upgrade_preflight(
        options,
        runner=runner,
        which=which,
        snapshot=snapshot,
        urlopen=urlopen,
        modules_root=modules_root,
        pacman_conf_path=pacman_conf_path,
        progress=progress,
    )

    if not report.plan.available and not options.dry_run and not options.json_output:
        repaired = run_repository_health_autopilot_repairs(
            report,
            options,
            runner=runner,
            input_func=input_func,
            stdout=stdout,
            stderr=stderr,
            backup_root=repository_repair_backup_root,
        )
        if repaired:
            report = run_upgrade_preflight(
                options,
                runner=runner,
                which=which,
                snapshot=snapshot,
                urlopen=urlopen,
                modules_root=modules_root,
                pacman_conf_path=pacman_conf_path,
                progress=progress,
            )

    apply_trusted_handoff(report, options)

    if options.json_output:
        print(report.to_json(), file=stdout)
    else:
        print(report.render_terminal(verbose=options.verbose), file=stdout)

    if not report.plan.available:
        return EXIT_PREFLIGHT_UNAVAILABLE
    if options.dry_run:
        run_upgrade_config_drift("dry-run", options, input_func=input_func, stdout=stdout, stderr=stderr, root=config_drift_root, snapshot=snapshot, runner=config_drift_runner)
        return 0
    if options.json_output and not options.yes:
        return 0
    if not options.dry_run and not options.json_output:
        fix_status = run_kernel_module_autopilot_fixes(
            report,
            options,
            runner=runner,
            input_func=input_func,
            stdout=stdout,
            stderr=stderr,
            which=which,
            snapshot=snapshot,
            urlopen=urlopen,
            modules_root=modules_root,
            pacman_conf_path=pacman_conf_path,
            progress=progress,
        )
        if fix_status is not None:
            return fix_status
    if report.requires_confirmation and not options.yes:
        answer = input_func("AuraScan found upgrade risks. Continue anyway? [y/N] ").strip().lower()
        if answer not in {"y", "yes"}:
            print("[AuraScan] Upgrade not run.", file=stderr)
            return EXIT_USER_DECLINED

    run_upgrade_config_drift("before", options, input_func=input_func, stdout=stdout, stderr=stderr, root=config_drift_root, snapshot=snapshot, runner=config_drift_runner)
    print_trusted_handoff_note(report, options, stdout=stdout, stderr=stderr)
    print_package_manager_handoff_context(report, options, stdout=stdout, stderr=stderr)
    try:
        result = runner(report.plan.final_command, check=False)
    except OSError as exc:
        print(f"[AuraScan] Upgrade command failed to start: {exc}", file=stderr)
        return EXIT_UPGRADE_COMMAND_FAILED_TO_START
    result_code = int(getattr(result, "returncode", 0))
    if result_code == 0:
        verification = verify_upgrade_handoff(report.plan, runner=runner)
        if verification:
            print("[AuraScan] Upgrade command reported success, but planned package versions were not installed.", file=stderr)
            for item in verification[:12]:
                print(f"[AuraScan] Not upgraded: {item}", file=stderr)
            if len(verification) > 12:
                print(f"[AuraScan] {len(verification) - 12} additional planned packages did not verify.", file=stderr)
            print_upgrade_failure_diagnosis(report.plan, options, runner=runner, urlopen=urlopen, stdout=stdout, stderr=stderr)
            print("[AuraScan] Skipping post-upgrade aftercare because the package transaction did not verify.", file=stderr)
            return EXIT_UPGRADE_VERIFICATION_FAILED
        print_verified_upgrade_summary(report.plan, options, stdout=stdout, stderr=stderr)
        run_upgrade_kernel_module_aftercare(options, plan=report.plan, runner=runner, stdout=stdout, stderr=stderr, snapshot=snapshot, modules_root=modules_root)
        run_upgrade_config_drift("after", options, input_func=input_func, stdout=stdout, stderr=stderr, root=config_drift_root, snapshot=snapshot, runner=config_drift_runner)
    else:
        print_upgrade_failure_diagnosis(report.plan, options, runner=runner, urlopen=urlopen, stdout=stdout, stderr=stderr)
    return result_code


def verify_upgrade_handoff(plan: UpgradePlan, *, runner: Callable = subprocess.run) -> List[str]:
    expected = {pkg.name: pkg.new_version for pkg in plan.repo_packages if pkg.name and pkg.new_version}
    if not expected:
        return []
    installed = installed_package_versions(expected.keys(), runner=runner)
    missing: List[str] = []
    for name, version in expected.items():
        installed_version = installed.get(name, "")
        if installed_version != version:
            found = installed_version or "(not installed)"
            missing.append(f"{name} expected {version}, found {found}")
    return missing


def installed_package_versions(packages: Iterable[str], *, runner: Callable = subprocess.run) -> Dict[str, str]:
    names = sorted({name for name in packages if name})
    if not names:
        return {}
    try:
        result = runner(["pacman", "-Q"] + names, capture_output=True, text=True, check=False)
    except OSError:
        return {}
    versions: Dict[str, str] = {}
    output = str(getattr(result, "stdout", "") or "")
    for raw in output.splitlines():
        parts = raw.strip().split(maxsplit=1)
        if len(parts) == 2:
            versions[parts[0]] = parts[1]
    return versions


def upgrade_progress_reporter(options: UpgradeOptions, stdout) -> ProgressReporter:
    if options.json_output:
        return lambda _message: None

    def report(message: str) -> None:
        print(f"[AuraScan] {message}", file=stdout, flush=True)

    return report


def print_upgrade_failure_diagnosis(
    plan: UpgradePlan,
    options: UpgradeOptions,
    *,
    runner: Callable = subprocess.run,
    urlopen: Optional[Callable] = None,
    stdout=None,
    stderr=None,
) -> None:
    diagnosis = diagnose_upgrade_failure(plan, runner=runner, urlopen=urlopen)
    if diagnosis is None:
        return
    stream = stderr if options.json_output else stdout
    print(diagnosis.render_terminal(), file=stream)


def diagnose_upgrade_failure(
    plan: UpgradePlan,
    *,
    runner: Callable = subprocess.run,
    urlopen: Optional[Callable] = None,
    max_urls: int = 60,
) -> Optional[UpgradeFailureDiagnosis]:
    urls = planned_package_download_urls(plan, runner=runner, max_urls=max_urls)
    missing = [url for url in urls if package_url_status(url, urlopen=urlopen) in {404, 410}]
    if not missing:
        return None
    return UpgradeFailureDiagnosis(
        kind="mirror_not_found",
        title="Package mirror looks temporarily out of sync",
        summary=(
            "One or more package files from the current pacman database are missing on the selected mirror. "
            "This is usually a mirror sync race, not a sign that the upgrade damaged the installed system."
        ),
        likely_cause=(
            "The repository database was refreshed before that mirror finished publishing the matching package archive."
        ),
        recommended_action=(
            "Wait a little and run AuraScan upgrade again, or refresh/rank mirrors if the same package URL keeps returning NotFound."
        ),
        evidence=missing,
    )


def planned_package_download_urls(
    plan: UpgradePlan,
    *,
    runner: Callable = subprocess.run,
    max_urls: int = 60,
) -> List[str]:
    names = [pkg.name for pkg in plan.repo_packages if pkg.name]
    if not names:
        return []
    with tempfile.TemporaryDirectory(prefix="aurascan-url-check.") as cache_dir:
        cmd = ["pacman", "-Sp", "--cachedir", cache_dir] + names[:max_urls]
        try:
            result = runner(cmd, capture_output=True, text=True, check=False)
        except OSError:
            return []
    output = "\n".join([
        str(getattr(result, "stdout", "") or ""),
        str(getattr(result, "stderr", "") or ""),
    ])
    urls: List[str] = []
    for raw in output.splitlines():
        line = raw.strip()
        if line.startswith(("http://", "https://")) and line.endswith(".pkg.tar.zst"):
            urls.append(line)
    return urls[:max_urls]


def package_url_status(url: str, *, urlopen: Optional[Callable] = None, timeout: int = 4) -> int:
    opener = urlopen or urllib_urlopen
    try:
        request = Request(url, method="HEAD", headers={"User-Agent": "AuraScan upgrade failure diagnosis"})
        with opener(request, timeout=timeout) as response:
            return int(getattr(response, "status", 200) or 200)
    except HTTPError as exc:
        return int(exc.code)
    except (URLError, TimeoutError, OSError, ValueError):
        return 0


def apply_trusted_handoff(report: UpgradePreflightReport, options: UpgradeOptions) -> bool:
    command = trusted_handoff_command(report, options)
    changed = command != report.plan.final_command
    report.plan.final_command = command
    return changed


def trusted_handoff_command(report: UpgradePreflightReport, options: UpgradeOptions) -> List[str]:
    command = helper_upgrade_command(report.plan.selected_helper)
    if not should_use_trusted_handoff(report, options):
        return command
    if report.plan.selected_helper == "shelly":
        return command + ["--no-confirm"]
    return command


def should_use_trusted_handoff(report: UpgradePreflightReport, options: UpgradeOptions) -> bool:
    if not options.trusted_handoff_enabled or not report.plan.available:
        return False
    if report.requires_confirmation:
        return False
    return report.plan.selected_helper == "shelly"


def print_trusted_handoff_note(report: UpgradePreflightReport, options: UpgradeOptions, *, stdout, stderr=None) -> None:
    if should_use_trusted_handoff(report, options):
        stream = stderr if options.json_output and stderr is not None else stdout
        print("[AuraScan] Preflight passed; using Shelly --no-confirm so the approved upgrade continues without a second default-no prompt.", file=stream)


def print_package_manager_handoff_context(
    report: UpgradePreflightReport,
    options: UpgradeOptions,
    *,
    stdout,
    stderr,
) -> None:
    stream = stderr if options.json_output else stdout
    helper = "Shelly/pacman" if report.plan.selected_helper == "shelly" else "the package manager"
    print("\n[AuraScan] Package-manager handoff", file=stream, flush=True)
    print(
        f"Download, mirror, and package-transition lines below come from {helper} and configured repositories, not AuraScan.",
        file=stream,
        flush=True,
    )
    print(
        "A mirror-specific NotFound/404 can be recovered automatically by the next mirror. "
        "AuraScan will verify every planned repository version before reporting success.",
        file=stream,
        flush=True,
    )
    transitions = package_transition_descriptions(report.plan)
    if transitions:
        print(f"Declared repository transition: {transitions[0]}", file=stream, flush=True)
        if len(transitions) > 1:
            print(f"Additional declared transitions: {len(transitions) - 1}", file=stream, flush=True)


def print_verified_upgrade_summary(
    plan: UpgradePlan,
    options: UpgradeOptions,
    *,
    stdout,
    stderr,
) -> None:
    stream = stderr if options.json_output else stdout
    planned_count = len([pkg for pkg in plan.repo_packages if pkg.name and pkg.new_version])
    print("\n[AuraScan] Upgrade transaction verified", file=stream)
    if planned_count == 1:
        print("The planned repository package version is installed.", file=stream)
    elif planned_count > 1:
        print(f"All {planned_count} planned repository package versions are installed.", file=stream)
    else:
        print("No repository package version required post-upgrade verification.", file=stream)
    print(
        "Any mirror-specific NotFound/404 messages shown during this successful run were recovered by package-manager fallback. "
        "They came from repository infrastructure, not AuraScan, and require no action for this completed transaction.",
        file=stream,
    )
    transitions = package_transition_descriptions(plan)
    if transitions:
        print(
            "Declared conflicts/replacements were repository package metadata used to complete the transition; "
            "AuraScan verified the resulting package versions.",
            file=stream,
        )


def package_transition_descriptions(plan: UpgradePlan, *, limit: int = 12) -> List[str]:
    descriptions: List[str] = []
    for pkg in plan.repo_packages:
        details: List[str] = []
        if pkg.replaces:
            details.append("replaces " + ", ".join(pkg.replaces))
        if pkg.conflicts:
            details.append("conflicts with " + ", ".join(pkg.conflicts))
        if not details:
            continue
        source = f"{pkg.repo}/{pkg.name}" if pkg.repo else pkg.name
        descriptions.append(f"{source} " + "; ".join(details))
        if len(descriptions) >= limit:
            break
    return descriptions


def run_kernel_module_autopilot_fixes(
    report: UpgradePreflightReport,
    options: UpgradeOptions,
    *,
    runner: Callable,
    input_func: Callable[[str], str],
    stdout,
    stderr,
    which: Callable[[str], Optional[str]],
    snapshot: Optional[SystemSnapshot],
    urlopen: Optional[Callable],
    modules_root: Path,
    pacman_conf_path: Path,
    progress: Optional[ProgressReporter] = None,
) -> Optional[int]:
    check = report.kernel_module_check
    if not options.kernel_module_autopilot_enabled or check is None or not check.fix_packages():
        return None
    command = kernel_module_fix_command(check)
    if not command:
        return None
    packages = ", ".join(command[4:])
    answer = input_func(f"AuraScan can install missing kernel support packages: {packages}. Apply fix before upgrading? [Y/n] ").strip().lower()
    if answer in {"", "y", "yes"}:
        print(f"[AuraScan] Running kernel/module fix: {' '.join(command)}", file=stdout)
        try:
            result = runner(command, check=False)
        except OSError as exc:
            print(f"[AuraScan] Kernel/module fix command failed to start: {exc}", file=stderr)
            return EXIT_UPGRADE_COMMAND_FAILED_TO_START
        code = int(getattr(result, "returncode", 0))
        if code != 0:
            print(f"[AuraScan] Kernel/module fix command failed with exit code {code}. Upgrade not run.", file=stderr)
            return code
        print("[AuraScan] Kernel/module fix completed. Rerunning preflight.", file=stdout)
        refreshed = run_upgrade_preflight(
            options,
            runner=runner,
            which=which,
            snapshot=snapshot,
            urlopen=urlopen,
            modules_root=modules_root,
            pacman_conf_path=pacman_conf_path,
            progress=progress,
        )
        report.plan = refreshed.plan
        report.snapshot = refreshed.snapshot
        report.findings = refreshed.findings
        report.ai_review = refreshed.ai_review
        report.kernel_module_check = refreshed.kernel_module_check
        report.repository_health = refreshed.repository_health
        apply_trusted_handoff(report, options)
        print(report.render_terminal(verbose=options.verbose), file=stdout)
    else:
        print("[AuraScan] Kernel/module fix skipped. Keeping preflight risk for confirmation.", file=stderr)
    return None


def run_upgrade_kernel_module_aftercare(
    options: UpgradeOptions,
    *,
    plan: UpgradePlan,
    runner: Callable,
    stdout,
    stderr,
    snapshot: Optional[SystemSnapshot],
    modules_root: Path,
) -> None:
    if not options.kernel_module_autopilot_enabled or options.dry_run:
        return
    post_snapshot = snapshot or SystemSnapshot.collect(runner=runner)
    check = build_kernel_module_check(plan, post_snapshot, runner=runner, modules_root=modules_root, mode="post_upgrade")
    stream = stderr if options.json_output else stdout
    print("\n[AuraScan] Kernel/module aftercare", file=stream)
    print(f"Kernel/module check: {check.summary}.", file=stream)
    if check.reboot_required:
        print("Reboot required after successful kernel upgrade.", file=stream)
    elif getattr(post_snapshot, "running_kernel", ""):
        print("No new kernel transaction is visible in aftercare; reboot only if the package manager requested it.", file=stream)
    for issue in check.fixable_issues + check.unfixable_issues:
        print(f"- {issue.summary}", file=stream)


def run_upgrade_config_drift(
    stage: str,
    options: UpgradeOptions,
    *,
    input_func: Callable[[str], str],
    stdout,
    stderr,
    root: Optional[Path],
    snapshot: Optional[SystemSnapshot],
    runner: Callable,
) -> int:
    if not options.config_drift_enabled or options.json_output:
        return 0
    if root is None and snapshot is not None:
        return 0
    if options.config_drift_error:
        print(f"[AuraScan] Config drift assistant skipped: {options.config_drift_error}", file=stderr)
        return 0
    drift_root = root or Path("/etc")
    args = ["--root", str(drift_root)]
    if options.no_ai:
        args.append("--no-ai")
    if options.config_drift_ai_diffs:
        args.append("--ai-diffs")
    if options.yes:
        args.append("--yes")
    if options.dry_run or stage == "dry-run":
        args.append("--dry-run")
    print(f"\n[AuraScan] Config drift check ({stage})", file=stdout)
    try:
        return int(runner(args, input_func=input_func, stdout=stdout, stderr=stderr))
    except TypeError:
        return int(runner(args))


def run_repository_health_autopilot_repairs(
    report: UpgradePreflightReport,
    options: UpgradeOptions,
    *,
    runner: Callable,
    input_func: Callable[[str], str],
    stdout,
    stderr,
    backup_root: Path = REPOSITORY_HEALTH_BACKUP_ROOT,
) -> bool:
    check = report.repository_health
    if check is None or not check.fixable_issues:
        return False
    print("\n[AuraScan] Pacman repository repair", file=stdout)
    print(f"Repository health: {check.summary}.", file=stdout)
    for issue in check.fixable_issues[:6]:
        repos = ", ".join(issue.repositories)
        print(f"- {issue.include_path} has no active servers for {repos}; backup has {issue.backup_active_servers}.", file=stdout)
    if not options.yes:
        answer = input_func("AuraScan can restore the disabled mirrorlist from backup and rerun preflight. Apply repair? [Y/n] ").strip().lower()
        if answer in {"n", "no"}:
            print("[AuraScan] Repository repair skipped. Upgrade preflight remains unavailable.", file=stderr)
            return False

    result = apply_repository_health_repairs(check, runner=runner, backup_root=backup_root)
    if not result.success:
        print("[AuraScan] Repository repair failed. Upgrade preflight remains unavailable.", file=stderr)
        for error in result.errors[:6]:
            print(f"[AuraScan] {error}", file=stderr)
        return False
    for applied in result.applied:
        print(f"[AuraScan] Repaired mirrorlist: {applied}", file=stdout)
    if result.backup_dir:
        print(f"[AuraScan] Repository repair backup: {result.backup_dir}", file=stdout)
    print("[AuraScan] Repository repair completed. Rerunning preflight.", file=stdout)
    return True


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


def apply_repository_health_repairs(
    check: RepositoryHealthCheck,
    *,
    runner: Callable = subprocess.run,
    backup_root: Path = REPOSITORY_HEALTH_BACKUP_ROOT,
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

    try:
        if use_sudo:
            command = ["sudo", "mkdir", "-p", str(backup_dir)]
            status = runner(command, check=False)
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
                copy_status = runner(["sudo", "cp", "-a", str(target), str(backup_path)], check=False)
                if int(getattr(copy_status, "returncode", 0)) != 0:
                    result.errors.append(f"failed to back up {target} to {backup_path}")
                    return result
                install_status = runner([
                    "sudo",
                    "install",
                    "-o",
                    str(owner),
                    "-g",
                    str(group),
                    "-m",
                    f"{mode & 0o777:o}",
                    str(source),
                    str(target),
                ], check=False)
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
        write_repository_repair_manifest(manifest_path, manifest, runner=runner, use_sudo=use_sudo)
    except OSError as exc:
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
) -> None:
    text = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    if not use_sudo:
        manifest_path.write_text(text, encoding="utf-8")
        return
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
        handle.write(text)
        tmp_path = Path(handle.name)
    try:
        status = runner(["sudo", "install", "-m", "0644", str(tmp_path), str(manifest_path)], check=False)
        if int(getattr(status, "returncode", 0)) != 0:
            raise OSError(f"failed to write repair manifest to {manifest_path}")
    finally:
        try:
            tmp_path.unlink()
        except OSError:
            pass


def build_upgrade_unavailable_report(reason: str) -> UpgradePreflightReport:
    return UpgradePreflightReport(
        plan=UpgradePlan(
            selected_helper="none",
            preview_error=reason,
            command_source="disabled",
        ),
        snapshot=SystemSnapshot(),
        findings=[
            UpgradeFinding(
                rule_id="UPG-PREFLIGHT-DISABLED",
                severity=Severity.LOW,
                title="Upgrade preflight did not run.",
                summary=reason,
                why_it_matters="AuraScan cannot provide upgrade-risk guidance when preflight is disabled or misconfigured.",
                recommended_action="Enable upgrade preflight or run your package manager directly with normal care.",
                evidence=reason,
            )
        ],
        ai_review={"enabled": False, "status": "not_run"},
    )


def run_upgrade_preflight(
    options: UpgradeOptions,
    *,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
    snapshot: Optional[SystemSnapshot] = None,
    urlopen: Optional[Callable] = None,
    modules_root: Path = Path("/usr/lib/modules"),
    pacman_conf_path: Path = Path("/etc/pacman.conf"),
    progress: Optional[ProgressReporter] = None,
) -> UpgradePreflightReport:
    progress = progress or (lambda _message: None)
    plan = build_upgrade_plan(options, runner=runner, which=which, progress=progress)
    progress("Collecting local system facts.")
    system_snapshot = snapshot or SystemSnapshot.collect(runner=runner)
    repository_health = build_repository_health_check(pacman_conf_path) if preview_error_indicates_no_servers(plan.preview_error) else None
    kernel_module_check = None
    if options.kernel_module_autopilot_enabled and not plan.preview_error:
        progress("Checking kernel and external module compatibility.")
        kernel_module_check = build_kernel_module_check(plan, system_snapshot, runner=runner, modules_root=modules_root)
    progress("Evaluating deterministic upgrade risks.")
    findings = analyze_upgrade_risks(
        plan,
        system_snapshot,
        kernel_module_check=kernel_module_check,
        kernel_module_autopilot_enabled=options.kernel_module_autopilot_enabled,
        repository_health=repository_health,
    )
    report = UpgradePreflightReport(
        plan=plan,
        snapshot=system_snapshot,
        findings=findings,
        kernel_module_check=kernel_module_check,
        repository_health=repository_health,
    )
    if not options.no_ai:
        progress("Requesting AI advisory review.")
    apply_ai_upgrade_review(report, disabled=options.no_ai, urlopen=urlopen)
    return report


def build_upgrade_plan(
    options: UpgradeOptions,
    *,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
    progress: Optional[ProgressReporter] = None,
) -> UpgradePlan:
    progress = progress or (lambda _message: None)
    helper, helper_error = resolve_aur_helper(options.aur_helper, which=which)
    final_command = helper_upgrade_command(helper)
    preview_command = ["sudo", "pacman", "-Syu", "--print", "--print-format", PACMAN_PRINT_FORMAT]
    plan = UpgradePlan(
        selected_helper=helper,
        helper_error=helper_error,
        preview_command=preview_command,
        final_command=final_command,
        command_source=helper if helper != "none" else "pacman",
    )
    if helper_error and options.aur_helper in {"paru", "yay", "shelly"}:
        plan.preview_error = helper_error
        return plan

    progress("Building pacman upgrade preview. This may sync package databases and can take a moment.")
    try:
        result = runner(preview_command, capture_output=True, text=True, check=False)
    except OSError as exc:
        plan.preview_error = f"pacman upgrade preview failed: {exc}"
        return plan
    if int(getattr(result, "returncode", 0)) != 0:
        stderr = str(getattr(result, "stderr", "") or "").strip()
        plan.preview_error = "pacman upgrade preview failed" + (f": {stderr}" if stderr else ".")
        return plan

    plan.repo_packages = parse_pacman_preview(str(getattr(result, "stdout", "") or ""))
    for pkg in plan.repo_packages:
        plan.conflicts.extend(pkg.conflicts)
        plan.replacements.extend(pkg.replaces)

    if helper != "none":
        progress(f"Checking AUR updates with {helper}.")
        helper_result = query_helper_updates(helper, runner=runner)
        if helper_result["ok"]:
            plan.aur_packages = helper_result["packages"]
        else:
            plan.helper_error = str(helper_result["error"])

    return plan


def resolve_aur_helper(selection: str, *, which: Callable[[str], Optional[str]] = shutil.which) -> Tuple[str, str]:
    if selection == "none":
        return "none", ""
    if selection in {"paru", "yay", "shelly"}:
        return (selection, "") if which(selection) else ("none", f"requested AUR helper '{selection}' was not found in PATH")
    for helper in ("paru", "yay", "shelly"):
        if which(helper):
            return helper, ""
    return "none", "no supported AUR helper found; foreign packages will be reported as advisory context only"


def helper_upgrade_command(helper: str) -> List[str]:
    if helper == "none":
        return ["sudo", "pacman", "-Syu"]
    if helper == "shelly":
        return ["shelly", "upgrade-all", "--no-flatpak", "--no-appimage"]
    return [helper, "-Syu"]


def query_helper_updates(helper: str, *, runner: Callable = subprocess.run) -> Dict[str, object]:
    if helper == "shelly":
        cmd = ["shelly", "check-updates", "--aur", "--json"]
        parser = parse_shelly_updates
    else:
        cmd = [helper, "-Qua"]
        parser = parse_aur_updates
    try:
        result = runner(cmd, capture_output=True, text=True, check=False)
    except OSError as exc:
        return {"ok": False, "packages": [], "error": f"{helper} AUR update query failed: {exc}"}
    if int(getattr(result, "returncode", 0)) != 0:
        stderr = str(getattr(result, "stderr", "") or "").strip()
        return {"ok": False, "packages": [], "error": f"{helper} AUR update query failed" + (f": {stderr}" if stderr else ".")}
    try:
        packages = parser(str(getattr(result, "stdout", "") or ""))
    except ValueError as exc:
        return {"ok": False, "packages": [], "error": f"{helper} AUR update query output could not be parsed: {exc}"}
    return {"ok": True, "packages": packages, "error": ""}


def parse_pacman_preview(output: str) -> List[UpgradePackage]:
    packages: List[UpgradePackage] = []
    for raw in output.splitlines():
        line = raw.strip()
        if not line:
            continue
        fields = line.split("\t")
        if len(fields) < 2:
            continue
        fields = (fields + [""] * 7)[:7]
        name, version, repo, size, depends, conflicts, replaces = fields[:7]
        if not name or name.startswith(("http://", "https://", "file://")):
            continue
        packages.append(UpgradePackage(
            name=name.strip(),
            new_version=version.strip(),
            repo=repo.strip(),
            size=size.strip(),
            depends=_split_pacman_list(depends),
            conflicts=_split_pacman_list(conflicts),
            replaces=_split_pacman_list(replaces),
        ))
    return packages


def parse_aur_updates(output: str) -> List[UpgradePackage]:
    packages: List[UpgradePackage] = []
    for raw in output.splitlines():
        line = raw.strip()
        if not line or " -> " not in line:
            continue
        before, new_version = line.rsplit(" -> ", 1)
        parts = before.split()
        if not parts:
            continue
        name = parts[0].split("/")[-1]
        old_version = parts[1] if len(parts) > 1 else ""
        packages.append(UpgradePackage(
            name=name,
            old_version=old_version,
            new_version=new_version.strip(),
            repo="aur",
            package_type="aur",
        ))
    return packages


def parse_shelly_updates(output: str) -> List[UpgradePackage]:
    data = _load_noisy_json(output)
    if isinstance(data, list):
        aur_items = data
    elif isinstance(data, dict):
        aur_items = data.get("Aur") or data.get("AUR") or data.get("aur") or []
    else:
        aur_items = []
    if not isinstance(aur_items, list):
        return []

    packages: List[UpgradePackage] = []
    for item in aur_items:
        if not isinstance(item, Mapping):
            continue
        name = str(item.get("Name") or item.get("name") or "").strip()
        if not name:
            continue
        packages.append(UpgradePackage(
            name=name,
            old_version=str(item.get("OldVersion") or item.get("CurrentVersion") or item.get("currentVersion") or "").strip(),
            new_version=str(item.get("Version") or item.get("NewVersion") or item.get("newVersion") or "").strip(),
            repo="aur",
            package_type="aur",
            size=str(item.get("DownloadSize") or item.get("downloadSize") or "").strip(),
        ))
    return packages


def _load_noisy_json(output: str) -> object:
    decoder = json.JSONDecoder()
    for index, char in enumerate(output):
        if char not in "[{":
            continue
        try:
            data, _end = decoder.raw_decode(output[index:])
            return data
        except json.JSONDecodeError:
            continue
    raise ValueError("no JSON object or array found")


def analyze_upgrade_risks(
    plan: UpgradePlan,
    snapshot: SystemSnapshot,
    *,
    kernel_module_check: Optional[KernelModuleCheck] = None,
    kernel_module_autopilot_enabled: bool = False,
    repository_health: Optional[RepositoryHealthCheck] = None,
) -> List[UpgradeFinding]:
    findings: List[UpgradeFinding] = []
    updated_names = set(plan.package_names())
    repo_names = {pkg.name for pkg in plan.repo_packages}
    kernel_updates = sorted(name for name in repo_names if is_kernel_package(name))
    sensitive_updates = sorted(name for name in repo_names if is_boot_sensitive_package(name) or is_kernel_package(name))
    module_packages = sorted(set(snapshot.dkms_packages + snapshot.nvidia_packages + snapshot.zfs_packages + snapshot.virtualbox_packages))
    foreign_dependency_issues = foreign_package_dependency_issues(snapshot, plan)

    if plan.preview_error:
        action = "Resolve the preview error, then run the upgrade preflight again."
        evidence = plan.preview_error
        if repository_health and repository_health.fixable_issues:
            action = "Let AuraScan restore active mirrorlist servers from backup, then rerun preflight."
            details = "; ".join(
                f"{issue.include_path} from {issue.backup_path} for {', '.join(issue.repositories)}"
                for issue in repository_health.fixable_issues[:6]
            )
            evidence = f"{plan.preview_error}; repairable mirrorlists={details}"
        findings.append(_finding(
            "UPG-PREVIEW-FAILED",
            Severity.CRITICAL,
            "Upgrade preview could not be built.",
            "AuraScan could not get an authoritative package-manager preview for this upgrade.",
            "Without a transaction preview, AuraScan cannot reliably check upgrade breakage risks before handing off to pacman or a helper.",
            action,
            evidence,
        ))
        return findings

    if plan.helper_error:
        severity = Severity.MEDIUM if snapshot.foreign_packages else Severity.LOW
        findings.append(_finding(
            "UPG-AUR-HELPER-UNAVAILABLE",
            severity,
            "AUR helper coverage is limited.",
            "AuraScan could not fully query AUR updates with a supported helper.",
            "Foreign packages can break after repo library, compiler, Python, Qt, Electron, or kernel updates even when pacman itself succeeds.",
            "Install or expose paru, yay, or shelly if you want AuraScan to include AUR update context.",
            plan.helper_error,
        ))

    if updated_names and is_manjaro_snapshot(snapshot):
        findings.append(_finding(
            "UPG-MANJARO-AUR-CAVEAT",
            Severity.LOW,
            "Manjaro upgrade compatibility has AUR timing caveats.",
            "AuraScan detected Manjaro while an upgrade is pending.",
            "Manjaro intentionally delays repository updates compared with Arch, so AUR packages and Arch-targeted advice may not line up exactly with the current Manjaro branch.",
            "Prefer normal Manjaro update cadence, avoid partial upgrades, and rebuild affected AUR packages only after the repo transaction succeeds.",
            f"distro={snapshot.distro_info.get('id', 'unknown')}; support_tier={snapshot.distro_info.get('support_tier', 'unknown')}",
        ))

    if sensitive_updates and snapshot.boot_free_mib is not None and snapshot.boot_free_mib < 512:
        findings.append(_finding(
            "UPG-BOOT-SPACE",
            Severity.HIGH,
            "Boot partition space is low for this upgrade.",
            "This upgrade touches kernel, initramfs, bootloader, or systemd packages while /boot has limited free space.",
            "A full boot partition can leave kernels or initramfs images partially written, which can make the next boot fail.",
            "Free space in /boot before continuing.",
            f"/boot free MiB={snapshot.boot_free_mib}; sensitive packages={', '.join(sensitive_updates[:8])}",
        ))

    if sensitive_updates and snapshot.root_free_mib is not None and snapshot.root_free_mib < 2048:
        findings.append(_finding(
            "UPG-ROOT-SPACE",
            Severity.MEDIUM,
            "Root filesystem space is low for this upgrade.",
            "The root filesystem has limited free space while important system packages are pending.",
            "Low disk space can interrupt package extraction, hooks, cache writes, initramfs generation, or post-transaction work.",
            "Free disk space before continuing.",
            f"/ free MiB={snapshot.root_free_mib}; sensitive packages={', '.join(sensitive_updates[:8])}",
        ))

    if kernel_updates:
        findings.append(_finding(
            "UPG-KERNEL-REBOOT",
            Severity.MEDIUM,
            "Kernel update will need a clean reboot.",
            "This transaction updates kernel packages.",
            "The running kernel and installed modules can diverge after a kernel upgrade until the system reboots.",
            "Plan to reboot after a successful upgrade, especially before loading new kernel modules.",
            f"running kernel={snapshot.running_kernel}; kernel packages={', '.join(kernel_updates)}",
        ))

    running_kernel_pkg = expected_running_kernel_package(snapshot.running_kernel)
    if running_kernel_pkg and snapshot.installed_packages and running_kernel_pkg not in snapshot.installed_packages:
        findings.append(_finding(
            "UPG-RUNNING-KERNEL-UNTRACKED",
            Severity.MEDIUM,
            "Running kernel package could not be matched locally.",
            "AuraScan could not match the running kernel to an installed kernel package name.",
            "Kernel/module checks are less certain when the running kernel package is missing or named unexpectedly.",
            "Confirm your installed kernel package set before upgrading kernel or module packages.",
            f"running kernel={snapshot.running_kernel}; expected package={running_kernel_pkg}",
        ))

    if kernel_updates and module_packages and not kernel_module_autopilot_enabled:
        findings.append(_finding(
            "UPG-KERNEL-MODULES",
            Severity.HIGH,
            "Kernel module packages may need rebuild or reboot handling.",
            "This upgrade changes kernel packages and the system has external module packages installed.",
            "NVIDIA, DKMS, ZFS, VirtualBox, and similar modules can fail to load if module rebuilds or matching packages do not complete cleanly.",
            "Make sure matching module packages are upgraded and be ready to rebuild DKMS modules or boot an older kernel if needed.",
            f"kernel packages={', '.join(kernel_updates)}; module packages={', '.join(module_packages[:12])}",
        ))

    if kernel_module_autopilot_enabled and kernel_module_check is not None:
        for item in issues_to_findings(kernel_module_check):
            findings.append(_finding(
                str(item["rule_id"]),
                item["severity"],
                str(item["title"]),
                str(item["summary"]),
                str(item["why"]),
                str(item["action"]),
                str(item["evidence"]),
            ))

    cachyos_kernel_updates = [name for name in kernel_updates if name.startswith("linux-cachyos")]
    if cachyos_kernel_updates:
        findings.append(_finding(
            "UPG-CACHYOS-KERNEL",
            Severity.MEDIUM,
            "CachyOS kernel packages are changing.",
            "This transaction updates CachyOS kernel packages.",
            "Kernel flavor changes can affect boot entries, modules, initramfs generation, and recovery expectations.",
            "Confirm your boot entries and installed module packages after the upgrade.",
            ", ".join(cachyos_kernel_updates),
        ))

    boot_sensitive = sorted(name for name in repo_names if is_boot_sensitive_package(name))
    if boot_sensitive:
        findings.append(_finding(
            "UPG-BOOTLOADER-INITRAMFS",
            Severity.MEDIUM,
            "Boot or initramfs tooling is being updated.",
            "This transaction touches packages involved in boot, initramfs, or early userspace.",
            "Failures in hooks or config drift around these packages can make recovery harder after reboot.",
            "Watch the pacman hook output and review bootloader/initramfs warnings before rebooting.",
            ", ".join(boot_sensitive),
        ))

    if updated_names and (snapshot.ignored_packages or snapshot.ignored_groups):
        findings.append(_finding(
            "UPG-IGNORED-PACKAGES",
            Severity.HIGH,
            "Ignored packages can create partial-upgrade risk.",
            "This system has IgnorePkg or IgnoreGroup entries while an upgrade is pending.",
            "Arch-family distributions do not support partial upgrades; holding core libraries, kernels, drivers, or desktop components can break dependencies.",
            "Review ignored packages/groups and remove holds unless you deliberately understand the compatibility impact.",
            f"IgnorePkg={', '.join(snapshot.ignored_packages) or '(none)'}; IgnoreGroup={', '.join(snapshot.ignored_groups) or '(none)'}",
        ))

    replacement_targets = applicable_replacements(plan, snapshot)
    if plan.removals or replacement_targets:
        sensitive_changes = [name for name in plan.removals + replacement_targets if is_sensitive_transaction_change(name)]
        severity = Severity.HIGH if plan.removals or sensitive_changes else Severity.MEDIUM
        metadata_only = sorted(set(plan.replacements) - set(replacement_targets))
        transition_details = package_transition_descriptions(plan)
        findings.append(_finding(
            "UPG-TRANSACTION-REPLACES",
            severity,
            "Upgrade includes an installed package transition or removal.",
            "The repository transaction replaces an installed package name or explicitly removes a package. "
            "This declaration comes from package metadata, not AuraScan.",
            "Official repositories use replacement metadata for package renames and consolidations, but unrelated removals still deserve attention.",
            "Continue when the named transition matches the expected repository packages; stop if the package manager proposes an unrelated removal.",
            f"installed replacement targets={', '.join(replacement_targets) or '(none)'}; removals={', '.join(plan.removals) or '(none)'}; metadata-only replaces={', '.join(metadata_only[:16]) or '(none)'}; transitions={'; '.join(transition_details) or '(none)'}",
        ))

    if plan.conflicts:
        transition_details = package_transition_descriptions(plan)
        findings.append(_finding(
            "UPG-TRANSACTION-CONFLICTS",
            Severity.MEDIUM,
            "Repository package transition metadata was detected.",
            "One or more pending repository packages declare conflicts. These declarations come from repository package metadata, not AuraScan.",
            "Package managers use conflicts for legitimate renames, replacements, and package consolidation; an unrelated conflict can still alter the transaction.",
            "Let the package manager resolve the declared transition, but stop if it proposes removing an unrelated package. AuraScan verifies planned versions afterward.",
            f"conflicts={', '.join(sorted(set(plan.conflicts))[:16])}; transitions={'; '.join(transition_details) or '(owner unavailable)'}",
        ))

    abi_updates = sorted(name for name in repo_names if name in ABI_SENSITIVE_PACKAGES or is_kernel_package(name))
    if snapshot.foreign_packages and abi_updates:
        findings.append(_finding(
            "UPG-AUR-REBUILD-RISK",
            Severity.MEDIUM,
            "Foreign/AUR packages may need rebuilds after this upgrade.",
            "This system has foreign packages installed and the repo upgrade touches ABI-sensitive packages.",
            "AUR packages built against older libraries, Python versions, Qt/Electron stacks, or kernels can stop working until rebuilt.",
            "AuraScan checked installed foreign package dependencies locally. Rebuild affected AUR packages if they fail after the ABI-sensitive upgrade.",
            f"ABI-sensitive updates={', '.join(abi_updates[:12])}; foreign package count={len(snapshot.foreign_packages)}; local dependency issues={len(foreign_dependency_issues)}",
        ))

    missing_dep_issues = [item for item in foreign_dependency_issues if item["kind"] == "missing_dependency"]
    if missing_dep_issues:
        findings.append(_finding(
            "UPG-AUR-DEPENDENCY-MISSING",
            Severity.HIGH,
            "Foreign package dependencies look unsatisfied.",
            "AuraScan checked installed foreign package dependency metadata against the local package set and pending repo packages.",
            "A foreign package with missing dependencies is likely to break or remain broken after the upgrade.",
            "Fix or remove the listed foreign package dependency issue before relying on the package.",
            "; ".join(f"{item['package']}: {item['dependency']}" for item in missing_dep_issues[:12]),
        ))

    conflict_issues = [item for item in foreign_dependency_issues if item["kind"] == "conflicts_with_upgrade"]
    if conflict_issues:
        findings.append(_finding(
            "UPG-AUR-CONFLICTS",
            Severity.HIGH,
            "Foreign package conflicts with the pending upgrade.",
            "AuraScan found installed foreign package conflict metadata that overlaps with pending repo package names.",
            "Package conflicts can cause removals, blocked transactions, or broken local packages.",
            "Resolve the listed foreign package conflict before continuing.",
            "; ".join(f"{item['package']}: {item['dependency']}" for item in conflict_issues[:12]),
        ))

    if snapshot.foreign_packages and plan.selected_helper == "none":
        findings.append(_finding(
            "UPG-AUR-NOT-CHECKED",
            Severity.LOW,
            "Foreign package updates were not checked.",
            "AuraScan found installed foreign packages but no supported AUR helper was selected.",
            "Repo upgrades can still affect AUR packages even when no AUR update query was available.",
            "Use --aur-helper paru, --aur-helper yay, or --aur-helper shelly when available.",
            f"foreign package count={len(snapshot.foreign_packages)}",
        ))

    pac_config_count = snapshot.pacnew_count + snapshot.pacsave_count
    if pac_config_count and (sensitive_updates or pac_config_count >= 10):
        findings.append(_finding(
            "UPG-PACNEW-CONFIG",
            Severity.MEDIUM,
            "Unmerged pacman config files may matter for this upgrade.",
            "AuraScan found pending .pacnew or .pacsave files under /etc.",
            "Unmerged configuration can cause services, boot tooling, or package-manager behavior to differ from what updated packages expect.",
            "Merge relevant .pacnew/.pacsave files with pacdiff or another merge tool. Restart only services whose configs you change; reboot only when the upgrade itself requires it.",
            f"pacnew={snapshot.pacnew_count}; pacsave={snapshot.pacsave_count}; truncated={snapshot.pacnew_scan_truncated}",
        ))

    return findings


def apply_ai_upgrade_review(
    report: UpgradePreflightReport,
    *,
    disabled: bool = False,
    urlopen: Optional[Callable] = None,
) -> None:
    if disabled:
        report.ai_review = {"enabled": False, "status": "disabled"}
        return

    config = resolve_ai_config(os.environ)
    if config.error:
        report.ai_review = {"enabled": False, "status": "config_error", "error": config.error}
        return
    if not config.enabled or not config.api_key_present:
        report.ai_review = {"enabled": False, "status": "not_configured"}
        return

    prompt = build_upgrade_ai_prompt(report)
    try:
        text = call_ai_provider(config, prompt, timeout=20, urlopen=urlopen)
    except Exception as exc:
        report.ai_review = {"enabled": True, "provider": config.provider, "status": "error", "error": str(exc)}
        return

    try:
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError("AI response was not a JSON object")
    except Exception as exc:
        report.ai_review = {"enabled": True, "provider": config.provider, "status": "invalid_response", "error": str(exc)}
        return

    applied = apply_ai_risk_raises(report, data)
    report.ai_review = {
        "enabled": True,
        "provider": config.provider,
        "status": "ok",
        "summary": normalize_upgrade_ai_summary(report, str(data.get("summary") or "")),
        "raises_applied": applied,
    }


def build_upgrade_ai_prompt(report: UpgradePreflightReport) -> str:
    replacement_targets = applicable_replacements(report.plan, report.snapshot)
    payload = {
        "repo_packages": [{"name": pkg.name, "new_version": pkg.new_version, "repo": pkg.repo} for pkg in report.plan.repo_packages],
        "aur_packages": [{"name": pkg.name, "old_version": pkg.old_version, "new_version": pkg.new_version} for pkg in report.plan.aur_packages],
        "selected_helper": report.plan.selected_helper,
        "transaction_changes": {
            "removals": list(report.plan.removals),
            "installed_replacement_targets": replacement_targets,
            "metadata_only_replaces": sorted(set(report.plan.replacements) - set(replacement_targets))[:30],
            "declared_conflicts": sorted(set(report.plan.conflicts))[:30],
            "package_transitions": package_transition_descriptions(report.plan, limit=20),
        },
        "system_facts": {
            "running_kernel": report.snapshot.running_kernel,
            "root_free_mib": report.snapshot.root_free_mib,
            "boot_free_mib": report.snapshot.boot_free_mib,
            "foreign_package_count": len(report.snapshot.foreign_packages),
            "foreign_package_dependency_check": {
                "checked_package_count": len(report.snapshot.foreign_package_info),
                "issues": foreign_package_dependency_issues(report.snapshot, report.plan),
                "helper_query_succeeded": report.plan.selected_helper != "none" and not report.plan.helper_error,
                "helper_update_count": len(report.plan.aur_packages),
            },
            "ignored_packages": list(report.snapshot.ignored_packages),
            "ignored_groups": list(report.snapshot.ignored_groups),
            "module_package_names": sorted(set(report.snapshot.dkms_packages + report.snapshot.nvidia_packages + report.snapshot.zfs_packages + report.snapshot.virtualbox_packages))[:30],
            "pacnew_count": report.snapshot.pacnew_count,
            "pacsave_count": report.snapshot.pacsave_count,
        },
        "kernel_module_check": report.kernel_module_check.to_dict() if report.kernel_module_check else {"enabled": False, "status": "not_run"},
        "repository_health": report.repository_health.to_dict() if report.repository_health else {"enabled": False, "status": "not_run"},
        "deterministic_findings": [
            {
                "rule_id": finding.rule_id,
                "severity": finding.severity.value,
                "title": finding.title,
                "summary": finding.summary,
            }
            for finding in report.findings
            if finding.source == "deterministic"
        ],
    }
    return (
        "You are AuraScan's upgrade preflight reviewer for Arch-family systems.\n"
        "Use only the JSON data below. Do not claim the upgrade is safe.\n"
        "You may only suggest risk raises, never risk reductions. Do not suggest hard blocking.\n"
        "Do not create package commands or package-fix plans; AuraScan's deterministic kernel/module autopilot owns those decisions.\n"
        "Do not propose arbitrary pacman.conf or mirrorlist edits; AuraScan's deterministic repository_health repair owns mirrorlist recovery decisions.\n"
        "Do not tell the user to manually verify kernel/module compatibility when kernel_module_check status is ok.\n"
        "Do not raise fallback-kernel risk when kernel_module_check.fallback_kernel.available is true.\n"
        "Do not raise replacement/removal risk solely from transaction_changes.metadata_only_replaces; those are package metadata, not installed removals.\n"
        "Declared conflicts, replacements, and package transitions originate in repository package metadata, not AuraScan. Explain that distinction plainly.\n"
        "Do not claim manual conflict resolution is required merely because declared_conflicts or package_transitions are present; the package manager resolves declared transitions and AuraScan verifies planned versions afterward.\n"
        "Do not raise risk merely because foreign/AUR packages exist when AuraScan's foreign package dependency check reports no issues and the helper query succeeded.\n"
        "Avoid telling the user to manually verify compatibility unless AuraScan found a concrete issue or a named check could not run.\n"
        "For .pacnew/.pacsave config drift, do not recommend rebooting or restarting services merely because files exist; recommend merging config and restarting only affected services when config actually changes.\n"
        "Return strict JSON only, with this shape:\n"
        "{\"summary\":\"short plain-language summary\",\"risk_raises\":[{\"target_rule_id\":\"existing rule id or empty\",\"severity\":\"MEDIUM or HIGH\",\"reason\":\"why\",\"recommended_action\":\"what to do\"}]}\n"
        "Do not include secrets, markdown, or extra text.\n\n"
        + json.dumps(payload, sort_keys=True)
    )


def apply_ai_risk_raises(report: UpgradePreflightReport, data: Mapping[str, object]) -> int:
    raises = data.get("risk_raises", [])
    if not isinstance(raises, list):
        return 0
    by_rule = {finding.rule_id: finding for finding in report.findings}
    applied = 0
    for item in raises:
        if not isinstance(item, Mapping):
            continue
        severity = _ai_severity(str(item.get("severity") or ""))
        if severity is None:
            continue
        target = str(item.get("target_rule_id") or item.get("rule_id") or "").strip()
        reason = str(item.get("reason") or "").strip()
        action = str(item.get("recommended_action") or "Review this risk before upgrading.").strip()
        if _is_vague_foreign_ai_raise(report, target, reason):
            continue
        if _is_metadata_only_transition_ai_raise(report, target, reason):
            continue
        if target and target in by_rule:
            finding = by_rule[target]
            if SEVERITY_ORDER.index(severity) > SEVERITY_ORDER.index(finding.severity):
                finding.severity = severity
                finding.summary = f"{finding.summary} AI review raised this risk: {reason}" if reason else finding.summary
                applied += 1
            continue
        report.findings.append(UpgradeFinding(
            rule_id="UPG-AI-RISK",
            severity=severity,
            title="AI review found an additional upgrade risk.",
            summary=reason or "AI review found a risk correlation worth reviewing.",
            why_it_matters="AI review can connect multiple preflight signals, but it can be wrong and cannot prove the upgrade is unsafe by itself.",
            recommended_action=action,
            evidence="AI raise-only preflight review",
            source="ai_review",
        ))
        applied += 1
    return applied


def _is_vague_foreign_ai_raise(report: UpgradePreflightReport, target: str, reason: str) -> bool:
    if target:
        return False
    text = reason.lower()
    if not any(token in text for token in ("foreign", "aur package", "aur packages", "aur ")):
        return False
    foreign_coverage_gap_rules = {
        "UPG-AUR-HELPER-UNAVAILABLE",
        "UPG-AUR-NOT-CHECKED",
        "UPG-AUR-DEPENDENCY-MISSING",
        "UPG-AUR-CONFLICTS",
    }
    has_foreign_coverage_gap = any(finding.rule_id in foreign_coverage_gap_rules for finding in report.findings)
    helper_succeeded = report.plan.selected_helper != "none" and not report.plan.helper_error
    local_issues = foreign_package_dependency_issues(report.snapshot, report.plan)
    return helper_succeeded and not has_foreign_coverage_gap and not local_issues


def _is_metadata_only_transition_ai_raise(report: UpgradePreflightReport, target: str, reason: str) -> bool:
    if not report.plan.conflicts:
        return False
    if report.plan.removals or applicable_replacements(report.plan, report.snapshot):
        return False
    if target == "UPG-TRANSACTION-CONFLICTS":
        return True
    text = reason.lower()
    return not target and any(token in text for token in ("package conflict", "declared conflict", "replacement", "package transition"))


def normalize_upgrade_ai_summary(report: UpgradePreflightReport, summary: str) -> str:
    text = summary.strip()
    lowered = text.lower()
    manual_transition_claim = (
        any(token in lowered for token in ("manual resolution", "resolve manually", "manually resolve"))
        and any(token in lowered for token in ("conflict", "replacement", "transition"))
    )
    concrete_change = bool(report.plan.removals or applicable_replacements(report.plan, report.snapshot))
    if manual_transition_claim and report.plan.conflicts and not concrete_change:
        return (
            "AI noted repository package transition metadata. These declarations come from the repository, not AuraScan; "
            "metadata alone does not require manual conflict resolution. The package manager will resolve the transaction "
            "and AuraScan will verify the planned versions afterward."
        )
    return text


def _ai_severity(value: str) -> Optional[Severity]:
    normalized = value.strip().upper()
    if normalized == "CRITICAL":
        return Severity.HIGH
    if normalized in {"MEDIUM", "HIGH"}:
        return Severity(normalized)
    return None


def is_kernel_package(name: str) -> bool:
    return bool(KERNEL_PACKAGE_RE.match(name))


def is_boot_sensitive_package(name: str) -> bool:
    return name in INITRAMFS_BOOT_PACKAGES or name.startswith("systemd-boot")


def applicable_replacements(plan: UpgradePlan, snapshot: SystemSnapshot) -> List[str]:
    installed = set(snapshot.installed_packages)
    return sorted(name for name in set(plan.replacements) if name in installed)


def is_sensitive_transaction_change(name: str) -> bool:
    return is_kernel_package(name) or is_boot_sensitive_package(name) or name in ABI_SENSITIVE_PACKAGES


def is_manjaro_snapshot(snapshot: SystemSnapshot) -> bool:
    return str(snapshot.distro_info.get("id", "")).lower() == "manjaro"


def expected_running_kernel_package(running_kernel: str) -> str:
    kernel = running_kernel.lower()
    if not kernel:
        return ""
    if "cachyos" in kernel:
        return "linux-cachyos"
    if "lts" in kernel:
        return "linux-lts"
    if "zen" in kernel:
        return "linux-zen"
    if "hardened" in kernel:
        return "linux-hardened"
    return "linux"


def count_pacnew_pacsave(root: Path, *, max_entries: int = 20000) -> Tuple[int, int, bool]:
    pacnew = 0
    pacsave = 0
    seen = 0
    try:
        for current, dirs, files in os.walk(str(root)):
            dirs[:] = [name for name in dirs if name not in {".git", "pacman.d/gnupg"}]
            for filename in files:
                seen += 1
                if filename.endswith(".pacnew"):
                    pacnew += 1
                elif filename.endswith(".pacsave"):
                    pacsave += 1
                if seen >= max_entries:
                    return pacnew, pacsave, True
    except OSError:
        return pacnew, pacsave, False
    return pacnew, pacsave, False


def collect_foreign_package_info(packages: Iterable[str], *, runner: Callable = subprocess.run) -> List[ForeignPackageInfo]:
    info: List[ForeignPackageInfo] = []
    for package in packages:
        text = _command_text(runner, ["pacman", "-Qi", package])
        if not text:
            info.append(ForeignPackageInfo(name=package))
            continue
        item = parse_pacman_qi(text)
        if not item.name:
            item.name = package
        if item.depends:
            missing = _command_stdout_lines(runner, ["pacman", "-T"] + item.depends)
            item.missing_depends = missing
        info.append(item)
    return info


def parse_pacman_qi(text: str) -> ForeignPackageInfo:
    fields: Dict[str, str] = {}
    current_key = ""
    for raw in text.splitlines():
        if not raw.strip():
            continue
        if ":" in raw:
            key, value = raw.split(":", 1)
            current_key = key.strip()
            fields[current_key] = value.strip()
        elif current_key:
            fields[current_key] = f"{fields.get(current_key, '')} {raw.strip()}".strip()

    return ForeignPackageInfo(
        name=fields.get("Name", ""),
        version=fields.get("Version", ""),
        depends=_split_pacman_list(fields.get("Depends On", "")),
        provides=_split_pacman_list(fields.get("Provides", "")),
        conflicts=_split_pacman_list(fields.get("Conflicts With", "")),
        install_script=fields.get("Install Script", "").strip().lower() == "yes",
    )


def foreign_package_dependency_issues(snapshot: SystemSnapshot, plan: UpgradePlan) -> List[Dict[str, str]]:
    issues: List[Dict[str, str]] = []
    pending_names = {pkg.name for pkg in plan.repo_packages}
    for info in snapshot.foreign_package_info:
        for dependency in info.missing_depends:
            issues.append({
                "kind": "missing_dependency",
                "package": info.name,
                "dependency": dependency,
            })
        for conflict in info.conflicts:
            conflict_name = _dependency_name(conflict)
            if conflict_name and conflict_name in pending_names:
                issues.append({
                    "kind": "conflicts_with_upgrade",
                    "package": info.name,
                    "dependency": conflict,
                })
    return issues


def _dependency_name(value: str) -> str:
    return re.split(r"[<>=]", value, maxsplit=1)[0].strip()


def _finding(
    rule_id: str,
    severity: Severity,
    title: str,
    summary: str,
    why: str,
    action: str,
    evidence: str,
) -> UpgradeFinding:
    return UpgradeFinding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        summary=summary,
        why_it_matters=why,
        recommended_action=action,
        evidence=evidence,
    )


def _split_pacman_list(value: str) -> List[str]:
    value = value.strip()
    if not value or value.lower() in {"none", "(none)"}:
        return []
    parts = re.split(r"[,\s]+", value)
    return [part for part in parts if part and part.lower() not in {"none", "(none)"}]


def _command_text(runner: Callable, cmd: Sequence[str]) -> str:
    try:
        result = runner(list(cmd), capture_output=True, text=True, check=False)
    except OSError:
        return ""
    if int(getattr(result, "returncode", 0)) != 0:
        return ""
    return str(getattr(result, "stdout", "") or "").strip()


def _command_lines(runner: Callable, cmd: Sequence[str]) -> List[str]:
    text = _command_text(runner, cmd)
    return [line.strip() for line in text.splitlines() if line.strip()]


def _command_stdout_lines(runner: Callable, cmd: Sequence[str]) -> List[str]:
    try:
        result = runner(list(cmd), capture_output=True, text=True, check=False)
    except OSError:
        return []
    text = str(getattr(result, "stdout", "") or "")
    return [line.strip() for line in text.splitlines() if line.strip()]


def _free_mib(path: Path) -> Optional[int]:
    try:
        usage = shutil.disk_usage(str(path))
    except OSError:
        return None
    return int(usage.free / (1024 * 1024))
