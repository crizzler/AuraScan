import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from aurascan.core.ai_provider import call_ai_provider, resolve_ai_config
from aurascan.core.ai_provider import parse_bool as parse_config_bool
from aurascan.core.config_drift import (
    CONFIG_DRIFT_AI_DIFFS_ENV,
    CONFIG_DRIFT_ENABLED_ENV,
    resolve_config_drift_config,
    run_config_drift,
)
from aurascan.core.kernel_module_autopilot import (
    KERNEL_MODULE_AUTOPILOT_ENV,
    KernelModuleCheck,
    build_kernel_module_check,
    issues_to_findings,
    kernel_module_fix_command,
)
from aurascan.core.models import SCANNER_VERSION, Severity


UPGRADE_PREFLIGHT_SCHEMA_VERSION = "1.1"
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
UPGRADE_AUR_HELPERS = {"auto", "paru", "yay", "shelly", "none"}

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
class SystemSnapshot:
    running_kernel: str = ""
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
    config_error: str = ""
    config_drift_error: str = ""


def build_upgrade_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aurascan upgrade",
        description="Preview and preflight Arch/CachyOS upgrades before handing off to pacman or an AUR helper.",
    )
    parser.add_argument("--dry-run", action="store_true", help="show the preflight report without running the upgrade command")
    parser.add_argument("--json", action="store_true", dest="json_output", help="emit a structured JSON preflight report")
    parser.add_argument("--verbose", action="store_true", help="show all preflight findings and technical details")
    parser.add_argument("--yes", action="store_true", help="skip AuraScan's high-risk confirmation prompt")
    parser.add_argument("--no-ai", action="store_true", help="disable AI upgrade risk review for this run")
    parser.add_argument("--no-config-drift", action="store_true", help="skip the config drift assistant before and after the upgrade")
    parser.add_argument("--no-kernel-module-autopilot", action="store_true", help="skip deterministic kernel/module compatibility autopilot checks")
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

    aur_helper = source.get(UPGRADE_PREFLIGHT_AUR_HELPER_ENV, "auto").strip().lower() or "auto"
    if aur_helper not in UPGRADE_AUR_HELPERS:
        return UpgradeConfig(error=f"invalid {UPGRADE_PREFLIGHT_AUR_HELPER_ENV} value")

    return UpgradeConfig(
        preflight_enabled=bool(preflight_enabled),
        aur_helper=aur_helper,
        ai_enabled=bool(ai_enabled),
        kernel_module_autopilot_enabled=bool(autopilot_enabled),
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

    report = run_upgrade_preflight(options, runner=runner, which=which, snapshot=snapshot, urlopen=urlopen, modules_root=modules_root)

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
        )
        if fix_status is not None:
            return fix_status
    if report.requires_confirmation and not options.yes:
        answer = input_func("AuraScan found upgrade risks. Continue anyway? [y/N] ").strip().lower()
        if answer not in {"y", "yes"}:
            print("[AuraScan] Upgrade not run.", file=stderr)
            return EXIT_USER_DECLINED

    run_upgrade_config_drift("before", options, input_func=input_func, stdout=stdout, stderr=stderr, root=config_drift_root, snapshot=snapshot, runner=config_drift_runner)
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
            print("[AuraScan] Skipping post-upgrade aftercare because the package transaction did not verify.", file=stderr)
            return EXIT_UPGRADE_VERIFICATION_FAILED
        run_upgrade_kernel_module_aftercare(options, plan=report.plan, runner=runner, stdout=stdout, stderr=stderr, snapshot=snapshot, modules_root=modules_root)
        run_upgrade_config_drift("after", options, input_func=input_func, stdout=stdout, stderr=stderr, root=config_drift_root, snapshot=snapshot, runner=config_drift_runner)
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
        refreshed = run_upgrade_preflight(options, runner=runner, which=which, snapshot=snapshot, urlopen=urlopen, modules_root=modules_root)
        report.plan = refreshed.plan
        report.snapshot = refreshed.snapshot
        report.findings = refreshed.findings
        report.ai_review = refreshed.ai_review
        report.kernel_module_check = refreshed.kernel_module_check
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
) -> UpgradePreflightReport:
    plan = build_upgrade_plan(options, runner=runner, which=which)
    system_snapshot = snapshot or SystemSnapshot.collect(runner=runner)
    kernel_module_check = None
    if options.kernel_module_autopilot_enabled and not plan.preview_error:
        kernel_module_check = build_kernel_module_check(plan, system_snapshot, runner=runner, modules_root=modules_root)
    findings = analyze_upgrade_risks(
        plan,
        system_snapshot,
        kernel_module_check=kernel_module_check,
        kernel_module_autopilot_enabled=options.kernel_module_autopilot_enabled,
    )
    report = UpgradePreflightReport(plan=plan, snapshot=system_snapshot, findings=findings, kernel_module_check=kernel_module_check)
    apply_ai_upgrade_review(report, disabled=options.no_ai, urlopen=urlopen)
    return report


def build_upgrade_plan(
    options: UpgradeOptions,
    *,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
) -> UpgradePlan:
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
) -> List[UpgradeFinding]:
    findings: List[UpgradeFinding] = []
    updated_names = set(plan.package_names())
    repo_names = {pkg.name for pkg in plan.repo_packages}
    kernel_updates = sorted(name for name in repo_names if is_kernel_package(name))
    sensitive_updates = sorted(name for name in repo_names if is_boot_sensitive_package(name) or is_kernel_package(name))
    module_packages = sorted(set(snapshot.dkms_packages + snapshot.nvidia_packages + snapshot.zfs_packages + snapshot.virtualbox_packages))
    foreign_dependency_issues = foreign_package_dependency_issues(snapshot, plan)

    if plan.preview_error:
        findings.append(_finding(
            "UPG-PREVIEW-FAILED",
            Severity.CRITICAL,
            "Upgrade preview could not be built.",
            "AuraScan could not get an authoritative package-manager preview for this upgrade.",
            "Without a transaction preview, AuraScan cannot reliably check upgrade breakage risks before handing off to pacman or a helper.",
            "Resolve the preview error, then run the upgrade preflight again.",
            plan.preview_error,
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
            "Arch and CachyOS do not support partial upgrades; holding core libraries, kernels, drivers, or desktop components can break dependencies.",
            "Review ignored packages/groups and remove holds unless you deliberately understand the compatibility impact.",
            f"IgnorePkg={', '.join(snapshot.ignored_packages) or '(none)'}; IgnoreGroup={', '.join(snapshot.ignored_groups) or '(none)'}",
        ))

    replacement_targets = applicable_replacements(plan, snapshot)
    if plan.removals or replacement_targets:
        sensitive_changes = [name for name in plan.removals + replacement_targets if is_sensitive_transaction_change(name)]
        severity = Severity.HIGH if plan.removals or sensitive_changes else Severity.MEDIUM
        metadata_only = sorted(set(plan.replacements) - set(replacement_targets))
        findings.append(_finding(
            "UPG-TRANSACTION-REPLACES",
            severity,
            "Upgrade includes replacements or removals.",
            "The package-manager preview contains installed replacement targets or removals.",
            "Installed replacements/removals can change package names or remove files that local packages still expect.",
            "Review the concrete replacement/removal list before accepting pacman's confirmation prompt.",
            f"installed replacement targets={', '.join(replacement_targets) or '(none)'}; removals={', '.join(plan.removals) or '(none)'}; metadata-only replaces={', '.join(metadata_only[:16]) or '(none)'}",
        ))

    if plan.conflicts:
        findings.append(_finding(
            "UPG-TRANSACTION-CONFLICTS",
            Severity.MEDIUM,
            "Upgrade preview includes package conflicts.",
            "The pending transaction reports package conflicts.",
            "Conflicts are often legitimate, but they can also cause package swaps or removals that affect a working system.",
            "Review the conflicting package names before continuing.",
            ", ".join(sorted(set(plan.conflicts))[:16]),
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
        "summary": str(data.get("summary") or ""),
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
        "You are AuraScan's upgrade preflight reviewer for Arch/CachyOS.\n"
        "Use only the JSON data below. Do not claim the upgrade is safe.\n"
        "You may only suggest risk raises, never risk reductions. Do not suggest hard blocking.\n"
        "Do not create package commands or package-fix plans; AuraScan's deterministic kernel/module autopilot owns those decisions.\n"
        "Do not tell the user to manually verify kernel/module compatibility when kernel_module_check status is ok.\n"
        "Do not raise fallback-kernel risk when kernel_module_check.fallback_kernel.available is true.\n"
        "Do not raise replacement/removal risk solely from transaction_changes.metadata_only_replaces; those are package metadata, not installed removals.\n"
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
