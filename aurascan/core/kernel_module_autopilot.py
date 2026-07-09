import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Mapping, Optional, Sequence

from aurascan.core.models import Severity


KERNEL_MODULE_AUTOPILOT_ENV = "AURASCAN_KERNEL_MODULE_AUTOPILOT_ENABLED"
MODULE_FAMILY_MARKERS = {
    "nvidia": ("nvidia",),
    "dkms": ("dkms",),
    "zfs": ("zfs", "spl"),
    "virtualbox": ("virtualbox",),
    "broadcom": ("broadcom", "broadcom-wl"),
    "v4l2loopback": ("v4l2loopback",),
}


@dataclass
class PackageFacts:
    name: str
    version: str = ""
    depends: List[str] = field(default_factory=list)
    provides: List[str] = field(default_factory=list)
    conflicts: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "name": self.name,
            "version": self.version,
            "depends": list(self.depends),
            "provides": list(self.provides),
            "conflicts": list(self.conflicts),
        }


@dataclass
class KernelModuleIssue:
    kind: str
    severity: Severity
    summary: str
    action: str
    packages: List[str] = field(default_factory=list)
    evidence: str = ""
    fixable: bool = False

    def __post_init__(self) -> None:
        self.severity = Severity(self.severity.value if isinstance(self.severity, Severity) else str(self.severity))

    def to_dict(self) -> Dict[str, object]:
        return {
            "kind": self.kind,
            "severity": self.severity.value,
            "summary": self.summary,
            "action": self.action,
            "packages": list(self.packages),
            "evidence": self.evidence,
            "fixable": self.fixable,
        }


@dataclass
class KernelModuleCheck:
    enabled: bool = True
    mode: str = "preflight"
    status: str = "ok"
    summary: str = "no kernel/module risk detected"
    running_kernel: str = ""
    running_kernel_package: str = ""
    target_kernel_packages: List[str] = field(default_factory=list)
    installed_kernel_packages: List[str] = field(default_factory=list)
    installed_module_families: List[str] = field(default_factory=list)
    module_dirs: Dict[str, str] = field(default_factory=dict)
    headers_status: List[Dict[str, object]] = field(default_factory=list)
    prebuilt_module_status: List[Dict[str, object]] = field(default_factory=list)
    dkms_status: Dict[str, object] = field(default_factory=dict)
    fallback_kernel: Dict[str, object] = field(default_factory=dict)
    fixable_issues: List[KernelModuleIssue] = field(default_factory=list)
    unfixable_issues: List[KernelModuleIssue] = field(default_factory=list)
    reboot_required: bool = False

    @property
    def has_issues(self) -> bool:
        return bool(self.fixable_issues or self.unfixable_issues)

    @property
    def highest_severity(self) -> Severity:
        issues = self.fixable_issues + self.unfixable_issues
        if not issues:
            return Severity.LOW
        order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return max((issue.severity for issue in issues), key=order.index)

    def fix_packages(self) -> List[str]:
        packages: List[str] = []
        for issue in self.fixable_issues:
            packages.extend(issue.packages)
        return sorted(set(packages))

    def to_dict(self) -> Dict[str, object]:
        return {
            "enabled": self.enabled,
            "mode": self.mode,
            "status": self.status,
            "summary": self.summary,
            "running_kernel": self.running_kernel,
            "running_kernel_package": self.running_kernel_package,
            "target_kernel_packages": list(self.target_kernel_packages),
            "installed_kernel_packages": list(self.installed_kernel_packages),
            "installed_module_families": list(self.installed_module_families),
            "module_dirs": dict(self.module_dirs),
            "headers_status": list(self.headers_status),
            "prebuilt_module_status": list(self.prebuilt_module_status),
            "dkms_status": dict(self.dkms_status),
            "fallback_kernel": dict(self.fallback_kernel),
            "fixable_issues": [issue.to_dict() for issue in self.fixable_issues],
            "unfixable_issues": [issue.to_dict() for issue in self.unfixable_issues],
            "fix_packages": self.fix_packages(),
            "reboot_required": self.reboot_required,
        }


def build_kernel_module_check(
    plan,
    snapshot,
    *,
    runner: Callable = subprocess.run,
    modules_root: Path = Path("/usr/lib/modules"),
    mode: str = "preflight",
) -> KernelModuleCheck:
    installed_packages = set(getattr(snapshot, "installed_packages", []) or [])
    repo_packages = list(getattr(plan, "repo_packages", []) or [])
    repo_by_name = {str(getattr(pkg, "name", "")): pkg for pkg in repo_packages if str(getattr(pkg, "name", ""))}
    pending_names = set(repo_by_name)
    removed_names = set(getattr(plan, "removals", []) or []) | set(getattr(plan, "replacements", []) or [])
    module_dirs = collect_module_pkgbases(modules_root)
    package_facts = _package_fact_map(getattr(snapshot, "package_info", []) or [])

    relevant_names = sorted(
        name
        for name in installed_packages | pending_names
        if is_kernel_base_package(name) or is_module_related_package(name) or name.endswith("-headers")
    )
    missing_fact_names = [name for name in relevant_names if name not in package_facts and name in installed_packages]
    package_facts.update(collect_package_facts(missing_fact_names, runner=runner))

    target_kernels = sorted(name for name in pending_names if is_kernel_base_package(name))
    installed_kernels = sorted({name for name in installed_packages if is_kernel_base_package(name)} | set(module_dirs.values()))
    running_kernel = str(getattr(snapshot, "running_kernel", "") or "")
    running_kernel_package = expected_running_kernel_package(running_kernel, module_dirs=module_dirs)
    module_families = detect_module_families(installed_packages)
    reboot_required = bool(target_kernels)

    check = KernelModuleCheck(
        enabled=True,
        mode=mode,
        running_kernel=running_kernel,
        running_kernel_package=running_kernel_package,
        target_kernel_packages=target_kernels,
        installed_kernel_packages=installed_kernels,
        installed_module_families=module_families,
        module_dirs=module_dirs,
        reboot_required=reboot_required,
    )

    _check_headers(check, installed_packages, pending_names, target_kernels, module_families)
    _check_prebuilt_modules(check, installed_packages, pending_names, repo_by_name, target_kernels, package_facts)
    _check_dkms(check, module_families, runner=runner)
    _check_fallback_kernel(check, installed_kernels, target_kernels, removed_names)
    _finish_status(check)
    return check


def kernel_module_fix_command(check: KernelModuleCheck) -> List[str]:
    packages = check.fix_packages()
    if not packages:
        return []
    return ["sudo", "pacman", "-S", "--needed"] + packages


def issues_to_findings(check: KernelModuleCheck) -> List[object]:
    findings = []
    for issue in check.fixable_issues + check.unfixable_issues:
        rule_id = "UPG-KERNEL-MODULE-FIXABLE" if issue.fixable else "UPG-KERNEL-MODULE-CHECK-INCOMPLETE"
        if not issue.fixable and issue.kind in {"prebuilt_module_missing", "prebuilt_module_mismatch", "dkms_failed"}:
            rule_id = "UPG-KERNEL-MODULE-MISMATCH"
        findings.append({
            "rule_id": rule_id,
            "severity": issue.severity,
            "title": _issue_title(issue),
            "summary": issue.summary,
            "why": "Kernel modules must match the kernel that will boot after the upgrade.",
            "action": issue.action,
            "evidence": issue.evidence,
        })
    return findings


def collect_module_pkgbases(root: Path) -> Dict[str, str]:
    result: Dict[str, str] = {}
    try:
        entries = sorted(root.iterdir())
    except OSError:
        return result
    for entry in entries:
        pkgbase = entry / "pkgbase"
        if not pkgbase.exists():
            continue
        try:
            value = pkgbase.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if value:
            result[entry.name] = value
    return result


def collect_package_facts(packages: Iterable[str], *, runner: Callable = subprocess.run) -> Dict[str, PackageFacts]:
    facts: Dict[str, PackageFacts] = {}
    for package in packages:
        text = _command_text(runner, ["pacman", "-Qi", package])
        if not text:
            continue
        fact = parse_package_facts(text)
        if not fact.name:
            fact.name = package
        facts[fact.name] = fact
    return facts


def parse_package_facts(text: str) -> PackageFacts:
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
    return PackageFacts(
        name=fields.get("Name", ""),
        version=fields.get("Version", ""),
        depends=split_pacman_list(fields.get("Depends On", "")),
        provides=split_pacman_list(fields.get("Provides", "")),
        conflicts=split_pacman_list(fields.get("Conflicts With", "")),
    )


def is_kernel_base_package(name: str) -> bool:
    if name in {"linux", "linux-lts", "linux-zen", "linux-hardened"}:
        return True
    if not name.startswith("linux-cachyos"):
        return False
    excluded_fragments = (
        "headers",
        "nvidia",
        "zfs",
        "virtualbox",
        "dkms",
        "api-headers",
        "firmware",
        "modules",
    )
    return not any(fragment in name for fragment in excluded_fragments)


def is_module_related_package(name: str) -> bool:
    if name.startswith("linux-firmware"):
        return False
    return any(any(marker in name for marker in markers) for markers in MODULE_FAMILY_MARKERS.values())


def detect_module_families(packages: Iterable[str]) -> List[str]:
    names = {name for name in packages if not name.startswith("linux-firmware")}
    families = []
    for family, markers in MODULE_FAMILY_MARKERS.items():
        if any(any(marker in name for marker in markers) for name in names):
            families.append(family)
    return sorted(families)


def expected_running_kernel_package(running_kernel: str, *, module_dirs: Optional[Mapping[str, str]] = None) -> str:
    if module_dirs and running_kernel in module_dirs:
        return str(module_dirs[running_kernel])
    kernel = running_kernel.lower()
    if not kernel:
        return ""
    if "cachyos-lts" in kernel:
        return "linux-cachyos-lts"
    if "cachyos" in kernel:
        return "linux-cachyos"
    if "lts" in kernel:
        return "linux-lts"
    if "zen" in kernel:
        return "linux-zen"
    if "hardened" in kernel:
        return "linux-hardened"
    return "linux"


def split_pacman_list(value: str) -> List[str]:
    value = value.strip()
    if not value or value.lower() in {"none", "(none)"}:
        return []
    parts = re.split(r"[,\s]+", value)
    return [part for part in parts if part and part.lower() not in {"none", "(none)"}]


def _check_headers(
    check: KernelModuleCheck,
    installed_packages: set,
    pending_names: set,
    target_kernels: Sequence[str],
    module_families: Sequence[str],
) -> None:
    if "dkms" not in module_families:
        return
    for kernel in target_kernels:
        header = f"{kernel}-headers"
        installed = header in installed_packages
        pending = header in pending_names
        check.headers_status.append({
            "kernel": kernel,
            "header_package": header,
            "installed": installed,
            "pending": pending,
            "ok": installed or pending,
        })
        if not installed and not pending:
            check.fixable_issues.append(KernelModuleIssue(
                kind="missing_headers",
                severity=Severity.HIGH,
                summary=f"AuraScan found DKMS packages but {header} is not installed or pending.",
                action=f"AuraScan can install {header} before the upgrade so DKMS has matching kernel headers.",
                packages=[header],
                evidence=f"kernel={kernel}; header_package={header}",
                fixable=True,
            ))


def _check_prebuilt_modules(
    check: KernelModuleCheck,
    installed_packages: set,
    pending_names: set,
    repo_by_name: Mapping[str, object],
    target_kernels: Sequence[str],
    package_facts: Mapping[str, PackageFacts],
) -> None:
    for kernel in target_kernels:
        installed_prebuilt = sorted(
            name
            for name in installed_packages
            if name.startswith(f"{kernel}-") and any(marker in name for marker in ("nvidia", "virtualbox", "zfs", "v4l2loopback", "broadcom"))
        )
        for module_package in installed_prebuilt:
            pending = module_package in pending_names
            pending_pkg = repo_by_name.get(module_package)
            pending_version = str(getattr(pending_pkg, "new_version", "") or "") if pending_pkg is not None else ""
            kernel_version = str(getattr(repo_by_name.get(kernel), "new_version", "") or "")
            version_match = bool(pending and (not pending_version or not kernel_version or pending_version == kernel_version))
            dependency_match = _pending_dependency_matches_kernel(pending_pkg, kernel, kernel_version) if pending_pkg is not None else False
            ok = bool(pending and (version_match or dependency_match))
            check.prebuilt_module_status.append({
                "kernel": kernel,
                "module_package": module_package,
                "installed": True,
                "pending": pending,
                "pending_version": pending_version,
                "kernel_version": kernel_version,
                "ok": ok,
            })
            if ok:
                continue
            if not pending:
                check.fixable_issues.append(KernelModuleIssue(
                    kind="prebuilt_module_missing",
                    severity=Severity.HIGH,
                    summary=f"{kernel} is upgrading but matching module package {module_package} is not in the transaction.",
                    action=f"AuraScan can explicitly add {module_package} before the upgrade and rerun preflight.",
                    packages=[module_package],
                    evidence=f"kernel={kernel}; module_package={module_package}",
                    fixable=True,
                ))
            else:
                check.unfixable_issues.append(KernelModuleIssue(
                    kind="prebuilt_module_mismatch",
                    severity=Severity.HIGH,
                    summary=f"{module_package} is pending but AuraScan could not prove it matches {kernel}.",
                    action="Do not reboot into the new kernel until the module package version/dependency mismatch is resolved.",
                    evidence=f"kernel={kernel} {kernel_version}; module={module_package} {pending_version}; installed_depends={package_facts.get(module_package).depends if module_package in package_facts else []}",
                ))

    if target_kernels and "nvidia" in check.installed_module_families and not any(item["module_package"] for item in check.prebuilt_module_status) and "dkms" not in check.installed_module_families:
        check.unfixable_issues.append(KernelModuleIssue(
            kind="nvidia_module_unknown",
            severity=Severity.HIGH,
            summary="NVIDIA userland packages are installed, but AuraScan did not find a matching NVIDIA kernel module package or DKMS package.",
            action="Install a kernel-matching NVIDIA module package or nvidia-dkms before relying on the upgraded kernel.",
            evidence="nvidia family detected without prebuilt module package or DKMS package",
        ))


def _pending_dependency_matches_kernel(pending_pkg: object, kernel: str, kernel_version: str) -> bool:
    if pending_pkg is None or not kernel_version:
        return False
    for dependency in getattr(pending_pkg, "depends", []) or []:
        if dependency == f"{kernel}={kernel_version}":
            return True
    return False


def _check_dkms(check: KernelModuleCheck, module_families: Sequence[str], *, runner: Callable) -> None:
    if "dkms" not in module_families:
        check.dkms_status = {"available": False, "packages_present": False, "status_lines": [], "failures": []}
        return
    result = _run(runner, ["dkms", "status"])
    if result is None:
        check.dkms_status = {"available": False, "packages_present": True, "status_lines": [], "failures": []}
        check.unfixable_issues.append(KernelModuleIssue(
            kind="dkms_unavailable",
            severity=Severity.HIGH,
            summary="DKMS packages are installed, but the dkms command was not available for verification.",
            action="Install or expose dkms before upgrading kernels with DKMS-backed modules.",
            evidence="dkms status could not be executed",
        ))
        return
    lines = [line.strip() for line in str(getattr(result, "stdout", "") or "").splitlines() if line.strip()]
    failures = [line for line in lines if any(token in line.lower() for token in ("failed", "failure", "error", "broken", "bad"))]
    check.dkms_status = {
        "available": True,
        "packages_present": True,
        "status_lines": lines,
        "failures": failures,
    }
    if failures:
        check.unfixable_issues.append(KernelModuleIssue(
            kind="dkms_failed",
            severity=Severity.HIGH,
            summary="DKMS reports failed or broken module builds.",
            action="Resolve the DKMS failure before relying on a kernel upgrade.",
            evidence="; ".join(failures[:8]),
        ))


def _check_fallback_kernel(check: KernelModuleCheck, installed_kernels: Sequence[str], target_kernels: Sequence[str], removed_names: set) -> None:
    available = sorted(kernel for kernel in installed_kernels if kernel not in removed_names)
    fallback = sorted(kernel for kernel in available if kernel not in set(target_kernels))
    check.fallback_kernel = {
        "available": bool(fallback),
        "installed_kernel_packages": list(installed_kernels),
        "fallback_kernel_packages": fallback,
    }
    if target_kernels and not fallback:
        check.unfixable_issues.append(KernelModuleIssue(
            kind="fallback_kernel_missing",
            severity=Severity.MEDIUM,
            summary="AuraScan did not find a separate fallback kernel package.",
            action="Consider installing an LTS or alternate kernel before risky kernel/module upgrades.",
            evidence=f"installed kernels={', '.join(installed_kernels) or '(none)'}",
        ))


def _finish_status(check: KernelModuleCheck) -> None:
    if check.fixable_issues:
        check.status = "fixable"
    elif check.unfixable_issues:
        check.status = "risk"
    else:
        check.status = "ok"

    if check.status == "ok":
        if check.target_kernel_packages and check.installed_module_families:
            families = ", ".join(check.installed_module_families)
            kernels = ", ".join(check.target_kernel_packages)
            check.summary = f"verified {families} module coverage for {kernels}; reboot required after upgrade"
        elif check.target_kernel_packages:
            kernels = ", ".join(check.target_kernel_packages)
            check.summary = f"kernel update detected for {kernels}; reboot required after upgrade"
        else:
            check.summary = "no kernel update or external module mismatch detected"
    elif check.status == "fixable":
        packages = ", ".join(check.fix_packages())
        check.summary = f"missing kernel support packages can be fixed before upgrade: {packages}"
    else:
        check.summary = "; ".join(issue.summary for issue in check.unfixable_issues[:2])


def _issue_title(issue: KernelModuleIssue) -> str:
    if issue.fixable:
        return "AuraScan can fix missing kernel support packages."
    if issue.kind == "fallback_kernel_missing":
        return "Fallback kernel evidence is limited."
    if issue.kind == "dkms_failed":
        return "DKMS module status needs repair."
    return "Kernel module compatibility could not be verified."


def _package_fact_map(items: Iterable[object]) -> Dict[str, PackageFacts]:
    facts: Dict[str, PackageFacts] = {}
    for item in items:
        name = str(getattr(item, "name", "") or "")
        if not name:
            continue
        facts[name] = PackageFacts(
            name=name,
            version=str(getattr(item, "version", "") or ""),
            depends=list(getattr(item, "depends", []) or []),
            provides=list(getattr(item, "provides", []) or []),
            conflicts=list(getattr(item, "conflicts", []) or []),
        )
    return facts


def _run(runner: Callable, cmd: Sequence[str]):
    try:
        result = runner(list(cmd), capture_output=True, text=True, check=False)
    except OSError:
        return None
    if int(getattr(result, "returncode", 0)) != 0:
        return None
    return result


def _command_text(runner: Callable, cmd: Sequence[str]) -> str:
    result = _run(runner, cmd)
    if result is None:
        return ""
    return str(getattr(result, "stdout", "") or "").strip()
