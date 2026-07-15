import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from aurascan.core.incidents import (
    INCIDENT_REPAIR_ROOT,
    IncidentReport,
    RepairAction,
    RepairResult,
    atomic_write_json,
    redact_incident_text,
    redact_structure,
    run_bounded_command,
    valid_boot_target,
)
from aurascan.core.kernel_module_autopilot import is_kernel_base_package
from aurascan.core.models import Severity
from aurascan.core.upgrade_preflight import (
    apply_repository_health_repairs,
    build_repository_health_check,
)


SAFE_NAME_RE = re.compile(r"^[a-zA-Z0-9@._+:-]{1,200}$")
SAFE_UNIT_RE = re.compile(r"^[a-zA-Z0-9@_.:-]+\.(?:service|socket|timer|mount)$")
PACMAN_CACHE_ROOT = Path("/var/cache/pacman/pkg")
PACKAGE_MANAGER_NAMES = {
    "pacman",
    "makepkg",
    "octopi",
    "paru",
    "yay",
    "pikaur",
    "shelly",
    "pamac",
    "pamac-daemon",
    "pamac-manager",
    "packagekitd",
    "trizen",
}
CRITICAL_UNIT_PREFIXES = (
    "accounts-daemon",
    "auditd",
    "containerd",
    "docker",
    "dbus",
    "display-manager",
    "gdm",
    "getty@",
    "greetd",
    "iwd",
    "lightdm",
    "libvirtd",
    "systemd-",
    "NetworkManager",
    "networkd",
    "nslcd",
    "polkit",
    "sddm",
    "sshd",
    "wpa_supplicant",
    "systemd-logind",
    "cryptsetup",
    "lvm2",
    "mdmonitor",
    "firewalld",
    "ufw",
)
MUTABLE_PACKAGE_PATH_PREFIXES = ("/etc/", "/var/", "/home/", "/root/", "/run/", "/tmp/")
IMMUTABLE_PACKAGE_PATH_PREFIXES = ("/usr/", "/opt/")
RECIPE_ORDER = {
    "repository_restore": 10,
    "stale_pacman_lock": 20,
    "package_cache_cleanup": 30,
    "kernel_headers_install": 40,
    "dkms_autoinstall": 50,
    "initramfs_rebuild": 60,
    "exact_package_reinstall": 70,
    "restart_system_service": 80,
    "restart_user_service": 90,
}


def plan_repair_actions(
    report: IncidentReport,
    *,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
    lock_path: Path = Path("/var/lib/pacman/db.lck"),
    cache_root: Path = Path("/var/cache/pacman/pkg"),
    pacman_conf_path: Path = Path("/etc/pacman.conf"),
    proc_root: Path = Path("/proc"),
) -> List[RepairAction]:
    categories = {finding.category for finding in report.findings}
    actions: List[RepairAction] = []

    if "repository" in categories:
        action = plan_repository_restore(pacman_conf_path)
        if action:
            actions.append(action)

    if "package_manager" in categories and lock_path.exists():
        action = plan_stale_lock(lock_path, proc_root=proc_root)
        if action:
            actions.append(action)

    if "disk_space" in categories and which("paccache"):
        action = plan_package_cache_cleanup(runner=runner, cache_root=cache_root, target_boot=report.target_boot)
        if action:
            actions.append(action)

    installed = command_lines(runner, ["pacman", "-Qq"]) if which("pacman") else []
    if "kernel_module" in categories and installed:
        header_action = plan_kernel_headers(installed, runner=runner)
        if header_action:
            actions.append(header_action)
        dkms_action = plan_dkms_autoinstall(installed, runner=runner, which=which)
        if dkms_action:
            actions.append(dkms_action)

    if "initramfs" in categories:
        action = plan_initramfs_rebuild(which=which, target_boot=report.target_boot)
        if action:
            actions.append(action)

    if "application_crash" in categories and which("pacman"):
        for group in report.coredumps[:20]:
            action = plan_exact_package_reinstall(group.executable, group.package, runner=runner, which=which, cache_root=cache_root)
            if action and not any(existing.parameters.get("package") == action.parameters.get("package") for existing in actions):
                actions.append(action)

    failed_units = sorted({item.unit for item in report.evidence if item.source in {"systemctl", "systemctl-user"} and item.unit})
    for unit in failed_units[:20]:
        user_service = any(item.unit == unit and item.source == "systemctl-user" for item in report.evidence)
        action = plan_service_restart(unit, user_service=user_service)
        if action:
            actions.append(action)

    actions.sort(key=lambda action: (RECIPE_ORDER.get(action.recipe_id, 999), action.action_id))
    return actions


def plan_repository_restore(pacman_conf_path: Path) -> Optional[RepairAction]:
    check = build_repository_health_check(pacman_conf_path)
    if not check.fixable_issues:
        return None
    targets = [issue.include_path for issue in check.fixable_issues]
    return make_action(
        "repository_restore",
        "Restore repository mirror configuration",
        "AuraScan found repository includes with no active servers and verified packaged backup mirrorlists with active servers.",
        Severity.MEDIUM,
        {"pacman_conf_path": str(pacman_conf_path), "targets": targets, "category": "repository"},
        [["install", "<verified-backup-mirrorlist>", "<repository-include>"]],
        reversible=True,
        backup="Current mirrorlists and a manifest will be stored under the incident repair directory.",
    )


def plan_stale_lock(lock_path: Path, *, proc_root: Path = Path("/proc")) -> Optional[RepairAction]:
    if package_manager_processes(proc_root):
        return None
    try:
        age = max(0, int(time.time() - lock_path.stat().st_mtime))
    except OSError:
        return None
    if age < 600:
        return None
    return make_action(
        "stale_pacman_lock",
        "Move the stale pacman database lock",
        f"No package manager is running and the lock is {age // 60} minutes old. AuraScan will move it into the repair backup before checking the package database.",
        Severity.LOW,
        {"lock_path": str(lock_path), "minimum_age": 600, "category": "package_manager"},
        [["mv", str(lock_path), "<repair-backup>"], ["pacman", "-Dk"]],
        reversible=True,
        backup="The lock file is moved, not deleted, and is restored if package database validation fails.",
    )


def plan_package_cache_cleanup(*, runner: Callable, cache_root: Path, target_boot: str = "0") -> Optional[RepairAction]:
    try:
        usage = shutil.disk_usage(cache_root)
    except OSError:
        return None
    low_space_threshold = min(1024 * 1024 * 1024, max(256 * 1024 * 1024, int(usage.total * 0.05)))
    if usage.free > low_space_threshold:
        return None
    output = run_bounded_command(runner, ["paccache", "-d", "-k", "2", "-c", str(cache_root)], max_chars=128000, timeout=30)
    if output.returncode != 0:
        return None
    candidates = [line.strip() for line in output.stdout.splitlines() if line.strip().startswith(str(cache_root))]
    if not candidates:
        return None
    reclaim = 0
    for raw in candidates[:5000]:
        try:
            reclaim += Path(raw).stat().st_size
        except OSError:
            continue
    if reclaim < 64 * 1024 * 1024:
        return None
    return make_action(
        "package_cache_cleanup",
        "Free bounded package-cache space",
        f"AuraScan can reclaim approximately {reclaim // (1024 * 1024)} MiB while preserving the newest two versions of each cached package.",
        Severity.MEDIUM,
        {"cache_root": str(cache_root), "minimum_reclaim": reclaim, "target_boot": target_boot, "category": "disk_space"},
        [["paccache", "-r", "-k", "2", "-c", str(cache_root)]],
        reversible=False,
        backup="Package archives removed from the cache cannot be restored by AuraScan.",
    )


def plan_kernel_headers(installed_packages: Sequence[str], *, runner: Callable = subprocess.run) -> Optional[RepairAction]:
    installed = set(installed_packages)
    has_dkms = any("dkms" in name for name in installed)
    if not has_dkms:
        return None
    kernels = sorted(name for name in installed if is_kernel_base_package(name))
    missing = []
    versions: Dict[str, str] = {}
    for kernel in kernels:
        header = f"{kernel}-headers"
        if header in installed:
            continue
        kernel_version = query_installed_version(kernel, runner=runner)
        header_version = query_sync_version(header, runner=runner)
        if not kernel_version or header_version != kernel_version:
            return None
        missing.append(header)
        versions[header] = header_version
    if not missing:
        return None
    return make_action(
        "kernel_headers_install",
        "Install missing kernel headers",
        "DKMS-backed modules are installed, but matching headers are missing for: " + ", ".join(missing),
        Severity.MEDIUM,
        {"packages": missing, "kernels": kernels, "versions": versions, "category": "kernel_module"},
        [["pacman", "-S", "--needed", "--noconfirm"] + missing],
        reversible=False,
        backup="Pacman records the package transaction; AuraScan does not remove headers automatically on rollback.",
    )


def plan_dkms_autoinstall(
    installed_packages: Sequence[str],
    *,
    runner: Callable,
    which: Callable[[str], Optional[str]],
) -> Optional[RepairAction]:
    if not which("dkms") or not any("dkms" in name for name in installed_packages):
        return None
    output = run_bounded_command(runner, ["dkms", "status"], max_chars=64000, timeout=20)
    combined = (output.stdout + "\n" + output.stderr).lower()
    if output.returncode == 0 and not any(token in combined for token in ("failed", "failure", "broken", "error", "added")):
        return None
    kernels = sorted(name for name in installed_packages if is_kernel_base_package(name))
    if any(f"{kernel}-headers" not in installed_packages for kernel in kernels):
        return None
    return make_action(
        "dkms_autoinstall",
        "Rebuild DKMS modules",
        "DKMS reports incomplete or failed module state and matching kernel headers are installed.",
        Severity.MEDIUM,
        {"kernels": kernels, "category": "kernel_module"},
        [["dkms", "autoinstall"]],
        reversible=False,
        backup="DKMS keeps its build state; AuraScan verifies status after rebuilding.",
    )


def plan_initramfs_rebuild(*, which: Callable[[str], Optional[str]], target_boot: str = "0") -> Optional[RepairAction]:
    generator = "mkinitcpio" if which("mkinitcpio") else "dracut" if which("dracut") else ""
    if not generator:
        return None
    command = ["mkinitcpio", "-P"] if generator == "mkinitcpio" else ["dracut", "--regenerate-all", "--force"]
    return make_action(
        "initramfs_rebuild",
        "Rebuild initramfs images",
        f"AuraScan found an initramfs failure and verified that {generator} is installed. Existing images will be backed up first.",
        Severity.MEDIUM,
        {"generator": generator, "target_boot": target_boot, "category": "initramfs"},
        [command],
        reversible=True,
        backup="Existing initramfs images and checksums will be stored before regeneration.",
    )


def plan_service_restart(unit: str, *, user_service: bool = False) -> Optional[RepairAction]:
    if not SAFE_UNIT_RE.fullmatch(unit) or is_critical_unit(unit):
        return None
    recipe = "restart_user_service" if user_service else "restart_system_service"
    prefix = ["systemctl", "--user"] if user_service else ["systemctl"]
    return make_action(
        recipe,
        f"Restart failed {'user ' if user_service else ''}unit {unit}",
        "AuraScan will reset the failed state, restart the unit, and verify that it becomes active.",
        Severity.MEDIUM,
        {"unit": unit, "user_service": user_service, "category": "failed_service"},
        [prefix + ["reset-failed", unit], prefix + ["restart", unit], prefix + ["is-active", unit]],
        requires_root=not user_service,
        reversible=False,
        backup="The prior active/enabled state is recorded in the repair manifest.",
    )


def plan_exact_package_reinstall(
    executable: str,
    package_hint: str,
    *,
    runner: Callable,
    which: Callable[[str], Optional[str]],
    cache_root: Path,
) -> Optional[RepairAction]:
    executable_path = which(executable) if executable and executable != "unknown" else None
    package = package_hint.strip()
    if not package and executable_path:
        owner = run_bounded_command(runner, ["pacman", "-Qo", executable_path], max_chars=4000, timeout=10)
        package = parse_package_owner(owner.stdout) if owner.returncode == 0 else ""
    if not package or not SAFE_NAME_RE.fullmatch(package):
        return None
    foreign = run_bounded_command(runner, ["pacman", "-Qm", package], max_chars=4000, timeout=10)
    if foreign.returncode == 0:
        return None
    installed = run_bounded_command(runner, ["pacman", "-Q", package], max_chars=4000, timeout=10)
    installed_name, installed_version = parse_package_query(installed.stdout)
    if installed.returncode != 0 or installed_name != package or not installed_version:
        return None
    missing = package_missing_immutable_files(package, runner=runner)
    if not missing:
        return None
    archive = find_exact_cached_package(package, installed_version, cache_root=cache_root, runner=runner)
    if archive is None or not Path(str(archive) + ".sig").exists():
        return None
    verify = run_bounded_command(runner, ["pacman-key", "--verify", str(archive) + ".sig", str(archive)], max_chars=16000, timeout=30)
    if verify.returncode != 0:
        return None
    return make_action(
        "exact_package_reinstall",
        f"Reinstall exact cached package {package}",
        f"AuraScan proved that {len(missing)} immutable package file(s) are missing and verified a signed local archive for the currently installed version {installed_version}.",
        Severity.MEDIUM,
        {
            "package": package,
            "version": installed_version,
            "archive": str(archive),
            "archive_sha256": sha256_file(archive),
            "missing_files": missing[:50],
            "category": "application_crash",
        },
        [["pacman", "-U", "--noconfirm", str(archive)]],
        reversible=False,
        backup="The exact signed archive and its checksum are recorded; this reinstalls the same version rather than performing a partial upgrade.",
    )


def make_action(
    recipe_id: str,
    title: str,
    summary: str,
    risk: Severity,
    parameters: Dict[str, object],
    command_preview: List[List[str]],
    *,
    requires_root: bool = True,
    reversible: bool = False,
    backup: str = "",
) -> RepairAction:
    action_id = repair_action_id(recipe_id, parameters)
    return RepairAction(
        action_id=action_id,
        recipe_id=recipe_id,
        title=title,
        summary=summary,
        risk=risk,
        parameters=parameters,
        command_preview=command_preview,
        eligible=True,
        verified=True,
        requires_root=requires_root,
        reversible=reversible,
        backup_description=backup,
    )


def repair_action_id(recipe_id: str, parameters: Mapping[str, object]) -> str:
    material = json.dumps({"recipe": recipe_id, "parameters": dict(parameters)}, sort_keys=True)
    return "ira-" + hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()[:16]


def repair_manifest_entry(action: RepairAction, result: RepairResult, *, run_root: Path) -> Dict[str, object]:
    parameter_text = json.dumps(action.parameters, sort_keys=True)
    checksums: Dict[str, str] = {}
    archive_hash = str(action.parameters.get("archive_sha256") or "")
    if archive_hash:
        checksums["prepared_archive_sha256"] = archive_hash
    checksums.update(backup_checksums(result.backup_path, run_root=run_root))
    return {
        "action_id": action.action_id,
        "recipe_id": action.recipe_id,
        "parameters": redact_structure(action.parameters),
        "parameters_sha256": hashlib.sha256(parameter_text.encode("utf-8", "replace")).hexdigest(),
        "commands": trusted_repair_commands(action) if result.status != "refused" else [],
        "pre_validation": "passed" if result.status != "refused" else "refused",
        "post_validation": "passed" if result.verified else "failed_or_not_run",
        "checksums": checksums,
        "backup_path": redact_incident_text(result.backup_path),
        "rollback_available": result.rollback_available,
        "bounded_redacted_output": result.output_excerpt or redact_incident_text(result.message)[:4000],
    }


def trusted_repair_commands(action: RepairAction) -> List[List[str]]:
    recipe = action.recipe_id
    parameters = action.parameters
    if recipe == "repository_restore":
        return [["install", "<verified-backup-mirrorlist>", "<verified-repository-include>"]]
    if recipe == "stale_pacman_lock":
        return [["mv", "/var/lib/pacman/db.lck", "<repair-backup>"], ["pacman", "-Dk"]]
    if recipe == "package_cache_cleanup":
        return [["paccache", "-r", "-k", "2", "-c", "/var/cache/pacman/pkg"]]
    if recipe == "kernel_headers_install":
        packages = [str(item) for item in parameters.get("packages", []) if SAFE_NAME_RE.fullmatch(str(item))]
        return [["pacman", "-S", "--needed", "--noconfirm"] + packages]
    if recipe == "dkms_autoinstall":
        return [["dkms", "autoinstall"], ["dkms", "status"]]
    if recipe == "initramfs_rebuild":
        return [["mkinitcpio", "-P"]] if parameters.get("generator") == "mkinitcpio" else [["dracut", "--regenerate-all", "--force"]]
    if recipe == "exact_package_reinstall":
        return [["pacman", "-U", "--noconfirm", str(parameters.get("archive") or "")]]
    if recipe in {"restart_system_service", "restart_user_service"}:
        unit = str(parameters.get("unit") or "")
        prefix = ["systemctl", "--user"] if recipe == "restart_user_service" else ["systemctl"]
        return [prefix + ["reset-failed", unit], prefix + ["restart", unit], prefix + ["is-active", unit]]
    return []


def backup_checksums(backup_path: str, *, run_root: Path) -> Dict[str, str]:
    if not backup_path:
        return {}
    try:
        path = Path(backup_path).resolve()
        path.relative_to(run_root.resolve())
    except (OSError, ValueError):
        return {}
    candidates = [path] if path.is_file() else sorted(item for item in path.rglob("*") if item.is_file())[:50]
    result = {}
    for candidate in candidates:
        digest = sha256_file(candidate)
        if digest:
            result[str(candidate.relative_to(run_root))] = digest
    return result


def apply_repair_plan(
    actions: Sequence[RepairAction],
    *,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
    stdout=None,
    stderr=None,
    repair_root: Path = INCIDENT_REPAIR_ROOT,
) -> Tuple[List[RepairResult], bool]:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    ordered = sorted(actions, key=lambda action: (RECIPE_ORDER.get(action.recipe_id, 999), action.action_id))
    root_actions = [action for action in ordered if action.requires_root]
    local_actions = [action for action in ordered if not action.requires_root]
    results: List[RepairResult] = []

    if root_actions:
        request = {"schema_version": "1.0", "actions": [action.to_dict() for action in root_actions]}
        fd, request_name = tempfile.mkstemp(prefix="aurascan-incident-repair-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(request, handle)
            os.chmod(request_name, 0o600)
            if hasattr(os, "geteuid") and os.geteuid() == 0:
                root_results, root_ok = execute_repair_request(Path(request_name), runner=runner, which=which, repair_root=repair_root)
            else:
                helper = Path("/usr/bin/aurascan")
                if not helper.is_file():
                    return [RepairResult("", "", "failed", "Privileged repairs require the package-managed /usr/bin/aurascan executable.")], False
                command = ["sudo", str(helper), "incidents", "--apply-request", request_name]
                print("[AuraScan] Applying verified incident repairs requires root privileges.", file=stderr)
                output = run_bounded_command(runner, command, max_chars=256000, timeout=1800)
                root_results, root_ok = parse_repair_response(output.stdout, output.returncode)
                if output.stderr.strip():
                    print(redact_incident_text(output.stderr.strip())[:2000], file=stderr)
            results.extend(root_results)
            if not root_ok:
                return results, False
        finally:
            try:
                os.unlink(request_name)
            except OSError:
                pass

    for action in local_actions:
        result = execute_one_repair(action, runner=runner, which=which, run_root=repair_root / make_run_id())
        results.append(result)
        if result.status != "applied":
            return results, False
    return results, True


def execute_repair_request(
    request_path: Path,
    *,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
    repair_root: Path = INCIDENT_REPAIR_ROOT,
) -> Tuple[List[RepairResult], bool]:
    if request_path.is_symlink() or not request_path.is_file():
        return [RepairResult("", "", "refused", "Repair request is not a regular file.")], False
    try:
        data = json.loads(request_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [RepairResult("", "", "refused", f"Invalid repair request: {exc}")], False
    if not isinstance(data, dict) or data.get("schema_version") != "1.0":
        return [RepairResult("", "", "refused", "Repair request schema is invalid.")], False
    raw_actions = data.get("actions", [])
    if not isinstance(raw_actions, list) or not raw_actions or len(raw_actions) > 20:
        return [RepairResult("", "", "refused", "Repair request action count is invalid.")], False
    actions = [RepairAction.from_dict(item) for item in raw_actions if isinstance(item, dict)]
    if len(actions) != len(raw_actions):
        return [RepairResult("", "", "refused", "Repair request contains malformed actions.")], False
    run_root = repair_root / make_run_id()
    run_root.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(run_root, 0o700)
    results = []
    manifest = {
        "schema": "incident_repair_manifest/1.0",
        "schema_version": "1.0",
        "created_at": int(time.time()),
        "actions": [],
        "results": [],
    }
    ok = True
    for action in sorted(actions, key=lambda item: (RECIPE_ORDER.get(item.recipe_id, 999), item.action_id)):
        if (
            action.recipe_id == "restart_user_service"
            or not action.requires_root
            or not action.eligible
            or not action.verified
            or action.action_id != repair_action_id(action.recipe_id, action.parameters)
        ):
            result = refused(action, "Repair request action identity or privilege scope is invalid.")
        else:
            result = execute_one_repair(action, runner=runner, which=which, run_root=run_root)
        results.append(result)
        manifest["actions"].append(repair_manifest_entry(action, result, run_root=run_root))
        manifest["results"].append(result.to_dict())
        if result.status != "applied":
            ok = False
            break
    atomic_write_json(run_root / "manifest.json", manifest, mode=0o600)
    return results, ok


def execute_one_repair(
    action: RepairAction,
    *,
    runner: Callable,
    which: Callable[[str], Optional[str]],
    run_root: Path,
) -> RepairResult:
    handlers = {
        "repository_restore": execute_repository_restore,
        "stale_pacman_lock": execute_stale_lock,
        "package_cache_cleanup": execute_package_cache_cleanup,
        "kernel_headers_install": execute_kernel_headers,
        "dkms_autoinstall": execute_dkms_autoinstall,
        "initramfs_rebuild": execute_initramfs_rebuild,
        "exact_package_reinstall": execute_exact_package_reinstall,
        "restart_system_service": execute_service_restart,
        "restart_user_service": execute_service_restart,
    }
    handler = handlers.get(action.recipe_id)
    if handler is None or not action.action_id.startswith("ira-"):
        return RepairResult(action.action_id, action.recipe_id, "refused", "Unknown or malformed repair recipe.")
    try:
        return handler(action, runner=runner, which=which, run_root=run_root)
    except Exception as exc:
        return RepairResult(action.action_id, action.recipe_id, "failed", redact_incident_text(str(exc))[:1000])


def execute_repository_restore(action: RepairAction, *, runner: Callable, which: Callable, run_root: Path) -> RepairResult:
    conf = Path(str(action.parameters.get("pacman_conf_path") or "/etc/pacman.conf"))
    if conf != Path("/etc/pacman.conf"):
        return refused(action, "Repository configuration path is not allowlisted.")
    check = build_repository_health_check(conf)
    if not check.fixable_issues:
        return refused(action, "Repository repair is no longer needed or cannot be verified.")
    result = apply_repository_health_repairs(check, runner=runner, backup_root=run_root / "repository")
    if not result.success:
        rolled_back = rollback_repository_repair(result.applied, Path(result.backup_dir))
        message = "; ".join(result.errors) or "Repository repair failed."
        if result.applied:
            message += " Applied mirrorlists were restored from the repair backup." if rolled_back else " Automatic rollback was incomplete."
        return failed(action, message, result.backup_dir)
    verified = not build_repository_health_check(conf).issues
    if not verified:
        rolled_back = rollback_repository_repair(result.applied, Path(result.backup_dir))
        message = "Repository files changed but active servers still could not be verified."
        message += " Previous mirrorlists were restored." if rolled_back else " Automatic rollback was incomplete."
        return failed(action, message, result.backup_dir)
    return applied(action, "Repository mirror configuration was restored and active servers were verified.", result.backup_dir, True)


def execute_stale_lock(action: RepairAction, *, runner: Callable, which: Callable, run_root: Path) -> RepairResult:
    lock = Path(str(action.parameters.get("lock_path") or ""))
    if lock != Path("/var/lib/pacman/db.lck"):
        return refused(action, "Pacman lock path is not allowlisted.")
    if not lock.exists() or package_manager_processes(Path("/proc")):
        return refused(action, "The lock disappeared or a package manager is running.")
    minimum_age = max(600, int(action.parameters.get("minimum_age") or 600))
    if time.time() - lock.stat().st_mtime < minimum_age:
        return refused(action, "The package database lock is too recent to treat as stale.")
    backup = run_root / "pacman" / "db.lck"
    backup.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(lock), str(backup))
    if package_manager_processes(Path("/proc")):
        if not lock.exists():
            shutil.move(str(backup), str(lock))
        return failed(action, "A package manager started during lock recovery; AuraScan stopped before database validation.", str(backup))
    check = run_bounded_command(runner, ["pacman", "-Dk"], max_chars=64000, timeout=60)
    if check.returncode != 0:
        shutil.move(str(backup), str(lock))
        return failed(action, "Package database validation failed; the lock was restored.", str(backup), command_output_excerpt(check))
    return applied(action, "The stale pacman lock was moved and the package database passed validation.", str(backup), True, command_output_excerpt(check))


def execute_package_cache_cleanup(action: RepairAction, *, runner: Callable, which: Callable, run_root: Path) -> RepairResult:
    cache = Path(str(action.parameters.get("cache_root") or ""))
    if cache != Path("/var/cache/pacman/pkg") or not which("paccache"):
        return refused(action, "Package cache cleanup path or tool is not allowlisted.")
    preview = run_bounded_command(runner, ["paccache", "-d", "-k", "2", "-c", str(cache)], max_chars=128000, timeout=30)
    candidates = [line.strip() for line in preview.stdout.splitlines() if line.strip().startswith(str(cache))]
    if preview.returncode != 0 or not candidates:
        return refused(action, "No bounded cache cleanup is currently available.")
    usage = shutil.disk_usage(cache)
    low_space_threshold = min(1024 * 1024 * 1024, max(256 * 1024 * 1024, int(usage.total * 0.05)))
    target_boot = str(action.parameters.get("target_boot") or "")
    if usage.free > low_space_threshold or not journal_has_pattern(runner, target_boot, r"(?i)no space left on device|ENOSPC|disk quota exceeded"):
        return refused(action, "Fresh disk-space validation no longer proves that bounded cache cleanup is needed.")
    reclaim = sum(path_size(Path(raw)) for raw in candidates[:5000])
    if reclaim < 64 * 1024 * 1024:
        return refused(action, "Fresh cache cleanup preview would reclaim less than 64 MiB.")
    before = usage.free
    result = run_bounded_command(runner, ["paccache", "-r", "-k", "2", "-c", str(cache)], max_chars=128000, timeout=300)
    after = shutil.disk_usage(cache).free
    if result.returncode != 0:
        return failed(action, "paccache failed; removed archives cannot be restored.", output=command_output_excerpt(result))
    return applied(action, f"Package cache cleanup completed and free space increased by {(after - before) // (1024 * 1024)} MiB.", "", False, command_output_excerpt(result))


def execute_kernel_headers(action: RepairAction, *, runner: Callable, which: Callable, run_root: Path) -> RepairResult:
    packages = [str(item) for item in action.parameters.get("packages", [])]
    if not packages or any(not SAFE_NAME_RE.fullmatch(item) or not item.endswith("-headers") for item in packages):
        return refused(action, "Kernel header package request is malformed.")
    installed = set(command_lines(runner, ["pacman", "-Qq"]))
    kernels = sorted(name for name in installed if is_kernel_base_package(name))
    expected = sorted(f"{kernel}-headers" for kernel in kernels if f"{kernel}-headers" not in installed)
    requested_versions = action.parameters.get("versions", {})
    if not isinstance(requested_versions, Mapping):
        return refused(action, "Kernel header version proof is missing.")
    verified_expected = []
    for kernel in kernels:
        header = f"{kernel}-headers"
        if header in installed:
            continue
        kernel_version = query_installed_version(kernel, runner=runner)
        header_version = query_sync_version(header, runner=runner)
        if kernel_version and header_version == kernel_version and str(requested_versions.get(header) or "") == header_version:
            verified_expected.append(header)
    if sorted(packages) != sorted(verified_expected) or sorted(packages) != expected or not any("dkms" in name for name in installed):
        return refused(action, "Fresh kernel/header validation no longer matches the prepared action.")
    result = run_bounded_command(runner, ["pacman", "-S", "--needed", "--noconfirm"] + packages, max_chars=128000, timeout=1800)
    if result.returncode != 0:
        return failed(action, "Pacman could not install the verified kernel headers.", output=command_output_excerpt(result))
    now_installed = set(command_lines(runner, ["pacman", "-Qq"]))
    if any(package not in now_installed or query_installed_version(package, runner=runner) != str(requested_versions.get(package) or "") for package in packages):
        return failed(action, "Pacman returned success but one or more kernel headers did not verify as installed.", output=command_output_excerpt(result))
    return applied(action, "Matching kernel headers were installed and verified.", "", False, command_output_excerpt(result))


def execute_dkms_autoinstall(action: RepairAction, *, runner: Callable, which: Callable, run_root: Path) -> RepairResult:
    if not which("dkms"):
        return refused(action, "dkms is no longer available.")
    installed = set(command_lines(runner, ["pacman", "-Qq"]))
    kernels = sorted(name for name in installed if is_kernel_base_package(name))
    if not kernels or any(f"{kernel}-headers" not in installed for kernel in kernels):
        return refused(action, "Matching kernel headers are not installed for every detected kernel.")
    before_status = run_bounded_command(runner, ["dkms", "status"], max_chars=128000, timeout=60)
    before_text = (before_status.stdout + "\n" + before_status.stderr).lower()
    if before_status.returncode == 0 and not any(token in before_text for token in ("failed", "failure", "broken", "error", "added")):
        return refused(action, "DKMS status is already clean; an autoinstall is no longer needed.")
    result = run_bounded_command(runner, ["dkms", "autoinstall"], max_chars=128000, timeout=1800)
    status = run_bounded_command(runner, ["dkms", "status"], max_chars=128000, timeout=60)
    combined = (status.stdout + "\n" + status.stderr).lower()
    if result.returncode != 0 or status.returncode != 0 or any(token in combined for token in ("failed", "failure", "broken", "error")):
        return failed(action, "DKMS rebuild did not produce a clean verified status.", output=command_output_excerpt(result, status))
    return applied(action, "DKMS modules were rebuilt and status is clean.", "", False, command_output_excerpt(result, status))


def execute_initramfs_rebuild(action: RepairAction, *, runner: Callable, which: Callable, run_root: Path) -> RepairResult:
    generator = str(action.parameters.get("generator") or "")
    if generator not in {"mkinitcpio", "dracut"} or not which(generator):
        return refused(action, "The prepared initramfs generator is not available.")
    target_boot = str(action.parameters.get("target_boot") or "")
    if not journal_has_pattern(runner, target_boot, r"(?i)(mkinitcpio|dracut|initramfs).*(?:failed|error|missing)"):
        return refused(action, "Fresh journal validation no longer proves an initramfs failure for the selected boot.")
    boot = Path("/boot")
    if not boot.exists() or shutil.disk_usage(boot).free < 128 * 1024 * 1024:
        return refused(action, "At least 128 MiB of free /boot space is required for a guarded rebuild.")
    images = [path for path in boot.glob("*.img") if path.is_file() and not path.is_symlink()]
    if not images:
        return refused(action, "No existing initramfs images were found to back up.")
    backup_bytes = sum(path_size(image) for image in images)
    if shutil.disk_usage(run_root).free < backup_bytes + 64 * 1024 * 1024:
        return refused(action, "Incident repair storage does not have enough free space to back up initramfs images.")
    backup_dir = run_root / "initramfs"
    backup_dir.mkdir(parents=True, exist_ok=True)
    before = {}
    for image in images:
        backup = backup_dir / image.name
        shutil.copy2(image, backup)
        before[str(image)] = sha256_file(image)
    command = ["mkinitcpio", "-P"] if generator == "mkinitcpio" else ["dracut", "--regenerate-all", "--force"]
    result = run_bounded_command(runner, command, max_chars=256000, timeout=1800)
    verified = result.returncode == 0 and all(path.exists() and path.stat().st_size > 0 for path in images)
    if not verified:
        for image in images:
            backup = backup_dir / image.name
            if backup.exists():
                shutil.copy2(backup, image)
        return failed(action, "Initramfs rebuild failed verification; previous images were restored.", str(backup_dir), command_output_excerpt(result))
    return applied(action, "Initramfs images were rebuilt and verified.", str(backup_dir), True, command_output_excerpt(result))


def execute_exact_package_reinstall(action: RepairAction, *, runner: Callable, which: Callable, run_root: Path) -> RepairResult:
    package = str(action.parameters.get("package") or "")
    version = str(action.parameters.get("version") or "")
    archive = Path(str(action.parameters.get("archive") or ""))
    expected_hash = str(action.parameters.get("archive_sha256") or "")
    if not SAFE_NAME_RE.fullmatch(package) or not version or not archive.is_file():
        return refused(action, "Exact-package repair parameters are malformed or the archive disappeared.")
    try:
        archive.resolve().relative_to(PACMAN_CACHE_ROOT.resolve())
    except (OSError, ValueError):
        return refused(action, "Package archive is outside the allowlisted pacman cache.")
    installed_name, installed_version = parse_package_query(command_text(runner, ["pacman", "-Q", package]))
    if installed_name != package or installed_version != version:
        return refused(action, "Installed package version changed since the repair was prepared.")
    foreign = run_bounded_command(runner, ["pacman", "-Qm", package], max_chars=4000, timeout=15)
    if foreign.returncode == 0:
        return refused(action, "The package is foreign to the configured official repositories.")
    if sha256_file(archive) != expected_hash:
        return refused(action, "Cached package checksum changed since the repair was prepared.")
    sig = Path(str(archive) + ".sig")
    verify = run_bounded_command(runner, ["pacman-key", "--verify", str(sig), str(archive)], max_chars=32000, timeout=60)
    if not sig.exists() or verify.returncode != 0:
        return refused(action, "The cached package signature could not be freshly verified.")
    metadata_name, metadata_version = parse_package_query(command_text(runner, ["pacman", "-Qp", str(archive)]))
    if metadata_name != package or metadata_version != version:
        return refused(action, "Cached package metadata does not exactly match the installed package.")
    missing = package_missing_immutable_files(package, runner=runner)
    if not missing:
        return refused(action, "Missing immutable package files are no longer present.")
    result = run_bounded_command(runner, ["pacman", "-U", "--noconfirm", str(archive)], max_chars=256000, timeout=1800)
    if result.returncode != 0 or package_missing_immutable_files(package, runner=runner):
        return failed(action, "Exact package reinstall did not restore all missing immutable files.", output=command_output_excerpt(result))
    return applied(action, f"Exact package {package} {version} was reinstalled from the verified local cache.", str(archive), False, command_output_excerpt(result))


def execute_service_restart(action: RepairAction, *, runner: Callable, which: Callable, run_root: Path) -> RepairResult:
    unit = str(action.parameters.get("unit") or "")
    user_service = bool(action.parameters.get("user_service", False))
    expected_recipe = "restart_user_service" if user_service else "restart_system_service"
    if action.recipe_id != expected_recipe or not SAFE_UNIT_RE.fullmatch(unit) or is_critical_unit(unit):
        return refused(action, "Service restart request is not allowlisted.")
    prefix = ["systemctl", "--user"] if user_service else ["systemctl"]
    failed_state = run_bounded_command(runner, prefix + ["is-failed", unit], max_chars=4000, timeout=15)
    if failed_state.stdout.strip() != "failed":
        return refused(action, "The unit is no longer in a failed state.")
    enabled_state = run_bounded_command(runner, prefix + ["is-enabled", unit], max_chars=4000, timeout=15).stdout.strip()
    run_bounded_command(runner, prefix + ["reset-failed", unit], max_chars=8000, timeout=30)
    restarted = run_bounded_command(runner, prefix + ["restart", unit], max_chars=64000, timeout=120)
    active = run_bounded_command(runner, prefix + ["is-active", unit], max_chars=4000, timeout=30)
    if restarted.returncode != 0 or active.stdout.strip() != "active":
        return failed(action, f"{unit} did not become active after restart; previous enabled state was {enabled_state or 'unknown'}.", output=command_output_excerpt(restarted, active))
    return applied(action, f"{unit} restarted successfully and is active.", "", False, command_output_excerpt(restarted, active))


def parse_repair_response(text: str, returncode: int) -> Tuple[List[RepairResult], bool]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return [RepairResult("", "", "failed", "Privileged repair helper returned invalid output.")], False
    if not isinstance(data, dict):
        return [RepairResult("", "", "failed", "Privileged repair helper returned invalid output.")], False
    results = [RepairResult.from_dict(item) for item in data.get("results", []) if isinstance(item, dict)]
    return results, bool(data.get("ok", False)) and returncode == 0


def package_manager_processes(proc_root: Path = Path("/proc")) -> List[str]:
    found = []
    try:
        for index, entry in enumerate(proc_root.iterdir()):
            if index >= 10000:
                found.append("scan-limit")
                break
            if not entry.name.isdigit():
                continue
            try:
                name = (entry / "comm").read_text(encoding="utf-8", errors="replace").strip()
            except OSError:
                continue
            if name in PACKAGE_MANAGER_NAMES:
                found.append(name)
    except OSError:
        found.append("unknown")
    return sorted(set(found))


def package_missing_immutable_files(package: str, *, runner: Callable) -> List[str]:
    if not SAFE_NAME_RE.fullmatch(package):
        return []
    output = run_bounded_command(runner, ["pacman", "-Qkk", package], max_chars=128000, timeout=120)
    missing = []
    for raw in (output.stdout + "\n" + output.stderr).splitlines():
        match = re.search(r"(?i)missing (?:file|directory):\s*(?:\S+\s+)?(/\S+)", raw)
        if not match:
            match = re.search(r"(?i)^warning:\s+[^:]+:\s+(.+?)\s+\(No such file or directory\)\s*$", raw.strip())
        if not match:
            continue
        path = match.group(1).strip().strip("'\"")
        if path.startswith(MUTABLE_PACKAGE_PATH_PREFIXES):
            continue
        if path.startswith(IMMUTABLE_PACKAGE_PATH_PREFIXES) and path not in missing:
            missing.append(path)
    return missing


def find_exact_cached_package(package: str, version: str, *, cache_root: Path, runner: Callable) -> Optional[Path]:
    try:
        candidates = sorted(
            [path for path in cache_root.glob(f"{package}-*.pkg.tar.*") if not path.name.endswith(".sig")],
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
    except OSError:
        return None
    for candidate in candidates[:30]:
        name, found_version = parse_package_query(command_text(runner, ["pacman", "-Qp", str(candidate)]))
        if name == package and found_version == version:
            return candidate
    return None


def parse_package_owner(text: str) -> str:
    match = re.search(r"\bis owned by\s+([^\s]+)\s+", text)
    return match.group(1) if match else ""


def parse_package_query(text: str) -> Tuple[str, str]:
    line = str(text or "").strip().splitlines()
    if not line:
        return "", ""
    parts = line[0].split(maxsplit=1)
    return (parts[0], parts[1]) if len(parts) == 2 else ("", "")


def query_installed_version(package: str, *, runner: Callable) -> str:
    name, version = parse_package_query(command_text(runner, ["pacman", "-Q", package]))
    return version if name == package else ""


def query_sync_version(package: str, *, runner: Callable) -> str:
    name, version = parse_package_query(command_text(runner, ["pacman", "-Sp", "--print-format", "%n %v", package]))
    return version if name == package else ""


def command_lines(runner: Callable, command: Sequence[str]) -> List[str]:
    output = run_bounded_command(runner, command, max_chars=256000, timeout=120)
    return [line.strip() for line in output.stdout.splitlines() if line.strip()] if output.returncode == 0 else []


def command_text(runner: Callable, command: Sequence[str]) -> str:
    output = run_bounded_command(runner, command, max_chars=64000, timeout=120)
    return output.stdout if output.returncode == 0 else ""


def journal_has_pattern(runner: Callable, target_boot: str, pattern: str) -> bool:
    if not valid_boot_target(target_boot):
        return False
    output = run_bounded_command(
        runner,
        ["journalctl", f"--boot={target_boot}", "--no-pager", "--output=cat", "--priority=0..4", "--lines=2000"],
        max_chars=256000,
        timeout=30,
    )
    return output.returncode == 0 and bool(re.search(pattern, output.stdout))


def rollback_repository_repair(applied_paths: Sequence[str], backup_dir: Path) -> bool:
    ok = True
    for raw_target in reversed(list(applied_paths)):
        target = Path(raw_target)
        backup = backup_dir / target.name
        try:
            if backup.exists():
                shutil.copy2(backup, target)
            elif target.exists():
                target.unlink()
        except OSError:
            ok = False
    return ok


def path_size(path: Path) -> int:
    try:
        return path.stat().st_size if path.is_file() else 0
    except OSError:
        return 0


def is_critical_unit(unit: str) -> bool:
    return any(unit.startswith(prefix) for prefix in CRITICAL_UNIT_PREFIXES) or unit.endswith((".mount", ".socket"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()


def make_run_id() -> str:
    return time.strftime("%Y%m%d-%H%M%S") + f"-{os.getpid()}"


def refused(action: RepairAction, message: str) -> RepairResult:
    return RepairResult(action.action_id, action.recipe_id, "refused", message)


def failed(action: RepairAction, message: str, backup: str = "", output: str = "") -> RepairResult:
    return RepairResult(
        action.action_id,
        action.recipe_id,
        "failed",
        message,
        False,
        backup,
        bool(backup),
        redact_incident_text(output)[:4000],
    )


def applied(action: RepairAction, message: str, backup: str, rollback: bool, output: str = "") -> RepairResult:
    return RepairResult(
        action.action_id,
        action.recipe_id,
        "applied",
        message,
        True,
        backup,
        rollback,
        redact_incident_text(output)[:4000],
    )


def command_output_excerpt(*outputs: object) -> str:
    chunks = []
    for output in outputs:
        stdout = str(getattr(output, "stdout", "") or "")
        stderr = str(getattr(output, "stderr", "") or "")
        text = "\n".join(item.strip() for item in (stdout, stderr) if item.strip())
        if text:
            chunks.append(text)
    return redact_incident_text("\n".join(chunks))[:4000]
