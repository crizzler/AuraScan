import argparse
import curses
import getpass
import importlib.metadata
import json
import os
import platform
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import zipapp
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from aurascan.core.ai_provider import (
    AI_ENABLED_ENV,
    AI_MODEL_ENV,
    AI_PROVIDER_ENV,
    get_provider_spec,
    provider_choices,
    resolve_ai_config,
)
from aurascan.core.recovery import (
    RECOVERY_AI_ENABLED_ENV,
    RECOVERY_AUTO_REFRESH_ENV,
    RECOVERY_POLICY_PATH,
    RECOVERY_RUNTIME_MARKER,
    RECOVERY_STATE_ROOT,
    RECOVERY_TARGET_MOUNT,
    RECOVERY_WIFI_PROFILES_ENV,
    RecoveryConfig,
    RecoveryPolicy,
    RecoveryReport,
    RecoveryTarget,
    activate_recovery_storage_layers,
    apply_recovery_ai_plan,
    discover_recovery_target_candidates,
    find_mounted_recovery_targets,
    inspect_recovery_target,
    load_opted_user_ai_environment,
    mount_recovery_target_read_only,
    read_recovery_policy,
    resolve_recovery_config,
    scan_recovery_target,
    write_recovery_policy,
)
from aurascan.core.recovery_boot import (
    RECOVERY_BACKUP_RELATIVE,
    RECOVERY_GRUB_SCRIPT,
    RECOVERY_LIMINE_BEGIN,
    RECOVERY_LIMINE_END,
    RECOVERY_UKI_RELATIVE,
    BootOperationResult,
    atomic_write,
    backup_file,
    build_uki_command,
    choose_recovery_kernel,
    detect_bootloader,
    detect_secure_boot,
    download_recovery_iso,
    inspect_usb_device,
    install_bootloader_entry,
    load_iso_manifest,
    recovery_image_status,
    sign_recovery_image,
    sbctl_owner_key_ready,
    validate_recovery_image,
    verify_recovery_iso,
    write_iso_to_usb,
)
from aurascan.core.recovery_network import (
    connect_wifi,
    detect_network_state,
    import_saved_wifi_profiles,
    scan_wifi_networks,
    start_network_manager,
)
from aurascan.core.recovery_repairs import execute_recovery_plan, export_recovery_report, save_recovery_report


RECOVERY_PROFILE_PATH = Path("/usr/lib/aurascan/recovery/mkosi.conf")
RECOVERY_ISO_MANIFEST_PATH = Path("/usr/share/aurascan/recovery/iso-manifest.json")
RECOVERY_REFRESH_HOOK = Path("/usr/share/libalpm/hooks/aurascan-recovery-refresh.hook")
RECOVERY_MIN_ESP_FREE = 64 * 1024 * 1024
RECOVERY_REFRESH_DELAY_SECONDS = 30
RECOVERY_REFRESH_UNIT = "aurascan-recovery-refresh"
EXIT_RECOVERY_UNAVAILABLE = 50
EXIT_RECOVERY_DECLINED = 51
EXIT_RECOVERY_FAILED = 52


def _recovery_subprocess_runner(runner: Callable) -> Callable:
    """Keep provider credentials and host session state out of recovery tools."""
    clean_env = {
        "HOME": "/root",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.environ.get(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/bin:/sbin",
        ),
    }
    if os.environ.get("TERM"):
        clean_env["TERM"] = os.environ["TERM"]

    def run(command, **kwargs):
        kwargs["env"] = dict(clean_env)
        return runner(command, **kwargs)

    return run


@dataclass
class RecoveryInstallResult:
    ok: bool
    status: str
    message: str
    details: Dict[str, object]

    def to_dict(self) -> Dict[str, object]:
        return {"ok": self.ok, "status": self.status, "message": self.message, "details": dict(self.details)}


def recovery_version() -> str:
    try:
        return importlib.metadata.version("aurascan")
    except importlib.metadata.PackageNotFoundError:
        return "0.6.0-dev"


def rooted(root: Path, path: Path) -> Path:
    return path if root == Path("/") else root / str(path).lstrip("/")


def source_asset(name: str) -> Path:
    source = Path(__file__).resolve().parents[1] / "assets" / name
    return source if source.is_file() else Path("")


def resolve_recovery_profile(path: Path = RECOVERY_PROFILE_PATH) -> Path:
    if path.is_file():
        return path
    source = source_asset("aurascan-recovery-mkosi.conf")
    return source if source.is_file() else path


def resolve_iso_manifest(path: Path = RECOVERY_ISO_MANIFEST_PATH) -> Path:
    if path.is_file():
        return path
    source = source_asset("aurascan-recovery-iso.json")
    return source if source.is_file() else path


def build_recovery_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aurascan recovery",
        description="Install, inspect, or run the optional AuraScan AI-assisted recovery environment.",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--install", action="store_true", help="build and install the internal recovery UKI and boot entry")
    mode.add_argument("--remove", action="store_true", help="remove the AuraScan-owned internal recovery image and boot entry")
    mode.add_argument("--refresh", action="store_true", help="atomically rebuild an enabled internal recovery image")
    mode.add_argument("--status", action="store_true", help="show recovery image, policy, and bootloader status")
    mode.add_argument("--download-iso", action="store_true", help="download and verify the release recovery USB ISO")
    mode.add_argument("--write-usb", metavar="DEVICE", help="write the verified recovery ISO to an eligible removable whole disk")
    parser.add_argument("--iso", type=Path, help="ISO path for --write-usb or destination for --download-iso")
    parser.add_argument("--dry-run", action="store_true", help="show planned installation or repairs without writing")
    parser.add_argument("--json", action="store_true", dest="json_output", help="emit structured JSON")
    parser.add_argument("--no-ai", action="store_true", help="disable recovery AI for this run")
    parser.add_argument("--facts-only", action="store_true", help="send structured facts but no evidence excerpts to recovery AI")
    parser.add_argument("--yes", action="store_true", help="accept ordinary verified actions; typed destructive confirmations still apply")
    parser.add_argument("--root", type=Path, help=argparse.SUPPRESS)
    parser.add_argument("--opted-uid", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--wifi-profiles", choices=["auto", "ask", "never"], help=argparse.SUPPRESS)
    parser.add_argument("--refresh-policy", choices=["automatic", "manual"], help=argparse.SUPPRESS)
    parser.add_argument("--runtime", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--refresh-from-hook", action="store_true", help=argparse.SUPPRESS)
    return parser


def _policy_path(root: Path) -> Path:
    return rooted(root, RECOVERY_POLICY_PATH)


def _state_root(root: Path) -> Path:
    return rooted(root, RECOVERY_STATE_ROOT)


def _esp_path(root: Path) -> Path:
    candidates = [rooted(root, Path("/boot")), rooted(root, Path("/efi")), rooted(root, Path("/boot/efi"))]
    for candidate in candidates:
        if (candidate / "EFI").exists() or (candidate / "loader").exists() or (candidate / "limine.conf").exists():
            return candidate
    return candidates[0]


def _installation_prerequisites(
    root: Path,
    *,
    esp: Path,
    runner: Callable,
    which: Callable[[str], Optional[str]],
) -> Tuple[bool, List[str], str, str]:
    errors: List[str] = []
    architecture = platform.machine().lower()
    if architecture not in {"x86_64", "amd64"}:
        errors.append("Internal recovery currently supports x86-64 only.")
    if root == Path("/") and not Path("/sys/firmware/efi").exists():
        errors.append("Internal recovery requires a UEFI-booted system; use the hybrid USB ISO for legacy BIOS.")
    try:
        if esp.is_symlink() or not esp.is_dir():
            errors.append("The detected ESP mount path is unavailable or is a symlink.")
    except OSError:
        errors.append("The detected ESP could not be inspected.")
    if root == Path("/") and esp.is_dir() and not esp.is_symlink():
        identity = runner(
            ["findmnt", "--json", "--target", str(esp), "--output", "TARGET,SOURCE,FSTYPE,OPTIONS"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        try:
            payload = json.loads(identity.stdout) if identity.returncode == 0 else {}
            filesystems = payload.get("filesystems", []) if isinstance(payload, Mapping) else []
            mount = filesystems[0] if filesystems and isinstance(filesystems[0], Mapping) else {}
        except ValueError:
            mount = {}
        fstype = str(mount.get("fstype") or "").lower()
        options = str(mount.get("options") or "").split(",")
        if fstype not in {"vfat", "fat", "msdos"}:
            errors.append("The detected ESP is not a dedicated FAT filesystem mount.")
        if "rw" not in options:
            errors.append("The detected ESP is not mounted read-write.")
    bootloader = detect_bootloader(root, esp)
    if not bootloader.installed:
        errors.append("No supported Limine, systemd-boot, or GRUB bootloader was positively detected.")
    kernel, pkgbase = choose_recovery_kernel(rooted(root, Path("/usr/lib/modules")))
    if not kernel:
        errors.append("No installed kernel/module tree is available for the recovery image.")
    if not which("mkosi"):
        errors.append("mkosi is not installed.")
    if not which("ukify"):
        errors.append("ukify is not installed.")
    profile = resolve_recovery_profile()
    if not profile.is_file():
        errors.append("The packaged AuraScan recovery image profile is missing.")
    secure_boot = detect_secure_boot(runner=runner, which=which) if root == Path("/") else "disabled"
    if secure_boot == "enabled" and not which("sbctl"):
        errors.append("Secure Boot is enabled but no sbctl-compatible signing tool is available; use USB recovery or configure an enrolled owner key.")
    elif secure_boot == "enabled":
        signing_ready, signing_message = sbctl_owner_key_ready(runner=runner, which=which)
        if not signing_ready:
            errors.append(signing_message + " Use USB recovery or configure an enrolled owner key.")
    elif secure_boot == "unknown" and root == Path("/"):
        errors.append("Secure Boot state could not be proven; AuraScan will not install a potentially unbootable unsigned recovery entry.")
    return not errors, errors, kernel, pkgbase


def _copy_image_atomic(source: Path, destination: Path, backup: Path) -> Tuple[bool, str, List[str]]:
    changed: List[str] = []
    destination.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    backup.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    try:
        if destination.exists():
            if destination.is_symlink() or not destination.is_file():
                return False, "Existing recovery image is not a regular file.", changed
            shutil.copy2(destination, backup)
            os.chmod(backup, 0o600)
            changed.append(str(backup))
        fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=str(destination.parent))
        try:
            with os.fdopen(fd, "wb") as output, source.open("rb") as input_file:
                shutil.copyfileobj(input_file, output, length=4 * 1024 * 1024)
                output.flush()
                os.fsync(output.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, destination)
            changed.append(str(destination))
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    except OSError as exc:
        return False, f"Recovery image replacement failed: {exc}", changed
    return True, "Recovery image replaced atomically.", changed


def _normalize_mkosi_output(path: Path) -> Tuple[bool, str]:
    """Replace mkosi's versioned artifact symlink with a private regular file."""
    try:
        metadata = path.lstat()
        if stat.S_ISREG(metadata.st_mode):
            os.chmod(path, 0o600)
            return True, ""
        if not stat.S_ISLNK(metadata.st_mode):
            return False, "mkosi output is not a regular file or a versioned artifact symlink."
        parent = path.parent.resolve(strict=True)
        resolved = path.resolve(strict=True)
        resolved.relative_to(parent)
        if not stat.S_ISREG(resolved.lstat().st_mode):
            return False, "mkosi artifact symlink does not resolve to a regular file."
        fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
        try:
            with os.fdopen(fd, "wb") as output, resolved.open("rb") as source:
                shutil.copyfileobj(source, output, length=4 * 1024 * 1024)
                output.flush()
                os.fsync(output.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        return True, ""
    except (OSError, ValueError) as exc:
        return False, f"mkosi output could not be normalized safely: {exc}"


def create_recovery_overlay(destination: Path) -> Path:
    """Create a credential-free zipapp and systemd overlay for the exact installed code."""
    if destination.exists():
        shutil.rmtree(destination)
    app_root = destination / ".zipapp-source"
    package_source = Path(__file__).resolve().parents[1]
    package_target = app_root / "aurascan"
    shutil.copytree(
        package_source,
        package_target,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo", ".env", "*.key", "*.pem"),
    )
    (app_root / "__main__.py").write_text(
        "from aurascan.cli import main\nmain()\n",
        encoding="utf-8",
    )
    executable = destination / "usr/bin/aurascan"
    executable.parent.mkdir(parents=True, mode=0o755, exist_ok=True)
    zipapp.create_archive(app_root, target=executable, interpreter="/usr/bin/python3", compressed=True)
    os.chmod(executable, 0o755)
    shutil.rmtree(app_root)
    service_source = source_asset("aurascan-recovery.service")
    if not service_source.is_file():
        service_source = Path("/usr/lib/systemd/system/aurascan-recovery.service")
    service_target = destination / "usr/lib/systemd/system/aurascan-recovery.service"
    service_target.parent.mkdir(parents=True, mode=0o755, exist_ok=True)
    shutil.copy2(service_source, service_target)
    os.chmod(service_target, 0o644)
    preset = destination / "usr/lib/systemd/system-preset/90-aurascan-recovery.preset"
    preset.parent.mkdir(parents=True, mode=0o755, exist_ok=True)
    preset.write_text("enable aurascan-recovery.service\nenable NetworkManager.service\n", encoding="utf-8")
    os.chmod(preset, 0o644)
    wants = destination / "etc/systemd/system/multi-user.target.wants"
    wants.mkdir(parents=True, mode=0o755, exist_ok=True)
    service_link = wants / "aurascan-recovery.service"
    service_link.symlink_to("/usr/lib/systemd/system/aurascan-recovery.service")
    getty_mask = destination / "etc/systemd/system/getty@tty1.service"
    getty_mask.parent.mkdir(parents=True, mode=0o755, exist_ok=True)
    getty_mask.symlink_to("/dev/null")
    issue = destination / "etc/issue"
    issue.parent.mkdir(parents=True, mode=0o755, exist_ok=True)
    issue.write_text(
        f"AuraScan Recovery {recovery_version()}\nOffline diagnostics start automatically. AI requires recovery consent.\n",
        encoding="utf-8",
    )
    os.chmod(issue, 0o644)
    machine_id = destination / "etc/machine-id"
    machine_id.write_text("", encoding="ascii")
    os.chmod(machine_id, 0o444)
    marker = destination / "etc/aurascan/recovery-environment"
    marker.parent.mkdir(parents=True, mode=0o755, exist_ok=True)
    marker.write_text("1\n", encoding="ascii")
    os.chmod(marker, 0o644)
    return destination


def install_or_refresh_recovery(
    *,
    root: Path = Path("/"),
    refresh: bool = False,
    dry_run: bool = False,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
    opted_uid: Optional[int] = None,
    wifi_profiles: Optional[str] = None,
    refresh_policy: Optional[str] = None,
    recovery_ai_enabled: Optional[bool] = None,
) -> RecoveryInstallResult:
    root = root.resolve()
    policy_path = _policy_path(root)
    policy = read_recovery_policy(policy_path)
    if policy.error:
        return RecoveryInstallResult(False, "config_error", policy.error, {})
    if refresh and not policy.enabled:
        return RecoveryInstallResult(False, "disabled", "Recovery refresh was skipped because internal recovery is disabled.", {})
    if root == Path("/") and os.geteuid() != 0 and not dry_run:
        return RecoveryInstallResult(False, "refused", "Installing internal recovery requires root privileges.", {})
    esp = _esp_path(root)
    ready, errors, kernel, pkgbase = _installation_prerequisites(root, esp=esp, runner=runner, which=which)
    bootloader = detect_bootloader(root, esp)
    profile = resolve_recovery_profile()
    state_root = _state_root(root)
    stage = state_root / "staging" / f"aurascan-recovery-{int(time.time())}.efi"
    overlay = state_root / "staging" / f"overlay-{int(time.time())}-{os.getpid()}"
    if profile.name != "mkosi.conf":
        staged_profile = state_root / "staging/profile/mkosi.conf"
        if not dry_run:
            staged_profile.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            shutil.copy2(profile, staged_profile)
            os.chmod(staged_profile, 0o600)
        profile = staged_profile
    details: Dict[str, object] = {
        "root": str(root),
        "esp": str(esp),
        "kernel_version": kernel,
        "kernel_package": pkgbase,
        "bootloader": bootloader.to_dict(),
        "secure_boot": detect_secure_boot(runner=runner, which=which) if root == Path("/") else "disabled",
        "errors": errors,
    }
    if not ready:
        return RecoveryInstallResult(False, "unavailable", "Internal recovery compatibility checks did not pass.", details)
    if not dry_run:
        try:
            create_recovery_overlay(overlay)
        except OSError as exc:
            return RecoveryInstallResult(False, "overlay_failed", f"Credential-free recovery runtime overlay could not be built: {exc}", details)
    command = build_uki_command(
        stage,
        kernel,
        mkosi=which("mkosi") or "/usr/bin/mkosi",
        profile_path=profile,
        extra_tree=overlay,
    )
    details["build_command"] = command
    if dry_run:
        return RecoveryInstallResult(True, "dry_run", "Recovery image build and boot entry installation are ready.", details)
    stage.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    try:
        result = runner(command, capture_output=True, text=True, timeout=1800, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        stage.unlink(missing_ok=True)
        details["build_error"] = str(exc)[:2000]
        return RecoveryInstallResult(False, "build_failed", "mkosi could not build the recovery image; the previous image was left unchanged.", details)
    finally:
        shutil.rmtree(overlay, ignore_errors=True)
    if result.returncode != 0:
        details["build_error"] = (result.stderr or result.stdout or "")[-2000:]
        return RecoveryInstallResult(False, "build_failed", "mkosi failed; the previous recovery image was left unchanged.", details)
    normalized, normalization_error = _normalize_mkosi_output(stage)
    if not normalized:
        stage.unlink(missing_ok=True)
        details["validation_errors"] = [normalization_error]
        return RecoveryInstallResult(False, "validation_failed", "Staged recovery image failed path validation; the active image was not changed.", details)
    identity_markers = []
    hostname = socket.gethostname().strip()
    if len(hostname) >= 4 and hostname not in {"localhost", "localhost.localdomain", "aurascan-recovery"}:
        identity_markers.append(hostname.encode("utf-8", "replace"))
    username = os.environ.get("SUDO_USER", "").strip() or os.environ.get("USER", "").strip()
    if len(username) >= 4 and username not in {"root", "nobody"}:
        identity_markers.append(username.encode("utf-8", "replace"))
    valid, validation_errors = validate_recovery_image(
        stage,
        runner=runner,
        which=which,
        expected_kernel_version=kernel,
        forbidden_markers=identity_markers,
    )
    if not valid:
        stage.unlink(missing_ok=True)
        details["validation_errors"] = validation_errors
        return RecoveryInstallResult(False, "validation_failed", "Staged recovery image failed validation; the active image was not changed.", details)
    secure_boot = str(details["secure_boot"])
    if secure_boot == "enabled":
        signed = sign_recovery_image(stage, runner=runner, which=which)
        details["signing"] = signed.to_dict()
        if not signed.ok:
            stage.unlink(missing_ok=True)
            return RecoveryInstallResult(False, "signing_failed", signed.message, details)
    try:
        free = shutil.disk_usage(esp).free
        required = stage.stat().st_size + RECOVERY_MIN_ESP_FREE
    except OSError as exc:
        return RecoveryInstallResult(False, "esp_failed", f"ESP space could not be checked: {exc}", details)
    details["esp_free_bytes"] = free
    details["required_bytes"] = required
    if free < required:
        stage.unlink(missing_ok=True)
        return RecoveryInstallResult(False, "no_space", "The ESP does not have enough free space for a staged recovery image and safety margin.", details)
    destination = esp / RECOVERY_UKI_RELATIVE
    backup = esp / RECOVERY_BACKUP_RELATIVE
    copied, copy_message, changed = _copy_image_atomic(stage, destination, backup)
    stage.unlink(missing_ok=True)
    details["changed"] = changed
    if not copied:
        return RecoveryInstallResult(False, "install_failed", copy_message, details)
    valid, installed_errors = validate_recovery_image(
        destination,
        runner=runner,
        which=which,
        expected_kernel_version=kernel,
        forbidden_markers=identity_markers,
    )
    if not valid:
        if backup.is_file():
            shutil.copy2(backup, destination)
        else:
            destination.unlink(missing_ok=True)
        return RecoveryInstallResult(False, "post_validation_failed", "Installed image failed validation; the previous image was restored.", {**details, "validation_errors": installed_errors})
    backup_root = state_root / "boot-config-backups" / str(int(time.time()))
    entry = install_bootloader_entry(bootloader, root=root, esp_path=esp, backup_root=backup_root, runner=runner, which=which)
    details["boot_entry"] = entry.to_dict()
    if not entry.ok:
        if backup.is_file():
            shutil.copy2(backup, destination)
        else:
            destination.unlink(missing_ok=True)
        return RecoveryInstallResult(False, "boot_entry_failed", entry.message + " The previous recovery image was restored.", details)
    version = recovery_version()
    atomic_write(destination.with_suffix(destination.suffix + ".version"), (version + "\n").encode("utf-8"), mode=0o600)
    policy.enabled = True
    policy.bootloader = bootloader.kind
    policy.refresh_policy = refresh_policy or policy.refresh_policy or "automatic"
    if opted_uid is not None:
        policy.opted_in_uid = opted_uid
    if wifi_profiles is not None:
        policy.wifi_profiles = wifi_profiles
    policy.image_version = version
    policy.last_refresh_status = "ok"
    policy.last_refresh_error = ""
    write_recovery_policy(policy, policy_path, require_root=root == Path("/"))
    details["policy"] = policy.to_dict()
    details["recovery_ai_enabled"] = recovery_ai_enabled
    return RecoveryInstallResult(True, "refreshed" if refresh else "installed", f"AuraScan Recovery {version} is ready in {bootloader.name}.", details)


def _strip_limine_entry(text: str) -> str:
    pattern = re.compile(rf"(?ms)^\s*{re.escape(RECOVERY_LIMINE_BEGIN)}.*?^\s*{re.escape(RECOVERY_LIMINE_END)}\s*\n?")
    return pattern.sub("", text).rstrip() + "\n"


def remove_recovery(
    *,
    root: Path = Path("/"),
    dry_run: bool = False,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
) -> RecoveryInstallResult:
    root = root.resolve()
    if root == Path("/") and os.geteuid() != 0 and not dry_run:
        return RecoveryInstallResult(False, "refused", "Removing internal recovery requires root privileges.", {})
    policy_path = _policy_path(root)
    policy = read_recovery_policy(policy_path)
    esp = _esp_path(root)
    bootloader = detect_bootloader(root, esp)
    image = esp / RECOVERY_UKI_RELATIVE
    version_file = image.with_suffix(image.suffix + ".version")
    changed: List[str] = []
    commands: List[List[str]] = []
    if bootloader.kind == "limine":
        config = esp / "limine.conf"
        if config.is_file() and not config.is_symlink():
            old = config.read_text(encoding="utf-8", errors="replace")
            new = _strip_limine_entry(old)
            if old != new:
                changed.append(str(config))
                if not dry_run:
                    backup_file(config, _state_root(root) / "removal-backup")
                    atomic_write(config, new.encode("utf-8"), mode=0o600)
    elif bootloader.kind == "grub":
        script = rooted(root, Path("/") / RECOVERY_GRUB_SCRIPT)
        output = rooted(root, Path("/boot/grub/grub.cfg"))
        grub_mkconfig = which("grub-mkconfig") if root == Path("/") else None
        target_generator = rooted(root, Path("/usr/bin/grub-mkconfig"))
        if root == Path("/") and not grub_mkconfig:
            return RecoveryInstallResult(False, "unavailable", "GRUB removal requires grub-mkconfig so the active menu can be validated.", {})
        if root != Path("/") and (not target_generator.is_file() or target_generator.is_symlink() or not which("arch-chroot")):
            return RecoveryInstallResult(False, "unavailable", "GRUB removal requires the target generator and arch-chroot.", {})
        script_backup = None
        output_backup = None
        if script.is_symlink():
            return RecoveryInstallResult(False, "refused", "GRUB recovery script is a symlink; removal was refused.", {})
        if script.exists():
            changed.append(str(script))
            if not dry_run:
                script_backup = backup_file(script, _state_root(root) / "removal-backup")
                script.unlink()
        if not dry_run:
            if output.is_symlink():
                if script_backup:
                    shutil.copy2(script_backup, script)
                return RecoveryInstallResult(False, "refused", "GRUB configuration is a symlink; removal was rolled back.", {"changed": changed})
            output_backup = backup_file(output, _state_root(root) / "removal-backup")
            command = [grub_mkconfig, "-o", str(rooted(root, Path("/boot/grub/grub.cfg")))] if root == Path("/") else ["arch-chroot", str(root), "grub-mkconfig", "-o", "/boot/grub/grub.cfg"]
            commands.append(command)
            result = runner(command, capture_output=True, text=True, timeout=180, check=False)
            try:
                generated = output.read_text(encoding="utf-8", errors="replace") if output.is_file() and not output.is_symlink() else ""
            except OSError:
                generated = ""
            if result.returncode != 0 or "AuraScan Recovery" in generated or not generated.strip():
                if script_backup:
                    shutil.copy2(script_backup, script)
                if output_backup:
                    shutil.copy2(output_backup, output)
                return RecoveryInstallResult(False, "failed", "GRUB regeneration or validation failed; the previous script and configuration were restored.", {"changed": changed, "commands": commands})
    for path in (image, version_file):
        if path.exists():
            changed.append(str(path))
            if not dry_run:
                if path.is_symlink() or not path.is_file():
                    return RecoveryInstallResult(False, "refused", "AuraScan recovery image path is not a regular file.", {"changed": changed})
                if path == image:
                    backup_file(path, _state_root(root) / "removal-backup")
                path.unlink()
    if not dry_run:
        policy.enabled = False
        policy.last_refresh_status = "removed"
        policy.last_refresh_error = ""
        write_recovery_policy(policy, policy_path, require_root=root == Path("/"))
    return RecoveryInstallResult(True, "dry_run" if dry_run else "removed", "AuraScan-owned internal recovery files and boot entry were removed." if changed else "AuraScan Recovery was already absent.", {"changed": changed, "commands": commands})


def recovery_status(
    *,
    root: Path = Path("/"),
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
) -> Dict[str, object]:
    root = root.resolve()
    policy = read_recovery_policy(_policy_path(root))
    esp = _esp_path(root)
    image = recovery_image_status(root=root, esp_path=esp, expected_version=recovery_version(), runner=runner, which=which)
    install_ready, install_errors, kernel, kernel_package = _installation_prerequisites(
        root,
        esp=esp,
        runner=runner,
        which=which,
    )
    try:
        esp_free = shutil.disk_usage(esp).free
    except OSError:
        esp_free = 0
    profile = resolve_recovery_profile()
    manifest = resolve_iso_manifest()
    last_recovery: Dict[str, object] = {}
    report_root = _state_root(root) / "reports"
    try:
        reports = [path for path in report_root.glob("*.json") if path.is_file() and not path.is_symlink()]
        latest = max(reports[:200], key=lambda path: path.stat().st_mtime) if reports else None
        if latest is not None and latest.stat().st_size <= 2 * 1024 * 1024:
            data = json.loads(latest.read_text(encoding="utf-8", errors="replace"))
            if isinstance(data, Mapping):
                results = data.get("repair_results", []) if isinstance(data.get("repair_results"), list) else []
                last_recovery = {
                    "recovery_id": str(data.get("recovery_id") or "")[:120],
                    "created_at": int(data.get("created_at") or 0),
                    "complete": bool(data.get("complete", False)),
                    "repair_statuses": [str(item.get("status") or "") for item in results if isinstance(item, Mapping)][:50],
                }
    except (OSError, ValueError, TypeError):
        last_recovery = {"error": "Last private recovery result could not be summarized."}
    return {
        "schema": "recovery_status/1.0",
        "supported_architecture": platform.machine().lower() in {"x86_64", "amd64"},
        "uefi_booted": Path("/sys/firmware/efi").exists() if root == Path("/") else True,
        "policy": policy.to_dict(),
        "image": image.to_dict(),
        "installation": {
            "ready": install_ready,
            "errors": install_errors,
            "esp_path": str(esp),
            "esp_free_bytes": esp_free,
            "minimum_esp_free_bytes": RECOVERY_MIN_ESP_FREE,
            "esp_space_ready": esp_free >= RECOVERY_MIN_ESP_FREE,
            "kernel_version": kernel,
            "kernel_package": kernel_package,
            "secure_boot_signing_ready": image.secure_boot != "enabled" or not any(
                "owner key" in item.lower() or "sbctl" in item.lower() for item in install_errors
            ),
        },
        "profile_installed": profile.is_file(),
        "refresh_hook_installed": rooted(root, RECOVERY_REFRESH_HOOK).is_file() if root != Path("/") else RECOVERY_REFRESH_HOOK.is_file(),
        "iso_manifest": load_iso_manifest(manifest),
        "last_recovery": last_recovery,
        "tools": {name: bool(which(name)) for name in ("mkosi", "ukify", "sbctl", "NetworkManager", "nmcli", "iwd", "cryptsetup", "lvm", "mdadm", "snapper", "btrfs", "arch-chroot")},
    }


def _print_status(status: Mapping[str, object], stream) -> None:
    policy = status.get("policy", {})
    image = status.get("image", {})
    print("AuraScan Recovery status", file=stream)
    print(f"Internal recovery: {'enabled' if policy.get('enabled') else 'disabled'}", file=stream)
    print(f"Image: {'installed' if image.get('installed') else 'not installed'} | version: {image.get('version') or 'unknown'} | stale: {'yes' if image.get('stale') else 'no'}", file=stream)
    bootloader = image.get("bootloader", {}) if isinstance(image, Mapping) else {}
    print(f"Bootloader: {bootloader.get('name', 'Unknown')} | Secure Boot: {image.get('secure_boot', 'unknown')}", file=stream)
    print(f"Build profile: {'ready' if status.get('profile_installed') else 'missing'} | refresh hook: {'installed' if status.get('refresh_hook_installed') else 'missing'}", file=stream)
    if policy.get("last_refresh_error"):
        print("Last refresh warning: " + str(policy.get("last_refresh_error")), file=stream)


def _prompt_yes_no(prompt: str, input_func: Callable[[str], str], *, default: bool) -> bool:
    suffix = " [Y/n] " if default else " [y/N] "
    answer = input_func(prompt + suffix).strip().lower()
    if not answer:
        return default
    return answer in {"y", "yes"}


def _progress(message: str, stream) -> None:
    print(f"[AuraScan] {message}...", file=stream, flush=True)


def schedule_recovery_refresh(
    *,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
) -> BootOperationResult:
    systemd_run = which("systemd-run")
    if not systemd_run:
        return BootOperationResult(False, "unavailable", "systemd-run is unavailable; the recovery refresh was not scheduled.")
    command = [
        systemd_run,
        "--quiet",
        "--collect",
        "--no-block",
        f"--on-active={RECOVERY_REFRESH_DELAY_SECONDS}s",
        f"--unit={RECOVERY_REFRESH_UNIT}",
        "--property=Nice=10",
        "--property=IOSchedulingClass=idle",
        "/usr/bin/aurascan",
        "recovery",
        "--refresh",
    ]
    try:
        result = runner(command, capture_output=True, text=True, timeout=15, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return BootOperationResult(False, "failed", f"Recovery refresh scheduling failed: {exc}", command=command)
    if result.returncode != 0:
        return BootOperationResult(False, "failed", "systemd could not schedule the recovery refresh.", command=command)
    return BootOperationResult(
        True,
        "scheduled",
        f"Recovery refresh scheduled {RECOVERY_REFRESH_DELAY_SECONDS} seconds after the package transaction.",
        command=command,
    )


def _offer_report_export(
    report: RecoveryReport,
    save_message: str,
    *,
    input_func: Callable[[str], str],
    stdout,
    runner: Callable,
) -> None:
    if "retained in recovery RAM" not in save_message or not sys.stdin.isatty():
        return
    destination = input_func("Target is read-only. Enter a mounted removable-media directory to export the report, or press Enter to skip: ").strip()
    if not destination:
        return
    _path, message = export_recovery_report(report, Path(destination), runner=runner)
    print(message, file=stdout)


def _in_memory_ai_environment(
    current: Mapping[str, str],
    *,
    input_func: Callable[[str], str],
    getpass_func: Callable[[str], str],
    stdout,
) -> Dict[str, str]:
    result = dict(current)
    result[AI_ENABLED_ENV] = "1"
    configured = resolve_ai_config(result)
    if configured.api_key_present and not configured.error:
        return result
    choices = list(provider_choices())
    print("No validated recovery AI key was found. A session-only key can be used and will not be saved.", file=stdout)
    for index, provider in enumerate(choices, start=1):
        spec = get_provider_spec(provider)
        print(f"{index}. {spec.label if spec else provider}", file=stdout)
    answer = input_func("AI provider (Enter to continue offline): ").strip().lower()
    if not answer:
        return result
    if answer.isdigit() and 1 <= int(answer) <= len(choices):
        provider = choices[int(answer) - 1]
    elif answer in choices:
        provider = answer
    else:
        return result
    spec = get_provider_spec(provider)
    if spec is None:
        return result
    model = input_func(f"Model [{spec.default_model}]: ").strip() or spec.default_model
    key = getpass_func(f"{spec.label} API key for this recovery session (input hidden): ").strip()
    if not key:
        return result
    result.update({
        AI_PROVIDER_ENV: provider,
        AI_MODEL_ENV: model,
        AI_ENABLED_ENV: "1",
        spec.key_env: key,
    })
    return result


def _load_target_recovery_context(
    target: RecoveryTarget,
    base_env: Mapping[str, str],
) -> Tuple[RecoveryPolicy, RecoveryConfig, Dict[str, str], str, bool]:
    policy = read_recovery_policy(_policy_path(Path(target.root_path)))
    combined = dict(base_env)
    note = ""
    user_config_loaded = False
    if not policy.error and policy.opted_in_uid >= 0:
        user_env, note = load_opted_user_ai_environment(Path(target.root_path), policy.opted_in_uid)
        if user_env:
            combined.update(user_env)
            user_config_loaded = True
    config = resolve_recovery_config(combined, policy=policy)
    return policy, config, combined, note, user_config_loaded


def _select_runtime_target(
    *,
    root: Optional[Path],
    input_func: Callable[[str], str],
    getpass_func: Callable[[str], str],
    stdout,
    runner: Callable,
    which: Callable[[str], Optional[str]],
    interactive: bool = True,
) -> Tuple[Optional[RecoveryTarget], str]:
    if root is not None:
        if not rooted(root.resolve(), Path("/etc/os-release")).is_file():
            return None, "The supplied recovery root does not contain /etc/os-release."
        return inspect_recovery_target(root.resolve(), mounted_read_only=False, runner=runner), "Selected explicit recovery root."
    mounted = find_mounted_recovery_targets(runner=runner)
    if mounted:
        if len(mounted) == 1:
            return mounted[0], "Found one mounted Arch-family target."
        if not interactive:
            return None, "Multiple mounted recovery targets require an explicit --root selection."
        print("Mounted recovery targets:", file=stdout)
        for index, item in enumerate(mounted, start=1):
            print(f"{index}. {item.distro.get('name')} at {item.root_path}", file=stdout)
        choice = input_func("Target [1]: ").strip() or "1"
        if choice.isdigit() and 1 <= int(choice) <= len(mounted):
            return mounted[int(choice) - 1], "Selected mounted target."
        return None, "Invalid recovery target selection."
    candidates = discover_recovery_target_candidates(runner=runner, which=which)
    if os.geteuid() == 0:
        activate_recovery_storage_layers(runner=runner, which=which)
        candidates = discover_recovery_target_candidates(runner=runner, which=which)
    if not candidates:
        return None, "No supported mounted or block-device target was found."
    supported = [item for item in candidates if item.supported]
    if not interactive:
        if len(supported) != 1:
            return None, "Recovery target selection is ambiguous; supply an explicit --root path."
        return mount_recovery_target_read_only(supported[0], runner=runner, which=which)
    print("Available storage targets:", file=stdout)
    for index, item in enumerate(candidates, start=1):
        lock = " encrypted" if item.encrypted else ""
        print(f"{index}. {item.device} {item.fstype}{lock} {item.label}", file=stdout)
    choice = input_func("Target [1]: ").strip() or "1"
    if not choice.isdigit() or not 1 <= int(choice) <= len(candidates):
        return None, "Invalid recovery target selection."
    return mount_recovery_target_read_only(
        candidates[int(choice) - 1],
        unlock_secret_func=getpass_func,
        runner=runner,
        which=which,
    )


def _configure_runtime_network(
    target: RecoveryTarget,
    policy: RecoveryPolicy,
    *,
    input_func: Callable[[str], str],
    getpass_func: Callable[[str], str],
    stdout,
    runner: Callable,
    which: Callable[[str], Optional[str]],
    interactive: bool = True,
) -> object:
    start_network_manager(runner=runner, which=which)
    state = detect_network_state(runner=runner, which=which)
    if state.connected and not state.captive_portal:
        return state
    import_profiles = policy.wifi_profiles == "auto"
    if policy.wifi_profiles == "ask" and interactive:
        import_profiles = _prompt_yes_no("Use saved Wi-Fi profiles from the installed system for this recovery session?", input_func, default=True)
    if import_profiles:
        imported, notes = import_saved_wifi_profiles(Path(target.root_path), runner=runner, which=which)
        state.imported_profiles = imported
        state.notes.extend(notes)
        state = detect_network_state(runner=runner, which=which)
        state.imported_profiles = imported
        state.notes.extend(notes)
    if state.connected and not state.captive_portal:
        return state
    networks = scan_wifi_networks(runner=runner, which=which)
    supported = [item for item in networks if item.supported]
    if not interactive:
        state.notes.append("Interactive Wi-Fi selection was skipped for structured recovery output.")
        return state
    if not supported:
        state.notes.append("No supported Wi-Fi network was found; Ethernet, USB tethering, or offline recovery can be used.")
        return state
    print("Wi-Fi networks:", file=stdout)
    for index, item in enumerate(supported[:20], start=1):
        print(f"{index}. {item.ssid} | signal {item.signal}% | {item.security}", file=stdout)
    choice = input_func("Wi-Fi network (Enter to stay offline): ").strip()
    if not choice:
        return state
    if not choice.isdigit() or not 1 <= int(choice) <= min(20, len(supported)):
        state.notes.append("Invalid Wi-Fi selection; continuing offline.")
        return state
    selected = supported[int(choice) - 1]
    ssid = input_func("Hidden Wi-Fi SSID: ").strip() if selected.hidden else selected.ssid
    connected, message = connect_wifi(ssid, hidden=selected.hidden, password_func=getpass_func if selected.security != "open" else None, runner=runner, which=which)
    state.notes.append(message)
    return detect_network_state(runner=runner, which=which) if connected else state


def run_recovery_session(
    *,
    root: Optional[Path],
    dry_run: bool,
    json_output: bool,
    no_ai: bool,
    facts_only: bool,
    yes: bool,
    input_func: Callable[[str], str] = input,
    getpass_func: Callable[[str], str] = getpass.getpass,
    stdout=None,
    stderr=None,
    env: Optional[Mapping[str, str]] = None,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
    urlopen: Optional[Callable] = None,
) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    progress_stream = stderr if json_output else stdout
    _progress("Discovering and validating the installed operating system", progress_stream)
    target, message = _select_runtime_target(
        root=root,
        input_func=input_func,
        getpass_func=getpass_func,
        stdout=stdout,
        runner=runner,
        which=which,
        interactive=not json_output,
    )
    if target is None:
        print(message, file=stderr)
        return EXIT_RECOVERY_UNAVAILABLE
    base_env = dict(os.environ if env is None else env)
    policy, config, ai_env, config_note, user_config_loaded = _load_target_recovery_context(target, base_env)
    if policy.error or config.error:
        print(policy.error or config.error, file=stderr)
        return EXIT_RECOVERY_UNAVAILABLE
    _progress("Running deterministic offline boot and package diagnostics", progress_stream)
    report = scan_recovery_target(target, runner=runner, which=which)
    _progress("Checking Ethernet, USB tethering, and saved Wi-Fi options", progress_stream)
    network = _configure_runtime_network(
        target,
        policy,
        input_func=input_func,
        getpass_func=getpass_func,
        stdout=stdout,
        runner=runner,
        which=which,
        interactive=not json_output,
    )
    report.network = network
    ai_enabled = config.ai_enabled and not no_ai
    if config_note and not user_config_loaded:
        report.notes.append(config_note)
    if not no_ai and not ai_enabled and not user_config_loaded and not json_output:
        ai_enabled = _prompt_yes_no(
            "Use network AI for this recovery session?",
            input_func,
            default=False,
        )
        if ai_enabled:
            ai_env[RECOVERY_AI_ENABLED_ENV] = "1"
    if ai_enabled and network.connected and not network.captive_portal and not json_output:
        ai_env = _in_memory_ai_environment(
            ai_env,
            input_func=input_func,
            getpass_func=getpass_func,
            stdout=stdout,
        )
    apply_recovery_ai_plan(
        report,
        enabled=ai_enabled,
        facts_only=facts_only or config.facts_only,
        env=ai_env,
        runner=runner,
        which=which,
        urlopen=urlopen,
        progress_callback=lambda message: _progress(message, progress_stream),
    )
    report_only = dry_run or (json_output and not yes) or not report.eligible_actions
    if not json_output:
        print(report.render_terminal(verbose=True), file=stdout)
    if report_only:
        _saved_path, save_message = save_recovery_report(report)
        if json_output:
            print(json.dumps(report.to_dict(), indent=2), file=stdout)
        else:
            print(save_message, file=stdout)
            _offer_report_export(report, save_message, input_func=input_func, stdout=stdout, runner=runner)
        return 0
    apply = yes or _prompt_yes_no("Apply the verified recovery plan?", input_func, default=report.apply_prompt_default_yes)
    if not apply:
        save_recovery_report(report)
        print("Recovery plan was not applied.", file=stdout)
        return EXIT_RECOVERY_DECLINED
    typed: Dict[str, str] = {}
    if not json_output:
        for action in report.eligible_actions:
            if not action.confirmation_phrase:
                continue
            answer = input_func(f"Type {action.confirmation_phrase} to allow '{action.title}', or press Enter to skip it: ")
            if answer == action.confirmation_phrase:
                typed[action.action_id] = answer
    results = execute_recovery_plan(
        report,
        typed_confirmations=typed,
        runner=runner,
        progress_callback=lambda message: _progress(message, progress_stream),
    )
    _saved_path, save_message = save_recovery_report(report)
    if json_output:
        print(json.dumps(report.to_dict(), indent=2), file=stdout)
    else:
        print(report.render_terminal(verbose=True), file=stdout)
        print(save_message, file=stdout)
        _offer_report_export(report, save_message, input_func=input_func, stdout=stdout, runner=runner)
        print("AuraScan will not reboot automatically. Review validation above, then reboot when ready.", file=stdout)
    return EXIT_RECOVERY_FAILED if any(item.status in {"failed", "refused", "rolled_back"} for item in results) else 0


class _CursesRecoveryIO:
    def __init__(self, screen) -> None:
        self.screen = screen
        self.lines: List[str] = []
        self.pending = ""
        self.screen.keypad(True)
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        self._render()

    def isatty(self) -> bool:
        return True

    def flush(self) -> None:
        self._render()

    def write(self, value: object) -> int:
        text = str(value).replace("\r", "")
        self.pending += text
        while "\n" in self.pending:
            line, self.pending = self.pending.split("\n", 1)
            self.lines.append(line)
        self.lines = self.lines[-2000:]
        self._render()
        return len(text)

    def _visual_lines(self, width: int) -> List[str]:
        visual: List[str] = []
        for line in [*self.lines, self.pending]:
            wrapped = textwrap.wrap(
                line,
                width=max(8, width - 1),
                replace_whitespace=False,
                drop_whitespace=False,
            )
            visual.extend(wrapped or [""])
        return visual

    def _render(self) -> Tuple[int, int]:
        height, width = self.screen.getmaxyx()
        self.screen.erase()
        title = " AuraScan Recovery | deterministic diagnosis, consented AI, verified repairs "
        try:
            self.screen.addnstr(0, 0, title, max(1, width - 1), curses.A_REVERSE)
        except curses.error:
            pass
        visible = self._visual_lines(width)[-max(1, height - 1):]
        for index, line in enumerate(visible, start=1):
            if index >= height:
                break
            try:
                self.screen.addnstr(index, 0, line, max(1, width - 1))
            except curses.error:
                pass
        row = min(max(1, len(visible)), max(1, height - 1))
        column = min(len(visible[-1]) if visible else 0, max(0, width - 2))
        try:
            self.screen.refresh()
        except curses.error:
            pass
        return row, column

    def _read(self, prompt: str, *, hidden: bool) -> str:
        self.write(prompt + "\n> ")
        row, column = self._render()
        height, width = self.screen.getmaxyx()
        try:
            curses.noecho() if hidden else curses.echo()
            curses.curs_set(1)
            raw = self.screen.getstr(row, column, max(1, width - column - 1))
        finally:
            curses.noecho()
            try:
                curses.curs_set(0)
            except curses.error:
                pass
        answer = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
        self.pending += "[input hidden]" if hidden and answer else answer
        self.write("\n")
        return answer

    def input(self, prompt: str = "") -> str:
        return self._read(prompt, hidden=False)

    def getpass(self, prompt: str = "") -> str:
        return self._read(prompt, hidden=True)


def run_recovery_tui(**kwargs) -> int:
    stdout = kwargs.get("stdout") or sys.stdout
    if not getattr(stdout, "isatty", lambda: False)() or not sys.stdin.isatty():
        return run_recovery_session(**kwargs)

    status: List[int] = []

    def session(screen) -> None:
        interface = _CursesRecoveryIO(screen)
        interface.write("Offline diagnostics start first. Network AI is used only after recovery consent.\n\n")
        session_kwargs = dict(kwargs)
        session_kwargs.update({
            "stdout": interface,
            "stderr": interface,
            "input_func": interface.input,
            "getpass_func": interface.getpass,
        })
        status.append(run_recovery_session(**session_kwargs))
        answer = interface.input("Recovery session finished. Type REBOOT to restart, or press Enter to leave this screen.")
        if answer == "REBOOT":
            runner = kwargs.get("runner", subprocess.run)
            result = runner(["systemctl", "reboot"], capture_output=True, text=True, timeout=30, check=False)
            if result.returncode != 0:
                interface.write("The confirmed reboot request failed. The system was not restarted.\n")
                interface.input("Press Enter to leave this screen.")

    curses.wrapper(session)
    return status[0] if status else EXIT_RECOVERY_FAILED


def run_recovery(
    argv=None,
    *,
    stdout=None,
    stderr=None,
    input_func: Callable[[str], str] = input,
    getpass_func: Callable[[str], str] = getpass.getpass,
    env: Optional[Mapping[str, str]] = None,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
    urlopen: Optional[Callable] = None,
) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    args = build_recovery_parser().parse_args(argv)
    runner = _recovery_subprocess_runner(runner)
    root = args.root.resolve() if args.root else Path("/")
    if args.install or args.refresh or args.refresh_from_hook:
        if args.refresh_from_hook:
            hook_policy = read_recovery_policy(_policy_path(root))
            if not hook_policy.enabled or hook_policy.refresh_policy != "automatic":
                return 0
            if root == Path("/") and os.geteuid() == 0:
                scheduled = schedule_recovery_refresh(runner=runner, which=which)
                hook_policy.last_refresh_status = "scheduled" if scheduled.ok else "warning"
                hook_policy.last_refresh_error = "" if scheduled.ok else scheduled.message
                try:
                    write_recovery_policy(hook_policy, _policy_path(root), require_root=True)
                except OSError:
                    pass
                if not scheduled.ok:
                    print("[AuraScan] Recovery image refresh warning: " + scheduled.message, file=stderr)
                return 0
        result = install_or_refresh_recovery(
            root=root,
            refresh=args.refresh or args.refresh_from_hook,
            dry_run=args.dry_run,
            runner=runner,
            which=which,
            opted_uid=args.opted_uid,
            wifi_profiles=args.wifi_profiles,
            refresh_policy=args.refresh_policy,
        )
        if args.refresh_from_hook and not result.ok:
            policy = read_recovery_policy(_policy_path(root))
            policy.last_refresh_status = "warning"
            policy.last_refresh_error = result.message
            try:
                write_recovery_policy(policy, _policy_path(root), require_root=root == Path("/"))
            except OSError:
                pass
            print("[AuraScan] Recovery image refresh warning: " + result.message, file=stderr)
            return 0
        print(json.dumps(result.to_dict(), indent=2) if args.json_output else result.message, file=stdout if result.ok else stderr)
        return 0 if result.ok else EXIT_RECOVERY_FAILED
    if args.remove:
        result = remove_recovery(root=root, dry_run=args.dry_run, runner=runner, which=which)
        print(json.dumps(result.to_dict(), indent=2) if args.json_output else result.message, file=stdout if result.ok else stderr)
        return 0 if result.ok else EXIT_RECOVERY_FAILED
    if args.download_iso:
        manifest = load_iso_manifest(resolve_iso_manifest())
        version = str(manifest.get("version") or recovery_version())
        destination = args.iso or (Path.home() / "Downloads" / f"AuraScan-Recovery-{version}.iso")
        url = str(manifest.get("url") or "")
        digest = str(manifest.get("sha256") or "").lower()
        if args.dry_run:
            ready = url.startswith("https://github.com/crizzler/AuraScan/releases/download/") and bool(re.fullmatch(r"[0-9a-f]{64}", digest))
            result = BootOperationResult(
                ready,
                "dry_run" if ready else "unavailable",
                f"Would download and SHA-256 verify AuraScan Recovery {version} at {destination}." if ready else "The packaged recovery ISO manifest is not finalized for this release.",
                [str(destination)] if ready else [],
            )
        else:
            result = download_recovery_iso(manifest, destination, urlopen=urlopen or __import__("urllib.request", fromlist=["urlopen"]).urlopen)
        print(json.dumps(result.to_dict(), indent=2) if args.json_output else result.message, file=stdout if result.ok else stderr)
        return 0 if result.ok else EXIT_RECOVERY_FAILED
    if args.write_usb:
        manifest = load_iso_manifest(resolve_iso_manifest())
        version = str(manifest.get("version") or recovery_version())
        iso_path = args.iso or (Path.home() / "Downloads" / f"AuraScan-Recovery-{version}.iso")
        if not iso_path.is_file():
            print(f"Verified recovery ISO was not found at {iso_path}. Run --download-iso first.", file=stderr)
            return EXIT_RECOVERY_UNAVAILABLE
        iso_valid, iso_message, expected_digest = verify_recovery_iso(iso_path, manifest)
        if not iso_valid:
            print(iso_message, file=stderr)
            return EXIT_RECOVERY_UNAVAILABLE
        root_source = ""
        findmnt = runner(["findmnt", "-no", "SOURCE", "/"], capture_output=True, text=True, timeout=10, check=False)
        if findmnt.returncode == 0:
            root_source = findmnt.stdout.strip()
        device = inspect_usb_device(args.write_usb, runner=runner, root_source=root_source)
        if not device.eligible:
            print(device.refusal, file=stderr)
            return EXIT_RECOVERY_UNAVAILABLE
        if args.dry_run:
            result = BootOperationResult(
                True,
                "dry_run",
                f"Verified {iso_path} and eligible removable target {device.path}; no bytes were written.",
                details={"iso": str(iso_path), "sha256": expected_digest, "device": device.to_dict()},
            )
            print(json.dumps(result.to_dict(), indent=2) if args.json_output else result.message, file=stdout)
            return 0
        if args.json_output:
            result = BootOperationResult(
                False,
                "refused",
                "USB writing requires an interactive non-JSON run with exact typed device-path confirmation.",
                details={"device": device.to_dict()},
            )
            print(json.dumps(result.to_dict(), indent=2), file=stdout)
            return EXIT_RECOVERY_DECLINED
        print(f"USB target: {device.path} | {device.model or 'unknown model'} | serial {device.serial or 'unknown'} | {device.size // (1024 ** 3)} GiB", file=stdout)
        confirmation = input_func(f"Type the exact device path {device.path} to erase and write it: ")
        fresh_device = inspect_usb_device(args.write_usb, runner=runner, root_source=root_source)
        if (
            not fresh_device.eligible
            or fresh_device.serial != device.serial
            or fresh_device.model != device.model
            or fresh_device.size != device.size
        ):
            print("USB device identity or eligibility changed after confirmation; the write was refused.", file=stderr)
            return EXIT_RECOVERY_UNAVAILABLE
        result = write_iso_to_usb(
            iso_path,
            fresh_device,
            confirmation=confirmation,
            expected_sha256=expected_digest,
            progress=lambda done, total: print(f"\rWriting and verifying: {done * 100 // max(1, total)}%", end="", file=stdout, flush=True),
        )
        print("", file=stdout)
        print(json.dumps(result.to_dict(), indent=2) if args.json_output else result.message, file=stdout if result.ok else stderr)
        return 0 if result.ok else EXIT_RECOVERY_FAILED
    if args.status:
        status = recovery_status(root=root, runner=runner, which=which)
        if args.json_output:
            print(json.dumps(status, indent=2), file=stdout)
        else:
            _print_status(status, stdout)
        return 0
    in_recovery = args.runtime or RECOVERY_RUNTIME_MARKER.exists()
    if in_recovery or args.root is not None:
        run = run_recovery_tui if in_recovery and args.root is None and not args.json_output else run_recovery_session
        return run(
            root=args.root,
            dry_run=args.dry_run,
            json_output=args.json_output,
            no_ai=args.no_ai,
            facts_only=args.facts_only,
            yes=args.yes,
            input_func=input_func,
            getpass_func=getpass_func,
            stdout=stdout,
            stderr=stderr,
            env=env,
            runner=runner,
            which=which,
            urlopen=urlopen,
        )
    status = recovery_status(root=root, runner=runner, which=which)
    print(json.dumps(status, indent=2) if args.json_output else "", file=stdout, end="" if args.json_output else "")
    if args.json_output:
        print("", file=stdout)
    else:
        _print_status(status, stdout)
        print("Management: --install, --refresh, --remove, --download-iso, or --write-usb DEVICE", file=stdout)
    return 0
