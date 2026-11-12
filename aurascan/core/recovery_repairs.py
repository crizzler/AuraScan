import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from aurascan.core.redaction import redact_incident_text
from aurascan.core.trusted_tools import (
    HOST_TOOL_FIRST_USE_MESSAGE,
    TrustedToolError,
    require_trusted_system_tool,
)
from aurascan.core.recovery import (
    CRITICAL_UNIT_PREFIXES,
    RECOVERY_STATE_ROOT,
    SAFE_NAME_RE,
    SAFE_UNIT_RE,
    RecoveryAction,
    RecoveryRepairResult,
    RecoveryReport,
    inspect_recovery_target,
    recovery_recipe_order,
    rooted,
    scan_recovery_target,
)
from aurascan.core.recovery_boot import bootloader_reinstall_commands


RECOVERY_ALLOWED_RECIPES = {
    "repository_restore",
    "stale_pacman_lock",
    "package_cache_cleanup",
    "complete_pacman_transaction",
    "kernel_module_restore",
    "kernel_headers_install",
    "dkms_autoinstall",
    "boot_config_drift",
    "initramfs_rebuild",
    "disable_boot_service",
    "exact_package_reinstall",
    "snapshot_test_boot",
    "snapshot_restore",
    "bootloader_reinstall",
}
MAX_BACKUP_FILE_SIZE = 1024 * 1024 * 1024
MAX_PACKAGE_ARCHIVE_SIZE = 2 * 1024 * 1024 * 1024
MAX_BOOT_BACKUPS = 100
SNAPSHOT_ID_RE = re.compile(r"0|[1-9][0-9]{0,18}")

# Finding-driven recovery host-tool messages.  ``HOST_TOOL_FIRST_USE_MESSAGE``
# (imported from the trust boundary) may only be reported while no runner
# command and no target-visible mutation has happened in the action; later
# trust failures use the per-site text below.
PACMAN_CONF_TRUST_LATER_MESSAGE = (
    "Package-signature policy queries were interrupted because pacman-conf failed trust "
    "revalidation; the target policy is not proven."
)
FINDMNT_QUERY_TRUST_LATER_MESSAGE = (
    "Mountpoint queries were interrupted because findmnt failed trust revalidation; "
    "the target was not modified."
)
MOUNT_TRUST_LATER_MESSAGE = (
    "Mountpoint queries ran, but mount failed trust revalidation; no remount was attempted "
    "and the target was not modified."
)
MOUNT_TRUST_LATER_REMOUNTED_MESSAGE = (
    "A target mount was remounted writable, but mount failed trust revalidation before a "
    "later remount; the earlier remount was retained."
)
FINDMNT_VERIFY_TRUST_LATER_MESSAGE = (
    "The target mount was remounted writable, but findmnt failed trust revalidation before "
    "verification; writability is unproven and the remount was retained."
)
STALE_LOCK_TRUST_LATER_RESTORED_MESSAGE = (
    "The stale pacman lock was removed, but pacman failed trust revalidation before database "
    "validation; the lock was restored from backup."
)
STALE_LOCK_TRUST_LATER_RETAINED_MESSAGE = (
    "The stale pacman lock was removed, but pacman failed trust revalidation before database "
    "validation; the lock could not be restored and the backup was retained."
)
PACMAN_KEY_TRUST_LATER_MESSAGE = (
    "Package-signature policy queries ran, but arch-chroot failed trust revalidation before "
    "keyring verification; no package transaction was executed."
)
PACMAN_TRANSACTION_TRUST_LATER_MESSAGE = (
    "Package-signature preconditions ran, but the transaction command failed trust "
    "revalidation; no package transaction was executed."
)
INITRAMFS_TRUST_LATER_MESSAGE = (
    "Initramfs images were backed up, but the generator failed trust revalidation; no rebuild "
    "command was executed and the backups were retained."
)
SNAPSHOT_TEST_TRUST_LATER_MESSAGE = (
    "The one-shot snapshot entry was written, but bootctl failed trust revalidation; "
    "the entry was removed again."
)
SNAPSHOT_RESTORE_TRUST_LATER_MESSAGE = (
    "Pre-recovery snapshot {created} was created and retained; snapper failed trust "
    "revalidation and the rollback was not executed."
)
EXPORT_LSBLK_TRUST_LATER_MESSAGE = (
    "The export destination probe was interrupted because lsblk failed trust revalidation; "
    "the report was not exported."
)
# ``_execute_bootloader`` runs a real inspection and takes loader backups before
# its per-command revalidation, so a failure there is never a first use.  When it
# happens before command 1 the target files are untouched; say so without
# claiming any repair progress or inventing backups that were not taken.
BOOTLOADER_TRUST_BEFORE_COMMAND_BACKED_UP_MESSAGE = (
    "{name} was revalidated, but arch-chroot failed trust revalidation before the first "
    "reinstall command; no bootloader file was changed and the backed-up loader files were retained."
)
BOOTLOADER_TRUST_BEFORE_COMMAND_NO_BACKUP_MESSAGE = (
    "{name} was revalidated, but arch-chroot failed trust revalidation before the first "
    "reinstall command; no bootloader file was changed."
)
# A plan can prepare the target (mount queries, a writable remount, recovery
# state) before an executor makes its own fresh capture.  That later capture
# can still fail, and it is then not a first use even though the executor
# itself has not run a command.  ``RepairProgress`` carries that ownership
# across the plan/preparation/executor boundaries so only a genuinely
# zero-progress outcome may carry ``HOST_TOOL_FIRST_USE_MESSAGE``.
PARTIAL_PREPARATION_TRUST_MESSAGE = (
    "Recovery preparation already ran {commands} command(s) and recorded {mutations} "
    "target or recovery-state change step(s); a required host tool then failed trust "
    "revalidation, so this action executed no repair command and nothing was rolled back."
)


class RepairProgress:
    """Ordered ownership of side effects for one recovery plan."""

    def __init__(self) -> None:
        self.commands = 0
        self.remounts = 0
        self.state_created = False

    def command(self) -> None:
        self.commands += 1

    def remount(self) -> None:
        self.remounts += 1

    def created_state(self) -> None:
        self.state_created = True

    @property
    def mutations(self) -> int:
        return self.remounts + (1 if self.state_created else 0)

    @property
    def advanced(self) -> bool:
        return bool(self.commands or self.mutations)


def _validated_snapshot_id(value: object) -> str:
    """Return the canonical snapshot id, or ``""`` when the value is not one.

    Total contract (never raises, never converts untrusted objects):

    - Only exact builtin ``str`` and ``int`` values are accepted
      (``type(value) is str`` / ``type(value) is int``).  ``bool`` is refused
      (``type(True) is bool`` never reaches the int branch), as are all
      subclasses and all other types, without running ``__str__``,
      ``__repr__``, or any other conversion hook.
    - ``int`` inputs must satisfy ``0 <= value < 10**19``; the bound is checked
      before any stringification, so no int-to-str conversion limit can raise.
    - ``str`` inputs must match :data:`SNAPSHOT_ID_RE` exactly (``fullmatch``):
      ``"0"`` or a 1-19 digit ASCII decimal without leading zeros.
    - Zero behaves consistently: ``0`` and ``"0"`` both return ``"0"``.
    - Every other input returns ``""``; the caller refuses.
    """

    if type(value) is int:
        if value < 0 or value >= 10 ** 19:
            return ""
        return str(value)
    if type(value) is str:
        return value if SNAPSHOT_ID_RE.fullmatch(value) else ""
    return ""


def _within(path: Path, root: Path) -> bool:
    try:
        path.resolve(strict=False).relative_to(root.resolve(strict=False))
        return True
    except (OSError, ValueError):
        return False


def _safe_directory_chain(path: Path, root: Path) -> bool:
    root = root.resolve(strict=False)
    try:
        relative = path.absolute().relative_to(root)
    except ValueError:
        return False
    current = root
    for part in relative.parts:
        current = current / part
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            return False
        if current.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
            return False
    return _within(path, root)


def _safe_regular(
    path: Path,
    root: Path,
    *,
    owner_uid: int = 0,
    max_size: int = MAX_BACKUP_FILE_SIZE,
) -> bool:
    if not _within(path, root):
        return False
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISREG(metadata.st_mode)
        and not path.is_symlink()
        and metadata.st_uid == owner_uid
        and metadata.st_size <= max_size
    )


def _trusted_target_binary(path: Path, root: Path) -> bool:
    """Validate a target program before arch-chroot executes it as root.

    Programs handed to ``arch-chroot`` are resolved inside the target and
    would otherwise run the target's own bytes — including a replaced or
    symlinked package manager, keyring helper, initramfs generator, dkms,
    snapper or bootloader installer.  Apply at least the same root-owned,
    non-symlink, size-bounded regular-file discipline that mere data files
    already receive, and require an executable bit.
    """

    if not _safe_regular(path, root, max_size=512 * 1024 * 1024):
        return False
    try:
        return bool(stat.S_IMODE(path.lstat().st_mode) & 0o111)
    except OSError:
        return False


def _trusted_arch_chroot_tools(command: List[str], root: Path) -> bool:
    """Validate the bare-name tool of an ``arch-chroot <root> <tool> …`` recipe."""

    if len(command) < 3 or command[0] != "arch-chroot" or str(command[1]) != str(root):
        return False
    tool = str(command[2])
    if not tool or "/" in tool:
        return False
    return _trusted_target_binary(rooted(root, Path(f"/usr/bin/{tool}")), root)


def _active_servers(path: Path) -> bool:
    try:
        return any(
            line.strip().lower().startswith("server") and not line.lstrip().startswith("#")
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
        )
    except OSError:
        return False


def _sha256_file(path: Path, *, max_size: int = MAX_BACKUP_FILE_SIZE) -> str:
    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(4 * 1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_size:
                    return ""
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()


def _missing_immutable_package_files(output: str) -> List[str]:
    missing: List[str] = []
    for raw in output.splitlines():
        match = re.search(r"(?i)missing (?:file|directory):\s*(?:\S+\s+)?(/\S+)", raw)
        if not match:
            match = re.search(r"(?i)^warning:\s+[^:]+:\s+(.+?)\s+\(No such file or directory\)\s*$", raw.strip())
        if not match:
            continue
        path = match.group(1).strip().strip("'\"")
        if path.startswith(("/usr/", "/opt/")) and path not in missing:
            missing.append(path)
    return missing[:50]


def _atomic_json(path: Path, data: Mapping[str, object]) -> None:
    if path.is_symlink():
        raise OSError("refusing to replace a symlink with private recovery state")
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent), text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _backup_file(path: Path, backup_root: Path, manifest: List[Dict[str, object]]) -> Optional[Path]:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink() or metadata.st_size > MAX_BACKUP_FILE_SIZE:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    digest = hashlib.sha256(data).hexdigest()
    destination = backup_root / "files" / f"{len(manifest) + 1:04d}-{path.name}-{digest[:12]}"
    destination.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".backup.", dir=str(destination.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    manifest.append({
        "source": str(path),
        "backup": str(destination),
        "sha256": digest,
        "mode": oct(stat.S_IMODE(metadata.st_mode)),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "size": metadata.st_size,
    })
    return destination


def _restore_backup_records(
    records: Sequence[Mapping[str, object]],
    *,
    backup_root: Path,
    allowed_roots: Sequence[Path],
) -> bool:
    restored = True
    for record in reversed(records):
        source = Path(str(record.get("source") or ""))
        backup = Path(str(record.get("backup") or ""))
        allowed_root = next(
            (
                root
                for root in allowed_roots
                if _within(source, root) and _safe_directory_chain(source.parent, root)
            ),
            None,
        )
        try:
            metadata = backup.lstat()
            data = backup.read_bytes()
            expected = str(record.get("sha256") or "")
            if (
                allowed_root is None
                or not _within(backup, backup_root)
                or backup.is_symlink()
                or not stat.S_ISREG(metadata.st_mode)
                or hashlib.sha256(data).hexdigest() != expected
            ):
                restored = False
                continue
            mode = int(str(record.get("mode") or "0o600"), 8)
            uid = int(record.get("uid", 0))
            gid = int(record.get("gid", 0))
            fd, temporary = tempfile.mkstemp(prefix=f".{source.name}.restore.", dir=str(source.parent))
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(temporary, mode)
                if os.geteuid() == 0:
                    os.chown(temporary, uid, gid)
                os.replace(temporary, source)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        except (OSError, TypeError, ValueError):
            restored = False
    return restored


def _retained_backup_records(
    records: Sequence[Mapping[str, object]],
    *,
    backup_root: Path,
) -> bool:
    """True only when every record still names a stable, verified backup file.

    ``_restore_backup_records`` returning ``False`` only says that writing the
    destination failed; it does not prove that usable backup bytes remain.
    Availability messages and ``rollback_available`` must be derived from the
    backup bytes re-read and re-hashed now, never from a stale manifest record.
    """

    if not records:
        return False
    for record in records:
        backup = Path(str(record.get("backup") or ""))
        expected = str(record.get("sha256") or "")
        try:
            metadata = backup.lstat()
            size = int(str(record.get("size", -1)))
        except (OSError, TypeError, ValueError):
            return False
        if (
            not expected
            or not _within(backup, backup_root)
            or backup.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size != size
            or _sha256_file(backup) != expected
        ):
            return False
    return True


def _loader_backup_outcome(
    records: Sequence[Mapping[str, object]],
    *,
    backup_root: Path,
    restored: bool,
) -> Tuple[str, bool, str]:
    """Truthful restore suffix, rollback availability and backup path."""

    if restored:
        return "backed-up loader files were restored.", True, str(backup_root)
    if _retained_backup_records(records, backup_root=backup_root):
        return (
            "the destination restore failed, but the backed-up loader bytes were verified and retained.",
            True,
            str(backup_root),
        )
    return "no verified loader backup remains, so a rollback is not available.", False, ""


def _run(
    runner: Callable,
    command: Sequence[str],
    *,
    timeout: int = 600,
    redact: bool = True,
) -> Tuple[int, str]:
    try:
        result = runner(list(command), capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, redact_incident_text(str(exc))[:4000]
    output = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
    rendered = redact_incident_text(output) if redact else output
    return result.returncode, rendered[:4000]


def _package_manager_running(runner: Callable) -> bool:
    try:
        ps = require_trusted_system_tool("ps")
    except TrustedToolError:
        return True
    code, output = _run(runner, [ps.path, "-eo", "comm="], timeout=15)
    if code != 0:
        return True
    package_managers = {"pacman", "paru", "yay", "shelly", "pamac", "packagekitd", "makepkg"}
    return any(line.strip() in package_managers for line in output.splitlines())


def _signature_policy_is_strict(output: str) -> bool:
    tokens = {item.strip().lower() for item in output.splitlines() if item.strip()}
    unsafe = {"packagenever", "packageoptional", "packagetrustall", "never", "optional", "trustall"}
    required = bool(tokens & {"packagerequired", "required"})
    trusted = bool(tokens & {"packagetrustedonly", "trustedonly"})
    return required and trusted and not bool(tokens & unsafe)


def _pacman_transaction_preconditions(root: Path, runner: Callable) -> Tuple[bool, str]:
    base = [f"--sysroot={root}"]

    def query(*arguments: str, timeout: int = 30) -> Tuple[int, str]:
        tool = require_trusted_system_tool("pacman-conf")
        return _run(runner, [tool.path, *base, *arguments], timeout=timeout)

    try:
        require_trusted_system_tool("pacman-conf")
    except TrustedToolError:
        return False, HOST_TOOL_FIRST_USE_MESSAGE
    completed_queries = 0
    try:
        code, global_policy = query("SigLevel")
        completed_queries += 1
        if code != 0 or not _signature_policy_is_strict(global_policy):
            return False, "The target does not prove a required, trusted package-signature policy."
        code, repo_output = query("--repo-list")
        completed_queries += 1
        repositories = [line.strip() for line in repo_output.splitlines() if SAFE_NAME_RE.fullmatch(line.strip())]
        if code != 0 or not repositories or len(repositories) > 50:
            return False, "Configured target repositories could not be bounded and validated."
        for repository in repositories:
            code, servers = query(f"--repo={repository}", "Server")
            completed_queries += 1
            if code != 0 or not any(line.strip() for line in servers.splitlines()):
                return False, f"Repository {repository} has no validated package server."
            code, override = query(f"--repo={repository}", "SigLevel")
            completed_queries += 1
            if code != 0:
                return False, f"Repository {repository} signature policy could not be queried."
            if override.strip() and not _signature_policy_is_strict(override):
                return False, f"Repository {repository} overrides the required trusted-signature policy."
    except TrustedToolError:
        # A capture failure before the first query completes is still a first
        # use: no command has run and nothing was changed.
        if completed_queries == 0:
            return False, HOST_TOOL_FIRST_USE_MESSAGE
        return False, PACMAN_CONF_TRUST_LATER_MESSAGE
    return True, "Target package signatures and repositories passed validation."


def _prepare_write_target(
    report: RecoveryReport,
    runner: Callable,
    *,
    required_tools: Sequence[str] = (),
    progress: Optional[RepairProgress] = None,
) -> Tuple[bool, str]:
    root = Path(report.target.root_path)
    if root == Path("/"):
        return False, "AuraScan refuses recovery repair against the running recovery environment itself."
    if os.geteuid() != 0:
        return False, "Recovery repairs require root privileges."
    # Caller-owned actions must be preflighted before the first preparation
    # mutation (remount or recovery-state creation) so that a first-use refusal
    # in the executor can never be reported after progress.
    if required_tools:
        try:
            for name in required_tools:
                require_trusted_system_tool(name)
        except TrustedToolError:
            return False, HOST_TOOL_FIRST_USE_MESSAGE
    if report.target.mounted_read_only:
        requested_paths = [root]
        esp = Path(report.target.esp_path)
        if esp != root and _within(esp, root):
            requested_paths.append(esp)
        try:
            require_trusted_system_tool("findmnt")
            require_trusted_system_tool("mount")
        except TrustedToolError:
            return False, HOST_TOOL_FIRST_USE_MESSAGE
        mountpoints: Dict[str, Tuple[Path, set]] = {}
        completed_queries = 0
        try:
            for requested in requested_paths:
                findmnt = require_trusted_system_tool("findmnt")
                code, output = _run(
                    runner,
                    [findmnt.path, "--noheadings", "--output", "TARGET,OPTIONS", "--target", str(requested)],
                    timeout=15,
                    redact=False,
                )
                completed_queries += 1
                fields = output.splitlines()[0].split(None, 1) if code == 0 and output.splitlines() else []
                if len(fields) != 2:
                    return False, f"The mountpoint containing {requested} could not be proven."
                mountpoint = Path(fields[0]).resolve(strict=False)
                options = {item.strip() for item in fields[1].split(",") if item.strip()}
                if mountpoint == Path("/") or not _within(requested, mountpoint):
                    return False, f"The mountpoint containing {requested} failed path validation."
                mountpoints[str(mountpoint)] = (mountpoint, options)
        except TrustedToolError:
            if completed_queries == 0:
                return False, HOST_TOOL_FIRST_USE_MESSAGE
            return False, FINDMNT_QUERY_TRUST_LATER_MESSAGE
        remounted = 0
        for mountpoint, options in mountpoints.values():
            if "rw" in options and "ro" not in options:
                continue
            try:
                mount = require_trusted_system_tool("mount")
            except TrustedToolError:
                return False, MOUNT_TRUST_LATER_REMOUNTED_MESSAGE if remounted else MOUNT_TRUST_LATER_MESSAGE
            code, output = _run(runner, [mount.path, "-o", "remount,rw", str(mountpoint)], timeout=60)
            if code != 0:
                return False, f"The target mount {mountpoint} could not be remounted writable: " + output[:500]
            remounted += 1
            if progress is not None:
                progress.remount()
            try:
                findmnt = require_trusted_system_tool("findmnt")
            except TrustedToolError:
                return False, FINDMNT_VERIFY_TRUST_LATER_MESSAGE
            code, verify = _run(
                runner,
                [findmnt.path, "--noheadings", "--output", "OPTIONS", "--target", str(mountpoint)],
                timeout=15,
                redact=False,
            )
            verified_options = {item.strip() for item in verify.splitlines()[0].split(",")} if code == 0 and verify.splitlines() else set()
            if "rw" not in verified_options or "ro" in verified_options:
                return False, f"The target mount {mountpoint} did not verify as writable after remount."
        report.target.mounted_read_only = False
        report.target.writable = True
    return True, "Target is writable."


def _unit_still_failed(root: Path, unit: str, runner: Callable) -> bool:
    journal_root = root / "var/log/journal"
    if not journal_root.is_dir() or journal_root.is_symlink():
        return False
    try:
        journalctl = require_trusted_system_tool("journalctl")
    except TrustedToolError:
        return False
    code, output = _run(
        runner,
        [journalctl.path, f"--directory={journal_root}", "--boot=0", "--priority=0..3", "--no-pager", "--lines=2000", "_COMM=systemd", "_PID=1"],
        timeout=45,
    )
    if code not in {0, 1}:
        return False
    return any(
        unit in line and re.search(r"(?i)failed to start|dependency failed|start operation timed out|job .* failed", line)
        for line in output.splitlines()
    )


def _fresh_action(report: RecoveryReport, action: RecoveryAction, runner: Callable) -> Optional[RecoveryAction]:
    target = inspect_recovery_target(
        Path(report.target.root_path),
        source=report.target.source,
        mounted_read_only=report.target.mounted_read_only,
        encrypted=report.target.encrypted,
        storage_layers=report.target.storage_layers,
        runner=runner,
    )
    fresh = scan_recovery_target(target, runner=runner)
    matches = [item for item in fresh.eligible_actions if item.recipe_id == action.recipe_id]
    if not matches and action.recipe_id == "kernel_headers_install":
        packages = action.parameters.get("packages", [])
        if isinstance(packages, list) and packages and all(
            SAFE_NAME_RE.fullmatch(str(item)) and str(item).endswith("-headers") and str(item) not in target.installed_packages
            for item in packages
        ) and any(name.endswith("-dkms") for name in target.installed_packages):
            return action
    if not matches and action.recipe_id == "dkms_autoinstall":
        has_headers = all(f"{kernel}-headers" in target.installed_packages for kernel in target.installed_kernels)
        if has_headers and any(name.endswith("-dkms") for name in target.installed_packages) and _trusted_target_binary(Path(target.root_path) / "usr/bin/dkms", Path(target.root_path)):
            return action
    if not matches and action.recipe_id == "disable_boot_service":
        unit = str(action.parameters.get("unit") or "")
        unit_paths = [
            Path(target.root_path) / "usr/lib/systemd/system" / unit,
            Path(target.root_path) / "etc/systemd/system" / unit,
        ]
        try:
            require_trusted_system_tool("journalctl")
        except TrustedToolError:
            return None
        if (
            SAFE_UNIT_RE.fullmatch(unit)
            and not unit.startswith(CRITICAL_UNIT_PREFIXES)
            and any(path.is_file() and not path.is_symlink() for path in unit_paths)
            and _unit_still_failed(Path(target.root_path), unit, runner)
        ):
            return action
    if not matches and action.recipe_id == "exact_package_reinstall":
        package = str(action.parameters.get("package") or "")
        version = str(action.parameters.get("version") or "")
        archive = Path(str(action.parameters.get("archive") or ""))
        cache = Path(target.root_path) / "var/cache/pacman/pkg"
        signature = Path(str(archive) + ".sig")
        expected_digest = str(action.parameters.get("archive_sha256") or "")
        if not _trusted_target_binary(rooted(Path(target.root_path), Path("/usr/bin/pacman")), Path(target.root_path)):
            return None
        try:
            arch_chroot = require_trusted_system_tool("arch-chroot")
        except TrustedToolError:
            return None
        foreign_code, _foreign = _run(runner, [arch_chroot.path, target.root_path, "pacman", "-Qm", package], timeout=30)
        try:
            arch_chroot = require_trusted_system_tool("arch-chroot")
        except TrustedToolError:
            return None
        integrity_code, integrity = _run(runner, [arch_chroot.path, target.root_path, "pacman", "-Qkk", package], timeout=120)
        if (
            SAFE_NAME_RE.fullmatch(package)
            and target.installed_packages.get(package) == version
            and re.fullmatch(r"[0-9a-f]{64}", expected_digest)
            and foreign_code != 0
            and integrity_code in {0, 1}
            and _missing_immutable_package_files(integrity)
            and _safe_regular(archive, cache, max_size=MAX_PACKAGE_ARCHIVE_SIZE)
            and _safe_regular(signature, cache)
            and _sha256_file(archive, max_size=MAX_PACKAGE_ARCHIVE_SIZE) == expected_digest
        ):
            return action
    if not matches:
        return None
    if action.recipe_id in {"snapshot_restore", "snapshot_test_boot"}:
        wanted = str(action.parameters.get("snapshot_id") or "")
        return next((item for item in matches if str(item.parameters.get("snapshot_id") or "") == wanted), None)
    return matches[0]


def _execute_repository_restore(
    report: RecoveryReport,
    action: RecoveryAction,
    backup_root: Path,
    backups: List[Dict[str, object]],
) -> RecoveryRepairResult:
    root = Path(report.target.root_path)
    pairs = action.parameters.get("pairs", [])
    if not isinstance(pairs, list) or not pairs:
        return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", "No validated repository replacement pair remains.")
    staged: List[Tuple[Path, Path, Path]] = []
    backup_start = len(backups)
    for pair in pairs[:20]:
        if not isinstance(pair, Mapping):
            return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", "Repository repair parameters are malformed.")
        target = Path(str(pair.get("target") or ""))
        source = Path(str(pair.get("backup") or ""))
        allowed = root / "etc/pacman.d"
        if not _within(target, allowed) or not _within(source, allowed):
            return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", "Repository repair escaped /etc/pacman.d.")
        if not _safe_regular(source, root) or not _active_servers(source) or _active_servers(target):
            return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", "Repository backup or inactive-target validation changed.")
        if target.exists() and not _safe_regular(target, allowed):
            return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", "Inactive repository target is not a root-owned regular file.")
        backup = _backup_file(target, backup_root, backups) if target.exists() else None
        if target.exists() and backup is None:
            return RecoveryRepairResult(action.action_id, action.recipe_id, "failed", "Current repository configuration could not be backed up.")
        staged.append((target, source, backup or Path("")))
    applied: List[Tuple[Path, Path]] = []
    try:
        for target, source, backup in staged:
            data = source.read_bytes()
            fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=str(target.parent))
            try:
                with os.fdopen(fd, "wb") as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(temporary, 0o644)
                os.replace(temporary, target)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
            applied.append((target, backup))
        if not all(_active_servers(target) for target, _backup in applied):
            raise OSError("restored repository configuration did not pass active-server validation")
    except OSError as exc:
        rollback_ok = _restore_backup_records(
            backups[backup_start:],
            backup_root=backup_root,
            allowed_roots=[root / "etc/pacman.d"],
        )
        for target, backup in reversed(applied):
            if backup:
                continue
            try:
                target.unlink(missing_ok=True)
            except OSError:
                rollback_ok = False
        status = "rolled_back" if rollback_ok else "failed"
        return RecoveryRepairResult(action.action_id, action.recipe_id, status, f"Repository restoration failed and {'was rolled back' if rollback_ok else 'could not be fully rolled back'}: {redact_incident_text(str(exc))[:300]}", False, str(backup_root), not rollback_ok and bool(applied))
    return RecoveryRepairResult(action.action_id, action.recipe_id, "applied", "Validated repository mirror configuration was restored.", True, str(backup_root), True)


def _execute_stale_lock(
    report: RecoveryReport,
    action: RecoveryAction,
    backup_root: Path,
    backups: List[Dict[str, object]],
    runner: Callable,
) -> RecoveryRepairResult:
    lock = Path(str(action.parameters.get("lock_path") or ""))
    root = Path(report.target.root_path)
    if not _within(lock, root / "var/lib/pacman") or lock.name != "db.lck" or lock.is_symlink():
        return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", "Pacman lock path validation failed.")
    try:
        require_trusted_system_tool("ps")
        require_trusted_system_tool("pacman")
    except TrustedToolError:
        return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", HOST_TOOL_FIRST_USE_MESSAGE)
    if _package_manager_running(runner):
        return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", "A package manager is running in the recovery environment.")
    try:
        age = int(time.time() - lock.stat().st_mtime)
    except OSError:
        return RecoveryRepairResult(action.action_id, action.recipe_id, "no_action", "The pacman lock no longer exists.", True)
    if age < 600:
        return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", "The pacman lock is not old enough to prove it is stale.")
    backup = _backup_file(lock, backup_root, backups)
    if backup is None:
        return RecoveryRepairResult(action.action_id, action.recipe_id, "failed", "The pacman lock could not be backed up.")
    lock.unlink()
    dbpath = root / "var/lib/pacman"
    try:
        pacman = require_trusted_system_tool("pacman")
    except TrustedToolError:
        try:
            shutil.copy2(backup, lock)
        except OSError:
            return RecoveryRepairResult(
                action.action_id,
                action.recipe_id,
                "failed",
                STALE_LOCK_TRUST_LATER_RETAINED_MESSAGE,
                False,
                str(backup),
                True,
            )
        return RecoveryRepairResult(
            action.action_id,
            action.recipe_id,
            "rolled_back",
            STALE_LOCK_TRUST_LATER_RESTORED_MESSAGE,
            False,
            str(backup),
            False,
        )
    code, output = _run(runner, [pacman.path, "--root", str(root), "--dbpath", str(dbpath), "-Dk"], timeout=60)
    if code != 0:
        shutil.copy2(backup, lock)
        return RecoveryRepairResult(action.action_id, action.recipe_id, "rolled_back", "Package database validation failed; the lock was restored.", False, str(backup), False, output)
    return RecoveryRepairResult(action.action_id, action.recipe_id, "applied", "The stale pacman lock was moved and the package database passed validation.", True, str(backup), True, output)


def _execute_cache_cleanup(report: RecoveryReport, action: RecoveryAction, runner: Callable) -> RecoveryRepairResult:
    cache = Path(str(action.parameters.get("cache_root") or ""))
    root = Path(report.target.root_path)
    if not _within(cache, root / "var/cache/pacman") or cache.name != "pkg":
        return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", "Package cache path validation failed.")
    try:
        paccache = require_trusted_system_tool("paccache")
    except TrustedToolError:
        return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", HOST_TOOL_FIRST_USE_MESSAGE)
    code, output = _run(runner, [paccache.path, "-r", "-k", "2", "-c", str(cache)], timeout=300)
    return RecoveryRepairResult(action.action_id, action.recipe_id, "applied" if code == 0 else "failed", "Bounded package-cache cleanup completed." if code == 0 else "Package-cache cleanup failed.", code == 0, output_excerpt=output)


def _execute_pacman_action(report: RecoveryReport, action: RecoveryAction, runner: Callable) -> RecoveryRepairResult:
    root = Path(report.target.root_path)
    try:
        require_trusted_system_tool("pacman-conf")
        require_trusted_system_tool("arch-chroot")
    except TrustedToolError:
        return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", HOST_TOOL_FIRST_USE_MESSAGE)
    ready, reason = _pacman_transaction_preconditions(root, runner)
    if not ready:
        return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", reason)
    if not _trusted_target_binary(rooted(root, Path("/usr/bin/pacman")), root):
        return RecoveryRepairResult(
            action.action_id,
            action.recipe_id,
            "refused",
            "The target package manager is not a root-owned non-symlink executable; refusing to execute it as recovery root.",
        )
    if action.recipe_id == "complete_pacman_transaction":
        if not report.network.connected or report.network.captive_portal:
            return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", "A full non-captive network connection is required for the repository transaction.")
        command = ["arch-chroot", str(root), "pacman", "-Syu", "--noconfirm"]
    elif action.recipe_id in {"kernel_module_restore", "kernel_headers_install"}:
        packages = action.parameters.get("packages", [])
        if not isinstance(packages, list) or not packages or not all(SAFE_NAME_RE.fullmatch(str(item)) for item in packages):
            return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", "Kernel package target validation failed.")
        if not report.network.connected or report.network.captive_portal:
            return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", "A usable network connection is required for kernel package restoration.")
        command = ["arch-chroot", str(root), "pacman", "-S", "--needed", "--noconfirm", *map(str, packages)]
    elif action.recipe_id == "exact_package_reinstall":
        archive = Path(str(action.parameters.get("archive") or ""))
        cache = root / "var/cache/pacman/pkg"
        signature = Path(str(archive) + ".sig")
        if not _safe_regular(archive, cache, max_size=MAX_PACKAGE_ARCHIVE_SIZE) or not _safe_regular(signature, cache):
            return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", "Exact signed cached package validation failed.")
        expected_digest = str(action.parameters.get("archive_sha256") or "")
        if not re.fullmatch(r"[0-9a-f]{64}", expected_digest) or _sha256_file(archive, max_size=MAX_PACKAGE_ARCHIVE_SIZE) != expected_digest:
            return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", "Exact cached package checksum validation failed.")
        try:
            target_archive = "/" + str(archive.resolve().relative_to(root.resolve()))
            target_signature = "/" + str(signature.resolve().relative_to(root.resolve()))
        except (OSError, ValueError):
            return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", "Cached package path escaped the recovery target.")
        if not _trusted_target_binary(rooted(root, Path("/usr/bin/pacman-key")), root):
            return RecoveryRepairResult(
                action.action_id,
                action.recipe_id,
                "refused",
                "The target keyring helper is not a root-owned non-symlink executable; refusing to execute it as recovery root.",
            )
        try:
            arch_chroot = require_trusted_system_tool("arch-chroot")
        except TrustedToolError:
            return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", PACMAN_KEY_TRUST_LATER_MESSAGE)
        verify_code, verify_output = _run(
            runner,
            [arch_chroot.path, str(root), "pacman-key", "--verify", target_signature, target_archive],
            timeout=60,
        )
        if verify_code != 0:
            return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", "The exact cached package failed fresh target-keyring signature verification.", output_excerpt=verify_output)
        command = ["arch-chroot", str(root), "pacman", "-U", "--noconfirm", target_archive]
    else:
        return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", "Unsupported package repair recipe.")
    try:
        arch_chroot = require_trusted_system_tool("arch-chroot")
    except TrustedToolError:
        return RecoveryRepairResult(action.action_id, action.recipe_id, "failed", PACMAN_TRANSACTION_TRUST_LATER_MESSAGE)
    code, output = _run(runner, [arch_chroot.path, *command[1:]], timeout=1800)
    return RecoveryRepairResult(action.action_id, action.recipe_id, "applied" if code == 0 else "failed", "Package recovery transaction completed." if code == 0 else "Package recovery transaction failed.", code == 0, output_excerpt=output)


def _execute_initramfs(
    report: RecoveryReport,
    action: RecoveryAction,
    backup_root: Path,
    backups: List[Dict[str, object]],
    runner: Callable,
) -> RecoveryRepairResult:
    root = Path(report.target.root_path)
    generator = str(action.parameters.get("generator") or "")
    if generator not in {"mkinitcpio", "dracut"} or not _trusted_target_binary(rooted(root, Path(f"/usr/bin/{generator}")), root):
        return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", "Installed initramfs generator validation failed.")
    try:
        require_trusted_system_tool("arch-chroot")
    except TrustedToolError:
        return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", HOST_TOOL_FIRST_USE_MESSAGE)
    boot = rooted(root, Path("/boot"))
    try:
        if shutil.disk_usage(boot).free < 256 * 1024 * 1024:
            return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", "Boot filesystem has less than 256 MiB free.")
    except OSError:
        return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", "Boot filesystem space could not be checked.")
    images = [
        path
        for path in boot.glob("initramfs*.img")
        if path.is_file() and not path.is_symlink() and _within(path, boot)
    ][:MAX_BOOT_BACKUPS]
    original_names = {path.name for path in images}
    backup_start = len(backups)
    for image in images:
        if _backup_file(image, backup_root, backups) is None:
            return RecoveryRepairResult(action.action_id, action.recipe_id, "failed", f"Could not back up {image.name}.")
    command = ["arch-chroot", str(root), "mkinitcpio", "-P"] if generator == "mkinitcpio" else ["arch-chroot", str(root), "dracut", "--regenerate-all", "--force"]
    try:
        arch_chroot = require_trusted_system_tool("arch-chroot")
    except TrustedToolError:
        if not backups[backup_start:]:
            # No image existed to back up and no command ran: this is still a
            # truthful first-use refusal, not a retained-backup failure.
            return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", HOST_TOOL_FIRST_USE_MESSAGE)
        return RecoveryRepairResult(
            action.action_id,
            action.recipe_id,
            "failed",
            INITRAMFS_TRUST_LATER_MESSAGE,
            False,
            str(backup_root),
            True,
        )
    code, output = _run(runner, [arch_chroot.path, *command[1:]], timeout=900)
    if code != 0:
        cleanup_ok = True
        for path in list(boot.glob("initramfs*.img"))[:MAX_BOOT_BACKUPS * 2]:
            if path.name in original_names:
                continue
            try:
                if path.is_symlink() or not path.is_file() or not _within(path, boot):
                    cleanup_ok = False
                    continue
                path.unlink()
            except OSError:
                cleanup_ok = False
        rollback_ok = cleanup_ok and _restore_backup_records(
            backups[backup_start:],
            backup_root=backup_root,
            allowed_roots=[boot],
        )
        if rollback_ok:
            return RecoveryRepairResult(action.action_id, action.recipe_id, "rolled_back", "Initramfs rebuild failed; previous images were restored.", False, str(backup_root), False, output)
        return RecoveryRepairResult(action.action_id, action.recipe_id, "failed", "Initramfs rebuild failed and the previous image set could not be fully restored.", False, str(backup_root), bool(images), output)
    return RecoveryRepairResult(action.action_id, action.recipe_id, "applied", "Initramfs images were rebuilt.", True, str(backup_root), bool(images), output)


def _execute_config_drift(report: RecoveryReport, action: RecoveryAction, runner: Callable) -> RecoveryRepairResult:
    root = Path(report.target.root_path)
    try:
        aurascan = require_trusted_system_tool("aurascan")
    except TrustedToolError:
        return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", HOST_TOOL_FIRST_USE_MESSAGE)
    code, output = _run(runner, [aurascan.path, "config-drift", "--root", str(root), "--yes", "--no-ai"], timeout=600)
    return RecoveryRepairResult(action.action_id, action.recipe_id, "applied" if code == 0 else "failed", "Boot-critical config drift assistant completed." if code == 0 else "Boot-critical config drift assistant did not complete.", code == 0, output_excerpt=output)


def _execute_dkms(report: RecoveryReport, action: RecoveryAction, runner: Callable) -> RecoveryRepairResult:
    root = Path(report.target.root_path)
    headers = list((root / "usr/lib/modules").glob("*/build"))
    if not headers or not _trusted_target_binary(rooted(root, Path("/usr/bin/dkms")), root):
        return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", "DKMS or matching kernel headers are unavailable.")
    try:
        arch_chroot = require_trusted_system_tool("arch-chroot")
    except TrustedToolError:
        return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", HOST_TOOL_FIRST_USE_MESSAGE)
    code, output = _run(runner, [arch_chroot.path, str(root), "dkms", "autoinstall"], timeout=1200)
    return RecoveryRepairResult(action.action_id, action.recipe_id, "applied" if code == 0 else "failed", "DKMS modules were rebuilt." if code == 0 else "DKMS autoinstall failed.", code == 0, output_excerpt=output)


def _execute_disable_service(report: RecoveryReport, action: RecoveryAction, runner: Callable) -> RecoveryRepairResult:
    root = Path(report.target.root_path)
    unit = str(action.parameters.get("unit") or "")
    if not SAFE_UNIT_RE.fullmatch(unit) or unit.startswith(CRITICAL_UNIT_PREFIXES):
        return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", "Service is invalid or belongs to the critical denylist.")
    try:
        systemctl = require_trusted_system_tool("systemctl")
    except TrustedToolError:
        return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", HOST_TOOL_FIRST_USE_MESSAGE)
    code, output = _run(runner, [systemctl.path, f"--root={root}", "disable", unit], timeout=60)
    return RecoveryRepairResult(action.action_id, action.recipe_id, "applied" if code == 0 else "failed", f"Disabled proven noncritical boot-blocking service {unit}." if code == 0 else "Service disable failed.", code == 0, output_excerpt=output)


def _execute_snapshot_test(report: RecoveryReport, action: RecoveryAction, runner: Callable) -> RecoveryRepairResult:
    root = Path(report.target.root_path)
    snapshot_id = _validated_snapshot_id(action.parameters.get("snapshot_id"))
    if not snapshot_id or not (root / f".snapshots/{snapshot_id}/snapshot").is_dir():
        return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", "Snapshot validation failed.")
    if report.target.bootloader.kind != "systemd-boot":
        return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", "Automatic one-shot snapshot boot is currently available only for positively detected systemd-boot targets.")
    esp = Path(report.target.esp_path)
    entries = esp / "loader/entries"
    try:
        target_esp = "/" + str(esp.resolve(strict=False).relative_to(root.resolve(strict=False)))
    except (OSError, ValueError):
        return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", "The detected ESP escaped the recovery target.")
    if not _within(entries, esp) or not _safe_directory_chain(entries, esp):
        return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", "The systemd-boot entry directory failed path validation.")
    try:
        source = next(path for path in sorted(entries.glob("*.conf")) if path.is_file() and not path.is_symlink())
        text = source.read_text(encoding="utf-8", errors="replace")
    except (OSError, StopIteration):
        return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", "No reusable systemd-boot entry was found.")
    options = re.search(r"(?m)^options\s+(.+)$", text)
    if not options:
        return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", "The systemd-boot entry has no kernel options line.")
    current = options.group(1)
    current = re.sub(r"\brootflags=[^\s]+", "", current).strip()
    new_text = re.sub(r"(?m)^title\s+.*$", f"title AuraScan Snapshot {snapshot_id} (one shot)", text, count=1)
    new_text = re.sub(r"(?m)^options\s+.*$", f"options {current} rootflags=subvol=/.snapshots/{snapshot_id}/snapshot", new_text, count=1)
    target = entries / f"aurascan-snapshot-{snapshot_id}.conf"
    try:
        require_trusted_system_tool("bootctl")
    except TrustedToolError:
        return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", HOST_TOOL_FIRST_USE_MESSAGE)
    fd, temporary = tempfile.mkstemp(prefix=f".{target.name}.", dir=str(entries), text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(new_text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    try:
        bootctl = require_trusted_system_tool("bootctl")
    except TrustedToolError:
        target.unlink(missing_ok=True)
        return RecoveryRepairResult(action.action_id, action.recipe_id, "failed", SNAPSHOT_TEST_TRUST_LATER_MESSAGE)
    code, output = _run(runner, [bootctl.path, f"--root={root}", f"--esp-path={target_esp}", "set-oneshot", target.stem], timeout=30)
    if code != 0:
        target.unlink(missing_ok=True)
        return RecoveryRepairResult(action.action_id, action.recipe_id, "failed", "systemd-boot rejected the one-shot snapshot entry.", output_excerpt=output)
    return RecoveryRepairResult(action.action_id, action.recipe_id, "applied", f"Snapshot {snapshot_id} is prepared for one test boot; the permanent default was not changed.", True, str(target), True, output)


def _execute_snapshot_restore(
    report: RecoveryReport,
    action: RecoveryAction,
    runner: Callable,
) -> RecoveryRepairResult:
    root = Path(report.target.root_path)
    snapshot_id = _validated_snapshot_id(action.parameters.get("snapshot_id"))
    if not snapshot_id:
        return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", "Snapshot restore prerequisites changed.")
    snapshot = root / f".snapshots/{snapshot_id}/snapshot"
    if report.target.filesystem != "btrfs" or not snapshot.is_dir() or not _trusted_target_binary(rooted(root, Path("/usr/bin/snapper")), root):
        return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", "Snapshot restore prerequisites changed.")
    try:
        require_trusted_system_tool("arch-chroot")
    except TrustedToolError:
        return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", HOST_TOOL_FIRST_USE_MESSAGE)
    snapshot_root = root / ".snapshots"
    try:
        existing_ids = {
            item.name for item in snapshot_root.iterdir()
            if item.name.isdigit() and item.is_dir() and not item.is_symlink()
        }
    except OSError:
        return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", "Existing snapshot state could not be bounded before restore.")
    label = f"AuraScan pre-recovery {report.recovery_id}"
    create = ["arch-chroot", str(root), "snapper", "create", "--print-number", "--type", "single", "--description", label]
    try:
        arch_chroot = require_trusted_system_tool("arch-chroot")
    except TrustedToolError:
        return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", HOST_TOOL_FIRST_USE_MESSAGE)
    code, output = _run(runner, [arch_chroot.path, *create[1:]], timeout=180)
    if code != 0:
        return RecoveryRepairResult(action.action_id, action.recipe_id, "failed", "Pre-recovery snapshot creation failed; restore was not attempted.", output_excerpt=output)
    created = next((token for token in reversed(re.findall(r"\b\d+\b", output)) if token.isdigit()), "")
    created_path = root / f".snapshots/{created}/snapshot" if created else Path("")
    if not created or created in existing_ids or not created_path.is_dir() or created_path.is_symlink():
        return RecoveryRepairResult(action.action_id, action.recipe_id, "failed", "Pre-recovery snapshot could not be validated; restore was not attempted.", output_excerpt=output)
    command = ["arch-chroot", str(root), "snapper", "rollback", snapshot_id]
    try:
        arch_chroot = require_trusted_system_tool("arch-chroot")
    except TrustedToolError:
        return RecoveryRepairResult(
            action.action_id,
            action.recipe_id,
            "failed",
            SNAPSHOT_RESTORE_TRUST_LATER_MESSAGE.format(created=created),
            False,
            str(created_path),
            True,
        )
    code, restore_output = _run(runner, [arch_chroot.path, *command[1:]], timeout=900)
    message = f"Snapshot {snapshot_id} was restored after validating pre-recovery snapshot {created}." if code == 0 else f"Snapshot rollback failed; pre-recovery snapshot {created} was retained."
    return RecoveryRepairResult(action.action_id, action.recipe_id, "applied" if code == 0 else "failed", message, code == 0, str(created_path), True, restore_output)


def _execute_bootloader(
    report: RecoveryReport,
    action: RecoveryAction,
    backup_root: Path,
    backups: List[Dict[str, object]],
    runner: Callable,
) -> RecoveryRepairResult:
    root = Path(report.target.root_path)
    esp = Path(report.target.esp_path)
    expected = str(action.parameters.get("bootloader") or "")
    # The reinstall recipe for Limine and GRUB executes through the host
    # ``arch-chroot``.  Preflight it before the inspection below runs a
    # command, so a first-use refusal really has zero commands and zero
    # target mutations.  The systemd-boot recipe uses ``bootctl`` and is
    # refused by the unchanged tool gate instead.
    if expected in {"limine", "grub"}:
        try:
            require_trusted_system_tool("arch-chroot")
        except TrustedToolError:
            return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", HOST_TOOL_FIRST_USE_MESSAGE)
    info = inspect_recovery_target(root, runner=runner).bootloader
    if not info.installed or info.kind != expected or not info.supports_reinstall:
        return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", "The exact bootloader could not be freshly revalidated.")
    raw_paths = [Path(item) for item in [info.config_path, *info.evidence[:20]] if item]
    paths: List[Path] = []
    for path in raw_paths:
        if path not in paths and (_within(path, root) or _within(path, esp)):
            paths.append(path)
    backup_start = len(backups)
    for path in paths:
        if not path.exists():
            continue
        allowed = esp if _within(path, esp) else root
        if not _safe_regular(path, allowed) or _backup_file(path, backup_root, backups) is None:
            return RecoveryRepairResult(action.action_id, action.recipe_id, "failed", "Bootloader files could not be validated and backed up.")
    commands = bootloader_reinstall_commands(info, root=root, esp_path=esp)
    if not commands:
        return RecoveryRepairResult(action.action_id, action.recipe_id, "refused", "No bounded reinstall recipe exists for the detected loader.")
    if not all(_trusted_arch_chroot_tools(command, root) for command in commands):
        return RecoveryRepairResult(
            action.action_id,
            action.recipe_id,
            "refused",
            "A bootloader reinstall tool is not a root-owned non-symlink executable; refusing to execute it as recovery root.",
        )
    outputs = []
    for index, command in enumerate(commands):
        try:
            arch_chroot = require_trusted_system_tool("arch-chroot")
        except TrustedToolError:
            action_backups = backups[backup_start:]
            if index == 0:
                # The inspection above already ran a command, so this is not a
                # first use; no reinstall command ran and the target files are
                # untouched.  Only claim retained backups when the recorded
                # backup bytes are still present and verified now.
                retained = _retained_backup_records(action_backups, backup_root=backup_root)
                message = (
                    BOOTLOADER_TRUST_BEFORE_COMMAND_BACKED_UP_MESSAGE.format(name=info.name)
                    if retained
                    else BOOTLOADER_TRUST_BEFORE_COMMAND_NO_BACKUP_MESSAGE.format(name=info.name)
                )
                return RecoveryRepairResult(
                    action.action_id,
                    action.recipe_id,
                    "failed",
                    message,
                    False,
                    str(backup_root) if retained else "",
                    retained,
                )
            restored = _restore_backup_records(
                backups[backup_start:],
                backup_root=backup_root,
                allowed_roots=[root, esp],
            )
            status = "rolled_back" if restored else "failed"
            suffix, rollback_available, backup_path = _loader_backup_outcome(
                backups[backup_start:],
                backup_root=backup_root,
                restored=restored,
            )
            message = (
                f"{info.name} reinstall commands 1..{index} ran; command {index + 1} failed trust "
                "revalidation and the remaining commands were not executed; " + suffix
            )
            return RecoveryRepairResult(action.action_id, action.recipe_id, status, message, False, backup_path, rollback_available, "\n".join(outputs))
        code, output = _run(runner, [arch_chroot.path, *command[1:]], timeout=900)
        outputs.append(output)
        if code != 0:
            restored = _restore_backup_records(
                backups[backup_start:],
                backup_root=backup_root,
                allowed_roots=[root, esp],
            )
            status = "rolled_back" if restored else "failed"
            suffix, rollback_available, backup_path = _loader_backup_outcome(
                backups[backup_start:],
                backup_root=backup_root,
                restored=restored,
            )
            return RecoveryRepairResult(action.action_id, action.recipe_id, status, f"{info.name} reinstall failed; {suffix}", False, backup_path, rollback_available, "\n".join(outputs))
    refreshed = inspect_recovery_target(root, runner=runner).bootloader
    config = Path(refreshed.config_path) if refreshed.config_path else Path("")
    config_valid = bool(
        config
        and config.is_file()
        and not config.is_symlink()
        and (_within(config, root) or _within(config, esp))
        and config.stat().st_size > 0
    )
    verified = refreshed.installed and refreshed.kind == info.kind and config_valid
    if not verified:
        restored = _restore_backup_records(
            backups[backup_start:],
            backup_root=backup_root,
            allowed_roots=[root, esp],
        )
        status = "rolled_back" if restored else "failed"
        suffix, rollback_available, backup_path = _loader_backup_outcome(
            backups[backup_start:],
            backup_root=backup_root,
            restored=restored,
        )
        return RecoveryRepairResult(
            action.action_id,
            action.recipe_id,
            status,
            f"Bootloader commands completed but post-validation failed; {suffix}",
            False,
            backup_path,
            rollback_available,
            "\n".join(outputs),
        )
    return RecoveryRepairResult(action.action_id, action.recipe_id, "applied", f"{info.name} was reinstalled without changing firmware variables and detected again.", True, str(backup_root), bool(backups), "\n".join(outputs))


def _truthful_first_use_result(
    result: RecoveryRepairResult,
    progress: Optional[RepairProgress],
) -> RecoveryRepairResult:
    """Never keep first-use wording once the plan has made progress.

    ``HOST_TOOL_FIRST_USE_MESSAGE`` asserts that no command ran and nothing
    changed.  A later fresh capture inside an executor can still fail after
    the caller prepared the target, so the shared tracker decides whether that
    claim is true; if it is not, the result becomes a partial-preparation
    failure with an explicit, non-first-use message.
    """

    if progress is None or result.message != HOST_TOOL_FIRST_USE_MESSAGE or not progress.advanced:
        return result
    return RecoveryRepairResult(
        result.action_id,
        result.recipe_id,
        "failed",
        PARTIAL_PREPARATION_TRUST_MESSAGE.format(
            commands=progress.commands,
            mutations=progress.mutations,
        ),
        False,
        result.backup_path,
        result.rollback_available,
        result.output_excerpt,
    )


def execute_recovery_action(
    report: RecoveryReport,
    action: RecoveryAction,
    *,
    backup_root: Path,
    backups: List[Dict[str, object]],
    runner: Callable = subprocess.run,
    progress: Optional[RepairProgress] = None,
) -> RecoveryRepairResult:
    if action.recipe_id not in RECOVERY_ALLOWED_RECIPES:
        result = RecoveryRepairResult(action.action_id, action.recipe_id, "refused", "Repair recipe is not allowlisted.")
    elif action.recipe_id == "repository_restore":
        result = _execute_repository_restore(report, action, backup_root, backups)
    elif action.recipe_id == "stale_pacman_lock":
        result = _execute_stale_lock(report, action, backup_root, backups, runner)
    elif action.recipe_id == "package_cache_cleanup":
        result = _execute_cache_cleanup(report, action, runner)
    elif action.recipe_id in {"complete_pacman_transaction", "kernel_module_restore", "kernel_headers_install", "exact_package_reinstall"}:
        result = _execute_pacman_action(report, action, runner)
    elif action.recipe_id == "boot_config_drift":
        result = _execute_config_drift(report, action, runner)
    elif action.recipe_id == "initramfs_rebuild":
        result = _execute_initramfs(report, action, backup_root, backups, runner)
    elif action.recipe_id == "dkms_autoinstall":
        result = _execute_dkms(report, action, runner)
    elif action.recipe_id == "disable_boot_service":
        result = _execute_disable_service(report, action, runner)
    elif action.recipe_id == "snapshot_test_boot":
        result = _execute_snapshot_test(report, action, runner)
    elif action.recipe_id == "snapshot_restore":
        result = _execute_snapshot_restore(report, action, runner)
    elif action.recipe_id == "bootloader_reinstall":
        result = _execute_bootloader(report, action, backup_root, backups, runner)
    else:
        result = RecoveryRepairResult(action.action_id, action.recipe_id, "refused", "No recovery executor exists for this action.")
    return _truthful_first_use_result(result, progress)


# Host tools each allowlisted recipe needs before it can execute anything.
# ``execute_recovery_plan`` preflights these before it remounts a target or
# creates recovery state, so a genuinely first-use refusal keeps its
# zero-command/zero-mutation meaning at the plan level.  The preflight does not
# guarantee that the executor's later fresh capture succeeds: ``RepairProgress``
# records the plan's mount queries, remount, state creation and earlier actions
# so such a later failure is reported as a partial-preparation failure instead
# of reusing the first-use text.
ACTION_REQUIRED_HOST_TOOLS: Dict[str, Tuple[str, ...]] = {
    "stale_pacman_lock": ("ps", "pacman"),
    "package_cache_cleanup": ("paccache",),
    "complete_pacman_transaction": ("pacman-conf", "arch-chroot"),
    "kernel_module_restore": ("pacman-conf", "arch-chroot"),
    "kernel_headers_install": ("pacman-conf", "arch-chroot"),
    "exact_package_reinstall": ("pacman-conf", "arch-chroot"),
    "boot_config_drift": ("aurascan",),
    "initramfs_rebuild": ("arch-chroot",),
    "dkms_autoinstall": ("arch-chroot",),
    "disable_boot_service": ("systemctl",),
    "snapshot_test_boot": ("bootctl",),
    "snapshot_restore": ("arch-chroot",),
}


def _action_required_host_tools(action: RecoveryAction) -> Tuple[str, ...]:
    if action.recipe_id == "bootloader_reinstall":
        # The systemd-boot recipe uses bootctl and is refused by the unchanged
        # tool gate; only Limine/GRUB execute through arch-chroot.
        if str(action.parameters.get("bootloader") or "") == "systemd-boot":
            return ()
        return ("arch-chroot",)
    return ACTION_REQUIRED_HOST_TOOLS.get(action.recipe_id, ())


def _plan_required_host_tools(actions: Sequence[RecoveryAction]) -> Tuple[str, ...]:
    names: List[str] = []
    for action in actions:
        for name in _action_required_host_tools(action):
            if name not in names:
                names.append(name)
    return tuple(names)


def execute_recovery_plan(
    report: RecoveryReport,
    *,
    typed_confirmations: Optional[Mapping[str, str]] = None,
    runner: Callable = subprocess.run,
    dry_run: bool = False,
    progress_callback: Optional[Callable[[str], None]] = None,
) -> List[RecoveryRepairResult]:
    typed = dict(typed_confirmations or {})
    actions = sorted(report.eligible_actions, key=lambda item: (recovery_recipe_order(item.recipe_id), item.action_id))
    if dry_run:
        results = [RecoveryRepairResult(item.action_id, item.recipe_id, "planned", "Verified action was not applied in dry-run mode.", True) for item in actions]
        report.repair_results = results
        return results
    runnable = [
        item for item in actions
        if not item.confirmation_phrase or typed.get(item.action_id, "") == item.confirmation_phrase
    ]
    if not runnable:
        results = [RecoveryRepairResult(item.action_id, item.recipe_id, "declined", "Required typed confirmation was not supplied.") for item in actions]
        report.repair_results = results
        return results
    # One shared tracker and one shared runner funnel: every command the plan,
    # freshness inspection or executor runs is preparation progress that no
    # later layer may describe as a first use.
    progress = RepairProgress()

    def tracked_runner(command, **kwargs):
        progress.command()
        return runner(command, **kwargs)

    ready, message = _prepare_write_target(
        report,
        tracked_runner,
        required_tools=_plan_required_host_tools(runnable),
        progress=progress,
    )
    if not ready:
        results = [RecoveryRepairResult("plan", "plan", "refused", message)]
        report.repair_results = results
        return results
    run_root = Path(report.target.root_path) / "var/lib/aurascan/recovery" / report.recovery_id
    if not _safe_directory_chain(run_root.parent, Path(report.target.root_path)):
        return [RecoveryRepairResult("plan", "plan", "refused", "Recovery state path contains an unsafe symlink or non-directory component.")]
    run_root.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(run_root, 0o700)
    progress.created_state()
    backups: List[Dict[str, object]] = []
    results: List[RecoveryRepairResult] = []
    manifest_path = run_root / "manifest.json"
    for action in actions:
        if action.confirmation_phrase and typed.get(action.action_id, "") != action.confirmation_phrase:
            results.append(RecoveryRepairResult(action.action_id, action.recipe_id, "declined", "Required typed confirmation was not supplied."))
            continue
        if progress_callback:
            progress_callback(f"Applying verified repair: {action.title}")
        fresh = _fresh_action(report, action, tracked_runner)
        if fresh is None or not fresh.eligible or not fresh.verified:
            results.append(RecoveryRepairResult(action.action_id, action.recipe_id, "refused", "Fresh root-side revalidation no longer approves this action."))
            break
        result = execute_recovery_action(report, fresh, backup_root=run_root, backups=backups, runner=tracked_runner, progress=progress)
        results.append(result)
        _atomic_json(manifest_path, {
            "schema": "recovery_repair_manifest/1.0",
            "recovery_id": report.recovery_id,
            "target_id": report.target.target_id,
            "created_at": int(time.time()),
            "actions": [item.to_dict() for item in actions],
            "backups": backups,
            "results": [item.to_dict() for item in results],
        })
        if result.status not in {"applied", "no_action", "declined"}:
            break
    report.backups = backups
    report.repair_results = results
    if progress_callback:
        progress_callback("Validating the repaired operating system")
    post_target = inspect_recovery_target(
        Path(report.target.root_path),
        source=report.target.source,
        mounted_read_only=False,
        encrypted=report.target.encrypted,
        storage_layers=report.target.storage_layers,
        runner=runner,
    )
    post = scan_recovery_target(post_target, runner=runner)
    report.post_repair = {
        "validated_at": int(time.time()),
        "remaining_findings": [item.rule_id for item in post.findings],
        "highest_severity": post.highest_severity.value,
        "manifest": str(manifest_path),
    }
    _atomic_json(manifest_path, {
        "schema": "recovery_repair_manifest/1.0",
        "recovery_id": report.recovery_id,
        "target_id": report.target.target_id,
        "created_at": int(time.time()),
        "actions": [item.to_dict() for item in actions],
        "backups": backups,
        "results": [item.to_dict() for item in results],
        "post_repair": report.post_repair,
    })
    return results


def save_recovery_report(
    report: RecoveryReport,
    *,
    target_root: Optional[Path] = None,
) -> Tuple[Optional[Path], str]:
    root = target_root or Path(report.target.root_path)
    destination = root / "var/lib/aurascan/recovery/reports" / f"{report.recovery_id}.json"
    try:
        if not _safe_directory_chain(destination.parent, root):
            raise OSError("target recovery report path contains an unsafe symlink or non-directory component")
        _atomic_json(destination, report.to_dict())
        return destination, "Recovery report saved on the target."
    except OSError as exc:
        runtime = RECOVERY_STATE_ROOT / "reports" / f"{report.recovery_id}.json"
        try:
            if not _safe_directory_chain(runtime.parent, Path("/")):
                raise OSError("runtime recovery report path is unsafe")
            _atomic_json(runtime, report.to_dict())
            return runtime, "Target was not writable; recovery report was retained in recovery RAM."
        except OSError:
            return None, f"Recovery report could not be saved: {exc}"


def export_recovery_report(
    report: RecoveryReport,
    destination_root: Path,
    *,
    runner: Callable = subprocess.run,
) -> Tuple[Optional[Path], str]:
    try:
        metadata = destination_root.lstat()
        if destination_root.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
            return None, "Export destination is not a regular mounted directory."
    except OSError as exc:
        return None, f"Export destination could not be inspected: {exc}"
    try:
        require_trusted_system_tool("findmnt")
        require_trusted_system_tool("lsblk")
    except TrustedToolError:
        return None, HOST_TOOL_FIRST_USE_MESSAGE
    try:
        findmnt = require_trusted_system_tool("findmnt")
    except TrustedToolError:
        return None, HOST_TOOL_FIRST_USE_MESSAGE
    code, output = _run(runner, [findmnt.path, "--json", "--target", str(destination_root), "--output", "SOURCE,TARGET"], timeout=15)
    if code != 0:
        return None, "Export destination is not a proven mountpoint."
    try:
        payload = json.loads(output)
        filesystems = payload.get("filesystems", []) if isinstance(payload, Mapping) else []
        source = str(filesystems[0].get("source") or "") if filesystems and isinstance(filesystems[0], Mapping) else ""
    except (ValueError, IndexError):
        source = ""
    if not source.startswith("/dev/"):
        return None, "Export destination is not backed by a removable block device."
    try:
        lsblk = require_trusted_system_tool("lsblk")
    except TrustedToolError:
        return None, EXPORT_LSBLK_TRUST_LATER_MESSAGE
    code, removable = _run(runner, [lsblk.path, "--noheadings", "--output", "RM", source.split("[")[0]], timeout=15)
    if code != 0 or removable.strip().splitlines()[:1] != ["1"]:
        return None, "Export destination is not reported as removable."
    export_root = destination_root / "AuraScan-Recovery"
    destination = export_root / f"{report.recovery_id}.json"
    try:
        _atomic_json(destination, report.to_dict())
    except OSError as exc:
        return None, f"Recovery report export failed: {exc}"
    return destination, f"Recovery report exported to {destination}."
