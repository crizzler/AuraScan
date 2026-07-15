import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Mapping, Optional, Sequence, Tuple


RECOVERY_UKI_RELATIVE = Path("EFI/Linux/aurascan-recovery.efi")
RECOVERY_BACKUP_RELATIVE = Path("EFI/AuraScan/backups/aurascan-recovery.previous.efi")
RECOVERY_LIMINE_BEGIN = "# AURASCAN RECOVERY BEGIN"
RECOVERY_LIMINE_END = "# AURASCAN RECOVERY END"
RECOVERY_GRUB_SCRIPT = Path("etc/grub.d/41_aurascan_recovery")
RECOVERY_MIN_IMAGE_SIZE = 1024 * 1024
RECOVERY_IMAGE_SECRET_MARKERS = (
    b"AURASCAN_AI_KEY=",
    b"AURASCAN_OPENAI_API_KEY=",
    b"AURASCAN_ANTHROPIC_API_KEY=",
    b"AURASCAN_DEEPSEEK_API_KEY=",
    b"AURASCAN_GEMINI_API_KEY=",
    b"AURASCAN_OPENROUTER_API_KEY=",
    b"/home/",
    b"system-connections/",
)
SAFE_KERNEL_VERSION_RE = re.compile(r"^[A-Za-z0-9._+~-]{1,160}$")


@dataclass
class BootloaderInfo:
    kind: str = "unknown"
    name: str = "Unknown"
    config_path: str = ""
    installed: bool = False
    supports_entry: bool = False
    supports_reinstall: bool = False
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "kind": self.kind,
            "name": self.name,
            "config_path": self.config_path,
            "installed": self.installed,
            "supports_entry": self.supports_entry,
            "supports_reinstall": self.supports_reinstall,
            "evidence": list(self.evidence),
        }


@dataclass
class RecoveryImageStatus:
    installed: bool = False
    image_path: str = ""
    backup_path: str = ""
    image_size: int = 0
    valid_pe: bool = False
    version: str = ""
    stale: bool = False
    secure_boot: str = "unknown"
    signed: bool = False
    bootloader: BootloaderInfo = field(default_factory=BootloaderInfo)
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "installed": self.installed,
            "image_path": self.image_path,
            "backup_path": self.backup_path,
            "image_size": self.image_size,
            "valid_pe": self.valid_pe,
            "version": self.version,
            "stale": self.stale,
            "secure_boot": self.secure_boot,
            "signed": self.signed,
            "bootloader": self.bootloader.to_dict(),
            "errors": list(self.errors),
        }


@dataclass
class BootOperationResult:
    ok: bool
    status: str
    message: str
    changed: List[str] = field(default_factory=list)
    backup_paths: List[str] = field(default_factory=list)
    command: List[str] = field(default_factory=list)
    details: Dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return {
            "ok": self.ok,
            "status": self.status,
            "message": self.message,
            "changed": list(self.changed),
            "backup_paths": list(self.backup_paths),
            "command": list(self.command),
            "details": dict(self.details),
        }


@dataclass
class UsbDeviceInfo:
    path: str
    kind: str = ""
    removable: bool = False
    size: int = 0
    model: str = ""
    serial: str = ""
    mountpoints: List[str] = field(default_factory=list)
    children: List[str] = field(default_factory=list)
    eligible: bool = False
    refusal: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "path": self.path,
            "type": self.kind,
            "removable": self.removable,
            "size": self.size,
            "model": self.model,
            "serial": self.serial,
            "mountpoints": list(self.mountpoints),
            "children": list(self.children),
            "eligible": self.eligible,
            "refusal": self.refusal,
        }


def rooted(root: Path, absolute: Path) -> Path:
    root = Path(root)
    if root == Path("/"):
        return absolute
    return root / str(absolute).lstrip("/")


def detect_bootloader(root: Path = Path("/"), esp_path: Optional[Path] = None) -> BootloaderInfo:
    root = Path(root)
    esp = Path(esp_path) if esp_path is not None else rooted(root, Path("/boot"))
    grub_efi = []
    try:
        grub_efi = [path for path in (esp / "EFI").glob("*/grubx64.efi") if path.is_file() and not path.is_symlink()][:20]
    except OSError:
        pass
    candidates = [
        (
            "limine",
            "Limine",
            rooted(root, Path("/etc/default/limine")),
            [esp / "limine.conf", esp / "EFI/limine/limine_x64.efi"],
        ),
        (
            "systemd-boot",
            "systemd-boot",
            esp / "loader/loader.conf",
            [esp / "EFI/systemd/systemd-bootx64.efi"],
        ),
        (
            "grub",
            "GRUB",
            rooted(root, Path("/etc/default/grub")),
            grub_efi,
        ),
    ]
    detected: List[Tuple[int, BootloaderInfo]] = []
    for kind, name, config, evidence_paths in candidates:
        positive = [path for path in evidence_paths if path.exists() and not path.is_symlink()]
        found = [str(path) for path in [config] if path.exists() and not path.is_symlink()] + [str(path) for path in positive]
        if positive:
            config_path = config
            if kind == "limine" and (esp / "limine.conf").exists():
                config_path = esp / "limine.conf"
            elif kind == "grub" and rooted(root, Path("/boot/grub/grub.cfg")).exists():
                config_path = rooted(root, Path("/boot/grub/grub.cfg"))
            config_present = config_path.exists() and not config_path.is_symlink()
            score = 2 if config_present else 1
            detected.append((score, BootloaderInfo(kind, name, str(config_path), True, True, True, found)))
    if detected:
        highest = max(score for score, _item in detected)
        strongest = [item for score, item in detected if score == highest]
        if len(strongest) == 1:
            return strongest[0]
        names = ", ".join(sorted(item.name for item in strongest))
        evidence = [path for item in strongest for path in item.evidence]
        evidence.append(f"Multiple equally strong bootloader installations were detected: {names}.")
        return BootloaderInfo(evidence=evidence)
    return BootloaderInfo(evidence=[f"No supported bootloader evidence under {root} and {esp}."])


def choose_recovery_kernel(modules_root: Path = Path("/usr/lib/modules")) -> Tuple[str, str]:
    choices: List[Tuple[int, float, str, str]] = []
    try:
        directories = list(modules_root.iterdir())
    except OSError:
        return "", ""
    for directory in directories:
        kernel_image = directory / "vmlinuz"
        if directory.is_symlink() or not directory.is_dir() or not SAFE_KERNEL_VERSION_RE.fullmatch(directory.name):
            continue
        if kernel_image.is_symlink() or not kernel_image.is_file():
            continue
        pkgbase = ""
        try:
            pkgbase = (directory / "pkgbase").read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            pass
        if pkgbase and not re.fullmatch(r"[A-Za-z0-9._+~-]{1,160}", pkgbase):
            continue
        try:
            modified = kernel_image.stat().st_mtime
        except OSError:
            modified = 0
        lowered = f"{directory.name} {pkgbase}".lower()
        priority = 0 if "lts" in lowered else 1 if "hardened" in lowered else 2
        choices.append((priority, -modified, directory.name, pkgbase))
    if not choices:
        return "", ""
    _priority, _modified, version, pkgbase = sorted(choices)[0]
    return version, pkgbase


def build_uki_command(
    output_path: Path,
    kernel_version: str,
    *,
    mkosi: str = "/usr/bin/mkosi",
    profile_path: Path = Path("/usr/lib/aurascan/recovery/mkosi.conf"),
    extra_tree: Optional[Path] = None,
) -> List[str]:
    if not SAFE_KERNEL_VERSION_RE.fullmatch(kernel_version):
        raise ValueError("invalid kernel version for recovery image")
    modules = Path("/usr/lib/modules") / kernel_version
    command = [
        mkosi,
        "--force",
        "--directory=",
        "--format=uki",
        f"--output={output_path.name}",
        f"--output-directory={output_path.parent}",
        "--include=mkosi-initrd",
        f"--include={profile_path}",
        f"--extra-tree={modules}:{modules}",
        "--extra-tree=/usr/lib/firmware:/usr/lib/firmware",
        "--remove-files=/usr/lib/firmware/*-ucode",
        "--build-sources=",
        "--kernel-modules=host",
        (
            "--kernel-command-line=rd.systemd.unit=multi-user.target "
            "systemd.unit=multi-user.target "
            "rd.systemd.wants=aurascan-recovery.service "
            "systemd.wants=aurascan-recovery.service"
        ),
        "--output-mode=600",
    ]
    if extra_tree is not None:
        command.append(f"--extra-tree={extra_tree}:/")
    return command


def validate_recovery_image(
    path: Path,
    *,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
    minimum_size: int = RECOVERY_MIN_IMAGE_SIZE,
    expected_kernel_version: str = "",
    forbidden_markers: Sequence[bytes] = (),
) -> Tuple[bool, List[str]]:
    errors: List[str] = []
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
            return False, ["Recovery image is not a regular non-symlink file."]
        if metadata.st_size < minimum_size:
            errors.append("Recovery image is unexpectedly small.")
        with path.open("rb") as handle:
            head = handle.read(2)
            if head != b"MZ":
                errors.append("Recovery image is not a PE/COFF executable.")
            handle.seek(0)
            overlap = b""
            markers = tuple(RECOVERY_IMAGE_SECRET_MARKERS) + tuple(item for item in forbidden_markers if len(item) >= 4)
            max_marker = max(map(len, markers))
            while True:
                chunk = handle.read(4 * 1024 * 1024)
                if not chunk:
                    break
                sample = overlap + chunk
                if any(marker in sample for marker in markers):
                    errors.append("Recovery image contains forbidden credential or user-profile material.")
                    break
                overlap = sample[-max_marker:]
    except OSError as exc:
        return False, [f"Recovery image could not be read: {exc}"]
    ukify = which("ukify")
    if ukify and not errors:
        result = runner([ukify, "inspect", str(path)], capture_output=True, text=True, timeout=30, check=False)
        if result.returncode != 0:
            errors.append("ukify could not validate the recovery image.")
        else:
            inspection = (result.stdout or "") + "\n" + (result.stderr or "")
            if expected_kernel_version and expected_kernel_version not in inspection:
                errors.append("ukify did not prove the selected recovery kernel version is present.")
            if "systemd.wants=aurascan-recovery.service" not in inspection:
                errors.append("The recovery UKI does not request the AuraScan recovery service at boot.")
    return not errors, errors


def detect_secure_boot(
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
    efivars_root: Path = Path("/sys/firmware/efi/efivars"),
) -> str:
    bootctl = which("bootctl")
    if bootctl:
        result = runner([bootctl, "status", "--no-pager"], capture_output=True, text=True, timeout=15, check=False)
        combined = (result.stdout + "\n" + result.stderr).lower()
        if "secure boot: enabled" in combined:
            return "enabled"
        if "secure boot: disabled" in combined:
            return "disabled"
    try:
        candidates = list(efivars_root.glob("SecureBoot-*"))[:2]
    except OSError:
        candidates = []
    for candidate in candidates:
        try:
            if candidate.is_symlink() or not candidate.is_file():
                continue
            data = candidate.read_bytes()
        except OSError:
            continue
        if len(data) >= 5 and data[4] in {0, 1}:
            return "enabled" if data[4] == 1 else "disabled"
    return "unknown"


def sbctl_owner_key_ready(
    *,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
) -> Tuple[bool, str]:
    sbctl = which("sbctl")
    if not sbctl:
        return False, "sbctl is unavailable."
    status = runner([sbctl, "status", "--json"], capture_output=True, text=True, timeout=20, check=False)
    if status.returncode != 0:
        return False, "AuraScan could not verify enrolled local Secure Boot keys."
    try:
        status_data = json.loads(status.stdout)
    except ValueError:
        return False, "sbctl returned invalid signing-key status."

    def installed(value: object) -> bool:
        if isinstance(value, Mapping):
            return any(
                (str(key).lower() == "installed" and nested is True) or installed(nested)
                for key, nested in value.items()
            )
        if isinstance(value, list):
            return any(installed(item) for item in value)
        return False

    if not installed(status_data):
        return False, "No enrolled sbctl-compatible owner key was proven."
    return True, "An enrolled sbctl-compatible owner key is ready."


def sign_recovery_image(path: Path, *, runner: Callable = subprocess.run, which: Callable[[str], Optional[str]] = shutil.which) -> BootOperationResult:
    sbctl = which("sbctl")
    if not sbctl:
        return BootOperationResult(False, "unavailable", "Secure Boot is enabled but sbctl is unavailable.")
    ready, reason = sbctl_owner_key_ready(runner=runner, which=which)
    if not ready:
        return BootOperationResult(False, "refused", reason)
    command = [sbctl, "sign", "--save", str(path)]
    signed = runner(command, capture_output=True, text=True, timeout=120, check=False)
    if signed.returncode != 0:
        return BootOperationResult(False, "failed", "sbctl failed to sign the recovery image.", command=command)
    verify = runner([sbctl, "verify", str(path)], capture_output=True, text=True, timeout=30, check=False)
    if verify.returncode != 0:
        return BootOperationResult(False, "failed", "The signed recovery image failed sbctl verification.", command=command)
    return BootOperationResult(True, "signed", "Recovery image was signed with the enrolled local owner key.", command=command)


def render_limine_recovery_entry(uki_path: Path = RECOVERY_UKI_RELATIVE) -> str:
    return "\n".join([
        RECOVERY_LIMINE_BEGIN,
        "/AuraScan Recovery",
        "  protocol: efi",
        f"  path: boot():/{uki_path.as_posix()}",
        "  comment: AI-assisted offline-capable system recovery",
        RECOVERY_LIMINE_END,
    ]) + "\n"


def merge_marked_block(text: str, block: str, begin: str, end: str) -> str:
    pattern = re.compile(rf"(?ms)^\s*{re.escape(begin)}.*?^\s*{re.escape(end)}\s*\n?")
    cleaned = pattern.sub("", text).rstrip()
    return (cleaned + "\n\n" if cleaned else "") + block


def render_grub_recovery_script(uki_path: Path = RECOVERY_UKI_RELATIVE) -> str:
    return "\n".join([
        "#!/bin/sh",
        "exec tail -n +3 $0",
        "menuentry 'AuraScan Recovery' --class recovery {",
        "    insmod chain",
        "    insmod fat",
        "    search --no-floppy --file --set=esp /" + uki_path.as_posix(),
        "    chainloader ($esp)/" + uki_path.as_posix(),
        "}",
        "",
    ])


def backup_file(path: Path, backup_root: Path) -> Optional[Path]:
    if not path.exists():
        return None
    backup_root.mkdir(parents=True, mode=0o700, exist_ok=True)
    digest = hashlib.sha256(str(path).encode("utf-8", "replace")).hexdigest()[:12]
    backup = backup_root / f"{path.name}.{digest}.bak"
    shutil.copy2(path, backup)
    os.chmod(backup, 0o600)
    return backup


def atomic_write(path: Path, content: bytes, *, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def install_bootloader_entry(
    bootloader: BootloaderInfo,
    *,
    root: Path,
    esp_path: Path,
    backup_root: Path,
    dry_run: bool = False,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
) -> BootOperationResult:
    if bootloader.kind == "unknown" or not bootloader.supports_entry:
        return BootOperationResult(False, "unsupported", "No supported Limine, systemd-boot, or GRUB installation was detected.")
    if bootloader.kind == "systemd-boot":
        return BootOperationResult(True, "ready", "systemd-boot discovers the recovery UKI from EFI/Linux.")
    changed: List[str] = []
    backups: List[str] = []
    if bootloader.kind == "limine":
        config = esp_path / "limine.conf"
        if config.is_symlink():
            return BootOperationResult(False, "refused", "Limine configuration is a symlink; AuraScan will not replace it.")
        try:
            old = config.read_text(encoding="utf-8", errors="replace") if config.exists() else ""
        except OSError as exc:
            return BootOperationResult(False, "failed", f"Limine configuration could not be read: {exc}")
        new = merge_marked_block(old, render_limine_recovery_entry(), RECOVERY_LIMINE_BEGIN, RECOVERY_LIMINE_END)
        if not dry_run and new != old:
            backup = backup_file(config, backup_root)
            if backup:
                backups.append(str(backup))
            atomic_write(config, new.encode("utf-8"), mode=0o600)
            changed.append(str(config))
        return BootOperationResult(True, "installed" if changed else "unchanged", "Limine AuraScan Recovery entry is ready.", changed, backups)
    script = rooted(root, Path("/") / RECOVERY_GRUB_SCRIPT)
    grub_mkconfig = which("grub-mkconfig") if root == Path("/") else None
    target_grub_mkconfig = rooted(root, Path("/usr/bin/grub-mkconfig"))
    if root == Path("/") and not grub_mkconfig:
        return BootOperationResult(False, "unavailable", "GRUB was detected but grub-mkconfig is unavailable.")
    if root != Path("/") and (not target_grub_mkconfig.is_file() or target_grub_mkconfig.is_symlink() or not which("arch-chroot")):
        return BootOperationResult(False, "unavailable", "The target GRUB generator or arch-chroot is unavailable.")
    output = rooted(root, Path("/boot/grub/grub.cfg"))
    if output.is_symlink():
        return BootOperationResult(False, "refused", "GRUB configuration is a symlink; AuraScan will not replace it.")
    if script.is_symlink():
        return BootOperationResult(False, "refused", "GRUB recovery script path is a symlink; AuraScan will not replace it.")
    content = render_grub_recovery_script()
    old = ""
    try:
        old = script.read_text(encoding="utf-8", errors="replace") if script.exists() else ""
    except OSError as exc:
        return BootOperationResult(False, "failed", f"GRUB recovery script could not be read: {exc}")
    if not dry_run and old != content:
        backup = backup_file(script, backup_root)
        if backup:
            backups.append(str(backup))
        atomic_write(script, content.encode("utf-8"), mode=0o755)
        changed.append(str(script))
    output_backup = None
    if not dry_run:
        output_backup = backup_file(output, backup_root)
        if output_backup:
            backups.append(str(output_backup))
        command = [grub_mkconfig, "-o", str(output)] if root == Path("/") else ["arch-chroot", str(root), "grub-mkconfig", "-o", "/boot/grub/grub.cfg"]
        result = runner(command, capture_output=True, text=True, timeout=180, check=False)
        try:
            generated = output.read_text(encoding="utf-8", errors="replace") if output.is_file() and not output.is_symlink() else ""
        except OSError:
            generated = ""
        if result.returncode != 0 or "AuraScan Recovery" not in generated:
            if old:
                atomic_write(script, old.encode("utf-8"), mode=0o755)
            else:
                script.unlink(missing_ok=True)
            if output_backup:
                shutil.copy2(output_backup, output)
            else:
                output.unlink(missing_ok=True)
            return BootOperationResult(False, "failed", "GRUB configuration regeneration or validation failed; the previous script and configuration were restored.", changed, backups, command)
        changed.append(str(output))
    return BootOperationResult(True, "installed" if changed else "unchanged", "GRUB AuraScan Recovery entry is ready.", changed, backups)


def bootloader_reinstall_commands(bootloader: BootloaderInfo, *, root: Path, esp_path: Path) -> List[List[str]]:
    try:
        target_esp = "/" + str(esp_path.resolve(strict=False).relative_to(root.resolve(strict=False)))
    except ValueError:
        return []
    if bootloader.kind == "limine":
        return [["arch-chroot", str(root), "limine-install", "--no-efi-register"]]
    if bootloader.kind == "systemd-boot":
        return [["bootctl", f"--root={root}", f"--esp-path={target_esp}", "--no-variables", "install"]]
    if bootloader.kind == "grub":
        return [
            ["arch-chroot", str(root), "grub-install", "--target=x86_64-efi", f"--efi-directory={target_esp}", "--bootloader-id=GRUB", "--no-nvram"],
            ["arch-chroot", str(root), "grub-mkconfig", "-o", "/boot/grub/grub.cfg"],
        ]
    return []


def read_recovery_version(path: Path) -> str:
    sidecar = path.with_suffix(path.suffix + ".version")
    try:
        return sidecar.read_text(encoding="utf-8", errors="replace").strip()[:80]
    except OSError:
        return ""


def recovery_image_status(
    *,
    root: Path = Path("/"),
    esp_path: Optional[Path] = None,
    expected_version: str = "",
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
) -> RecoveryImageStatus:
    esp = Path(esp_path) if esp_path is not None else rooted(root, Path("/boot"))
    image = esp / RECOVERY_UKI_RELATIVE
    backup = esp / RECOVERY_BACKUP_RELATIVE
    bootloader = detect_bootloader(root, esp)
    secure_boot = detect_secure_boot(runner=runner, which=which)
    status = RecoveryImageStatus(image_path=str(image), backup_path=str(backup), secure_boot=secure_boot, bootloader=bootloader)
    try:
        metadata = image.stat()
        status.installed = image.is_file() and not image.is_symlink()
        status.image_size = metadata.st_size if status.installed else 0
        if status.installed:
            with image.open("rb") as handle:
                status.valid_pe = handle.read(2) == b"MZ"
    except OSError:
        pass
    status.version = read_recovery_version(image)
    status.stale = bool(status.installed and expected_version and status.version != expected_version)
    if secure_boot == "enabled" and status.installed:
        sbctl = which("sbctl")
        if sbctl:
            result = runner([sbctl, "verify", str(image)], capture_output=True, text=True, timeout=20, check=False)
            status.signed = result.returncode == 0
        if not status.signed:
            status.errors.append("Secure Boot is enabled but the recovery image signature was not verified.")
    if status.installed and not status.valid_pe:
        status.errors.append("Installed recovery image does not have a PE/COFF header.")
    return status


def load_iso_manifest(path: Path) -> Dict[str, object]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return dict(data) if isinstance(data, Mapping) else {}


def download_recovery_iso(
    manifest: Mapping[str, object],
    destination: Path,
    *,
    urlopen: Callable = urllib.request.urlopen,
    max_size: int = 4 * 1024 * 1024 * 1024,
) -> BootOperationResult:
    url = str(manifest.get("url") or "")
    expected = str(manifest.get("sha256") or "").lower()
    if not url.startswith("https://github.com/crizzler/AuraScan/releases/download/") or not re.fullmatch(r"[0-9a-f]{64}", expected):
        return BootOperationResult(False, "unavailable", "The packaged recovery ISO manifest is not finalized for this release.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=str(destination.parent))
    digest = hashlib.sha256()
    size = 0
    try:
        with os.fdopen(fd, "wb") as output, urlopen(url, timeout=60) as response:
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > max_size:
                    return BootOperationResult(False, "refused", "Recovery ISO exceeded the bounded download size.")
                output.write(chunk)
                digest.update(chunk)
            output.flush()
            os.fsync(output.fileno())
        if digest.hexdigest() != expected:
            return BootOperationResult(False, "failed", "Recovery ISO checksum verification failed.")
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, destination)
        return BootOperationResult(True, "downloaded", f"Downloaded and verified AuraScan Recovery ISO at {destination}.", [str(destination)])
    except (OSError, ValueError) as exc:
        return BootOperationResult(False, "failed", f"Recovery ISO download failed: {exc}")
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def sha256_file(path: Path, *, max_size: int = 4 * 1024 * 1024 * 1024) -> str:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(4 * 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > max_size:
                raise ValueError("recovery ISO exceeds the verification size bound")
            digest.update(chunk)
    return digest.hexdigest()


def verify_recovery_iso(
    path: Path,
    manifest: Mapping[str, object],
    *,
    allow_local_sidecar: bool = False,
) -> Tuple[bool, str, str]:
    expected = str(manifest.get("sha256") or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        if not allow_local_sidecar:
            return False, "The packaged recovery ISO digest is not finalized for this release.", ""
        sidecar = Path(str(path) + ".sha256")
        try:
            token = sidecar.read_text(encoding="utf-8", errors="replace").split()[0].lower()
        except (OSError, IndexError):
            return False, "Recovery ISO has no finalized manifest digest or trusted local .sha256 sidecar.", ""
        if not re.fullmatch(r"[0-9a-f]{64}", token):
            return False, "Recovery ISO sidecar does not contain a valid SHA-256 digest.", ""
        expected = token
    try:
        actual = sha256_file(path)
    except (OSError, ValueError) as exc:
        return False, f"Recovery ISO could not be verified: {exc}", expected
    if actual != expected:
        return False, "Recovery ISO SHA-256 verification failed.", expected
    return True, "Recovery ISO SHA-256 was verified.", expected


def _flatten_lsblk(nodes: Sequence[Mapping[str, object]]) -> List[Mapping[str, object]]:
    flattened: List[Mapping[str, object]] = []
    for node in nodes:
        flattened.append(node)
        children = node.get("children", [])
        if isinstance(children, list):
            flattened.extend(_flatten_lsblk([item for item in children if isinstance(item, Mapping)]))
    return flattened


def inspect_usb_device(
    device: str,
    *,
    runner: Callable = subprocess.run,
    root_source: str = "",
) -> UsbDeviceInfo:
    info = UsbDeviceInfo(path=device)
    if not re.fullmatch(r"/dev/[A-Za-z0-9._+-]+", device):
        info.refusal = "USB target must be an absolute /dev whole-disk path."
        return info
    command = ["lsblk", "--json", "--bytes", "--output", "PATH,TYPE,RM,SIZE,MODEL,SERIAL,MOUNTPOINTS,PKNAME"]
    result = runner(command, capture_output=True, text=True, timeout=20, check=False)
    try:
        payload = json.loads(result.stdout) if result.returncode == 0 else {}
    except ValueError:
        payload = {}
    nodes = payload.get("blockdevices", []) if isinstance(payload, Mapping) else []
    flat = _flatten_lsblk([item for item in nodes if isinstance(item, Mapping)])
    parent_by_path: Dict[str, str] = {}

    def record_parents(items: Sequence[Mapping[str, object]], parent: str = "") -> None:
        for item in items:
            path = str(item.get("path") or "")
            if path and parent:
                parent_by_path[path] = parent
            children = item.get("children", [])
            if isinstance(children, list):
                record_parents([child for child in children if isinstance(child, Mapping)], path)

    record_parents([item for item in nodes if isinstance(item, Mapping)])
    selected = next((item for item in flat if str(item.get("path") or "") == device), None)
    if selected is None:
        info.refusal = "USB target was not found in lsblk output."
        return info
    info.kind = str(selected.get("type") or "")
    info.removable = bool(int(selected.get("rm") or 0))
    info.size = int(selected.get("size") or 0)
    info.model = str(selected.get("model") or "").strip()[:120]
    info.serial = str(selected.get("serial") or "").strip()[:120]
    raw_mounts = selected.get("mountpoints") or []
    if isinstance(raw_mounts, list):
        info.mountpoints = [str(value) for value in raw_mounts if value]
    root_parent = root_source.split("[")[0]
    root_aliases = {root_parent, os.path.realpath(root_parent)} if root_parent else set()
    root_node = next((str(item.get("path") or "") for item in flat if str(item.get("path") or "") in root_aliases or os.path.realpath(str(item.get("path") or "")) in root_aliases), "")
    root_ancestors = set()
    cursor = root_node
    while cursor and cursor not in root_ancestors:
        root_ancestors.add(cursor)
        cursor = parent_by_path.get(cursor, "")
    selected_descendants = {device}
    changed = True
    while changed:
        changed = False
        for child, parent in parent_by_path.items():
            if parent in selected_descendants and child not in selected_descendants:
                selected_descendants.add(child)
                changed = True
    descendants = [item for item in flat if str(item.get("path") or "") in selected_descendants and str(item.get("path") or "") != device]
    info.children = [str(item.get("path") or "") for item in descendants]
    for child in descendants:
        mounts = child.get("mountpoints") or []
        if isinstance(mounts, list):
            info.mountpoints.extend(str(value) for value in mounts if value)
    fallback_prefix = device.rstrip("0123456789")
    if info.kind != "disk":
        info.refusal = "USB target is not a whole-disk block device."
    elif not info.removable:
        info.refusal = "USB target is not reported as removable; AuraScan will not override this safety check."
    elif root_parent and (
        device in root_ancestors
        or root_node in selected_descendants
        or root_parent == device
        or (not root_node and root_parent.startswith(fallback_prefix))
    ):
        info.refusal = "USB target contains the running root filesystem."
    elif info.mountpoints:
        info.refusal = "USB target or one of its partitions is mounted."
    elif info.size < 1024 * 1024 * 1024:
        info.refusal = "USB target is smaller than 1 GiB."
    else:
        info.eligible = True
    return info


def write_iso_to_usb(
    iso_path: Path,
    device: UsbDeviceInfo,
    *,
    confirmation: str,
    progress: Optional[Callable[[int, int], None]] = None,
    chunk_size: int = 4 * 1024 * 1024,
    expected_sha256: str = "",
) -> BootOperationResult:
    if not device.eligible or confirmation.strip() != device.path:
        return BootOperationResult(False, "refused", "USB write requires an eligible device and exact typed device-path confirmation.")
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return BootOperationResult(False, "refused", "Writing a recovery USB requires root privileges.")
    try:
        total = iso_path.stat().st_size
        if total <= 0 or total > device.size:
            return BootOperationResult(False, "refused", "Recovery ISO does not fit on the selected USB device.")
        digest = hashlib.sha256()
        if expected_sha256 and sha256_file(iso_path) != expected_sha256.lower():
            return BootOperationResult(False, "refused", "Recovery ISO changed after pre-write verification.")
        written = 0
        with iso_path.open("rb") as source, open(device.path, "wb", buffering=0) as target:
            while True:
                chunk = source.read(chunk_size)
                if not chunk:
                    break
                target.write(chunk)
                digest.update(chunk)
                written += len(chunk)
                if progress:
                    progress(written, total)
            target.flush()
            os.fsync(target.fileno())
        verify = hashlib.sha256()
        with open(device.path, "rb", buffering=0) as target:
            remaining = total
            while remaining:
                chunk = target.read(min(chunk_size, remaining))
                if not chunk:
                    break
                verify.update(chunk)
                remaining -= len(chunk)
        if remaining or verify.digest() != digest.digest():
            return BootOperationResult(False, "failed", "USB verification failed after writing.")
        return BootOperationResult(True, "written", f"AuraScan Recovery USB was written and verified on {device.path}.", [device.path])
    except OSError as exc:
        return BootOperationResult(False, "failed", f"Recovery USB write failed: {exc}")
