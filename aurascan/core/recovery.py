import glob
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from aurascan.core.ai_provider import call_ai_provider, parse_bool, resolve_ai_config
from aurascan.core.compatibility import DistroInfo, distro_from_os_release, parse_os_release
from aurascan.core.config import parse_env_lines
from aurascan.core.incidents import (
    DiagnosticProbe,
    DiagnosticProbeResult,
    CoredumpGroup,
    INCIDENT_AI_EVIDENCE_ENV,
    INCIDENT_AI_EVIDENCE_VALUES,
    INCIDENT_MAX_LOCAL_EVIDENCE_CHARS,
    IncidentEvidence,
    IncidentFinding,
    IncidentReport,
    INCIDENT_RULES,
    bound_evidence,
    collect_coredumps,
    collect_pstore_evidence,
    deduplicate_evidence,
    deduplicate_findings,
    redact_incident_text,
)
from aurascan.core.models import Confidence, SCANNER_VERSION, Severity
from aurascan.core.recovery_boot import BootloaderInfo, detect_bootloader
from aurascan.core.recovery_network import RecoveryNetworkState


RECOVERY_SCHEMA_VERSION = "1.0"
RECOVERY_REPORT_TYPE = "recovery_report"
RECOVERY_AI_ENABLED_ENV = "AURASCAN_RECOVERY_AI_ENABLED"
RECOVERY_WIFI_PROFILES_ENV = "AURASCAN_RECOVERY_WIFI_PROFILES"
RECOVERY_AUTO_REFRESH_ENV = "AURASCAN_RECOVERY_AUTO_REFRESH"
RECOVERY_WIFI_PROFILE_VALUES = {"auto", "ask", "never"}
RECOVERY_REFRESH_VALUES = {"automatic", "manual"}
RECOVERY_POLICY_PATH = Path("/etc/aurascan/recovery.conf")
RECOVERY_STATE_ROOT = Path("/var/lib/aurascan/recovery")
RECOVERY_RUNTIME_MARKER = Path("/run/aurascan-recovery/environment")
RECOVERY_TARGET_MOUNT = Path("/run/aurascan-recovery/target")
RECOVERY_MAX_EVIDENCE = 80
RECOVERY_MAX_AI_CHARS = 12000
RECOVERY_MAX_PROBES = 24
RECOVERY_MAX_AI_PROBES = 6
RECOVERY_MAX_EXECUTED_PROBES = 12
RECOVERY_MAX_PROBE_SECONDS = 180
RECOVERY_MAX_PACMAN_LOG = 256 * 1024
RECOVERY_MAX_JOURNAL = 2000
RECOVERY_SUPPORTED_FILESYSTEMS = {"btrfs", "ext4", "xfs"}
RECOVERY_STORAGE_LAYERS = {"crypto_luks", "lvm2_member", "linux_raid_member"}
RECOVERY_IGNORED_FILESYSTEMS = {"", "swap", "vfat", "fat", "fat32", "iso9660", "squashfs"}
SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9@._+:-]{1,200}$")
SAFE_DEVICE_RE = re.compile(r"^/dev/[A-Za-z0-9._+/-]{1,240}$")
SAFE_UNIT_RE = re.compile(r"^[A-Za-z0-9@_.:-]+\.service$")
CRITICAL_UNIT_PREFIXES = (
    "cryptsetup",
    "dbus",
    "display-manager",
    "getty@",
    "NetworkManager",
    "polkit",
    "sshd",
    "systemd-",
    "systemd-logind",
)


@dataclass
class RecoveryPolicy:
    enabled: bool = False
    bootloader: str = "auto"
    refresh_policy: str = "automatic"
    opted_in_uid: int = -1
    wifi_profiles: str = "ask"
    image_version: str = ""
    last_refresh_status: str = "never"
    last_refresh_error: str = ""
    error: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "enabled": self.enabled,
            "bootloader": self.bootloader,
            "refresh_policy": self.refresh_policy,
            "opted_in_uid": self.opted_in_uid,
            "wifi_profiles": self.wifi_profiles,
            "image_version": self.image_version,
            "last_refresh_status": self.last_refresh_status,
            "last_refresh_error": self.last_refresh_error,
            "error": self.error,
        }


@dataclass
class RecoveryConfig:
    ai_enabled: bool = False
    facts_only: bool = False
    wifi_profiles: str = "ask"
    auto_refresh: bool = True
    error: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "ai_enabled": self.ai_enabled,
            "facts_only": self.facts_only,
            "wifi_profiles": self.wifi_profiles,
            "auto_refresh": self.auto_refresh,
            "error": self.error,
        }


@dataclass
class RecoveryTargetCandidate:
    device: str
    fstype: str = ""
    label: str = ""
    uuid: str = ""
    size: int = 0
    mountpoints: List[str] = field(default_factory=list)
    encrypted: bool = False
    storage_layers: List[str] = field(default_factory=list)
    supported: bool = False
    reason: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "device": self.device,
            "filesystem": self.fstype,
            "label": self.label,
            "uuid": self.uuid,
            "size": self.size,
            "mountpoints": list(self.mountpoints),
            "encrypted": self.encrypted,
            "storage_layers": list(self.storage_layers),
            "supported": self.supported,
            "reason": self.reason,
        }


@dataclass
class RecoveryTarget:
    target_id: str
    root_path: str
    source: str = ""
    distro: Dict[str, object] = field(default_factory=dict)
    filesystem: str = "unknown"
    encrypted: bool = False
    storage_layers: List[str] = field(default_factory=list)
    mounted_read_only: bool = True
    writable: bool = False
    esp_path: str = ""
    bootloader: BootloaderInfo = field(default_factory=BootloaderInfo)
    installed_packages: Dict[str, str] = field(default_factory=dict)
    installed_kernels: List[str] = field(default_factory=list)
    snapshots: List[Dict[str, object]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "target_id": self.target_id,
            "root_path": self.root_path,
            "source": self.source,
            "distro": dict(self.distro),
            "filesystem": self.filesystem,
            "encrypted": self.encrypted,
            "storage_layers": list(self.storage_layers),
            "mounted_read_only": self.mounted_read_only,
            "writable": self.writable,
            "esp_path": self.esp_path,
            "bootloader": self.bootloader.to_dict(),
            "installed_package_count": len(self.installed_packages),
            "installed_packages": dict(self.installed_packages),
            "installed_kernels": list(self.installed_kernels),
            "snapshots": list(self.snapshots),
            "notes": list(self.notes),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "RecoveryTarget":
        boot = data.get("bootloader", {}) if isinstance(data.get("bootloader"), Mapping) else {}
        return cls(
            target_id=str(data.get("target_id") or ""),
            root_path=str(data.get("root_path") or ""),
            source=str(data.get("source") or ""),
            distro=dict(data.get("distro") or {}) if isinstance(data.get("distro"), Mapping) else {},
            filesystem=str(data.get("filesystem") or "unknown"),
            encrypted=bool(data.get("encrypted", False)),
            storage_layers=[str(item) for item in data.get("storage_layers", [])] if isinstance(data.get("storage_layers"), list) else [],
            mounted_read_only=bool(data.get("mounted_read_only", True)),
            writable=bool(data.get("writable", False)),
            esp_path=str(data.get("esp_path") or ""),
            bootloader=BootloaderInfo(
                kind=str(boot.get("kind") or "unknown"),
                name=str(boot.get("name") or "Unknown"),
                config_path=str(boot.get("config_path") or ""),
                installed=bool(boot.get("installed", False)),
                supports_entry=bool(boot.get("supports_entry", False)),
                supports_reinstall=bool(boot.get("supports_reinstall", False)),
                evidence=[str(item) for item in boot.get("evidence", [])] if isinstance(boot.get("evidence"), list) else [],
            ),
            installed_packages=dict(data.get("installed_packages") or {}) if isinstance(data.get("installed_packages"), Mapping) else {},
            installed_kernels=[str(item) for item in data.get("installed_kernels", [])] if isinstance(data.get("installed_kernels"), list) else [],
            snapshots=list(data.get("snapshots", [])) if isinstance(data.get("snapshots"), list) else [],
            notes=[str(item) for item in data.get("notes", [])] if isinstance(data.get("notes"), list) else [],
        )


@dataclass
class RecoveryAction:
    action_id: str
    recipe_id: str
    title: str
    summary: str
    risk: Severity
    parameters: Dict[str, object] = field(default_factory=dict)
    command_preview: List[List[str]] = field(default_factory=list)
    eligible: bool = False
    verified: bool = False
    reversible: bool = False
    backup_description: str = ""
    reason: str = ""
    confirmation_phrase: str = ""
    ai_recommended: bool = False

    def __post_init__(self) -> None:
        if isinstance(self.risk, str):
            self.risk = Severity(self.risk.upper())

    def to_dict(self) -> Dict[str, object]:
        return {
            "action_id": self.action_id,
            "recipe_id": self.recipe_id,
            "title": self.title,
            "summary": self.summary,
            "risk": self.risk.value,
            "parameters": dict(self.parameters),
            "command_preview": [list(item) for item in self.command_preview],
            "eligible": self.eligible,
            "verified": self.verified,
            "reversible": self.reversible,
            "backup_description": self.backup_description,
            "reason": self.reason,
            "confirmation_phrase": self.confirmation_phrase,
            "ai_recommended": self.ai_recommended,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "RecoveryAction":
        raw_commands = data.get("command_preview", [])
        commands = [list(map(str, item)) for item in raw_commands if isinstance(item, list)] if isinstance(raw_commands, list) else []
        return cls(
            action_id=str(data.get("action_id") or ""),
            recipe_id=str(data.get("recipe_id") or ""),
            title=str(data.get("title") or ""),
            summary=str(data.get("summary") or ""),
            risk=str(data.get("risk") or "LOW"),
            parameters=dict(data.get("parameters") or {}) if isinstance(data.get("parameters"), Mapping) else {},
            command_preview=commands,
            eligible=bool(data.get("eligible", False)),
            verified=bool(data.get("verified", False)),
            reversible=bool(data.get("reversible", False)),
            backup_description=str(data.get("backup_description") or ""),
            reason=str(data.get("reason") or ""),
            confirmation_phrase=str(data.get("confirmation_phrase") or ""),
            ai_recommended=bool(data.get("ai_recommended", False)),
        )


@dataclass
class RecoveryRepairResult:
    action_id: str
    recipe_id: str
    status: str
    message: str
    verified: bool = False
    backup_path: str = ""
    rollback_available: bool = False
    output_excerpt: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "action_id": self.action_id,
            "recipe_id": self.recipe_id,
            "status": self.status,
            "message": self.message,
            "verified": self.verified,
            "backup_path": self.backup_path,
            "rollback_available": self.rollback_available,
            "output_excerpt": redact_incident_text(self.output_excerpt)[:4000],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "RecoveryRepairResult":
        return cls(
            action_id=str(data.get("action_id") or ""),
            recipe_id=str(data.get("recipe_id") or ""),
            status=str(data.get("status") or "unknown"),
            message=str(data.get("message") or ""),
            verified=bool(data.get("verified", False)),
            backup_path=str(data.get("backup_path") or ""),
            rollback_available=bool(data.get("rollback_available", False)),
            output_excerpt=redact_incident_text(str(data.get("output_excerpt") or ""))[:4000],
        )


@dataclass
class RecoveryReport:
    recovery_id: str
    target: RecoveryTarget
    created_at: int = field(default_factory=lambda: int(time.time()))
    network: RecoveryNetworkState = field(default_factory=RecoveryNetworkState)
    incident_report: Optional[IncidentReport] = None
    diagnostic_probes: List[DiagnosticProbe] = field(default_factory=list)
    probe_results: List[DiagnosticProbeResult] = field(default_factory=list)
    repair_actions: List[RecoveryAction] = field(default_factory=list)
    repair_results: List[RecoveryRepairResult] = field(default_factory=list)
    backups: List[Dict[str, object]] = field(default_factory=list)
    post_repair: Dict[str, object] = field(default_factory=dict)
    ai_review: Dict[str, object] = field(default_factory=dict)
    complete: bool = True
    notes: List[str] = field(default_factory=list)
    schema_version: str = RECOVERY_SCHEMA_VERSION
    scanner_version: str = SCANNER_VERSION

    @property
    def findings(self) -> List[IncidentFinding]:
        return self.incident_report.findings if self.incident_report else []

    @property
    def highest_severity(self) -> Severity:
        if not self.findings:
            return Severity.LOW
        return max((item.severity for item in self.findings), key=SEVERITY_ORDER.index)

    @property
    def eligible_actions(self) -> List[RecoveryAction]:
        return [item for item in self.repair_actions if item.eligible and item.verified]

    @property
    def apply_prompt_default_yes(self) -> bool:
        incomplete_probe = any(
            item.affects_plan and item.status in {"failed", "timeout", "incomplete", "unavailable"}
            for item in self.probe_results
        )
        network_recipes = {"complete_pacman_transaction", "kernel_module_restore", "kernel_headers_install"}
        network_unavailable = any(
            item.recipe_id in network_recipes for item in self.eligible_actions
        ) and (not self.network.connected or self.network.captive_portal)
        unresolved = any(
            item.severity in {Severity.HIGH, Severity.CRITICAL}
            and not any(str(action.parameters.get("category") or "") == item.category for action in self.eligible_actions)
            for item in self.findings
        )
        return bool(self.complete and self.eligible_actions and not incomplete_probe and not network_unavailable and not unresolved)

    def to_dict(self) -> Dict[str, object]:
        return {
            "schema": f"{RECOVERY_REPORT_TYPE}/{self.schema_version}",
            "schema_version": self.schema_version,
            "scanner_version": self.scanner_version,
            "report_type": RECOVERY_REPORT_TYPE,
            "recovery_id": self.recovery_id,
            "created_at": self.created_at,
            "target": self.target.to_dict(),
            "network": self.network.to_dict(),
            "incident_report": self.incident_report.to_dict() if self.incident_report else {},
            "diagnostic_probes": [item.to_dict() for item in self.diagnostic_probes],
            "probe_results": [item.to_dict() for item in self.probe_results],
            "repair_actions": [item.to_dict() for item in self.repair_actions],
            "repair_results": [item.to_dict() for item in self.repair_results],
            "backups": list(self.backups),
            "post_repair": dict(self.post_repair),
            "ai_review": dict(self.ai_review),
            "complete": self.complete,
            "notes": list(self.notes),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "RecoveryReport":
        schema_version = str(data.get("schema_version") or str(data.get("schema") or "").partition("/")[2] or RECOVERY_SCHEMA_VERSION)
        if schema_version != RECOVERY_SCHEMA_VERSION:
            raise ValueError(f"unsupported recovery report schema: {schema_version}")
        incident_data = data.get("incident_report", {})
        incident = IncidentReport.from_dict(incident_data) if isinstance(incident_data, Mapping) and incident_data else None
        network_data = data.get("network", {}) if isinstance(data.get("network"), Mapping) else {}
        network = RecoveryNetworkState(
            available=bool(network_data.get("available", False)),
            connected=bool(network_data.get("connected", False)),
            connectivity=str(network_data.get("connectivity") or "unknown"),
            connection_type=str(network_data.get("connection_type") or ""),
            connection_name=str(network_data.get("connection_name") or ""),
            captive_portal=bool(network_data.get("captive_portal", False)),
            imported_profiles=int(network_data.get("imported_profiles") or 0),
            notes=[str(item) for item in network_data.get("notes", [])] if isinstance(network_data.get("notes"), list) else [],
        )
        return cls(
            recovery_id=str(data.get("recovery_id") or ""),
            target=RecoveryTarget.from_dict(data.get("target", {}) if isinstance(data.get("target"), Mapping) else {}),
            created_at=int(data.get("created_at") or 0),
            network=network,
            incident_report=incident,
            diagnostic_probes=[DiagnosticProbe.from_dict(item) for item in data.get("diagnostic_probes", []) if isinstance(item, Mapping)] if isinstance(data.get("diagnostic_probes"), list) else [],
            probe_results=[DiagnosticProbeResult.from_dict(item) for item in data.get("probe_results", []) if isinstance(item, Mapping)] if isinstance(data.get("probe_results"), list) else [],
            repair_actions=[RecoveryAction.from_dict(item) for item in data.get("repair_actions", []) if isinstance(item, Mapping)] if isinstance(data.get("repair_actions"), list) else [],
            repair_results=[RecoveryRepairResult.from_dict(item) for item in data.get("repair_results", []) if isinstance(item, Mapping)] if isinstance(data.get("repair_results"), list) else [],
            backups=list(data.get("backups", [])) if isinstance(data.get("backups"), list) else [],
            post_repair=dict(data.get("post_repair") or {}) if isinstance(data.get("post_repair"), Mapping) else {},
            ai_review=dict(data.get("ai_review") or {}) if isinstance(data.get("ai_review"), Mapping) else {},
            complete=bool(data.get("complete", True)),
            notes=[str(item) for item in data.get("notes", [])] if isinstance(data.get("notes"), list) else [],
            schema_version=schema_version,
            scanner_version=str(data.get("scanner_version") or SCANNER_VERSION),
        )

    def render_terminal(self, *, verbose: bool = False) -> str:
        lines = [
            "\n[AuraScan] AI-Assisted Recovery",
            "=" * 56,
            f"Target: {self.target.distro.get('name', 'Unknown')} | Filesystem: {self.target.filesystem} | Bootloader: {self.target.bootloader.name}",
            f"Findings: {len(self.findings)} | Risk: {self.highest_severity.value} | Verified repairs: {len(self.eligible_actions)}",
            f"Network: {'connected' if self.network.connected else 'offline'} | AI: {self.ai_review.get('status', 'not run')}",
            "-" * 56,
        ]
        if not self.findings:
            lines.append("[OK] No recognized boot-blocking or package-state problem was found.")
        for index, finding in enumerate(self.findings if verbose else self.findings[:6], start=1):
            lines.append(f"{index}. {finding.title} [{finding.severity.value}]")
            lines.append(finding.summary)
            if finding.recommended_action:
                lines.append("AuraScan response: " + finding.recommended_action)
        if len(self.findings) > 6 and not verbose:
            lines.append(f"{len(self.findings) - 6} additional findings hidden. Use --verbose to show all.")
        if self.eligible_actions:
            lines.append("\nRecommended recovery plan:")
            ordered = sorted(self.eligible_actions, key=lambda item: (not item.ai_recommended, recovery_recipe_order(item.recipe_id)))
            for index, action in enumerate(ordered, start=1):
                suffix = " | AI recommended" if action.ai_recommended else ""
                lines.append(f"{index}. {action.title} [{action.risk.value}{suffix}]")
                lines.append(action.summary)
                if action.confirmation_phrase:
                    lines.append("   Requires separate typed confirmation.")
                if verbose:
                    for command in action.command_preview:
                        lines.append("   Command: " + " ".join(command))
        if self.probe_results:
            successful = sum(item.status not in {"failed", "timeout"} for item in self.probe_results)
            lines.append(f"\nLocal verification: {successful}/{len(self.probe_results)} probe(s) completed.")
        summary = str(self.ai_review.get("summary") or "")
        if summary:
            lines.append("\nAI explanation: " + summary)
        if self.notes:
            lines.append("\nRecovery notes:")
            lines.extend("- " + item for item in self.notes[:10])
        if self.repair_results:
            lines.append("\nRepair results:")
            lines.extend(f"- {item.status}: {item.message}" for item in self.repair_results)
        return "\n".join(lines)


def rooted(root: Path, path: Path) -> Path:
    return path if Path(root) == Path("/") else Path(root) / str(path).lstrip("/")


def _safe_target_file(path: Path, root: Path, *, allow_symlink: bool = False, max_size: int = 4 * 1024 * 1024) -> bool:
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
        metadata = resolved.stat()
        return (
            (allow_symlink or not path.is_symlink())
            and stat.S_ISREG(metadata.st_mode)
            and 0 <= metadata.st_size <= max_size
        )
    except (OSError, ValueError):
        return False


def _root_owned_target_file(path: Path, root: Path, *, max_size: int) -> bool:
    if not _safe_target_file(path, root, max_size=max_size):
        return False
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return not path.is_symlink() and stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0


def _safe_target_directory(path: Path, root: Path) -> bool:
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root.resolve(strict=True))
        metadata = path.lstat()
        return not path.is_symlink() and stat.S_ISDIR(metadata.st_mode)
    except (OSError, ValueError):
        return False


def _target_distro(root: Path) -> DistroInfo:
    path = rooted(root, Path("/etc/os-release"))
    if not _safe_target_file(path, root, allow_symlink=True, max_size=64 * 1024):
        return DistroInfo(caveat="Could not safely read target /etc/os-release.")
    try:
        return distro_from_os_release(parse_os_release(path.read_text(encoding="utf-8", errors="replace")))
    except OSError:
        return DistroInfo(caveat="Could not read target /etc/os-release.")


def parse_recovery_policy(text: str) -> RecoveryPolicy:
    values = parse_env_lines(text.splitlines())
    enabled = parse_bool(values.get("AURASCAN_RECOVERY_ENABLED"))
    if values.get("AURASCAN_RECOVERY_ENABLED") is not None and enabled is None:
        return RecoveryPolicy(error="invalid AURASCAN_RECOVERY_ENABLED value")
    refresh = values.get("AURASCAN_RECOVERY_REFRESH", "automatic").strip().lower()
    wifi = values.get("AURASCAN_RECOVERY_WIFI_PROFILES", "ask").strip().lower()
    bootloader = values.get("AURASCAN_RECOVERY_BOOTLOADER", "auto").strip().lower()
    if refresh not in RECOVERY_REFRESH_VALUES:
        return RecoveryPolicy(error="invalid AURASCAN_RECOVERY_REFRESH value")
    if wifi not in RECOVERY_WIFI_PROFILE_VALUES:
        return RecoveryPolicy(error="invalid AURASCAN_RECOVERY_WIFI_PROFILES value")
    if bootloader not in {"auto", "limine", "systemd-boot", "grub"}:
        return RecoveryPolicy(error="invalid AURASCAN_RECOVERY_BOOTLOADER value")
    try:
        opted_uid = int(values.get("AURASCAN_RECOVERY_OPTED_UID", "-1"))
    except ValueError:
        return RecoveryPolicy(error="invalid AURASCAN_RECOVERY_OPTED_UID value")
    return RecoveryPolicy(
        enabled=bool(enabled),
        bootloader=bootloader,
        refresh_policy=refresh,
        opted_in_uid=opted_uid,
        wifi_profiles=wifi,
        image_version=values.get("AURASCAN_RECOVERY_IMAGE_VERSION", "")[:80],
        last_refresh_status=values.get("AURASCAN_RECOVERY_LAST_REFRESH", "never")[:80],
        last_refresh_error=values.get("AURASCAN_RECOVERY_LAST_ERROR", "")[:500],
    )


def read_recovery_policy(path: Path = RECOVERY_POLICY_PATH) -> RecoveryPolicy:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            return RecoveryPolicy(error="recovery policy is not a regular non-symlink file")
        if metadata.st_uid != 0 and Path(path).is_absolute():
            return RecoveryPolicy(error="recovery policy is not root-owned")
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            return RecoveryPolicy(error="recovery policy is writable by group or others")
        return parse_recovery_policy(path.read_text(encoding="utf-8", errors="replace"))
    except FileNotFoundError:
        return RecoveryPolicy()
    except OSError as exc:
        return RecoveryPolicy(error=f"recovery policy could not be read: {exc}")


def render_recovery_policy(policy: RecoveryPolicy) -> str:
    safe_error = policy.last_refresh_error.replace("\n", " ").replace("\r", " ")[:500]
    return "\n".join([
        "# Root-owned AuraScan Recovery policy. No credentials belong in this file.",
        f"AURASCAN_RECOVERY_ENABLED={'1' if policy.enabled else '0'}",
        f"AURASCAN_RECOVERY_BOOTLOADER={policy.bootloader}",
        f"AURASCAN_RECOVERY_REFRESH={policy.refresh_policy}",
        f"AURASCAN_RECOVERY_OPTED_UID={policy.opted_in_uid}",
        f"AURASCAN_RECOVERY_WIFI_PROFILES={policy.wifi_profiles}",
        f"AURASCAN_RECOVERY_IMAGE_VERSION={policy.image_version}",
        f"AURASCAN_RECOVERY_LAST_REFRESH={policy.last_refresh_status}",
        f"AURASCAN_RECOVERY_LAST_ERROR={safe_error}",
        "",
    ])


def write_recovery_policy(policy: RecoveryPolicy, path: Path = RECOVERY_POLICY_PATH, *, require_root: bool = True) -> None:
    if require_root and os.geteuid() != 0:
        raise PermissionError("writing recovery policy requires root")
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent), text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(render_recovery_policy(policy))
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def resolve_recovery_config(
    env: Optional[Mapping[str, str]] = None,
    *,
    policy: Optional[RecoveryPolicy] = None,
) -> RecoveryConfig:
    source = os.environ if env is None else env
    recovery_policy = policy or RecoveryPolicy()
    ai_raw = source.get(RECOVERY_AI_ENABLED_ENV)
    ai_enabled = parse_bool(ai_raw)
    if ai_raw is not None and ai_enabled is None:
        return RecoveryConfig(error=f"invalid {RECOVERY_AI_ENABLED_ENV} value")
    refresh_raw = source.get(RECOVERY_AUTO_REFRESH_ENV)
    auto_refresh = parse_bool(refresh_raw)
    if refresh_raw is not None and auto_refresh is None:
        return RecoveryConfig(error=f"invalid {RECOVERY_AUTO_REFRESH_ENV} value")
    wifi = source.get(RECOVERY_WIFI_PROFILES_ENV, recovery_policy.wifi_profiles).strip().lower()
    if wifi not in RECOVERY_WIFI_PROFILE_VALUES:
        return RecoveryConfig(error=f"invalid {RECOVERY_WIFI_PROFILES_ENV} value")
    evidence_policy = source.get(INCIDENT_AI_EVIDENCE_ENV, "redacted").strip().lower() or "redacted"
    if evidence_policy not in INCIDENT_AI_EVIDENCE_VALUES:
        return RecoveryConfig(error=f"invalid {INCIDENT_AI_EVIDENCE_ENV} value")
    return RecoveryConfig(
        ai_enabled=bool(ai_enabled),
        wifi_profiles=wifi,
        auto_refresh=True if auto_refresh is None else bool(auto_refresh),
        facts_only=evidence_policy == "facts-only",
    )


def load_opted_user_ai_environment(target_root: Path, uid: int) -> Tuple[Dict[str, str], str]:
    if uid < 0:
        return {}, "Recovery AI has no opted-in user."
    passwd_path = rooted(target_root, Path("/etc/passwd"))
    if not _safe_target_file(passwd_path, target_root, max_size=4 * 1024 * 1024):
        return {}, "The target user database failed path or file validation."
    try:
        entries = passwd_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return {}, "The target user database could not be read."
    home = ""
    for entry in entries:
        fields = entry.split(":")
        if len(fields) >= 7 and fields[2].isdigit() and int(fields[2]) == uid:
            home = fields[5]
            break
    if not home.startswith("/") or home in {"/", "/root"} or ".." in Path(home).parts:
        return {}, "The opted-in user home could not be resolved safely."
    config = rooted(target_root, Path(home) / ".config/aurascan/.env")
    try:
        config.resolve(strict=False).relative_to(target_root.resolve(strict=False))
    except (OSError, ValueError):
        return {}, "The opted-in AI config escaped the mounted target."
    try:
        metadata = config.lstat()
        if config.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            return {}, "The opted-in AI config is not a regular file."
        if metadata.st_uid != uid or stat.S_IMODE(metadata.st_mode) != 0o600:
            return {}, "The opted-in AI config failed owner or 0600 mode validation."
        values = parse_env_lines(config.read_text(encoding="utf-8", errors="replace").splitlines())
    except OSError as exc:
        return {}, f"The opted-in AI config could not be read: {exc}"
    return values, "validated"


def _flatten_lsblk(nodes: Sequence[Mapping[str, object]], parents: Sequence[str] = ()) -> List[Tuple[Mapping[str, object], List[str]]]:
    flattened: List[Tuple[Mapping[str, object], List[str]]] = []
    for node in nodes:
        current_layers = list(parents)
        fstype = str(node.get("fstype") or "").lower()
        if fstype in RECOVERY_STORAGE_LAYERS:
            current_layers.append(fstype)
        flattened.append((node, current_layers))
        children = node.get("children", [])
        if isinstance(children, list):
            flattened.extend(_flatten_lsblk([item for item in children if isinstance(item, Mapping)], current_layers))
    return flattened


def discover_recovery_target_candidates(
    *,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
) -> List[RecoveryTargetCandidate]:
    if not which("lsblk"):
        return []
    command = ["lsblk", "--json", "--bytes", "--output", "PATH,FSTYPE,LABEL,UUID,SIZE,MOUNTPOINTS,TYPE"]
    result = runner(command, capture_output=True, text=True, timeout=20, check=False)
    try:
        payload = json.loads(result.stdout) if result.returncode == 0 else {}
    except ValueError:
        payload = {}
    nodes = payload.get("blockdevices", []) if isinstance(payload, Mapping) else []
    candidates: List[RecoveryTargetCandidate] = []
    for node, layers in _flatten_lsblk([item for item in nodes if isinstance(item, Mapping)]):
        device = str(node.get("path") or "")
        fstype = str(node.get("fstype") or "").lower()
        if not device or fstype in RECOVERY_IGNORED_FILESYSTEMS:
            continue
        mounts = node.get("mountpoints") or []
        mountpoints = [str(item) for item in mounts if item] if isinstance(mounts, list) else []
        encrypted = "crypto_luks" in layers or fstype == "crypto_luks"
        supported = fstype in RECOVERY_SUPPORTED_FILESYSTEMS or fstype == "crypto_luks"
        if supported:
            reason = ""
        elif fstype in RECOVERY_STORAGE_LAYERS:
            reason = "Activate this storage container and select its filesystem child."
        else:
            reason = "This filesystem is visible for diagnosis only; AuraScan will not mount or repair it."
        candidates.append(RecoveryTargetCandidate(
            device=device,
            fstype=fstype,
            label=str(node.get("label") or "")[:120],
            uuid=str(node.get("uuid") or "")[:120],
            size=int(node.get("size") or 0),
            mountpoints=mountpoints,
            encrypted=encrypted,
            storage_layers=layers,
            supported=supported,
            reason=reason,
        ))
    return sorted(candidates, key=lambda item: (not item.supported, item.device))[:100]


def activate_recovery_storage_layers(
    *,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
) -> List[str]:
    """Activate already configured mdraid/LVM containers without filesystem writes."""
    notes: List[str] = []
    if which("mdadm"):
        result = runner(["mdadm", "--assemble", "--scan", "--readonly"], capture_output=True, text=True, timeout=60, check=False)
        notes.append("mdraid discovery completed." if result.returncode in {0, 1, 2} else "mdraid discovery was incomplete.")
    if which("vgchange") or which("lvm"):
        command = [which("vgchange") or "vgchange", "--activate", "y", "--readonly"]
        result = runner(command, capture_output=True, text=True, timeout=60, check=False)
        notes.append("LVM logical volumes were activated for discovery." if result.returncode == 0 else "LVM discovery was incomplete.")
    return notes


def mount_target_esp_read_only(
    target_root: Path,
    *,
    runner: Callable = subprocess.run,
) -> Tuple[Optional[Path], str]:
    fstab = rooted(target_root, Path("/etc/fstab"))
    try:
        lines = fstab.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None, "Target fstab is unavailable; a separate ESP was not mounted."
    for raw in lines[:500]:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) < 3 or fields[1] not in {"/boot", "/efi", "/boot/efi"}:
            continue
        source, mountpoint, fstype = fields[:3]
        if fstype.lower() not in {"vfat", "fat", "fat32", "auto"}:
            continue
        if (
            not re.fullmatch(r"(?:UUID|PARTUUID|LABEL|PARTLABEL)=[A-Za-z0-9._+:-]+|/dev/[A-Za-z0-9._+/-]+", source)
            or ".." in Path(source).parts
        ):
            return None, "ESP source in fstab did not pass safe identifier validation."
        destination = rooted(target_root, Path(mountpoint))
        try:
            destination.mkdir(parents=True, mode=0o755, exist_ok=True)
        except OSError:
            return None, "Target ESP mountpoint is unavailable on the read-only installation."
        check = runner(["findmnt", "--noheadings", "--target", str(destination)], capture_output=True, text=True, timeout=10, check=False)
        if check.returncode == 0 and check.stdout.strip():
            return destination, "Target ESP was already mounted."
        result = runner(["mount", "-o", "ro,nosuid,nodev,noexec", source, str(destination)], capture_output=True, text=True, timeout=60, check=False)
        if result.returncode == 0:
            return destination, "Target ESP was mounted read-only."
        return None, "Target ESP could not be mounted read-only."
    return None, "No separate ESP mount was declared in target fstab."


def _read_pacman_local_db(root: Path) -> Dict[str, str]:
    database = rooted(root, Path("/var/lib/pacman/local"))
    packages: Dict[str, str] = {}
    try:
        if database.is_symlink():
            return packages
        database.resolve(strict=True).relative_to(root.resolve(strict=True))
        directories = sorted(database.iterdir())[:20000]
    except (OSError, ValueError):
        return packages
    for directory in directories:
        if directory.is_symlink():
            continue
        try:
            directory.resolve(strict=False).relative_to(database.resolve(strict=False))
        except (OSError, ValueError):
            continue
        desc = directory / "desc"
        try:
            if desc.is_symlink() or not desc.is_file():
                continue
            lines = desc.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        fields: Dict[str, str] = {}
        key = ""
        for line in lines:
            if line.startswith("%") and line.endswith("%"):
                key = line.strip("%")
            elif key and line:
                fields.setdefault(key, line)
                key = ""
        name = fields.get("NAME", "")
        version = fields.get("VERSION", "")
        if SAFE_NAME_RE.fullmatch(name):
            packages[name] = version[:200]
    return packages


def _detect_target_filesystem(root: Path, runner: Callable = subprocess.run) -> str:
    result = runner(["findmnt", "--noheadings", "--output", "FSTYPE", "--target", str(root)], capture_output=True, text=True, timeout=10, check=False)
    return result.stdout.strip().splitlines()[0].lower() if result.returncode == 0 and result.stdout.strip() else "unknown"


def _detect_esp(root: Path) -> Path:
    candidates = [rooted(root, Path("/boot")), rooted(root, Path("/efi")), rooted(root, Path("/boot/efi"))]
    for candidate in candidates:
        if (candidate / "EFI").exists() or (candidate / "loader").exists() or (candidate / "limine.conf").exists():
            return candidate
    return candidates[0]


def _read_snapshots(root: Path) -> List[Dict[str, object]]:
    snapshots: List[Dict[str, object]] = []
    snapshot_root = rooted(root, Path("/.snapshots"))
    try:
        if snapshot_root.is_symlink():
            return snapshots
        snapshot_root.resolve(strict=True).relative_to(root.resolve(strict=True))
        entries = sorted(
            snapshot_root.iterdir(),
            key=lambda item: int(item.name) if item.name.isdigit() else 2 ** 63,
        )[:500]
    except (OSError, ValueError):
        return snapshots
    for entry in entries:
        if entry.is_symlink() or not entry.name.isdigit() or (entry / "snapshot").is_symlink() or not (entry / "snapshot").is_dir():
            continue
        snapshots.append({"id": int(entry.name), "path": f"/.snapshots/{entry.name}/snapshot"})
    return snapshots


def inspect_recovery_target(
    root: Path,
    *,
    source: str = "",
    mounted_read_only: bool = True,
    encrypted: bool = False,
    storage_layers: Sequence[str] = (),
    filesystem_hint: str = "",
    runner: Callable = subprocess.run,
) -> RecoveryTarget:
    root = Path(root).resolve()
    distro = _target_distro(root)
    packages = _read_pacman_local_db(root)
    kernels = sorted(
        name for name in packages
        if name in {"linux", "linux-lts", "linux-zen", "linux-hardened"} or name.startswith("linux-cachyos")
        if not name.endswith("-headers") and "nvidia" not in name and "zfs" not in name
    )
    esp = _detect_esp(root)
    bootloader = detect_bootloader(root, esp)
    target_material = f"{source}|{root}|{distro.distro_id}"
    return RecoveryTarget(
        target_id=hashlib.sha256(target_material.encode("utf-8", "replace")).hexdigest()[:16],
        root_path=str(root),
        source=source,
        distro=distro.to_dict(),
        filesystem=filesystem_hint if filesystem_hint in RECOVERY_SUPPORTED_FILESYSTEMS else _detect_target_filesystem(root, runner=runner),
        encrypted=encrypted,
        storage_layers=list(storage_layers),
        mounted_read_only=mounted_read_only,
        writable=os.access(root, os.W_OK) and not mounted_read_only,
        esp_path=str(esp),
        bootloader=bootloader,
        installed_packages=packages,
        installed_kernels=kernels,
        snapshots=_read_snapshots(root),
    )


def find_mounted_recovery_targets(
    search_roots: Sequence[Path] = (Path("/sysroot"), Path("/mnt"), RECOVERY_TARGET_MOUNT),
    *,
    runner: Callable = subprocess.run,
) -> List[RecoveryTarget]:
    targets: List[RecoveryTarget] = []
    seen: set = set()
    for candidate in search_roots:
        paths = [candidate]
        try:
            paths.extend(item for item in candidate.iterdir() if item.is_dir())
        except OSError:
            pass
        for path in paths[:100]:
            resolved = path.resolve()
            if str(resolved) in seen or not rooted(resolved, Path("/etc/os-release")).is_file():
                continue
            seen.add(str(resolved))
            target = inspect_recovery_target(resolved, runner=runner)
            if target.distro.get("arch_family"):
                targets.append(target)
    return targets


def mount_recovery_target_read_only(
    candidate: RecoveryTargetCandidate,
    *,
    mount_root: Path = RECOVERY_TARGET_MOUNT,
    unlock_secret_func: Optional[Callable[[str], str]] = None,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
) -> Tuple[Optional[RecoveryTarget], str]:
    if os.geteuid() != 0:
        return None, "Mounting a recovery target requires root privileges."
    if not candidate.supported or not SAFE_DEVICE_RE.fullmatch(candidate.device) or ".." in Path(candidate.device).parts:
        return None, "The selected recovery target is unsupported or unsafe."
    device = candidate.device
    layers = list(candidate.storage_layers)
    opened_mapping = ""
    if candidate.fstype == "crypto_luks":
        if not which("cryptsetup"):
            return None, "cryptsetup is unavailable."
        if unlock_secret_func is None:
            return None, "The encrypted target requires an interactive unlock password."
        try:
            passphrase = unlock_secret_func(f"Unlock password for {device}: ")
        except (EOFError, KeyboardInterrupt):
            return None, "Encrypted target unlock was cancelled."
        if not passphrase or "\n" in passphrase or "\r" in passphrase:
            return None, "Encrypted target unlock was cancelled."
        mapping = "aurascan-target-" + hashlib.sha256(device.encode()).hexdigest()[:8]
        result = runner(
            ["cryptsetup", "open", "--readonly", "--type", "luks2", "--key-file", "-", device, mapping],
            input=passphrase,
            text=True,
            timeout=120,
            check=False,
        )
        passphrase = ""
        if result.returncode != 0:
            return None, "The encrypted target could not be unlocked."
        device = f"/dev/mapper/{mapping}"
        opened_mapping = mapping
        layers.append("crypto_luks")
    mount_root.mkdir(parents=True, mode=0o700, exist_ok=True)
    mapped_fstype = candidate.fstype
    if candidate.fstype == "crypto_luks":
        probe = runner(["lsblk", "--noheadings", "--output", "FSTYPE", device], capture_output=True, text=True, timeout=10, check=False)
        if probe.returncode == 0 and probe.stdout.strip():
            mapped_fstype = probe.stdout.strip().splitlines()[0].lower()
    command = ["mount", "-o", "ro,nosuid,nodev", device, str(mount_root)]
    if mapped_fstype == "btrfs":
        command = ["mount", "-o", "ro,nosuid,nodev,subvolid=5", device, str(mount_root)]
    elif mapped_fstype == "ext4":
        command = ["mount", "-o", "ro,noload,nosuid,nodev", device, str(mount_root)]
    elif mapped_fstype == "xfs":
        command = ["mount", "-o", "ro,norecovery,nosuid,nodev", device, str(mount_root)]
    result = runner(command, capture_output=True, text=True, timeout=60, check=False)
    if result.returncode != 0:
        if opened_mapping:
            runner(["cryptsetup", "close", opened_mapping], capture_output=True, text=True, timeout=30, check=False)
        return None, "The selected target could not be mounted read-only."
    roots = [mount_root]
    try:
        roots.extend(item for item in mount_root.iterdir() if item.is_dir())
    except OSError:
        pass
    root = next((item for item in roots if rooted(item, Path("/etc/os-release")).is_file()), None)
    if root is None:
        runner(["umount", str(mount_root)], capture_output=True, text=True, timeout=30, check=False)
        if opened_mapping:
            runner(["cryptsetup", "close", opened_mapping], capture_output=True, text=True, timeout=30, check=False)
        return None, "No Arch-family installation was found in the mounted filesystem."
    esp, esp_note = mount_target_esp_read_only(root, runner=runner)
    target = inspect_recovery_target(
        root,
        source=candidate.device,
        mounted_read_only=True,
        encrypted=candidate.encrypted,
        storage_layers=layers,
        filesystem_hint=mapped_fstype,
        runner=runner,
    )
    if not target.distro.get("arch_family"):
        runner(["umount", str(mount_root)], capture_output=True, text=True, timeout=30, check=False)
        if opened_mapping:
            runner(["cryptsetup", "close", opened_mapping], capture_output=True, text=True, timeout=30, check=False)
        return None, "The mounted operating system is not a supported Arch-family target."
    target.notes.append(esp_note)
    if esp is not None:
        target.esp_path = str(esp)
        target.bootloader = detect_bootloader(Path(target.root_path), esp)
    return target, "Recovery target mounted read-only."


def _evidence(source: str, message: str, severity: Severity = Severity.LOW) -> IncidentEvidence:
    clean = redact_incident_text(message)[:4000]
    digest = hashlib.sha256(f"{source}|{clean}".encode("utf-8", "replace")).hexdigest()[:16]
    return IncidentEvidence(f"rec-{digest}", source, clean, severity=severity)


def _finding(
    rule_id: str,
    severity: Severity,
    title: str,
    summary: str,
    category: str,
    evidence_ids: Sequence[str],
    action: str,
    *,
    confidence: Confidence = Confidence.HIGH,
) -> IncidentFinding:
    return IncidentFinding(
        rule_id,
        severity,
        confidence,
        title,
        summary,
        "This condition can prevent the installed system from completing boot or package recovery safely.",
        action,
        category,
        list(evidence_ids),
    )


def _repository_health(root: Path) -> Tuple[List[Path], List[Tuple[Path, Path]]]:
    config = rooted(root, Path("/etc/pacman.conf"))
    includes: List[Path] = []
    try:
        if not _safe_target_file(config, root, max_size=2 * 1024 * 1024):
            return [], []
        lines = config.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return [], []
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or not stripped.lower().startswith("include") or "=" not in stripped:
            continue
        pattern = stripped.split("=", 1)[1].strip()
        target_pattern_path = rooted(root, Path(pattern))
        static_parent = Path(str(target_pattern_path).split("*", 1)[0].split("?", 1)[0]).parent
        try:
            static_parent.resolve(strict=False).relative_to(root.resolve(strict=False))
        except (OSError, ValueError):
            continue
        target_pattern = str(target_pattern_path)
        for item in glob.glob(target_pattern)[:100]:
            candidate = Path(item)
            try:
                candidate.resolve(strict=False).relative_to(root.resolve(strict=False))
            except (OSError, ValueError):
                continue
            if _safe_target_file(candidate, root, max_size=2 * 1024 * 1024):
                includes.append(candidate)
    broken: List[Path] = []
    repairs: List[Tuple[Path, Path]] = []
    for include in sorted(set(includes)):
        try:
            active = any(line.strip().lower().startswith("server") and not line.lstrip().startswith("#") for line in include.read_text(encoding="utf-8", errors="replace").splitlines())
        except OSError:
            active = False
        if active:
            continue
        broken.append(include)
        for suffix in (".pacnew", ".pacsave", ".backup", ".bak"):
            backup = Path(str(include) + suffix)
            try:
                if not _safe_target_file(backup, root, max_size=2 * 1024 * 1024):
                    continue
                valid = any(line.strip().lower().startswith("server") and not line.lstrip().startswith("#") for line in backup.read_text(encoding="utf-8", errors="replace").splitlines())
            except OSError:
                valid = False
            if valid and backup.is_file() and not backup.is_symlink():
                repairs.append((include, backup))
                break
    return broken, repairs


def _latest_pacman_log(root: Path) -> str:
    path = rooted(root, Path("/var/log/pacman.log"))
    try:
        if not _safe_target_file(path, root, max_size=4 * 1024 * 1024 * 1024):
            return ""
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - RECOVERY_MAX_PACMAN_LOG))
            return handle.read(RECOVERY_MAX_PACMAN_LOG).decode("utf-8", "replace")
    except OSError:
        return ""


def _transaction_incomplete(log_text: str) -> bool:
    tail = log_text.lower().splitlines()[-500:]
    joined = "\n".join(tail)
    failure = max(joined.rfind("transaction failed"), joined.rfind("failed to commit transaction"))
    success = max(joined.rfind("transaction completed"), joined.rfind("system upgraded"), joined.rfind("installed "))
    return failure >= 0 and failure > success


def _initramfs_status(target: RecoveryTarget) -> Tuple[List[str], List[str]]:
    root = Path(target.root_path)
    images = []
    for pattern in ("boot/initramfs*.img", "boot/EFI/Linux/*.efi"):
        images.extend(str(path.relative_to(root)) for path in root.glob(pattern) if _safe_target_file(path, root, max_size=2 * 1024 * 1024 * 1024))
    missing = []
    for kernel in target.installed_kernels:
        expected = f"initramfs-{kernel}"
        image_match = any(
            Path(path).name == f"{expected}.img"
            or Path(path).name.startswith(f"{expected}-fallback.")
            for path in images
        )
        uki_match = any(
            Path(path).suffix.lower() == ".efi"
            and (
                (kernel == "linux" and Path(path).stem in {"linux", "arch-linux"})
                or (kernel != "linux" and kernel in Path(path).stem)
            )
            for path in images
        )
        if not image_match and not uki_match:
            missing.append(kernel)
    return sorted(images), missing


def _boot_config_drift(root: Path) -> List[Path]:
    patterns = (
        "etc/mkinitcpio.conf.pacnew",
        "etc/default/grub.pacnew",
        "etc/default/limine.pacnew",
        "etc/fstab.pacnew",
        "etc/crypttab.pacnew",
        "boot/loader/loader.conf.pacnew",
    )
    return [root / item for item in patterns if (root / item).is_file() and not (root / item).is_symlink()]


def _collect_target_journal_findings(
    root: Path,
    *,
    runner: Callable,
    which: Callable[[str], Optional[str]],
) -> Tuple[List[IncidentEvidence], List[IncidentFinding], List[str]]:
    journal_root = rooted(root, Path("/var/log/journal"))
    if not which("journalctl") or not _safe_target_directory(journal_root, root):
        return [], [], []
    command = [
        "journalctl",
        f"--directory={journal_root}",
        "--boot=0",
        "--priority=0..4",
        "--no-pager",
        f"--lines={RECOVERY_MAX_JOURNAL}",
    ]
    try:
        result = runner(command, capture_output=True, text=True, timeout=45, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return [], [], ["Target journal could not be read: " + redact_incident_text(str(exc))[:500]]
    if result.returncode not in {0, 1}:
        return [], [], ["Target journal query failed; file-based recovery checks continued."]
    text = (result.stdout or "")[:256 * 1024]
    evidence: List[IncidentEvidence] = []
    findings: List[IncidentFinding] = []
    seen_rules = set()
    for line in text.splitlines()[:RECOVERY_MAX_JOURNAL]:
        clean = redact_incident_text(line)[:2000]
        for rule in INCIDENT_RULES:
            if rule.rule_id in seen_rules or not rule.pattern.search(clean):
                continue
            item = _evidence("target-journal", clean, rule.severity)
            evidence.append(item)
            findings.append(IncidentFinding(
                rule.rule_id,
                rule.severity,
                rule.confidence,
                rule.title,
                clean,
                rule.why,
                rule.action,
                rule.category,
                [item.evidence_id],
            ))
            seen_rules.add(rule.rule_id)
        if "INC-SYSTEMD-FAILED" not in seen_rules and re.search(
            r"(?i)failed to start|dependency failed|start operation timed out|job .* failed",
            clean,
        ) and re.search(r"\b[A-Za-z0-9@_.:-]+\.service\b", clean):
            item = _evidence("target-journal", clean, Severity.MEDIUM)
            evidence.append(item)
            findings.append(IncidentFinding(
                "INC-SYSTEMD-FAILED",
                Severity.MEDIUM,
                Confidence.HIGH,
                "A service blocked or failed during the latest boot",
                clean,
                "A failed noncritical service can delay or prevent a usable boot, while critical services require manual recovery judgment.",
                "AuraScan will identify and freshly validate only noncritical service candidates before offering a reversible disable action.",
                "failed_service",
                [item.evidence_id],
            ))
            seen_rules.add("INC-SYSTEMD-FAILED")
    return evidence, findings, []


def _collect_target_coredumps(
    root: Path,
    *,
    runner: Callable,
    which: Callable[[str], Optional[str]],
) -> Tuple[List[CoredumpGroup], List[IncidentEvidence], List[IncidentFinding], List[str], bool]:
    journal_root = rooted(root, Path("/var/log/journal"))
    if not _safe_target_directory(journal_root, root) or not which("coredumpctl"):
        return [], [], [], [], False

    def target_runner(command, **kwargs):
        adjusted = list(command)
        executable = Path(str(adjusted[0])).name if adjusted else ""
        if executable == "coredumpctl":
            adjusted.insert(1, f"--root={root}")
        elif executable == "journalctl":
            adjusted.insert(1, f"--directory={journal_root}")
        return runner(adjusted, **kwargs)

    return collect_coredumps(
        "0",
        boot_id="",
        runner=target_runner,
        which=which,
        include_all_users=True,
    )


def scan_recovery_target(
    target: RecoveryTarget,
    *,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
) -> RecoveryReport:
    root = Path(target.root_path)
    incident = IncidentReport(
        incident_id=f"recovery-{int(time.time())}-{target.target_id}",
        target_boot="offline-target",
        trigger="recovery_environment",
        distro=dict(target.distro),
        collection_status="complete",
        system_facts={
            "target_id": target.target_id,
            "filesystem": target.filesystem,
            "bootloader": target.bootloader.to_dict(),
            "installed_kernels": list(target.installed_kernels),
            "snapshot_count": len(target.snapshots),
        },
    )
    if not target.distro.get("arch_family"):
        item = _evidence("os-release", "The selected target is not a supported Arch-family installation.", Severity.CRITICAL)
        incident.evidence.append(item)
        incident.findings.append(_finding("REC-UNSUPPORTED-TARGET", Severity.CRITICAL, "The selected operating system is unsupported", item.message, "target", [item.evidence_id], "Select an Arch Linux, EndeavourOS, Manjaro, or CachyOS installation."))

    journal_evidence, journal_findings, journal_errors = _collect_target_journal_findings(root, runner=runner, which=which)
    incident.evidence.extend(journal_evidence)
    incident.findings.extend(journal_findings)
    incident.collection_errors.extend(journal_errors)
    if journal_errors:
        incident.collection_status = "partial"

    coredumps, coredump_evidence, coredump_findings, coredump_errors, coredump_truncated = _collect_target_coredumps(
        root,
        runner=runner,
        which=which,
    )
    incident.coredumps.extend(coredumps)
    incident.evidence.extend(coredump_evidence)
    incident.findings.extend(coredump_findings)
    incident.collection_errors.extend(coredump_errors)
    if coredump_errors or coredump_truncated:
        incident.collection_status = "partial"
        incident.truncated = incident.truncated or coredump_truncated

    if RECOVERY_RUNTIME_MARKER.exists():
        pstore_evidence, pstore_findings, pstore_errors = collect_pstore_evidence()
        incident.evidence.extend(pstore_evidence)
        incident.findings.extend(pstore_findings)
        incident.collection_errors.extend(pstore_errors)

    lock = rooted(root, Path("/var/lib/pacman/db.lck"))
    if lock.exists():
        try:
            age = max(0, int(time.time() - lock.stat().st_mtime))
        except OSError:
            age = 0
        severity = Severity.MEDIUM if age >= 600 else Severity.LOW
        item = _evidence("pacman", f"A pacman database lock exists and is {age // 60} minute(s) old.", severity)
        incident.evidence.append(item)
        incident.findings.append(_finding("REC-PACMAN-LOCK", severity, "A package transaction lock remains", item.message, "package_manager", [item.evidence_id], "AuraScan can move a proven stale lock into its recovery backup and validate the package database."))

    broken_repos, repo_repairs = _repository_health(root)
    if broken_repos:
        item = _evidence("pacman-conf", f"{len(broken_repos)} repository include file(s) have no active package server.", Severity.HIGH)
        incident.evidence.append(item)
        action = "AuraScan found a validated local mirrorlist backup." if repo_repairs else "Use offline diagnosis or connect to a network and repair repository configuration."
        incident.findings.append(_finding("REC-REPOSITORY-BROKEN", Severity.HIGH, "Package repositories are not usable", item.message, "repository", [item.evidence_id], action))

    log_text = _latest_pacman_log(root)
    if _transaction_incomplete(log_text):
        item = _evidence("pacman-log", "The latest bounded pacman history ends with a transaction failure and no later completion marker.", Severity.HIGH)
        incident.evidence.append(item)
        incident.findings.append(_finding("REC-PACMAN-INTERRUPTED", Severity.HIGH, "A package transaction may be incomplete", item.message, "package_transaction", [item.evidence_id], "AuraScan can prepare a complete signed repository transaction after repository and network validation."))

    images, missing_images = _initramfs_status(target)
    incident.system_facts["initramfs_images"] = images
    if target.installed_kernels and missing_images:
        item = _evidence("initramfs", "No matching boot image was proven for: " + ", ".join(missing_images), Severity.HIGH)
        incident.evidence.append(item)
        incident.findings.append(_finding("REC-INITRAMFS-MISSING", Severity.HIGH, "Kernel boot images are incomplete", item.message, "initramfs", [item.evidence_id], "AuraScan can rebuild initramfs only after checking the installed generator, modules, backups, and boot-space availability."))

    module_root = rooted(root, Path("/usr/lib/modules"))
    module_dirs = []
    try:
        module_dirs = [
            item.name
            for item in module_root.iterdir()
            if item.is_dir() and not item.is_symlink() and ((item / "pkgbase").is_file() or (item / "vmlinuz").is_file())
        ][:100]
    except OSError:
        pass
    incident.system_facts["module_directories"] = module_dirs
    if target.installed_kernels and not module_dirs:
        item = _evidence("kernel-modules", "Installed kernel packages exist but no kernel module directories were found.", Severity.CRITICAL)
        incident.evidence.append(item)
        incident.findings.append(_finding("REC-KERNEL-MODULES-MISSING", Severity.CRITICAL, "Installed kernel modules are missing", item.message, "kernel_module", [item.evidence_id], "AuraScan can prepare exact official kernel and module package restoration after repository validation."))

    drift = _boot_config_drift(root)
    if drift:
        item = _evidence("config-drift", f"{len(drift)} boot-critical packaged configuration update(s) remain unresolved.", Severity.HIGH)
        incident.evidence.append(item)
        incident.findings.append(_finding("REC-BOOT-CONFIG-DRIFT", Severity.HIGH, "Boot-critical configuration drift exists", item.message, "boot_config", [item.evidence_id], "AuraScan will prepare a backed-up config-drift plan; it will not guess a sensitive merge."))
        incident.system_facts["boot_config_drift"] = [str(path.relative_to(root)) for path in drift]

    if not target.bootloader.installed:
        item = _evidence("bootloader", "No supported Limine, systemd-boot, or GRUB installation was positively detected.", Severity.HIGH)
        incident.evidence.append(item)
        incident.findings.append(_finding("REC-BOOTLOADER-UNKNOWN", Severity.HIGH, "The bootloader could not be verified", item.message, "bootloader", [item.evidence_id], "AuraScan will not modify EFI files until a supported loader and ESP are positively identified."))

    try:
        usage = shutil.disk_usage(root)
        incident.system_facts["root_free_bytes"] = usage.free
        if usage.free < min(1024 * 1024 * 1024, max(256 * 1024 * 1024, int(usage.total * 0.05))):
            item = _evidence("storage", f"The target root has only {usage.free // (1024 * 1024)} MiB free.", Severity.HIGH)
            incident.evidence.append(item)
            incident.findings.append(_finding("REC-ROOT-SPACE", Severity.HIGH, "The target filesystem is nearly full", item.message, "disk_space", [item.evidence_id], "AuraScan can prepare bounded package-cache cleanup while preserving two package versions."))
    except OSError:
        incident.collection_errors.append("Target free space could not be measured.")
        incident.collection_status = "partial"

    incident.evidence = deduplicate_evidence(incident.evidence)
    incident.findings = deduplicate_findings(incident.findings)
    if sum(len(item.message) for item in incident.evidence) > INCIDENT_MAX_LOCAL_EVIDENCE_CHARS:
        incident.evidence = bound_evidence(incident.evidence, INCIDENT_MAX_LOCAL_EVIDENCE_CHARS)
        incident.truncated = True
        incident.collection_status = "partial"
        incident.collection_errors.append("Local recovery evidence reached the 256 KiB safety bound.")
    retained_evidence = {item.evidence_id for item in incident.evidence}
    for finding in incident.findings:
        finding.evidence_ids = [item for item in finding.evidence_ids if item in retained_evidence]

    report = RecoveryReport(
        recovery_id=f"recovery-{int(time.time())}-{uuid.uuid4().hex[:8]}",
        target=target,
        incident_report=incident,
        complete=incident.collection_status == "complete" and not incident.truncated,
    )
    report.repair_actions = prepare_recovery_actions(report, repository_repairs=repo_repairs)
    return report


def _action_id(recipe: str, material: str) -> str:
    digest = hashlib.sha256(f"{recipe}|{material}".encode("utf-8", "replace")).hexdigest()[:16]
    return f"rec-action-{digest}"


def recovery_recipe_order(recipe: str) -> int:
    return {
        "repository_restore": 10,
        "stale_pacman_lock": 20,
        "package_cache_cleanup": 30,
        "complete_pacman_transaction": 40,
        "kernel_module_restore": 50,
        "kernel_headers_install": 60,
        "dkms_autoinstall": 70,
        "boot_config_drift": 80,
        "initramfs_rebuild": 90,
        "disable_boot_service": 100,
        "exact_package_reinstall": 110,
        "snapshot_test_boot": 120,
        "snapshot_restore": 130,
        "bootloader_reinstall": 140,
    }.get(recipe, 999)


def prepare_recovery_actions(
    report: RecoveryReport,
    *,
    repository_repairs: Sequence[Tuple[Path, Path]] = (),
) -> List[RecoveryAction]:
    target = report.target
    root = Path(target.root_path)
    categories = {item.category for item in report.findings}
    actions: List[RecoveryAction] = []
    if repository_repairs:
        pairs = [{"target": str(target_path), "backup": str(backup)} for target_path, backup in repository_repairs]
        actions.append(RecoveryAction(
            _action_id("repository_restore", json.dumps(pairs, sort_keys=True)),
            "repository_restore",
            "Restore verified repository mirror configuration",
            "AuraScan can replace inactive mirror includes with local backups that contain active package servers.",
            Severity.MEDIUM,
            {"pairs": pairs, "category": "repository"},
            [["install", "<validated-mirror-backup>", "<inactive-mirrorlist>"]],
            True, True, True,
            "Every replaced mirrorlist is copied into the recovery manifest first.",
        ))
    lock = rooted(root, Path("/var/lib/pacman/db.lck"))
    if "package_manager" in categories and lock.exists():
        try:
            age = max(0, int(time.time() - lock.stat().st_mtime))
        except OSError:
            age = 0
        verified = age >= 600
        actions.append(RecoveryAction(
            _action_id("stale_pacman_lock", str(lock)),
            "stale_pacman_lock",
            "Move the stale pacman lock",
            "The installed OS is offline; AuraScan can move the old lock into its recovery backup and validate the package database.",
            Severity.LOW,
            {"lock_path": str(lock), "minimum_age": 600, "category": "package_manager"},
            [["mv", str(lock), "<recovery-backup>"], ["pacman", "--root", str(root), "-Dk"]],
            verified, verified, True,
            "The lock is moved rather than deleted and can be restored if validation fails.",
            "" if verified else "The lock is not old enough to prove it is stale.",
        ))
    if "disk_space" in categories and rooted(root, Path("/var/cache/pacman/pkg")).is_dir():
        actions.append(RecoveryAction(
            _action_id("package_cache_cleanup", target.target_id),
            "package_cache_cleanup",
            "Free bounded package-cache space",
            "AuraScan can remove older cached archives while preserving the newest two versions of each package.",
            Severity.MEDIUM,
            {"cache_root": str(rooted(root, Path('/var/cache/pacman/pkg'))), "category": "disk_space"},
            [["paccache", "-r", "-k", "2", "-c", str(rooted(root, Path('/var/cache/pacman/pkg')))]],
            True, True, False,
            "Deleted package archives cannot be restored by AuraScan.",
        ))
    if "package_transaction" in categories:
        packages = sorted(target.installed_kernels)
        actions.append(RecoveryAction(
            _action_id("complete_pacman_transaction", target.target_id),
            "complete_pacman_transaction",
            "Complete a signed repository transaction",
            "After network and repository validation, pacman can complete a full system transaction inside the installed OS.",
            Severity.HIGH,
            {"category": "package_transaction", "kernels": packages},
            [["arch-chroot", str(root), "pacman", "-Syu"]],
            True, True, False,
            "Pacman package archives remain available for normal downgrade or reinstall procedures.",
        ))
    if "kernel_module" in categories and target.installed_kernels:
        packages = sorted(set(target.installed_kernels + [f"{name}-headers" for name in target.installed_kernels]))
        actions.append(RecoveryAction(
            _action_id("kernel_module_restore", ",".join(packages)),
            "kernel_module_restore",
            "Restore matching kernel and module support",
            "AuraScan can reinstall the detected official kernel families and matching headers from configured signed repositories.",
            Severity.HIGH,
            {"packages": packages, "category": "kernel_module"},
            [["arch-chroot", str(root), "pacman", "-S", "--needed", *packages]],
            all(SAFE_NAME_RE.fullmatch(item) for item in packages),
            all(SAFE_NAME_RE.fullmatch(item) for item in packages),
            False,
            "Pacman cache and the recovery manifest record the package transaction.",
        ))
    if "boot_config" in categories:
        actions.append(RecoveryAction(
            _action_id("boot_config_drift", target.target_id),
            "boot_config_drift",
            "Run the backed-up boot config drift assistant",
            "AuraScan will classify boot-critical .pacnew files and apply only independently safe merges with backups.",
            Severity.HIGH,
            {"category": "boot_config"},
            [["aurascan", "config-drift", "--root", str(root)]],
            True, True, True,
            "Config Drift Assistant creates a root-owned manifest and file backups.",
        ))
    if "initramfs" in categories:
        generator = "mkinitcpio" if rooted(root, Path("/usr/bin/mkinitcpio")).exists() else "dracut" if rooted(root, Path("/usr/bin/dracut")).exists() else ""
        command = ["arch-chroot", str(root), generator, "-P" if generator == "mkinitcpio" else "--regenerate-all", "--force"] if generator else []
        actions.append(RecoveryAction(
            _action_id("initramfs_rebuild", generator or "missing"),
            "initramfs_rebuild",
            "Rebuild installed kernel boot images",
            "AuraScan can back up current images and run the installed initramfs generator after checking boot-space availability.",
            Severity.HIGH,
            {"generator": generator, "category": "initramfs"},
            [command] if command else [],
            bool(generator), bool(generator), True,
            "Existing boot images are copied into the recovery backup before rebuilding.",
            "No supported initramfs generator was found." if not generator else "",
        ))
    snapshot_relevant = bool(categories & {"bootloader", "kernel_module", "initramfs", "package_transaction", "boot_config"})
    if target.snapshots and snapshot_relevant:
        snapshot_id = str(target.snapshots[-1].get("id"))
        actions.append(RecoveryAction(
            _action_id("snapshot_test_boot", snapshot_id),
            "snapshot_test_boot",
            "Prepare a one-shot snapshot test boot",
            f"AuraScan can prepare a one-time boot of snapshot {snapshot_id} without making it the permanent default.",
            Severity.MEDIUM,
            {"snapshot_id": snapshot_id, "category": "snapshot"},
            [["aurascan-recovery-snapshot-boot", snapshot_id]],
            target.bootloader.kind == "systemd-boot" and target.filesystem == "btrfs",
            target.bootloader.kind == "systemd-boot" and target.filesystem == "btrfs",
            True,
            "The permanent default is preserved; AuraScan owns the generated snapshot entry and replaces it on a later test.",
        ))
        phrase = f"RESTORE SNAPSHOT {snapshot_id}"
        actions.append(RecoveryAction(
            _action_id("snapshot_restore", snapshot_id),
            "snapshot_restore",
            "Restore a Btrfs/Snapper snapshot",
            f"AuraScan can create a pre-recovery snapshot and restore snapshot {snapshot_id} after explicit typed confirmation.",
            Severity.CRITICAL,
            {"snapshot_id": snapshot_id, "category": "snapshot"},
            [["arch-chroot", str(root), "snapper", "rollback", snapshot_id]],
            target.filesystem == "btrfs", target.filesystem == "btrfs", True,
            "A pre-recovery snapshot and rollback details are recorded first.",
            confirmation_phrase=phrase,
        ))
    if "bootloader" in categories and target.bootloader.installed and target.bootloader.supports_reinstall:
        actions.append(RecoveryAction(
            _action_id("bootloader_reinstall", target.bootloader.kind),
            "bootloader_reinstall",
            f"Reinstall detected {target.bootloader.name} bootloader",
            "AuraScan can back up the detected loader configuration and exact EFI files, regenerate configuration, and validate the result.",
            Severity.CRITICAL,
            {"bootloader": target.bootloader.kind, "esp_path": target.esp_path, "category": "bootloader"},
            [["aurascan-recovery-bootloader-reinstall", target.bootloader.kind]],
            True, True, True,
            "Detected bootloader configuration and EFI files are backed up before changes.",
            confirmation_phrase="REINSTALL BOOTLOADER",
        ))
    return sorted(actions, key=lambda item: (recovery_recipe_order(item.recipe_id), item.action_id))


def _probe_id(target_id: str, probe_type: str) -> str:
    digest = hashlib.sha256(f"{target_id}|{probe_type}".encode("utf-8", "replace")).hexdigest()[:16]
    return f"rec-probe-{digest}"


def discover_recovery_probes(report: RecoveryReport) -> List[DiagnosticProbe]:
    categories = {item.category for item in report.findings}
    definitions = [
        ("repository_health", "Check repository health", "Verify active package servers and local backups.", "repository"),
        ("package_database", "Check package database", "Validate the target package database without changing it.", "package_manager"),
        ("transaction_state", "Check interrupted package state", "Correlate bounded pacman history with installed package records.", "package_transaction"),
        ("kernel_module_state", "Check kernels and modules", "Compare installed kernel families, headers, module trees, and DKMS metadata.", "kernel_module"),
        ("initramfs_state", "Check boot images", "Verify the installed generator, image files, and available boot space.", "initramfs"),
        ("boot_config_drift", "Check boot configuration drift", "Classify pending boot-critical packaged configuration updates.", "boot_config"),
        ("bootloader_state", "Check bootloader and ESP", "Verify the detected loader, EFI files, and configuration ownership.", "bootloader"),
        ("snapshot_state", "Check recovery snapshots", "Verify available Snapper/Btrfs snapshots and rollback prerequisites.", "snapshot"),
        ("storage_space", "Check recovery workspace", "Measure target, boot, and package-cache space.", "disk_space"),
        ("failed_boot_services", "Check failed boot services", "Inspect bounded target journal evidence for boot-blocking services.", "failed_service"),
        ("signed_package_cache", "Check signed cached packages", "Find exact cached official packages that can support offline repair.", "package_transaction"),
        ("filesystem_readonly", "Check filesystem state", "Confirm whether the target was forced read-only by filesystem errors.", "filesystem"),
    ]
    probes: List[DiagnosticProbe] = []
    for priority, (probe_type, title, summary, category) in enumerate(definitions, start=1):
        required = category in categories
        probes.append(DiagnosticProbe(
            _probe_id(report.target.target_id, probe_type),
            probe_type,
            title,
            summary,
            {"target_id": report.target.target_id, "category": category},
            [item.evidence_id for item in report.incident_report.evidence if item.source] if required and report.incident_report else [],
            priority=priority if required else priority + 50,
            required=required,
            affects_plan=True,
        ))
    seen_packages = set()
    coredumps = report.incident_report.coredumps if report.incident_report else []
    for index, group in enumerate(coredumps[:12], start=1):
        package = group.package.strip()
        if package in seen_packages or not SAFE_NAME_RE.fullmatch(package) or package not in report.target.installed_packages:
            continue
        seen_packages.add(package)
        required = bool(group.count >= 3 or group.desktop_component)
        probes.append(DiagnosticProbe(
            _probe_id(report.target.target_id, f"crashed-package-integrity:{package}"),
            "crashed_package_integrity",
            f"Check crashed package {package}",
            "Verify installed immutable files and an exact signed cached archive without reading core memory.",
            {
                "target_id": report.target.target_id,
                "category": "application_crash",
                "package": package,
            },
            list(group.evidence_ids),
            priority=20 + index if required else 80 + index,
            required=required,
            affects_plan=True,
        ))
    return sorted(probes, key=lambda item: (not item.required, item.priority, item.probe_id))[:RECOVERY_MAX_PROBES]


def _probe_actions(report: RecoveryReport, category: str) -> List[str]:
    return [
        item.action_id for item in report.eligible_actions
        if str(item.parameters.get("category") or "") == category
    ]


def _run_bounded(
    runner: Callable,
    command: Sequence[str],
    *,
    timeout: int = 30,
    max_chars: int = 8000,
) -> Tuple[int, str]:
    try:
        result = runner(list(command), capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, redact_incident_text(str(exc))[:max_chars]
    combined = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
    return result.returncode, redact_incident_text(combined)[:max_chars]


def _probe_kernel_modules(report: RecoveryReport) -> Tuple[str, str]:
    root = Path(report.target.root_path)
    module_root = rooted(root, Path("/usr/lib/modules"))
    module_dirs: List[str] = []
    pkgbases: List[str] = []
    try:
        for directory in sorted(module_root.iterdir())[:100]:
            if not directory.is_dir():
                continue
            module_dirs.append(directory.name)
            try:
                pkgbases.append((directory / "pkgbase").read_text(encoding="utf-8", errors="replace").strip())
            except OSError:
                pass
    except OSError:
        pass
    kernels = report.target.installed_kernels
    headers = [f"{item}-headers" for item in kernels if f"{item}-headers" in report.target.installed_packages]
    dkms = sorted(name for name in report.target.installed_packages if name == "dkms" or name.endswith("-dkms"))
    if kernels and not module_dirs:
        return "action_ready", f"{len(kernels)} kernel package(s) are installed, but no module tree exists; exact kernel restoration is ready."
    if dkms and len(headers) < len(kernels):
        return "action_ready", f"DKMS packages exist and {len(kernels) - len(headers)} kernel family/families lack installed headers."
    return "ok", f"Found {len(kernels)} kernel package(s), {len(module_dirs)} module tree(s), {len(headers)} matching header package(s), and {len(dkms)} DKMS package(s)."


def _probe_initramfs(report: RecoveryReport) -> Tuple[str, str]:
    root = Path(report.target.root_path)
    images, missing = _initramfs_status(report.target)
    generator = "mkinitcpio" if rooted(root, Path("/usr/bin/mkinitcpio")).exists() else "dracut" if rooted(root, Path("/usr/bin/dracut")).exists() else ""
    try:
        free = shutil.disk_usage(rooted(root, Path("/boot"))).free
    except OSError:
        free = 0
    if missing and generator and free >= 256 * 1024 * 1024:
        return "action_ready", f"{len(missing)} kernel boot image(s) are missing; {generator} is installed and boot space is sufficient."
    if missing:
        return "incomplete", f"{len(missing)} boot image(s) are missing, but generator or boot-space prerequisites are incomplete."
    return "ok", f"Found {len(images)} boot image(s); generator is {generator or 'unavailable'}."


def _probe_bootloader(report: RecoveryReport) -> Tuple[str, str]:
    info = detect_bootloader(Path(report.target.root_path), Path(report.target.esp_path))
    report.target.bootloader = info
    if not info.installed:
        return "incomplete", "No supported bootloader and ESP pair was positively detected."
    return "ok", f"Detected {info.name} from {len(info.evidence)} local evidence item(s)."


def _probe_snapshots(report: RecoveryReport) -> Tuple[str, str]:
    snapshots = _read_snapshots(Path(report.target.root_path))
    report.target.snapshots = snapshots
    if snapshots:
        return "ok", f"Found {len(snapshots)} local Btrfs/Snapper snapshot(s)."
    return "no_action", "No local Snapper snapshot was found."


def _probe_storage(report: RecoveryReport) -> Tuple[str, str]:
    root = Path(report.target.root_path)
    values = []
    for label, path in (("root", root), ("boot", rooted(root, Path("/boot"))), ("cache", rooted(root, Path("/var/cache/pacman/pkg")))):
        try:
            free = shutil.disk_usage(path).free
            values.append(f"{label}={free // (1024 * 1024)}MiB")
        except OSError:
            values.append(f"{label}=unavailable")
    return "ok", "Available space: " + ", ".join(values) + "."


def _probe_failed_services(report: RecoveryReport, runner: Callable, which: Callable[[str], Optional[str]]) -> Tuple[str, str]:
    journal_root = rooted(Path(report.target.root_path), Path("/var/log/journal"))
    if not which("journalctl") or not journal_root.is_dir():
        return "unavailable", "Persistent target journal data is unavailable."
    code, output = _run_bounded(
        runner,
        ["journalctl", f"--directory={journal_root}", "--boot=0", "--priority=0..3", "--no-pager", f"--lines={RECOVERY_MAX_JOURNAL}"],
        timeout=45,
        max_chars=12000,
    )
    if code != 0:
        return "failed", "The target journal could not be queried."
    units = sorted({
        unit
        for line in output.splitlines()
        if re.search(r"(?i)failed to start|dependency failed|start operation timed out|job .* failed", line)
        for unit in re.findall(r"\b([A-Za-z0-9@_.:-]+\.service)\b", line)
    })[:20]
    noncritical = [unit for unit in units if not unit.startswith(CRITICAL_UNIT_PREFIXES)]
    if noncritical:
        report.incident_report.system_facts["failed_noncritical_units"] = noncritical
        return "action_ready", f"Found {len(noncritical)} noncritical service failure candidate(s) for fresh validation."
    return "ok", f"No supported noncritical boot-blocking service was proven in {min(RECOVERY_MAX_JOURNAL, len(output.splitlines()))} bounded journal line(s)."


def _probe_signed_cache(report: RecoveryReport) -> Tuple[str, str]:
    cache = rooted(Path(report.target.root_path), Path("/var/cache/pacman/pkg"))
    signed = 0
    archives = 0
    try:
        for path in list(cache.glob("*.pkg.tar.*"))[:5000]:
            if path.name.endswith(".sig"):
                continue
            archives += 1
            if Path(str(path) + ".sig").is_file():
                signed += 1
    except OSError:
        pass
    return ("ok" if signed else "no_action"), f"Found {archives} cached package archive(s), including {signed} with detached signature files."


def _parse_package_query(text: str) -> Tuple[str, str]:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return "", ""
    fields = lines[-1].split(None, 1)
    return (fields[0], fields[1]) if len(fields) == 2 else ("", "")


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


def _target_relative_path(root: Path, path: Path) -> str:
    try:
        return "/" + str(path.resolve(strict=False).relative_to(root.resolve(strict=False)))
    except (OSError, ValueError):
        return ""


def _bounded_sha256(path: Path, *, max_size: int = 2 * 1024 * 1024 * 1024) -> str:
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


def _probe_crashed_package_integrity(
    report: RecoveryReport,
    probe: DiagnosticProbe,
    runner: Callable,
    which: Callable[[str], Optional[str]],
) -> Tuple[str, str]:
    root = Path(report.target.root_path)
    package = str(probe.target.get("package") or "")
    version = report.target.installed_packages.get(package, "")
    if not SAFE_NAME_RE.fullmatch(package) or not version:
        return "unavailable", "The crashed package target is no longer installed or valid."
    if not which("arch-chroot") or not which("pacman") or not which("pacman-key"):
        return "unavailable", "Package integrity tools are incomplete in the recovery environment."
    code, _foreign = _run_bounded(runner, ["arch-chroot", str(root), "pacman", "-Qm", package], timeout=30)
    if code == 0:
        return "no_action", "The crashed package is foreign/AUR-managed; automatic recovery reinstall is not allowed."
    code, integrity = _run_bounded(runner, ["arch-chroot", str(root), "pacman", "-Qkk", package], timeout=120, max_chars=128000)
    missing = _missing_immutable_package_files(integrity)
    if not missing:
        return ("ok" if code == 0 else "incomplete"), "No missing immutable file was proven for the crashed official package."
    cache = rooted(root, Path("/var/cache/pacman/pkg"))
    try:
        candidates = sorted(
            (
                path for path in cache.glob(f"{package}-*.pkg.tar.*")
                if not path.name.endswith(".sig") and _safe_target_file(path, root, max_size=2 * 1024 * 1024 * 1024)
            ),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )[:30]
    except OSError:
        candidates = []
    for archive in candidates:
        signature = Path(str(archive) + ".sig")
        archive_in_target = _target_relative_path(root, archive)
        signature_in_target = _target_relative_path(root, signature)
        if (
            not _root_owned_target_file(archive, root, max_size=2 * 1024 * 1024 * 1024)
            or not _root_owned_target_file(signature, root, max_size=4 * 1024 * 1024)
            or not archive_in_target
            or not signature_in_target
        ):
            continue
        query_code, query = _run_bounded(runner, ["arch-chroot", str(root), "pacman", "-Qp", archive_in_target], timeout=30)
        found_name, found_version = _parse_package_query(query)
        if query_code != 0 or found_name != package or found_version != version:
            continue
        verify_code, _verify = _run_bounded(
            runner,
            ["arch-chroot", str(root), "pacman-key", "--verify", signature_in_target, archive_in_target],
            timeout=60,
        )
        digest = _bounded_sha256(archive)
        if verify_code != 0 or not digest:
            continue
        parameters = {
            "package": package,
            "version": version,
            "archive": str(archive),
            "archive_sha256": digest,
            "missing_files": missing,
            "category": "application_crash",
        }
        key = ("exact_package_reinstall", json.dumps(parameters, sort_keys=True))
        existing = {(item.recipe_id, json.dumps(item.parameters, sort_keys=True)) for item in report.repair_actions}
        if key not in existing:
            report.repair_actions.append(RecoveryAction(
                _action_id("exact_package_reinstall", f"{package}|{version}|{digest}"),
                "exact_package_reinstall",
                f"Reinstall exact cached package {package}",
                f"AuraScan proved {len(missing)} missing immutable file(s) and verified the signed cached archive for installed version {version}.",
                Severity.MEDIUM,
                parameters,
                [["arch-chroot", str(root), "pacman", "-U", archive_in_target]],
                True,
                True,
                False,
                "The exact archive checksum and target-keyring verification are recorded in the private recovery report.",
            ))
            report.repair_actions.sort(key=lambda item: (recovery_recipe_order(item.recipe_id), item.action_id))
        return "action_ready", f"Verified an exact signed cached reinstall for {package} after proving {len(missing)} missing immutable file(s)."
    return "incomplete", "Immutable package files are missing, but no exact signed cached archive passed target-keyring verification."


def execute_recovery_probe(
    report: RecoveryReport,
    probe: DiagnosticProbe,
    *,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
    requested_by: str = "deterministic",
) -> DiagnosticProbeResult:
    started = time.monotonic()
    category = str(probe.target.get("category") or "")
    status = "ok"
    summary = "Check completed."
    try:
        if probe.probe_type == "repository_health":
            broken, repairs = _repository_health(Path(report.target.root_path))
            status = "action_ready" if broken and repairs else "incomplete" if broken else "ok"
            summary = f"Found {len(broken)} inactive repository include(s) and {len(repairs)} validated local replacement(s)."
        elif probe.probe_type == "package_database":
            local = rooted(Path(report.target.root_path), Path("/var/lib/pacman/local"))
            if not local.is_dir() or not report.target.installed_packages:
                status, summary = "failed", "The local package database could not be parsed."
            elif which("pacman"):
                code, _output = _run_bounded(runner, ["pacman", "--root", report.target.root_path, "--dbpath", str(local.parent), "-Dk"], timeout=45)
                status = "ok" if code == 0 else "incomplete"
                summary = f"Parsed {len(report.target.installed_packages)} package records; pacman database validation {'passed' if code == 0 else 'was incomplete'}."
            else:
                status, summary = "ok", f"Parsed {len(report.target.installed_packages)} package records; pacman is unavailable for the secondary check."
        elif probe.probe_type == "transaction_state":
            incomplete = _transaction_incomplete(_latest_pacman_log(Path(report.target.root_path)))
            status = "action_ready" if incomplete else "ok"
            summary = "A failed transaction remains the latest bounded package event." if incomplete else "No unresolved transaction failure was found in bounded package history."
        elif probe.probe_type == "kernel_module_state":
            status, summary = _probe_kernel_modules(report)
        elif probe.probe_type == "initramfs_state":
            status, summary = _probe_initramfs(report)
        elif probe.probe_type == "boot_config_drift":
            drift = _boot_config_drift(Path(report.target.root_path))
            status = "action_ready" if drift else "ok"
            summary = f"Found {len(drift)} boot-critical config drift file(s)."
        elif probe.probe_type == "bootloader_state":
            status, summary = _probe_bootloader(report)
        elif probe.probe_type == "snapshot_state":
            status, summary = _probe_snapshots(report)
        elif probe.probe_type == "storage_space":
            status, summary = _probe_storage(report)
        elif probe.probe_type == "failed_boot_services":
            status, summary = _probe_failed_services(report, runner, which)
        elif probe.probe_type == "signed_package_cache":
            status, summary = _probe_signed_cache(report)
        elif probe.probe_type == "crashed_package_integrity":
            status, summary = _probe_crashed_package_integrity(report, probe, runner, which)
        elif probe.probe_type == "filesystem_readonly":
            status = "incomplete" if report.target.filesystem not in RECOVERY_SUPPORTED_FILESYSTEMS else "ok"
            summary = f"Target filesystem is {report.target.filesystem}; AuraScan filesystem checks remain read-only."
        else:
            status, summary = "unavailable", "The requested probe type is unsupported."
    except Exception as exc:
        status, summary = "failed", "Local verification failed: " + redact_incident_text(str(exc))[:500]
    return DiagnosticProbeResult(
        probe.probe_id,
        probe.probe_type,
        status,
        summary,
        requested_by=requested_by,
        evidence_ids=list(probe.evidence_ids),
        action_ids=_probe_actions(report, category) if status == "action_ready" else [],
        affects_plan=probe.affects_plan,
        duration_ms=int((time.monotonic() - started) * 1000),
    )


def select_recovery_probe_ids(probes: Sequence[DiagnosticProbe], requested_ids: Sequence[str]) -> List[str]:
    known = {item.probe_id: item for item in probes}
    selected = [item.probe_id for item in probes if item.required]
    ai_count = 0
    for probe_id in requested_ids:
        if probe_id not in known or probe_id in selected or ai_count >= RECOVERY_MAX_AI_PROBES:
            continue
        selected.append(probe_id)
        ai_count += 1
    return selected[:RECOVERY_MAX_EXECUTED_PROBES]


def execute_recovery_probes(
    report: RecoveryReport,
    requested_ids: Sequence[str],
    *,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
) -> List[DiagnosticProbeResult]:
    known = {item.probe_id: item for item in report.diagnostic_probes}
    valid_requested = {item for item in requested_ids if item in known}
    selected = select_recovery_probe_ids(report.diagnostic_probes, requested_ids)
    deadline = time.monotonic() + RECOVERY_MAX_PROBE_SECONDS
    results: List[DiagnosticProbeResult] = []
    for probe_id in selected:
        probe = known[probe_id]
        if time.monotonic() >= deadline:
            results.append(DiagnosticProbeResult(
                probe.probe_id, probe.probe_type, "timeout", "The bounded recovery probe deadline was reached.",
                requested_by="ai" if probe_id in valid_requested else "deterministic",
                evidence_ids=list(probe.evidence_ids), affects_plan=probe.affects_plan,
            ))
            continue
        results.append(execute_recovery_probe(
            report,
            probe,
            runner=runner,
            which=which,
            requested_by="ai" if probe_id in valid_requested else "deterministic",
        ))
    return results


def augment_recovery_actions_from_probes(report: RecoveryReport) -> None:
    existing = {(item.recipe_id, json.dumps(item.parameters, sort_keys=True)) for item in report.repair_actions}
    root = Path(report.target.root_path)
    successful_types = {
        item.probe_type for item in report.probe_results
        if item.status in {"ok", "action_ready"}
    }
    if "kernel_module_state" in successful_types:
        dkms_packages = sorted(name for name in report.target.installed_packages if name.endswith("-dkms"))
        missing_headers = sorted(
            f"{kernel}-headers" for kernel in report.target.installed_kernels
            if f"{kernel}-headers" not in report.target.installed_packages
        )
        if dkms_packages and missing_headers:
            parameters = {"packages": missing_headers, "category": "kernel_module"}
            key = ("kernel_headers_install", json.dumps(parameters, sort_keys=True))
            if key not in existing and all(SAFE_NAME_RE.fullmatch(item) for item in missing_headers):
                report.repair_actions.append(RecoveryAction(
                    _action_id("kernel_headers_install", ",".join(missing_headers)),
                    "kernel_headers_install",
                    "Install matching kernel headers",
                    "A local probe confirmed DKMS packages and missing headers for installed kernel families.",
                    Severity.MEDIUM,
                    parameters,
                    [["arch-chroot", str(root), "pacman", "-S", "--needed", *missing_headers]],
                    True, True, False,
                    "The signed package transaction is recorded in the recovery manifest.",
                ))
        elif dkms_packages and rooted(root, Path("/usr/bin/dkms")).is_file():
            parameters = {"category": "kernel_module"}
            key = ("dkms_autoinstall", json.dumps(parameters, sort_keys=True))
            if key not in existing:
                report.repair_actions.append(RecoveryAction(
                    _action_id("dkms_autoinstall", report.target.target_id),
                    "dkms_autoinstall",
                    "Rebuild matching DKMS modules",
                    "A local probe confirmed DKMS packages and matching installed kernel headers.",
                    Severity.MEDIUM,
                    parameters,
                    [["arch-chroot", str(root), "dkms", "autoinstall"]],
                    True, True, False,
                    "DKMS build output is retained in the private recovery manifest.",
                ))
    if "failed_boot_services" in successful_types:
        units = report.incident_report.system_facts.get("failed_noncritical_units", []) if report.incident_report else []
        if isinstance(units, list):
            for unit in units[:5]:
                unit = str(unit)
                if not SAFE_UNIT_RE.fullmatch(unit) or unit.startswith(CRITICAL_UNIT_PREFIXES):
                    continue
                parameters = {"unit": unit, "category": "failed_service"}
                key = ("disable_boot_service", json.dumps(parameters, sort_keys=True))
                if key in existing:
                    continue
                report.repair_actions.append(RecoveryAction(
                    _action_id("disable_boot_service", unit),
                    "disable_boot_service",
                    f"Disable proven noncritical boot blocker {unit}",
                    "A bounded target-journal probe identified this noncritical service as a boot-failure candidate. AuraScan will validate the unit again before changing enablement.",
                    Severity.HIGH,
                    parameters,
                    [["systemctl", f"--root={root}", "disable", unit]],
                    True, True, True,
                    "The unit file is not deleted; enablement links can be restored.",
                ))
    report.repair_actions.sort(key=lambda item: (recovery_recipe_order(item.recipe_id), item.action_id))


def _ai_evidence(report: RecoveryReport, *, facts_only: bool) -> List[Dict[str, str]]:
    if facts_only or not report.incident_report:
        return []
    excerpts: List[Dict[str, str]] = []
    used = 0
    for item in report.incident_report.evidence[:RECOVERY_MAX_EVIDENCE]:
        message = redact_incident_text(item.message)[:1000]
        if used + len(message) > RECOVERY_MAX_AI_CHARS:
            break
        excerpts.append({"evidence_id": item.evidence_id, "source": item.source, "message": message})
        used += len(message)
    return excerpts


def build_recovery_ai_prompt(report: RecoveryReport, *, phase: str, facts_only: bool) -> str:
    known_evidence = [item.evidence_id for item in report.incident_report.evidence[:RECOVERY_MAX_EVIDENCE]] if report.incident_report else []
    payload: Dict[str, object] = {
        "phase": phase,
        "target": {
            "distro": report.target.distro.get("id"),
            "filesystem": report.target.filesystem,
            "encrypted": report.target.encrypted,
            "bootloader": report.target.bootloader.kind,
            "installed_kernels": list(report.target.installed_kernels),
            "snapshot_count": len(report.target.snapshots),
        },
        "network": {"connected": report.network.connected, "connectivity": report.network.connectivity},
        "findings": [
            {
                "rule_id": item.rule_id,
                "severity": item.severity.value,
                "title": item.title,
                "summary": item.summary,
                "category": item.category,
                "evidence_ids": list(item.evidence_ids),
            }
            for item in report.findings
        ],
        "evidence": _ai_evidence(report, facts_only=facts_only),
        "known_evidence_ids": known_evidence,
        "verified_action_ids": [item.action_id for item in report.eligible_actions],
    }
    if phase == "triage":
        payload["available_probes"] = [
            {"probe_id": item.probe_id, "title": item.title, "summary": item.summary}
            for item in report.diagnostic_probes
        ]
    else:
        payload["probe_results"] = [
            {
                "probe_id": item.probe_id,
                "status": item.status,
                "summary": redact_incident_text(item.summary)[:1000],
                "action_ids": list(item.action_ids),
            }
            for item in report.probe_results
        ]
    instructions = (
        "You are AuraScan's recovery correlation layer. Return one strict JSON object only. "
        "Never provide commands, shell text, paths, package names not already shown, file edits, or new action/probe IDs. "
        "You may select only available opaque probe IDs during triage and recommend only verified action IDs. "
        "You cannot suppress deterministic findings, approve execution, declare the machine safe, or request filesystem, partition, firmware, authentication, user-data, Secure Boot key, or arbitrary repairs. "
        "Schema: {\"summary\":string,\"likely_causes\":[{\"title\":string,\"confidence\":\"low|medium|high\",\"evidence_ids\":[string],\"explanation\":string}],"
        "\"requested_probe_ids\":[string],\"recommended_action_ids\":[string]}. "
        "For final phase requested_probe_ids must be empty."
    )
    prefix = instructions + "\nRECOVERY_DATA="
    material_budget = max(1000, RECOVERY_MAX_AI_CHARS - len(prefix))
    material = json.dumps(payload, sort_keys=True, ensure_ascii=True)
    trim_order = ["evidence", "findings", "probe_results" if phase != "triage" else "available_probes", "known_evidence_ids"]
    while len(material) > material_budget:
        changed = False
        for key in trim_order:
            values = payload.get(key)
            if isinstance(values, list) and values:
                values.pop()
                changed = True
                break
        if not changed:
            break
        material = json.dumps(payload, sort_keys=True, ensure_ascii=True)
    if len(material) > material_budget:
        payload = {
            "phase": phase,
            "target": payload["target"],
            "network": payload["network"],
            "verified_action_ids": payload["verified_action_ids"],
            "findings": [],
            "evidence": [],
            "known_evidence_ids": [],
        }
        material = json.dumps(payload, sort_keys=True, ensure_ascii=True)
    return prefix + material


def validate_recovery_ai_response(
    report: RecoveryReport,
    data: Mapping[str, object],
    *,
    phase: str,
) -> Dict[str, object]:
    summary = redact_incident_text(str(data.get("summary") or ""))[:2000]
    known_evidence = {item.evidence_id for item in report.incident_report.evidence} if report.incident_report else set()
    known_probes = {item.probe_id for item in report.diagnostic_probes}
    known_actions = {item.action_id for item in report.eligible_actions}
    requested = data.get("requested_probe_ids", [])
    recommended = data.get("recommended_action_ids", [])
    requested_ids = [] if phase == "final" else [str(item) for item in requested if str(item) in known_probes][:RECOVERY_MAX_AI_PROBES] if isinstance(requested, list) else []
    recommended_ids = [str(item) for item in recommended if str(item) in known_actions] if isinstance(recommended, list) else []
    causes = []
    raw_causes = data.get("likely_causes", [])
    if isinstance(raw_causes, list):
        for cause in raw_causes[:5]:
            if not isinstance(cause, Mapping):
                continue
            confidence = str(cause.get("confidence") or "low").lower()
            if confidence not in {"low", "medium", "high"}:
                confidence = "low"
            evidence_ids = cause.get("evidence_ids", [])
            causes.append({
                "title": redact_incident_text(str(cause.get("title") or "Possible cause"))[:300],
                "confidence": confidence,
                "evidence_ids": [str(item) for item in evidence_ids if str(item) in known_evidence][:20] if isinstance(evidence_ids, list) else [],
                "explanation": redact_incident_text(str(cause.get("explanation") or ""))[:1200],
            })
    return {
        "summary": summary,
        "likely_causes": causes,
        "requested_probe_ids": requested_ids,
        "recommended_action_ids": recommended_ids,
    }


def apply_recovery_ai_plan(
    report: RecoveryReport,
    *,
    enabled: bool,
    facts_only: bool = False,
    env: Optional[Mapping[str, str]] = None,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
    urlopen: Optional[Callable] = None,
    progress_callback: Optional[Callable[[str], None]] = None,
) -> None:
    report.diagnostic_probes = discover_recovery_probes(report)
    if not enabled:
        report.probe_results = execute_recovery_probes(report, [], runner=runner, which=which)
        augment_recovery_actions_from_probes(report)
        report.ai_review = {"enabled": False, "status": "disabled", "provider_requests": 0}
        return
    if not report.network.connected or report.network.captive_portal:
        report.probe_results = execute_recovery_probes(report, [], runner=runner, which=which)
        augment_recovery_actions_from_probes(report)
        report.ai_review = {"enabled": True, "status": "offline", "provider_requests": 0, "summary": "AI was unavailable; deterministic recovery checks remain usable."}
        return
    source = dict(os.environ if env is None else env)
    source["AURASCAN_AI_ENABLED"] = "1"
    config = resolve_ai_config(source)
    if config.error or not config.api_key_present:
        report.probe_results = execute_recovery_probes(report, [], runner=runner, which=which)
        augment_recovery_actions_from_probes(report)
        report.ai_review = {"enabled": True, "status": "not_configured", "provider_requests": 0, "summary": "No validated recovery-session AI key was available."}
        return
    triage: Dict[str, object] = {}
    try:
        if progress_callback:
            progress_callback("AI is selecting bounded local recovery checks")
        raw = call_ai_provider(config, build_recovery_ai_prompt(report, phase="triage", facts_only=facts_only), timeout=30, urlopen=urlopen)
        parsed = json.loads(raw)
        if not isinstance(parsed, Mapping):
            raise ValueError("AI triage was not a JSON object")
        triage = validate_recovery_ai_response(report, parsed, phase="triage")
        triage["status"] = "ok"
    except Exception as exc:
        triage = {"status": "invalid_response", "error": redact_incident_text(str(exc))[:500], "requested_probe_ids": []}
    requested = triage.get("requested_probe_ids", []) if isinstance(triage.get("requested_probe_ids"), list) else []
    if progress_callback:
        progress_callback("AuraScan is independently verifying the recovery plan")
    report.probe_results = execute_recovery_probes(report, requested, runner=runner, which=which)
    augment_recovery_actions_from_probes(report)
    final: Dict[str, object] = {}
    requests = 1
    valid_probe_ran = any(
        item.status not in {"failed", "timeout", "unavailable"}
        for item in report.probe_results
    )
    if valid_probe_ran:
        try:
            if progress_callback:
                progress_callback("AI is explaining and prioritizing verified repairs")
            raw = call_ai_provider(config, build_recovery_ai_prompt(report, phase="final", facts_only=facts_only), timeout=30, urlopen=urlopen)
            requests += 1
            parsed = json.loads(raw)
            if not isinstance(parsed, Mapping):
                raise ValueError("AI final review was not a JSON object")
            final = validate_recovery_ai_response(report, parsed, phase="final")
            final["status"] = "ok"
        except Exception as exc:
            final = {"status": "invalid_response", "error": redact_incident_text(str(exc))[:500]}
    selected = final if final.get("status") == "ok" else triage
    recommended = selected.get("recommended_action_ids", []) if isinstance(selected.get("recommended_action_ids"), list) else []
    for action in report.repair_actions:
        action.ai_recommended = action.action_id in recommended
    report.ai_review = {
        "enabled": True,
        "provider": config.provider,
        "status": "ok" if final.get("status") == "ok" else "triage_only" if triage.get("status") == "ok" else "invalid_response",
        "provider_requests": requests,
        "evidence_mode": "facts-only" if facts_only else "redacted",
        "summary": str(selected.get("summary") or ""),
        "likely_causes": list(selected.get("likely_causes", [])) if isinstance(selected.get("likely_causes"), list) else [],
        "recommended_action_ids": recommended,
        "triage": triage,
        "final": final,
    }
