import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from aurascan.core.ai_provider import call_ai_provider, resolve_ai_config
from aurascan.core.hardware_health import (
    HARDWARE_HEALTH_PROBE_ID,
    HardwareHealthReport,
    collect_hardware_health,
    question_requests_hardware_context,
)


FOLLOWUP_SCHEMA_VERSION = "1.0"
FOLLOWUP_REPORT_TYPE = "followup_context"
FOLLOWUP_MAX_CONTEXTS = 50
FOLLOWUP_RETENTION_DAYS = 30
FOLLOWUP_MAX_QUESTIONS = 8
FOLLOWUP_MAX_PROVIDER_REQUESTS = 12
FOLLOWUP_MAX_PROMPT_CHARS = 12000
FOLLOWUP_MAX_QUESTION_CHARS = 2000
FOLLOWUP_MAX_ANSWER_CHARS = 4000
FOLLOWUP_MAX_CONTEXT_BYTES = 2 * 1024 * 1024
FOLLOWUP_AI_TIMEOUT_SECONDS = 60
FOLLOWUP_ACTION_REPOSITORY = "fua-upgrade-repository-restore"
FOLLOWUP_ACTION_KERNEL = "fua-upgrade-kernel-support"
FOLLOWUP_ACTION_CONFIG_DRIFT = "fua-upgrade-config-drift"
FOLLOWUP_PROBE_UPGRADE_REFRESH = "fup-upgrade-refresh"
FOLLOWUP_PROBE_MAINTENANCE_INCIDENT = "fup-maintenance-incident"
FOLLOWUP_RECOVERY_RUNTIME_MARKER = Path("/run/aurascan-recovery/environment")
EXIT_FOLLOWUP_UNAVAILABLE = 70
EXIT_FOLLOWUP_PROVIDER_ERROR = 71
EXIT_FOLLOWUP_ACTION_FAILED = 72

SAFE_CONTEXT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
URL_USERINFO_RE = re.compile(r"([a-z][a-z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@", re.IGNORECASE)
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(password|passwd|passphrase|secret|token|api[_-]?key|apikey|authorization|credential)"
    r"(\s*[:=]\s*)([^\s,;]+)"
)
HOME_PATH_RE = re.compile(r"/home/([A-Za-z0-9._-]+)")
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
MAC_RE = re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}:){5}[0-9a-f]{2}(?![0-9a-f])")
TERMINAL_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


@dataclass
class FollowUpFact:
    fact_id: str
    kind: str
    summary: str
    details: str = ""
    severity: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "fact_id": self.fact_id,
            "kind": self.kind,
            "summary": self.summary,
            "details": self.details,
            "severity": self.severity,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "FollowUpFact":
        return cls(
            fact_id=str(data.get("fact_id") or ""),
            kind=str(data.get("kind") or ""),
            summary=str(data.get("summary") or ""),
            details=str(data.get("details") or ""),
            severity=str(data.get("severity") or ""),
        )


@dataclass
class FollowUpProbe:
    probe_id: str
    title: str
    summary: str
    probe_type: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "probe_id": self.probe_id,
            "probe_type": self.probe_type,
            "title": self.title,
            "summary": self.summary,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "FollowUpProbe":
        return cls(
            probe_id=str(data.get("probe_id") or ""),
            probe_type=str(data.get("probe_type") or ""),
            title=str(data.get("title") or ""),
            summary=str(data.get("summary") or ""),
        )


@dataclass
class FollowUpAction:
    action_id: str
    title: str
    summary: str
    risk: str = "MEDIUM"
    verified: bool = False
    reversible: bool = False

    def to_dict(self) -> Dict[str, object]:
        return {
            "action_id": self.action_id,
            "title": self.title,
            "summary": self.summary,
            "risk": self.risk,
            "verified": self.verified,
            "reversible": self.reversible,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "FollowUpAction":
        return cls(
            action_id=str(data.get("action_id") or ""),
            title=str(data.get("title") or ""),
            summary=str(data.get("summary") or ""),
            risk=str(data.get("risk") or "MEDIUM"),
            verified=bool(data.get("verified", False)),
            reversible=bool(data.get("reversible", False)),
        )


@dataclass
class FollowUpContext:
    context_id: str
    source_type: str
    source_id: str
    phase: str
    title: str
    facts: List[FollowUpFact] = field(default_factory=list)
    probes: List[FollowUpProbe] = field(default_factory=list)
    actions: List[FollowUpAction] = field(default_factory=list)
    metadata: Dict[str, object] = field(default_factory=dict)
    privacy_mode: str = "redacted"
    source_fingerprint: str = ""
    created_at: int = field(default_factory=lambda: int(time.time()))
    updated_at: int = field(default_factory=lambda: int(time.time()))
    schema_version: str = FOLLOWUP_SCHEMA_VERSION

    def to_dict(self) -> Dict[str, object]:
        return {
            "schema": f"{FOLLOWUP_REPORT_TYPE}/{self.schema_version}",
            "schema_version": self.schema_version,
            "report_type": FOLLOWUP_REPORT_TYPE,
            "context_id": self.context_id,
            "source_type": self.source_type,
            "source_id": self.source_id,
            "phase": self.phase,
            "title": self.title,
            "facts": [redact_followup_structure(item.to_dict()) for item in self.facts],
            "probes": [redact_followup_structure(item.to_dict()) for item in self.probes],
            "actions": [redact_followup_structure(item.to_dict()) for item in self.actions],
            "metadata": redact_followup_structure(self.metadata),
            "privacy_mode": self.privacy_mode,
            "source_fingerprint": followup_context_fingerprint(self),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "FollowUpContext":
        schema_version = str(
            data.get("schema_version")
            or str(data.get("schema") or "").partition("/")[2]
            or FOLLOWUP_SCHEMA_VERSION
        )
        if schema_version != FOLLOWUP_SCHEMA_VERSION:
            raise ValueError(f"unsupported follow-up context schema: {schema_version}")
        facts = data.get("facts", [])
        probes = data.get("probes", [])
        actions = data.get("actions", [])
        metadata = data.get("metadata", {})
        return cls(
            context_id=str(data.get("context_id") or ""),
            source_type=str(data.get("source_type") or ""),
            source_id=str(data.get("source_id") or ""),
            phase=str(data.get("phase") or ""),
            title=str(data.get("title") or "AuraScan result"),
            facts=[FollowUpFact.from_dict(item) for item in facts if isinstance(item, Mapping)][:200]
            if isinstance(facts, list)
            else [],
            probes=[FollowUpProbe.from_dict(item) for item in probes if isinstance(item, Mapping)][:24]
            if isinstance(probes, list)
            else [],
            actions=[FollowUpAction.from_dict(item) for item in actions if isinstance(item, Mapping)][:30]
            if isinstance(actions, list)
            else [],
            metadata=dict(metadata) if isinstance(metadata, Mapping) else {},
            privacy_mode=str(data.get("privacy_mode") or "redacted"),
            source_fingerprint=str(data.get("source_fingerprint") or ""),
            created_at=int(data.get("created_at") or 0),
            updated_at=int(data.get("updated_at") or 0),
            schema_version=schema_version,
        )


@dataclass
class FollowUpTurn:
    question: str
    answer: str

    def to_ai_dict(self) -> Dict[str, str]:
        return {
            "question": redact_followup_text(self.question)[:FOLLOWUP_MAX_QUESTION_CHARS],
            "answer": redact_followup_text(self.answer)[:FOLLOWUP_MAX_ANSWER_CHARS],
        }


@dataclass
class FollowUpResponse:
    answer: str
    referenced_fact_ids: List[str] = field(default_factory=list)
    requested_probe_ids: List[str] = field(default_factory=list)
    requested_action_ids: List[str] = field(default_factory=list)
    status: str = "ok"
    error: str = ""


@dataclass
class FollowUpProbeResult:
    probe_id: str
    status: str
    summary: str
    action_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "probe_id": self.probe_id,
            "status": self.status,
            "summary": self.summary,
            "action_ids": list(self.action_ids),
        }


@dataclass
class FollowUpActionOutcome:
    attempted: bool = False
    applied: bool = False
    failed: bool = False
    source_changed: bool = False
    message: str = ""


@dataclass
class FollowUpSessionResult:
    questions: int = 0
    provider_requests: int = 0
    actions_prepared: List[str] = field(default_factory=list)
    action_outcome: FollowUpActionOutcome = field(default_factory=FollowUpActionOutcome)
    provider_failed: bool = False


ProbeRunner = Callable[
    [FollowUpContext, Sequence[str]],
    Tuple[FollowUpContext, Sequence[FollowUpProbeResult]],
]
ActionRunner = Callable[
    [FollowUpContext, Sequence[str], Callable[[str], str], object, object],
    FollowUpActionOutcome,
]


@dataclass
class FollowUpRuntime:
    run_probes: Optional[ProbeRunner] = None
    run_actions: Optional[ActionRunner] = None
    defer_actions: bool = False


def build_ask_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aurascan ask",
        description="Ask the configured AI provider about a retained AuraScan result.",
    )
    parser.add_argument("context_id", nargs="?", help="retained follow-up context or incident report ID")
    parser.add_argument("--latest", action="store_true", help="open the newest retained AuraScan context")
    parser.add_argument("--facts-only", action="store_true", help="omit evidence excerpts from AI requests")
    return parser


def user_followup_root(env: Optional[Mapping[str, str]] = None) -> Path:
    source = env if env is not None else os.environ
    state_home = str(source.get("XDG_STATE_HOME") or "").strip()
    base = Path(state_home) if state_home else Path.home() / ".local" / "state"
    return base / "aurascan" / "follow-up"


def make_context_id(source_type: str, source_id: str = "") -> str:
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    material = f"{source_type}:{source_id}:{time.time_ns()}:{os.getpid()}"
    digest = hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()[:10]
    return f"followup-{timestamp}-{digest}"


def stable_followup_id(prefix: str, *values: object) -> str:
    material = json.dumps([str(item) for item in values], sort_keys=True)
    return prefix + hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()[:16]


def ensure_hardware_health_probe(context: FollowUpContext) -> FollowUpContext:
    probe = FollowUpProbe(
        HARDWARE_HEALTH_PROBE_ID,
        "Inspect hardware, cooling, firmware, and driver context",
        (
            "Collect a bounded read-only CPU, GPU, memory, motherboard, BIOS, sensor, "
            "microcode, package, firmware, and current hardware-error summary."
        ),
        "hardware_health",
    )
    existing = [item for item in context.probes if item.probe_id != HARDWARE_HEALTH_PROBE_ID]
    context.probes = [probe] + existing[:23]
    return context


def _hardware_followup_facts(report: HardwareHealthReport) -> List[FollowUpFact]:
    inventory = dict(report.inventory)
    memory = dict(report.memory)
    gpus = [dict(item) for item in report.gpus[:8]]
    sensor_items = sorted(
        (dict(item) for item in report.sensors[:64]),
        key=lambda item: (
            item.get("status") not in {"alarm", "critical", "fault"},
            item.get("kind") != "temperature",
            str(item.get("chip") or ""),
            str(item.get("label") or ""),
        ),
    )
    return [
        FollowUpFact(
            "hardware-health-summary",
            "hardware_health",
            report.summary,
            f"Collection status: {report.status}; sampled at Unix time {report.collected_at}.",
            (
                "HIGH"
                if any(item.get("status") in {"alarm", "critical", "fault"} for item in sensor_items)
                else "MEDIUM"
                if report.hardware_error_counts
                else "LOW"
            ),
        ),
        FollowUpFact(
            "hardware-cpu-platform",
            "hardware_cpu",
            (
                f"CPU: {inventory.get('cpu_model') or 'unknown'}; active microcode: "
                f"{inventory.get('active_microcode') or 'unknown'}."
            ),
            json.dumps({
                key: inventory.get(key)
                for key in (
                    "cpu_vendor",
                    "cpu_family",
                    "cpu_model_number",
                    "cpu_stepping",
                    "logical_cpus",
                    "system_vendor",
                    "system_model",
                    "board_vendor",
                    "board_model",
                    "board_version",
                    "bios_vendor",
                    "bios_version",
                    "bios_date",
                )
                if inventory.get(key) not in {"", None}
            }, sort_keys=True)[:2400],
        ),
        FollowUpFact(
            "hardware-memory",
            "hardware_memory",
            (
                f"Memory: {float(memory.get('total_mib') or 0) / 1024:.1f} GiB total, "
                f"{float(memory.get('available_mib') or 0) / 1024:.1f} GiB currently available; "
                f"{memory.get('populated_dimms', 'unknown')} populated DIMM(s)."
            ),
            json.dumps({
                **memory,
                "pressure": report.memory_pressure,
            }, sort_keys=True)[:2400],
        ),
        FollowUpFact(
            "hardware-gpu-drivers",
            "hardware_gpu",
            (
                "GPU and driver context: "
                + (
                    "; ".join(
                        f"{item.get('name') or item.get('pci_id') or 'unknown'} "
                        f"({item.get('driver') or 'driver unknown'} "
                        f"{item.get('runtime_driver_version') or item.get('module_version') or ''})".strip()
                        for item in gpus
                    )
                    if gpus
                    else "unavailable"
                )
            ),
            json.dumps(gpus, sort_keys=True)[:2600],
        ),
        FollowUpFact(
            "hardware-sensors-errors",
            "hardware_sensors",
            (
                f"Live cooling sample: {len(sensor_items)} sensor reading(s); "
                f"hardware error categories this boot: {sum(report.hardware_error_counts.values())}."
            ),
            json.dumps({
                "sensors": sensor_items[:24],
                "hardware_error_counts": report.hardware_error_counts,
            }, sort_keys=True)[:3000],
            (
                "HIGH"
                if any(item.get("status") in {"alarm", "critical", "fault"} for item in sensor_items)
                else "MEDIUM"
                if report.hardware_error_counts
                else "LOW"
            ),
        ),
        FollowUpFact(
            "hardware-updates-advisories",
            "hardware_updates",
            (
                f"Firmware status: {report.firmware.get('status', 'unknown')}; "
                f"motherboard/system firmware updates reported by fwupd: "
                f"{report.firmware.get('system_firmware_updates', 0)}; "
                f"{sum(item.get('status') == 'update_available' for item in report.package_updates)} "
                "hardware support package update(s) found in the local repositories."
            ),
            json.dumps({
                "package_updates": report.package_updates,
                "firmware": report.firmware,
                "advisories": report.advisories,
                "notes": report.notes,
                "pacman_sync_age_hours": inventory.get("pacman_sync_age_hours"),
            }, sort_keys=True)[:3200],
            (
                "MEDIUM"
                if report.firmware.get("status") == "updates_available"
                or any(item.get("status") == "update_available" for item in report.package_updates)
                or any(
                    item.get("status") == "active_microcode_below_guidance"
                    for item in report.advisories
                )
                else "LOW"
            ),
        ),
    ]


def add_hardware_health_to_context(
    context: FollowUpContext,
    report: HardwareHealthReport,
) -> FollowUpContext:
    ensure_hardware_health_probe(context)
    retained = [
        item
        for item in context.facts
        if not item.fact_id.startswith("hardware-")
    ]
    hardware = _hardware_followup_facts(report)
    context.facts = (retained[:1] + hardware + retained[1:])[:200]
    context.metadata["hardware_health"] = {
        "status": report.status,
        "collected_at": report.collected_at,
        "sensor_count": len(report.sensors),
        "firmware_status": report.firmware.get("status", "unknown"),
    }
    context.updated_at = int(time.time())
    context.source_fingerprint = followup_context_fingerprint(context)
    return context


def with_hardware_health_runtime(
    context: FollowUpContext,
    runtime: FollowUpRuntime,
    *,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
) -> FollowUpRuntime:
    ensure_hardware_health_probe(context)
    if bool(getattr(runtime, "_hardware_health_enabled", False)):
        return runtime
    base_probes = runtime.run_probes

    def probes_callback(
        current: FollowUpContext,
        probe_ids: Sequence[str],
    ) -> Tuple[FollowUpContext, Sequence[FollowUpProbeResult]]:
        selected = list(dict.fromkeys(str(item) for item in probe_ids))
        hardware_requested = HARDWARE_HEALTH_PROBE_ID in selected
        remaining = [item for item in selected if item != HARDWARE_HEALTH_PROBE_ID]
        refreshed = current
        results: List[FollowUpProbeResult] = []
        if remaining and base_probes is not None:
            refreshed, base_results = base_probes(refreshed, remaining)
            results.extend(base_results)
        if hardware_requested:
            report = collect_hardware_health(
                runner=runner,
                which=which,
                refresh_firmware_metadata=True,
            )
            refreshed = add_hardware_health_to_context(refreshed, report)
            results.append(FollowUpProbeResult(
                HARDWARE_HEALTH_PROBE_ID,
                "ok" if report.status == "ok" else "partial",
                report.summary,
                [],
            ))
        return refreshed, results

    wrapped = FollowUpRuntime(
        run_probes=probes_callback,
        run_actions=runtime.run_actions,
        defer_actions=runtime.defer_actions,
    )
    setattr(wrapped, "_hardware_health_enabled", True)
    return wrapped


def followup_context_fingerprint(context: FollowUpContext) -> str:
    payload = {
        "source_type": context.source_type,
        "source_id": context.source_id,
        "phase": context.phase,
        "facts": [redact_followup_structure(item.to_dict()) for item in context.facts],
        "probes": [redact_followup_structure(item.to_dict()) for item in context.probes],
        "actions": [redact_followup_structure(item.to_dict()) for item in context.actions],
        "metadata": redact_followup_structure(context.metadata),
    }
    material = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()


def persist_followup_context(context: FollowUpContext, root: Optional[Path] = None) -> Path:
    root = root or user_followup_root()
    ensure_private_directory(root)
    context.updated_at = int(time.time())
    context.source_fingerprint = followup_context_fingerprint(context)
    if not SAFE_CONTEXT_ID_RE.fullmatch(context.context_id):
        raise ValueError("unsafe follow-up context ID")
    path = root / f"{context.context_id}.json"
    atomic_write_private_json(path, context.to_dict())
    prune_followup_contexts(root)
    return path


def load_followup_context(context_id: str, root: Optional[Path] = None) -> Optional[FollowUpContext]:
    if not SAFE_CONTEXT_ID_RE.fullmatch(str(context_id or "")):
        return None
    root = root or user_followup_root()
    if not private_user_directory(root):
        return None
    path = root / f"{context_id}.json"
    if not private_user_file(path):
        return None
    try:
        if path.stat().st_size > FOLLOWUP_MAX_CONTEXT_BYTES:
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, Mapping) or data.get("report_type") != FOLLOWUP_REPORT_TYPE:
            return None
        context = FollowUpContext.from_dict(data)
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None
    if (
        context.context_id != context_id
        or not context.source_type
        or not context.source_fingerprint
        or context.source_fingerprint != followup_context_fingerprint(context)
    ):
        return None
    return context


def latest_followup_context(root: Optional[Path] = None) -> Optional[FollowUpContext]:
    root = root or user_followup_root()
    if not private_user_directory(root):
        return None
    try:
        paths = sorted(root.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True)
    except OSError:
        return None
    for path in paths[:FOLLOWUP_MAX_CONTEXTS]:
        context = load_followup_context(path.stem, root)
        if context is not None:
            return context
    return None


def prune_followup_contexts(root: Path, *, now: Optional[float] = None) -> None:
    now = time.time() if now is None else now
    cutoff = now - FOLLOWUP_RETENTION_DAYS * 86400
    try:
        paths = sorted(root.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True)
    except OSError:
        return
    for index, path in enumerate(paths):
        try:
            stale = path.stat().st_mtime < cutoff
        except OSError:
            continue
        if index >= FOLLOWUP_MAX_CONTEXTS or stale:
            try:
                path.unlink()
            except OSError:
                pass


def followup_doctor_status(
    env: Optional[Mapping[str, str]] = None,
    *,
    root: Optional[Path] = None,
) -> Dict[str, object]:
    source = dict(os.environ if env is None else env)
    context_root = root or user_followup_root(source)
    config = resolve_ai_config(source)
    exists = context_root.exists()
    safe = False
    error = ""
    if exists:
        try:
            metadata = context_root.stat()
            safe = (
                context_root.is_dir()
                and not context_root.is_symlink()
                and metadata.st_uid == current_user_uid()
                and metadata.st_mode & 0o077 == 0
            )
            if not safe:
                error = "follow-up context directory must be user-owned with 0700 permissions"
        except OSError as exc:
            error = str(exc)
    latest = latest_followup_context(context_root) if not exists or safe else None
    return {
        "provider_ready": not config.error and config.enabled and config.api_key_present,
        "root": str(context_root),
        "storage_exists": exists,
        "storage_safe": safe if exists else True,
        "latest_context_id": latest.context_id if latest else "",
        "latest_context_age_seconds": max(0, int(time.time()) - latest.updated_at) if latest else None,
        "error": error,
    }


def context_from_upgrade(
    report,
    *,
    phase: str,
    outcome: Optional[Mapping[str, object]] = None,
    context_id: str = "",
    metadata: Optional[Mapping[str, object]] = None,
) -> FollowUpContext:
    plan = report.plan
    facts = [
        FollowUpFact(
            "upgrade-summary",
            "summary",
            f"{len(plan.repo_packages)} repository package(s) and {len(plan.aur_packages)} AUR package(s) are planned.",
            f"Highest risk: {report.highest_severity.value}; action: {report.action}; helper: {plan.selected_helper}.",
            report.highest_severity.value,
        ),
    ]
    for index, package in enumerate((plan.repo_packages + plan.aur_packages)[:120]):
        facts.append(FollowUpFact(
            stable_followup_id("fuf-upkg-", index, package.name, package.new_version),
            "package",
            f"{package.name}: {package.old_version or 'not installed'} -> {package.new_version or 'unknown'}",
            f"Repository/type: {package.repo or package.package_type}; conflicts: {', '.join(package.conflicts[:8]) or 'none'}; replaces: {', '.join(package.replaces[:8]) or 'none'}.",
        ))
    for index, finding in enumerate(report.terminal_findings()[:30]):
        facts.append(FollowUpFact(
            stable_followup_id("fuf-ufind-", index, finding.rule_id, finding.evidence),
            "finding",
            f"{finding.title} [{finding.severity.value}]",
            f"{finding.summary} Why it matters: {finding.why_it_matters} AuraScan response: {finding.recommended_action}",
            finding.severity.value,
        ))
    if report.kernel_module_check is not None:
        check = report.kernel_module_check
        facts.append(FollowUpFact(
            "upgrade-kernel-module",
            "kernel_module",
            check.summary,
            json.dumps(redact_followup_structure(check.to_dict()), sort_keys=True)[:3000],
        ))
    if report.repository_health is not None:
        facts.append(FollowUpFact(
            "upgrade-repository-health",
            "repository",
            report.repository_health.summary,
            f"Status: {report.repository_health.status}; enabled repositories: {', '.join(report.repository_health.enabled_repositories[:20])}.",
        ))
    ai_summary = str(report.ai_review.get("summary") or "") if isinstance(report.ai_review, Mapping) else ""
    if ai_summary:
        facts.append(FollowUpFact("upgrade-ai-summary", "ai_summary", "Earlier AI review", ai_summary))
    if outcome:
        status = str(outcome.get("status") or "unknown")
        facts.append(FollowUpFact(
            "upgrade-outcome",
            "outcome",
            f"Upgrade outcome: {status}",
            redact_followup_text(str(outcome.get("summary") or ""))[:2000],
            str(outcome.get("severity") or ""),
        ))

    probes = [
        FollowUpProbe(
            FOLLOWUP_PROBE_UPGRADE_REFRESH,
            "Refresh upgrade preflight",
            "Rerun the deterministic package, repository, and kernel/module checks without starting the upgrade.",
            "upgrade_refresh",
        )
    ]
    actions: List[FollowUpAction] = []
    if report.repository_health is not None and report.repository_health.fixable_issues:
        actions.append(FollowUpAction(
            FOLLOWUP_ACTION_REPOSITORY,
            "Restore verified repository mirror configuration",
            report.repository_health.summary,
            "MEDIUM",
            True,
            True,
        ))
    if report.kernel_module_check is not None and report.kernel_module_check.fix_packages():
        packages = ", ".join(report.kernel_module_check.fix_packages())
        actions.append(FollowUpAction(
            FOLLOWUP_ACTION_KERNEL,
            "Install verified kernel support packages",
            f"Install the currently verified missing support packages: {packages}.",
            "MEDIUM",
            True,
            False,
        ))
    if report.snapshot.pacnew_count or report.snapshot.pacsave_count:
        actions.append(FollowUpAction(
            FOLLOWUP_ACTION_CONFIG_DRIFT,
            "Run Config Drift Assistant",
            f"Handle {report.snapshot.pacnew_count} .pacnew and {report.snapshot.pacsave_count} .pacsave file(s) through the existing guarded assistant.",
            "MEDIUM",
            True,
            True,
        ))
    context = FollowUpContext(
        context_id=context_id or make_context_id("upgrade", phase),
        source_type="upgrade",
        source_id=f"upgrade-{int(time.time())}",
        phase=phase,
        title="AuraScan Upgrade",
        facts=facts,
        probes=probes,
        actions=actions,
        metadata={
            "selected_helper": plan.selected_helper,
            "phase": phase,
            **dict(metadata or {}),
        },
        privacy_mode="redacted",
    )
    ensure_hardware_health_probe(context)
    context.source_fingerprint = followup_context_fingerprint(context)
    return context


def context_from_incident(
    report,
    *,
    context_id: str = "",
    metadata: Optional[Mapping[str, object]] = None,
    privacy_mode: str = "redacted",
) -> FollowUpContext:
    facts: List[FollowUpFact] = [
        FollowUpFact(
            "incident-summary",
            "summary",
            f"{len(report.findings)} finding(s) and {sum(item.count for item in report.coredumps)} application crash record(s).",
            f"Risk: {report.highest_severity.value}; collection: {report.collection_status}; truncated: {report.truncated}.",
            report.highest_severity.value,
        )
    ]
    for index, finding in enumerate(report.findings[:30]):
        facts.append(FollowUpFact(
            stable_followup_id("fuf-ifind-", index, finding.rule_id, finding.category),
            "finding",
            f"{finding.title} [{finding.severity.value}]",
            f"{finding.summary} Why it matters: {finding.why_it_matters} AuraScan response: {finding.recommended_action}",
            finding.severity.value,
        ))
    if privacy_mode != "facts-only":
        for item in report.evidence[:80]:
            facts.append(FollowUpFact(
                item.evidence_id,
                "evidence",
                f"{item.source}: {item.unit or item.executable or item.package or 'system evidence'}",
                redact_followup_text(item.message)[:1000],
                item.severity.value,
            ))
    for index, group in enumerate(report.coredumps[:30]):
        facts.append(FollowUpFact(
            stable_followup_id("fuf-crash-", index, group.signature),
            "coredump",
            f"{group.executable or 'Application'} crashed with {group.signal} {group.count} time(s).",
            f"Package: {group.package or 'unknown'}; top frame: {group.top_frame or 'unavailable'}.",
            "MEDIUM" if group.count >= 3 else "LOW",
        ))
    ai_summary = str(report.ai_review.get("summary") or "") if isinstance(report.ai_review, Mapping) else ""
    if ai_summary:
        facts.append(FollowUpFact("incident-ai-summary", "ai_summary", "Earlier AI review", ai_summary))
    probes = [
        FollowUpProbe(item.probe_id, item.title, item.summary, item.probe_type)
        for item in report.diagnostic_probes[:24]
    ]
    actions = [
        FollowUpAction(
            item.action_id,
            item.title,
            item.summary,
            item.risk.value,
            item.eligible and item.verified,
            item.reversible,
        )
        for item in report.eligible_actions[:30]
    ]
    action_probe_map: Dict[str, List[str]] = {}
    for result in report.probe_results:
        for action_id in result.action_ids:
            action_probe_map.setdefault(action_id, []).append(result.probe_id)
    context = FollowUpContext(
        context_id=context_id or make_context_id("incident", report.incident_id),
        source_type="incident",
        source_id=report.incident_id,
        phase=str(report.trigger or "incident"),
        title="AuraScan Incident Recovery",
        facts=facts,
        probes=probes,
        actions=actions,
        metadata={
            "target_boot": report.target_boot,
            "boot_id": report.boot_id,
            "collection_status": report.collection_status,
            "truncated": report.truncated,
            "action_probe_map": action_probe_map,
            **dict(metadata or {}),
        },
        privacy_mode=privacy_mode,
    )
    ensure_hardware_health_probe(context)
    context.source_fingerprint = followup_context_fingerprint(context)
    return context


def context_from_config_drift(
    report,
    *,
    context_id: str = "",
    ai_diffs_allowed: bool = False,
    metadata: Optional[Mapping[str, object]] = None,
) -> FollowUpContext:
    from aurascan.core.config_drift import config_drift_action_id, redacted_preview_diff

    facts = [
        FollowUpFact(
            "config-drift-summary",
            "summary",
            f"{len(report.files)} drift file(s), {len(report.apply_actions)} planned fix(es), and {len(report.manual_actions)} manual item(s).",
            f"Scan truncated: {report.scan_truncated}; errors: {len(report.errors)}; AI diffs allowed: {ai_diffs_allowed}.",
            "MEDIUM" if report.files else "LOW",
        )
    ]
    for index, action in enumerate(report.actions[:100]):
        diff_note = ""
        if ai_diffs_allowed:
            redacted_diff = redacted_preview_diff(
                action.drift_file.target_path,
                action.drift_file.path,
                max_chars=2000,
            )
            if redacted_diff:
                diff_note = f" Redacted diff preview:\n{redacted_diff}"
        facts.append(FollowUpFact(
            stable_followup_id("fuf-drift-", index, str(action.drift_file.path), action.action),
            "config_drift",
            f"{action.drift_file.path}: {action.action}",
            (
                f"{action.summary} Risk: {action.drift_file.risk}; "
                f"sensitive: {action.drift_file.sensitive}; applies: {action.applies}."
                f"{diff_note}"
            ),
            "HIGH" if action.drift_file.sensitive and not action.applies else "MEDIUM",
        ))
    actions = [
        FollowUpAction(
            config_drift_action_id(item),
            f"Apply {item.action} to {item.drift_file.path}",
            item.summary,
            "HIGH" if item.drift_file.sensitive else "MEDIUM",
            item.applies,
            item.backup_required,
        )
        for item in report.apply_actions[:30]
    ]
    context = FollowUpContext(
        context_id=context_id or make_context_id("config-drift", report.root),
        source_type="config_drift",
        source_id=stable_followup_id("config-", report.root, int(time.time())),
        phase="config_drift",
        title="AuraScan Config Drift",
        facts=facts,
        probes=[],
        actions=actions,
        metadata={
            "root": report.root,
            "ai_diffs_allowed": bool(ai_diffs_allowed),
            "scan_truncated": report.scan_truncated,
            **dict(metadata or {}),
        },
        privacy_mode="redacted" if ai_diffs_allowed else "facts-only",
    )
    ensure_hardware_health_probe(context)
    context.source_fingerprint = followup_context_fingerprint(context)
    return context


def context_from_maintenance(
    status: Mapping[str, object],
    marker: Optional[Mapping[str, object]] = None,
    *,
    context_id: str = "",
) -> FollowUpContext:
    facts = [
        FollowUpFact(
            "maintenance-summary",
            "summary",
            f"Weekly maintenance result: {status.get('collection_status', 'unknown')}.",
            f"Last success: {status.get('last_success_usec', 0)}; overdue: {bool(status.get('overdue', False))}; incomplete: {bool(status.get('incomplete', False))}.",
            str(marker.get("severity") or "LOW") if marker else "LOW",
        )
    ]
    probes: List[FollowUpProbe] = []
    metadata: Dict[str, object] = {"status": redact_followup_structure(status)}
    if marker:
        categories = marker.get("categories", [])
        facts.append(FollowUpFact(
            "maintenance-marker",
            "finding",
            f"Maintenance recorded an actionable {marker.get('severity', 'unknown')} marker.",
            f"Categories: {', '.join(str(item) for item in categories[:20]) if isinstance(categories, list) else 'bounded system findings'}.",
            str(marker.get("severity") or ""),
        ))
        probes.append(FollowUpProbe(
            FOLLOWUP_PROBE_MAINTENANCE_INCIDENT,
            "Open detailed incident evidence",
            "Collect a user-scoped bounded incident report for the boot referenced by the maintenance marker.",
            "maintenance_incident",
        ))
        metadata.update({
            "boot_id": str(marker.get("boot_id") or ""),
            "scan_id": str(marker.get("scan_id") or ""),
            "marker_type": str(marker.get("marker_type") or ""),
            "marker": {
                key: marker.get(key)
                for key in (
                    "marker_type",
                    "scan_id",
                    "boot_id",
                    "uid_scope",
                    "severity",
                    "categories",
                    "category_severities",
                    "resolved_categories",
                    "count",
                    "repeated",
                )
            },
        })
    context = FollowUpContext(
        context_id=context_id or make_context_id("maintenance", str(metadata.get("scan_id") or "")),
        source_type="maintenance",
        source_id=str(metadata.get("scan_id") or f"maintenance-{int(time.time())}"),
        phase="weekly_maintenance",
        title="AuraScan System Maintenance",
        facts=facts,
        probes=probes,
        actions=[],
        metadata=metadata,
        privacy_mode="facts-only",
    )
    ensure_hardware_health_probe(context)
    context.source_fingerprint = followup_context_fingerprint(context)
    return context


def followup_available(
    *,
    env: Optional[Mapping[str, str]] = None,
    stdout=None,
    stdin=None,
    disabled: bool = False,
    force_interactive: Optional[bool] = None,
) -> bool:
    if disabled:
        return False
    source = dict(os.environ if env is None else env)
    if (
        source.get("AURASCAN_RECOVERY_RUNTIME", "").strip().lower() in {"1", "true", "yes", "on"}
        or FOLLOWUP_RECOVERY_RUNTIME_MARKER.exists()
    ):
        return False
    config = resolve_ai_config(source)
    if config.error or not config.enabled or not config.api_key_present:
        return False
    if force_interactive is not None:
        return bool(force_interactive)
    stdout = stdout or sys.stdout
    stdin = stdin or sys.stdin
    return bool(
        getattr(stdout, "isatty", lambda: False)()
        and getattr(stdin, "isatty", lambda: False)()
    )


def build_followup_ai_prompt(
    context: FollowUpContext,
    question: str,
    turns: Sequence[FollowUpTurn],
    *,
    facts_only: bool = False,
    probe_results: Sequence[FollowUpProbeResult] = (),
) -> str:
    instructions = (
        "You are AuraScan's contextual assistant for Arch-family Linux systems.\n"
        "Answer only from the supplied bounded redacted facts and conversation.\n"
        "Be calm, direct, and honest about uncertainty. Never claim that a system, package, or repair is guaranteed safe.\n"
        "You may request only known opaque probe IDs and known verified action IDs supplied below.\n"
        "Never create or suggest shell commands, scripts, package targets, file paths, file edits, service names, bootloader changes, reboots, or arbitrary repairs.\n"
        "Do not claim an action ran or succeeded. AuraScan's deterministic code owns all validation, confirmation, and execution.\n"
        "Return strict JSON only with this shape:\n"
        "{\"answer\":\"plain-language answer\",\"referenced_fact_ids\":[\"known fact id\"],\"requested_probe_ids\":[\"known probe id\"],\"requested_action_ids\":[\"known action id\"]}\n\n"
    )
    facts = []
    for item in context.facts:
        facts.append({
            "fact_id": item.fact_id,
            "kind": item.kind,
            "summary": redact_followup_text(item.summary)[:1000],
            "details": (
                ""
                if facts_only and item.kind == "evidence"
                else redact_followup_text(item.details)[:4000]
            ),
            "severity": item.severity,
        })
    payload = {
        "context": {
            "context_id": context.context_id,
            "source_type": context.source_type,
            "phase": context.phase,
            "title": context.title,
            "privacy_mode": "facts-only" if facts_only else context.privacy_mode,
        },
        "facts": facts,
        "available_probes": [item.to_dict() for item in context.probes],
        "available_actions": [item.to_dict() for item in context.actions if item.verified],
        "probe_results": [item.to_dict() for item in probe_results],
        "conversation": [item.to_ai_dict() for item in turns],
        "question": redact_followup_text(question)[:FOLLOWUP_MAX_QUESTION_CHARS],
        "input_truncated": False,
    }
    prompt = instructions + json.dumps(payload, sort_keys=True)
    while len(prompt) > FOLLOWUP_MAX_PROMPT_CHARS:
        payload["input_truncated"] = True
        if payload["conversation"]:
            payload["conversation"].pop(0)
        elif payload["facts"] and len(payload["facts"]) > 1:
            payload["facts"].pop()
        elif payload["probe_results"]:
            payload["probe_results"].pop()
        elif payload["available_probes"]:
            payload["available_probes"].pop()
        elif payload["available_actions"]:
            payload["available_actions"].pop()
        else:
            break
        prompt = instructions + json.dumps(payload, sort_keys=True)
    return prompt[:FOLLOWUP_MAX_PROMPT_CHARS]


def validate_followup_ai_response(
    context: FollowUpContext,
    data: Mapping[str, object],
) -> FollowUpResponse:
    if not isinstance(data.get("answer"), str):
        raise ValueError("follow-up response answer must be a string")
    for key in ("referenced_fact_ids", "requested_probe_ids", "requested_action_ids"):
        if not isinstance(data.get(key), list):
            raise ValueError(f"follow-up response {key} must be a list")
    known_facts = {item.fact_id for item in context.facts}
    known_probes = {item.probe_id for item in context.probes}
    known_actions = {item.action_id for item in context.actions if item.verified}
    return FollowUpResponse(
        answer=redact_followup_text(str(data.get("answer") or ""))[:FOLLOWUP_MAX_ANSWER_CHARS],
        referenced_fact_ids=_known_unique_ids(data.get("referenced_fact_ids"), known_facts, 20),
        requested_probe_ids=_known_unique_ids(data.get("requested_probe_ids"), known_probes, 6),
        requested_action_ids=_known_unique_ids(data.get("requested_action_ids"), known_actions, 20),
    )


def ask_followup_ai(
    context: FollowUpContext,
    question: str,
    turns: Sequence[FollowUpTurn],
    *,
    facts_only: bool = False,
    probe_results: Sequence[FollowUpProbeResult] = (),
    env: Optional[Mapping[str, str]] = None,
    urlopen: Optional[Callable] = None,
) -> FollowUpResponse:
    source = dict(os.environ if env is None else env)
    config = resolve_ai_config(source)
    if config.error:
        return FollowUpResponse("", status="config_error", error=config.error)
    if not config.enabled or not config.api_key_present:
        return FollowUpResponse("", status="not_configured", error="network AI is disabled or not configured")
    prompt = build_followup_ai_prompt(
        context,
        question,
        turns,
        facts_only=facts_only,
        probe_results=probe_results,
    )
    try:
        text = call_ai_provider(
            config,
            prompt,
            timeout=FOLLOWUP_AI_TIMEOUT_SECONDS,
            urlopen=urlopen,
        )
        data = json.loads(text)
        if not isinstance(data, Mapping):
            raise ValueError("follow-up response was not a JSON object")
        return validate_followup_ai_response(context, data)
    except Exception as exc:
        return FollowUpResponse(
            "",
            status=classify_followup_failure(exc),
            error=redact_followup_text(str(exc))[:500],
        )


def run_followup_session(
    context: FollowUpContext,
    *,
    runtime: Optional[FollowUpRuntime] = None,
    input_func: Callable[[str], str] = input,
    stdout=None,
    stderr=None,
    env: Optional[Mapping[str, str]] = None,
    facts_only: bool = False,
    urlopen: Optional[Callable] = None,
    context_root: Optional[Path] = None,
    first_prompt: str = "Ask AuraScan about this result, or press Enter to finish: ",
) -> FollowUpSessionResult:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    runtime = runtime or FollowUpRuntime()
    result = FollowUpSessionResult()
    turns: List[FollowUpTurn] = []
    current = context
    maintenance_opened = False
    hardware_opened = bool(current.metadata.get("hardware_health"))
    ensure_hardware_health_probe(current)
    persist_followup_context(current, context_root)
    prompt = first_prompt
    while result.questions < FOLLOWUP_MAX_QUESTIONS and result.provider_requests < FOLLOWUP_MAX_PROVIDER_REQUESTS:
        try:
            question = input_func(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            print("", file=stdout)
            break
        if not question:
            break
        if question == "/stop":
            print("[AuraScan] Follow-up session closed.", file=stdout)
            break
        if question == "/status":
            print(
                f"[AuraScan] Follow-up status: guarded tools only; "
                f"questions={result.questions}/{FOLLOWUP_MAX_QUESTIONS}, "
                f"provider requests={result.provider_requests}/{FOLLOWUP_MAX_PROVIDER_REQUESTS}.",
                file=stdout,
            )
            continue
        if question == "/agent" or question.startswith("/agent "):
            from aurascan.core.agent import (
                AGENT_ACCESS_ORDER,
                AGENT_ACCESS_VALUES,
                run_agent_session,
                resolve_agent_config,
            )

            agent_config = resolve_agent_config(env)
            requested_access = question.partition(" ")[2].strip() or agent_config.access
            if agent_config.error:
                print(f"[AuraScan] Repair Agent configuration error: {agent_config.error}.", file=stderr)
                continue
            if requested_access not in AGENT_ACCESS_VALUES:
                print(
                    "[AuraScan] Usage: /agent guarded|user-shell|root-shell",
                    file=stdout,
                )
                continue
            if requested_access == "guarded":
                print(
                    "[AuraScan] This follow-up session is already using guarded AuraScan tools.",
                    file=stdout,
                )
                continue
            if AGENT_ACCESS_ORDER[requested_access] > AGENT_ACCESS_ORDER[agent_config.access]:
                print(
                    f"[AuraScan] {requested_access} exceeds the configured access ceiling "
                    f"{agent_config.access}. Change it through `aurascan init` first.",
                    file=stderr,
                )
                continue
            agent_result = run_agent_session(
                current,
                access=requested_access,
                approval=agent_config.approval,
                output_sharing=agent_config.output_sharing,
                session_timeout_minutes=agent_config.session_timeout_minutes,
                runtime=runtime,
                input_func=input_func,
                stdout=stdout,
                stderr=stderr,
                env=env,
                facts_only=facts_only,
                urlopen=urlopen,
                context_root=context_root,
            )
            result.provider_requests += agent_result.provider_requests
            result.action_outcome = agent_result.action_outcome
            result.provider_failed = result.provider_failed or agent_result.provider_failed
            if agent_result.action_outcome.applied or agent_result.action_outcome.source_changed:
                break
            prompt = "Ask another question, or press Enter to finish: "
            continue
        result.questions += 1
        initial_probe_results: List[FollowUpProbeResult] = []
        if (
            not maintenance_opened
            and current.source_type == "maintenance"
            and any(
                item.probe_id == FOLLOWUP_PROBE_MAINTENANCE_INCIDENT
                for item in current.probes
            )
            and runtime.run_probes
        ):
            maintenance_opened = True
            print(
                "[AuraScan] Opening the matching user-scoped incident analysis...",
                file=stdout,
                flush=True,
            )
            try:
                current, maintenance_results = runtime.run_probes(
                    current,
                    [FOLLOWUP_PROBE_MAINTENANCE_INCIDENT],
                )
                initial_probe_results.extend(maintenance_results)
            except Exception as exc:
                initial_probe_results = [
                    FollowUpProbeResult(
                        FOLLOWUP_PROBE_MAINTENANCE_INCIDENT,
                        "failed",
                        redact_followup_text(str(exc))[:500],
                    )
                ]
            persist_followup_context(current, context_root)
        if (
            not hardware_opened
            and question_requests_hardware_context(question)
            and any(item.probe_id == HARDWARE_HEALTH_PROBE_ID for item in current.probes)
            and runtime.run_probes
        ):
            hardware_opened = True
            print(
                "[AuraScan] Checking CPU, GPU, memory, cooling, firmware, and driver context...",
                file=stdout,
                flush=True,
            )
            try:
                current, hardware_results = runtime.run_probes(
                    current,
                    [HARDWARE_HEALTH_PROBE_ID],
                )
                initial_probe_results.extend(hardware_results)
            except Exception as exc:
                initial_probe_results.append(FollowUpProbeResult(
                    HARDWARE_HEALTH_PROBE_ID,
                    "failed",
                    redact_followup_text(str(exc))[:500],
                ))
            persist_followup_context(current, context_root)
        print("[AuraScan] Asking AI about the current AuraScan result...", file=stdout, flush=True)
        response = ask_followup_ai(
            current,
            question,
            turns,
            facts_only=facts_only or current.privacy_mode == "facts-only",
            probe_results=initial_probe_results,
            env=env,
            urlopen=urlopen,
        )
        result.provider_requests += 1
        if response.status != "ok":
            result.provider_failed = True
            print(
                f"[AuraScan] Follow-up AI was unavailable ({response.status}). "
                "The original AuraScan result remains valid.",
                file=stderr,
            )
            if response.error:
                print(f"[AuraScan] Provider detail: {response.error}", file=stderr)
            break

        if response.requested_probe_ids and runtime.run_probes:
            print(
                f"[AuraScan] Running {len(response.requested_probe_ids)} bounded local verification check(s)...",
                file=stdout,
                flush=True,
            )
            try:
                refreshed, probe_results = runtime.run_probes(current, response.requested_probe_ids)
            except Exception as exc:
                refreshed = current
                probe_results = [
                    FollowUpProbeResult(
                        response.requested_probe_ids[0],
                        "failed",
                        redact_followup_text(str(exc))[:500],
                    )
                ]
            current = refreshed
            persist_followup_context(current, context_root)
            if result.provider_requests < FOLLOWUP_MAX_PROVIDER_REQUESTS:
                print("[AuraScan] Asking AI to review the locally verified results...", file=stdout, flush=True)
                response = ask_followup_ai(
                    current,
                    question,
                    turns,
                    facts_only=facts_only or current.privacy_mode == "facts-only",
                    probe_results=probe_results,
                    env=env,
                    urlopen=urlopen,
                )
                result.provider_requests += 1
                if response.status != "ok":
                    result.provider_failed = True
                    summaries = " ".join(item.summary for item in probe_results)
                    response = FollowUpResponse(
                        answer=(
                            "The AI review did not complete, but AuraScan's local verification did. "
                            + redact_followup_text(summaries)[:2000]
                        ),
                        status="local_only",
                    )

        print("\n[AuraScan] Follow-up answer", file=stdout)
        print(response.answer or "AuraScan did not receive a usable explanatory answer.", file=stdout)
        action_ids = response.requested_action_ids
        if action_ids:
            result.actions_prepared = list(dict.fromkeys(result.actions_prepared + action_ids))
            if runtime.defer_actions:
                _print_deferred_actions(current, action_ids, stdout)
            elif runtime.run_actions:
                print(
                    "[AuraScan] Refreshing local state and preparing a verified action plan...",
                    file=stdout,
                    flush=True,
                )
                outcome = runtime.run_actions(current, action_ids, input_func, stdout, stderr)
                result.action_outcome = outcome
                if outcome.message:
                    print(outcome.message, file=stdout if not outcome.failed else stderr)
                if outcome.applied or outcome.source_changed:
                    break
            else:
                print(
                    "[AuraScan] The requested operation is not executable from this retained context. "
                    "No command was generated or run.",
                    file=stdout,
                )
        turns.append(FollowUpTurn(question, response.answer))
        prompt = "Ask another question, or press Enter to finish: "
    if result.questions >= FOLLOWUP_MAX_QUESTIONS:
        print("[AuraScan] Follow-up question limit reached for this session.", file=stdout)
    elif result.provider_requests >= FOLLOWUP_MAX_PROVIDER_REQUESTS:
        print("[AuraScan] Follow-up AI request limit reached for this session.", file=stdout)
    return result


def prompt_with_followup(
    prompt: str,
    context: FollowUpContext,
    *,
    runtime: Optional[FollowUpRuntime] = None,
    input_func: Callable[[str], str] = input,
    stdout=None,
    stderr=None,
    env: Optional[Mapping[str, str]] = None,
    facts_only: bool = False,
    urlopen: Optional[Callable] = None,
    context_root: Optional[Path] = None,
    force_interactive: Optional[bool] = None,
) -> Tuple[str, FollowUpSessionResult]:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    empty = FollowUpSessionResult()
    if not followup_available(
        env=env,
        stdout=stdout,
        disabled=False,
        force_interactive=force_interactive,
    ):
        return input_func(prompt), empty
    persist_followup_context(context, context_root)
    decorated = prompt.rstrip()
    if decorated.endswith("]"):
        decorated = decorated[:-1] + "/?]"
    else:
        decorated += " [? for questions]"
    decorated += " "
    last_session = empty
    while True:
        try:
            answer = input_func(decorated)
        except (EOFError, KeyboardInterrupt):
            return "", empty
        if answer.strip() != "?":
            return answer, last_session
        session = run_followup_session(
            context,
            runtime=runtime,
            input_func=input_func,
            stdout=stdout,
            stderr=stderr,
            env=env,
            facts_only=facts_only,
            urlopen=urlopen,
            context_root=context_root,
        )
        last_session = session
        if session.action_outcome.applied or session.action_outcome.source_changed:
            return "", session


def offer_followup(
    context: FollowUpContext,
    *,
    runtime: Optional[FollowUpRuntime] = None,
    input_func: Callable[[str], str] = input,
    stdout=None,
    stderr=None,
    env: Optional[Mapping[str, str]] = None,
    facts_only: bool = False,
    urlopen: Optional[Callable] = None,
    context_root: Optional[Path] = None,
    disabled: bool = False,
    force_interactive: Optional[bool] = None,
) -> FollowUpSessionResult:
    stdout = stdout or sys.stdout
    if not followup_available(
        env=env,
        stdout=stdout,
        disabled=disabled,
        force_interactive=force_interactive,
    ):
        return FollowUpSessionResult()
    return run_followup_session(
        context,
        runtime=runtime,
        input_func=input_func,
        stdout=stdout,
        stderr=stderr,
        env=env,
        facts_only=facts_only,
        urlopen=urlopen,
        context_root=context_root,
    )


def run_ask(
    argv: Optional[Sequence[str]] = None,
    *,
    input_func: Callable[[str], str] = input,
    stdout=None,
    stderr=None,
    env: Optional[Mapping[str, str]] = None,
    urlopen: Optional[Callable] = None,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
    context_root: Optional[Path] = None,
    incident_root: Optional[Path] = None,
    system_root: Optional[Path] = None,
    force_interactive: Optional[bool] = None,
) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    args = build_ask_parser().parse_args(list(argv or []))
    source = dict(os.environ if env is None else env)
    if (
        source.get("AURASCAN_RECOVERY_RUNTIME", "").strip().lower() in {"1", "true", "yes", "on"}
        or FOLLOWUP_RECOVERY_RUNTIME_MARKER.exists()
    ):
        print(
            "[AuraScan] Contextual follow-up is not available inside AuraScan Recovery v1.",
            file=stderr,
        )
        return EXIT_FOLLOWUP_UNAVAILABLE
    config = resolve_ai_config(source)
    if config.error or not config.enabled or not config.api_key_present:
        detail = config.error or "network AI is disabled or not configured"
        print(f"[AuraScan] Follow-up assistant unavailable: {detail}.", file=stderr)
        return EXIT_FOLLOWUP_UNAVAILABLE
    root = context_root or user_followup_root(source)
    context: Optional[FollowUpContext]
    if args.context_id and not args.latest:
        context = load_followup_context(args.context_id, root)
        if context is None:
            context = context_from_saved_incident(
                args.context_id,
                env=source,
                incident_root=incident_root,
            )
            if context is not None:
                persist_followup_context(context, root)
    else:
        context = latest_followup_context(root)
        if context is None:
            context = context_from_latest_saved_incident(
                env=source,
                incident_root=incident_root,
            )
            if context is not None:
                persist_followup_context(context, root)
    if context is None:
        print("[AuraScan] No retained AuraScan result is available for follow-up.", file=stderr)
        return EXIT_FOLLOWUP_UNAVAILABLE
    if force_interactive is None and not (
        getattr(stdout, "isatty", lambda: False)()
        and getattr(sys.stdin, "isatty", lambda: False)()
    ):
        print("[AuraScan] The follow-up assistant requires an interactive terminal.", file=stderr)
        return EXIT_FOLLOWUP_UNAVAILABLE
    runtime = build_default_runtime(
        context,
        env=source,
        runner=runner,
        which=which,
        urlopen=urlopen,
        context_root=root,
        incident_root=incident_root,
        system_root=system_root,
    )
    result = run_followup_session(
        context,
        runtime=runtime,
        input_func=input_func,
        stdout=stdout,
        stderr=stderr,
        env=source,
        facts_only=bool(args.facts_only),
        urlopen=urlopen,
        context_root=root,
    )
    if result.action_outcome.failed:
        return EXIT_FOLLOWUP_ACTION_FAILED
    if result.provider_failed:
        return EXIT_FOLLOWUP_PROVIDER_ERROR
    return 0


def context_from_saved_incident(
    incident_id: str,
    *,
    env: Optional[Mapping[str, str]] = None,
    incident_root: Optional[Path] = None,
) -> Optional[FollowUpContext]:
    from aurascan.core.incidents import load_incident_report, resolve_incident_config, user_incident_root

    root = incident_root or user_incident_root(env)
    report = load_incident_report(incident_id, root)
    if report is None:
        return None
    config = resolve_incident_config(env)
    privacy_mode = "facts-only" if not config.error and config.ai_evidence == "facts-only" else "redacted"
    return context_from_incident(report, privacy_mode=privacy_mode)


def context_from_latest_saved_incident(
    *,
    env: Optional[Mapping[str, str]] = None,
    incident_root: Optional[Path] = None,
) -> Optional[FollowUpContext]:
    from aurascan.core.incidents import list_incident_reports, user_incident_root

    root = incident_root or user_incident_root(env)
    history = list_incident_reports(root)
    for item in history:
        incident_id = str(item.get("incident_id") or "")
        if not incident_id:
            continue
        context = context_from_saved_incident(
            incident_id,
            env=env,
            incident_root=root,
        )
        if context is not None:
            return context
    return None


def build_default_runtime(
    context: FollowUpContext,
    *,
    env: Optional[Mapping[str, str]] = None,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
    urlopen: Optional[Callable] = None,
    context_root: Optional[Path] = None,
    incident_root: Optional[Path] = None,
    system_root: Optional[Path] = None,
) -> FollowUpRuntime:
    if context.source_type == "incident":
        return build_incident_runtime(
            context,
            env=env,
            runner=runner,
            which=which,
            context_root=context_root,
            incident_root=incident_root,
            system_root=system_root,
        )
    if context.source_type == "config_drift":
        return build_config_drift_runtime(
            context,
            runner=runner,
            context_root=context_root,
        )
    if context.source_type == "upgrade":
        return build_upgrade_runtime(
            context,
            runner=runner,
            which=which,
            urlopen=urlopen,
            context_root=context_root,
        )
    if context.source_type == "maintenance":
        return build_maintenance_runtime(
            context,
            env=env,
            runner=runner,
            which=which,
            context_root=context_root,
            incident_root=incident_root,
            system_root=system_root,
        )
    return with_hardware_health_runtime(
        context,
        FollowUpRuntime(),
        runner=runner,
        which=which,
    )


def build_incident_runtime(
    initial_context: FollowUpContext,
    *,
    env: Optional[Mapping[str, str]],
    runner: Callable,
    which: Callable,
    context_root: Optional[Path],
    incident_root: Optional[Path],
    system_root: Optional[Path],
    report_override=None,
    defer_actions: bool = False,
) -> FollowUpRuntime:
    from aurascan.core.incident_diagnostics import (
        discover_diagnostic_probes,
        execute_diagnostic_probes,
        merge_repair_actions,
    )
    from aurascan.core.incident_repairs import apply_repair_plan, plan_repair_actions
    from aurascan.core.incidents import (
        INCIDENT_REPAIR_ROOT,
        INCIDENT_SYSTEM_ROOT,
        build_incident_report,
        current_user_uid,
        incident_reviewed_state_path,
        load_incident_report,
        mark_pending_markers_seen,
        persist_incident_report,
        resolve_incident_config,
        summarize_post_repair,
        unseen_pending_markers,
        user_incident_root,
    )

    source = dict(os.environ if env is None else env)
    reports = incident_root or user_incident_root(source)
    incident_system_root = system_root or INCIDENT_SYSTEM_ROOT
    repairs = incident_system_root / "repairs"
    state = {"report": report_override}

    def load_report():
        report = state.get("report")
        if report is not None:
            return report
        report = load_incident_report(initial_context.source_id, reports)
        if report is None:
            target = str(initial_context.metadata.get("target_boot") or initial_context.metadata.get("boot_id") or "0")
            report = build_incident_report(target, trigger="followup", runner=runner, which=which)
            report.repair_actions = plan_repair_actions(
                report,
                runner=runner,
                which=which,
                include_package_integrity=True,
            )
            report.diagnostic_probes = discover_diagnostic_probes(report)
            persist_incident_report(report, reports)
        state["report"] = report
        return report

    def probes_callback(
        current: FollowUpContext,
        probe_ids: Sequence[str],
    ) -> Tuple[FollowUpContext, Sequence[FollowUpProbeResult]]:
        report = load_report()
        candidates = discover_diagnostic_probes(report)
        known = {item.probe_id for item in candidates}
        selected = [item for item in probe_ids if item in known][:6]
        results, actions = execute_diagnostic_probes(
            report,
            candidates,
            selected,
            ai_requested_ids=selected,
            runner=runner,
            which=which,
        )
        report.diagnostic_probes = candidates
        existing_results = {item.probe_id: item for item in report.probe_results}
        for item in results:
            existing_results[item.probe_id] = item
        report.probe_results = list(existing_results.values())[:12]
        report.repair_actions = merge_repair_actions(report.repair_actions, actions)
        persist_incident_report(report, reports)
        config = resolve_incident_config(source)
        privacy = "facts-only" if not config.error and config.ai_evidence == "facts-only" else current.privacy_mode
        refreshed = context_from_incident(
            report,
            context_id=current.context_id,
            metadata={
                key: value
                for key, value in current.metadata.items()
                if key not in {"action_probe_map"}
            },
            privacy_mode=privacy,
        )
        state["report"] = report
        return refreshed, [
            FollowUpProbeResult(item.probe_id, item.status, item.summary, list(item.action_ids))
            for item in results
        ]

    def actions_callback(
        current: FollowUpContext,
        action_ids: Sequence[str],
        input_func: Callable[[str], str],
        stdout,
        stderr,
    ) -> FollowUpActionOutcome:
        report = load_report()
        fresh = build_incident_report(
            str(current.metadata.get("target_boot") or report.target_boot or "0"),
            trigger="followup_revalidation",
            runner=runner,
            which=which,
        )
        fresh.repair_actions = plan_repair_actions(
            fresh,
            runner=runner,
            which=which,
            include_package_integrity=True,
        )
        fresh.diagnostic_probes = discover_diagnostic_probes(fresh)
        action_probe_map = current.metadata.get("action_probe_map", {})
        needed_probes = []
        if isinstance(action_probe_map, Mapping):
            for action_id in action_ids:
                raw = action_probe_map.get(action_id, [])
                if isinstance(raw, list):
                    needed_probes.extend(str(item) for item in raw)
        if needed_probes:
            probe_results, probe_actions = execute_diagnostic_probes(
                fresh,
                fresh.diagnostic_probes,
                list(dict.fromkeys(needed_probes))[:12],
                ai_requested_ids=needed_probes,
                runner=runner,
                which=which,
            )
            fresh.probe_results = probe_results
            fresh.repair_actions = merge_repair_actions(fresh.repair_actions, probe_actions)
        by_id = {item.action_id: item for item in fresh.eligible_actions}
        selected = [by_id[item] for item in action_ids if item in by_id]
        if not selected:
            return FollowUpActionOutcome(
                attempted=True,
                source_changed=True,
                message="AuraScan refreshed the incident state; the requested repair is no longer verified or required.",
            )
        _print_action_plan(
            [
                FollowUpAction(
                    item.action_id,
                    item.title,
                    item.summary,
                    item.risk.value,
                    item.eligible and item.verified,
                    item.reversible,
                )
                for item in selected
            ],
            stdout,
        )
        default_yes = bool(
            fresh.collection_status == "complete"
            and not fresh.truncated
            and not any(item.severity.value in {"HIGH", "CRITICAL"} for item in fresh.findings)
            and all(item.risk.value in {"LOW", "MEDIUM"} for item in selected)
            and all(item.reversible for item in selected)
        )
        if not _confirm_action_plan(input_func, default_yes):
            return FollowUpActionOutcome(attempted=True, message="[AuraScan] Follow-up repair was not applied.")
        results, ok = apply_repair_plan(
            selected,
            runner=runner,
            which=which,
            stdout=stdout,
            stderr=stderr,
            repair_root=repairs if system_root is not None else INCIDENT_REPAIR_ROOT,
        )
        fresh.repair_results.extend(results)
        after = build_incident_report(
            fresh.target_boot,
            trigger="post_repair",
            runner=runner,
            which=which,
        )
        fresh.post_repair = summarize_post_repair(fresh, after)
        persist_incident_report(fresh, reports)
        state["report"] = fresh
        acknowledged = 0
        if ok and results and (
            bool(current.metadata.get("resolve_pending"))
            or bool(current.metadata.get("maintenance_source_id"))
        ):
            reviewed_path = incident_reviewed_state_path(source, report_root=reports)
            markers = unseen_pending_markers(
                uid=current_user_uid(),
                marker_root=incident_system_root / "pending",
                seen_path=reviewed_path,
                include_resolved=True,
            )
            boot_id = str(fresh.boot_id or current.metadata.get("boot_id") or "").replace("-", "")
            scan_id = str(current.metadata.get("maintenance_source_id") or "")
            matching = [
                item
                for item in markers
                if (
                    boot_id
                    and str(item.get("boot_id") or "").replace("-", "") == boot_id
                )
                or (
                    scan_id
                    and str(item.get("scan_id") or "") == scan_id
                )
            ]
            mark_pending_markers_seen(matching, seen_path=reviewed_path)
            acknowledged = len(matching)
        return FollowUpActionOutcome(
            attempted=True,
            applied=ok and bool(results),
            failed=not ok,
            source_changed=True,
            message=(
                (
                    f"[AuraScan] Applied and checked {len(results)} follow-up repair(s). "
                    f"Acknowledged {acknowledged} matching tray alert(s)."
                    if acknowledged
                    else f"[AuraScan] Applied and checked {len(results)} follow-up repair(s)."
                )
                if ok
                else "[AuraScan] Follow-up repair stopped after fresh validation or execution failed."
            ),
        )

    return with_hardware_health_runtime(
        initial_context,
        FollowUpRuntime(
            run_probes=probes_callback,
            run_actions=actions_callback,
            defer_actions=defer_actions,
        ),
        runner=runner,
        which=which,
    )


def build_config_drift_runtime(
    initial_context: FollowUpContext,
    *,
    runner: Callable,
    context_root: Optional[Path],
    defer_actions: bool = False,
) -> FollowUpRuntime:
    from aurascan.core.config_drift import (
        build_config_drift_report,
        config_drift_action_id,
        run_config_drift,
    )

    def actions_callback(
        current: FollowUpContext,
        action_ids: Sequence[str],
        input_func: Callable[[str], str],
        stdout,
        stderr,
    ) -> FollowUpActionOutcome:
        root = Path(str(current.metadata.get("root") or "/etc"))
        report = build_config_drift_report(root)
        by_id = {config_drift_action_id(item): item for item in report.apply_actions}
        selected_ids = [item for item in action_ids if item in by_id]
        if not selected_ids:
            refreshed = context_from_config_drift(
                report,
                context_id=current.context_id,
                ai_diffs_allowed=bool(current.metadata.get("ai_diffs_allowed", False)),
            )
            persist_followup_context(refreshed, context_root)
            return FollowUpActionOutcome(
                attempted=True,
                source_changed=True,
                message="AuraScan refreshed the config state; the requested fix is no longer verified or required.",
            )
        selected = [
            FollowUpAction(
                item,
                f"Apply {by_id[item].action} to {by_id[item].drift_file.path}",
                by_id[item].summary,
                "HIGH" if by_id[item].drift_file.sensitive else "MEDIUM",
                True,
                by_id[item].backup_required,
            )
            for item in selected_ids
        ]
        _print_action_plan(selected, stdout)
        safe_default = bool(
            not report.errors
            and not report.scan_truncated
            and all(by_id[item].applies for item in selected_ids)
            and not any(by_id[item].drift_file.sensitive for item in selected_ids)
            and all(by_id[item].backup_required for item in selected_ids)
        )
        if not _confirm_action_plan(input_func, safe_default):
            return FollowUpActionOutcome(attempted=True, message="[AuraScan] Follow-up config fix was not applied.")
        args = ["--root", str(root), "--no-ai", "--yes"]
        for action_id in selected_ids:
            args.extend(["--action-id", action_id])
        status = run_config_drift(
            args,
            input_func=input_func,
            stdout=stdout,
            stderr=stderr,
            runner=runner,
        )
        return FollowUpActionOutcome(
            attempted=True,
            applied=status == 0,
            failed=status != 0,
            source_changed=True,
            message=(
                "[AuraScan] The selected config drift fix completed with backups."
                if status == 0
                else "[AuraScan] The selected config drift fix failed or was refused after fresh validation."
            ),
        )

    return with_hardware_health_runtime(
        initial_context,
        FollowUpRuntime(run_actions=actions_callback, defer_actions=defer_actions),
        runner=runner,
    )


def build_upgrade_runtime(
    initial_context: FollowUpContext,
    *,
    runner: Callable,
    which: Callable,
    urlopen: Optional[Callable],
    context_root: Optional[Path],
    defer_actions: bool = False,
) -> FollowUpRuntime:
    from aurascan.core.config_drift import (
        build_config_drift_report,
        config_drift_action_id,
        run_config_drift,
    )
    from aurascan.core.kernel_module_autopilot import kernel_module_fix_command
    from aurascan.core.upgrade_preflight import (
        SystemSnapshot,
        apply_repository_health_repairs,
        build_upgrade_parser,
        options_from_args,
        run_upgrade_preflight,
    )

    def refreshed_report():
        helper = str(initial_context.metadata.get("selected_helper") or "auto")
        args = build_upgrade_parser().parse_args(["--dry-run", "--no-ai", "--aur-helper", helper])
        options = options_from_args(args)
        return run_upgrade_preflight(
            options,
            runner=runner,
            which=which,
            snapshot=SystemSnapshot.collect(runner=runner),
            urlopen=urlopen,
            progress=lambda _message: None,
        ), options

    def probes_callback(
        current: FollowUpContext,
        probe_ids: Sequence[str],
    ) -> Tuple[FollowUpContext, Sequence[FollowUpProbeResult]]:
        if FOLLOWUP_PROBE_UPGRADE_REFRESH not in probe_ids:
            return current, []
        report, _options = refreshed_report()
        refreshed = context_from_upgrade(
            report,
            phase="refreshed_preflight",
            context_id=current.context_id,
            metadata=current.metadata,
        )
        return refreshed, [
            FollowUpProbeResult(
                FOLLOWUP_PROBE_UPGRADE_REFRESH,
                "ok" if report.plan.available else "failed",
                (
                    "The deterministic upgrade preflight was refreshed successfully."
                    if report.plan.available
                    else f"The refreshed preflight remains unavailable: {report.plan.preview_error}"
                ),
                [item.action_id for item in refreshed.actions],
            )
        ]

    def actions_callback(
        current: FollowUpContext,
        action_ids: Sequence[str],
        input_func: Callable[[str], str],
        stdout,
        stderr,
    ) -> FollowUpActionOutcome:
        report, options = refreshed_report()
        refreshed = context_from_upgrade(
            report,
            phase="action_revalidation",
            context_id=current.context_id,
            metadata=current.metadata,
        )
        available = {item.action_id: item for item in refreshed.actions}
        selected_ids = [item for item in action_ids if item in available]
        persist_followup_context(refreshed, context_root)
        if not selected_ids:
            return FollowUpActionOutcome(
                attempted=True,
                source_changed=True,
                message="AuraScan refreshed the preflight; the requested operation is no longer verified or required.",
            )
        selected = [available[item] for item in selected_ids]
        config_report = None
        config_action_ids: List[str] = []
        if FOLLOWUP_ACTION_CONFIG_DRIFT in selected_ids:
            config_report = build_config_drift_report(Path("/etc"))
            config_action_ids = [
                config_drift_action_id(item)
                for item in config_report.apply_actions
            ]
            if not config_action_ids:
                selected_ids = [
                    item for item in selected_ids
                    if item != FOLLOWUP_ACTION_CONFIG_DRIFT
                ]
                selected = [
                    item for item in selected
                    if item.action_id != FOLLOWUP_ACTION_CONFIG_DRIFT
                ]
            else:
                print(config_report.render_terminal(), file=stdout)
        if not selected:
            return FollowUpActionOutcome(
                attempted=True,
                source_changed=True,
                message="AuraScan refreshed the state; none of the requested support actions remain necessary.",
            )
        _print_action_plan(selected, stdout)
        config_safe = bool(
            config_report is None
            or (
                not config_report.errors
                and not config_report.scan_truncated
                and not config_report.manual_actions
                and not any(item.drift_file.sensitive for item in config_report.apply_actions)
            )
        )
        default_yes = (
            config_safe
            and report.highest_severity.value not in {"HIGH", "CRITICAL"}
            and all(item.verified and item.risk in {"LOW", "MEDIUM"} for item in selected)
            and all(item.reversible for item in selected)
        )
        if not _confirm_action_plan(input_func, default_yes):
            return FollowUpActionOutcome(attempted=True, message="[AuraScan] Follow-up upgrade support action was not applied.")
        for action_id in (
            FOLLOWUP_ACTION_REPOSITORY,
            FOLLOWUP_ACTION_KERNEL,
            FOLLOWUP_ACTION_CONFIG_DRIFT,
        ):
            if action_id not in selected_ids:
                continue
            if action_id == FOLLOWUP_ACTION_REPOSITORY:
                check = report.repository_health
                if check is None or not check.fixable_issues:
                    return FollowUpActionOutcome(attempted=True, failed=True, source_changed=True, message="[AuraScan] Repository repair no longer passes validation.")
                repair = apply_repository_health_repairs(check, runner=runner)
                if not repair.success:
                    return FollowUpActionOutcome(attempted=True, failed=True, source_changed=True, message="[AuraScan] Repository repair failed and retained its backup manifest.")
            elif action_id == FOLLOWUP_ACTION_KERNEL:
                check = report.kernel_module_check
                command = kernel_module_fix_command(check) if check is not None else []
                if not command:
                    return FollowUpActionOutcome(attempted=True, failed=True, source_changed=True, message="[AuraScan] Kernel support fix no longer passes validation.")
                try:
                    result = runner(command, check=False)
                except OSError as exc:
                    return FollowUpActionOutcome(attempted=True, failed=True, source_changed=True, message=f"[AuraScan] Kernel support fix could not start: {redact_followup_text(str(exc))}.")
                if int(getattr(result, "returncode", 0)) != 0:
                    return FollowUpActionOutcome(attempted=True, failed=True, source_changed=True, message="[AuraScan] Kernel support package command failed.")
            elif action_id == FOLLOWUP_ACTION_CONFIG_DRIFT:
                args = ["--no-ai", "--yes"]
                for config_action_id_value in config_action_ids:
                    args.extend(["--action-id", config_action_id_value])
                status = run_config_drift(
                    args,
                    input_func=input_func,
                    stdout=stdout,
                    stderr=stderr,
                    runner=runner,
                )
                if status != 0:
                    return FollowUpActionOutcome(attempted=True, failed=True, source_changed=True, message="[AuraScan] Config Drift Assistant failed or refused the refreshed plan.")
        return FollowUpActionOutcome(
            attempted=True,
            applied=True,
            source_changed=True,
            message="[AuraScan] The selected upgrade support action completed. Run a fresh preflight before upgrading.",
        )

    return with_hardware_health_runtime(
        initial_context,
        FollowUpRuntime(
            run_probes=probes_callback,
            run_actions=actions_callback,
            defer_actions=defer_actions,
        ),
        runner=runner,
        which=which,
    )


def build_maintenance_runtime(
    initial_context: FollowUpContext,
    *,
    env: Optional[Mapping[str, str]],
    runner: Callable,
    which: Callable,
    context_root: Optional[Path],
    incident_root: Optional[Path],
    system_root: Optional[Path],
) -> FollowUpRuntime:
    state: Dict[str, object] = {"incident_runtime": None, "incident_context": None}

    def probes_callback(
        current: FollowUpContext,
        probe_ids: Sequence[str],
    ) -> Tuple[FollowUpContext, Sequence[FollowUpProbeResult]]:
        if FOLLOWUP_PROBE_MAINTENANCE_INCIDENT not in probe_ids:
            runtime = state.get("incident_runtime")
            incident_context = state.get("incident_context")
            if (
                isinstance(runtime, FollowUpRuntime)
                and isinstance(incident_context, FollowUpContext)
                and runtime.run_probes is not None
            ):
                refreshed, results = runtime.run_probes(incident_context, probe_ids)
                state["incident_context"] = refreshed
                return refreshed, results
            return current, []
        from aurascan.core.incident_diagnostics import discover_diagnostic_probes
        from aurascan.core.incident_repairs import plan_repair_actions
        from aurascan.core.incidents import build_incident_report, persist_incident_report, resolve_incident_config, user_incident_root

        target = str(current.metadata.get("boot_id") or "0")
        report = build_incident_report(target, trigger="maintenance_followup", runner=runner, which=which)
        report.repair_actions = plan_repair_actions(
            report,
            runner=runner,
            which=which,
            include_package_integrity=True,
        )
        report.diagnostic_probes = discover_diagnostic_probes(report)
        reports = incident_root or user_incident_root(env)
        marker = current.metadata.get("marker")
        if isinstance(marker, Mapping):
            from aurascan.core.incident_automation import load_reusable_background_plan
            from aurascan.core.incident_diagnostics import merge_repair_actions

            cached = load_reusable_background_plan(report, marker, reports)
            if cached is not None:
                report.ai_review = dict(cached.ai_review)
                report.probe_results = list(cached.probe_results)[:12]
                report.repair_actions = merge_repair_actions(
                    report.repair_actions,
                    cached.repair_actions,
                )
                report.automation["followup_background_plan"] = {
                    "status": "reused",
                    "source_report_id": cached.incident_id,
                }
        persist_incident_report(report, reports)
        config = resolve_incident_config(env)
        privacy = "facts-only" if not config.error and config.ai_evidence == "facts-only" else "redacted"
        refreshed = context_from_incident(
            report,
            context_id=current.context_id,
            metadata={
                "maintenance_source_id": current.source_id,
                "resolve_pending": True,
            },
            privacy_mode=privacy,
        )
        runtime = build_incident_runtime(
            refreshed,
            env=env,
            runner=runner,
            which=which,
            context_root=context_root,
            incident_root=reports,
            system_root=system_root,
            report_override=report,
        )
        state["incident_runtime"] = runtime
        state["incident_context"] = refreshed
        return refreshed, [
            FollowUpProbeResult(
                FOLLOWUP_PROBE_MAINTENANCE_INCIDENT,
                "ok" if report.collection_status != "unavailable" else "failed",
                f"User-scoped incident analysis completed with {len(report.findings)} finding(s) and {sum(item.count for item in report.coredumps)} crash record(s).",
                [item.action_id for item in refreshed.actions],
            )
        ]

    def actions_callback(
        current: FollowUpContext,
        action_ids: Sequence[str],
        input_func: Callable[[str], str],
        stdout,
        stderr,
    ) -> FollowUpActionOutcome:
        runtime = state.get("incident_runtime")
        incident_context = state.get("incident_context")
        if not isinstance(runtime, FollowUpRuntime) or not isinstance(incident_context, FollowUpContext):
            return FollowUpActionOutcome(
                attempted=True,
                message="AuraScan needs the detailed incident probe before it can prepare a repair. No command was run.",
            )
        if runtime.run_actions is None:
            return FollowUpActionOutcome(attempted=True, message="No verified incident action is available.")
        return runtime.run_actions(incident_context, action_ids, input_func, stdout, stderr)

    return with_hardware_health_runtime(
        initial_context,
        FollowUpRuntime(run_probes=probes_callback, run_actions=actions_callback),
        runner=runner,
        which=which,
    )


def _known_unique_ids(raw: object, known: set, limit: int) -> List[str]:
    values: List[str] = []
    if not isinstance(raw, list):
        return values
    for item in raw:
        value = str(item)
        if value in known and value not in values:
            values.append(value)
        if len(values) >= limit:
            break
    return values


def _print_deferred_actions(context: FollowUpContext, action_ids: Sequence[str], stdout) -> None:
    by_id = {item.action_id: item for item in context.actions}
    selected = [by_id[item] for item in action_ids if item in by_id]
    if not selected:
        return
    print("\n[AuraScan] Locally verified action available", file=stdout)
    for item in selected:
        print(f"- {item.title}: {item.summary}", file=stdout)
    print("AuraScan will include this in the workflow confirmation that follows. No command ran from AI text.", file=stdout)


def _print_action_plan(actions: Sequence[FollowUpAction], stdout) -> None:
    print("\n[AuraScan] Verified follow-up action plan", file=stdout)
    for item in actions:
        reversible = "reversible" if item.reversible else "not automatically reversible"
        print(f"- {item.title} [{item.risk}; {reversible}]", file=stdout)
        print(f"  {item.summary}", file=stdout)


def _confirm_action_plan(input_func: Callable[[str], str], default_yes: bool) -> bool:
    suffix = "[Y/n]" if default_yes else "[y/N]"
    try:
        answer = input_func(f"Apply this locally verified AuraScan plan? {suffix} ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer not in {"n", "no"} if default_yes else answer in {"y", "yes"}


def classify_followup_failure(exc: Exception) -> str:
    text = str(exc).lower()
    if isinstance(exc, TimeoutError) or "timed out" in text or "timeout" in text:
        return "timeout"
    if isinstance(exc, (json.JSONDecodeError, ValueError, TypeError, KeyError)):
        return "invalid_response"
    return "provider_error"


def redact_followup_text(text: object) -> str:
    value = str(text or "")
    value = TERMINAL_CONTROL_RE.sub("", value)
    value = PRIVATE_KEY_RE.sub("<redacted-private-key>", value)
    value = URL_USERINFO_RE.sub(r"\1<redacted-user>:<redacted-password>@", value)
    value = SECRET_ASSIGNMENT_RE.sub(r"\1\2<redacted>", value)
    value = HOME_PATH_RE.sub(lambda match: "/home/" + correlation_token("user", match.group(1)), value)
    value = MAC_RE.sub(lambda match: correlation_token("mac", match.group(0).lower()), value)
    value = IPV4_RE.sub(lambda match: correlation_token("ip", match.group(0)), value)
    usernames = {os.environ.get("USER", "").strip(), os.environ.get("SUDO_USER", "").strip()}
    for username in sorted((item for item in usernames if len(item) >= 2), key=len, reverse=True):
        value = re.sub(
            rf"(?<![\w.-]){re.escape(username)}(?![\w.-])",
            correlation_token("user", username),
            value,
        )
    return value


def redact_followup_structure(value: object) -> object:
    if isinstance(value, Mapping):
        result = {}
        for key, item in list(value.items())[:100]:
            name = str(key)
            if any(token in name.lower() for token in ("password", "secret", "token", "api_key", "private_key")):
                result[name] = "<redacted>"
            else:
                result[name] = redact_followup_structure(item)
        return result
    if isinstance(value, (list, tuple)):
        return [redact_followup_structure(item) for item in list(value)[:200]]
    if isinstance(value, str):
        return redact_followup_text(value)[:4000]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return redact_followup_text(str(value))[:1000]


def correlation_token(kind: str, value: str) -> str:
    digest = hashlib.sha256(str(value).encode("utf-8", "replace")).hexdigest()[:8]
    return f"<{kind}:{digest}>"


def current_user_uid() -> int:
    try:
        return int(os.getuid())
    except (AttributeError, OSError):
        return -1


def private_user_file(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return bool(
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == current_user_uid()
        and metadata.st_mode & 0o077 == 0
    )


def private_user_directory(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return bool(
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == current_user_uid()
        and metadata.st_mode & 0o077 == 0
    )


def ensure_private_directory(path: Path) -> None:
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise PermissionError(f"cannot inspect follow-up context directory: {path}") from exc
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != current_user_uid():
        raise PermissionError(
            f"follow-up context directory must be a user-owned directory: {path}"
        )
    os.chmod(path, 0o700)


def atomic_write_private_json(path: Path, data: object) -> None:
    ensure_private_directory(path.parent)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent), text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, path)
        os.chmod(path, 0o600)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
