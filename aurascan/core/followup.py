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
from aurascan.core.text_safety import (
    load_strict_json_object,
    validate_model_advisory_text,
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
FOLLOWUP_MAX_AI_RESPONSE_CHARS = 12000
FOLLOWUP_MAX_CONTEXT_BYTES = 2 * 1024 * 1024
FOLLOWUP_AI_TIMEOUT_SECONDS = 60
FOLLOWUP_PROBE_MAINTENANCE_INCIDENT = "fup-maintenance-incident"
FOLLOWUP_RECOVERY_RUNTIME_MARKER = Path("/run/aurascan-recovery/environment")
EXIT_FOLLOWUP_UNAVAILABLE = 70
EXIT_FOLLOWUP_PROVIDER_ERROR = 71
EXIT_FOLLOWUP_ACTION_FAILED = 72
FOLLOWUP_AI_REJECTION_DETAIL = "AI response rejected by guarded follow-up contract"
FOLLOWUP_AI_PROVIDER_FAILURE_DETAIL = "AI provider request failed"
FOLLOWUP_AI_TIMEOUT_DETAIL = "AI provider request timed out"

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
        "provider_ready": config.ready,
        "root": str(context_root),
        "storage_exists": exists,
        "storage_safe": safe if exists else True,
        "latest_context_id": latest.context_id if latest else "",
        "latest_context_age_seconds": max(0, int(time.time()) - latest.updated_at) if latest else None,
        "error": error,
    }


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
    if not config.ready:
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
    allow_probe_requests: bool = True,
) -> str:
    instructions = (
        "You are AuraScan's contextual assistant for Arch-family Linux systems.\n"
        "Answer only from the supplied bounded redacted facts and conversation.\n"
        "Be calm, direct, and honest about uncertainty. Never claim that a system, package, or repair is guaranteed safe.\n"
        "Never create or suggest shell commands, scripts, package targets, file paths, file edits, service names, bootloader changes, reboots, or arbitrary repairs.\n"
        "Do not claim an action ran or succeeded. AuraScan's deterministic code owns all validation, confirmation, and execution.\n"
        + (
            "You may request only known opaque probe IDs and known verified action IDs supplied below.\n"
            if allow_probe_requests
            else (
                "This is the final review after the local probe_results below already ran. "
                "Explain those completed results now, use requested_probe_ids=[], and never say that you will request or run another probe.\n"
                "You may recommend only known verified action IDs supplied below.\n"
            )
        )
        +
        "The answer must be bounded, single-line, non-executable prose: no URLs, commands, credentials, terminal controls, product impersonation, or unsupported safe/compromised claims.\n"
        "Return strict JSON only with exactly this shape and no additional keys:\n"
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
        "available_probes": (
            [item.to_dict() for item in context.probes]
            if allow_probe_requests
            else []
        ),
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
    *,
    allow_probe_requests: bool = True,
) -> FollowUpResponse:
    expected_keys = {
        "answer",
        "referenced_fact_ids",
        "requested_probe_ids",
        "requested_action_ids",
    }
    if set(data.keys()) != expected_keys:
        raise ValueError("follow-up response did not match the exact schema")
    known_facts = {item.fact_id for item in context.facts}
    known_probes = {item.probe_id for item in context.probes}
    known_actions = {item.action_id for item in context.actions if item.verified}
    answer = validate_model_advisory_text(
        data["answer"],
        max_chars=FOLLOWUP_MAX_ANSWER_CHARS,
        allow_empty=False,
    )
    fact_ids = _validate_known_id_list(
        data["referenced_fact_ids"],
        known_facts,
        field_name="referenced_fact_ids",
        limit=20,
    )
    probe_ids = _validate_known_id_list(
        data["requested_probe_ids"],
        known_probes,
        field_name="requested_probe_ids",
        limit=6,
    )
    action_ids = _validate_known_id_list(
        data["requested_action_ids"],
        known_actions,
        field_name="requested_action_ids",
        limit=20,
    )
    if not allow_probe_requests and probe_ids:
        raise ValueError("final follow-up review cannot request additional probes")
    return FollowUpResponse(
        answer=answer,
        referenced_fact_ids=fact_ids,
        requested_probe_ids=probe_ids if allow_probe_requests else [],
        requested_action_ids=action_ids,
    )


def ask_followup_ai(
    context: FollowUpContext,
    question: str,
    turns: Sequence[FollowUpTurn],
    *,
    facts_only: bool = False,
    probe_results: Sequence[FollowUpProbeResult] = (),
    allow_probe_requests: bool = True,
    env: Optional[Mapping[str, str]] = None,
    urlopen: Optional[Callable] = None,
) -> FollowUpResponse:
    source = dict(os.environ if env is None else env)
    config = resolve_ai_config(source)
    if config.error:
        return FollowUpResponse("", status="config_error", error=config.error)
    if not config.ready:
        return FollowUpResponse("", status="not_configured", error="AI provider is disabled or not configured")
    prompt = build_followup_ai_prompt(
        context,
        question,
        turns,
        facts_only=facts_only,
        probe_results=probe_results,
        allow_probe_requests=allow_probe_requests,
    )
    try:
        text = call_ai_provider(
            config,
            prompt,
            timeout=FOLLOWUP_AI_TIMEOUT_SECONDS,
            urlopen=urlopen,
        )
        data = load_strict_json_object(
            text,
            max_chars=FOLLOWUP_MAX_AI_RESPONSE_CHARS,
        )
        return validate_followup_ai_response(
            context,
            data,
            allow_probe_requests=allow_probe_requests,
        )
    except Exception as exc:
        status = classify_followup_failure(exc)
        return FollowUpResponse(
            "",
            status=status,
            error=_fixed_followup_failure_detail(status),
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
    agent_escalation_provider: Optional[Callable] = None,
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

    def print_probe_results(probe_results: Sequence[FollowUpProbeResult]) -> None:
        if not probe_results:
            return
        labels = {item.probe_id: item.title for item in current.probes}
        print("[AuraScan] Local verification result", file=stdout)
        for item in probe_results:
            status = {
                "ok": "OK",
                "no_action": "OK",
                "action_ready": "READY",
                "partial": "PARTIAL",
                "timeout": "TIMEOUT",
                "failed": "FAILED",
            }.get(item.status, item.status.upper() or "UNKNOWN")
            label = labels.get(item.probe_id, "Bounded local check")
            summary = redact_followup_text(item.summary)[:1000]
            print(f"- [{status}] {label}: {summary}", file=stdout)

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
            # The agent lifecycle supplies this escalation. Without a provider the
            # session refuses the command instead of starting an agent session
            # through any other route.
            if agent_escalation_provider is None:
                print(
                    "[AuraScan] Repair Agent escalation is unavailable in this follow-up session.",
                    file=stderr,
                )
                continue
            escalation = agent_escalation_provider(
                current,
                question.partition(" ")[2].strip(),
                runtime=runtime,
                input_func=input_func,
                stdout=stdout,
                stderr=stderr,
                env=env,
                facts_only=facts_only,
                urlopen=urlopen,
                context_root=context_root,
            )
            # A provider that ran no session only reported why it refused.
            agent_result = getattr(escalation, "result", None)
            if not getattr(escalation, "session_ran", False) or agent_result is None:
                continue
            outcome = getattr(agent_result, "action_outcome", FollowUpActionOutcome())
            result.provider_requests += int(getattr(agent_result, "provider_requests", 0))
            result.action_outcome = outcome
            result.provider_failed = result.provider_failed or bool(
                getattr(agent_result, "provider_failed", False)
            )
            if outcome.applied or outcome.source_changed:
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
        print_probe_results(initial_probe_results)
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
            print_probe_results(probe_results)
            if result.provider_requests < FOLLOWUP_MAX_PROVIDER_REQUESTS:
                print("[AuraScan] Asking AI to review the locally verified results...", file=stdout, flush=True)
                response = ask_followup_ai(
                    current,
                    question,
                    turns,
                    facts_only=facts_only or current.privacy_mode == "facts-only",
                    probe_results=probe_results,
                    allow_probe_requests=False,
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
    agent_escalation_provider: Optional[Callable] = None,
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
            agent_escalation_provider=agent_escalation_provider,
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
    agent_escalation_provider: Optional[Callable] = None,
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
        agent_escalation_provider=agent_escalation_provider,
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
    refresh_upgrade_report: Optional[Callable] = None,
    incident_context_provider: Optional[Callable] = None,
    incident_runtime_provider: Optional[Callable] = None,
    config_drift_runtime_provider: Optional[Callable] = None,
    config_drift_remediation_provider: Optional[Callable] = None,
    agent_escalation_provider: Optional[Callable] = None,
    upgrade_runtime_provider: Optional[Callable] = None,
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
    if not config.ready:
        detail = config.error or "AI provider is disabled or not configured"
        print(f"[AuraScan] Follow-up assistant unavailable: {detail}.", file=stderr)
        return EXIT_FOLLOWUP_UNAVAILABLE
    root = context_root or user_followup_root(source)
    context: Optional[FollowUpContext]
    if args.context_id and not args.latest:
        context = load_followup_context(args.context_id, root)
        if context is None and incident_context_provider is not None:
            context = incident_context_provider(
                args.context_id,
                env=source,
                incident_root=incident_root,
            )
            if context is not None:
                persist_followup_context(context, root)
    else:
        context = latest_followup_context(root)
        if context is None and incident_context_provider is not None:
            context = incident_context_provider(
                env=source,
                incident_root=incident_root,
                latest=True,
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
        refresh_upgrade_report=refresh_upgrade_report,
        incident_runtime_provider=incident_runtime_provider,
        config_drift_runtime_provider=config_drift_runtime_provider,
        config_drift_remediation_provider=config_drift_remediation_provider,
        upgrade_runtime_provider=upgrade_runtime_provider,
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
        agent_escalation_provider=agent_escalation_provider,
    )
    if result.action_outcome.failed:
        return EXIT_FOLLOWUP_ACTION_FAILED
    if result.provider_failed:
        return EXIT_FOLLOWUP_PROVIDER_ERROR
    return 0


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
    refresh_upgrade_report: Optional[Callable] = None,
    incident_runtime_provider: Optional[Callable] = None,
    config_drift_runtime_provider: Optional[Callable] = None,
    config_drift_remediation_provider: Optional[Callable] = None,
    upgrade_runtime_provider: Optional[Callable] = None,
) -> FollowUpRuntime:
    if context.source_type in {"incident", "maintenance"}:
        # The incident lifecycle supplies its own runtime builder. Without a
        # provider there is no incident authority to act with, so the session
        # degrades to facts only instead of running stale probes or repairs.
        if incident_runtime_provider is None:
            return with_hardware_health_runtime(
                context,
                FollowUpRuntime(),
                runner=runner,
                which=which,
            )
        return incident_runtime_provider(
            context,
            env=env,
            runner=runner,
            which=which,
            context_root=context_root,
            incident_root=incident_root,
            system_root=system_root,
        )
    if context.source_type == "config_drift":
        # The config-drift lifecycle supplies its own runtime builder. Without a
        # provider the session degrades to facts only instead of applying stale
        # configuration fixes.
        if config_drift_runtime_provider is None:
            return with_hardware_health_runtime(
                context,
                FollowUpRuntime(),
                runner=runner,
                which=which,
            )
        return config_drift_runtime_provider(
            context,
            runner=runner,
            context_root=context_root,
        )
    if context.source_type == "upgrade":
        # The upgrade lifecycle supplies its own runtime builder. Without a
        # provider the session degrades to facts only instead of running the
        # repository, kernel-module or config-drift fixes an upgrade session may
        # offer.
        if upgrade_runtime_provider is None:
            return with_hardware_health_runtime(
                context,
                FollowUpRuntime(),
                runner=runner,
                which=which,
            )
        return upgrade_runtime_provider(
            context,
            runner=runner,
            which=which,
            urlopen=urlopen,
            context_root=context_root,
            refresh_report=refresh_upgrade_report,
            config_drift_remediation_provider=config_drift_remediation_provider,
        )
    return with_hardware_health_runtime(
        context,
        FollowUpRuntime(),
        runner=runner,
        which=which,
    )


def _validate_known_id_list(
    raw: object,
    known: set,
    *,
    field_name: str,
    limit: int,
) -> List[str]:
    if not isinstance(raw, list):
        raise ValueError(f"follow-up response {field_name} must be a list")
    if len(raw) > limit:
        raise ValueError(f"follow-up response {field_name} exceeded its item limit")
    values: List[str] = []
    for item in raw:
        if not isinstance(item, str) or item not in known:
            raise ValueError(f"follow-up response {field_name} contained an unknown ID")
        if item in values:
            raise ValueError(f"follow-up response {field_name} contained a duplicate ID")
        values.append(item)
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


def _fixed_followup_failure_detail(status: str) -> str:
    if status == "timeout":
        return FOLLOWUP_AI_TIMEOUT_DETAIL
    if status == "invalid_response":
        return FOLLOWUP_AI_REJECTION_DETAIL
    return FOLLOWUP_AI_PROVIDER_FAILURE_DETAIL


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
