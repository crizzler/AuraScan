import argparse
from datetime import datetime
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from aurascan.core.ai_provider import call_ai_provider, parse_bool as parse_config_bool, resolve_ai_config
from aurascan.core.compatibility import detect_distro
from aurascan.core.config import read_env_file, user_env_path, write_user_env
from aurascan.core.models import Confidence, SCANNER_VERSION, Severity


INCIDENT_SCHEMA_VERSION = "1.3"
INCIDENT_REPORT_TYPE = "incident_report"
INCIDENT_MONITOR_ENABLED_ENV = "AURASCAN_INCIDENT_MONITOR_ENABLED"
INCIDENT_AI_ENABLED_ENV = "AURASCAN_INCIDENT_AI_ENABLED"
INCIDENT_AI_EVIDENCE_ENV = "AURASCAN_INCIDENT_AI_EVIDENCE"
INCIDENT_BACKGROUND_AI_ENV = "AURASCAN_INCIDENT_BACKGROUND_AI"
INCIDENT_AI_EVIDENCE_VALUES = {"redacted", "facts-only"}
INCIDENT_MONITOR_SERVICE = "aurascan-incident-monitor.service"
INCIDENT_MAINTENANCE_SERVICE = "aurascan-incident-maintenance.service"
INCIDENT_MAINTENANCE_TIMER = "aurascan-incident-maintenance.timer"
INCIDENT_SYSTEM_ROOT = Path("/var/lib/aurascan/incidents")
INCIDENT_MONITOR_MARKER_ROOT = INCIDENT_SYSTEM_ROOT / "pending"
INCIDENT_SYSTEM_REPORT_ROOT = INCIDENT_SYSTEM_ROOT / "reports"
INCIDENT_REPAIR_ROOT = INCIDENT_SYSTEM_ROOT / "repairs"
INCIDENT_MAINTENANCE_ROOT = INCIDENT_SYSTEM_ROOT / "maintenance"
INCIDENT_MAINTENANCE_STATE = INCIDENT_MAINTENANCE_ROOT / "state.json"
INCIDENT_MAINTENANCE_STATUS = INCIDENT_MAINTENANCE_ROOT / "status.json"
INCIDENT_MAX_JOURNAL_RECORDS = 2000
INCIDENT_MAX_JOURNAL_RAW_CHARS = 2 * 1024 * 1024
INCIDENT_MAX_LOCAL_EVIDENCE_CHARS = 256 * 1024
INCIDENT_MAX_COREDUMPS = 200
INCIDENT_MAX_AI_EVIDENCE = 80
INCIDENT_MAX_AI_CHARS = 12000
INCIDENT_COLLECTION_PROGRESS_STEPS = 7
INCIDENT_ANALYSIS_PROGRESS_STEPS = 12
INCIDENT_RETENTION_DAYS = 30
INCIDENT_MAX_REPORTS = 50
INCIDENT_MAINTENANCE_DUE_SECONDS = 8 * 24 * 60 * 60

EXIT_INCIDENT_UNAVAILABLE = 40
EXIT_INCIDENT_USER_DECLINED = 41
EXIT_INCIDENT_REPAIR_FAILED = 42
EXIT_INCIDENT_CONFIG_ERROR = 43

SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
CONFIDENCE_ORDER = [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH, Confidence.CONFIRMED]
SAFE_INCIDENT_ID_RE = re.compile(r"^[a-zA-Z0-9_.-]{1,120}$")
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)",
    re.DOTALL,
)
URL_USERINFO_RE = re.compile(r"([a-z][a-z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@", re.IGNORECASE)
SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)(\b(?:password|passwd|passphrase|secret|token|api[_-]?key|apikey|private[_-]?key|credential|authorization)\b\s*[:=]\s*)(\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;]+)"
)
AUTHORIZATION_TOKEN_RE = re.compile(r"(?i)(\bauthorization\b\s*[:=]?\s*(?:bearer|basic)\s+)[^\s,;]+")
COMMAND_FIELD_RE = re.compile(r"(?i)(\b(?:COMMAND|CMDLINE|PROCTITLE)\s*=\s*).*$")
HOME_PATH_RE = re.compile(r"/home/([^/\s]+)")
IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])")
MAC_RE = re.compile(r"(?i)(?<![0-9a-f])(?:[0-9a-f]{2}:){5}[0-9a-f]{2}(?![0-9a-f])")

CLEAN_SHUTDOWN_MARKERS = (
    "reached target system power off",
    "reached target system reboot",
    "systemd-shutdown",
    "powering off.",
    "rebooting.",
    "shutting down.",
)

DESKTOP_COMPONENTS = {
    "kwin_wayland",
    "kwin_x11",
    "plasmashell",
    "gnome-shell",
    "mutter",
    "xfwm4",
    "cinnamon",
    "mate-panel",
    "sddm",
    "gdm",
    "lightdm",
    "Xorg",
    "Xwayland",
}


@dataclass
class IncidentConfig:
    monitor_enabled: bool = False
    ai_enabled: bool = True
    ai_evidence: str = "redacted"
    background_ai_enabled: bool = False
    error: str = ""


@dataclass
class IncidentOptions:
    target: str = "auto"
    dry_run: bool = False
    json_output: bool = False
    verbose: bool = False
    yes: bool = False
    no_ai: bool = False
    facts_only: bool = False
    history: bool = False
    show_id: str = ""
    resolve_pending: bool = False
    capture_monitor: bool = False
    capture_maintenance: bool = False
    run_maintenance: bool = False
    maintenance_status: bool = False
    apply_request: str = ""
    config: IncidentConfig = field(default_factory=IncidentConfig)


@dataclass
class MaintenanceCheckpoint:
    boot_id: str = ""
    journal_cursor: str = ""
    journal_since_usec: int = 0
    coredump_since_usec: int = 0
    coredump_seen_ids: List[str] = field(default_factory=list)
    last_window_end_usec: int = 0
    last_success_usec: int = 0

    def to_dict(self) -> Dict[str, object]:
        return {
            "schema": "incident_maintenance_state/1.0",
            "boot_id": self.boot_id,
            "journal_cursor": self.journal_cursor,
            "journal_since_usec": self.journal_since_usec,
            "coredump_since_usec": self.coredump_since_usec,
            "coredump_seen_ids": list(self.coredump_seen_ids[-200:]),
            "last_window_end_usec": self.last_window_end_usec,
            "last_success_usec": self.last_success_usec,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "MaintenanceCheckpoint":
        seen = data.get("coredump_seen_ids", [])
        return cls(
            boot_id=str(data.get("boot_id") or ""),
            journal_cursor=str(data.get("journal_cursor") or ""),
            journal_since_usec=safe_int(data.get("journal_since_usec")),
            coredump_since_usec=safe_int(data.get("coredump_since_usec")),
            coredump_seen_ids=[str(item) for item in seen[-200:]] if isinstance(seen, list) else [],
            last_window_end_usec=safe_int(data.get("last_window_end_usec")),
            last_success_usec=safe_int(data.get("last_success_usec")),
        )


@dataclass
class IncidentEvidence:
    evidence_id: str
    source: str
    message: str
    timestamp: str = ""
    boot_id: str = ""
    unit: str = ""
    executable: str = ""
    package: str = ""
    uid: Optional[int] = None
    severity: Severity = Severity.LOW

    def __post_init__(self) -> None:
        self.severity = _severity(self.severity)

    def to_dict(self) -> Dict[str, object]:
        return {
            "evidence_id": self.evidence_id,
            "source": self.source,
            "timestamp": self.timestamp,
            "boot_id": self.boot_id,
            "unit": self.unit,
            "executable": self.executable,
            "package": self.package,
            "uid": self.uid,
            "severity": self.severity.value,
            "message": self.message,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "IncidentEvidence":
        uid_value = data.get("uid")
        try:
            uid = int(uid_value) if uid_value is not None else None
        except (TypeError, ValueError):
            uid = None
        return cls(
            evidence_id=str(data.get("evidence_id") or ""),
            source=str(data.get("source") or ""),
            message=str(data.get("message") or ""),
            timestamp=str(data.get("timestamp") or ""),
            boot_id=str(data.get("boot_id") or ""),
            unit=str(data.get("unit") or ""),
            executable=str(data.get("executable") or ""),
            package=str(data.get("package") or ""),
            uid=uid,
            severity=_severity(str(data.get("severity") or "LOW")),
        )


@dataclass
class IncidentFinding:
    rule_id: str
    severity: Severity
    confidence: Confidence
    title: str
    summary: str
    why_it_matters: str
    recommended_action: str
    category: str
    evidence_ids: List[str] = field(default_factory=list)
    source: str = "deterministic"

    def __post_init__(self) -> None:
        self.severity = _severity(self.severity)
        self.confidence = _confidence(self.confidence)

    def to_dict(self) -> Dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "title": self.title,
            "summary": self.summary,
            "why_it_matters": self.why_it_matters,
            "recommended_action": self.recommended_action,
            "category": self.category,
            "evidence_ids": list(self.evidence_ids),
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "IncidentFinding":
        return cls(
            rule_id=str(data.get("rule_id") or ""),
            severity=_severity(str(data.get("severity") or "LOW")),
            confidence=_confidence(str(data.get("confidence") or "LOW")),
            title=str(data.get("title") or ""),
            summary=str(data.get("summary") or ""),
            why_it_matters=str(data.get("why_it_matters") or ""),
            recommended_action=str(data.get("recommended_action") or ""),
            category=str(data.get("category") or "unknown"),
            evidence_ids=[str(item) for item in data.get("evidence_ids", []) if str(item)],
            source=str(data.get("source") or "deterministic"),
        )


@dataclass
class CoredumpGroup:
    signature: str
    executable: str
    package: str
    signal: str
    top_frame: str
    count: int = 1
    uid: Optional[int] = None
    timestamps: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    desktop_component: bool = False

    def to_dict(self) -> Dict[str, object]:
        return {
            "signature": self.signature,
            "executable": self.executable,
            "package": self.package,
            "signal": self.signal,
            "top_frame": self.top_frame,
            "count": self.count,
            "uid": self.uid,
            "timestamps": list(self.timestamps),
            "evidence_ids": list(self.evidence_ids),
            "desktop_component": self.desktop_component,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "CoredumpGroup":
        uid_value = data.get("uid")
        try:
            uid = int(uid_value) if uid_value is not None else None
        except (TypeError, ValueError):
            uid = None
        return cls(
            signature=str(data.get("signature") or ""),
            executable=str(data.get("executable") or ""),
            package=str(data.get("package") or ""),
            signal=str(data.get("signal") or ""),
            top_frame=str(data.get("top_frame") or ""),
            count=int(data.get("count") or 1),
            uid=uid,
            timestamps=[str(item) for item in data.get("timestamps", [])],
            evidence_ids=[str(item) for item in data.get("evidence_ids", [])],
            desktop_component=bool(data.get("desktop_component", False)),
        )


@dataclass
class DiagnosticProbe:
    probe_id: str
    probe_type: str
    title: str
    summary: str
    target: Dict[str, object] = field(default_factory=dict)
    evidence_ids: List[str] = field(default_factory=list)
    priority: int = 100
    required: bool = False
    affects_plan: bool = True

    def to_dict(self) -> Dict[str, object]:
        return {
            "probe_id": self.probe_id,
            "probe_type": self.probe_type,
            "title": self.title,
            "summary": self.summary,
            "target": dict(self.target),
            "evidence_ids": list(self.evidence_ids),
            "priority": self.priority,
            "required": self.required,
            "affects_plan": self.affects_plan,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "DiagnosticProbe":
        return cls(
            probe_id=str(data.get("probe_id") or ""),
            probe_type=str(data.get("probe_type") or ""),
            title=str(data.get("title") or ""),
            summary=str(data.get("summary") or ""),
            target=dict(data.get("target") or {}) if isinstance(data.get("target"), Mapping) else {},
            evidence_ids=[str(item) for item in data.get("evidence_ids", [])],
            priority=int(data.get("priority") or 100),
            required=bool(data.get("required", False)),
            affects_plan=bool(data.get("affects_plan", True)),
        )


@dataclass
class DiagnosticProbeResult:
    probe_id: str
    probe_type: str
    status: str
    summary: str
    requested_by: str = "ai"
    evidence_ids: List[str] = field(default_factory=list)
    action_ids: List[str] = field(default_factory=list)
    affects_plan: bool = True
    duration_ms: int = 0

    def to_dict(self) -> Dict[str, object]:
        return {
            "probe_id": self.probe_id,
            "probe_type": self.probe_type,
            "status": self.status,
            "summary": self.summary,
            "requested_by": self.requested_by,
            "evidence_ids": list(self.evidence_ids),
            "action_ids": list(self.action_ids),
            "affects_plan": self.affects_plan,
            "duration_ms": self.duration_ms,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "DiagnosticProbeResult":
        return cls(
            probe_id=str(data.get("probe_id") or ""),
            probe_type=str(data.get("probe_type") or ""),
            status=str(data.get("status") or "unknown"),
            summary=str(data.get("summary") or ""),
            requested_by=str(data.get("requested_by") or "ai"),
            evidence_ids=[str(item) for item in data.get("evidence_ids", [])],
            action_ids=[str(item) for item in data.get("action_ids", [])],
            affects_plan=bool(data.get("affects_plan", True)),
            duration_ms=max(0, int(data.get("duration_ms") or 0)),
        )


@dataclass
class RepairAction:
    action_id: str
    recipe_id: str
    title: str
    summary: str
    risk: Severity
    parameters: Dict[str, object] = field(default_factory=dict)
    command_preview: List[List[str]] = field(default_factory=list)
    eligible: bool = False
    verified: bool = False
    requires_root: bool = True
    reversible: bool = False
    backup_description: str = ""
    reason: str = ""

    def __post_init__(self) -> None:
        self.risk = _severity(self.risk)

    def to_dict(self) -> Dict[str, object]:
        return {
            "action_id": self.action_id,
            "recipe_id": self.recipe_id,
            "title": self.title,
            "summary": self.summary,
            "risk": self.risk.value,
            "parameters": dict(self.parameters),
            "command_preview": [list(command) for command in self.command_preview],
            "eligible": self.eligible,
            "verified": self.verified,
            "requires_root": self.requires_root,
            "reversible": self.reversible,
            "backup_description": self.backup_description,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "RepairAction":
        raw_commands = data.get("command_preview", [])
        commands = []
        if isinstance(raw_commands, list):
            for item in raw_commands:
                if isinstance(item, list):
                    commands.append([str(part) for part in item])
        return cls(
            action_id=str(data.get("action_id") or ""),
            recipe_id=str(data.get("recipe_id") or ""),
            title=str(data.get("title") or ""),
            summary=str(data.get("summary") or ""),
            risk=_severity(str(data.get("risk") or "LOW")),
            parameters=dict(data.get("parameters") or {}) if isinstance(data.get("parameters"), Mapping) else {},
            command_preview=commands,
            eligible=bool(data.get("eligible", False)),
            verified=bool(data.get("verified", False)),
            requires_root=bool(data.get("requires_root", True)),
            reversible=bool(data.get("reversible", False)),
            backup_description=str(data.get("backup_description") or ""),
            reason=str(data.get("reason") or ""),
        )


@dataclass
class RepairResult:
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
            "output_excerpt": self.output_excerpt,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "RepairResult":
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
class IncidentReport:
    incident_id: str
    target_boot: str
    trigger: str
    created_at: int = field(default_factory=lambda: int(time.time()))
    boot_id: str = ""
    distro: Dict[str, object] = field(default_factory=dict)
    collection_status: str = "complete"
    collection_errors: List[str] = field(default_factory=list)
    truncated: bool = False
    evidence: List[IncidentEvidence] = field(default_factory=list)
    findings: List[IncidentFinding] = field(default_factory=list)
    coredumps: List[CoredumpGroup] = field(default_factory=list)
    system_facts: Dict[str, object] = field(default_factory=dict)
    diagnostic_probes: List[DiagnosticProbe] = field(default_factory=list)
    probe_results: List[DiagnosticProbeResult] = field(default_factory=list)
    repair_actions: List[RepairAction] = field(default_factory=list)
    repair_results: List[RepairResult] = field(default_factory=list)
    post_repair: Dict[str, object] = field(default_factory=dict)
    ai_review: Dict[str, object] = field(default_factory=dict)
    scan_window: Dict[str, object] = field(default_factory=dict)
    automation: Dict[str, object] = field(default_factory=dict)
    schema_version: str = INCIDENT_SCHEMA_VERSION
    scanner_version: str = SCANNER_VERSION

    @property
    def highest_severity(self) -> Severity:
        if not self.findings:
            return Severity.LOW
        return max((finding.severity for finding in self.findings), key=SEVERITY_ORDER.index)

    @property
    def eligible_actions(self) -> List[RepairAction]:
        return [action for action in self.repair_actions if action.eligible and action.verified]

    @property
    def unresolved_high_risk(self) -> bool:
        return any(
            finding.severity in {Severity.HIGH, Severity.CRITICAL}
            and not any(repair_action_covers_finding(action, finding) for action in self.eligible_actions)
            for finding in self.findings
        )

    @property
    def probe_plan_incomplete(self) -> bool:
        return any(
            item.affects_plan and item.status in {"failed", "timeout"}
            for item in self.probe_results
        )

    @property
    def apply_prompt_default_yes(self) -> bool:
        return bool(
            self.eligible_actions
            and self.collection_status == "complete"
            and not self.truncated
            and not self.probe_plan_incomplete
            and not self.unresolved_high_risk
            and all(action.risk in {Severity.LOW, Severity.MEDIUM} for action in self.eligible_actions)
        )

    def to_dict(self) -> Dict[str, object]:
        return {
            "schema": f"{INCIDENT_REPORT_TYPE}/{self.schema_version}",
            "schema_version": self.schema_version,
            "scanner_version": self.scanner_version,
            "report_type": INCIDENT_REPORT_TYPE,
            "incident_id": self.incident_id,
            "created_at": self.created_at,
            "target_boot": self.target_boot,
            "boot_id": self.boot_id,
            "trigger": self.trigger,
            "distro": dict(self.distro),
            "collection": {
                "status": self.collection_status,
                "errors": list(self.collection_errors),
                "truncated": self.truncated,
            },
            "summary": {
                "severity": self.highest_severity.value,
                "findings": len(self.findings),
                "coredump_groups": len(self.coredumps),
                "coredump_count": sum(group.count for group in self.coredumps),
                "repair_actions": len(self.eligible_actions),
                "diagnostic_probes": len(self.diagnostic_probes),
                "completed_probes": sum(item.status not in {"failed", "timeout"} for item in self.probe_results),
                "probe_plan_incomplete": self.probe_plan_incomplete,
                "default_apply_yes": self.apply_prompt_default_yes,
            },
            "evidence": [item.to_dict() for item in self.evidence],
            "findings": [item.to_dict() for item in self.findings],
            "coredumps": [item.to_dict() for item in self.coredumps],
            "system_facts": dict(self.system_facts),
            "diagnostic_probes": [item.to_dict() for item in self.diagnostic_probes],
            "probe_results": [item.to_dict() for item in self.probe_results],
            "repair_actions": [item.to_dict() for item in self.repair_actions],
            "repair_results": [item.to_dict() for item in self.repair_results],
            "post_repair": dict(self.post_repair),
            "ai_review": dict(self.ai_review),
            "scan_window": dict(self.scan_window),
            "automation": dict(self.automation),
        }

    def to_json(self, *, indent: Optional[int] = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: Mapping[str, object]) -> "IncidentReport":
        collection = data.get("collection", {})
        if not isinstance(collection, Mapping):
            collection = {}
        return cls(
            incident_id=str(data.get("incident_id") or ""),
            target_boot=str(data.get("target_boot") or ""),
            trigger=str(data.get("trigger") or "manual"),
            created_at=int(data.get("created_at") or 0),
            boot_id=str(data.get("boot_id") or ""),
            distro=dict(data.get("distro") or {}) if isinstance(data.get("distro"), Mapping) else {},
            collection_status=str(collection.get("status") or "unknown"),
            collection_errors=[str(item) for item in collection.get("errors", [])],
            truncated=bool(collection.get("truncated", False)),
            evidence=[IncidentEvidence.from_dict(item) for item in data.get("evidence", []) if isinstance(item, Mapping)],
            findings=[IncidentFinding.from_dict(item) for item in data.get("findings", []) if isinstance(item, Mapping)],
            coredumps=[CoredumpGroup.from_dict(item) for item in data.get("coredumps", []) if isinstance(item, Mapping)],
            system_facts=dict(data.get("system_facts") or {}) if isinstance(data.get("system_facts"), Mapping) else {},
            diagnostic_probes=[DiagnosticProbe.from_dict(item) for item in data.get("diagnostic_probes", []) if isinstance(item, Mapping)],
            probe_results=[DiagnosticProbeResult.from_dict(item) for item in data.get("probe_results", []) if isinstance(item, Mapping)],
            repair_actions=[RepairAction.from_dict(item) for item in data.get("repair_actions", []) if isinstance(item, Mapping)],
            repair_results=[RepairResult.from_dict(item) for item in data.get("repair_results", []) if isinstance(item, Mapping)],
            post_repair=dict(data.get("post_repair") or {}) if isinstance(data.get("post_repair"), Mapping) else {},
            ai_review=dict(data.get("ai_review") or {}) if isinstance(data.get("ai_review"), Mapping) else {},
            scan_window=dict(data.get("scan_window") or {}) if isinstance(data.get("scan_window"), Mapping) else {},
            automation=dict(data.get("automation") or {}) if isinstance(data.get("automation"), Mapping) else {},
            schema_version=str(data.get("schema_version") or str(data.get("schema") or "").partition("/")[2] or INCIDENT_SCHEMA_VERSION),
            scanner_version=str(data.get("scanner_version") or SCANNER_VERSION),
        )

    def render_terminal(self, *, verbose: bool = False) -> str:
        lines = [
            "\n[AuraScan] Incident Recovery Assistant",
            "=" * 54,
            f"Incident: {self.incident_id} | Boot: {self.boot_id or self.target_boot}",
            f"Findings: {len(self.findings)} | Application crashes: {sum(group.count for group in self.coredumps)} | Risk: {self.highest_severity.value}",
            f"Collection: {self.collection_status}" + (" (truncated)" if self.truncated else ""),
            "-" * 54,
        ]
        if not self.findings and not self.coredumps:
            lines.append("[OK] AuraScan did not find a recognized crash or system-failure pattern.")
        ordered = sorted(
            enumerate(self.findings),
            key=lambda item: (-SEVERITY_ORDER.index(item[1].severity), item[0]),
        )
        visible = ordered if verbose else ordered[:5]
        if visible:
            lines.append("Likely causes and incidents:")
            for index, (_original, finding) in enumerate(visible, start=1):
                lines.append(f"{index}. {finding.title} [{finding.severity.value}, {finding.confidence.value.lower()} confidence]")
                lines.append(finding.summary)
                if finding.why_it_matters:
                    lines.append(f"Why: {finding.why_it_matters}")
                if finding.recommended_action:
                    lines.append(f"AuraScan response: {finding.recommended_action}")
                if verbose and finding.evidence_ids:
                    lines.append("Evidence: " + ", ".join(finding.evidence_ids[:8]))
                lines.append("")
            if lines[-1] == "":
                lines.pop()
        hidden = len(ordered) - len(visible)
        if hidden:
            lines.append(f"{hidden} additional incident findings hidden. Use --verbose to show all.")
        if self.coredumps:
            lines.append("\nApplication crash groups:")
            groups = self.coredumps if verbose else self.coredumps[:8]
            for group in groups:
                label = group.executable or "unknown application"
                package = f" ({group.package})" if group.package else ""
                lines.append(f"- {label}{package}: signal {group.signal or 'unknown'}, count {group.count}")
            if len(self.coredumps) > len(groups):
                lines.append(f"- {len(self.coredumps) - len(groups)} additional groups hidden")
        if self.probe_results:
            completed = sum(item.status not in {"failed", "timeout"} for item in self.probe_results)
            ready = sum(item.status == "action_ready" for item in self.probe_results)
            failed = len(self.probe_results) - completed
            lines.append(
                f"\nAI-guided local checks: {completed}/{len(self.probe_results)} completed; "
                f"{ready} produced verified repair options"
                + (f"; {failed} incomplete" if failed else "")
                + "."
            )
            if verbose:
                for item in self.probe_results:
                    lines.append(f"- {item.probe_type}: {item.status} - {item.summary}")
        if self.eligible_actions:
            eligible_actions = self.eligible_actions
            recommended_ids = self.ai_review.get("recommended_action_ids", []) if isinstance(self.ai_review, Mapping) else []
            recommended = {str(item) for item in recommended_ids} if isinstance(recommended_ids, list) else set()
            original_order = {item.action_id: index for index, item in enumerate(eligible_actions)}
            display_actions = sorted(
                eligible_actions,
                key=lambda item: (item.action_id not in recommended, original_order[item.action_id]),
            )
            lines.append("\nPrepared repairs:")
            for index, action in enumerate(display_actions, start=1):
                recommendation = " | AI recommended" if action.action_id in recommended else ""
                lines.append(f"{index}. {action.title} [{action.risk.value}{recommendation}]")
                lines.append(action.summary)
                if verbose and action.command_preview:
                    for command in action.command_preview:
                        lines.append("   Command: " + " ".join(command))
                if action.backup_description:
                    lines.append("   Backup: " + action.backup_description)
        if self.collection_errors:
            lines.append("\nCollection notes:")
            lines.extend(f"- {item}" for item in self.collection_errors[:8])
        if self.ai_review:
            status = str(self.ai_review.get("status") or "unknown")
            provider = str(self.ai_review.get("provider") or "")
            summary = str(self.ai_review.get("summary") or "")
            final_phase = self.ai_review.get("final", {})
            phase_label = "two-pass" if isinstance(final_phase, Mapping) and final_phase.get("status") == "ok" else "triage"
            lines.append("\nAI review: " + status + (f", {phase_label}" if status in {"ok", "triage_only"} else "") + (f" ({provider})" if provider else ""))
            if summary:
                lines.append(summary)
            causes = self.ai_review.get("likely_causes", [])
            if isinstance(causes, list) and causes:
                lines.append("AI-correlated causes:")
                for cause in causes[:3]:
                    if not isinstance(cause, Mapping):
                        continue
                    title = str(cause.get("title") or "Possible cause")
                    confidence = str(cause.get("confidence") or "unknown")
                    explanation = str(cause.get("explanation") or "")
                    lines.append(f"- {title} [{confidence} confidence]" + (f": {explanation}" if explanation else ""))
            recommended_ids = self.ai_review.get("recommended_action_ids", [])
            if isinstance(recommended_ids, list) and recommended_ids:
                action_titles = {action.action_id: action.title for action in self.eligible_actions}
                recommended = [action_titles[item] for item in recommended_ids if item in action_titles]
                if recommended:
                    lines.append("AI recommends these already-verified AuraScan actions: " + "; ".join(recommended))
        if self.post_repair:
            resolved = len(self.post_repair.get("resolved_finding_keys", []))
            remaining = len(self.post_repair.get("remaining_finding_keys", []))
            lines.append(f"\nPost-repair diagnostics: {resolved} resolved, {remaining} still observed.")
        return "\n".join(lines)


def repair_action_covers_finding(action: RepairAction, finding: IncidentFinding) -> bool:
    recipes_by_category = {
        "repository": {"repository_restore"},
        "package_manager": {"stale_pacman_lock"},
        "disk_space": {"package_cache_cleanup"},
        "initramfs": {"initramfs_rebuild"},
        "failed_service": {"restart_system_service", "restart_user_service"},
        "application_crash": {"exact_package_reinstall"},
    }
    if finding.category == "kernel_module":
        text = " ".join([finding.title, finding.summary, finding.recommended_action]).lower()
        if "unavailable" in text or "not available" in text:
            return False
        if "header" in text:
            return action.recipe_id == "kernel_headers_install"
        return action.recipe_id == "dkms_autoinstall"
    return action.recipe_id in recipes_by_category.get(finding.category, set())


@dataclass
class CommandOutput:
    returncode: int
    stdout: str = ""
    stderr: str = ""
    truncated: bool = False


class IncidentProgressDisplay:
    """Render honest stage progress while open-ended diagnostic commands run."""

    _FRAMES = ("|", "/", "-", "\\")

    def __init__(
        self,
        stream,
        *,
        total_steps: int,
        enabled: bool = True,
        completion_label: str = "Incident analysis ready",
        interval: float = 0.25,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.stream = stream
        self.total_steps = max(1, int(total_steps))
        self.enabled = enabled
        self.completion_label = completion_label
        self.interval = max(0.05, float(interval))
        self.clock = clock
        self._interactive = bool(getattr(stream, "isatty", lambda: False)())
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._started_at = 0.0
        self._step = 0
        self._label = "Starting bounded incident scan"
        self._frame_index = 0
        self._last_width = 0
        self._last_static_stage: Tuple[int, str] = (-1, "")

    def __enter__(self) -> "IncidentProgressDisplay":
        if not self.enabled:
            return self
        self._started_at = self.clock()
        if self._interactive:
            self._thread = threading.Thread(target=self._animate, name="aurascan-incident-progress", daemon=True)
            self._thread.start()
        return self

    def update(self, step: int, label: str) -> None:
        if not self.enabled:
            return
        clean_label = str(label).strip().rstrip(".") or "Working"
        with self._lock:
            self._step = min(self.total_steps, max(0, int(step)))
            self._label = clean_label
            if self._interactive:
                self._render_interactive_locked()
                return
            stage = (self._step, self._label)
            if stage != self._last_static_stage:
                print(
                    f"[AuraScan] Step {self._step}/{self.total_steps}: {self._label}...",
                    file=self.stream,
                    flush=True,
                )
                self._last_static_stage = stage

    def __exit__(self, exc_type, _exc, _traceback) -> bool:
        if not self.enabled:
            return False
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=max(1.0, self.interval * 4))
        elapsed = max(0.0, self.clock() - self._started_at)
        label = self.completion_label if exc_type is None else "Incident analysis stopped"
        final_line = f"[AuraScan] {label} in {elapsed:.1f}s."
        if self._interactive:
            with self._lock:
                self.stream.write("\r" + final_line.ljust(self._last_width) + "\n")
                self.stream.flush()
        else:
            print(final_line, file=self.stream, flush=True)
        return False

    def _animate(self) -> None:
        while not self._stop.wait(self.interval):
            with self._lock:
                self._frame_index += 1
                self._render_interactive_locked()

    def _render_interactive_locked(self) -> None:
        elapsed = max(0.0, self.clock() - self._started_at)
        frame = self._FRAMES[self._frame_index % len(self._FRAMES)]
        line = (
            f"[AuraScan] {frame} Step {self._step}/{self.total_steps}: "
            f"{self._label} ({elapsed:.0f}s elapsed)"
        )
        self.stream.write("\r" + line.ljust(self._last_width))
        self.stream.flush()
        self._last_width = max(self._last_width, len(line))


@dataclass(frozen=True)
class IncidentRule:
    rule_id: str
    category: str
    severity: Severity
    confidence: Confidence
    pattern: re.Pattern
    title: str
    why: str
    action: str


INCIDENT_RULES = (
    IncidentRule("INC-KERNEL-PANIC", "kernel_panic", Severity.CRITICAL, Confidence.CONFIRMED, re.compile(r"(?i)kernel panic|not syncing:|panic_on_oops"), "The kernel appears to have panicked", "A kernel panic stops normal system operation and usually forces a reset or reboot.", "AuraScan will verify kernel/module state; bootloader and filesystem recovery remain manual."),
    IncidentRule("INC-WATCHDOG", "watchdog", Severity.HIGH, Confidence.HIGH, re.compile(r"(?i)watchdog.*(?:lockup|timeout|hard LOCKUP|soft lockup)|NMI watchdog"), "A watchdog or CPU lockup was recorded", "Watchdogs reset systems when the kernel or hardware stops responding.", "AuraScan will correlate kernel, module, thermal, and hardware evidence before offering a repair."),
    IncidentRule("INC-OOM", "out_of_memory", Severity.HIGH, Confidence.CONFIRMED, re.compile(r"(?i)invoked oom-killer|oom-kill|out of memory:\s*killed process|memory cgroup out of memory|killed process \d+ .* total-vm|systemd-oomd.*killed"), "The system ran out of usable memory", "The kernel or systemd killed a process to recover memory, which can terminate the desktop or critical services.", "AuraScan will identify affected processes; V1 does not guess swap or memory-policy changes."),
    IncidentRule("INC-NVIDIA-ALLOCATION", "gpu", Severity.MEDIUM, Confidence.HIGH, re.compile(r"(?i)NVRM:.*(?:NV_ERR_NO_MEMORY|assert(?:ion)? failed: out of memory)"), "The NVIDIA driver reported a memory-allocation failure", "An NVIDIA allocation failure can reflect GPU address-space pressure, resource pressure, or a driver defect; by itself it does not prove that system RAM was exhausted.", "AuraScan will correlate driver/module consistency and stronger GPU-reset evidence. It will not apply speculative memory or driver changes."),
    IncidentRule("INC-GPU-RESET", "gpu", Severity.HIGH, Confidence.HIGH, re.compile(r"(?i)(NVRM: Xid|GPU has fallen off the bus|amdgpu.*(?:ring|GPU reset|timeout)|i915.*GPU HANG|drm.*GPU reset)"), "The graphics driver reported a GPU failure", "GPU resets can freeze or terminate the graphical session and may be caused by driver/module mismatch or hardware instability.", "AuraScan will verify installed kernel and module support before suggesting a package or DKMS repair."),
    IncidentRule("INC-STORAGE-IO", "storage", Severity.CRITICAL, Confidence.HIGH, re.compile(r"(?i)(I/O error|blk_update_request|Buffer I/O error|nvme.*(?:critical|reset|timeout)|ata\d.*(?:failed|error)|medium error)"), "Storage I/O errors were recorded", "Continuing writes to unreliable storage can corrupt data or filesystems.", "AuraScan will not run filesystem or partition repair automatically; preserve data and inspect device health."),
    IncidentRule("INC-FILESYSTEM", "filesystem", Severity.HIGH, Confidence.HIGH, re.compile(r"(?i)(EXT4-fs error|BTRFS.*(?:error|corrupt)|XFS.*corruption|filesystem.*read-only|remounting filesystem read-only)"), "The filesystem reported an error", "Filesystem corruption or forced read-only mode needs controlled offline recovery.", "AuraScan will explain the evidence but will not automate fsck, partition, or mount repairs."),
    IncidentRule("INC-THERMAL", "thermal_power", Severity.HIGH, Confidence.HIGH, re.compile(r"(?i)(critical temperature|thermal.*shutdown|CPU.*over temperature|power supply.*failure|MCE:.*hardware error|machine check)"), "Thermal, power, or hardware-fault evidence was recorded", "Hardware protection events can abruptly reset the system and are not safely solved with a generic software command.", "AuraScan will preserve the evidence and avoid speculative hardware changes."),
    IncidentRule("INC-PACKAGE-INTERRUPTED", "package_manager", Severity.MEDIUM, Confidence.HIGH, re.compile(r"(?i)(failed to (?:commit|release) transaction|transaction not initialized|database is locked|could not lock database|interrupted package|pacman.*terminated)"), "A package transaction appears to have been interrupted", "Interrupted package operations can leave a stale lock or incomplete package state.", "AuraScan will check for active package-manager processes and prepare only a bounded lock or repository repair."),
    IncidentRule("INC-DKMS", "kernel_module", Severity.HIGH, Confidence.HIGH, re.compile(r"(?i)(dkms.*(?:failed|error|broken)|module.*invalid module format|unknown symbol|module verification failed|failed to load kernel module)"), "A kernel module or DKMS operation failed", "External modules must match the installed kernel and headers.", "AuraScan will verify headers and DKMS state before preparing a repair."),
    IncidentRule("INC-INITRAMFS", "initramfs", Severity.HIGH, Confidence.HIGH, re.compile(r"(?i)(mkinitcpio.*(?:failed|error)|dracut.*(?:failed|error)|failed to generate initramfs|initramfs.*missing)"), "Initramfs generation failed", "A missing or incomplete initramfs can prevent a kernel from booting.", "AuraScan can rebuild initramfs only after checking the installed generator, boot space, and backups."),
    IncidentRule("INC-DISK-FULL", "disk_space", Severity.HIGH, Confidence.CONFIRMED, re.compile(r"(?i)(no space left on device|ENOSPC|disk quota exceeded)"), "A filesystem ran out of space", "Package operations and services can fail or corrupt temporary state when writes cannot complete.", "AuraScan can offer bounded package-cache cleanup when the cache is large enough to help."),
    IncidentRule("INC-REPOSITORY", "repository", Severity.MEDIUM, Confidence.HIGH, re.compile(r"(?i)(no servers configured for repository|failed to synchronize all databases|failed retrieving file.*404|failed to download.*NotFound)"), "Package repository access failed", "Stale or disabled mirrors can prevent repair and upgrade operations without damaging installed packages.", "AuraScan will reuse its deterministic repository-health checks before offering a mirror repair."),
)


def build_incidents_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aurascan incidents",
        description="Diagnose system and application crashes and prepare guarded recovery actions.",
    )
    target = parser.add_mutually_exclusive_group()
    target.add_argument("--last-boot", action="store_true", help="analyze the previous boot")
    target.add_argument("--current-boot", action="store_true", help="analyze the current boot")
    target.add_argument("--boot", help="analyze a specific journal boot ID or offset")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--history", action="store_true", help="list saved incident reports")
    mode.add_argument("--show", metavar="INCIDENT_ID", help="show a saved incident report")
    mode.add_argument("--resolve", action="store_true", help="resolve or acknowledge pending tray findings in one guided flow")
    automation = parser.add_mutually_exclusive_group()
    automation.add_argument("--enable-monitor", action="store_true", help="enable read-only boot and weekly incident monitoring")
    automation.add_argument("--disable-monitor", action="store_true", help="disable boot and weekly incident monitoring")
    automation.add_argument("--monitor-status", action="store_true", help="show boot monitor and weekly timer status")
    automation.add_argument("--run-maintenance", action="store_true", help="run the bounded weekly maintenance scan now")
    automation.add_argument("--maintenance-status", action="store_true", help="show weekly incident maintenance status")
    automation.add_argument("--enable-background-ai", action="store_true", help="enable redacted incident AI analysis in the logged-in user session")
    automation.add_argument("--disable-background-ai", action="store_true", help="disable logged-in background incident AI analysis")
    automation.add_argument("--background-ai-status", action="store_true", help="show background incident AI configuration and timer status")
    automation.add_argument("--auto-repair", choices=["off", "safe"], help="configure the root-owned deterministic incident repair policy")
    parser.add_argument("--dry-run", action="store_true", help="diagnose and show repairs without applying them")
    parser.add_argument("--json", action="store_true", dest="json_output", help="emit structured incident JSON")
    parser.add_argument("--verbose", action="store_true", help="show all findings, evidence IDs, and command previews")
    parser.add_argument("--yes", action="store_true", help="apply fully verified allowlisted repairs without prompting")
    parser.add_argument("--no-ai", action="store_true", help="disable AI incident review for this run")
    parser.add_argument("--facts-only", action="store_true", help="send structured facts but no evidence excerpts to AI")
    parser.add_argument("--capture-monitor", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--capture-maintenance", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--background-assist", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--capture-safe-autopilot", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--safe-autopilot-enabled", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--set-auto-repair-policy", choices=["off", "safe"], help=argparse.SUPPRESS)
    parser.add_argument("--apply-request", help=argparse.SUPPRESS)
    return parser


def resolve_incident_config(env: Optional[Mapping[str, str]] = None) -> IncidentConfig:
    source = env if env is not None else os.environ
    monitor_raw = source.get(INCIDENT_MONITOR_ENABLED_ENV)
    monitor_enabled = parse_config_bool(monitor_raw)
    if monitor_raw is not None and monitor_enabled is None:
        return IncidentConfig(error=f"invalid {INCIDENT_MONITOR_ENABLED_ENV} value")
    if monitor_enabled is None:
        monitor_enabled = False

    ai_raw = source.get(INCIDENT_AI_ENABLED_ENV)
    ai_enabled = parse_config_bool(ai_raw)
    if ai_raw is not None and ai_enabled is None:
        return IncidentConfig(error=f"invalid {INCIDENT_AI_ENABLED_ENV} value")
    if ai_enabled is None:
        ai_enabled = True

    ai_evidence = source.get(INCIDENT_AI_EVIDENCE_ENV, "redacted").strip().lower() or "redacted"
    if ai_evidence not in INCIDENT_AI_EVIDENCE_VALUES:
        return IncidentConfig(error=f"invalid {INCIDENT_AI_EVIDENCE_ENV} value")
    background_raw = source.get(INCIDENT_BACKGROUND_AI_ENV)
    background_enabled = parse_config_bool(background_raw)
    if background_raw is not None and background_enabled is None:
        return IncidentConfig(error=f"invalid {INCIDENT_BACKGROUND_AI_ENV} value")
    if background_enabled is None:
        background_enabled = False
    return IncidentConfig(
        monitor_enabled=bool(monitor_enabled),
        ai_enabled=bool(ai_enabled),
        ai_evidence=ai_evidence,
        background_ai_enabled=bool(background_enabled),
    )


def incident_options_from_args(args: argparse.Namespace, env: Optional[Mapping[str, str]] = None) -> IncidentOptions:
    config = resolve_incident_config(env)
    target = "auto"
    if args.last_boot:
        target = "-1"
    elif args.current_boot:
        target = "0"
    elif args.boot is not None:
        target = str(args.boot).strip()
    return IncidentOptions(
        target=target,
        dry_run=bool(args.dry_run),
        json_output=bool(args.json_output),
        verbose=bool(args.verbose),
        yes=bool(args.yes),
        no_ai=bool(args.no_ai),
        facts_only=bool(args.facts_only),
        history=bool(args.history),
        show_id=str(args.show or ""),
        resolve_pending=bool(args.resolve),
        capture_monitor=bool(args.capture_monitor),
        capture_maintenance=bool(args.capture_maintenance),
        run_maintenance=bool(args.run_maintenance),
        maintenance_status=bool(args.maintenance_status),
        apply_request=str(args.apply_request or ""),
        config=config,
    )


def run_incidents(
    argv: Optional[Sequence[str]] = None,
    *,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
    input_func: Callable[[str], str] = input,
    stdout=None,
    stderr=None,
    env: Optional[Mapping[str, str]] = None,
    env_path: Optional[Path] = None,
    user_root: Optional[Path] = None,
    system_root: Path = INCIDENT_SYSTEM_ROOT,
    urlopen: Optional[Callable] = None,
) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    args = build_incidents_parser().parse_args(list(argv or []))
    if args.set_auto_repair_policy:
        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            print("[AuraScan] Safe Autopilot policy writes require root privileges.", file=stderr)
            return EXIT_INCIDENT_CONFIG_ERROR
        from aurascan.core.incident_automation import write_auto_repair_policy

        ok, message = write_auto_repair_policy(str(args.set_auto_repair_policy))
        print(message, file=stdout if ok else stderr)
        return 0 if ok else EXIT_INCIDENT_CONFIG_ERROR
    if args.safe_autopilot_enabled:
        from aurascan.core.incident_automation import read_auto_repair_policy

        return 0 if read_auto_repair_policy().policy == "safe" else 1
    if args.apply_request:
        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            print("[AuraScan] Privileged incident repair helper refused a non-root invocation.", file=stderr)
            return EXIT_INCIDENT_REPAIR_FAILED
        request_ok, request_error = validate_privileged_request_file(Path(args.apply_request))
        if not request_ok:
            print(f"[AuraScan] Privileged incident repair helper refused the request: {request_error}", file=stderr)
            return EXIT_INCIDENT_REPAIR_FAILED
        from aurascan.core.incident_repairs import execute_repair_request

        results, ok = execute_repair_request(Path(args.apply_request), runner=runner, which=which, repair_root=system_root / "repairs")
        print(json.dumps({"ok": ok, "results": [result.to_dict() for result in results]}), file=stdout)
        return 0 if ok else EXIT_INCIDENT_REPAIR_FAILED

    effective_env = dict(os.environ if env is None else env)
    if env_path and env_path.exists():
        try:
            effective_env.update(read_env_file(env_path))
        except OSError:
            pass
    if args.enable_background_ai or args.disable_background_ai:
        from aurascan.core.incident_automation import set_background_ai_enabled

        enabled = bool(args.enable_background_ai and not args.disable_background_ai)
        ok, message = set_background_ai_enabled(enabled, runner=runner, env_path=env_path or user_env_path())
        print(message, file=stdout if ok else stderr)
        return 0 if ok else EXIT_INCIDENT_CONFIG_ERROR
    if args.auto_repair:
        from aurascan.core.incident_automation import configure_auto_repair_policy

        ok, message = configure_auto_repair_policy(str(args.auto_repair), runner=runner)
        print(message, file=stdout if ok else stderr)
        return 0 if ok else EXIT_INCIDENT_CONFIG_ERROR
    if args.background_ai_status:
        from aurascan.core.incident_automation import print_background_ai_status

        return print_background_ai_status(
            env=effective_env,
            runner=runner,
            user_root=user_root,
            stdout=stdout,
            json_output=bool(args.json_output),
        )
    options = incident_options_from_args(args, effective_env)
    if options.config.error:
        print(f"[AuraScan] Incident configuration error: {options.config.error}", file=stderr)
        return EXIT_INCIDENT_CONFIG_ERROR
    if (options.capture_monitor or options.capture_maintenance or args.capture_safe_autopilot) and (not hasattr(os, "geteuid") or os.geteuid() != 0):
        print("[AuraScan] Incident monitor capture must run as root.", file=stderr)
        return EXIT_INCIDENT_CONFIG_ERROR

    if args.capture_safe_autopilot:
        from aurascan.core.incident_automation import run_safe_autopilot

        return run_safe_autopilot(system_root=system_root, runner=runner, which=which, stdout=stdout, stderr=stderr)
    if args.background_assist:
        from aurascan.core.incident_automation import run_background_assistant

        return run_background_assistant(
            env=effective_env,
            system_root=system_root,
            user_root=user_root,
            runner=runner,
            which=which,
            urlopen=urlopen,
            stdout=stdout,
            stderr=stderr,
        )
    if options.capture_maintenance:
        return capture_incident_maintenance(
            system_root=system_root,
            runner=runner,
            which=which,
            stdout=stdout,
            stderr=stderr,
        )

    if args.maintenance_status:
        return print_maintenance_status(system_root=system_root, runner=runner, stdout=stdout, json_output=bool(args.json_output))
    if args.run_maintenance:
        return run_maintenance_now(
            system_root=system_root,
            runner=runner,
            stdout=stdout,
            stderr=stderr,
            json_output=bool(args.json_output),
        )

    if args.enable_monitor or args.disable_monitor or args.monitor_status:
        return handle_incident_monitor_action(
            enable=bool(args.enable_monitor),
            disable=bool(args.disable_monitor),
            status=bool(args.monitor_status),
            runner=runner,
            stdout=stdout,
            stderr=stderr,
            env_path=env_path or user_env_path(),
        )

    report_root = user_root or user_incident_root(effective_env)
    if options.history:
        history = list_incident_reports(report_root)
        if options.json_output:
            print(json.dumps({"report_type": "incident_history", "reports": history}, indent=2), file=stdout)
        else:
            print("AuraScan incident history", file=stdout)
            if not history:
                print("No saved incident reports.", file=stdout)
            for item in history:
                created = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(item.get("created_at") or 0)))
                print(f"- {item.get('incident_id')}: {created} | {item.get('severity')} | {item.get('findings')} findings | {item.get('coredump_count')} crashes", file=stdout)
        return 0
    if options.show_id:
        report = load_incident_report(options.show_id, report_root)
        if report is None:
            print(f"[AuraScan] Saved incident not found: {options.show_id}", file=stderr)
            return EXIT_INCIDENT_UNAVAILABLE
        print(report.to_json() if options.json_output else report.render_terminal(verbose=options.verbose), file=stdout)
        return 0

    reviewed_path = incident_reviewed_state_path(effective_env, report_root=report_root)
    unreviewed_markers = unseen_pending_markers(
        uid=current_user_uid(),
        marker_root=system_root / "pending",
        seen_path=reviewed_path,
        include_resolved=options.resolve_pending,
    )
    pending_marker = highest_priority_pending_marker(unreviewed_markers)
    if options.target == "auto":
        pending_boot = str(pending_marker.get("boot_id") or "") if pending_marker else ""
        options.target = pending_boot if valid_boot_target(pending_boot) else "0"
    if not valid_boot_target(options.target):
        print("[AuraScan] Invalid boot target. Use an integer offset or a 32-character boot ID.", file=stderr)
        return EXIT_INCIDENT_UNAVAILABLE

    if options.resolve_pending and not options.json_output:
        boot_count = len({str(item.get("boot_id") or "") for item in unreviewed_markers if item.get("boot_id")})
        if unreviewed_markers:
            print(
                f"[AuraScan] Resolving {len(unreviewed_markers)} pending alert(s) across {boot_count or 1} boot(s).",
                file=stdout,
            )
        else:
            print("[AuraScan] No pending tray alert exists; checking current system evidence.", file=stdout)
    show_progress = not options.json_output and not options.capture_monitor
    if show_progress:
        print(
            "[AuraScan] Scanning logs and crash records. This can take a minute; "
            "no system changes are made during analysis.",
            file=stdout,
            flush=True,
        )
    activity = IncidentProgressDisplay(
        stdout,
        total_steps=INCIDENT_ANALYSIS_PROGRESS_STEPS,
        enabled=show_progress,
    )
    with activity:
        report = build_incident_report(
            options.target,
            trigger="boot_monitor" if options.capture_monitor else "manual",
            runner=runner,
            which=which,
            include_all_users=options.capture_monitor,
            progress_callback=activity.update if show_progress else None,
        )

        if options.capture_monitor:
            persist_system_incident_report(report, root=system_root / "reports")
            if report.findings or report.coredumps:
                write_pending_markers(report, root=system_root / "pending")
            return 0

        from aurascan.core.incident_repairs import plan_repair_actions
        from aurascan.core.incident_diagnostics import prepare_ai_guided_repair_plan

        activity.update(8, "Verifying safe repair recipes")
        ai_disabled = options.no_ai or not options.config.ai_enabled
        report.repair_actions = plan_repair_actions(
            report,
            runner=runner,
            which=which,
            include_package_integrity=ai_disabled,
        )
        cached_report = None
        if options.resolve_pending and pending_marker and not ai_disabled:
            from aurascan.core.incident_automation import load_reusable_background_plan

            cached_report = load_reusable_background_plan(report, pending_marker, report_root)
        activity.update(9, "Finalizing deterministic findings" if ai_disabled else "Preparing AI-guided diagnostic choices")
        guided_step = [9]

        def guided_progress(label: str) -> None:
            guided_step[0] = min(11, guided_step[0] + 1)
            activity.update(guided_step[0], label)

        prepare_ai_guided_repair_plan(
            report,
            disabled=ai_disabled,
            facts_only=options.facts_only or options.config.ai_evidence == "facts-only",
            runner=runner,
            which=which,
            urlopen=urlopen,
            env=effective_env,
            cached_report=cached_report,
            progress_callback=guided_progress if show_progress else None,
        )
        activity.update(12, "Saving the private incident report")
        persist_incident_report(report, report_root)
    if not options.resolve_pending and report.collection_status != "unavailable" and report.boot_id:
        reviewed = [item for item in unreviewed_markers if str(item.get("boot_id") or "").replace("-", "") == report.boot_id.replace("-", "")]
        mark_pending_markers_seen(reviewed, seen_path=reviewed_path)
    if not options.json_output:
        print(report.render_terminal(verbose=options.verbose), file=stdout)

    if not report.evidence and report.collection_status == "unavailable":
        if options.json_output:
            print(report.to_json(), file=stdout)
        return EXIT_INCIDENT_UNAVAILABLE
    if not report.eligible_actions or options.dry_run or (options.json_output and not options.yes):
        if options.json_output:
            print(report.to_json(), file=stdout)
        if should_acknowledge_resolution(options, report):
            acknowledge_incident_resolution(
                unreviewed_markers,
                seen_path=reviewed_path,
                report=report,
                stdout=stdout,
                quiet=options.json_output,
            )
        return 0
    if not options.yes:
        suffix = "[Y/n]" if report.apply_prompt_default_yes else "[y/N]"
        answer = input_func(
            f"AuraScan prepared one locally verified repair plan with {len(report.eligible_actions)} action(s). "
            f"Apply now? {suffix} "
        ).strip().lower()
        declined = answer in {"n", "no"} if report.apply_prompt_default_yes else answer not in {"y", "yes"}
        if declined:
            print("[AuraScan] Incident repairs were not applied.", file=stderr)
            if options.resolve_pending:
                print("[AuraScan] The tray alert remains active because the prepared repair was declined.", file=stderr)
            return EXIT_INCIDENT_USER_DECLINED

    from aurascan.core.incident_repairs import apply_repair_plan

    results, ok = apply_repair_plan(
        report.eligible_actions,
        runner=runner,
        which=which,
        stdout=stdout,
        stderr=stderr,
        repair_root=system_root / "repairs",
    )
    report.repair_results.extend(results)
    aftercare = IncidentProgressDisplay(
        stdout,
        total_steps=INCIDENT_COLLECTION_PROGRESS_STEPS,
        enabled=not options.json_output,
        completion_label="Repair aftercare scan complete",
    )
    with aftercare:
        fresh_report = build_incident_report(
            options.target,
            trigger="post_repair",
            runner=runner,
            which=which,
            progress_callback=aftercare.update if not options.json_output else None,
        )
    report.post_repair = summarize_post_repair(report, fresh_report)
    persist_incident_report(report, report_root)
    if options.json_output:
        print(report.to_json(), file=stdout)
    elif results:
        print("\n[AuraScan] Incident repair results", file=stdout)
        for result in results:
            print(f"- {result.status.upper()}: {result.message}", file=stdout)
        resolved = len(report.post_repair.get("resolved_finding_keys", []))
        remaining = len(report.post_repair.get("remaining_finding_keys", []))
        print(f"[AuraScan] Deterministic aftercare: {resolved} finding(s) resolved, {remaining} still observed.", file=stdout)
    if ok and should_acknowledge_resolution(options, report):
        acknowledge_incident_resolution(
            unreviewed_markers,
            seen_path=reviewed_path,
            report=report,
            stdout=stdout,
            repairs_applied=bool(results),
            quiet=options.json_output,
        )
    return 0 if ok else EXIT_INCIDENT_REPAIR_FAILED


def build_incident_report(
    target_boot: str,
    *,
    trigger: str = "manual",
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
    include_all_users: bool = False,
    pstore_root: Path = Path("/sys/fs/pstore"),
    pacman_log_path: Path = Path("/var/log/pacman.log"),
    pacman_conf_path: Path = Path("/etc/pacman.conf"),
    etc_root: Path = Path("/etc"),
    modules_root: Path = Path("/usr/lib/modules"),
    maintenance_context: Optional[Dict[str, object]] = None,
    progress_callback: Optional[Callable[[int, str], None]] = None,
) -> IncidentReport:
    if progress_callback is not None:
        progress_callback(1, "Reading bounded system journal records")
    incident_id = make_incident_id(target_boot)
    report = IncidentReport(
        incident_id=incident_id,
        target_boot=target_boot,
        trigger=trigger,
        distro=detect_distro().to_dict(),
        ai_review={"enabled": False, "status": "not_run"},
    )
    if maintenance_context is not None:
        journal_records, journal_errors, journal_truncated, journal_progress = collect_maintenance_journal_records(
            str(maintenance_context.get("boot_id") or current_boot_id()),
            after_cursor=str(maintenance_context.get("journal_cursor") or ""),
            since_usec=safe_int(maintenance_context.get("journal_since_usec")),
            requested_end_usec=safe_int(maintenance_context.get("requested_end_usec")),
            runner=runner,
            which=which,
        )
        maintenance_context.update(journal_progress)
    else:
        journal_records, journal_errors, journal_truncated = collect_journal_records(target_boot, runner=runner, which=which)
    report.collection_errors.extend(journal_errors)
    report.truncated = journal_truncated
    report.boot_id = first_boot_id(journal_records) or (str(maintenance_context.get("boot_id") or "") if maintenance_context is not None else "")

    if progress_callback is not None:
        progress_callback(2, "Analyzing boot evidence and package history")
    evidence, findings = analyze_journal_records(journal_records, target_boot=target_boot)
    report.evidence.extend(evidence)
    report.findings.extend(findings)

    pacman_evidence, pacman_findings, pacman_errors = collect_pacman_history(
        journal_records,
        path=pacman_log_path,
    )
    report.evidence.extend(pacman_evidence)
    report.findings.extend(pacman_findings)
    report.collection_errors.extend(pacman_errors)

    if progress_callback is not None:
        progress_callback(3, "Checking failed system and user services")
    failed_evidence, failed_findings = collect_failed_units(target_boot, runner=runner, which=which)
    report.evidence.extend(failed_evidence)
    report.findings.extend(failed_findings)

    if progress_callback is not None:
        progress_callback(4, "Reading bounded application crash records")
    if maintenance_context is not None:
        coredumps, coredump_evidence, coredump_findings, coredump_errors, coredump_truncated, coredump_progress = collect_maintenance_coredumps(
            target_boot,
            boot_id=report.boot_id,
            since_usec=safe_int(maintenance_context.get("coredump_since_usec")),
            requested_end_usec=safe_int(maintenance_context.get("requested_end_usec")),
            seen_record_ids=[str(item) for item in maintenance_context.get("coredump_seen_ids", [])] if isinstance(maintenance_context.get("coredump_seen_ids"), list) else [],
            runner=runner,
            which=which,
            include_all_users=include_all_users,
        )
        maintenance_context.update(coredump_progress)
    else:
        coredumps, coredump_evidence, coredump_findings, coredump_errors, coredump_truncated = collect_coredumps(
            target_boot,
            boot_id=report.boot_id,
            runner=runner,
            which=which,
            include_all_users=include_all_users,
        )
    report.coredumps.extend(coredumps)
    report.evidence.extend(coredump_evidence)
    report.findings.extend(coredump_findings)
    report.collection_errors.extend(coredump_errors)
    report.truncated = report.truncated or coredump_truncated

    if progress_callback is not None:
        progress_callback(5, "Checking retained kernel crash evidence")
    if maintenance_context is None:
        pstore_evidence, pstore_findings, pstore_errors = collect_pstore_evidence(pstore_root)
        report.evidence.extend(pstore_evidence)
        report.findings.extend(pstore_findings)
        report.collection_errors.extend(pstore_errors)

    if progress_callback is not None:
        progress_callback(6, "Checking repositories, kernel modules, and system health")
    system_facts, fact_evidence, fact_findings, fact_errors = collect_incident_system_facts(
        runner=runner,
        which=which,
        pacman_conf_path=pacman_conf_path,
        etc_root=etc_root,
        modules_root=modules_root,
    )
    report.system_facts = system_facts
    report.evidence.extend(fact_evidence)
    report.findings.extend(fact_findings)
    report.collection_errors.extend(fact_errors)
    if any("safety bound" in item.lower() for item in fact_errors):
        report.truncated = True

    if progress_callback is not None:
        progress_callback(7, "Finalizing and bounding diagnostic evidence")
    report.evidence = deduplicate_evidence(report.evidence)
    valid_ids = {item.evidence_id for item in report.evidence}
    for finding in report.findings:
        finding.evidence_ids = [item for item in finding.evidence_ids if item in valid_ids]
    report.findings = deduplicate_findings(report.findings)

    evidence_chars = sum(len(item.message) for item in report.evidence)
    if evidence_chars > INCIDENT_MAX_LOCAL_EVIDENCE_CHARS:
        report.evidence = bound_evidence(report.evidence, INCIDENT_MAX_LOCAL_EVIDENCE_CHARS)
        report.truncated = True
        report.collection_errors.append("Local evidence reached the 256 KiB safety bound.")
        retained_ids = {item.evidence_id for item in report.evidence}
        for finding in report.findings:
            finding.evidence_ids = [item for item in finding.evidence_ids if item in retained_ids]
    required_errors = journal_errors + coredump_errors
    if not journal_records and required_errors:
        report.collection_status = "unavailable"
    elif required_errors or report.truncated:
        report.collection_status = "partial"
    if maintenance_context is not None:
        report.scan_window = {
            "incremental": True,
            "boot_id": report.boot_id,
            "requested_start_usec": safe_int(maintenance_context.get("requested_start_usec")),
            "requested_end_usec": safe_int(maintenance_context.get("requested_end_usec")),
            "journal_processed_end_usec": safe_int(maintenance_context.get("journal_processed_end_usec")),
            "coredump_processed_end_usec": safe_int(maintenance_context.get("coredump_processed_end_usec")),
            "backlog_remaining": bool(maintenance_context.get("journal_backlog") or maintenance_context.get("coredump_backlog")),
        }
    return report


def collect_pacman_history(
    journal_records: Sequence[Mapping[str, object]],
    *,
    path: Path = Path("/var/log/pacman.log"),
) -> Tuple[List[IncidentEvidence], List[IncidentFinding], List[str]]:
    bounds = journal_time_bounds(journal_records)
    if bounds is None or not path.exists():
        return [], [], []
    try:
        text = read_file_tail(path, 128 * 1024)
    except OSError as exc:
        return [], [], [f"pacman history could not be read: {sanitize_error(str(exc))}"]
    evidence: List[IncidentEvidence] = []
    failure_ids: List[str] = []
    start, end = bounds
    for raw in text.splitlines():
        if "[PACMAN] Running" in raw:
            continue
        timestamp = pacman_log_timestamp(raw)
        if timestamp is None or timestamp < start - 300 or timestamp > end + 300:
            continue
        if not any(token in raw for token in ("[ALPM]", "[PACMAN]")):
            continue
        failed = bool(re.search(r"(?i)failed|error|interrupted|terminated|transaction not initialized", raw))
        if not failed and not re.search(r"(?i)transaction (?:started|completed)|installed |upgraded |removed |downgraded ", raw):
            continue
        message = redact_incident_text(raw)[:1000]
        item = IncidentEvidence(
            evidence_id=evidence_id("pacman-log", message),
            source="pacman-log",
            message=message,
            timestamp=str(int(timestamp)),
            severity=Severity.MEDIUM if failed else Severity.LOW,
        )
        evidence.append(item)
        if failed:
            failure_ids.append(item.evidence_id)
        if len(evidence) >= 80:
            break
    findings: List[IncidentFinding] = []
    if failure_ids:
        findings.append(IncidentFinding(
            "INC-PACKAGE-INTERRUPTED",
            Severity.MEDIUM,
            Confidence.HIGH,
            "Pacman history records an interrupted or failed transaction",
            "AuraScan matched package-manager failure lines within the selected boot's time range.",
            "An incomplete package transaction can leave locks, repository state, or package files needing deterministic validation.",
            "AuraScan will check current package-manager state and prepare only recipes whose preconditions still hold.",
            "package_manager",
            failure_ids[:12],
        ))
    return evidence, findings, []


def collect_incident_system_facts(
    *,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
    pacman_conf_path: Path = Path("/etc/pacman.conf"),
    etc_root: Path = Path("/etc"),
    modules_root: Path = Path("/usr/lib/modules"),
) -> Tuple[Dict[str, object], List[IncidentEvidence], List[IncidentFinding], List[str]]:
    from aurascan.core.kernel_module_autopilot import build_kernel_module_check
    from aurascan.core.upgrade_preflight import SystemSnapshot, UpgradePlan, build_repository_health_check

    facts: Dict[str, object] = {
        "tools": {
            "pacman": bool(which("pacman")),
            "pacman_conf": bool(which("pacman-conf")),
            "dkms": bool(which("dkms")),
        }
    }
    evidence: List[IncidentEvidence] = []
    findings: List[IncidentFinding] = []
    errors: List[str] = []

    repository = build_repository_health_check(pacman_conf_path)
    facts["repository_health"] = redact_structure(repository.to_dict())
    if repository.status == "error":
        errors.append("repository health could not be collected from the configured pacman file")
    if repository.status in {"broken", "repair_available"}:
        message = redact_incident_text(repository.summary)
        item = IncidentEvidence(
            evidence_id=evidence_id("repository-health", message),
            source="repository-health",
            message=message,
            severity=Severity.MEDIUM,
        )
        evidence.append(item)
        findings.append(IncidentFinding(
            "INC-REPOSITORY",
            Severity.MEDIUM,
            Confidence.CONFIRMED,
            "Repository mirror configuration is unhealthy",
            message,
            "Repair and package operations need at least one active server for every enabled repository.",
            "AuraScan will offer mirror recovery only when an active packaged backup mirrorlist is verified.",
            "repository",
            [item.evidence_id],
        ))

    if which("pacman"):
        try:
            installed_output = run_bounded_command(runner, ["pacman", "-Qq"], max_chars=256000, timeout=60)
            if installed_output.returncode != 0:
                raise RuntimeError("pacman could not list installed packages")
            if installed_output.truncated:
                errors.append("installed package facts reached the 256 KiB safety bound")
            installed_packages = [line.strip() for line in installed_output.stdout.splitlines() if line.strip()]
            kernel_runner = bounded_subprocess_runner(runner, max_chars=128000, timeout=60)
            snapshot = SystemSnapshot(
                running_kernel=run_bounded_command(runner, ["uname", "-r"], max_chars=2000, timeout=10).stdout.strip(),
                distro_info=detect_distro().to_dict(),
                installed_packages=installed_packages,
                root_free_mib=free_mib(Path("/")),
                boot_free_mib=free_mib(Path("/boot")) if Path("/boot").exists() else None,
                boot_paths=[str(path) for path in (Path("/boot"), Path("/boot/efi")) if path.exists()],
                dkms_packages=[name for name in installed_packages if "dkms" in name],
                nvidia_packages=[name for name in installed_packages if "nvidia" in name],
                zfs_packages=[name for name in installed_packages if name.startswith(("zfs", "spl"))],
                virtualbox_packages=[name for name in installed_packages if name.startswith("virtualbox")],
            )
            kernel_check = build_kernel_module_check(
                UpgradePlan(),
                snapshot,
                runner=kernel_runner,
                modules_root=modules_root,
                mode="incident",
            )
            kernel_facts = kernel_check.to_dict()
            kernel_facts["target_kernel_packages"] = list(kernel_facts.get("target_kernel_packages", []))[:32]
            kernel_facts["installed_kernel_packages"] = list(kernel_facts.get("installed_kernel_packages", []))[:32]
            kernel_facts["installed_module_families"] = list(kernel_facts.get("installed_module_families", []))[:32]
            kernel_facts["module_dirs"] = dict(list(dict(kernel_facts.get("module_dirs", {})).items())[:64])
            kernel_facts["headers_status"] = list(kernel_facts.get("headers_status", []))[:64]
            kernel_facts["prebuilt_module_status"] = list(kernel_facts.get("prebuilt_module_status", []))[:64]
            kernel_facts["fixable_issues"] = list(kernel_facts.get("fixable_issues", []))[:32]
            kernel_facts["unfixable_issues"] = list(kernel_facts.get("unfixable_issues", []))[:32]
            dkms_facts = kernel_facts.get("dkms_status", {})
            if isinstance(dkms_facts, Mapping):
                dkms_facts = dict(dkms_facts)
                dkms_facts["status_lines"] = [str(item)[:500] for item in dkms_facts.get("status_lines", [])[:100]]
                dkms_facts["failures"] = [str(item)[:500] for item in dkms_facts.get("failures", [])[:32]]
                kernel_facts["dkms_status"] = dkms_facts
            facts["kernel_module"] = redact_structure(kernel_facts)
            facts["storage"] = {
                "root_free_mib": snapshot.root_free_mib,
                "boot_free_mib": snapshot.boot_free_mib,
            }
            for issue in kernel_check.fixable_issues + kernel_check.unfixable_issues:
                if issue.kind not in {"dkms_failed", "dkms_unavailable", "missing_headers"}:
                    continue
                item = IncidentEvidence(
                    evidence_id=evidence_id("kernel-module", issue.kind + issue.evidence),
                    source="kernel-module",
                    message=redact_incident_text(issue.evidence or issue.summary)[:1000],
                    severity=issue.severity,
                )
                evidence.append(item)
                findings.append(IncidentFinding(
                    "INC-DKMS",
                    issue.severity,
                    Confidence.CONFIRMED,
                    "Current kernel module state needs attention",
                    issue.summary,
                    "Current package, header, and DKMS state can confirm whether a historical module error remains actionable.",
                    issue.action,
                    "kernel_module",
                    [item.evidence_id],
                ))
        except Exception as exc:
            errors.append(f"kernel/module facts could not be collected: {sanitize_error(str(exc))}")
    return facts, evidence, findings, errors


def bounded_subprocess_runner(runner: Callable, *, max_chars: int, timeout: int) -> Callable:
    def invoke(command, **_kwargs):
        return run_bounded_command(runner, command, max_chars=max_chars, timeout=timeout)

    return invoke


def free_mib(path: Path) -> Optional[int]:
    try:
        return int(shutil.disk_usage(path).free // (1024 * 1024))
    except OSError:
        return None


def collect_journal_records(
    target_boot: str,
    *,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
) -> Tuple[List[Dict[str, object]], List[str], bool]:
    if not which("journalctl"):
        return [], ["journalctl is not available."], False
    commands = [
        ["journalctl", f"--boot={target_boot}", "--output=json", "--no-pager", "--priority=0..4", f"--lines={INCIDENT_MAX_JOURNAL_RECORDS}"],
        ["journalctl", f"--boot={target_boot}", "--dmesg", "--output=json", "--no-pager", "--lines=1000"],
        ["journalctl", f"--boot={target_boot}", "--output=json", "--no-pager", "--lines=200"],
    ]
    records: List[Dict[str, object]] = []
    errors: List[str] = []
    seen = set()
    truncated = False
    for command in commands:
        output = run_bounded_command(runner, command, max_chars=INCIDENT_MAX_JOURNAL_RAW_CHARS, timeout=30)
        if output.returncode != 0:
            detail = sanitize_error(output.stderr or output.stdout)
            if detail and detail not in errors:
                errors.append(f"journalctl collection failed: {detail}")
            continue
        truncated = truncated or output.truncated
        for raw in output.stdout.splitlines():
            if len(records) >= INCIDENT_MAX_JOURNAL_RECORDS:
                truncated = True
                break
            try:
                item = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if not isinstance(item, dict):
                continue
            key = (
                str(item.get("__CURSOR") or ""),
                str(item.get("__REALTIME_TIMESTAMP") or ""),
                str(item.get("MESSAGE") or "")[:500],
            )
            if key in seen:
                continue
            seen.add(key)
            records.append(item)
    return records, errors, truncated


def collect_maintenance_journal_records(
    boot_id: str,
    *,
    after_cursor: str,
    since_usec: int,
    requested_end_usec: int,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
) -> Tuple[List[Dict[str, object]], List[str], bool, Dict[str, object]]:
    progress: Dict[str, object] = {
        "journal_cursor": after_cursor,
        "journal_since_usec": since_usec,
        "journal_processed_end_usec": since_usec,
        "journal_backlog": False,
    }
    if not which("journalctl"):
        return [], ["journalctl is not available."], False, progress
    requested_end_usec = requested_end_usec or int(time.time() * 1_000_000)
    since_usec = max(0, since_usec)
    candidate_end = requested_end_usec
    cursor = after_cursor
    cursor_fallback_used = False
    records: List[Dict[str, object]] = []
    output = CommandOutput(0, "", "", False)
    overflow = False
    for _attempt in range(12):
        command = [
            "journalctl",
            f"--boot={boot_id}",
            "--output=json",
            "--no-pager",
            "--priority=0..4",
            f"--until={journal_time_arg(candidate_end)}",
            f"--lines={INCIDENT_MAX_JOURNAL_RECORDS + 1}",
        ]
        if cursor:
            command.append(f"--after-cursor={cursor}")
        elif since_usec:
            command.append(f"--since={journal_time_arg(since_usec)}")
        output = run_bounded_command(runner, command, max_chars=INCIDENT_MAX_JOURNAL_RAW_CHARS, timeout=30)
        if output.returncode != 0 and cursor and not cursor_fallback_used:
            cursor = ""
            cursor_fallback_used = True
            continue
        if output.returncode != 0:
            detail = sanitize_error(output.stderr or output.stdout)
            return [], [f"journalctl maintenance collection failed: {detail}"], output.truncated, progress
        records = deduplicate_journal_records(parse_json_records(output.stdout))
        records.sort(key=journal_record_usec)
        overflow = output.truncated or len(records) > INCIDENT_MAX_JOURNAL_RECORDS
        if not overflow:
            break
        if candidate_end - since_usec <= 1_000_000:
            break
        candidate_end = since_usec + max(1, (candidate_end - since_usec) // 2)
    if len(records) > INCIDENT_MAX_JOURNAL_RECORDS:
        records = records[:INCIDENT_MAX_JOURNAL_RECORDS]
    backlog = bool(overflow or candidate_end < requested_end_usec)
    last_cursor = str(records[-1].get("__CURSOR") or "") if records else cursor
    progress.update({
        "journal_cursor": last_cursor,
        "journal_since_usec": candidate_end,
        "journal_processed_end_usec": candidate_end,
        "journal_backlog": backlog,
        "journal_cursor_recovered": cursor_fallback_used,
    })
    return records, [], backlog, progress


def deduplicate_journal_records(records: Sequence[Mapping[str, object]]) -> List[Dict[str, object]]:
    result: List[Dict[str, object]] = []
    seen = set()
    for record in records:
        key = (
            str(record.get("__CURSOR") or ""),
            str(record.get("__REALTIME_TIMESTAMP") or ""),
            str(record.get("MESSAGE") or "")[:500],
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(dict(record))
    return result


def journal_time_arg(usec: int) -> str:
    seconds, micros = divmod(max(0, int(usec)), 1_000_000)
    return f"@{seconds}.{micros:06d}"


def journal_record_usec(record: Mapping[str, object]) -> int:
    return safe_int(record.get("__REALTIME_TIMESTAMP") or record.get("_SOURCE_REALTIME_TIMESTAMP"))


def analyze_journal_records(
    records: Sequence[Mapping[str, object]],
    *,
    target_boot: str,
) -> Tuple[List[IncidentEvidence], List[IncidentFinding]]:
    evidence: List[IncidentEvidence] = []
    findings: List[IncidentFinding] = []
    messages = [str(record.get("MESSAGE") or "") for record in records]
    for rule in INCIDENT_RULES:
        matched_ids = []
        samples = []
        for record in records:
            message = str(record.get("MESSAGE") or "")
            if not message or not rule.pattern.search(message):
                continue
            item = evidence_from_journal(record, rule.severity, source="journal")
            evidence.append(item)
            matched_ids.append(item.evidence_id)
            samples.append(redact_incident_text(message)[:500])
            if len(matched_ids) >= 12:
                break
        if matched_ids:
            sample = samples[0] if samples else "matched system log evidence"
            findings.append(IncidentFinding(
                rule.rule_id,
                rule.severity,
                rule.confidence,
                rule.title,
                sample,
                rule.why,
                rule.action,
                rule.category,
                matched_ids,
            ))

    normalized_target = target_boot.replace("-", "").lower()
    active_boot = current_boot_id()
    is_previous = (
        (target_boot.startswith("-") and target_boot != "0")
        or (len(normalized_target) == 32 and bool(active_boot) and normalized_target != active_boot)
    )
    if is_previous and records and not any(any(marker in message.lower() for marker in CLEAN_SHUTDOWN_MARKERS) for message in messages):
        tail = records[-1]
        item = evidence_from_journal(tail, Severity.MEDIUM, source="journal-tail")
        evidence.append(item)
        findings.append(IncidentFinding(
            "INC-BOOT-UNCLEAN",
            Severity.MEDIUM,
            Confidence.MEDIUM,
            "The previous boot may have ended unexpectedly",
            "AuraScan did not find an orderly shutdown marker near the end of the previous boot.",
            "This can happen after a crash, reset, power loss, or incomplete journal flush; it is evidence, not proof of a kernel failure.",
            "AuraScan correlated the final boot evidence with stronger panic, watchdog, storage, and application crash signals.",
            "unclean_shutdown",
            [item.evidence_id],
        ))
    return evidence, findings


def collect_failed_units(
    target_boot: str,
    *,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
) -> Tuple[List[IncidentEvidence], List[IncidentFinding]]:
    if target_boot not in {"0", "+0"} or not which("systemctl"):
        return [], []
    evidence = []
    findings = []
    commands = [
        ("systemctl", ["systemctl", "--failed", "--no-legend", "--plain"], "System"),
        ("systemctl-user", ["systemctl", "--user", "--failed", "--no-legend", "--plain"], "User"),
    ]
    for source, command, scope in commands:
        output = run_bounded_command(runner, command, max_chars=32768, timeout=15)
        if output.returncode not in {0, 1}:
            continue
        for raw in output.stdout.splitlines()[:50]:
            parts = raw.strip().split()
            if not parts:
                continue
            unit = parts[0].lstrip("●")
            if not unit.endswith((".service", ".mount", ".socket", ".timer")):
                continue
            item = IncidentEvidence(
                evidence_id=evidence_id(f"{source}-failed", unit),
                source=source,
                message=redact_incident_text(raw)[:1000],
                unit=unit,
                severity=Severity.MEDIUM,
            )
            evidence.append(item)
            findings.append(IncidentFinding(
                "INC-SYSTEMD-FAILED",
                Severity.MEDIUM,
                Confidence.CONFIRMED,
                f"{scope} unit {unit} is failed",
                f"systemd currently reports {unit} in a failed state.",
                "A failed service can remove functionality or be a symptom of a larger package, configuration, or resource problem.",
                "AuraScan can restart a noncritical service only after checking its current state and denylist.",
                "failed_service",
                [item.evidence_id],
            ))
    return evidence, findings


def collect_coredumps(
    target_boot: str,
    *,
    boot_id: str,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
    include_all_users: bool = False,
    since_usec: int = 0,
    until_usec: int = 0,
    seen_record_ids: Sequence[str] = (),
    query_limit: int = INCIDENT_MAX_COREDUMPS,
    checkpoint_out: Optional[Dict[str, object]] = None,
) -> Tuple[List[CoredumpGroup], List[IncidentEvidence], List[IncidentFinding], List[str], bool]:
    if not which("coredumpctl"):
        return [], [], [], ["coredumpctl is not available; application crash metadata was not collected."], False
    bounded_limit = min(max(1, query_limit), INCIDENT_MAX_COREDUMPS + 1)
    command = ["coredumpctl", "--json=short", "--no-pager", "--reverse", "-n", str(bounded_limit)]
    if since_usec:
        command.append(f"--since={journal_time_arg(since_usec)}")
    if until_usec:
        command.append(f"--until={journal_time_arg(until_usec)}")
    command.append("list")
    if boot_id:
        command.append(f"_BOOT_ID={boot_id.replace('-', '')}")
    output = run_bounded_command(runner, command, max_chars=INCIDENT_MAX_LOCAL_EVIDENCE_CHARS, timeout=30)
    if output.returncode not in {0, 1}:
        return [], [], [], [f"coredumpctl collection failed: {sanitize_error(output.stderr or output.stdout)}"], output.truncated
    records = parse_json_records(output.stdout)
    details: List[Dict[str, object]] = []
    detail_truncated = False
    if which("journalctl"):
        detail_command = [
            "journalctl",
            f"--boot={target_boot}",
            "--output=json",
            "--no-pager",
            "--reverse",
            f"--lines={bounded_limit}",
            "--output-fields=COREDUMP_EXE,COREDUMP_UID,COREDUMP_SIGNAL_NAME,COREDUMP_PACKAGE_NAME,COREDUMP_STACKTRACE,MESSAGE,_BOOT_ID,__REALTIME_TIMESTAMP",
            "MESSAGE_ID=fc2e22bc6ee647b6b90729ab34a250b1",
        ]
        if since_usec:
            detail_command.insert(-2, f"--since={journal_time_arg(since_usec)}")
        if until_usec:
            detail_command.insert(-2, f"--until={journal_time_arg(until_usec)}")
        detail_output = run_bounded_command(runner, detail_command, max_chars=INCIDENT_MAX_LOCAL_EVIDENCE_CHARS, timeout=30)
        if detail_output.returncode == 0:
            details = parse_json_records(detail_output.stdout)
            detail_truncated = detail_output.truncated or len(details) >= bounded_limit
    if details:
        detail_map = {coredump_record_key(item): item for item in details}
        if records:
            records = [
                dict(item, **detail_map.get(coredump_record_key(item), {}))
                for item in records
                if boot_id or coredump_record_key(item) in detail_map
            ]
        else:
            records = details
    elif not boot_id:
        return [], [], [], ["Coredump metadata could not be bound to the selected boot."], output.truncated
    seen_ids = set(seen_record_ids)
    records = [
        item for item in records
        if (not since_usec or coredump_record_usec(item) >= since_usec)
        and (not until_usec or coredump_record_usec(item) <= until_usec)
        and coredump_record_identity(item) not in seen_ids
    ]
    records.sort(key=coredump_record_usec)
    truncated = output.truncated or detail_truncated or len(records) >= bounded_limit
    current_uid = current_user_uid()
    groups: Dict[str, CoredumpGroup] = {}
    evidence: List[IncidentEvidence] = []
    processed_records = records[:INCIDENT_MAX_COREDUMPS]
    for record in processed_records:
        record_boot = field_text(record, "BOOT_ID", "_BOOT_ID", "COREDUMP_BOOT_ID", "boot_id") or boot_id
        if boot_id and record_boot and record_boot.replace("-", "") != boot_id.replace("-", ""):
            continue
        uid = field_int(record, "UID", "COREDUMP_UID", "_UID", "uid")
        if not include_all_users and uid is not None and uid != current_uid and uid >= 1000:
            continue
        executable = field_text(record, "EXE", "COREDUMP_EXE", "COREDUMP_COMM", "COMM", "exe")
        executable = Path(executable).name if executable else "unknown"
        package = field_text(record, "COREDUMP_PACKAGE_NAME", "PACKAGE_NAME", "package")
        signal_name = field_text(record, "SIGNAL", "COREDUMP_SIGNAL_NAME", "COREDUMP_SIGNAL", "sig")
        top_frame = field_text(record, "COREDUMP_STACKTRACE", "STACK_TRACE", "COREDUMP_BACKTRACE", "MESSAGE")
        top_frame = first_safe_stack_frame(top_frame)
        timestamp = field_text(record, "TIME", "COREDUMP_TIMESTAMP", "__REALTIME_TIMESTAMP", "time")
        signature_material = "|".join([str(uid), executable, package, signal_name, top_frame])
        signature = hashlib.sha256(signature_material.encode("utf-8", "replace")).hexdigest()[:16]
        item_id = evidence_id("coredump", f"{signature}:{timestamp}:{uid}")
        message = f"{executable} terminated with signal {signal_name or 'unknown'}"
        item = IncidentEvidence(
            evidence_id=item_id,
            source="coredumpctl",
            message=redact_incident_text(message),
            timestamp=timestamp,
            boot_id=record_boot,
            executable=executable,
            package=package,
            uid=uid,
            severity=Severity.LOW,
        )
        evidence.append(item)
        group = groups.get(signature)
        if group is None:
            group = CoredumpGroup(
                signature=signature,
                executable=executable,
                package=package,
                signal=signal_name,
                top_frame=top_frame,
                uid=uid,
                desktop_component=executable in DESKTOP_COMPONENTS,
            )
            groups[signature] = group
        else:
            group.count += 1
        if timestamp:
            group.timestamps.append(timestamp)
        group.evidence_ids.append(item_id)
    ordered = sorted(groups.values(), key=lambda group: (-group.count, not group.desktop_component, group.executable))
    findings = []
    for group in ordered:
        severity = Severity.MEDIUM if group.desktop_component or group.count >= 3 else Severity.LOW
        confidence = Confidence.CONFIRMED
        scope = "desktop/session component" if group.desktop_component else "application"
        findings.append(IncidentFinding(
            "INC-APPLICATION-COREDUMP",
            severity,
            confidence,
            f"{group.executable} crashed",
            f"AuraScan found {group.count} coredump record(s) for this {scope}, signal {group.signal or 'unknown'}.",
            "Repeated crashes or desktop-component failures may explain visible instability; a one-off application crash does not imply the OS is damaged.",
            "AuraScan will verify package ownership and integrity before offering an exact cached-package reinstall.",
            "application_crash",
            list(group.evidence_ids),
        ))
    if checkpoint_out is not None:
        checkpoint_out["record_ids"] = [coredump_record_identity(item) for item in processed_records][-200:]
        checkpoint_out["last_record_usec"] = max((coredump_record_usec(item) for item in processed_records), default=since_usec)
    return ordered, evidence, findings, [], truncated


def collect_maintenance_coredumps(
    target_boot: str,
    *,
    boot_id: str,
    since_usec: int,
    requested_end_usec: int,
    seen_record_ids: Sequence[str],
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
    include_all_users: bool = True,
) -> Tuple[List[CoredumpGroup], List[IncidentEvidence], List[IncidentFinding], List[str], bool, Dict[str, object]]:
    requested_end_usec = requested_end_usec or int(time.time() * 1_000_000)
    since_usec = max(0, since_usec)
    if not which("coredumpctl"):
        progress = {
            "coredump_since_usec": requested_end_usec,
            "coredump_seen_ids": [],
            "coredump_processed_end_usec": requested_end_usec,
            "coredump_backlog": False,
        }
        return [], [], [], [], False, progress
    candidate_end = requested_end_usec
    result = ([], [], [], [], False)
    checkpoint: Dict[str, object] = {}
    for _attempt in range(12):
        checkpoint = {}
        result = collect_coredumps(
            target_boot,
            boot_id=boot_id,
            runner=runner,
            which=which,
            include_all_users=include_all_users,
            since_usec=since_usec,
            until_usec=candidate_end,
            seen_record_ids=seen_record_ids,
            query_limit=INCIDENT_MAX_COREDUMPS + 1,
            checkpoint_out=checkpoint,
        )
        if result[3] or not result[4]:
            break
        if candidate_end - since_usec <= 1_000_000:
            break
        candidate_end = since_usec + max(1, (candidate_end - since_usec) // 2)
    groups, evidence, findings, errors, truncated = result
    backlog = bool(truncated or candidate_end < requested_end_usec)
    progress = {
        "coredump_since_usec": candidate_end,
        "coredump_seen_ids": list(checkpoint.get("record_ids", []))[-200:],
        "coredump_processed_end_usec": candidate_end,
        "coredump_backlog": backlog,
    }
    return groups, evidence, findings, errors, backlog, progress


def collect_pstore_evidence(root: Path = Path("/sys/fs/pstore")) -> Tuple[List[IncidentEvidence], List[IncidentFinding], List[str]]:
    if not root.exists():
        return [], [], []
    evidence = []
    findings = []
    errors = []
    try:
        paths = [path for path in sorted(root.iterdir()) if path.is_file()][:20]
    except OSError as exc:
        return [], [], [f"pstore could not be read: {sanitize_error(str(exc))}"]
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")[:16384]
        except OSError as exc:
            errors.append(f"pstore entry {path.name} could not be read: {sanitize_error(str(exc))}")
            continue
        if not text.strip():
            continue
        item = IncidentEvidence(
            evidence_id=evidence_id("pstore", path.name + hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()),
            source="pstore",
            message=redact_incident_text(text)[:2000],
            severity=Severity.CRITICAL if re.search(r"(?i)panic|oops|watchdog", text) else Severity.HIGH,
        )
        evidence.append(item)
        findings.append(IncidentFinding(
            "INC-PSTORE-CRASH",
            item.severity,
            Confidence.CONFIRMED,
            "Persistent firmware/kernel crash data was found",
            f"The pstore entry {path.name} contains crash evidence retained across reboot.",
            "pstore is specifically intended to preserve low-level crash data after the normal journal can no longer write.",
            "AuraScan will correlate this evidence with kernel/module checks and will not alter or delete pstore automatically.",
            "kernel_crash",
            [item.evidence_id],
        ))
    return evidence, findings, errors


def apply_ai_incident_review(
    report: IncidentReport,
    *,
    disabled: bool = False,
    facts_only: bool = False,
    phase: str = "final",
    probes: Sequence[DiagnosticProbe] = (),
    probe_results: Sequence[DiagnosticProbeResult] = (),
    urlopen: Optional[Callable] = None,
    env: Optional[Mapping[str, str]] = None,
) -> None:
    if phase not in {"triage", "final"}:
        raise ValueError("incident AI phase must be triage or final")
    if disabled:
        report.ai_review = {"enabled": False, "status": "disabled"}
        return
    config = resolve_ai_config(env)
    if config.error:
        report.ai_review = {"enabled": False, "status": "config_error", "error": config.error}
        return
    if not config.enabled or not config.api_key_present:
        report.ai_review = {"enabled": False, "status": "not_configured"}
        return
    prompt = build_incident_ai_prompt(
        report,
        facts_only=facts_only,
        phase=phase,
        probes=probes,
        probe_results=probe_results,
    )
    try:
        text = call_ai_provider(config, prompt, timeout=25, urlopen=urlopen)
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError("AI response was not a JSON object")
        visible_probes = [
            item for item in probes
            if json.dumps(item.probe_id) in prompt
        ] if phase == "triage" else []
        visible_action_ids = [
            item.action_id for item in report.eligible_actions
            if json.dumps(item.action_id) in prompt
        ]
        validated = validate_incident_ai_response(
            report,
            data,
            phase=phase,
            probes=visible_probes,
            action_ids=visible_action_ids,
        )
    except Exception as exc:
        failed_phase = {
            "enabled": True,
            "provider": config.provider,
            "status": "invalid_response",
            "error": sanitize_error(str(exc)),
        }
        existing = dict(report.ai_review) if isinstance(report.ai_review, Mapping) else {}
        existing[phase] = failed_phase
        triage = existing.get("triage", {})
        if phase == "final" and isinstance(triage, Mapping) and triage.get("status") == "ok":
            existing.update({
                "enabled": True,
                "provider": config.provider,
                "status": "triage_only",
                "summary": str(triage.get("summary") or ""),
                "likely_causes": list(triage.get("likely_causes", [])),
                "recommended_action_ids": list(triage.get("recommended_action_ids", [])),
                "requested_probe_ids": list(triage.get("requested_probe_ids", [])),
                "error": failed_phase["error"],
            })
            report.ai_review = existing
            return
        existing.update(failed_phase)
        report.ai_review = existing
        return
    phase_review = {
        "enabled": True,
        "provider": config.provider,
        "status": "ok",
        "summary": validated["summary"],
        "likely_causes": validated["likely_causes"],
        "recommended_action_ids": validated["recommended_action_ids"],
        "requested_probe_ids": validated["requested_probe_ids"],
        "evidence_mode": "facts-only" if facts_only else "redacted",
    }
    existing = dict(report.ai_review) if isinstance(report.ai_review, Mapping) else {}
    existing[phase] = dict(phase_review)
    if phase == "final":
        triage = existing.get("triage", {})
        if isinstance(triage, Mapping):
            phase_review["requested_probe_ids"] = list(triage.get("requested_probe_ids", []))
    existing.update(phase_review)
    report.ai_review = existing


def build_incident_ai_prompt(
    report: IncidentReport,
    *,
    facts_only: bool = False,
    phase: str = "final",
    probes: Sequence[DiagnosticProbe] = (),
    probe_results: Sequence[DiagnosticProbeResult] = (),
) -> str:
    phase_instructions = (
        "This is the triage pass. Select only useful probe IDs from available_probes. "
        "A probe is a bounded read-only local check; selecting it does not authorize a repair.\n"
        "Return strict JSON only with this shape:\n"
        "{\"summary\":\"plain-language summary\",\"likely_causes\":[{\"title\":\"cause\",\"confidence\":\"low|medium|high\",\"evidence_ids\":[\"known id\"],\"explanation\":\"why\"}],\"requested_probe_ids\":[\"known probe id\"],\"recommended_action_ids\":[\"known prepared action id\"]}\n\n"
        if phase == "triage"
        else
        "This is the final review pass. Rank only verified action IDs after considering normalized probe results. "
        "Do not request more probes.\n"
        "Return strict JSON only with this shape:\n"
        "{\"summary\":\"plain-language summary\",\"likely_causes\":[{\"title\":\"cause\",\"confidence\":\"low|medium|high\",\"evidence_ids\":[\"known id\"],\"explanation\":\"why\"}],\"recommended_action_ids\":[\"known prepared action id\"]}\n\n"
    )
    instructions = (
        "You are AuraScan's incident analyst for Arch-family Linux systems.\n"
        "Use only the supplied bounded, redacted data. Do not claim certainty beyond the evidence.\n"
        "You may correlate causes and rank action IDs that AuraScan already prepared and locally verified.\n"
        "Do not claim that an application depends on, or was broken by, a package merely because that package was updated in the same boot. "
        "Package-update causation requires direct supplied ownership, dependency, integrity, or timestamp evidence; otherwise describe it as unproven.\n"
        "Treat NVIDIA NV_ERR_NO_MEMORY as a driver allocation failure, not proof of whole-system RAM exhaustion, unless separate OOM-killer evidence is supplied.\n"
        "Never create commands, scripts, package names, file edits, new action IDs, or privileged instructions.\n"
        "Never suppress deterministic findings or claim a repair succeeded.\n"
    ) + phase_instructions
    findings_payload = []
    for finding in report.findings[:30]:
        findings_payload.append(redact_structure({
            "rule_id": finding.rule_id,
            "severity": finding.severity.value,
            "confidence": finding.confidence.value,
            "title": finding.title[:240],
            "summary": finding.summary[:500],
            "why_it_matters": finding.why_it_matters[:500],
            "recommended_action": finding.recommended_action[:500],
            "category": finding.category,
            "evidence_ids": finding.evidence_ids[:12],
        }))
    coredump_payload = []
    for group in report.coredumps[:30]:
        coredump_payload.append(redact_structure({
            "signature": group.signature,
            "executable": group.executable[:200],
            "package": group.package[:200],
            "signal": group.signal[:80],
            "top_frame": group.top_frame[:400],
            "count": group.count,
            "desktop_component": group.desktop_component,
            "evidence_ids": group.evidence_ids[:12],
        }))
    evidence_payload = []
    if not facts_only:
        prioritized_evidence = sorted(
            enumerate(report.evidence),
            key=lambda pair: (-SEVERITY_ORDER.index(pair[1].severity), pair[0]),
        )
        for _index, item in prioritized_evidence[:INCIDENT_MAX_AI_EVIDENCE]:
            evidence_payload.append(redact_structure({
                "evidence_id": item.evidence_id,
                "source": item.source[:100],
                "unit": item.unit[:200],
                "executable": item.executable[:200],
                "package": item.package[:200],
                "severity": item.severity.value,
                "message": redact_incident_text(item.message)[:1000],
            }))
    payload = {
        "target_boot": report.target_boot,
        "distro": redact_structure(report.distro),
        "collection": {"status": report.collection_status, "truncated": report.truncated},
        "system_facts": bounded_ai_system_facts(report.system_facts),
        "deterministic_findings": findings_payload,
        "coredump_groups": coredump_payload,
        "prepared_actions": [
            {
                "action_id": action.action_id,
                "recipe_id": action.recipe_id,
                "title": redact_incident_text(action.title)[:240],
                "risk": action.risk.value,
                "eligible": action.eligible,
                "verified": action.verified,
            }
            for action in report.repair_actions[:20]
        ],
        "available_probes": [
            {
                "probe_id": item.probe_id,
                "probe_type": item.probe_type,
                "title": redact_incident_text(item.title)[:160],
                "required": item.required,
                "evidence_ids": item.evidence_ids[:4],
            }
            for item in probes[:24]
        ] if phase == "triage" else [],
        "probe_results": [
            {
                "probe_id": item.probe_id,
                "probe_type": item.probe_type,
                "status": item.status,
                "summary": redact_incident_text(item.summary)[:500],
                "evidence_ids": item.evidence_ids[:12],
                "action_ids": item.action_ids[:12],
            }
            for item in probe_results[:12]
        ] if phase == "final" else [],
        "evidence": evidence_payload,
        "input_truncated": bool(
            len(report.findings) > len(findings_payload)
            or len(report.coredumps) > len(coredump_payload)
            or (not facts_only and len(report.evidence) > len(evidence_payload))
        ),
    }
    prompt = instructions + json.dumps(payload, sort_keys=True)
    while len(prompt) > INCIDENT_MAX_AI_CHARS:
        payload["input_truncated"] = True
        if payload["evidence"]:
            payload["evidence"].pop()
        elif payload["coredump_groups"]:
            payload["coredump_groups"].pop()
        elif len(payload["deterministic_findings"]) > 1:
            payload["deterministic_findings"].pop()
        elif payload["prepared_actions"]:
            payload["prepared_actions"].pop()
        elif payload["system_facts"]:
            payload["system_facts"] = {}
        elif payload["available_probes"]:
            payload["available_probes"].pop()
        elif payload["probe_results"]:
            payload["probe_results"].pop()
        else:
            break
        prompt = instructions + json.dumps(payload, sort_keys=True)
        if len(prompt) <= INCIDENT_MAX_AI_CHARS or not any((
            payload["evidence"],
            payload["coredump_groups"],
            len(payload["deterministic_findings"]) > 1,
            payload["prepared_actions"],
            payload["available_probes"],
            payload["probe_results"],
            payload["system_facts"],
        )):
            break
    return prompt


def bounded_ai_system_facts(facts: Mapping[str, object]) -> Dict[str, object]:
    repository = facts.get("repository_health", {}) if isinstance(facts, Mapping) else {}
    kernel = facts.get("kernel_module", {}) if isinstance(facts, Mapping) else {}
    result = {
        "tools": facts.get("tools", {}) if isinstance(facts, Mapping) else {},
        "storage": facts.get("storage", {}) if isinstance(facts, Mapping) else {},
        "repository_health": {
            "status": repository.get("status"),
            "summary": repository.get("summary"),
            "enabled_repositories": list(repository.get("enabled_repositories", []))[:20],
        } if isinstance(repository, Mapping) else {},
        "kernel_module": {
            "status": kernel.get("status"),
            "summary": kernel.get("summary"),
            "running_kernel": kernel.get("running_kernel"),
            "running_kernel_package": kernel.get("running_kernel_package"),
            "installed_kernel_packages": list(kernel.get("installed_kernel_packages", []))[:12],
            "installed_module_families": list(kernel.get("installed_module_families", []))[:12],
            "headers_status": list(kernel.get("headers_status", []))[:12],
            "dkms_status": kernel.get("dkms_status", {}),
        } if isinstance(kernel, Mapping) else {},
    }
    return redact_structure(result)


def validate_incident_ai_response(
    report: IncidentReport,
    data: Mapping[str, object],
    *,
    phase: str = "final",
    probes: Sequence[DiagnosticProbe] = (),
    action_ids: Optional[Sequence[str]] = None,
) -> Dict[str, object]:
    if not isinstance(data.get("summary"), str):
        raise ValueError("AI incident response summary must be a string")
    if not isinstance(data.get("likely_causes"), list):
        raise ValueError("AI incident response likely_causes must be a list")
    if not isinstance(data.get("recommended_action_ids"), list):
        raise ValueError("AI incident response recommended_action_ids must be a list")
    if phase == "triage" and not isinstance(data.get("requested_probe_ids"), list):
        raise ValueError("AI incident triage response requested_probe_ids must be a list")
    valid_evidence = {item.evidence_id for item in report.evidence}
    valid_actions = {item.action_id for item in report.repair_actions if item.eligible and item.verified}
    if action_ids is not None:
        valid_actions &= {str(item) for item in action_ids}
    summary = redact_incident_text(bounded_text(data.get("summary"), 1000))
    causes = []
    raw_causes = data.get("likely_causes", [])
    if isinstance(raw_causes, list):
        for item in raw_causes[:10]:
            if not isinstance(item, Mapping):
                continue
            confidence = str(item.get("confidence") or "").strip().lower()
            if confidence not in {"low", "medium", "high"}:
                continue
            evidence_ids = [str(value) for value in item.get("evidence_ids", []) if str(value) in valid_evidence]
            if not evidence_ids:
                continue
            causes.append({
                "title": redact_incident_text(bounded_text(item.get("title"), 300)),
                "confidence": confidence,
                "evidence_ids": evidence_ids[:12],
                "explanation": redact_incident_text(bounded_text(item.get("explanation"), 1000)),
            })
    action_ids = []
    raw_actions = data.get("recommended_action_ids", [])
    if isinstance(raw_actions, list):
        for item in raw_actions:
            value = str(item)
            if value in valid_actions and value not in action_ids:
                action_ids.append(value)
    valid_probes = {item.probe_id for item in probes}
    probe_ids = []
    raw_probes = data.get("requested_probe_ids", [])
    if isinstance(raw_probes, list):
        for item in raw_probes:
            value = str(item)
            if value in valid_probes and value not in probe_ids:
                probe_ids.append(value)
            if len(probe_ids) >= 6:
                break
    return {
        "summary": summary,
        "likely_causes": causes,
        "recommended_action_ids": action_ids,
        "requested_probe_ids": probe_ids,
    }


def redact_incident_text(text: str) -> str:
    value = str(text or "")
    value = PRIVATE_KEY_RE.sub("<redacted-private-key>", value)
    value = URL_USERINFO_RE.sub(r"\1<redacted-user>:<redacted-password>@", value)
    value = AUTHORIZATION_TOKEN_RE.sub(r"\1<redacted>", value)
    value = SECRET_ASSIGNMENT_RE.sub(r"\1<redacted>", value)
    value = COMMAND_FIELD_RE.sub(r"\1<command-omitted>", value)
    value = HOME_PATH_RE.sub(lambda match: "/home/" + correlation_token("user", match.group(1)), value)
    value = MAC_RE.sub(lambda match: correlation_token("mac", match.group(0).lower()), value)
    value = IPV4_RE.sub(lambda match: correlation_token("ip", match.group(0)), value)
    value = IPV6_RE.sub(lambda match: correlation_token("ip", match.group(0).lower()), value)
    hostname = socket.gethostname().strip()
    if hostname:
        value = re.sub(rf"(?<![\w.-]){re.escape(hostname)}(?![\w.-])", correlation_token("host", hostname), value, flags=re.IGNORECASE)
    usernames = {os.environ.get("USER", "").strip(), os.environ.get("SUDO_USER", "").strip()}
    for username in sorted((item for item in usernames if len(item) >= 2), key=len, reverse=True):
        value = re.sub(rf"(?<![\w.-]){re.escape(username)}(?![\w.-])", correlation_token("user", username), value)
    return value


def correlation_token(kind: str, value: str) -> str:
    digest = hashlib.sha256(str(value).encode("utf-8", "replace")).hexdigest()[:8]
    return f"<{kind}:{digest}>"


def persist_incident_report(report: IncidentReport, root: Path) -> Path:
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    try:
        os.chmod(root, 0o700)
    except OSError:
        pass
    path = root / f"{report.incident_id}.json"
    atomic_write_json(path, report.to_dict(), mode=0o600)
    prune_incident_reports(root)
    return path


def persist_system_incident_report(report: IncidentReport, *, root: Path) -> Path:
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    try:
        os.chmod(root, 0o700)
    except OSError:
        pass
    path = root / f"{report.incident_id}.json"
    atomic_write_json(path, report.to_dict(), mode=0o600)
    prune_incident_reports(root)
    return path


def load_incident_report(incident_id: str, root: Path) -> Optional[IncidentReport]:
    if not SAFE_INCIDENT_ID_RE.fullmatch(incident_id):
        return None
    path = root / f"{incident_id}.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or data.get("report_type") != INCIDENT_REPORT_TYPE:
        return None
    return IncidentReport.from_dict(data)


def list_incident_reports(root: Path) -> List[Dict[str, object]]:
    items = []
    try:
        paths = sorted(root.glob("*.json"), key=lambda path: path.stat().st_mtime, reverse=True)
    except OSError:
        return []
    for path in paths[:INCIDENT_MAX_REPORTS]:
        report = load_incident_report(path.stem, root)
        if report is None:
            continue
        items.append({
            "incident_id": report.incident_id,
            "created_at": report.created_at,
            "boot_id": report.boot_id,
            "target_boot": report.target_boot,
            "severity": report.highest_severity.value,
            "findings": len(report.findings),
            "coredump_count": sum(group.count for group in report.coredumps),
            "repair_results": len(report.repair_results),
        })
    return items


def prune_incident_reports(root: Path, *, now: Optional[float] = None) -> None:
    now = time.time() if now is None else now
    cutoff = now - INCIDENT_RETENTION_DAYS * 86400
    try:
        paths = sorted(root.glob("*.json"), key=lambda path: path.stat().st_mtime, reverse=True)
    except OSError:
        return
    for index, path in enumerate(paths):
        try:
            stale = path.stat().st_mtime < cutoff
        except OSError:
            continue
        if index >= INCIDENT_MAX_REPORTS or stale:
            try:
                path.unlink()
            except OSError:
                pass


def maintenance_paths(system_root: Path = INCIDENT_SYSTEM_ROOT) -> Tuple[Path, Path]:
    root = system_root / "maintenance"
    return root / "state.json", root / "status.json"


def load_maintenance_checkpoint(path: Path = INCIDENT_MAINTENANCE_STATE) -> MaintenanceCheckpoint:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return MaintenanceCheckpoint()
    return MaintenanceCheckpoint.from_dict(data) if isinstance(data, Mapping) else MaintenanceCheckpoint()


def load_maintenance_status(
    path: Path = INCIDENT_MAINTENANCE_STATUS,
    *,
    now_usec: Optional[int] = None,
) -> Dict[str, object]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    now_usec = int(time.time() * 1_000_000) if now_usec is None else now_usec
    last_success = safe_int(data.get("last_success_usec"))
    collection_status = str(data.get("collection_status") or "never")
    overdue = bool(
        collection_status in {"partial", "unavailable", "failed"}
        or (last_success and now_usec - last_success > INCIDENT_MAINTENANCE_DUE_SECONDS * 1_000_000)
    )
    result = dict(data)
    result.setdefault("schema", "incident_maintenance_status/1.0")
    result.setdefault("last_attempt_usec", 0)
    result.setdefault("last_success_usec", 0)
    result.setdefault("next_due_usec", 0)
    result.setdefault("collection_status", collection_status)
    result["overdue"] = overdue
    return result


def capture_incident_maintenance(
    *,
    system_root: Path = INCIDENT_SYSTEM_ROOT,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
    stdout=None,
    stderr=None,
    now_usec: Optional[int] = None,
) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    attempted_usec = int(time.time() * 1_000_000) if now_usec is None else int(now_usec)
    state_path, status_path = maintenance_paths(system_root)
    checkpoint = load_maintenance_checkpoint(state_path)
    boot_id = current_boot_id()
    if not boot_id:
        write_maintenance_status(
            status_path,
            last_attempt_usec=attempted_usec,
            last_success_usec=checkpoint.last_success_usec,
            collection_status="unavailable",
        )
        print("[AuraScan] Weekly maintenance could not identify the current boot.", file=stderr)
        return EXIT_INCIDENT_UNAVAILABLE
    if checkpoint.boot_id != boot_id:
        checkpoint = MaintenanceCheckpoint(boot_id=boot_id, last_success_usec=checkpoint.last_success_usec)
        baseline_start = current_boot_start_usec(now_usec=attempted_usec)
        checkpoint.journal_since_usec = baseline_start
        checkpoint.coredump_since_usec = baseline_start
        checkpoint.last_window_end_usec = baseline_start
    requested_start = min(
        value for value in (checkpoint.journal_since_usec, checkpoint.coredump_since_usec, checkpoint.last_window_end_usec)
        if value > 0
    ) if any(value > 0 for value in (checkpoint.journal_since_usec, checkpoint.coredump_since_usec, checkpoint.last_window_end_usec)) else current_boot_start_usec(now_usec=attempted_usec)
    context: Dict[str, object] = {
        "boot_id": boot_id,
        "requested_start_usec": requested_start,
        "requested_end_usec": attempted_usec,
        "journal_cursor": checkpoint.journal_cursor,
        "journal_since_usec": checkpoint.journal_since_usec or requested_start,
        "coredump_since_usec": checkpoint.coredump_since_usec or requested_start,
        "coredump_seen_ids": list(checkpoint.coredump_seen_ids),
    }
    report = build_incident_report(
        "0",
        trigger="weekly_maintenance",
        runner=runner,
        which=which,
        include_all_users=True,
        maintenance_context=context,
    )
    persist_system_incident_report(report, root=system_root / "reports")
    if maintenance_report_needs_attention(report):
        write_pending_markers(report, root=system_root / "pending")
    if report.collection_status != "unavailable":
        checkpoint.boot_id = boot_id
        checkpoint.journal_cursor = str(context.get("journal_cursor") or checkpoint.journal_cursor)
        checkpoint.journal_since_usec = safe_int(context.get("journal_since_usec"), checkpoint.journal_since_usec)
        checkpoint.coredump_since_usec = safe_int(context.get("coredump_since_usec"), checkpoint.coredump_since_usec)
        checkpoint.coredump_seen_ids = [str(item) for item in context.get("coredump_seen_ids", [])][-200:] if isinstance(context.get("coredump_seen_ids"), list) else []
        checkpoint.last_window_end_usec = min(
            safe_int(context.get("journal_processed_end_usec"), attempted_usec),
            safe_int(context.get("coredump_processed_end_usec"), attempted_usec),
        )
        if report.collection_status == "complete":
            checkpoint.last_success_usec = attempted_usec
        ensure_maintenance_root(state_path.parent)
        atomic_write_json(state_path, checkpoint.to_dict(), mode=0o600)
    write_maintenance_status(
        status_path,
        last_attempt_usec=attempted_usec,
        last_success_usec=checkpoint.last_success_usec,
        collection_status=report.collection_status,
    )
    if report.collection_status == "unavailable":
        print("[AuraScan] Weekly incident maintenance was unavailable.", file=stderr)
        return EXIT_INCIDENT_UNAVAILABLE
    if report.findings or report.coredumps:
        print(f"[AuraScan] Weekly maintenance recorded {len(report.findings)} finding(s).", file=stdout)
    return 0


def write_maintenance_status(
    path: Path,
    *,
    last_attempt_usec: int,
    last_success_usec: int,
    collection_status: str,
) -> None:
    ensure_maintenance_root(path.parent)
    payload = {
        "schema": "incident_maintenance_status/1.0",
        "last_attempt_usec": int(last_attempt_usec),
        "last_success_usec": int(last_success_usec),
        "next_due_usec": int(last_success_usec + INCIDENT_MAINTENANCE_DUE_SECONDS * 1_000_000) if last_success_usec else 0,
        "collection_status": str(collection_status),
    }
    atomic_write_json(path, payload, mode=0o644)


def ensure_maintenance_root(path: Path) -> None:
    path.mkdir(parents=True, mode=0o755, exist_ok=True)
    try:
        os.chmod(path, 0o755)
    except OSError:
        pass


def maintenance_report_needs_attention(report: IncidentReport) -> bool:
    return any(
        SEVERITY_ORDER.index(finding.severity) >= SEVERITY_ORDER.index(Severity.MEDIUM)
        for finding in report.findings
    )


def current_boot_start_usec(*, now_usec: Optional[int] = None, uptime_path: Path = Path("/proc/uptime")) -> int:
    now_usec = int(time.time() * 1_000_000) if now_usec is None else int(now_usec)
    try:
        uptime_seconds = float(uptime_path.read_text(encoding="utf-8").split()[0])
    except (OSError, ValueError, IndexError):
        return max(0, now_usec - INCIDENT_MAINTENANCE_DUE_SECONDS * 1_000_000)
    return max(0, now_usec - int(uptime_seconds * 1_000_000))


def print_maintenance_status(
    *,
    system_root: Path = INCIDENT_SYSTEM_ROOT,
    runner: Callable = subprocess.run,
    stdout=None,
    json_output: bool = False,
) -> int:
    stdout = stdout or sys.stdout
    _state_path, status_path = maintenance_paths(system_root)
    status = load_maintenance_status(status_path)
    systemd = incident_monitor_status(runner=runner)
    if json_output:
        print(json.dumps({
            "report_type": "incident_maintenance_status",
            "status": status,
            "systemd": systemd,
        }, indent=2), file=stdout)
        return 0 if systemd.get("maintenance_installed") else 1
    print("AuraScan weekly incident maintenance", file=stdout)
    print(f"Installed: {'yes' if systemd.get('maintenance_installed') else 'no'}", file=stdout)
    print(f"Timer enabled: {systemd.get('maintenance_enabled', 'unknown')}", file=stdout)
    print(f"Timer active: {systemd.get('maintenance_active', 'unknown')}", file=stdout)
    print(f"Last result: {status.get('collection_status', 'never')}", file=stdout)
    print(f"Last successful scan: {format_usec_time(safe_int(status.get('last_success_usec')))}", file=stdout)
    print(f"Next due: {format_usec_time(safe_int(status.get('next_due_usec')))}", file=stdout)
    if systemd.get("maintenance_next_run"):
        print(f"Systemd next run: {systemd['maintenance_next_run']}", file=stdout)
    print(f"Maintenance due: {'yes' if status.get('overdue') else 'no'}", file=stdout)
    return 0 if systemd.get("maintenance_installed") else 1


def run_maintenance_now(
    *,
    system_root: Path = INCIDENT_SYSTEM_ROOT,
    runner: Callable = subprocess.run,
    stdout=None,
    stderr=None,
    json_output: bool = False,
) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    try:
        result = runner(["sudo", "systemctl", "start", INCIDENT_MAINTENANCE_SERVICE], check=False)
    except OSError as exc:
        print(f"[AuraScan] Could not start weekly maintenance: {exc}", file=stderr)
        return EXIT_INCIDENT_CONFIG_ERROR
    if int(getattr(result, "returncode", 0)) != 0:
        print(f"[AuraScan] Weekly maintenance failed to start (exit {result.returncode}).", file=stderr)
        return EXIT_INCIDENT_UNAVAILABLE
    return print_maintenance_status(system_root=system_root, runner=runner, stdout=stdout, json_output=json_output)


def format_usec_time(value: int) -> str:
    if value <= 0:
        return "never"
    try:
        return datetime.fromtimestamp(value / 1_000_000).astimezone().isoformat(timespec="seconds")
    except (OSError, OverflowError, ValueError):
        return "unknown"


def write_pending_markers(report: IncidentReport, *, root: Path) -> List[Path]:
    root.mkdir(parents=True, mode=0o755, exist_ok=True)
    try:
        os.chmod(root, 0o755)
    except OSError:
        pass
    boot_id = re.sub(r"[^a-zA-Z0-9]", "", report.boot_id)[:64]
    if not boot_id:
        return []
    markers = []
    marker_type = "maintenance" if report.trigger == "weekly_maintenance" else "boot_incident"
    scan_id = re.sub(r"[^a-zA-Z0-9_.-]", "", report.incident_id)[:120] if marker_type == "maintenance" else ""
    scope_counts: Dict[str, int] = {"global": len([item for item in report.findings if item.category != "application_crash"])}
    scope_categories: Dict[str, set] = {
        "global": {finding.category for finding in report.findings if finding.category != "application_crash"}
    }
    scope_severities: Dict[str, List[Severity]] = {
        "global": [finding.severity for finding in report.findings if finding.category != "application_crash"]
    }
    scope_category_severities: Dict[str, Dict[str, Severity]] = {"global": {}}
    for finding in report.findings:
        if finding.category == "application_crash":
            continue
        current = scope_category_severities["global"].get(finding.category)
        if current is None or SEVERITY_ORDER.index(finding.severity) > SEVERITY_ORDER.index(current):
            scope_category_severities["global"][finding.category] = finding.severity
    scope_repeated: Dict[str, bool] = {"global": False}
    for group in report.coredumps:
        scope = str(group.uid) if group.uid is not None and group.uid >= 1000 else "global"
        scope_counts[scope] = scope_counts.get(scope, 0) + group.count
        scope_categories.setdefault(scope, set()).add("application_crash")
        group_severity = Severity.MEDIUM if group.desktop_component or group.count >= 3 else Severity.LOW
        scope_severities.setdefault(scope, []).append(group_severity)
        current = scope_category_severities.setdefault(scope, {}).get("application_crash")
        if current is None or SEVERITY_ORDER.index(group_severity) > SEVERITY_ORDER.index(current):
            scope_category_severities[scope]["application_crash"] = group_severity
        scope_repeated[scope] = scope_repeated.get(scope, False) or group.count >= 3
    for scope, count in scope_counts.items():
        if count <= 0:
            continue
        severities = scope_severities.get(scope) or [Severity.LOW]
        severity = max(severities, key=SEVERITY_ORDER.index)
        if marker_type == "maintenance" and SEVERITY_ORDER.index(severity) < SEVERITY_ORDER.index(Severity.MEDIUM):
            continue
        marker = {
            "schema": "incident_marker/2.0",
            "marker_type": marker_type,
            "scan_id": scan_id,
            "boot_id": boot_id,
            "uid_scope": scope,
            "severity": severity.value,
            "categories": sorted(scope_categories.get(scope, set())),
            "category_severities": {
                category: category_severity.value
                for category, category_severity in sorted(scope_category_severities.get(scope, {}).items())
            },
            "resolved_categories": [],
            "auto_repair_state": "not_run",
            "count": count,
            "repeated": bool(scope_repeated.get(scope, False)),
        }
        key = marker_key(marker)
        prior: Dict[str, object] = {}
        for existing in root.glob("*.json"):
            try:
                existing_data = json.loads(existing.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(existing_data, Mapping) and marker_key(existing_data) == key:
                prior = dict(existing_data)
                try:
                    existing.unlink()
                except OSError:
                    pass
        prior_resolved = prior.get("resolved_categories", [])
        if isinstance(prior_resolved, list):
            marker["resolved_categories"] = sorted(
                category for category in {str(item) for item in prior_resolved}
                if category in marker["categories"]
            )
        prior_state = str(prior.get("auto_repair_state") or "")
        if prior_state in {"applied", "failed", "refused", "no_action"}:
            marker["auto_repair_state"] = prior_state
        file_key = scan_id if scan_id else boot_id
        path = root / f"{file_key}-{scope}.json"
        atomic_write_json(path, marker, mode=0o644)
        markers.append(path)
    return markers


def update_pending_marker_repair_state(
    report: IncidentReport,
    *,
    categories: Sequence[str],
    state: str,
    root: Path = INCIDENT_MONITOR_MARKER_ROOT,
) -> int:
    if state not in {"applied", "failed", "refused", "no_action"}:
        return 0
    wanted = {str(item) for item in categories if str(item)}
    boot_id = re.sub(r"[^a-zA-Z0-9]", "", report.boot_id)
    updated = 0
    try:
        paths = list(root.glob("*.json"))
    except OSError:
        return 0
    for path in paths:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        marker_boot = re.sub(r"[^a-zA-Z0-9]", "", str(data.get("boot_id") or ""))
        if marker_boot != boot_id or str(data.get("uid_scope") or "") != "global":
            continue
        if str(data.get("marker_type") or "boot_incident") == "maintenance":
            if str(data.get("scan_id") or "") != report.incident_id:
                continue
        marker_categories = {str(item) for item in data.get("categories", [])} if isinstance(data.get("categories"), list) else set()
        affected = wanted & marker_categories
        if wanted and not affected:
            continue
        data["schema"] = "incident_marker/2.0"
        data["auto_repair_state"] = state
        if state == "applied":
            resolved = {str(item) for item in data.get("resolved_categories", [])} if isinstance(data.get("resolved_categories"), list) else set()
            data["resolved_categories"] = sorted(resolved | affected)
        atomic_write_json(path, data, mode=0o644)
        updated += 1
    return updated


def pending_markers(
    *,
    uid: Optional[int] = None,
    root: Path = INCIDENT_MONITOR_MARKER_ROOT,
    include_resolved: bool = False,
) -> List[Dict[str, object]]:
    uid = current_user_uid() if uid is None else uid
    accepted_scopes = {"global", str(uid)}
    items = []
    try:
        paths = sorted(root.glob("*.json"), key=lambda path: path.stat().st_mtime, reverse=True)
    except OSError:
        return []
    for path in paths[:100]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict) and str(data.get("uid_scope") or data.get("scope") or "") in accepted_scopes:
            active_categories = marker_active_categories(data)
            if not active_categories and not include_resolved:
                continue
            normalized = dict(data)
            normalized["active_categories"] = active_categories
            normalized["severity"] = marker_effective_severity(data)
            items.append(normalized)
    return items


def marker_active_categories(marker: Mapping[str, object]) -> List[str]:
    categories = {str(item) for item in marker.get("categories", []) if str(item)} if isinstance(marker.get("categories"), list) else set()
    resolved = {str(item) for item in marker.get("resolved_categories", []) if str(item)} if isinstance(marker.get("resolved_categories"), list) else set()
    return sorted(categories - resolved)


def marker_effective_severity(marker: Mapping[str, object]) -> str:
    active = marker_active_categories(marker)
    category_severities = marker.get("category_severities", {})
    if isinstance(category_severities, Mapping) and active:
        fallback = str(marker.get("severity") or "LOW").upper()
        values = [str(category_severities.get(category) or fallback).upper() for category in active]
        rank = {severity.value: index for index, severity in enumerate(SEVERITY_ORDER)}
        return max(values, key=lambda value: rank.get(value, 0))
    return str(marker.get("severity") or "LOW").upper()


def latest_pending_marker(*, uid: Optional[int] = None, root: Path = INCIDENT_MONITOR_MARKER_ROOT) -> Optional[Dict[str, object]]:
    markers = pending_markers(uid=uid, root=root)
    return markers[0] if markers else None


def user_incident_root(env: Optional[Mapping[str, str]] = None) -> Path:
    source = env if env is not None else os.environ
    state_home = source.get("XDG_STATE_HOME", "").strip()
    base = Path(state_home) if state_home else Path.home() / ".local" / "state"
    return base / "aurascan" / "incidents"


def incident_seen_state_path(env: Optional[Mapping[str, str]] = None) -> Path:
    return user_incident_root(env).parent / "incident_seen.json"


def incident_reviewed_state_path(
    env: Optional[Mapping[str, str]] = None,
    *,
    report_root: Optional[Path] = None,
) -> Path:
    root = report_root or user_incident_root(env)
    return root.parent / "incident_reviewed.json"


def unseen_pending_markers(
    *,
    uid: Optional[int] = None,
    marker_root: Path = INCIDENT_MONITOR_MARKER_ROOT,
    seen_path: Optional[Path] = None,
    include_resolved: bool = False,
) -> List[Dict[str, object]]:
    seen_path = seen_path or incident_seen_state_path()
    seen = set()
    try:
        data = json.loads(seen_path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            seen = {str(item) for item in data}
    except (OSError, json.JSONDecodeError):
        pass
    return [
        item for item in pending_markers(uid=uid, root=marker_root, include_resolved=include_resolved)
        if marker_key(item) not in seen
    ]


def mark_pending_markers_seen(markers: Sequence[Mapping[str, object]], *, seen_path: Optional[Path] = None) -> None:
    if not markers:
        return
    seen_path = seen_path or incident_seen_state_path()
    existing = []
    try:
        data = json.loads(seen_path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            existing = [str(item) for item in data]
    except (OSError, json.JSONDecodeError):
        pass
    merged = (existing + [marker_key(item) for item in markers])[-200:]
    seen_path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    atomic_write_json(seen_path, merged, mode=0o600)


def marker_key(marker: Mapping[str, object]) -> str:
    boot = marker.get("boot_id") or marker.get("target_boot") or marker.get("incident_id")
    scope = marker.get("uid_scope") or marker.get("scope")
    marker_type = marker.get("marker_type") or "boot_incident"
    scan_id = marker.get("scan_id") or ""
    generation = scan_id if marker_type == "maintenance" and scan_id else boot
    return f"{marker_type}:{generation}:{scope}"


def highest_priority_pending_marker(markers: Sequence[Mapping[str, object]]) -> Optional[Mapping[str, object]]:
    if not markers:
        return None
    severity_rank = {severity.value: index for index, severity in enumerate(SEVERITY_ORDER)}
    _index, marker = max(
        enumerate(markers),
        key=lambda item: (
            severity_rank.get(marker_effective_severity(item[1]), 0),
            -item[0],
        ),
    )
    return marker


def should_acknowledge_resolution(options: IncidentOptions, report: IncidentReport) -> bool:
    return bool(
        options.resolve_pending
        and not options.dry_run
        and (not options.json_output or options.yes)
        and report.collection_status != "unavailable"
    )


def acknowledge_incident_resolution(
    markers: Sequence[Mapping[str, object]],
    *,
    seen_path: Path,
    report: IncidentReport,
    stdout,
    repairs_applied: bool = False,
    quiet: bool = False,
) -> None:
    mark_pending_markers_seen(markers, seen_path=seen_path)
    if quiet:
        return
    if repairs_applied:
        print("\n[AuraScan] Repair complete", file=stdout)
        print("Verified AuraScan repairs were applied and checked again.", file=stdout)
    elif report.findings or report.coredumps:
        print("\n[AuraScan] Review complete - no automatic repair applied", file=stdout)
        print(
            "No verified automatic repair was safe or required for the remaining historical evidence. "
            "AuraScan did not run an AI-generated command.",
            file=stdout,
        )
    else:
        print("\n[AuraScan] Check complete - no repair needed", file=stdout)
        print("No recognized system problem requires a repair.", file=stdout)
    if markers:
        print(
            f"Acknowledged {len(markers)} pending alert(s). The tray icon will return to normal; "
            "new crash evidence will create a new alert.",
            file=stdout,
        )
        print(
            "The reports remain in incident history. A normal icon means the findings were handled or reviewed, "
            "not that AuraScan erased the historical crash records.",
            file=stdout,
        )
    else:
        print("The tray already has no unreviewed incident alert.", file=stdout)


def handle_incident_monitor_action(
    *,
    enable: bool,
    disable: bool,
    status: bool,
    runner: Callable,
    stdout,
    stderr,
    env_path: Path,
) -> int:
    if status:
        state = incident_monitor_status(runner=runner)
        print("AuraScan incident monitor", file=stdout)
        print(f"Installed: {'yes' if state['installed'] else 'no'}", file=stdout)
        print(f"Enabled: {state['enabled']}", file=stdout)
        print(f"Active: {state['active']}", file=stdout)
        print(f"Weekly timer installed: {'yes' if state['maintenance_installed'] else 'no'}", file=stdout)
        print(f"Weekly timer enabled: {state['maintenance_enabled']}", file=stdout)
        print(f"Weekly timer active: {state['maintenance_active']}", file=stdout)
        return 0 if state["installed"] and state["maintenance_installed"] else 1
    desired = bool(enable and not disable)
    ok, message = set_incident_monitor_enabled(desired, runner=runner)
    if not ok:
        print(f"[AuraScan] {message}", file=stderr)
        return EXIT_INCIDENT_CONFIG_ERROR
    write_user_env({INCIDENT_MONITOR_ENABLED_ENV: "1" if desired else "0"}, path=env_path)
    print(message, file=stdout)
    return 0


def set_incident_monitor_enabled(enabled: bool, *, runner: Callable = subprocess.run) -> Tuple[bool, str]:
    units = [INCIDENT_MONITOR_SERVICE, INCIDENT_MAINTENANCE_TIMER]
    command = ["sudo", "systemctl", "enable" if enabled else "disable", "--now", *units]
    try:
        result = runner(command, check=False)
    except OSError as exc:
        return False, f"Could not configure incident monitor: {exc}"
    if int(getattr(result, "returncode", 0)) != 0:
        if enabled:
            try:
                runner(["sudo", "systemctl", "disable", "--now", *units], check=False)
            except OSError:
                pass
        if not enabled:
            state = incident_monitor_status(runner=runner)
            inactive = str(state.get("active") or "") in {"inactive", "failed"}
            disabled = str(state.get("enabled") or "") in {"disabled", "masked", "not-found"}
            maintenance_inactive = str(state.get("maintenance_active") or "") in {"inactive", "failed"}
            maintenance_disabled = str(state.get("maintenance_enabled") or "") in {"disabled", "masked", "not-found"}
            if disabled and inactive and maintenance_disabled and maintenance_inactive:
                return True, "AuraScan incident monitor is already disabled."
        return False, f"Incident monitor command failed with exit code {result.returncode}."
    if enabled:
        try:
            baseline = runner(["sudo", "systemctl", "start", INCIDENT_MAINTENANCE_SERVICE], check=False)
        except OSError as exc:
            return True, f"AuraScan incident monitor and weekly timer enabled; baseline scan could not start: {exc}"
        if int(getattr(baseline, "returncode", 0)) != 0:
            return True, f"AuraScan incident monitor and weekly timer enabled; baseline scan exited with {baseline.returncode}."
        return True, "AuraScan incident monitor and weekly timer enabled; baseline scan completed."
    return True, "AuraScan incident monitor and weekly timer disabled."


def incident_monitor_status(
    *,
    runner: Callable = subprocess.run,
    service_path: Path = Path("/usr/lib/systemd/system") / INCIDENT_MONITOR_SERVICE,
    maintenance_service_path: Path = Path("/usr/lib/systemd/system") / INCIDENT_MAINTENANCE_SERVICE,
    maintenance_timer_path: Path = Path("/usr/lib/systemd/system") / INCIDENT_MAINTENANCE_TIMER,
) -> Dict[str, object]:
    installed = service_path.exists()
    enabled_result = run_bounded_command(runner, ["systemctl", "is-enabled", INCIDENT_MONITOR_SERVICE], max_chars=2000, timeout=10)
    active_result = run_bounded_command(runner, ["systemctl", "is-active", INCIDENT_MONITOR_SERVICE], max_chars=2000, timeout=10)
    maintenance_enabled = run_bounded_command(runner, ["systemctl", "is-enabled", INCIDENT_MAINTENANCE_TIMER], max_chars=2000, timeout=10)
    maintenance_active = run_bounded_command(runner, ["systemctl", "is-active", INCIDENT_MAINTENANCE_TIMER], max_chars=2000, timeout=10)
    maintenance_schedule = run_bounded_command(
        runner,
        [
            "systemctl",
            "show",
            INCIDENT_MAINTENANCE_TIMER,
            "--property=LastTriggerUSec",
            "--property=NextElapseUSecRealtime",
            "--property=Result",
        ],
        max_chars=4000,
        timeout=10,
    )
    schedule = {}
    for raw in maintenance_schedule.stdout.splitlines():
        if "=" in raw:
            key, value = raw.split("=", 1)
            schedule[key] = value
    return {
        "installed": installed,
        "enabled": enabled_result.stdout.strip() or "unknown",
        "active": active_result.stdout.strip() or "unknown",
        "maintenance_installed": maintenance_service_path.exists() and maintenance_timer_path.exists(),
        "maintenance_enabled": maintenance_enabled.stdout.strip() or "unknown",
        "maintenance_active": maintenance_active.stdout.strip() or "unknown",
        "maintenance_last_trigger": schedule.get("LastTriggerUSec", ""),
        "maintenance_next_run": schedule.get("NextElapseUSecRealtime", ""),
        "maintenance_result": schedule.get("Result", ""),
    }


def run_bounded_command(
    runner: Callable,
    command: Sequence[str],
    *,
    max_chars: int,
    timeout: int,
) -> CommandOutput:
    kwargs = {"capture_output": True, "text": True, "check": False, "timeout": timeout}
    try:
        try:
            result = runner(list(command), **kwargs)
        except TypeError:
            kwargs.pop("timeout", None)
            result = runner(list(command), **kwargs)
    except (OSError, subprocess.SubprocessError) as exc:
        return CommandOutput(127, "", str(exc), False)
    stdout = str(getattr(result, "stdout", "") or "")
    stderr = str(getattr(result, "stderr", "") or "")
    truncated = len(stdout) > max_chars or len(stderr) > max_chars
    return CommandOutput(int(getattr(result, "returncode", 0)), stdout[:max_chars], stderr[:max_chars], truncated)


def evidence_from_journal(record: Mapping[str, object], severity: Severity, *, source: str) -> IncidentEvidence:
    message = redact_incident_text(str(record.get("MESSAGE") or ""))[:2000]
    timestamp = str(record.get("__REALTIME_TIMESTAMP") or record.get("_SOURCE_REALTIME_TIMESTAMP") or "")
    boot_id = str(record.get("_BOOT_ID") or "")
    unit = str(record.get("_SYSTEMD_UNIT") or record.get("UNIT") or "")
    executable = str(record.get("_EXE") or record.get("SYSLOG_IDENTIFIER") or record.get("_COMM") or "")
    uid = field_int(record, "_UID", "UID")
    material = "|".join([source, timestamp, boot_id, unit, message])
    return IncidentEvidence(
        evidence_id=evidence_id(source, material),
        source=source,
        message=message,
        timestamp=timestamp,
        boot_id=boot_id,
        unit=unit,
        executable=Path(executable).name if executable else "",
        uid=uid,
        severity=severity,
    )


def evidence_id(source: str, material: str) -> str:
    digest = hashlib.sha256((source + "|" + material).encode("utf-8", "replace")).hexdigest()[:16]
    return f"iev-{digest}"


def first_boot_id(records: Sequence[Mapping[str, object]]) -> str:
    for record in records:
        value = str(record.get("_BOOT_ID") or "").replace("-", "")
        if value:
            return value
    return ""


def field_text(record: Mapping[str, object], *keys: str) -> str:
    for key in keys:
        value = record.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def parse_json_records(text: str) -> List[Dict[str, object]]:
    value = str(text or "").strip()
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, list):
        return [dict(item) for item in parsed if isinstance(item, Mapping)]
    if isinstance(parsed, Mapping):
        return [dict(parsed)]
    records = []
    for raw in value.splitlines():
        try:
            item = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(item, Mapping):
            records.append(dict(item))
    return records


def coredump_record_key(record: Mapping[str, object]) -> str:
    timestamp = field_text(record, "TIME", "COREDUMP_TIMESTAMP", "__REALTIME_TIMESTAMP", "time")
    uid = field_text(record, "UID", "COREDUMP_UID", "_UID", "uid")
    executable = field_text(record, "EXE", "COREDUMP_EXE", "COREDUMP_COMM", "COMM", "exe")
    return f"{timestamp}:{uid}:{Path(executable).name if executable else ''}"


def coredump_record_identity(record: Mapping[str, object]) -> str:
    material = "|".join([
        coredump_record_key(record),
        field_text(record, "SIGNAL", "COREDUMP_SIGNAL_NAME", "COREDUMP_SIGNAL", "sig"),
        field_text(record, "COREDUMP_PACKAGE_NAME", "PACKAGE_NAME", "package"),
    ])
    return hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()[:24]


def coredump_record_usec(record: Mapping[str, object]) -> int:
    raw = field_text(record, "COREDUMP_TIMESTAMP", "__REALTIME_TIMESTAMP", "TIME", "time")
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return 0
    return value if value >= 1_000_000_000_000 else value * 1_000_000


def safe_int(value: object, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def field_int(record: Mapping[str, object], *keys: str) -> Optional[int]:
    value = field_text(record, *keys)
    try:
        return int(value) if value else None
    except ValueError:
        return None


def journal_time_bounds(records: Sequence[Mapping[str, object]]) -> Optional[Tuple[float, float]]:
    values = []
    for record in records:
        raw = record.get("__REALTIME_TIMESTAMP") or record.get("_SOURCE_REALTIME_TIMESTAMP")
        try:
            values.append(int(str(raw)) / 1_000_000.0)
        except (TypeError, ValueError):
            continue
    return (min(values), max(values)) if values else None


def pacman_log_timestamp(line: str) -> Optional[float]:
    match = re.match(r"^\[([^]]+)]", str(line or ""))
    if not match:
        return None
    value = match.group(1).strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        return None


def read_file_tail(path: Path, max_bytes: int) -> str:
    with path.open("rb") as handle:
        handle.seek(0, os.SEEK_END)
        size = handle.tell()
        handle.seek(max(0, size - max_bytes), os.SEEK_SET)
        data = handle.read(max_bytes)
    if size > max_bytes and b"\n" in data:
        data = data.split(b"\n", 1)[1]
    return data.decode("utf-8", errors="replace")


def first_safe_stack_frame(text: str) -> str:
    lines = [raw.strip() for raw in str(text or "").splitlines() if raw.strip()]
    ordered = [line for line in lines if re.match(r"^#\d+\s", line)] + [line for line in lines if not re.match(r"^#\d+\s", line)]
    for line in ordered:
        line = redact_incident_text(line)
        line = re.sub(r"0x[0-9a-fA-F]+", "<address>", line)
        return line[:500]
    return ""


def deduplicate_evidence(items: Sequence[IncidentEvidence]) -> List[IncidentEvidence]:
    result = []
    seen = set()
    for item in items:
        if item.evidence_id in seen:
            continue
        seen.add(item.evidence_id)
        result.append(item)
    return result


def deduplicate_findings(items: Sequence[IncidentFinding]) -> List[IncidentFinding]:
    result: Dict[Tuple[str, ...], IncidentFinding] = {}
    for item in items:
        key = (item.rule_id, item.title)
        if item.rule_id == "INC-APPLICATION-COREDUMP":
            key = (item.rule_id, item.title, item.evidence_ids[0] if item.evidence_ids else item.summary)
        existing = result.get(key)
        if existing is None:
            result[key] = item
            continue
        for evidence_value in item.evidence_ids:
            if evidence_value not in existing.evidence_ids:
                existing.evidence_ids.append(evidence_value)
        if SEVERITY_ORDER.index(item.severity) > SEVERITY_ORDER.index(existing.severity):
            existing.severity = item.severity
        if CONFIDENCE_ORDER.index(item.confidence) > CONFIDENCE_ORDER.index(existing.confidence):
            existing.confidence = item.confidence
    return list(result.values())


def bound_evidence(items: Sequence[IncidentEvidence], max_chars: int) -> List[IncidentEvidence]:
    result = []
    used = 0
    for item in sorted(items, key=lambda value: -SEVERITY_ORDER.index(value.severity)):
        if used + len(item.message) > max_chars:
            continue
        result.append(item)
        used += len(item.message)
    return result


def valid_boot_target(value: str) -> bool:
    target = str(value or "").strip()
    if re.fullmatch(r"[+-]?\d+", target):
        return True
    return bool(re.fullmatch(r"[0-9a-fA-F]{32}", target.replace("-", "")))


def validate_privileged_request_file(path: Path) -> Tuple[bool, str]:
    try:
        if path.is_symlink() or not path.is_file():
            return False, "request is not a regular file"
        stat_result = path.stat()
    except OSError as exc:
        return False, sanitize_error(str(exc))
    if stat_result.st_mode & 0o077:
        return False, "request permissions expose it to another user"
    sudo_uid = os.environ.get("SUDO_UID", "").strip()
    allowed_owners = {0}
    if sudo_uid.isdigit():
        allowed_owners.add(int(sudo_uid))
    if stat_result.st_uid not in allowed_owners:
        return False, "request owner does not match the invoking user"
    if stat_result.st_size > 256 * 1024:
        return False, "request exceeds the bounded repair-plan size"
    return True, ""


def make_incident_id(target_boot: str) -> str:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    target = re.sub(r"[^a-zA-Z0-9]+", "", target_boot)[:12] or "boot"
    return f"incident-{stamp}-{target}-{uuid.uuid4().hex[:8]}"


def current_user_uid() -> int:
    sudo_uid = os.environ.get("SUDO_UID", "").strip()
    if sudo_uid.isdigit():
        return int(sudo_uid)
    return os.getuid() if hasattr(os, "getuid") else 0


def current_boot_id(
    path: Path = Path("/proc/sys/kernel/random/boot_id"),
    *,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
) -> str:
    try:
        boot_id = normalize_boot_id(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        boot_id = ""
    if boot_id:
        return boot_id

    # ProcSubset=pid deliberately hides /proc/sys in the hardened monitor.
    # The journal's boot index provides the same identifier without relaxing
    # the service sandbox or granting access to kernel tunables.
    journalctl = which("journalctl")
    if not journalctl:
        return ""
    try:
        result = runner(
            [journalctl, "--list-boots", "--no-pager", "--output=json"],
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    if int(getattr(result, "returncode", 0)) != 0:
        return ""
    try:
        payload = json.loads(str(getattr(result, "stdout", "") or ""))
    except json.JSONDecodeError:
        return ""
    records = payload if isinstance(payload, list) else [payload]
    for record in records:
        if isinstance(record, Mapping) and str(record.get("index")) == "0":
            return normalize_boot_id(record.get("boot_id"))
    return ""


def normalize_boot_id(value: object) -> str:
    boot_id = str(value or "").strip().replace("-", "").lower()
    return boot_id if re.fullmatch(r"[0-9a-f]{32}", boot_id) else ""


def sanitize_error(text: str) -> str:
    return redact_incident_text(str(text or "").strip().replace("\n", " "))[:500]


def bounded_text(value: object, limit: int) -> str:
    return str(value or "").strip()[:limit]


def redact_structure(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): redact_structure(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_structure(item) for item in value]
    if isinstance(value, str):
        return redact_incident_text(value)
    return value


def summarize_post_repair(before: IncidentReport, after: IncidentReport) -> Dict[str, object]:
    def finding_key(finding: IncidentFinding) -> str:
        return f"{finding.rule_id}:{finding.category}:{finding.title}"

    before_keys = {finding_key(item) for item in before.findings}
    after_keys = {finding_key(item) for item in after.findings}
    return {
        "checked_at": int(time.time()),
        "collection_status": after.collection_status,
        "truncated": after.truncated,
        "resolved_finding_keys": sorted(before_keys - after_keys),
        "remaining_finding_keys": sorted(before_keys & after_keys),
        "new_finding_keys": sorted(after_keys - before_keys),
        "remaining_high_critical": sorted(
            finding_key(item)
            for item in after.findings
            if item.severity in {Severity.HIGH, Severity.CRITICAL}
        ),
    }


def atomic_write_json(path: Path, data: object, *, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent), text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
        os.chmod(path, mode)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def _severity(value: object) -> Severity:
    if isinstance(value, Severity):
        return value
    try:
        return Severity(str(value).upper())
    except ValueError:
        return Severity.LOW


def _confidence(value: object) -> Confidence:
    if isinstance(value, Confidence):
        return value
    try:
        return Confidence(str(value).upper())
    except ValueError:
        return Confidence.LOW
