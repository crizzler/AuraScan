"""Incident domain vocabulary: report value types and the state layout they live under.

This is the declarative surface of the incident domain, shared by the incident
workflow, the repair planner, the diagnostics planner, the automation layer, the
presenter and recovery: the report, evidence, finding, coredump, diagnostic and
repair value types, the schema/report identifiers, and the fixed paths incident
state is stored under.

Everything here is inert data and pure coercion. It performs no I/O, runs no
process, and holds no policy about whether an action may run — eligibility,
authorization and execution stay in the layers that own them.
"""

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Mapping, Optional

from aurascan.core.models import Confidence, SCANNER_VERSION, Severity
from aurascan.core.redaction import redact_incident_text


INCIDENT_SCHEMA_VERSION = "1.3"
INCIDENT_REPORT_TYPE = "incident_report"
INCIDENT_SYSTEM_ROOT = Path("/var/lib/aurascan/incidents")
INCIDENT_MONITOR_MARKER_ROOT = INCIDENT_SYSTEM_ROOT / "pending"
INCIDENT_SYSTEM_REPORT_ROOT = INCIDENT_SYSTEM_ROOT / "reports"
INCIDENT_REPAIR_ROOT = INCIDENT_SYSTEM_ROOT / "repairs"
INCIDENT_MAINTENANCE_ROOT = INCIDENT_SYSTEM_ROOT / "maintenance"
INCIDENT_MAINTENANCE_STATE = INCIDENT_MAINTENANCE_ROOT / "state.json"
INCIDENT_MAINTENANCE_STATUS = INCIDENT_MAINTENANCE_ROOT / "status.json"
SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
CONFIDENCE_ORDER = [Confidence.LOW, Confidence.MEDIUM, Confidence.HIGH, Confidence.CONFIRMED]


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


def valid_boot_target(value: str) -> bool:
    target = str(value or "").strip()
    if re.fullmatch(r"[+-]?\d+", target):
        return True
    return bool(re.fullmatch(r"[0-9a-fA-F]{32}", target.replace("-", "")))
