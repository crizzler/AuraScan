from dataclasses import dataclass, field
from enum import Enum
import json
from typing import Any, Dict, Iterable, List, Optional
import uuid


SCHEMA_VERSION = "1.0"
SCANNER_VERSION = "2.5.0"


class Severity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Confidence(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CONFIRMED = "CONFIRMED"


class ScanPhase(Enum):
    pkgbuild_static = "pkgbuild_static"
    install_hook_static = "install_hook_static"
    dependency_static = "dependency_static"
    source_archive_scan = "source_archive_scan"
    unpacked_source_scan = "unpacked_source_scan"
    generated_file_scan = "generated_file_scan"
    final_package_scan = "final_package_scan"
    pacman_hook_scan = "pacman_hook_scan"
    history_diff = "history_diff"
    sandbox_runtime = "sandbox_runtime"
    ai_review = "ai_review"


class FindingSource(Enum):
    clamav = "clamav"
    deterministic_rule = "deterministic_rule"
    yara_optional = "yara_optional"
    ai_review = "ai_review"
    history_analyzer = "history_analyzer"
    sandbox_observer = "sandbox_observer"


class EvidenceQuality(Enum):
    confirmed_signature = "confirmed_signature"
    confirmed_static_pattern = "confirmed_static_pattern"
    confirmed_history_diff = "confirmed_history_diff"
    sandbox_observed = "sandbox_observed"
    strong_heuristic = "strong_heuristic"
    weak_heuristic = "weak_heuristic"
    ai_interpretation = "ai_interpretation"


class RecommendedAction(Enum):
    allow = "allow"
    warn = "warn"
    manual_review = "manual_review"
    block = "block"


class RiskCategory(Enum):
    pkgbuild_script_risk = "pkgbuild_script_risk"
    install_hook_risk = "install_hook_risk"
    upstream_source_risk = "upstream_source_risk"
    dependency_risk = "dependency_risk"
    maintainer_history_risk = "maintainer_history_risk"
    clamav_signature_risk = "clamav_signature_risk"
    yara_signature_risk_optional = "yara_signature_risk_optional"
    sandbox_behavior_risk = "sandbox_behavior_risk"
    credential_exposure_risk = "credential_exposure_risk"
    network_behavior_risk = "network_behavior_risk"
    persistence_system_modification_risk = "persistence_system_modification_risk"


# Backward-compatible aliases used by the existing analyzers.
Phase = ScanPhase
Source = FindingSource


def _enum_value(value: Any) -> Any:
    return value.value if isinstance(value, Enum) else value


@dataclass
class PackageMetadata:
    name: str = "unknown"
    version: str = "unknown"
    pkgbase: Optional[str] = None
    maintainer: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "name": self.name,
            "version": self.version,
            "pkgbase": self.pkgbase,
            "maintainer": self.maintainer,
        }
        return {k: v for k, v in data.items() if v is not None}


@dataclass
class Finding:
    rule_id: str
    package_name: str
    package_version: str
    phase: ScanPhase
    source: FindingSource
    severity: Severity
    confidence: Confidence
    evidence_quality: EvidenceQuality
    file_path: str
    explanation: str
    recommendation: str
    blocks_installation: bool
    requires_manual_review: bool
    evidence_snippet: str = ""
    false_positive_notes: str = ""
    line_number: Optional[int] = None
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    risk_category: Optional[RiskCategory] = None
    raw_output: Optional[str] = None
    file_hash: Optional[str] = None
    user_title: Optional[str] = None
    user_summary: Optional[str] = None
    why_it_matters: Optional[str] = None
    is_this_common: Optional[str] = None
    what_aurascan_checked: Optional[str] = None
    what_aurascan_did_not_check: Optional[str] = None
    recommended_user_action: Optional[str] = None
    technical_details: Optional[str] = None
    show_by_default: bool = True
    display_group: Optional[str] = None
    display_priority: int = 50

    def __post_init__(self):
        self.phase = ScanPhase(_enum_value(self.phase))
        self.source = FindingSource(_enum_value(self.source))
        self.severity = Severity(_enum_value(self.severity))
        self.confidence = Confidence(_enum_value(self.confidence))
        self.evidence_quality = EvidenceQuality(_enum_value(self.evidence_quality))
        if self.risk_category is not None:
            self.risk_category = RiskCategory(_enum_value(self.risk_category))

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "package_name": self.package_name,
            "package_version": self.package_version,
            "phase": self.phase.value,
            "source": self.source.value,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "evidence_quality": self.evidence_quality.value,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "evidence_snippet": self.evidence_snippet,
            "explanation": self.explanation,
            "recommendation": self.recommendation,
            "false_positive_notes": self.false_positive_notes,
            "blocks_installation": self.blocks_installation,
            "requires_manual_review": self.requires_manual_review,
            "risk_category": self.risk_category.value if self.risk_category else None,
            "raw_output": self.raw_output,
            "file_hash": self.file_hash,
            "user_title": self.user_title,
            "user_summary": self.user_summary,
            "why_it_matters": self.why_it_matters,
            "is_this_common": self.is_this_common,
            "what_aurascan_checked": self.what_aurascan_checked,
            "what_aurascan_did_not_check": self.what_aurascan_did_not_check,
            "recommended_user_action": self.recommended_user_action,
            "technical_details": self.technical_details,
            "show_by_default": self.show_by_default,
            "display_group": self.display_group,
            "display_priority": self.display_priority,
        }
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        return cls(
            finding_id=data.get("finding_id", str(uuid.uuid4())),
            rule_id=data["rule_id"],
            package_name=data.get("package_name", "unknown"),
            package_version=data.get("package_version", "unknown"),
            phase=ScanPhase(data["phase"]),
            source=FindingSource(data["source"]),
            severity=Severity(data["severity"]),
            confidence=Confidence(data["confidence"]),
            evidence_quality=EvidenceQuality(data["evidence_quality"]),
            file_path=data.get("file_path", ""),
            line_number=data.get("line_number"),
            evidence_snippet=data.get("evidence_snippet", ""),
            explanation=data.get("explanation", ""),
            recommendation=data.get("recommendation", ""),
            false_positive_notes=data.get("false_positive_notes", ""),
            blocks_installation=bool(data.get("blocks_installation", False)),
            requires_manual_review=bool(data.get("requires_manual_review", False)),
            risk_category=RiskCategory(data["risk_category"]) if data.get("risk_category") else None,
            raw_output=data.get("raw_output"),
            file_hash=data.get("file_hash"),
            user_title=data.get("user_title"),
            user_summary=data.get("user_summary"),
            why_it_matters=data.get("why_it_matters"),
            is_this_common=data.get("is_this_common"),
            what_aurascan_checked=data.get("what_aurascan_checked"),
            what_aurascan_did_not_check=data.get("what_aurascan_did_not_check"),
            recommended_user_action=data.get("recommended_user_action"),
            technical_details=data.get("technical_details"),
            show_by_default=bool(data.get("show_by_default", True)),
            display_group=data.get("display_group"),
            display_priority=int(data.get("display_priority", 50)),
        )


@dataclass
class RiskSummary:
    severity: Severity
    action: RecommendedAction
    requires_manual_review: bool = False
    blocks_installation: bool = False
    reason: str = ""

    def __post_init__(self):
        self.severity = Severity(_enum_value(self.severity))
        self.action = RecommendedAction(_enum_value(self.action))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity.value,
            "action": "BLOCKED" if self.blocks_installation else self.action.value.upper(),
            "recommended_action": self.action.value,
            "requires_manual_review": self.requires_manual_review,
            "blocks_installation": self.blocks_installation,
            "reason": self.reason,
        }


@dataclass
class ScanReport:
    package_metadata: PackageMetadata
    findings: List[Finding] = field(default_factory=list)
    risk_summary: Optional[RiskSummary] = None
    schema_version: str = SCHEMA_VERSION
    scanner_version: str = SCANNER_VERSION
    messages: List[str] = field(default_factory=list)
    source_acquisition: List[Dict[str, Any]] = field(default_factory=list)
    scan_policy: Optional[str] = None
    scan_context: Optional[str] = None
    scan_context_source: Optional[str] = None
    scan_context_authority: Optional[str] = None
    context_eligible_for_fast_path: bool = False
    context_proof_reasons: List[str] = field(default_factory=list)
    context_proof_errors: List[str] = field(default_factory=list)
    context_user_warning: str = ""
    context_provider_name: str = ""
    context_installed_package_present: Optional[bool] = None
    context_installed_version: str = ""
    context_candidate_version: str = ""
    context_transaction_operation: str = ""
    fast_path_decision: Optional[Dict[str, Any]] = None
    previous_baseline_id: Optional[str] = None
    previous_baseline_scan_level: Optional[str] = None
    baseline_update_policy: Optional[str] = None
    trusted_baseline_updated: bool = False

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "schema_version": self.schema_version,
            "scanner_version": self.scanner_version,
            "package_metadata": self.package_metadata.to_dict(),
            "risk_summary": self.risk_summary.to_dict() if self.risk_summary else None,
            "findings": [finding.to_dict() for finding in self.findings],
            "messages": self.messages,
            "source_acquisition": self.source_acquisition,
        }
        if self.scan_policy is not None:
            data["scan_policy"] = self.scan_policy
            data["update_scan_policy"] = self.scan_policy
        if self.scan_context is not None:
            data["scan_context"] = self.scan_context
        if self.scan_context_source is not None:
            data["scan_context_source"] = self.scan_context_source
        if self.scan_context_authority is not None:
            data["scan_context_authority"] = self.scan_context_authority
        data["context_eligible_for_fast_path"] = self.context_eligible_for_fast_path
        data["context_proof_reasons"] = list(self.context_proof_reasons)
        data["context_proof_errors"] = list(self.context_proof_errors)
        if self.context_user_warning:
            data["context_user_warning"] = self.context_user_warning
        if self.context_provider_name:
            data["context_provider_name"] = self.context_provider_name
        if self.context_installed_package_present is not None:
            data["context_installed_package_present"] = self.context_installed_package_present
        if self.context_installed_version:
            data["context_installed_version"] = self.context_installed_version
        if self.context_candidate_version:
            data["context_candidate_version"] = self.context_candidate_version
        if self.context_transaction_operation:
            data["context_transaction_operation"] = self.context_transaction_operation
        if self.fast_path_decision is not None:
            data["fast_path_decision"] = self.fast_path_decision
        if self.previous_baseline_id is not None:
            data["previous_baseline_id"] = self.previous_baseline_id
        if self.previous_baseline_scan_level is not None:
            data["previous_baseline_scan_level"] = self.previous_baseline_scan_level
        if self.baseline_update_policy is not None:
            data["baseline_update_policy"] = self.baseline_update_policy
        data["trusted_baseline_updated"] = self.trusted_baseline_updated
        return data

    def to_json(self, *, indent: Optional[int] = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanReport":
        metadata = data.get("package_metadata", {})
        risk = data.get("risk_summary") or {}
        blocks = bool(risk.get("blocks_installation") or risk.get("action") == "BLOCKED")
        action = risk.get("recommended_action") or ("block" if blocks else "allow")
        if str(action).upper() == "BLOCKED":
            action = "block"
        if str(action).upper() == "PASSED":
            action = "allow"
        return cls(
            schema_version=data.get("schema_version", SCHEMA_VERSION),
            scanner_version=data.get("scanner_version", SCANNER_VERSION),
            package_metadata=PackageMetadata(
                name=metadata.get("name", "unknown"),
                version=metadata.get("version", "unknown"),
                pkgbase=metadata.get("pkgbase"),
                maintainer=metadata.get("maintainer"),
            ),
            risk_summary=RiskSummary(
                severity=Severity(risk.get("severity", "LOW")),
                action=RecommendedAction(action.lower()),
                requires_manual_review=bool(risk.get("requires_manual_review", False)),
                blocks_installation=blocks,
                reason=risk.get("reason", ""),
            ),
            findings=[Finding.from_dict(item) for item in data.get("findings", [])],
            messages=list(data.get("messages", [])),
            source_acquisition=list(data.get("source_acquisition", [])),
            scan_policy=data.get("scan_policy"),
            scan_context=data.get("scan_context"),
            scan_context_source=data.get("scan_context_source"),
            scan_context_authority=data.get("scan_context_authority"),
            context_eligible_for_fast_path=bool(data.get("context_eligible_for_fast_path", False)),
            context_proof_reasons=list(data.get("context_proof_reasons", [])),
            context_proof_errors=list(data.get("context_proof_errors", [])),
            context_user_warning=data.get("context_user_warning", ""),
            context_provider_name=data.get("context_provider_name", ""),
            context_installed_package_present=data.get("context_installed_package_present"),
            context_installed_version=data.get("context_installed_version", ""),
            context_candidate_version=data.get("context_candidate_version", ""),
            context_transaction_operation=data.get("context_transaction_operation", ""),
            fast_path_decision=data.get("fast_path_decision"),
            previous_baseline_id=data.get("previous_baseline_id"),
            previous_baseline_scan_level=data.get("previous_baseline_scan_level"),
            baseline_update_policy=data.get("baseline_update_policy"),
            trusted_baseline_updated=bool(data.get("trusted_baseline_updated", False)),
        )

    def render_terminal(self, use_color: bool = True, verbose: bool = False) -> str:
        from aurascan.core.presenter import FindingPresenter

        reset = "\033[0m" if use_color else ""
        red = "\033[91m" if use_color else ""
        yellow = "\033[93m" if use_color else ""
        green = "\033[92m" if use_color else ""
        risk = self.risk_summary or RiskSummary(Severity.LOW, RecommendedAction.allow)
        action = "BLOCKED" if risk.blocks_installation else risk.action.value.upper()
        color = red if risk.blocks_installation else yellow if risk.requires_manual_review else green

        lines = [
            f"\n[AuraScan] Audit Complete: {self.package_metadata.name} {self.package_metadata.version}",
            "=" * 50,
            f"Risk Score: {color}{risk.severity.value}{reset} | Action: {color}{action}{reset}",
            "-" * 50,
        ]

        if not self.findings:
            lines.append("[INFO] No findings were produced. This is not proof the package is safe.")

        if self.source_acquisition:
            counts: Dict[str, int] = {}
            for item in self.source_acquisition:
                status = str(item.get("status", "unknown"))
                counts[status] = counts.get(status, 0) + 1
            summary = ", ".join(f"{status}={count}" for status, count in sorted(counts.items()))
            lines.append(f"Source Acquisition: {summary}")

        if self.fast_path_decision:
            decision = self.fast_path_decision
            lines.append("Update Scan Policy:")
            if self.context_user_warning:
                lines.append("Update context was provided manually.")
                lines.append(self.context_user_warning)
            elif (
                self.context_eligible_for_fast_path
                and self.scan_context == "update"
                and self.scan_context_authority in ("verified_local_package_db", "verified_transaction_provider")
            ):
                if self.context_provider_name == "local_package_db":
                    lines.append("Package update verified locally")
                    lines.append("AuraScan confirmed from the local package database that this package is already installed and this scan is for an update.")
                    lines.append("Why it matters: Verified update context is required before AuraScan can safely consider the smart update fast path.")
                    lines.append("What AuraScan checked: AuraScan checked local installed package information and the candidate package metadata.")
                    lines.append("What AuraScan did not check: This does not prove the package is safe. It only proves the scan context.")
                    lines.append("Recommended action: No action needed.")
                else:
                    lines.append("Verified package update context.")
                    lines.append("AuraScan confirmed this package was already installed and this scan is for an update.")
            elif self.context_provider_name == "local_package_db":
                lines.append("Package update context could not be proven")
                lines.append("AuraScan could not clearly prove whether this package is a fresh install or an update.")
                lines.append("Why it matters: The update fast path is only allowed when AuraScan can prove the package was already installed and this scan is an update.")
                lines.append("What AuraScan checked: AuraScan checked the available local package information.")
                lines.append("What AuraScan did not check: AuraScan did not prove this is an already-installed package update.")
                lines.append("Recommended action: No action needed. AuraScan used the safer normal scan.")
            lines.append(str(decision.get("title") or "Update scan decision recorded."))
            if decision.get("summary"):
                lines.append(str(decision["summary"]))
            if decision.get("why_it_matters"):
                lines.append(f"Why it matters: {decision['why_it_matters']}")
            if decision.get("what_checked"):
                lines.append(f"What AuraScan checked: {decision['what_checked']}")
            if decision.get("what_not_checked"):
                lines.append(f"What AuraScan did not check: {decision['what_not_checked']}")
            if decision.get("recommended_action"):
                lines.append(f"Recommended action: {decision['recommended_action']}")
            if verbose and decision.get("technical_details"):
                lines.append("Technical details:")
                lines.append(json.dumps(decision["technical_details"], indent=2, sort_keys=True))

        presented_lines, _hidden = FindingPresenter().render(self.findings, verbose=verbose)
        lines.extend(presented_lines)

        if risk.reason:
            lines.append(f"\nRisk reason: {risk.reason}")
        if risk.blocks_installation:
            final_action = "DO NOT INSTALL."
        elif risk.requires_manual_review:
            final_action = "Manual review recommended before installation."
        else:
            final_action = "No blocking findings. Continue only with normal package trust checks."
        lines.append("\nRecommended Action: " + final_action)
        return "\n".join(lines)


class AnalysisResult:
    def __init__(self, is_safe: bool, msg: str, findings: Optional[List[Finding]] = None):
        self.is_safe = is_safe
        self.msg = msg
        self.findings = findings or []

    def get_highest_severity(self) -> Severity:
        order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        highest = Severity.LOW
        for finding in self.findings:
            if order.index(finding.severity) > order.index(highest):
                highest = finding.severity
        return highest

    def blocks_installation(self) -> bool:
        return not self.is_safe or any(f.blocks_installation for f in self.findings)

    def to_report(self, package_name: str, package_version: str) -> ScanReport:
        from aurascan.core.risk import RiskEngine

        report = ScanReport(
            package_metadata=PackageMetadata(package_name, package_version),
            findings=self.findings,
            messages=[self.msg] if self.msg else [],
        )
        report.risk_summary = RiskEngine().evaluate(self.findings)
        return report

    def to_dict(self, package_name: str, package_version: str) -> Dict[str, Any]:
        return self.to_report(package_name, package_version).to_dict()


def findings_from_results(results: Iterable[AnalysisResult]) -> List[Finding]:
    findings: List[Finding] = []
    for result in results:
        findings.extend(result.findings)
    return findings
