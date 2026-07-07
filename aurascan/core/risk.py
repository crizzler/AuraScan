from collections import Counter
from typing import Iterable, List

from aurascan.core.models import (
    Confidence,
    EvidenceQuality,
    Finding,
    FindingSource,
    RecommendedAction,
    RiskSummary,
    ScanPhase,
    Severity,
)


_SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


class RiskEngine:
    def evaluate(self, findings: Iterable[Finding]) -> RiskSummary:
        findings = list(findings)
        if not findings:
            return RiskSummary(
                Severity.LOW,
                RecommendedAction.allow,
                reason="No findings were produced; clean auxiliary scans are not proof of safety.",
            )

        normalized = [self._normalize(finding) for finding in findings]
        severity = max((f.severity for f in normalized), key=_SEVERITY_ORDER.index)
        reason_parts: List[str] = []

        if any(f.source == FindingSource.clamav and f.confidence == Confidence.CONFIRMED for f in normalized):
            severity = Severity.CRITICAL
            reason_parts.append("confirmed ClamAV signature")

        if any(
            f.source == FindingSource.deterministic_rule
            and f.severity == Severity.CRITICAL
            and f.confidence in (Confidence.HIGH, Confidence.CONFIRMED)
            for f in normalized
        ):
            severity = Severity.CRITICAL
            reason_parts.append("deterministic critical rule")

        if any(
            f.source == FindingSource.sandbox_observer
            and "credential" in f.rule_id.lower()
            and f.evidence_quality == EvidenceQuality.sandbox_observed
            for f in normalized
        ):
            severity = Severity.CRITICAL
            reason_parts.append("sandbox-observed credential access")

        medium_non_ai = [
            f for f in normalized
            if f.severity == Severity.MEDIUM and f.source != FindingSource.ai_review
        ]
        if len(medium_non_ai) >= 3 and severity in (Severity.LOW, Severity.MEDIUM):
            severity = Severity.HIGH
            reason_parts.append("multiple medium non-AI findings")

        has_ai_only = all(f.source == FindingSource.ai_review for f in normalized)
        if has_ai_only and severity == Severity.CRITICAL:
            severity = Severity.HIGH
            for finding in normalized:
                finding.blocks_installation = False
                finding.requires_manual_review = True
            reason_parts.append("AI-only suspicion capped below CRITICAL")

        requires_manual_review = any(f.requires_manual_review for f in normalized)
        history_count = sum(1 for f in normalized if f.phase == ScanPhase.history_diff)
        if history_count and not any(f.blocks_installation for f in normalized):
            requires_manual_review = True
            if severity == Severity.LOW:
                severity = Severity.MEDIUM
            reason_parts.append("history anomaly requires review")

        blocks_installation = any(f.blocks_installation for f in normalized)
        if has_ai_only:
            blocks_installation = False
        if severity == Severity.CRITICAL and not has_ai_only:
            blocks_installation = True

        action = RecommendedAction.block if blocks_installation else (
            RecommendedAction.manual_review if requires_manual_review else RecommendedAction.allow
        )
        if not reason_parts:
            counts = Counter(f.severity.value for f in normalized)
            reason_parts.append("highest finding severity: " + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))

        return RiskSummary(
            severity=severity,
            action=action,
            requires_manual_review=requires_manual_review,
            blocks_installation=blocks_installation,
            reason="; ".join(reason_parts),
        )

    def _normalize(self, finding: Finding) -> Finding:
        if finding.source == FindingSource.clamav and finding.confidence == Confidence.CONFIRMED:
            finding.severity = Severity.CRITICAL
            finding.blocks_installation = True
            finding.requires_manual_review = False
        if (
            finding.source == FindingSource.ai_review
            and finding.evidence_quality == EvidenceQuality.ai_interpretation
            and finding.severity == Severity.CRITICAL
        ):
            finding.severity = Severity.HIGH
            finding.blocks_installation = False
            finding.requires_manual_review = True
        return finding
