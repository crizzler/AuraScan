"""Adapter to AuraScan's ``Finding`` model. The only module that imports ``aurascan.core.models``."""

from typing import List, Sequence

from aurascan.core.models import Confidence, EvidenceQuality, Finding, Phase, Severity, Source

from . import catalog
from .model import InjectionEvidence

_SEVERITY = {"LOW": Severity.LOW, "MEDIUM": Severity.MEDIUM, "HIGH": Severity.HIGH}
_CONFIDENCE = {"LOW": Confidence.LOW, "MEDIUM": Confidence.MEDIUM, "HIGH": Confidence.HIGH}

_RECOMMENDATION = (
    "Treat the matched text as potential instructions aimed at an AI reader. Nothing was executed "
    "and nothing is blocked; review the surrounding text before letting an agent act on it."
)


def to_findings(evidence: Sequence[InjectionEvidence]) -> List[Finding]:
    """Map injection evidence onto raise-only findings.

    No finding sets ``blocks_installation``; ``requires_manual_review`` mirrors confidence >= MEDIUM.
    """
    findings = []
    for item in evidence:
        confidence = _CONFIDENCE.get(item.confidence, Confidence.LOW)
        notes = []
        if item.test_fixture_context:
            notes.append("test-fixture path: confidence is capped at LOW")
        elif item.confidence != "HIGH" and item.detector_id.startswith("override.regex."):
            notes.append("heuristic stem-family rule, not an exact canonical phrase")
        if item.confidence == "MEDIUM" and not item.test_fixture_context:
            notes.append("documentation context caps this at MEDIUM; quoting attacks is normal there")

        findings.append(
            Finding(
                rule_id=catalog.rule_id_for(item.detector_id),
                package_name="unknown",
                package_version="unknown",
                phase=Phase.source_archive_scan,
                source=Source.deterministic_rule,
                severity=_SEVERITY.get(item.severity, Severity.LOW),
                confidence=confidence,
                evidence_quality=(
                    EvidenceQuality.strong_heuristic
                    if confidence in (Confidence.MEDIUM, Confidence.HIGH)
                    else EvidenceQuality.weak_heuristic
                ),
                file_path=item.path,
                explanation=item.description,
                recommendation=_RECOMMENDATION,
                blocks_installation=False,
                requires_manual_review=confidence in (Confidence.MEDIUM, Confidence.HIGH),
                evidence_snippet=item.matched_text,
                false_positive_notes="; ".join(notes),
                line_number=item.line,
            )
        )
    return findings
