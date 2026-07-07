from aurascan.core.models import (
    Confidence,
    EvidenceQuality,
    Finding,
    PackageMetadata,
    Phase,
    ScanReport,
    Severity,
    Source,
)
from aurascan.core.risk import RiskEngine


def make_finding(**overrides):
    data = {
        "rule_id": "TEST-001",
        "package_name": "pkg",
        "package_version": "1",
        "phase": Phase.pkgbuild_static,
        "source": Source.deterministic_rule,
        "severity": Severity.MEDIUM,
        "confidence": Confidence.CONFIRMED,
        "evidence_quality": EvidenceQuality.confirmed_static_pattern,
        "file_path": "PKGBUILD",
        "explanation": "test finding",
        "recommendation": "review",
        "blocks_installation": False,
        "requires_manual_review": True,
    }
    data.update(overrides)
    return Finding(**data)


def test_scan_report_serialization_and_rendering():
    finding = make_finding(evidence_snippet="curl example.invalid")
    risk = RiskEngine().evaluate([finding])
    report = ScanReport(
        PackageMetadata("pkg", "1"),
        [finding],
        risk,
        source_acquisition=[{"original": "src.tar.gz", "status": "acquired"}],
    )

    data = report.to_dict()
    restored = ScanReport.from_dict(data)
    rendered = restored.render_terminal(use_color=False)

    assert data["schema_version"] == "1.0"
    assert data["findings"][0]["rule_id"] == "TEST-001"
    assert data["source_acquisition"][0]["status"] == "acquired"
    assert "AuraScan" in rendered
    assert "Source Acquisition" in rendered
    assert "test finding" in rendered


def test_clamav_confirmed_hit_becomes_critical_and_blocks():
    finding = make_finding(
        source=Source.clamav,
        rule_id="CLAMAV-Eicar-Test-Signature",
        severity=Severity.LOW,
        confidence=Confidence.CONFIRMED,
        evidence_quality=EvidenceQuality.confirmed_signature,
    )

    risk = RiskEngine().evaluate([finding])

    assert risk.severity == Severity.CRITICAL
    assert risk.blocks_installation is True


def test_deterministic_credential_exfil_pattern_becomes_critical():
    finding = make_finding(
        rule_id="CRED-SSH-001",
        severity=Severity.CRITICAL,
        source=Source.deterministic_rule,
        blocks_installation=True,
    )

    risk = RiskEngine().evaluate([finding])

    assert risk.severity == Severity.CRITICAL
    assert risk.blocks_installation is True


def test_ai_only_finding_does_not_become_critical_or_block():
    finding = make_finding(
        source=Source.ai_review,
        severity=Severity.CRITICAL,
        evidence_quality=EvidenceQuality.ai_interpretation,
        blocks_installation=True,
    )

    risk = RiskEngine().evaluate([finding])

    assert risk.severity == Severity.HIGH
    assert risk.blocks_installation is False
    assert risk.requires_manual_review is True


def test_ai_finding_does_not_suppress_deterministic_finding():
    deterministic = make_finding(severity=Severity.CRITICAL, blocks_installation=True)
    ai = make_finding(source=Source.ai_review, severity=Severity.LOW, requires_manual_review=False)

    risk = RiskEngine().evaluate([deterministic, ai])

    assert risk.severity == Severity.CRITICAL
    assert risk.blocks_installation is True


def test_clean_clamav_does_not_automatically_produce_safe():
    risk = RiskEngine().evaluate([])

    assert risk.severity == Severity.LOW
    assert "not proof of safety" in risk.reason


def test_multiple_medium_findings_escalate_to_high():
    findings = [make_finding(rule_id=f"MED-{idx}") for idx in range(3)]

    risk = RiskEngine().evaluate(findings)

    assert risk.severity == Severity.HIGH


def test_history_anomaly_requires_manual_review():
    finding = make_finding(
        phase=Phase.history_diff,
        source=Source.history_analyzer,
        evidence_quality=EvidenceQuality.confirmed_history_diff,
    )

    risk = RiskEngine().evaluate([finding])

    assert risk.requires_manual_review is True
    assert risk.blocks_installation is False
