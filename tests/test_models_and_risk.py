from aurascan.core.models import (
    AnalysisResult,
    Confidence,
    EvidenceQuality,
    Finding,
    PackageMetadata,
    Phase,
    RecommendedAction,
    ScanReport,
    Severity,
    Source,
)
from aurascan.core.risk import RiskEngine
from aurascan.core.scan_report_presenter import render_scan_report


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
    rendered = render_scan_report(restored, use_color=False)

    assert data["schema_version"] == "1.0"
    assert data["findings"][0]["rule_id"] == "TEST-001"
    assert data["source_acquisition"][0]["status"] == "acquired"
    assert "AuraScan" in rendered
    assert "Source Acquisition" in rendered
    assert "test finding" in rendered


def test_terminal_rendering_strips_control_sequences_and_bidi_spoofing():
    finding = make_finding(
        explanation="review\x1b]8;;https://example.invalid\x07click\x1b]8;;\x07\n[AuraScan] SAFE\u202e",
        recommendation="run nothing\x1b[2J",
        evidence_snippet="detail\x1b[31m forged",
    )
    report = ScanReport(PackageMetadata("pkg\x1b[2J", "1\u202e"), [finding])
    report.risk_summary = RiskEngine().evaluate([finding])

    rendered = render_scan_report(report, use_color=False, verbose=True)

    assert "\x1b" not in rendered
    assert "\u202e" not in rendered
    assert "https://example.invalid" not in rendered
    assert "[AuraScan] SAFE" not in rendered
    assert "reviewclick [untrusted text] SAFE" in rendered


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


def test_repository_artifact_inventory_does_not_self_escalate_to_high():
    findings = [
        make_finding(rule_id="AUR-REPO-OPAQUE-ARTIFACT-001")
        for _index in range(4)
    ]

    risk = RiskEngine().evaluate(findings)

    assert risk.severity == Severity.MEDIUM
    assert risk.blocks_installation is False


def test_history_anomaly_requires_manual_review():
    finding = make_finding(
        phase=Phase.history_diff,
        source=Source.history_analyzer,
        evidence_quality=EvidenceQuality.confirmed_history_diff,
    )

    risk = RiskEngine().evaluate([finding])

    assert risk.requires_manual_review is True
    assert risk.blocks_installation is False


def test_analysis_result_is_a_plain_analyzer_result_container():
    empty = AnalysisResult(True, "nothing to check")

    assert empty.is_safe is True
    assert empty.msg == "nothing to check"
    assert empty.findings == []

    findings = [make_finding()]
    populated = AnalysisResult(False, "needs review", findings)

    assert populated.is_safe is False
    assert populated.findings is findings


def test_analysis_result_does_not_assemble_or_serialize_reports():
    """Report assembly belongs to the application layer, not the domain model.

    ``AnalysisResult`` used to expose ``to_report()``/``to_dict()``, which
    imported the risk service into the domain evidence module and formed the
    ``models`` <-> ``risk`` import cycle. Neither method had any caller.
    """

    assert not hasattr(AnalysisResult, "to_report")
    assert not hasattr(AnalysisResult, "to_dict")


def test_application_layer_assembles_the_report_and_risk_summary():
    """The supported assembly path: build the report, then evaluate risk."""

    finding = make_finding()
    report = ScanReport(
        PackageMetadata("pkg", "1"),
        [finding],
        messages=["scan message"],
    )
    report.risk_summary = RiskEngine().evaluate(report.findings)

    assert report.package_metadata.name == "pkg"
    assert report.package_metadata.version == "1"
    assert report.messages == ["scan message"]
    assert report.findings == [finding]
    assert report.risk_summary.severity == Severity.MEDIUM
    assert report.to_dict()["risk_summary"]["severity"] == "MEDIUM"
    assert report.to_dict()["findings"][0]["rule_id"] == "TEST-001"


def test_low_risk_finding_allows_install():
    finding = make_finding(severity=Severity.LOW, requires_manual_review=False)

    risk = RiskEngine().evaluate([finding])

    assert risk.severity == Severity.LOW
    assert risk.requires_manual_review is False
    assert risk.blocks_installation is False
    assert risk.action == RecommendedAction.allow


def test_risk_summary_is_independent_of_finding_order():
    rule_ids = ["TEST-A", "TEST-B", "TEST-C"]

    forward = RiskEngine().evaluate([make_finding(rule_id=rule) for rule in rule_ids])
    backward = RiskEngine().evaluate(
        [make_finding(rule_id=rule) for rule in reversed(rule_ids)]
    )

    assert forward.severity == backward.severity == Severity.HIGH
    assert forward.action == backward.action
    assert forward.requires_manual_review == backward.requires_manual_review
    assert forward.blocks_installation == backward.blocks_installation
    assert forward.reason == backward.reason
