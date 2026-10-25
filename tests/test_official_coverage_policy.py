"""An official archive must not block a transaction on AuraScan's parser limits.

The v0.12.1 transaction aborted because a *verified official* package tripped a
bounded-inspection rule. Those rules describe AuraScan's own coverage, not the
package, so for an authenticated archive they stay a visible review advisory.
Local and AUR archives keep the blocker.
"""

from pathlib import Path

from aurascan.core.engine import (
    OFFICIAL_COVERAGE_REVIEW_RULES,
    AuraScanEngine,
    review_official_coverage_findings,
)
from aurascan.core.models import (
    AnalysisResult,
    Confidence,
    EvidenceQuality,
    Finding,
    Phase,
    Severity,
    Source,
)


def _finding(rule_id, *, blocks=True, review=False):
    return Finding(
        rule_id=rule_id,
        package_name="pkgfile",
        package_version="27-1.1",
        phase=Phase.install_hook_static,
        source=Source.deterministic_rule,
        severity=Severity.HIGH,
        confidence=Confidence.CONFIRMED,
        evidence_quality=EvidenceQuality.confirmed_static_pattern,
        file_path="/var/cache/pacman/pkg/pkgfile-27-1.1-x86_64_v3.pkg.tar.zst",
        explanation="Bounded parsing did not complete.",
        recommendation="Inspect the package manually.",
        blocks_installation=blocks,
        requires_manual_review=review,
    )


def test_coverage_rules_are_the_documented_ones():
    assert OFFICIAL_COVERAGE_REVIEW_RULES == {
        "STATIC-REMOTE-STAGE-INSPECTION-INCOMPLETE-001",
        "SUPPLYCHAIN-NPM-INSPECTION-INCOMPLETE-001",
    }


def test_demotion_keeps_the_finding_visible():
    demoted = review_official_coverage_findings(
        [_finding("STATIC-REMOTE-STAGE-INSPECTION-INCOMPLETE-001")]
    )

    assert len(demoted) == 1
    assert demoted[0].blocks_installation is False
    assert demoted[0].requires_manual_review is True
    assert demoted[0].severity is Severity.HIGH
    assert demoted[0].rule_id == "STATIC-REMOTE-STAGE-INSPECTION-INCOMPLETE-001"


def test_demotion_leaves_substantive_findings_alone():
    finding = _finding("STATIC-REMOTE-STAGE-EXEC-001")

    assert review_official_coverage_findings([finding])[0].blocks_installation is True


class _StubAnalyzer:
    def __init__(self, findings):
        self._findings = findings

    def analyze_package(self, _path, **_kwargs):
        blocking = any(finding.blocks_installation for finding in self._findings)
        return AnalysisResult(is_safe=not blocking, msg="stub", findings=self._findings)


def _engine(tmp_path, findings):
    engine = AuraScanEngine(json_output=True, local_package_db_root=tmp_path / "db")
    engine.analyzers = [_StubAnalyzer(findings)]
    return engine


def _package(tmp_path):
    archive = tmp_path / "pkgfile-27-1.1-x86_64_v3.pkg.tar.zst"
    archive.write_bytes(b"not really a package")
    return archive


def test_verified_official_archive_reports_review_instead_of_blocking(tmp_path):
    engine = _engine(tmp_path, [_finding("STATIC-REMOTE-STAGE-INSPECTION-INCOMPLETE-001")])

    ok = engine.scan_package(
        str(_package(tmp_path)),
        analyzers=engine.analyzers,
        official_repo=True,
        quiet=True,
    )

    assert ok is True
    summary = engine.last_report["risk_summary"]
    assert summary["blocks_installation"] is False
    assert summary["requires_manual_review"] is True


def test_local_archive_keeps_the_coverage_blocker(tmp_path):
    engine = _engine(tmp_path, [_finding("STATIC-REMOTE-STAGE-INSPECTION-INCOMPLETE-001")])

    ok = engine.scan_package(
        str(_package(tmp_path)),
        analyzers=engine.analyzers,
        official_repo=False,
        quiet=True,
    )

    assert ok is False
    assert engine.last_report["risk_summary"]["blocks_installation"] is True
