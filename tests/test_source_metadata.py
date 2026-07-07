import json
from pathlib import Path

from aurascan.analyzers.source_metadata import SourceMetadataAnalyzer
from aurascan.core.models import PackageMetadata, ScanReport, Severity
from aurascan.core.risk import RiskEngine


def findings_for(content: str):
    return SourceMetadataAnalyzer().analyze_pkgbuild("PKGBUILD", content).findings


def test_source_metadata_analyzer_emits_metadata_findings_without_acquisition():
    findings = findings_for('pkgname=demo\npkgver=1\nsource=("http://example.invalid/src.tar.gz")\nsha256sums=(SKIP)\n')
    rule_ids = {finding.rule_id for finding in findings}

    assert "SOURCE-META-HTTP-NOT-HTTPS" in rule_ids
    assert "SOURCE-META-SKIP-ARCHIVE-NO-SIGNATURE" in rule_ids
    assert "SOURCE-HTTP-FETCH-FAILED" not in rule_ids


def test_git_branch_with_skip_is_not_critical_by_itself():
    findings = findings_for('source=("git+https://example.invalid/repo.git#branch=main")\nsha256sums=(SKIP)\n')
    finding = next(f for f in findings if f.rule_id == "SOURCE-META-SKIP-GIT-BRANCH")

    assert finding.severity == Severity.MEDIUM
    assert not finding.blocks_installation


def test_git_commit_with_skip_is_low_and_hidden_unless_verbose():
    findings = findings_for('source=("git+https://example.invalid/repo.git#commit=0123456789abcdef0123456789abcdef01234567")\nsha256sums=(SKIP)\n')
    finding = next(f for f in findings if f.rule_id == "SOURCE-META-SKIP-GIT-COMMIT")

    assert finding.severity == Severity.LOW
    assert finding.show_by_default is False


def test_archive_skip_with_signature_less_severe_than_without_signature():
    with_sig = findings_for('source=("src.tar.gz" "src.tar.gz.sig")\nsha256sums=(SKIP SKIP)\n')
    without_sig = findings_for('source=("src.tar.gz")\nsha256sums=(SKIP)\n')

    with_finding = next(f for f in with_sig if f.rule_id == "SOURCE-META-SKIP-ARCHIVE-WITH-SIGNATURE")
    without_finding = next(f for f in without_sig if f.rule_id == "SOURCE-META-SKIP-ARCHIVE-NO-SIGNATURE")

    assert with_finding.severity == Severity.LOW
    assert without_finding.severity == Severity.MEDIUM


def test_http_skip_escalates():
    findings = findings_for('source=("http://example.invalid/src.tar.gz")\nsha256sums=(SKIP)\n')

    assert any(f.rule_id == "SOURCE-META-HTTP-NOT-HTTPS" and f.severity == Severity.HIGH for f in findings)
    assert any(f.rule_id == "SOURCE-META-SKIP-ARCHIVE-NO-SIGNATURE" and f.severity == Severity.HIGH for f in findings)


def test_checksum_count_mismatch_shows_prominently():
    findings = findings_for('source=("one.tar.gz" "two.tar.gz")\nsha256sums=(SKIP)\n')
    finding = next(f for f in findings if f.rule_id == "SOURCE-META-CHECKSUM-COUNT-MISMATCH")

    assert finding.severity == Severity.HIGH
    assert finding.show_by_default is True


def test_sha512_checksums_do_not_look_missing():
    findings = findings_for('source=("one.tar.gz" "two.tar.gz")\nsha512sums=(abc def)\n')

    assert not any(f.rule_id == "SOURCE-META-CHECKSUM-COUNT-MISMATCH" for f in findings)
    assert not any(f.rule_id == "SOURCE-META-MISSING-CHECKSUM" for f in findings)


def test_md5_checksum_is_weak_not_missing():
    findings = findings_for('source=("https://example.invalid/src.tar.gz")\nmd5sums=(abc)\n')
    rule_ids = {finding.rule_id for finding in findings}

    assert "SOURCE-META-WEAK-CHECKSUM" in rule_ids
    assert "SOURCE-META-MISSING-CHECKSUM" not in rule_ids


def test_local_md5_checksum_is_not_default_noise():
    findings = findings_for('source=("LICENSE")\nmd5sums=(abc)\n')

    assert not any(f.rule_id == "SOURCE-META-WEAK-CHECKSUM" for f in findings)
    assert not any(f.rule_id == "SOURCE-META-MISSING-CHECKSUM" for f in findings)


def test_arch_specific_checksums_do_not_look_mismatched():
    content = '''
source=("common.tar.gz")
source_x86_64=("x86_64.tar.gz")
sha256sums=(common)
sha256sums_x86_64=(x86_64)
'''
    findings = findings_for(content)

    assert not any(f.rule_id == "SOURCE-META-CHECKSUM-COUNT-MISMATCH" for f in findings)
    assert not any(f.rule_id == "SOURCE-META-MISSING-CHECKSUM" for f in findings)


def test_arch_specific_srcinfo_checksums_do_not_look_mismatched(tmp_path: Path):
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text("pkgname=demo\n", encoding="utf-8")
    (tmp_path / ".SRCINFO").write_text(
        """
pkgbase = demo
	source = common.tar.gz
	source_x86_64 = x86_64.tar.gz
	sha256sums = common
	sha256sums_x86_64 = x86_64
""",
        encoding="utf-8",
    )

    findings = SourceMetadataAnalyzer().analyze_pkgbuild(str(pkgbuild), pkgbuild.read_text()).findings

    assert not any(f.rule_id == "SOURCE-META-CHECKSUM-COUNT-MISMATCH" for f in findings)
    assert not any(f.rule_id == "SOURCE-META-MISSING-CHECKSUM" for f in findings)


def test_weak_validpgpkeys_has_understandable_warning():
    findings = findings_for('source=("src.tar.gz" "src.tar.gz.sig")\nsha256sums=(SKIP SKIP)\nvalidpgpkeys=("89ABCDEF")\n')
    finding = next(f for f in findings if f.rule_id == "SOURCE-META-WEAK-VALIDPGPKEY")

    assert finding.user_title.startswith("Signing key identifier is too short")
    assert "full signing-key fingerprints" in finding.recommended_user_action


def test_signature_present_but_validpgpkeys_missing_has_understandable_warning():
    findings = findings_for('source=("src.tar.gz" "src.tar.gz.sig")\nsha256sums=(SKIP SKIP)\n')
    finding = next(f for f in findings if f.rule_id == "SOURCE-META-VALIDPGPKEYS-MISSING")

    assert "Signature is present" in finding.user_title
    assert finding.requires_manual_review is True


def test_default_metadata_scan_does_not_emit_unsupported_source_findings():
    findings = findings_for('source=("git://example.invalid/repo.git")\nsha256sums=(SKIP)\n')
    rule_ids = {finding.rule_id for finding in findings}

    assert "SOURCE-META-UNSUPPORTED-SCHEME" not in rule_ids
    assert "SOURCE-UNSUPPORTED" not in rule_ids


def test_terminal_output_uses_plain_language_not_raw_rule_ids():
    findings = findings_for('source=("http://example.invalid/src.tar.gz")\nsha256sums=(SKIP)\n')
    report = ScanReport(PackageMetadata("pkg", "1"), findings)
    report.risk_summary = RiskEngine().evaluate(findings)

    rendered = report.render_terminal(use_color=False)

    assert "Source uses plain HTTP" in rendered
    assert "SOURCE-META-HTTP-NOT-HTTPS" not in rendered
    assert "deterministic_rule" not in rendered


def test_json_output_still_includes_rule_ids():
    findings = findings_for('source=("http://example.invalid/src.tar.gz")\nsha256sums=(SKIP)\n')
    report = ScanReport(PackageMetadata("pkg", "1"), findings)
    report.risk_summary = RiskEngine().evaluate(findings)

    data = json.loads(report.to_json())

    assert any(finding["rule_id"] == "SOURCE-META-HTTP-NOT-HTTPS" for finding in data["findings"])
    assert any(finding["user_title"] == "Source uses plain HTTP." for finding in data["findings"])


def test_verbose_terminal_output_includes_rule_ids_and_details():
    findings = findings_for('source=("http://example.invalid/src.tar.gz")\nsha256sums=(SKIP)\n')
    report = ScanReport(PackageMetadata("pkg", "1"), findings)
    report.risk_summary = RiskEngine().evaluate(findings)

    rendered = report.render_terminal(use_color=False, verbose=True)

    assert "SOURCE-META-HTTP-NOT-HTTPS" in rendered
    assert "Technical details:" in rendered


def test_repeated_skip_notes_are_grouped_in_terminal():
    findings = findings_for('source=("one.tar.gz" "two.tar.gz")\nsha256sums=(SKIP SKIP)\n')
    report = ScanReport(PackageMetadata("pkg", "1"), findings)
    report.risk_summary = RiskEngine().evaluate(findings)

    rendered = report.render_terminal(use_color=False)

    assert rendered.count("Source archive has no checksum verification.") == 1


def test_default_output_limits_lower_priority_warning_groups():
    content = '''
source=(
  "git+https://example.invalid/branch.git#branch=main"
  "git+https://example.invalid/unpinned.git"
  "https://example.invalid/skipped.tar.gz"
  "http://example.invalid/src.tar.gz"
  "https://example.invalid/skipped-too.tar.gz"
)
sha256sums=(SKIP SKIP SKIP abc SKIP)
'''
    findings = findings_for(content)
    report = ScanReport(PackageMetadata("pkg", "1"), findings)
    report.risk_summary = RiskEngine().evaluate(findings)

    rendered = report.render_terminal(use_color=False)

    assert "lower-risk" in rendered
