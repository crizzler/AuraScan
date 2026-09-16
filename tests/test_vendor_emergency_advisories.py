"""Inert installed-package evidence for the bounded vendor advisory fallback."""

import io
import json
import subprocess
from types import SimpleNamespace

import pytest

from aurascan.core import security_audit
from aurascan.core.models import Severity
from aurascan.core.intelligence import bundled_snapshot
from aurascan.core.security_audit_presenter import render_security_audit
from aurascan.core.security_audit import (
    ArchAuditResult,
    SecurityAuditReport,
    audit_vendor_emergency_exposure,
    build_security_audit,
    parse_arch_audit_json,
    run_security_audit,
)
from aurascan.core.upgrade_models import SystemSnapshot, UpgradePackage, UpgradePlan
from aurascan.core.upgrade_preflight import (
    UpgradePreflightReport,
    installed_version_evidence,
    security_audit_upgrade_findings,
)


EXPOSURE_RULE = "SEC-KNOWN-EXPLOITED-VERSION-LAG"
FLOOR_RULE = "SEC-VENDOR-SECURITY-FLOOR-LAG"
DERIVED_RULE = "SEC-VENDOR-ADVISORY-DERIVED-PACKAGE-UNMAPPED"
COVERAGE_RULE = "SEC-VENDOR-ADVISORY-VERSION-UNRESOLVED"
# Chromium carries two reviewed floors: the known-exploited fix and the later
# critical vendor floor. A release below both raises both findings, and a
# pending repository release that clears only the first floor keeps the second.
CHROMIUM_OLD_RULES = [EXPOSURE_RULE, FLOOR_RULE]


@pytest.fixture(autouse=True)
def isolated_runtime_intelligence(monkeypatch):
    # Installed host intelligence must not affect captured-version regressions.
    monkeypatch.setattr(security_audit, "load_intelligence_snapshot", bundled_snapshot)


def forbidden_external_call(*_args, **_kwargs):
    pytest.fail("injected advisory evidence must not invoke a native tool or network")


def offline_report(tmp_path, version, **kwargs):
    return build_security_audit(
        root=tmp_path / "root",
        home=tmp_path / "home",
        state_root=tmp_path / "state",
        installed_packages={"chromium": version},
        log_paths=[],
        runner=forbidden_external_call,
        which=forbidden_external_call,
        urlopen=forbidden_external_call,
        include_host_indicators=False,
        offline=True,
        **kwargs,
    )


@pytest.mark.parametrize("version", [
    "152.0.7977.82-1",
    "153.0.8010.35-1",
    "153.0.8009.999-1",
    "152.999.9999.999-20",
    "9:152.0.7977.82-999.1",
    "1:153.0.8010.35-999",
])
def test_older_upstream_release_is_high_even_with_larger_epoch_or_pkgrel(version):
    findings = audit_vendor_emergency_exposure({"chromium": version})

    assert [item.rule_id for item in findings] == CHROMIUM_OLD_RULES
    finding = findings[0]
    assert finding.rule_id == EXPOSURE_RULE
    assert finding.severity == Severity.HIGH
    assert finding.category == "vendor_emergency_advisory"
    assert finding.source == "vendor_emergency_advisory"
    assert finding.package_name == "chromium"
    serialized = json.dumps(finding.to_dict())
    assert "CVE-2026-87491" in serialized
    assert "153.0.8010.36" in serialized
    assert "chromereleases.googleblog.com" in serialized
    assert "cisa.gov" in serialized


@pytest.mark.parametrize("version", [
    "153.0.8010.36",
    "153.0.8010.36-1",
    "0:153.0.8010.36-1",
    "4:153.0.8010.36-2.1",
    "153.0.8010.37-1",
])
def test_release_between_the_two_chromium_floors_matches_only_the_later_floor(version):
    findings = audit_vendor_emergency_exposure({"chromium": version})

    assert [item.rule_id for item in findings] == [FLOOR_RULE]
    floor_finding = findings[0]
    assert floor_finding.severity == Severity.HIGH
    assert floor_finding.confidence == "medium"
    serialized = json.dumps(floor_finding.to_dict())
    assert "CVE-2026-91749" in serialized
    assert "153.0.8010.47" in serialized
    assert "CVE-2026-87491" not in serialized


@pytest.mark.parametrize("version", [
    "153.0.8010.47",
    "153.0.8010.47-1",
    "0:153.0.8010.47-1",
    "153.0.8011.0-1",
    "153.1.0.0-1",
    "154.0.0.0-1",
    "154.0.0.0-20",
])
def test_release_at_or_above_every_captured_floor_has_no_match(version):
    assert audit_vendor_emergency_exposure({"chromium": version}) == []


@pytest.mark.parametrize("version", [
    None,
    153,
    True,
    [],
    {},
    "",
    " ",
    "153.0.8010",
    "153.0.8010.36.1",
    "0153.0.8010.36-1",
    "153.00.8010.36-1",
    "v153.0.8010.36-1",
    "153.0.8010.36rc1-1",
    "153.0.8010.36+patched-1",
    "153.0.8010.36.r1.gabcdef-1",
    "153.0.8010.36-1custom",
    "-1:153.0.8010.36-1",
    "1:2:153.0.8010.36-1",
    "１５３.0.8010.36-1",
    "153.0.8010.36-1\n",
    "153.0.8010.36-1\x00",
    "153.0.8010.36-1\nFAKE_SECRET=fixture-only",
    "153.0.8010.36-" + "1" * 129,
])
def test_unknown_or_malformed_version_is_coverage_never_fixed_or_secret_echo(version):
    findings = audit_vendor_emergency_exposure({"chromium": version})

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == COVERAGE_RULE
    assert finding.severity == Severity.MEDIUM
    assert finding.category == "advisory_coverage"
    serialized = json.dumps(finding.to_dict())
    assert "FAKE_SECRET" not in serialized
    assert not any(item.startswith("installed=") for item in finding.evidence)
    if isinstance(version, str) and len(version) > 20:
        assert version not in serialized


@pytest.mark.parametrize("name", [
    "chromium-bin", "chromium-git", "chromium-dev",
    "chromium-docs", "chromium-widevine", "google-chrome", "Chromium",
    "extra/chromium", "not-chromium", "ordinary-outdated-package",
])
def test_package_name_similarity_or_outdated_status_does_not_establish_exposure(name):
    assert audit_vendor_emergency_exposure({name: "152.0.7977.82-1"}) == []


def test_declared_derivative_produces_coverage_never_exposure():
    # ungoogled-chromium is a reviewed derivative declaration, so it is reported
    # as unevaluated coverage instead of being matched by version similarity.
    findings = audit_vendor_emergency_exposure({"ungoogled-chromium": "152.0.7977.82-1"})

    assert [item.rule_id for item in findings] == [DERIVED_RULE, DERIVED_RULE]
    assert all(item.severity == Severity.MEDIUM for item in findings)
    assert all(item.category == "advisory_coverage" for item in findings)
    assert all(item.package_name == "ungoogled-chromium" for item in findings)
    assert all(item.advisory.get("intelligence_identity") for item in findings)
    serialized = json.dumps([item.to_dict() for item in findings])
    assert "derived-from=chromium" in serialized
    assert "153.0.8010.36" in serialized and "153.0.8010.47" in serialized
    assert EXPOSURE_RULE not in serialized and FLOOR_RULE not in serialized


def test_undeclared_lookalike_is_not_treated_as_a_derivative():
    for name in ("chromium-bin", "ungoogled-chromium-git", "librewolf") :
        findings = audit_vendor_emergency_exposure({name: "152.0.7977.82-1"})
        if name == "librewolf":
            assert [item.rule_id for item in findings] == [DERIVED_RULE]
        else:
            assert findings == []


def test_derivative_coverage_is_resolved_by_updating_that_exact_package():
    report = SecurityAuditReport(
        campaign=None,
        findings=audit_vendor_emergency_exposure({"ungoogled-chromium-bin": "152.0.7977.75-1"}),
    )
    plan = UpgradePlan(repo_packages=[UpgradePackage(name="ungoogled-chromium-bin",
                                                     new_version="153.0.8010.47-1")])

    assert security_audit_upgrade_findings(
        report, plan, version_compare=forbidden_external_call) == []
    # The installed-state audit keeps the coverage it captured.
    assert [item.rule_id for item in report.findings] == [DERIVED_RULE, DERIVED_RULE]


def test_absent_package_has_no_exposure_or_coverage_warning():
    assert audit_vendor_emergency_exposure({}) == []


def test_offline_emergency_advisory_remains_enabled_without_arch_audit(tmp_path):
    report = offline_report(tmp_path, "152.0.7977.82-1", include_arch_audit=False)

    assert report.has_alert
    assert report.arch_audit.status == "disabled"
    assert [item.rule_id for item in report.vendor_emergency_findings] == CHROMIUM_OLD_RULES
    assert report.official_vulnerability_findings == []
    assert report.campaign_findings == []
    assert report.to_dict()["risk_summary"]["vendor_emergency_findings"] == 2
    terminal = render_security_audit(report, verbose=True, use_color=False)
    assert "Treat the matched evidence as an incident" not in terminal
    assert "investigate from trusted media" not in terminal
    assert "verified fixed updates" in terminal


def test_offline_arch_audit_skip_does_not_skip_bundled_emergency_mapping(tmp_path):
    report = offline_report(tmp_path, "152.0.7977.82-1", include_arch_audit=True)

    assert report.arch_audit.status == "skipped_offline"
    assert [item.rule_id for item in report.vendor_emergency_findings] == CHROMIUM_OLD_RULES


def test_unknown_installed_release_keeps_advisory_coverage_partial(tmp_path):
    report = offline_report(tmp_path, "153.0.8010.36+patched-1", include_arch_audit=False)

    assert report.status == "partial"
    assert not report.has_alert
    assert report.vendor_emergency_findings == []
    assert [item.rule_id for item in report.findings] == [COVERAGE_RULE]
    assert report.to_dict()["risk_summary"]["vendor_emergency_findings"] == 0


def test_official_and_vendor_advisory_authorities_remain_independent(tmp_path, monkeypatch):
    official = parse_arch_audit_json([{
        "name": "AVG-INERT-TEST",
        "packages": ["chromium"],
        "issues": ["CVE-2026-87491"],
        "severity": "High",
        "status": "Vulnerable",
        "type": "arbitrary code execution",
        "fixed": "153.0.8010.36-1",
    }])
    monkeypatch.setattr(
        security_audit, "run_arch_audit",
        lambda **_kwargs: ArchAuditResult(status="ok", findings=official),
    )

    report = offline_report(tmp_path, "152.0.7977.82-1", include_arch_audit=True)

    assert len(report.vendor_emergency_findings) == 2
    assert len(report.official_vulnerability_findings) == 1
    assert {item.source for item in report.findings} == {"vendor_emergency_advisory", "arch-audit"}
    assert report.to_dict()["risk_summary"]["official_vulnerability_findings"] == 1
    assert report.to_dict()["risk_summary"]["vendor_emergency_findings"] == 2


def test_offline_cli_exposes_warning_with_no_arch_audit_or_external_call(tmp_path, monkeypatch):
    root = tmp_path / "root"

    def captured_packages(*, runner, root):
        assert root == tmp_path / "root"
        assert runner is forbidden_external_call
        return {"chromium": "152.0.7977.82-1"}, ""

    monkeypatch.setattr(security_audit, "collect_installed_packages", captured_packages)
    stdout = io.StringIO()
    stderr = io.StringIO()
    status = run_security_audit(
        ["--json", "--offline", "--no-arch-audit", "--root", str(root),
         "--home", str(tmp_path / "home"), "--state-root", str(tmp_path / "state")],
        runner=forbidden_external_call,
        which=forbidden_external_call,
        urlopen=forbidden_external_call,
        stdout=stdout,
        stderr=stderr,
    )

    data = json.loads(stdout.getvalue())
    assert status == 1
    assert data["risk_summary"]["vendor_emergency_findings"] == 2
    assert data["risk_summary"]["severity"] == "HIGH"
    assert data["risk_summary"]["clean_proof"] is False
    assert data["arch_audit"]["status"] == "disabled"
    assert stderr.getvalue() == ""


@pytest.mark.parametrize("failure", ["exit", "oserror", "timeout"])
def test_failed_installed_query_reports_partial_coverage_without_fabricated_exposure(tmp_path, failure):
    calls = []

    def failed_query(command, **_kwargs):
        calls.append(command)
        assert command[-1] == "-Q"
        assert "--root" in command
        assert str(tmp_path / "root") in command
        if failure == "oserror":
            raise OSError("injected package database read failure")
        if failure == "timeout":
            raise subprocess.TimeoutExpired(command, 1)
        return SimpleNamespace(returncode=1, stdout="", stderr="injected package database read failure")

    report = build_security_audit(
        root=tmp_path / "root", home=tmp_path / "home", state_root=tmp_path / "state",
        log_paths=[], runner=failed_query, which=forbidden_external_call,
        urlopen=forbidden_external_call, include_arch_audit=False,
        include_host_indicators=False, offline=True,
    )

    assert len(calls) == 1
    assert report.status == "partial"
    assert report.installed_package_count == 0
    assert report.vendor_emergency_findings == []
    assert not report.has_alert
    assert any("Installed package query failed" in note for note in report.notes)
    assert report.to_dict()["risk_summary"]["clean_proof"] is False


@pytest.mark.parametrize("package_output", [
    "chromium\n",
    "chromium 152.0.7977.82-1\nchromium 153.0.8010.36-1\n",
    "chromium 153.0.8010.36-1\nchromium 152.0.7977.82-1\n",
    "chromium 152.0.7977.82-1\nchromium 153.0.8010.36-1\nchromium 153.0.8010.36-1\n",
    "chromium\nchromium 153.0.8010.36-1\n",
    "chromium 153.0.8010.36-1\nchromium 153.0.8010.36-1\n",
])
def test_missing_or_duplicate_collected_version_remains_unresolved(tmp_path, package_output):
    calls = []

    def captured_query(command, **_kwargs):
        calls.append(command)
        assert command[-1] == "-Q"
        assert str(tmp_path / "root") in command
        return SimpleNamespace(returncode=0, stdout=package_output, stderr="")

    report = build_security_audit(
        root=tmp_path / "root", home=tmp_path / "home", state_root=tmp_path / "state",
        log_paths=[], runner=captured_query, which=forbidden_external_call,
        urlopen=forbidden_external_call, include_arch_audit=False,
        include_host_indicators=False, offline=True,
    )

    assert len(calls) == 1
    assert report.status == "partial"
    assert report.installed_package_count == 1
    assert [item.rule_id for item in report.findings] == [COVERAGE_RULE]
    assert report.vendor_emergency_findings == []
    assert not report.has_alert
    assert report.to_dict()["risk_summary"]["clean_proof"] is False


def test_invalid_collected_package_record_is_partial_without_raw_output_echo(tmp_path):
    def captured_query(command, **_kwargs):
        assert command[-1] == "-Q"
        assert str(tmp_path / "root") in command
        return SimpleNamespace(
            returncode=0,
            stdout="bad/package FAKE_SECRET=fixture-only\nchromium 153.0.8010.47-1\n",
            stderr="",
        )

    report = build_security_audit(
        root=tmp_path / "root", home=tmp_path / "home", state_root=tmp_path / "state",
        log_paths=[], runner=captured_query, which=forbidden_external_call,
        urlopen=forbidden_external_call, include_arch_audit=False,
        include_host_indicators=False, offline=True,
    )

    assert report.status == "partial"
    assert report.installed_package_count == 1
    assert report.findings == []
    assert not report.has_alert
    assert any("Installed package query failed" in note for note in report.notes)
    assert "FAKE_SECRET" not in report.to_json()
    assert "bad/package" not in report.to_json()


def test_upgrade_snapshot_without_version_retains_coverage_even_with_pending_fixed_package(tmp_path):
    report = offline_report(tmp_path, "", include_arch_audit=False)
    plan = UpgradePlan(repo_packages=[UpgradePackage(name="chromium", new_version="153.0.8010.36-1")])

    findings = security_audit_upgrade_findings(report, plan, version_compare=forbidden_external_call)

    assert report.status == "partial"
    assert [item.rule_id for item in report.findings] == [COVERAGE_RULE]
    assert [item.rule_id for item in findings] == [COVERAGE_RULE]
    assert report.vendor_emergency_findings == []
    assert not report.has_alert


@pytest.mark.parametrize("version", [
    "153.0.8010.47-1", "154.0.0.0-1",
])
def test_pending_exact_repo_package_at_fixed_floor_resolves_warning_without_vercmp(version):
    report = SecurityAuditReport(
        campaign=None,
        findings=audit_vendor_emergency_exposure({"chromium": "9:152.0.7977.82-99"}),
    )
    plan = UpgradePlan(repo_packages=[UpgradePackage(name="chromium", new_version=version)])

    assert security_audit_upgrade_findings(
        report, plan, version_compare=forbidden_external_call,
    ) == []
    # Pending transaction filtering must not erase the installed-state report.
    assert [item.rule_id for item in report.findings] == CHROMIUM_OLD_RULES


@pytest.mark.parametrize("version", [
    "153.0.8010.36-1", "153.0.8010.37-1",
    "0:153.0.8010.36-1", "4:153.0.8010.36-2.1",
])
def test_pending_release_clearing_only_the_older_floor_keeps_the_later_alert(version):
    report = SecurityAuditReport(
        campaign=None,
        findings=audit_vendor_emergency_exposure({"chromium": "9:152.0.7977.82-99"}),
    )
    plan = UpgradePlan(repo_packages=[UpgradePackage(name="chromium", new_version=version)])

    findings = security_audit_upgrade_findings(report, plan, version_compare=forbidden_external_call)

    assert [item.rule_id for item in findings] == [FLOOR_RULE]


@pytest.mark.parametrize("version", [
    "152.0.7977.82-999", "9:153.0.8010.35-99", "153.0.8010.36rc1-1",
    "153.0.8010.36+patched-1", "", None,
])
def test_old_or_uncertain_pending_repo_release_never_resolves_warning(version):
    report = SecurityAuditReport(
        campaign=None,
        findings=audit_vendor_emergency_exposure({"chromium": "152.0.7977.82-1"}),
    )
    plan = UpgradePlan(repo_packages=[UpgradePackage(name="chromium", new_version=version)])

    findings = security_audit_upgrade_findings(report, plan, version_compare=forbidden_external_call)

    assert [item.rule_id for item in findings] == CHROMIUM_OLD_RULES


@pytest.mark.parametrize("plan", [
    UpgradePlan(),
    UpgradePlan(repo_packages=[UpgradePackage(name="chromium-bin", new_version="153.0.8010.36-1")]),
    UpgradePlan(repo_packages=[UpgradePackage(name="unrelated", new_version="999.0.0.0-1")]),
    UpgradePlan(aur_packages=[UpgradePackage(name="chromium", new_version="153.0.8010.36-1", package_type="aur")]),
    UpgradePlan(removals=["chromium"]),
])
def test_other_packages_aur_replacements_or_removal_do_not_establish_verified_fix(plan):
    report = SecurityAuditReport(
        campaign=None,
        findings=audit_vendor_emergency_exposure({"chromium": "152.0.7977.82-1"}),
    )

    findings = security_audit_upgrade_findings(report, plan, version_compare=forbidden_external_call)

    assert [item.rule_id for item in findings] == CHROMIUM_OLD_RULES


def test_planned_fix_does_not_silence_uncertain_installed_identity():
    report = SecurityAuditReport(
        campaign=None,
        findings=audit_vendor_emergency_exposure({"chromium": "153.0.8010.36+patched-1"}),
    )
    plan = UpgradePlan(repo_packages=[UpgradePackage(name="chromium", new_version="153.0.8010.36-1")])

    findings = security_audit_upgrade_findings(report, plan, version_compare=forbidden_external_call)

    assert [item.rule_id for item in findings] == [COVERAGE_RULE]


def upgrade_evidence_snapshot(installed_versions, names=None, *, complete=True):
    return SystemSnapshot(
        installed_packages=list(names if names is not None else installed_versions),
        installed_package_versions=dict(installed_versions),
        installed_versions_complete=complete,
    )


def upgrade_evidence_findings(tmp_path, snapshot, plan):
    report = build_security_audit(
        root=tmp_path / "root", home=tmp_path / "home", state_root=tmp_path / "state",
        installed_packages=installed_version_evidence(snapshot),
        log_paths=[], runner=forbidden_external_call, which=forbidden_external_call,
        urlopen=forbidden_external_call, include_arch_audit=False,
        include_host_indicators=False, offline=True,
    )
    return report, security_audit_upgrade_findings(
        report, plan, version_compare=forbidden_external_call,
    )


def upgrade_action(snapshot, findings, plan):
    upgrade_report = UpgradePreflightReport(plan=plan, snapshot=snapshot, findings=findings)
    return upgrade_report.risk_summary()["action"]


def test_captured_upgrade_versions_raise_the_existing_high_lag_finding(tmp_path):
    """Captured local versions now reach the upgrade advisory evaluation."""
    snapshot = upgrade_evidence_snapshot({"chromium": "152.0.7977.82-1"})
    plan = UpgradePlan()

    report, findings = upgrade_evidence_findings(tmp_path, snapshot, plan)

    assert [item.rule_id for item in findings] == CHROMIUM_OLD_RULES
    assert findings[0].severity == Severity.HIGH
    assert findings[0].blocking is False
    assert COVERAGE_RULE not in {item.rule_id for item in report.findings}
    assert report.has_alert
    assert upgrade_action(snapshot, findings, plan) == "confirm"


@pytest.mark.parametrize("version", ["153.0.8010.47-1", "154.0.0.0-1"])
def test_captured_upgrade_version_at_or_above_floor_has_no_finding(tmp_path, version):
    snapshot = upgrade_evidence_snapshot({"chromium": version})
    plan = UpgradePlan()

    report, findings = upgrade_evidence_findings(tmp_path, snapshot, plan)

    assert findings == []
    assert report.findings == []
    assert report.status == "ok"
    assert not report.has_alert
    assert upgrade_action(snapshot, findings, plan) == "continue"


@pytest.mark.parametrize("version", ["153.0.8010.36-1", "153.0.8010.37-1", "4:153.0.8010.36-2.1"])
def test_captured_version_between_the_floors_keeps_the_later_alert(tmp_path, version):
    snapshot = upgrade_evidence_snapshot({"chromium": version})
    plan = UpgradePlan()

    report, findings = upgrade_evidence_findings(tmp_path, snapshot, plan)

    assert [item.rule_id for item in findings] == [FLOOR_RULE]
    assert report.has_alert


def test_captured_below_floor_version_stays_suppressed_by_pending_repository_fix(tmp_path):
    snapshot = upgrade_evidence_snapshot({"chromium": "152.0.7977.82-1"})
    plan = UpgradePlan(repo_packages=[UpgradePackage(name="chromium", new_version="153.0.8010.47-1")])

    report, findings = upgrade_evidence_findings(tmp_path, snapshot, plan)

    # The installed-state report keeps the exposure; the verified handoff resolves it.
    assert [item.rule_id for item in report.findings] == CHROMIUM_OLD_RULES
    assert findings == []
    assert upgrade_action(snapshot, findings, plan) == "continue"


def test_unavailable_upgrade_version_evidence_remains_unresolved_coverage(tmp_path):
    snapshot = upgrade_evidence_snapshot({}, names=["chromium"], complete=False)
    plan = UpgradePlan()

    assert installed_version_evidence(snapshot) == {"chromium": ""}
    report, findings = upgrade_evidence_findings(tmp_path, snapshot, plan)

    assert [item.rule_id for item in findings] == [COVERAGE_RULE]
    assert findings[0].severity == Severity.MEDIUM
    assert EXPOSURE_RULE not in {item.rule_id for item in report.findings}
    assert not report.has_alert
    assert upgrade_action(snapshot, findings, plan) == "continue"


def test_unrelated_installed_versions_produce_no_advisory_finding(tmp_path):
    snapshot = upgrade_evidence_snapshot({"linux": "7.1.3-1", "glibc": "2.42-1"})
    plan = UpgradePlan()

    report, findings = upgrade_evidence_findings(tmp_path, snapshot, plan)

    assert findings == []
    assert report.findings == []
    assert report.status == "ok"


def test_valid_installed_query_captures_name_version_pairs():
    calls = []

    def captured_query(command, **_kwargs):
        calls.append(command)
        return SimpleNamespace(
            returncode=0, stdout="package-a 1.2.3-1\npackage-b 4.5.6-2\n", stderr="",
        )

    packages, note = security_audit.collect_installed_packages(runner=captured_query)

    assert calls == [["pacman", "-Q"]]
    assert packages == {"package-a": "1.2.3-1", "package-b": "4.5.6-2"}
    assert note == ""


def test_oversized_installed_query_is_bounded_unavailable_evidence():
    def captured_query(_command, **_kwargs):
        return SimpleNamespace(
            returncode=0,
            stdout="".join(f"package-{index} 1.0.0-1\n" for index in range(300_000)),
            stderr="",
        )

    packages, note = security_audit.collect_installed_packages(runner=captured_query)

    assert packages == {}
    assert note == security_audit.INSTALLED_QUERY_SIZE_NOTE


def test_excessive_installed_record_count_is_bounded_partial_evidence():
    def captured_query(_command, **_kwargs):
        records = "".join(
            f"package-{index:05d} 1.0.0-1\n"
            for index in range(security_audit.MAX_INSTALLED_RECORDS + 5)
        )
        return SimpleNamespace(returncode=0, stdout=records, stderr="")

    packages, note = security_audit.collect_installed_packages(runner=captured_query)

    assert note == security_audit.INSTALLED_QUERY_RECORD_NOTE
    assert len(packages) == security_audit.MAX_INSTALLED_RECORDS
