"""Inert installed-package evidence for the bounded vendor advisory fallback."""

import io
import json
import subprocess
from types import SimpleNamespace

import pytest

from aurascan.core import security_audit
from aurascan.core.models import Severity
from aurascan.core.security_audit import (
    ArchAuditResult,
    SecurityAuditReport,
    audit_vendor_emergency_exposure,
    build_security_audit,
    parse_arch_audit_json,
    run_security_audit,
)
from aurascan.core.upgrade_preflight import (
    UpgradePackage,
    UpgradePlan,
    security_audit_upgrade_findings,
)


EXPOSURE_RULE = "SEC-KNOWN-EXPLOITED-VERSION-LAG"
COVERAGE_RULE = "SEC-VENDOR-ADVISORY-VERSION-UNRESOLVED"


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

    assert len(findings) == 1
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
    "153.0.8011.0-1",
    "153.1.0.0-1",
    "154.0.0.0-1",
])
def test_fixed_floor_or_later_has_no_match_for_this_advisory(version):
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
    "chromium-bin", "chromium-git", "chromium-dev", "ungoogled-chromium",
    "chromium-docs", "chromium-widevine", "google-chrome", "Chromium",
    "extra/chromium", "not-chromium", "ordinary-outdated-package",
])
def test_package_name_similarity_or_outdated_status_does_not_establish_exposure(name):
    assert audit_vendor_emergency_exposure({name: "152.0.7977.82-1"}) == []


def test_absent_package_has_no_exposure_or_coverage_warning():
    assert audit_vendor_emergency_exposure({}) == []


def test_offline_emergency_advisory_remains_enabled_without_arch_audit(tmp_path):
    report = offline_report(tmp_path, "152.0.7977.82-1", include_arch_audit=False)

    assert report.has_alert
    assert report.arch_audit.status == "disabled"
    assert [item.rule_id for item in report.vendor_emergency_findings] == [EXPOSURE_RULE]
    assert report.official_vulnerability_findings == []
    assert report.campaign_findings == []
    assert report.to_dict()["risk_summary"]["vendor_emergency_findings"] == 1
    terminal = report.render_terminal(verbose=True, use_color=False)
    assert "Treat the matched evidence as an incident" not in terminal
    assert "investigate from trusted media" not in terminal
    assert "verified fixed updates" in terminal


def test_offline_arch_audit_skip_does_not_skip_bundled_emergency_mapping(tmp_path):
    report = offline_report(tmp_path, "152.0.7977.82-1", include_arch_audit=True)

    assert report.arch_audit.status == "skipped_offline"
    assert [item.rule_id for item in report.vendor_emergency_findings] == [EXPOSURE_RULE]


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

    assert len(report.vendor_emergency_findings) == 1
    assert len(report.official_vulnerability_findings) == 1
    assert {item.source for item in report.findings} == {"vendor_emergency_advisory", "arch-audit"}
    assert report.to_dict()["risk_summary"]["official_vulnerability_findings"] == 1
    assert report.to_dict()["risk_summary"]["vendor_emergency_findings"] == 1


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
    assert data["risk_summary"]["vendor_emergency_findings"] == 1
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
            stdout="bad/package FAKE_SECRET=fixture-only\nchromium 153.0.8010.36-1\n",
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
    report = offline_report(
        tmp_path, "installed version not collected by upgrade snapshot",
        include_arch_audit=False,
    )
    plan = UpgradePlan(repo_packages=[UpgradePackage(name="chromium", new_version="153.0.8010.36-1")])

    findings = security_audit_upgrade_findings(report, plan, version_compare=forbidden_external_call)

    assert report.status == "partial"
    assert [item.rule_id for item in report.findings] == [COVERAGE_RULE]
    assert [item.rule_id for item in findings] == [COVERAGE_RULE]
    assert report.vendor_emergency_findings == []
    assert not report.has_alert


@pytest.mark.parametrize("version", [
    "153.0.8010.36-1", "153.0.8010.37-1", "154.0.0.0-1",
    "0:153.0.8010.36-1", "4:153.0.8010.36-2.1",
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
    assert [item.rule_id for item in report.findings] == [EXPOSURE_RULE]


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

    assert [item.rule_id for item in findings] == [EXPOSURE_RULE]


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

    assert [item.rule_id for item in findings] == [EXPOSURE_RULE]


def test_planned_fix_does_not_silence_uncertain_installed_identity():
    report = SecurityAuditReport(
        campaign=None,
        findings=audit_vendor_emergency_exposure({"chromium": "153.0.8010.36+patched-1"}),
    )
    plan = UpgradePlan(repo_packages=[UpgradePackage(name="chromium", new_version="153.0.8010.36-1")])

    findings = security_audit_upgrade_findings(report, plan, version_compare=forbidden_external_call)

    assert [item.rule_id for item in findings] == [COVERAGE_RULE]
