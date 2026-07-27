import hashlib
import io
import json
import os
from datetime import date
from pathlib import Path
from types import SimpleNamespace

import pytest

from aurascan.analyzers.deterministic import DeterministicAnalyzer
from aurascan.analyzers.deep_static import DeepStaticAnalyzer
from aurascan.core.models import Severity
from aurascan.core.security_audit import (
    MAX_CAMPAIGN_BYTES,
    ArchAuditResult,
    CampaignIntel,
    PacmanHistoryRecord,
    SecurityAuditReport,
    SecurityFinding,
    audit_campaign_exposure,
    build_security_audit,
    bundled_campaign_doctor_status,
    load_campaign_intel,
    parse_arch_audit_json,
    parse_campaign_package_names,
    parse_pacman_history,
    refresh_campaign_intel,
    run_arch_audit,
    run_security_audit,
)
from aurascan.core.upgrade_preflight import (
    UpgradePackage,
    UpgradePlan,
    security_audit_upgrade_findings,
)


class FakeResponse:
    def __init__(self, payload: bytes, final_url: str = ""):
        self.payload = payload
        self.headers = {"Content-Length": str(len(payload))}
        self.final_url = final_url

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, limit: int):
        return self.payload[:limit]

    def geturl(self):
        return self.final_url or "https://example.invalid/list.txt"


def campaign(names=None) -> CampaignIntel:
    return CampaignIntel(
        campaign_id="AUR-TEST",
        title="Test AUR campaign",
        source_url="https://example.invalid/list.txt",
        official_reference="https://archlinux.org/news/test/",
        source_kind="test",
        window_start=date(2026, 6, 9),
        window_end=date(2026, 6, 14),
        package_names=set(names or {"affected-package"}),
        payload_indicators=["js-digest"],
        sha256="0" * 64,
        retrieved_at="2026-06-15T00:00:00+00:00",
    )


def write_campaign_fixture(tmp_path: Path, names) -> tuple:
    text = "\n".join(names) + "\n"
    digest = hashlib.sha256(text.encode()).hexdigest()
    package_list = tmp_path / "packages.txt"
    package_list.write_text(text, encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps({
            "campaign_id": "AUR-TEST",
            "title": "Test campaign",
            "source_url": "https://example.invalid/packages.txt",
            "official_reference": "https://archlinux.org/news/test/",
            "source_kind": "test",
            "window_start": "2026-06-09",
            "window_end": "2026-06-14",
            "payload_indicators": ["js-digest"],
            "package_count": len(set(names)),
            "package_list_sha256": digest,
            "retrieved_at": "2026-06-15T00:00:00+00:00",
        }),
        encoding="utf-8",
    )
    return manifest, package_list


def test_bundled_campaign_manifest_and_hash_are_valid():
    status = bundled_campaign_doctor_status()

    assert status["ready"] is True
    assert status["campaign_id"] == "AUR-2026-06-11-MASS-ADOPTION"
    assert status["package_count"] == 1935
    assert status["sha256"] == "37376737ba95c828c8b570ebc7b359fecb801f1cf512d210284de2c6d9372d73"


def test_campaign_parser_accepts_shell_quoted_names_but_not_shell_syntax():
    names = parse_campaign_package_names('"c++-gtk-utils-gtk2"\nnormal-package\n')

    assert names == {"c++-gtk-utils-gtk2", "normal-package"}
    with pytest.raises(ValueError, match="too many invalid"):
        parse_campaign_package_names("\n".join("$(touch-pwned-%d)" % index for index in range(17)))


def test_campaign_parser_enforces_byte_bound():
    with pytest.raises(ValueError, match="bounded size"):
        parse_campaign_package_names("a" * (MAX_CAMPAIGN_BYTES + 1))


def test_load_campaign_rejects_hash_mismatch(tmp_path: Path):
    manifest, package_list = write_campaign_fixture(tmp_path, ["affected-package"])
    package_list.write_text("different-package\n", encoding="utf-8")

    with pytest.raises(ValueError, match="SHA-256"):
        load_campaign_intel(
            manifest_path=manifest,
            package_list_path=package_list,
            state_root=tmp_path / "state",
        )


def test_refresh_fetches_data_only_and_writes_private_cache(tmp_path: Path):
    original = campaign({"old-package"})
    payload = b"new-package\n"
    seen = {}

    def fake_urlopen(request, timeout):
        seen["url"] = request.full_url
        seen["timeout"] = timeout
        return FakeResponse(payload)

    refreshed = refresh_campaign_intel(
        original,
        state_root=tmp_path / "state",
        urlopen=fake_urlopen,
    )

    assert refreshed.package_names == {"new-package"}
    assert refreshed.data_origin == "refreshed-cache"
    assert seen["url"] == original.source_url
    cache_file = tmp_path / "state/aur-campaign-2026-06-11-packages.txt"
    assert cache_file.read_bytes() == payload
    assert cache_file.stat().st_mode & 0o777 == 0o600
    assert cache_file.parent.stat().st_mode & 0o777 == 0o700


def test_refresh_rejects_cross_host_redirect(tmp_path: Path):
    with pytest.raises(ValueError, match="redirected"):
        refresh_campaign_intel(
            campaign(),
            state_root=tmp_path / "state",
            urlopen=lambda *_args, **_kwargs: FakeResponse(
                b"package\n",
                final_url="https://attacker.invalid/list.txt",
            ),
        )


def test_parse_pacman_history_extracts_only_package_events():
    records = parse_pacman_history(
        "[2026-06-11T12:30:00+0000] [ALPM] installed affected-package (1.0-1)\n"
        "[2026-06-11T12:31:00+0000] [ALPM] running 'hook'...\n"
        "[2026-06-12T12:30:00+0000] [ALPM] upgraded other (1-1 -> 2-1)\n"
    )

    assert [record.package for record in records] == ["affected-package", "other"]
    assert records[0].event_date == date(2026, 6, 11)


def test_name_only_campaign_match_is_calm_medium_finding():
    findings = audit_campaign_exposure(
        campaign(),
        {"affected-package": "2.0-1"},
        [],
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-AUR-CAMPAIGN-INSTALLED-NAME"
    assert findings[0].severity == Severity.MEDIUM
    assert "not proof" in findings[0].why_it_matters.lower() or "needs correlation" in findings[0].why_it_matters.lower()


def test_campaign_window_history_match_is_critical_even_if_uninstalled():
    findings = audit_campaign_exposure(
        campaign(),
        {},
        [PacmanHistoryRecord(
            timestamp="2026-06-11T12:30:00+0000",
            action="installed",
            package="affected-package",
            version="1.0-1",
        )],
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "SEC-AUR-CAMPAIGN-HISTORY-WINDOW"
    assert findings[0].severity == Severity.CRITICAL


def test_pending_historical_package_name_requires_fresh_scan_not_removal():
    findings = audit_campaign_exposure(
        campaign(),
        {},
        [],
        pending_package_names=["affected-package"],
    )

    assert findings[0].severity == Severity.MEDIUM
    assert "current AUR commit" in findings[0].summary
    assert "PKGBUILD" in findings[0].recommended_action


def test_arch_audit_json_is_kept_separate_from_aur_campaign():
    findings = parse_arch_audit_json([{
        "name": "AVG-123",
        "packages": ["openssl"],
        "status": "Fixed",
        "type": "arbitrary code execution",
        "severity": "High",
        "fixed": "3.5.2-1",
        "issues": ["CVE-2026-1234"],
    }])

    assert len(findings) == 1
    assert findings[0].category == "official_vulnerability"
    assert findings[0].severity == Severity.HIGH
    assert findings[0].source == "arch-audit"
    assert "CVE-2026-1234" in findings[0].evidence


def test_arch_audit_missing_and_offline_are_nonfatal():
    missing = run_arch_audit(which=lambda _name: None)
    offline = run_arch_audit(offline=True, which=lambda _name: "/usr/bin/arch-audit")

    assert missing.status == "not_installed"
    assert offline.status == "skipped_offline"


def test_build_security_audit_correlates_fixture_root(tmp_path: Path):
    manifest, package_list = write_campaign_fixture(tmp_path, ["affected-package"])
    log = tmp_path / "root/var/log/pacman.log"
    log.parent.mkdir(parents=True)
    log.write_text(
        "[2026-06-11T12:30:00+0000] [ALPM] installed affected-package (1.0-1)\n",
        encoding="utf-8",
    )

    report = build_security_audit(
        root=tmp_path / "root",
        home=None,
        state_root=tmp_path / "state",
        manifest_path=manifest,
        package_list_path=package_list,
        installed_packages={},
        include_arch_audit=False,
        include_host_indicators=False,
    )

    assert report.status == "ok"
    assert report.has_alert
    assert report.highest_severity == Severity.CRITICAL
    assert report.history_record_count == 1


def test_security_audit_cli_json_and_alert_exit(tmp_path: Path):
    log = tmp_path / "root/var/log/pacman.log"
    log.parent.mkdir(parents=True)
    log.write_text(
        "[2026-06-11T12:30:00+0000] [ALPM] installed actual-ai (1.0-1)\n",
        encoding="utf-8",
    )
    stdout = io.StringIO()
    stderr = io.StringIO()

    status = run_security_audit(
        [
            "--json",
            "--no-arch-audit",
            "--root",
            str(tmp_path / "root"),
            "--state-root",
            str(tmp_path / "state"),
        ],
        runner=lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""),
        stdout=stdout,
        stderr=stderr,
    )

    data = json.loads(stdout.getvalue())
    assert status == 1
    assert data["report_type"] == "security_audit"
    assert data["risk_summary"]["severity"] == "CRITICAL"
    assert data["risk_summary"]["clean_proof"] is False


@pytest.mark.parametrize(
    "line",
    [
        "npm install atomic-lockfile",
        "bun add execa js-digest commander",
        "yarn add lockfile-js",
        "pnpm install js-digest",
    ],
)
def test_known_campaign_payload_dependency_blocks_pkgbuild(line: str):
    result = DeterministicAnalyzer().analyze_pkgbuild("PKGBUILD", f"build() {{ {line}; }}")

    matches = [item for item in result.findings if item.rule_id == "SUPPLYCHAIN-AUR-JS-20260611"]
    assert len(matches) == 1
    assert matches[0].severity == Severity.CRITICAL
    assert matches[0].blocks_installation
    assert result.is_safe is False


def test_known_campaign_payload_name_in_comment_does_not_trigger():
    result = DeterministicAnalyzer().analyze_pkgbuild(
        "PKGBUILD",
        "# incident example: npm install atomic-lockfile\nbuild() { true; }\n",
    )

    assert not any(item.rule_id == "SUPPLYCHAIN-AUR-JS-20260611" for item in result.findings)


def test_deep_static_source_text_blocks_known_campaign_payload(tmp_path: Path):
    source = tmp_path / "install.sh"
    source.write_text("bun add execa js-digest commander\n", encoding="utf-8")

    findings = DeepStaticAnalyzer()._inspect_text_file(source, source.read_text(encoding="utf-8"))

    match = next(item for item in findings if item.rule_id == "DEEPSTATIC-SUPPLYCHAIN-AUR-JS-20260611")
    assert match.severity == Severity.CRITICAL
    assert match.blocks_installation


def test_upgrade_conversion_omits_advisory_fixed_by_pending_repo_upgrade():
    security_report = SecurityAuditReport(
        campaign=None,
        arch_audit=ArchAuditResult(status="ok"),
        findings=[
            SecurityFinding(
                rule_id="SEC-ARCH-AUDIT-AVG-123",
                severity=Severity.HIGH,
                category="official_vulnerability",
                title="openssl has an advisory.",
                summary="Fixed upstream.",
                why_it_matters="Official advisory.",
                recommended_action="Upgrade.",
                package_name="openssl",
                evidence=["AVG-123", "fixed=3.5.2-1"],
            ),
            SecurityFinding(
                rule_id="SEC-AUR-CAMPAIGN-HISTORY-WINDOW",
                severity=Severity.CRITICAL,
                category="aur_campaign",
                title="Campaign history match.",
                summary="Matched.",
                why_it_matters="Possible exposure.",
                recommended_action="Investigate.",
                package_name="affected-package",
            ),
        ],
    )
    plan = UpgradePlan(repo_packages=[UpgradePackage(name="openssl", new_version="3.5.2-1")])

    findings = security_audit_upgrade_findings(
        security_report,
        plan,
        version_compare=lambda left, right: 0 if left == right else None,
    )

    assert [item.rule_id for item in findings] == ["SEC-AUR-CAMPAIGN-HISTORY-WINDOW"]


def test_upgrade_conversion_keeps_advisory_when_pending_version_is_too_old():
    security_report = SecurityAuditReport(
        campaign=None,
        findings=[
            SecurityFinding(
                rule_id="SEC-ARCH-AUDIT-AVG-123",
                severity=Severity.HIGH,
                category="official_vulnerability",
                title="openssl has an advisory.",
                summary="Fixed upstream.",
                why_it_matters="Official advisory.",
                recommended_action="Upgrade.",
                package_name="openssl",
                evidence=["AVG-123", "fixed=3.5.2-1"],
            ),
        ],
    )
    plan = UpgradePlan(repo_packages=[UpgradePackage(name="openssl", new_version="3.5.1-1")])

    findings = security_audit_upgrade_findings(
        security_report,
        plan,
        version_compare=lambda _left, _right: -1,
    )

    assert [item.rule_id for item in findings] == ["SEC-ARCH-AUDIT-AVG-123"]
