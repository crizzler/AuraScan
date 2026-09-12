"""Intelligence changes must affect real scan decisions, never fixture execution."""

import io
import json

import pytest

import aurascan.makepkg_wrapper as wrapper
from aurascan.analyzers.deep_static import DeepStaticAnalyzer
from aurascan.analyzers.deterministic import DeterministicAnalyzer
from aurascan.analyzers.history import HistoryAnalyzer
from aurascan.core.cache import ScanCache
from aurascan.core.engine import AuraScanEngine
from aurascan.core.intelligence import snapshot_from_payload
from aurascan.core.models import AnalysisResult, PackageMetadata, ScanReport
from aurascan.core.review import (
    ReviewDecisionStore, build_scan_fingerprint, validate_review_token,
)
from aurascan.core.trusted_tools import TrustedTool


BUILD = "pkgname=intelligence-fixture\npkgver=1\npkgrel=1\nbuild() { npm install inert-fixture-package@1.0.0; }\n"


def snapshot(*, indicator=False, sequence=1, status="current"):
    data = {
        "schema_version": "1.0", "feed_id": "aurascan-intelligence",
        "reviewed_at": "2026-09-12", "npm_campaigns": [],
        "vendor_advisories": [], "withdrawals": [],
    }
    if indicator:
        data["npm_campaigns"] = [{
            "id": "INERT-CAMPAIGN-FIXTURE", "reviewed_at": "2026-09-12",
            "references": ["https://example.invalid/advisory"],
            "rights": {"redistribution": "permitted", "basis": "Original inert test metadata."},
            "packages": [{
                "name": "inert-fixture-package", "versions": ["1.0.0"],
                "advisory_ids": ["INERT-ADVISORY-FIXTURE"],
                "references": ["https://example.invalid/advisory"],
                "broad_advisory": "none",
            }],
            "payload_sha256": [], "malicious_domains": [],
        }]
    return snapshot_from_payload(
        data, source="installed", sequence=sequence,
        manifest_digest=str(sequence) * 64, status=status,
        coverage_error="invalid_active_state" if status == "unavailable" else "",
    )


def package(tmp_path, content=BUILD):
    root = tmp_path / "package"
    root.mkdir()
    path = root / "PKGBUILD"
    path.write_text(content, encoding="utf-8")
    return path


def engine_for(tmp_path, current, **options):
    engine = AuraScanEngine(json_output=True, intelligence_loader=lambda: current[0], **options)
    engine.cache = ScanCache(tmp_path / "cache")
    engine.analyzers = [DeterministicAnalyzer(), HistoryAnalyzer(tmp_path / "history.db")]
    return engine


def test_unchanged_bytes_become_blocked_after_intelligence_update(tmp_path):
    path = package(tmp_path)
    original = path.read_bytes()
    current = [snapshot()]
    engine = engine_for(tmp_path, current)
    assert engine.scan_pkgbuild(str(path))
    first_report = engine.last_report
    assert engine.scan_pkgbuild(str(path))
    assert engine.last_report == first_report  # The prior clear cache is populated.

    current[0] = snapshot(indicator=True, sequence=2)
    assert not engine.scan_pkgbuild(str(path))
    assert path.read_bytes() == original
    assert any(f["blocks_installation"] and f["rule_id"] == "SUPPLYCHAIN-NPM-MALICIOUS-RELEASE-001" for f in engine.last_report["findings"])
    assert engine.last_report["intelligence"]["identity"] == current[0].identity
    assert first_report["intelligence"]["identity"] != current[0].identity


@pytest.mark.parametrize("policy", ["smart", "new-only"])
@pytest.mark.parametrize("previous_identity", ["missing", "different"])
def test_missing_or_changed_history_intelligence_forces_normal_scan(tmp_path, policy, previous_identity):
    path = package(tmp_path)
    current = [snapshot()]
    engine = engine_for(tmp_path, current, update_scan_policy=policy,
                        scan_context="update", scan_context_source="test_fixture")
    assert engine.scan_pkgbuild(str(path))
    history = engine._history_analyzer()
    accepted = history.get_snapshot("intelligence-fixture")
    if previous_identity == "missing":
        accepted.pop("intelligence_identity")
    else:
        accepted["intelligence_identity"] = snapshot(sequence=9).identity
    history.save_snapshot("intelligence-fixture", accepted)
    # A fresh local cache ensures this specifically exercises history policy.
    engine.cache = ScanCache(tmp_path / "second-cache")
    current[0] = snapshot(indicator=True, sequence=2)
    assert not engine.scan_pkgbuild(str(path))
    decision = engine.last_report["fast_path_decision"]
    assert decision["action"] == "use_full_scan"
    assert not decision["expensive_phases_skipped"]
    assert history.get_snapshot("intelligence-fixture")["snapshot_id"] == accepted["snapshot_id"]


@pytest.mark.parametrize("policy", ["full", "smart", "new-only"])
def test_stale_intelligence_detects_without_new_review_gate_or_shortcuts(tmp_path, policy, capsys):
    path = package(tmp_path)
    current = [snapshot()]
    engine = engine_for(tmp_path, current, update_scan_policy=policy,
                        scan_context="update", scan_context_source="test_fixture")
    assert engine.scan_pkgbuild(str(path))
    current[0] = snapshot(status="stale")
    assert engine.scan_pkgbuild(str(path))
    report = engine.last_report
    assert not report["risk_summary"]["requires_manual_review"]
    assert report["fast_path_decision"]["action"] == "use_full_scan"
    assert not report["trusted_baseline_updated"]
    assert "stale" in ScanReport.from_dict(report).render_terminal(use_color=False)
    # Stale records continue to detect rather than disappearing on expiry.
    current[0] = snapshot(indicator=True, sequence=2, status="stale")
    assert not engine.scan_pkgbuild(str(path))


def test_corrupt_active_state_blocks_but_preserves_available_detections(tmp_path):
    path = package(tmp_path)
    current = [snapshot(indicator=True, status="unavailable")]
    engine = engine_for(tmp_path, current)
    assert not engine.scan_pkgbuild(str(path))
    findings = engine.last_report["findings"]
    assert any(f["rule_id"] == "INTELLIGENCE-UNAVAILABLE-001" and f["blocks_installation"] for f in findings)
    assert any(f["rule_id"] == "SUPPLYCHAIN-NPM-MALICIOUS-RELEASE-001" and f["blocks_installation"] for f in findings)
    assert not engine.revalidate_intelligence()


def test_cached_report_missing_intelligence_cannot_be_reused(tmp_path):
    path = package(tmp_path)
    current = [snapshot(indicator=True)]
    engine = engine_for(tmp_path, current)
    # Even a cache record filed under the current key must carry its identity.
    engine._capture_intelligence()
    from aurascan.core.install_hook import capture_package_scan_input
    captured = capture_package_scan_input(path, allow_legacy_install=True)
    engine.cache.set_cached_result(
        str(path), engine.scanner_version, engine.rule_version,
        {"findings": [], "risk_summary": {"blocks_installation": False}},
        config_flags=engine._cache_flags(), input_digest=captured.input_digest,
    )
    assert not engine.scan_pkgbuild(str(path))


def test_each_scan_uses_one_snapshot_across_control_and_deep_phases(tmp_path):
    path = package(tmp_path)
    initial, updated = snapshot(), snapshot(indicator=True, sequence=2)
    current = [initial]
    observations, loads = [], []

    class UpdatingDeterministic(DeterministicAnalyzer):
        def analyze_pkgbuild(self, path, content):
            observations.append(self.intelligence_snapshot)
            current[0] = updated
            return super().analyze_pkgbuild(path, content)

    class ObservingDeep(DeepStaticAnalyzer):
        def analyze_pkgbuild(self, path, content):
            observations.append(self.intelligence_snapshot)
            return AnalysisResult(True, "Inert phase observation")

    def loader():
        loads.append(current[0])
        return current[0]

    engine = AuraScanEngine(json_output=True, deep_static=True, offline=True, intelligence_loader=loader)
    engine.cache = ScanCache(tmp_path / "cache")
    engine.analyzers = [UpdatingDeterministic(), ObservingDeep()]
    assert engine.scan_pkgbuild(str(path))
    assert loads == [initial]
    assert observations == [initial, initial]
    assert engine.last_report["intelligence"]["identity"] == initial.identity
    assert not engine.revalidate_intelligence()


def test_built_package_uses_one_snapshot_and_never_caches(tmp_path, monkeypatch):
    path = tmp_path / "inert.pkg.tar.zst"
    path.write_bytes(b"inert archive bytes; parser replaced by phase observations")
    initial, updated = snapshot(), snapshot(sequence=2)
    current = [initial]
    observations = []

    class ObservingDeterministic(DeterministicAnalyzer):
        def analyze_package(self, _path):
            observations.append(self.intelligence_snapshot)
            current[0] = updated
            return AnalysisResult(True, "Inert phase observation")

    class ObservingDeep(DeepStaticAnalyzer):
        def analyze_package(self, _path):
            observations.append(self.intelligence_snapshot)
            return AnalysisResult(True, "Inert phase observation")

    engine = engine_for(tmp_path, current)
    engine.analyzers = [ObservingDeterministic(), ObservingDeep()]
    monkeypatch.setattr(engine.cache, "get_cached_result", lambda *a, **kw: pytest.fail("built-package cache read"))
    monkeypatch.setattr(engine.cache, "set_cached_result", lambda *a, **kw: pytest.fail("built-package cache write"))
    assert engine.scan_package(str(path), "fixture", "1")
    assert observations == [initial, initial]
    assert engine.last_report["intelligence"]["identity"] == initial.identity
    assert engine.scan_package(str(path), "fixture", "1")
    assert observations[-2:] == [updated, updated]


def test_intelligence_identity_invalidates_remembered_and_legacy_review_tokens(tmp_path):
    path = package(tmp_path)
    report = ScanReport(PackageMetadata("intelligence-fixture", "1")).to_dict()
    legacy = build_scan_fingerprint(report, path)
    report["intelligence"] = snapshot().metadata()
    previous = build_scan_fingerprint(report, path)
    store = ReviewDecisionStore(tmp_path / "review.db")
    store.record_acceptance(previous, remember=True)
    report["intelligence"] = snapshot(sequence=2).metadata()
    updated = build_scan_fingerprint(report, path)
    assert len({legacy.review_token, previous.review_token, updated.review_token}) == 3
    assert not validate_review_token(previous.review_token, updated, store)[0]
    assert not validate_review_token(legacy.review_token, updated, store)[0]


def test_wrapper_refuses_generation_change_immediately_before_handoff(tmp_path):
    path = package(tmp_path)
    current = [snapshot()]
    makepkg_calls = []
    tool = TrustedTool("makepkg", "/usr/bin/makepkg", 1, 2, 0, 0, 0o100755)

    def factory(**options):
        options.pop("json_output")
        return engine_for(tmp_path, current, **options)

    def update_during_final_tool_check(_tool):
        current[0] = snapshot(indicator=True, sequence=2)

    output = io.StringIO()
    code = wrapper.run(
        ["--aurascan-json"], cwd=path.parent, engine_factory=factory,
        makepkg_locator=lambda: tool.path,
        makepkg_tool_capture=lambda *_args, **_kwargs: tool,
        makepkg_tool_revalidate=update_during_final_tool_check,
        subprocess_run=lambda *args, **kwargs: makepkg_calls.append(args),
        stdout=output, stderr=io.StringIO(),
    )
    assert code == wrapper.EXIT_SCAN_BLOCKED
    assert makepkg_calls == []
    envelope = json.loads(output.getvalue())
    assert envelope["makepkg_invoked"] is False
    assert "intelligence" in " ".join(envelope["errors"])


def test_reports_preserve_legacy_reading_and_bound_intelligence_metadata():
    legacy = {"package_metadata": {"name": "fixture", "version": "1"}, "findings": []}
    assert ScanReport.from_dict(legacy).intelligence == {}
    legacy["intelligence"] = {"payload": "untrusted" * 10000, "digest": "x" * 1000,
                              "status": "stale", "sequence": True}
    restored = ScanReport.from_dict(legacy)
    assert restored.to_dict()["intelligence"] == {"status": "stale"}
