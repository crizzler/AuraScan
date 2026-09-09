"""Campaign findings stay authoritative across favorable history and metadata."""

import socket
import subprocess
import urllib.request

import pytest

from aurascan.analyzers.deterministic import DeterministicAnalyzer
from aurascan.analyzers.history import HistoryAnalyzer
from aurascan.analyzers.source_metadata import SourceMetadataAnalyzer
from aurascan.core.cache import ScanCache
from aurascan.core.engine import AuraScanEngine
import aurascan.core.engine as engine_module
from aurascan.core.install_hook import capture_package_scan_input
from aurascan.core.review import get_non_acceptance_blockers, is_review_acceptance_eligible


CAMPAIGN_RULE = "SUPPLYCHAIN-NPM-SHAIHULUD-20260907"
BASE = """pkgname=campaign-policy-fixture
pkgver=1.0
pkgrel=1
source=('git+https://example.invalid/demo.git#commit=0123456789abcdef0123456789abcdef01234567')
sha256sums=('SKIP')
build() {
  echo ordinary-build-message
}
"""
MALICIOUS_COMMAND = "npm install blueai-cli@0.7.0"


@pytest.fixture
def private_engine(tmp_path, monkeypatch):
    """Bind construction, history, audit, and cache before any engine exists."""
    private_home = tmp_path / "home"
    private_home.mkdir()
    monkeypatch.setenv("HOME", str(private_home))
    monkeypatch.setenv("XDG_CACHE_HOME", str(private_home / ".cache"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(private_home / ".config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(private_home / ".local" / "state"))
    monkeypatch.setenv("AURASCAN_AI_ENABLED", "false")

    cache_init = ScanCache.__init__
    history_init = HistoryAnalyzer.__init__
    monkeypatch.setattr(
        ScanCache, "__init__",
        lambda self, cache_dir=None: cache_init(self, cache_dir or tmp_path / "cache"),
    )
    monkeypatch.setattr(
        HistoryAnalyzer, "__init__",
        lambda self, db_path=None: history_init(self, db_path or tmp_path / "history.db"),
    )
    monkeypatch.setattr(engine_module, "log_audit", lambda *args, **kwargs: None)

    def unexpected_external_operation(*args, **kwargs):
        raise AssertionError("Campaign policy tests must stay static and offline")

    monkeypatch.setattr(subprocess, "run", unexpected_external_operation)
    monkeypatch.setattr(subprocess, "Popen", unexpected_external_operation)
    monkeypatch.setattr(socket, "create_connection", unexpected_external_operation)
    monkeypatch.setattr(socket, "getaddrinfo", unexpected_external_operation)
    monkeypatch.setattr(urllib.request, "urlopen", unexpected_external_operation)

    def make_engine(policy="smart"):
        engine = AuraScanEngine(
            json_output=True,
            update_scan_policy=policy,
            scan_context="update",
            scan_context_source="test_fixture",
            local_package_db_root=tmp_path / "pacman-local",
        )
        history = next(item for item in engine.analyzers if isinstance(item, HistoryAnalyzer))
        engine.analyzers = [DeterministicAnalyzer(), history, SourceMetadataAnalyzer()]
        return engine, history

    return make_engine


def _package_root(tmp_path):
    package_root = tmp_path / "package"
    package_root.mkdir()
    return package_root / "PKGBUILD"


def _assert_campaign_blocks(report, expected_phase):
    matching = [finding for finding in report["findings"] if finding["rule_id"] == CAMPAIGN_RULE]
    assert matching
    assert all(finding["phase"] == expected_phase for finding in matching)
    assert all(finding["severity"] == "CRITICAL" and finding["blocks_installation"] for finding in matching)
    assert report["risk_summary"]["action"] == "BLOCKED"
    assert report["risk_summary"]["blocks_installation"] is True
    assert CAMPAIGN_RULE in {finding["rule_id"] for finding in get_non_acceptance_blockers(report)}
    assert is_review_acceptance_eligible(report) is False
    assert report["trusted_baseline_updated"] is False
    assert report["baseline_update_policy"] == "not_updated_blocked"


@pytest.mark.parametrize("policy", ["full", "smart"])
def test_new_campaign_intelligence_overrides_accepted_history_and_low_metadata(
    tmp_path, private_engine, policy,
):
    pkgbuild = _package_root(tmp_path)
    previous = BASE.replace("echo ordinary-build-message", MALICIOUS_COMMAND)
    previous += "# Registry availability and publish-time scanning are not a safety guarantee.\n"
    pkgbuild.write_text(previous, encoding="utf-8")
    engine, history = private_engine(policy)

    # Model an accepted snapshot from before this campaign became known. This
    # records inert bytes directly; it grants no executable fixture authority.
    captured = capture_package_scan_input(pkgbuild)
    history.analyze_pkgbuild(
        str(pkgbuild), previous,
        install_hook_resolution=captured.install_hook,
        repository_snapshot=captured.repository_snapshot,
    )
    history.commit_pending_snapshots(
        scan_level="fast_default", scanner_version="prior-scanner", rule_version="prior-intelligence",
    )
    baseline = history.get_accepted_snapshot("campaign-policy-fixture")
    pkgbuild.write_text(previous.replace("pkgver=1.0", "pkgver=1.1"), encoding="utf-8")

    assert engine.scan_pkgbuild(str(pkgbuild)) is False
    report = engine.last_report
    _assert_campaign_blocks(report, "pkgbuild_static")
    assert any(
        finding["rule_id"] == "SOURCE-META-SKIP-GIT-COMMIT" and finding["severity"] == "LOW"
        for finding in report["findings"]
    )
    expected_action = "use_smart_fast_path" if policy == "smart" else "use_full_scan"
    assert report["fast_path_decision"]["action"] == expected_action
    assert history.get_accepted_snapshot("campaign-policy-fixture")["snapshot_id"] == baseline["snapshot_id"]


@pytest.mark.parametrize("surface", ["pkgbuild", "install_hook"])
def test_changed_campaign_control_input_cannot_reuse_cached_allow_or_smart_skip(
    tmp_path, private_engine, surface,
):
    pkgbuild = _package_root(tmp_path)
    previous = BASE
    hook = pkgbuild.parent / "package.install"
    if surface == "install_hook":
        previous += "install=package.install\n"
        hook.write_text("post_install() {\n  echo ordinary-install-message\n}\n", encoding="utf-8")
    pkgbuild.write_text(previous, encoding="utf-8")
    engine, history = private_engine()
    assert engine.scan_pkgbuild(str(pkgbuild)) is True
    accepted = history.get_accepted_snapshot("campaign-policy-fixture")
    assert accepted
    prior_digest = engine.last_scan_input_digest
    cached = engine.cache.get_cached_result(
        str(pkgbuild), engine.scanner_version, engine.rule_version,
        config_flags=engine._cache_flags(), input_digest=prior_digest,
    )
    assert cached is not None and cached["risk_summary"]["blocks_installation"] is False

    if surface == "install_hook":
        hook.write_text("post_install() {\n  " + MALICIOUS_COMMAND + "\n}\n", encoding="utf-8")
        reason = "install_hook_changed"
        phase = "install_hook_static"
    else:
        pkgbuild.write_text(previous.replace("echo ordinary-build-message", MALICIOUS_COMMAND), encoding="utf-8")
        reason = "build_function_changed"
        phase = "pkgbuild_static"

    assert engine.scan_pkgbuild(str(pkgbuild)) is False
    report = engine.last_report
    _assert_campaign_blocks(report, phase)
    assert engine.last_scan_input_digest != prior_digest
    assert report["fast_path_decision"]["action"] == "use_full_scan"
    assert reason in report["fast_path_decision"]["reason_codes"]
    assert history.get_accepted_snapshot("campaign-policy-fixture")["snapshot_id"] == accepted["snapshot_id"]
