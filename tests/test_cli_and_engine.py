from aurascan.analyzers.deep_static import DeepStaticAnalyzer
from aurascan.analyzers.ai_static import AIStaticAnalyzer
from aurascan.analyzers.history import HistoryAnalyzer
from aurascan.analyzers.source_metadata import SourceMetadataAnalyzer
from aurascan.cli import build_parser
from aurascan.core.cache import ScanCache
from aurascan.core.engine import AuraScanEngine
from aurascan.core.models import AnalysisResult, Confidence, EvidenceQuality, Finding, Phase, ScanReport, Severity, Source
from aurascan.core.update_policy import UpdateScanPolicy
import aurascan.cli as cli


class NoopAnalyzer:
    def analyze_package(self, pkg_path):
        return AnalysisResult(True, "noop", [])

    def analyze_pkgbuild(self, pkgbuild_path, content):
        return AnalysisResult(True, "noop", [])


class LeakySourceAcquisitionAnalyzer(NoopAnalyzer):
    last_source_acquisition = [{"original": "git://example.invalid/repo.git", "status": "unsupported"}]

    def analyze_pkgbuild(self, pkgbuild_path, content):
        return AnalysisResult(True, "leaky", [Finding(
            rule_id="SOURCE-UNSUPPORTED",
            package_name="pkg",
            package_version="1",
            phase=Phase.source_archive_scan,
            source=Source.deterministic_rule,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            evidence_quality=EvidenceQuality.strong_heuristic,
            file_path=pkgbuild_path,
            explanation="Unsupported source scheme or VCS type for automated acquisition.",
            recommendation="manual review",
            blocks_installation=False,
            requires_manual_review=True,
        )])


class SpyAIAnalyzer(AIStaticAnalyzer):
    def __init__(self):
        self.called = False

    def analyze_pkgbuild(self, pkgbuild_path, content):
        self.called = True
        return AnalysisResult(True, "spy", [])


def cache_flags(engine):
    return {
        "deep_static": engine.deep_static,
        "update_scan_policy": engine.update_scan_policy.value,
        "scan_context": engine.scan_context.value,
        "scan_context_source": engine.scan_context_source.value,
        "allow_user_asserted_update_context": engine.allow_user_asserted_update_context,
        "local_package_db_root": str(engine.local_package_db_root) if engine.local_package_db_root is not None else "",
    }


def test_deep_static_flag_is_parsed_correctly():
    args = build_parser().parse_args(["--json", "--deep-static", "--pkgbuild", "PKGBUILD"])

    assert args.json_mode is True
    assert args.deep_static is True
    assert args.pkgbuild == "PKGBUILD"


def test_pgp_privacy_flags_are_parsed_correctly():
    args = build_parser().parse_args([
        "--deep-static",
        "--offline",
        "--no-auto-key-fetch",
        "--keyserver",
        "https://keys.example.invalid",
        "--trusted-key-dir",
        "/tmp/keys",
        "--pkgbuild",
        "PKGBUILD",
    ])

    assert args.offline is True
    assert args.no_auto_key_fetch is True
    assert args.keyserver == "https://keys.example.invalid"
    assert args.trusted_key_dir == ["/tmp/keys"]


def test_verbose_flag_is_parsed_correctly():
    args = build_parser().parse_args(["--verbose", "--pkgbuild", "PKGBUILD"])

    assert args.verbose is True


def test_update_scan_policy_flag_is_parsed_correctly():
    args = build_parser().parse_args(["--update-scan-policy", "smart", "--pkgbuild", "PKGBUILD"])

    assert args.update_scan_policy == "smart"


def test_scan_context_flag_is_parsed_correctly():
    args = build_parser().parse_args(["--scan-context", "update", "--pkgbuild", "PKGBUILD"])

    assert args.scan_context == "update"


def test_scan_context_auto_flag_is_parsed_correctly():
    args = build_parser().parse_args(["--scan-context", "auto", "--pkgbuild", "PKGBUILD"])

    assert args.scan_context == "auto"


def test_allow_user_asserted_update_context_flag_is_parsed_correctly():
    args = build_parser().parse_args([
        "--scan-context",
        "update",
        "--allow-user-asserted-update-context",
        "--pkgbuild",
        "PKGBUILD",
    ])

    assert args.allow_user_asserted_update_context is True


def test_setup_commands_are_mentioned_in_help():
    help_text = build_parser().format_help()

    assert "aurascan init" in help_text
    assert "aurascan doctor" in help_text


def test_init_subcommand_dispatches_before_scan_parser(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "load_env", lambda: None)
    monkeypatch.setattr(cli, "run_init", lambda argv: calls.append(argv) or 0)

    try:
        cli.main(["init", "--disable-ai"])
    except SystemExit as exc:
        assert exc.code == 0

    assert calls == [["--disable-ai"]]


def test_doctor_subcommand_dispatches_before_scan_parser(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "load_env", lambda: None)
    monkeypatch.setattr(cli, "run_doctor", lambda argv: calls.append(argv) or 0)

    try:
        cli.main(["doctor", "--json"])
    except SystemExit as exc:
        assert exc.code == 0

    assert calls == [["--json"]]


def test_default_scan_does_not_enable_deep_static():
    engine = AuraScanEngine()

    assert engine.deep_static is False
    assert not any(isinstance(analyzer, DeepStaticAnalyzer) for analyzer in engine.analyzers)


def test_package_archive_filename_populates_report_metadata(tmp_path, capsys):
    package = tmp_path / "wl-clipboard-1:2.3.0-1.1-x86_64_v3.pkg.tar.zst"
    package.write_bytes(b"not a real archive; analyzers are stubbed")
    engine = AuraScanEngine()
    engine.cache = ScanCache(tmp_path / "cache")
    engine.analyzers = [NoopAnalyzer()]

    assert engine.scan_package(str(package)) is True

    output = capsys.readouterr().out
    assert engine.last_report["package_metadata"]["name"] == "wl-clipboard"
    assert engine.last_report["package_metadata"]["version"] == "1:2.3.0-1.1"
    assert "Audit Complete: wl-clipboard 1:2.3.0-1.1" in output


def test_cached_package_report_with_unknown_metadata_is_repaired_from_filename(tmp_path, capsys):
    package = tmp_path / "demo-tools-2.0-3-x86_64.pkg.tar.zst"
    package.write_bytes(b"same content")
    engine = AuraScanEngine()
    engine.cache = ScanCache(tmp_path / "cache")
    engine.analyzers = [NoopAnalyzer()]
    cached_report = {
        "schema_version": "1.0",
        "scanner_version": "2.5.0",
        "package_metadata": {"name": "unknown", "version": "unknown"},
        "risk_summary": {
            "severity": "LOW",
            "action": "ALLOW",
            "recommended_action": "allow",
            "requires_manual_review": False,
            "blocks_installation": False,
            "reason": "cached fixture",
        },
        "findings": [],
        "messages": ["cached"],
        "source_acquisition": [],
    }
    engine.cache.set_cached_result(
        str(package),
        engine.scanner_version,
        engine.rule_version,
        cached_report,
        config_flags=cache_flags(engine),
    )

    assert engine.scan_package(str(package)) is True

    output = capsys.readouterr().out
    assert engine.last_report["package_metadata"]["name"] == "demo-tools"
    assert engine.last_report["package_metadata"]["version"] == "2.0-3"
    assert "Audit Complete: demo-tools 2.0-3" in output


def test_engine_records_update_scan_policy_without_skipping_runtime_scans():
    engine = AuraScanEngine(update_scan_policy="smart")

    assert engine.update_scan_policy == UpdateScanPolicy.smart
    assert engine._cache_flags()["update_scan_policy"] == "smart"


def test_deep_static_flag_adds_deep_static_analyzer():
    engine = AuraScanEngine(deep_static=True)

    assert any(isinstance(analyzer, DeepStaticAnalyzer) for analyzer in engine.analyzers)


def test_default_fast_scan_has_no_key_fetch_policy():
    engine = AuraScanEngine()

    assert not any(hasattr(analyzer, "source_fetcher") for analyzer in engine.analyzers)


def test_deep_static_auto_key_fetch_defaults_on():
    engine = AuraScanEngine(deep_static=True)
    analyzer = next(analyzer for analyzer in engine.analyzers if isinstance(analyzer, DeepStaticAnalyzer))

    assert analyzer.source_fetcher.policy.auto_key_fetch is True
    assert analyzer.source_fetcher.policy.offline is False


def test_deep_static_offline_disables_auto_key_fetch():
    engine = AuraScanEngine(deep_static=True, offline=True, auto_key_fetch=True)
    analyzer = next(analyzer for analyzer in engine.analyzers if isinstance(analyzer, DeepStaticAnalyzer))

    assert analyzer.source_fetcher.policy.offline is True
    assert analyzer.source_fetcher.policy.auto_key_fetch is False


def test_deep_static_no_auto_key_fetch_disables_keyserver_fetch():
    engine = AuraScanEngine(deep_static=True, auto_key_fetch=False)
    analyzer = next(analyzer for analyzer in engine.analyzers if isinstance(analyzer, DeepStaticAnalyzer))

    assert analyzer.source_fetcher.policy.auto_key_fetch is False


def test_default_fast_scan_does_not_emit_source_acquisition_findings(tmp_path):
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text('pkgname=demo\npkgver=1\nsource=("git://example.invalid/repo.git")\nsha256sums=(SKIP)\n')
    engine = AuraScanEngine()
    engine.cache = ScanCache(tmp_path / "cache")
    engine.analyzers = [NoopAnalyzer()]

    ok = engine.scan_pkgbuild(str(pkgbuild))

    assert ok is True
    cached = engine.cache.get_cached_result(str(pkgbuild), engine.scanner_version, engine.rule_version, config_flags=cache_flags(engine))
    assert cached["source_acquisition"] == []
    assert cached["scan_policy"] == "full"
    assert all(finding["rule_id"] != "SOURCE-UNSUPPORTED" for finding in cached["findings"])


def test_default_fast_scan_emits_metadata_without_acquisition(tmp_path):
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text('pkgname=demo\npkgver=1\nsource=("http://example.invalid/src.tar.gz")\nsha256sums=(SKIP)\n')
    engine = AuraScanEngine()
    engine.cache = ScanCache(tmp_path / "cache")
    engine.analyzers = [SourceMetadataAnalyzer()]

    engine.scan_pkgbuild(str(pkgbuild))

    cached = engine.cache.get_cached_result(str(pkgbuild), engine.scanner_version, engine.rule_version, config_flags=cache_flags(engine))
    assert cached["source_acquisition"] == []
    assert any(finding["rule_id"] == "SOURCE-META-HTTP-NOT-HTTPS" for finding in cached["findings"])
    assert all(finding["rule_id"] != "SOURCE-HTTP-FETCH-FAILED" for finding in cached["findings"])


def test_engine_ignores_acquisition_records_when_fast_mode_is_not_enabled(tmp_path):
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text("pkgname=demo\npkgver=1\n")
    engine = AuraScanEngine()
    engine.cache = ScanCache(tmp_path / "cache")
    engine.analyzers = [LeakySourceAcquisitionAnalyzer()]

    engine.scan_pkgbuild(str(pkgbuild))

    cached = engine.cache.get_cached_result(str(pkgbuild), engine.scanner_version, engine.rule_version, config_flags=cache_flags(engine))
    assert cached["source_acquisition"] == []
    assert all(finding["rule_id"] != "SOURCE-UNSUPPORTED" for finding in cached["findings"])


def test_explicit_deep_static_mode_keeps_source_acquisition_findings(tmp_path):
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text("pkgname=demo\npkgver=1\n")
    engine = AuraScanEngine(deep_static=True)
    engine.cache = ScanCache(tmp_path / "cache")
    engine.analyzers = [LeakySourceAcquisitionAnalyzer()]

    engine.scan_pkgbuild(str(pkgbuild))

    cached = engine.cache.get_cached_result(str(pkgbuild), engine.scanner_version, engine.rule_version, config_flags=cache_flags(engine))
    assert cached["source_acquisition"] == [{"original": "git://example.invalid/repo.git", "status": "unsupported"}]
    assert any(finding["rule_id"] == "SOURCE-UNSUPPORTED" for finding in cached["findings"])


BASE_UPDATE = """# Maintainer: Alice <alice@example.invalid>
pkgname=demo
pkgver=1.0
source=("https://example.invalid/demo-1.0.tar.gz")
sha256sums=("aaa")
validpgpkeys=("0123456789ABCDEF0123456789ABCDEF01234567")
depends=("glibc")
build() {
  echo ok
}
"""


def accepted_history(tmp_path):
    history = HistoryAnalyzer(tmp_path / "history.db")
    history.analyze_pkgbuild(str(tmp_path / "PKGBUILD"), BASE_UPDATE)
    history.commit_pending_snapshots(scan_level="fast_default", scanner_version="test", rule_version="test")
    return history


def write_local_db_entry(root, name="demo", version="1.0"):
    entry = root / f"{name}-{version}"
    entry.mkdir(parents=True)
    (entry / "desc").write_text(f"%NAME%\n{name}\n\n%VERSION%\n{version}\n")
    return entry


def test_smart_update_uses_trust_diff_and_skips_expensive_analyzers(tmp_path):
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text(BASE_UPDATE.replace("pkgver=1.0", "pkgver=1.1").replace("demo-1.0.tar.gz", "demo-1.1.tar.gz").replace('sha256sums=("aaa")', 'sha256sums=("bbb")'))
    history = accepted_history(tmp_path)
    spy_ai = SpyAIAnalyzer()
    engine = AuraScanEngine(update_scan_policy="smart", scan_context="update", scan_context_source="test_fixture")
    engine.cache = ScanCache(tmp_path / "cache")
    engine.analyzers = [history, SourceMetadataAnalyzer(), spy_ai]

    ok = engine.scan_pkgbuild(str(pkgbuild))

    cached = engine.cache.get_cached_result(str(pkgbuild), engine.scanner_version, engine.rule_version, config_flags=cache_flags(engine))
    assert ok is True
    assert spy_ai.called is False
    assert cached["fast_path_decision"]["action"] == "use_smart_fast_path"
    assert cached["fast_path_decision"]["technical_details"]["trust_boundary_diff"]["classification"] == "likely_normal_version_bump"
    assert cached["trusted_baseline_updated"] is True
    assert cached["baseline_update_policy"] == "trusted_baseline_updated"
    assert history.get_snapshot("demo")["scan_level"] == "smart_fast_path"


def test_smart_update_host_change_runs_normal_scan_and_keeps_baseline(tmp_path):
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text(BASE_UPDATE.replace("example.invalid", "evil.example.invalid").replace('sha256sums=("aaa")', 'sha256sums=("bbb")'))
    history = accepted_history(tmp_path)
    spy_ai = SpyAIAnalyzer()
    engine = AuraScanEngine(update_scan_policy="smart", scan_context="update", scan_context_source="test_fixture")
    engine.cache = ScanCache(tmp_path / "cache")
    engine.analyzers = [history, SourceMetadataAnalyzer(), spy_ai]

    engine.scan_pkgbuild(str(pkgbuild))

    cached = engine.cache.get_cached_result(str(pkgbuild), engine.scanner_version, engine.rule_version, config_flags=cache_flags(engine))
    assert spy_ai.called is True
    assert cached["fast_path_decision"]["action"] == "use_full_scan"
    assert "source_host_changed" in cached["fast_path_decision"]["reason_codes"]
    assert cached["trusted_baseline_updated"] is False
    assert cached["baseline_update_policy"] == "not_updated_manual_review_required"
    assert history.get_snapshot("demo")["version"] == "1.0"


def test_smart_update_unknown_context_runs_normal_scan(tmp_path):
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text(BASE_UPDATE.replace("pkgver=1.0", "pkgver=1.1"))
    history = accepted_history(tmp_path)
    spy_ai = SpyAIAnalyzer()
    engine = AuraScanEngine(update_scan_policy="smart")
    engine.cache = ScanCache(tmp_path / "cache")
    engine.analyzers = [history, spy_ai]

    engine.scan_pkgbuild(str(pkgbuild))

    cached = engine.cache.get_cached_result(str(pkgbuild), engine.scanner_version, engine.rule_version, config_flags=cache_flags(engine))
    assert spy_ai.called is True
    assert cached["fast_path_decision"]["action"] == "cannot_fast_path"
    assert cached["fast_path_decision"]["expensive_phases_skipped"] is False
    assert cached["trusted_baseline_updated"] is True


def test_new_only_update_skip_does_not_update_trusted_baseline(tmp_path):
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text(BASE_UPDATE.replace("pkgver=1.0", "pkgver=1.1"))
    history = accepted_history(tmp_path)
    spy_ai = SpyAIAnalyzer()
    engine = AuraScanEngine(update_scan_policy="new-only", scan_context="update", scan_context_source="test_fixture")
    engine.cache = ScanCache(tmp_path / "cache")
    engine.analyzers = [history, spy_ai]

    engine.scan_pkgbuild(str(pkgbuild))

    cached = engine.cache.get_cached_result(str(pkgbuild), engine.scanner_version, engine.rule_version, config_flags=cache_flags(engine))
    assert spy_ai.called is False
    assert cached["fast_path_decision"]["action"] == "skip_update_scan"
    assert cached["trusted_baseline_updated"] is False
    assert cached["baseline_update_policy"] == "not_updated_skipped_update"
    assert history.get_snapshot("demo")["version"] == "1.0"


def test_explicit_cli_update_context_without_opt_in_does_not_fast_path(tmp_path):
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text(BASE_UPDATE.replace("pkgver=1.0", "pkgver=1.1").replace("demo-1.0.tar.gz", "demo-1.1.tar.gz").replace('sha256sums=("aaa")', 'sha256sums=("bbb")'))
    history = accepted_history(tmp_path)
    spy_ai = SpyAIAnalyzer()
    engine = AuraScanEngine(update_scan_policy="smart", scan_context="update", scan_context_source="explicit_cli")
    engine.cache = ScanCache(tmp_path / "cache")
    engine.analyzers = [history, SourceMetadataAnalyzer(), spy_ai]

    engine.scan_pkgbuild(str(pkgbuild))

    cached = engine.cache.get_cached_result(str(pkgbuild), engine.scanner_version, engine.rule_version, config_flags=cache_flags(engine))
    assert spy_ai.called is True
    assert cached["fast_path_decision"]["action"] == "use_full_scan"
    assert "context_not_eligible_for_fast_path" in cached["fast_path_decision"]["reason_codes"]
    assert cached["scan_context_authority"] == "user_asserted"
    assert cached["context_eligible_for_fast_path"] is False
    assert "user_asserted_context_requires_opt_in" in cached["context_proof_errors"]
    output = ScanReport.from_dict(cached).render_terminal(use_color=False)
    assert "Update context was provided manually." in output
    assert "not verified by a package transaction provider" in output


def test_explicit_cli_update_context_with_opt_in_can_fast_path_but_warns(tmp_path):
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text(BASE_UPDATE.replace("pkgver=1.0", "pkgver=1.1").replace("demo-1.0.tar.gz", "demo-1.1.tar.gz").replace('sha256sums=("aaa")', 'sha256sums=("bbb")'))
    history = accepted_history(tmp_path)
    spy_ai = SpyAIAnalyzer()
    engine = AuraScanEngine(
        update_scan_policy="smart",
        scan_context="update",
        scan_context_source="explicit_cli",
        allow_user_asserted_update_context=True,
    )
    engine.cache = ScanCache(tmp_path / "cache")
    engine.analyzers = [history, SourceMetadataAnalyzer(), spy_ai]

    engine.scan_pkgbuild(str(pkgbuild))

    cached = engine.cache.get_cached_result(str(pkgbuild), engine.scanner_version, engine.rule_version, config_flags=cache_flags(engine))
    assert spy_ai.called is False
    assert cached["fast_path_decision"]["action"] == "use_smart_fast_path"
    assert cached["scan_context_authority"] == "user_asserted"
    assert cached["context_eligible_for_fast_path"] is True
    output = ScanReport.from_dict(cached).render_terminal(use_color=False)
    assert "Update context was provided manually." in output


def test_verified_provider_context_can_fast_path_and_reports_verification(tmp_path):
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text(BASE_UPDATE.replace("pkgver=1.0", "pkgver=1.1").replace("demo-1.0.tar.gz", "demo-1.1.tar.gz").replace('sha256sums=("aaa")', 'sha256sums=("bbb")'))
    history = accepted_history(tmp_path)
    spy_ai = SpyAIAnalyzer()
    engine = AuraScanEngine(update_scan_policy="smart", scan_context="update", scan_context_source="pacman_hook")
    engine.cache = ScanCache(tmp_path / "cache")
    engine.analyzers = [history, SourceMetadataAnalyzer(), spy_ai]

    engine.scan_pkgbuild(str(pkgbuild))

    cached = engine.cache.get_cached_result(str(pkgbuild), engine.scanner_version, engine.rule_version, config_flags=cache_flags(engine))
    assert spy_ai.called is False
    assert cached["fast_path_decision"]["action"] == "use_smart_fast_path"
    assert cached["scan_context_authority"] == "verified_transaction_provider"
    assert cached["context_proof_errors"] == []
    output = ScanReport.from_dict(cached).render_terminal(use_color=False)
    assert "Verified package update context." in output


def test_auto_context_verified_local_db_update_can_fast_path(tmp_path):
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text(BASE_UPDATE.replace("pkgver=1.0", "pkgver=1.1").replace("demo-1.0.tar.gz", "demo-1.1.tar.gz").replace('sha256sums=("aaa")', 'sha256sums=("bbb")'))
    local_db = tmp_path / "local"
    write_local_db_entry(local_db, "demo", "1.0")
    history = accepted_history(tmp_path)
    spy_ai = SpyAIAnalyzer()
    engine = AuraScanEngine(
        update_scan_policy="smart",
        scan_context="auto",
        scan_context_source="local_package_db",
        local_package_db_root=local_db,
        version_compare=lambda _installed, _candidate: -1,
    )
    engine.cache = ScanCache(tmp_path / "cache")
    engine.analyzers = [history, SourceMetadataAnalyzer(), spy_ai]

    engine.scan_pkgbuild(str(pkgbuild))

    cached = engine.cache.get_cached_result(str(pkgbuild), engine.scanner_version, engine.rule_version, config_flags=cache_flags(engine))
    assert spy_ai.called is False
    assert cached["scan_context"] == "update"
    assert cached["scan_context_source"] == "local_package_db"
    assert cached["scan_context_authority"] == "verified_local_package_db"
    assert cached["context_provider_name"] == "local_package_db"
    assert cached["context_installed_package_present"] is True
    assert cached["context_installed_version"] == "1.0"
    assert cached["context_candidate_version"] == "1.1"
    assert cached["context_transaction_operation"] == "upgrade"
    assert cached["context_eligible_for_fast_path"] is True
    assert cached["fast_path_decision"]["action"] == "use_smart_fast_path"
    output = ScanReport.from_dict(cached).render_terminal(use_color=False)
    assert "Package update verified locally" in output
    assert "This does not prove the package is safe. It only proves the scan context." in output
    assert "accepted_baseline" not in output


def test_auto_context_install_uses_normal_scan(tmp_path):
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text(BASE_UPDATE)
    local_db = tmp_path / "local"
    local_db.mkdir()
    history = HistoryAnalyzer(tmp_path / "history.db")
    spy_ai = SpyAIAnalyzer()
    engine = AuraScanEngine(
        update_scan_policy="smart",
        scan_context="auto",
        scan_context_source="local_package_db",
        local_package_db_root=local_db,
        version_compare=lambda _installed, _candidate: -1,
    )
    engine.cache = ScanCache(tmp_path / "cache")
    engine.analyzers = [history, spy_ai]

    engine.scan_pkgbuild(str(pkgbuild))

    cached = engine.cache.get_cached_result(str(pkgbuild), engine.scanner_version, engine.rule_version, config_flags=cache_flags(engine))
    assert spy_ai.called is True
    assert cached["scan_context"] == "install"
    assert cached["context_installed_package_present"] is False
    assert cached["fast_path_decision"]["action"] == "use_full_scan"
    assert cached["trusted_baseline_updated"] is True


def test_auto_context_unknown_uses_normal_scan_and_plain_terminal(tmp_path):
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text(BASE_UPDATE)
    missing_db = tmp_path / "missing"
    history = HistoryAnalyzer(tmp_path / "history.db")
    spy_ai = SpyAIAnalyzer()
    engine = AuraScanEngine(
        update_scan_policy="smart",
        scan_context="auto",
        scan_context_source="local_package_db",
        local_package_db_root=missing_db,
        version_compare=lambda _installed, _candidate: -1,
    )
    engine.cache = ScanCache(tmp_path / "cache")
    engine.analyzers = [history, spy_ai]

    engine.scan_pkgbuild(str(pkgbuild))

    cached = engine.cache.get_cached_result(str(pkgbuild), engine.scanner_version, engine.rule_version, config_flags=cache_flags(engine))
    assert spy_ai.called is True
    assert cached["scan_context"] == "unknown"
    assert cached["context_eligible_for_fast_path"] is False
    assert "local_package_db_missing" in cached["context_proof_errors"]
    assert cached["fast_path_decision"]["action"] == "cannot_fast_path"
    output = ScanReport.from_dict(cached).render_terminal(use_color=False)
    assert "Package update context could not be proven" in output
    assert "local_package_db_missing" not in output


def test_auto_context_new_only_skip_requires_verified_update_and_preserves_baseline(tmp_path):
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text(BASE_UPDATE.replace("pkgver=1.0", "pkgver=1.1"))
    local_db = tmp_path / "local"
    write_local_db_entry(local_db, "demo", "1.0")
    history = accepted_history(tmp_path)
    spy_ai = SpyAIAnalyzer()
    engine = AuraScanEngine(
        update_scan_policy="new-only",
        scan_context="auto",
        scan_context_source="local_package_db",
        local_package_db_root=local_db,
        version_compare=lambda _installed, _candidate: -1,
    )
    engine.cache = ScanCache(tmp_path / "cache")
    engine.analyzers = [history, spy_ai]

    engine.scan_pkgbuild(str(pkgbuild))

    cached = engine.cache.get_cached_result(str(pkgbuild), engine.scanner_version, engine.rule_version, config_flags=cache_flags(engine))
    assert spy_ai.called is False
    assert cached["fast_path_decision"]["action"] == "skip_update_scan"
    assert cached["trusted_baseline_updated"] is False
    assert cached["baseline_update_policy"] == "not_updated_skipped_update"
    assert history.get_snapshot("demo")["version"] == "1.0"


def test_auto_context_full_policy_ignores_fast_path(tmp_path):
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text(BASE_UPDATE.replace("pkgver=1.0", "pkgver=1.1"))
    local_db = tmp_path / "local"
    write_local_db_entry(local_db, "demo", "1.0")
    history = accepted_history(tmp_path)
    spy_ai = SpyAIAnalyzer()
    engine = AuraScanEngine(
        update_scan_policy="full",
        scan_context="auto",
        scan_context_source="local_package_db",
        local_package_db_root=local_db,
        version_compare=lambda _installed, _candidate: -1,
    )
    engine.cache = ScanCache(tmp_path / "cache")
    engine.analyzers = [history, spy_ai]

    engine.scan_pkgbuild(str(pkgbuild))

    cached = engine.cache.get_cached_result(str(pkgbuild), engine.scanner_version, engine.rule_version, config_flags=cache_flags(engine))
    assert spy_ai.called is True
    assert cached["fast_path_decision"]["action"] == "use_full_scan"
    assert cached["fast_path_decision"]["reason_codes"] == ["policy_full"]


def test_auto_context_deep_static_overrides_fast_path(tmp_path):
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text(BASE_UPDATE.replace("pkgver=1.0", "pkgver=1.1"))
    local_db = tmp_path / "local"
    write_local_db_entry(local_db, "demo", "1.0")
    history = accepted_history(tmp_path)
    spy_ai = SpyAIAnalyzer()
    engine = AuraScanEngine(
        deep_static=True,
        update_scan_policy="smart",
        scan_context="auto",
        scan_context_source="local_package_db",
        local_package_db_root=local_db,
        version_compare=lambda _installed, _candidate: -1,
    )
    engine.cache = ScanCache(tmp_path / "cache")
    engine.analyzers = [history, spy_ai]

    engine.scan_pkgbuild(str(pkgbuild))

    cached = engine.cache.get_cached_result(str(pkgbuild), engine.scanner_version, engine.rule_version, config_flags=cache_flags(engine))
    assert spy_ai.called is True
    assert cached["fast_path_decision"]["action"] == "use_full_scan"
    assert cached["fast_path_decision"]["reason_codes"] == ["explicit_deep_static_requested"]


def test_auto_context_still_requires_accepted_baseline(tmp_path):
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text(BASE_UPDATE.replace("pkgver=1.0", "pkgver=1.1"))
    local_db = tmp_path / "local"
    write_local_db_entry(local_db, "demo", "1.0")
    history = HistoryAnalyzer(tmp_path / "history.db")
    spy_ai = SpyAIAnalyzer()
    engine = AuraScanEngine(
        update_scan_policy="smart",
        scan_context="auto",
        scan_context_source="local_package_db",
        local_package_db_root=local_db,
        version_compare=lambda _installed, _candidate: -1,
    )
    engine.cache = ScanCache(tmp_path / "cache")
    engine.analyzers = [history, spy_ai]

    engine.scan_pkgbuild(str(pkgbuild))

    cached = engine.cache.get_cached_result(str(pkgbuild), engine.scanner_version, engine.rule_version, config_flags=cache_flags(engine))
    assert spy_ai.called is True
    assert cached["fast_path_decision"]["action"] == "use_full_scan"
    assert "missing_accepted_baseline" in cached["fast_path_decision"]["reason_codes"]


def test_auto_context_trust_diff_still_blocks_fast_path(tmp_path):
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text(BASE_UPDATE.replace("example.invalid", "evil.example.invalid").replace("pkgver=1.0", "pkgver=1.1").replace('sha256sums=("aaa")', 'sha256sums=("bbb")'))
    local_db = tmp_path / "local"
    write_local_db_entry(local_db, "demo", "1.0")
    history = accepted_history(tmp_path)
    spy_ai = SpyAIAnalyzer()
    engine = AuraScanEngine(
        update_scan_policy="smart",
        scan_context="auto",
        scan_context_source="local_package_db",
        local_package_db_root=local_db,
        version_compare=lambda _installed, _candidate: -1,
    )
    engine.cache = ScanCache(tmp_path / "cache")
    engine.analyzers = [history, SourceMetadataAnalyzer(), spy_ai]

    engine.scan_pkgbuild(str(pkgbuild))

    cached = engine.cache.get_cached_result(str(pkgbuild), engine.scanner_version, engine.rule_version, config_flags=cache_flags(engine))
    assert spy_ai.called is True
    assert cached["fast_path_decision"]["action"] == "use_full_scan"
    assert "source_host_changed" in cached["fast_path_decision"]["reason_codes"]
