from aurascan.analyzers.deep_static import DeepStaticAnalyzer
from aurascan.analyzers.ai_static import AIStaticAnalyzer
from aurascan.analyzers.deterministic import DeterministicAnalyzer
from aurascan.analyzers.history import HistoryAnalyzer
import aurascan.analyzers.history as history_module
from aurascan.analyzers.source_metadata import SourceMetadataAnalyzer
from aurascan.cli import build_parser
from aurascan.core.cache import ScanCache
from aurascan.core.engine import AuraScanEngine
import aurascan.core.engine as engine_module
from aurascan.core.models import AnalysisResult, Confidence, EvidenceQuality, Finding, Phase, ScanReport, Severity, Source
from aurascan.core.package_archive import PackageIdentityCapture, PACKAGE_IDENTITY_RESOLVED
from aurascan.core.update_policy import UpdateScanPolicy
from pathlib import Path
import io
import tarfile
import aurascan.__main__ as module_entrypoint
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


class HookSpyAnalyzer(NoopAnalyzer):
    def __init__(self):
        self.pkgbuild_calls = 0
        self.install_calls = 0
        self.install_contents = []

    def analyze_pkgbuild(self, pkgbuild_path, content):
        self.pkgbuild_calls += 1
        return AnalysisResult(True, "noop", [])

    def analyze_install_script(self, script_path, content):
        self.install_calls += 1
        self.install_contents.append(content)
        return AnalysisResult(True, "noop", [])


def cache_flags(engine):
    return dict(engine._cache_flags())


def cached_pkgbuild(engine, pkgbuild):
    return engine.cache.get_cached_result(
        str(pkgbuild),
        engine.scanner_version,
        engine.rule_version,
        config_flags=cache_flags(engine),
        input_digest=engine.last_scan_input_digest,
    )


def write_package_identity(path, name="fixture-tools", version="1:2.3-4"):
    payload = f"pkgname = {name}\npkgver = {version}\n".encode("utf-8")
    with tarfile.open(path, "w") as archive:
        info = tarfile.TarInfo(".PKGINFO")
        info.size = len(payload)
        info.mode = 0o644
        archive.addfile(info, io.BytesIO(payload))


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
    assert "aurascan upgrade" in help_text
    assert "aurascan config-drift" in help_text
    assert "aurascan ask" in help_text
    assert "aurascan agent" in help_text


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


def test_config_drift_subcommand_dispatches_before_scan_parser(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "load_env", lambda: None)
    monkeypatch.setattr(cli, "run_config_drift", lambda argv: calls.append(argv) or 0)

    try:
        cli.main(["config-drift", "--dry-run"])
    except SystemExit as exc:
        assert exc.code == 0

    assert calls == [["--dry-run"]]


def test_ask_subcommand_dispatches_before_scan_parser(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "load_env", lambda: None)
    monkeypatch.setattr(cli, "run_ask", lambda argv: calls.append(argv) or 0)

    try:
        cli.main(["ask", "--latest"])
    except SystemExit as exc:
        assert exc.code == 0

    assert calls == [["--latest"]]


def test_agent_subcommand_dispatches_before_scan_parser(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "load_env", lambda: None)
    monkeypatch.setattr(cli, "run_agent", lambda argv: calls.append(argv) or 0)

    try:
        cli.main(["agent", "--latest", "--access", "guarded"])
    except SystemExit as exc:
        assert exc.code == 0

    assert calls == [["--latest", "--access", "guarded"]]


def test_service_command_environment_keeps_ai_credentials_out_of_root_jobs(monkeypatch, tmp_path):
    calls = []
    user_config = tmp_path / ".env"
    monkeypatch.setattr(cli, "load_env", lambda paths=None: calls.append(paths))
    monkeypatch.setattr(cli, "user_env_path", lambda: user_config)

    cli.load_command_environment(["incidents", "--last-boot", "--capture-monitor"])
    cli.load_command_environment(["incidents", "--capture-safe-autopilot"])
    cli.load_command_environment(["agent", "--issue-root-session", "/tmp/request"])
    cli.load_command_environment(["agent", "--execute-request", "/tmp/request"])
    cli.load_command_environment(["agent", "--set-root-policy", "1"])
    assert calls == []

    cli.load_command_environment(["incidents", "--background-assist"])
    assert calls == [[user_config]]

    cli.load_command_environment(["incidents", "--current-boot"])
    assert calls[-1] is None


def test_python_module_entrypoint_delegates_to_cli(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "main", lambda: calls.append("called"))

    module_entrypoint.main()

    assert calls == ["called"]


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


def test_package_archive_uses_captured_pkginfo_identity(tmp_path, capsys, monkeypatch):
    package = tmp_path / "misleading-0-0-any.pkg.tar"
    write_package_identity(package)
    monkeypatch.setattr(
        engine_module,
        "capture_package_identity",
        lambda _path: PackageIdentityCapture(
            PACKAGE_IDENTITY_RESOLVED,
            name="fixture-tools",
            version="1:2.3-4",
        ),
    )
    engine = AuraScanEngine()
    engine.cache = ScanCache(tmp_path / "cache")
    engine.analyzers = [NoopAnalyzer()]

    assert engine.scan_package(str(package)) is True

    capsys.readouterr()
    assert engine.last_report["package_metadata"]["name"] == "fixture-tools"
    assert engine.last_report["package_metadata"]["version"] == "1:2.3-4"


def test_package_archive_symlink_fails_closed_in_deterministic_scan(tmp_path, capsys):
    package = tmp_path / "fixture-1-1-any.pkg.tar"
    write_package_identity(package, name="fixture", version="1-1")
    link = tmp_path / "linked-1-1-any.pkg.tar"
    link.symlink_to(package)
    engine = AuraScanEngine()
    engine.cache = ScanCache(tmp_path / "cache")
    engine.analyzers = [DeterministicAnalyzer()]

    assert engine.scan_package(str(link)) is False

    capsys.readouterr()
    blocker = next(
        finding
        for finding in engine.last_report["findings"]
        if finding["rule_id"] == "PACKAGE-INSTALL-HOOK-UNINSPECTED-001"
    )
    assert blocker["blocks_installation"] is True


def test_built_package_scan_does_not_cache_across_path_replacement(tmp_path, capsys):
    package = tmp_path / "demo-1.0-1-any.pkg.tar.zst"
    replacement = tmp_path / "replacement.pkg.tar.zst"
    package.write_bytes(b"first package bytes")
    replacement.write_bytes(b"other package bytes")

    class CountingAnalyzer(NoopAnalyzer):
        def __init__(self):
            self.calls = 0

        def analyze_package(self, pkg_path):
            self.calls += 1
            return AnalysisResult(True, "noop", [])

    analyzer = CountingAnalyzer()
    engine = AuraScanEngine()
    engine.cache = ScanCache(tmp_path / "cache")
    engine.analyzers = [analyzer]

    assert engine.scan_package(str(package)) is True
    replacement.replace(package)
    assert engine.scan_package(str(package)) is True

    capsys.readouterr()
    assert analyzer.calls == 2
    assert engine.cache.get_cached_result(
        str(package),
        engine.scanner_version,
        engine.rule_version,
        config_flags=cache_flags(engine),
    ) is None


def test_built_package_scan_ignores_legacy_path_cache_entry(tmp_path, capsys):
    package = tmp_path / "demo-tools-2.0-3-x86_64.pkg.tar.zst"
    package.write_bytes(b"same content")

    class CountingAnalyzer(NoopAnalyzer):
        def __init__(self):
            self.calls = 0

        def analyze_package(self, pkg_path):
            self.calls += 1
            return AnalysisResult(True, "fresh scan", [])

    analyzer = CountingAnalyzer()
    engine = AuraScanEngine()
    engine.cache = ScanCache(tmp_path / "cache")
    engine.analyzers = [analyzer]
    cached_report = {
        "schema_version": "1.0",
        "scanner_version": "2.5.0",
        "package_metadata": {"name": "stale-package", "version": "0-1"},
        "risk_summary": {
            "severity": "CRITICAL",
            "action": "BLOCKED",
            "recommended_action": "block",
            "requires_manual_review": False,
            "blocks_installation": True,
            "reason": "stale cached fixture",
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
    assert analyzer.calls == 1
    assert engine.last_report["package_metadata"]["name"] == "demo-tools"
    assert engine.last_report["package_metadata"]["version"] == "2.0-3"
    assert "Audit Complete: demo-tools 2.0-3" in output
    assert "(CACHED)" not in output


def test_engine_records_update_scan_policy_without_skipping_runtime_scans():
    engine = AuraScanEngine(update_scan_policy="smart")

    assert engine.update_scan_policy == UpdateScanPolicy.smart
    assert engine._cache_flags()["update_scan_policy"] == "smart"


def test_engine_cache_flags_separate_local_ai_configs_without_secrets(monkeypatch):
    for key in [
        "AURASCAN_AI_ENABLED",
        "AURASCAN_AI_PROVIDER",
        "AURASCAN_AI_MODEL",
        "AURASCAN_AI_BASE_URL",
        "AURASCAN_LOCAL_AI_API_KEY",
    ]:
        monkeypatch.delenv(key, raising=False)
    engine = AuraScanEngine()
    disabled = engine._cache_flags()

    monkeypatch.setenv("AURASCAN_AI_ENABLED", "1")
    monkeypatch.setenv("AURASCAN_AI_PROVIDER", "lmstudio")
    monkeypatch.setenv("AURASCAN_AI_MODEL", "fixture-model-a")
    monkeypatch.setenv("AURASCAN_AI_BASE_URL", "http://127.0.0.1:1234/v1")
    monkeypatch.setenv("AURASCAN_LOCAL_AI_API_KEY", "must-not-enter-cache")
    first_local = engine._cache_flags()

    monkeypatch.setenv("AURASCAN_AI_MODEL", "fixture-model-b")
    second_model = engine._cache_flags()
    monkeypatch.setenv("AURASCAN_AI_BASE_URL", "http://127.0.0.1:4321/v1")
    second_endpoint = engine._cache_flags()

    assert disabled != first_local
    assert first_local != second_model
    assert second_model != second_endpoint
    assert first_local["ai_ready"] is True
    assert first_local["ai_provider"] == "lmstudio"
    assert "must-not-enter-cache" not in repr(first_local)


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
    cached = cached_pkgbuild(engine, pkgbuild)
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

    cached = cached_pkgbuild(engine, pkgbuild)
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

    cached = cached_pkgbuild(engine, pkgbuild)
    assert cached["source_acquisition"] == []
    assert all(finding["rule_id"] != "SOURCE-UNSUPPORTED" for finding in cached["findings"])


def test_explicit_deep_static_mode_keeps_source_acquisition_findings(tmp_path):
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text("pkgname=demo\npkgver=1\n")
    engine = AuraScanEngine(deep_static=True)
    engine.cache = ScanCache(tmp_path / "cache")
    engine.analyzers = [LeakySourceAcquisitionAnalyzer()]

    engine.scan_pkgbuild(str(pkgbuild))

    assert engine.last_report["source_acquisition"] == [
        {"original": "git://example.invalid/repo.git", "status": "unsupported"}
    ]
    assert any(
        finding["rule_id"] == "SOURCE-UNSUPPORTED"
        for finding in engine.last_report["findings"]
    )
    assert cached_pkgbuild(engine, pkgbuild) is None


def test_deep_static_scans_never_reuse_or_write_pkgbuild_cache(tmp_path):
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text("pkgname=demo\npkgver=1\n", encoding="utf-8")

    class CountingAnalyzer(NoopAnalyzer):
        def __init__(self):
            self.calls = 0

        def analyze_pkgbuild(self, pkgbuild_path, content):
            self.calls += 1
            return AnalysisResult(True, "deep scan", [])

    analyzer = CountingAnalyzer()
    engine = AuraScanEngine(deep_static=True)
    engine.cache = ScanCache(tmp_path / "cache")
    engine.analyzers = [analyzer]

    assert engine.scan_pkgbuild(str(pkgbuild)) is True
    assert engine.scan_pkgbuild(str(pkgbuild)) is True

    assert analyzer.calls == 2
    assert cached_pkgbuild(engine, pkgbuild) is None


def test_pkgbuild_cache_is_bound_to_exact_pkgbuild_and_install_hook_bytes(tmp_path):
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_bytes(b"pkgname=demo\npkgver=1\ninstall=demo.install\n")
    hook = tmp_path / "demo.install"
    hook.write_bytes(b"post_install() { :; }\n")
    analyzer = HookSpyAnalyzer()
    engine = AuraScanEngine()
    engine.cache = ScanCache(tmp_path / "cache")
    engine.analyzers = [analyzer]

    assert engine.rule_version == "1.4.0"
    assert engine.scan_pkgbuild(str(pkgbuild)) is True
    first_digest = engine.last_scan_input_digest
    assert analyzer.pkgbuild_calls == 1
    assert analyzer.install_calls == 1

    assert engine.scan_pkgbuild(str(pkgbuild)) is True
    assert engine.last_scan_input_digest == first_digest
    assert analyzer.pkgbuild_calls == 1
    assert analyzer.install_calls == 1

    hook.write_bytes(b"post_install() { printf 'changed'; }\n")
    assert engine.scan_pkgbuild(str(pkgbuild)) is True
    hook_digest = engine.last_scan_input_digest
    assert hook_digest != first_digest
    assert analyzer.pkgbuild_calls == 2
    assert analyzer.install_calls == 2

    pkgbuild.write_bytes(pkgbuild.read_bytes().replace(b"\n", b"\r\n"))
    assert engine.scan_pkgbuild(str(pkgbuild)) is True
    assert engine.last_scan_input_digest != hook_digest
    assert analyzer.pkgbuild_calls == 3
    assert analyzer.install_calls == 3


def test_cache_write_cannot_bind_old_analysis_to_replaced_pkgbuild(tmp_path):
    pkgbuild = tmp_path / "PKGBUILD"
    original = b"pkgname=demo\npkgver=1\n"
    replacement = b"pkgname=demo\npkgver=2\n"
    pkgbuild.write_bytes(original)

    class ReplacingAnalyzer(NoopAnalyzer):
        def __init__(self):
            self.calls = 0

        def analyze_pkgbuild(self, pkgbuild_path, content):
            self.calls += 1
            if self.calls == 1:
                Path(pkgbuild_path).write_bytes(replacement)
            return AnalysisResult(True, "noop", [])

    analyzer = ReplacingAnalyzer()
    engine = AuraScanEngine()
    engine.cache = ScanCache(tmp_path / "cache")
    engine.analyzers = [analyzer]

    assert engine.scan_pkgbuild(str(pkgbuild)) is True
    first_digest = engine.last_scan_input_digest
    assert pkgbuild.read_bytes() == replacement

    assert engine.scan_pkgbuild(str(pkgbuild)) is True
    assert engine.last_scan_input_digest != first_digest
    assert analyzer.calls == 2


def test_missing_declared_install_hook_is_a_fixed_blocking_finding(tmp_path):
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text("pkgname=demo\npkgver=1\ninstall=missing.install\n", encoding="utf-8")
    analyzer = HookSpyAnalyzer()
    engine = AuraScanEngine()
    engine.cache = ScanCache(tmp_path / "cache")
    engine.analyzers = [analyzer]

    assert engine.scan_pkgbuild(str(pkgbuild), "demo", "1") is False

    finding = next(item for item in engine.last_report["findings"] if item["rule_id"] == "INSTALL-HOOK-UNINSPECTED-001")
    assert finding["blocks_installation"] is True
    assert finding["phase"] == "install_hook_static"
    assert finding["line_number"] == 3
    assert finding["evidence_snippet"] == "declared install hook was not safely inspected"
    assert "missing.install" not in finding["evidence_snippet"]
    assert analyzer.pkgbuild_calls == 1
    assert analyzer.install_calls == 0

    assert engine.scan_pkgbuild(str(pkgbuild), "demo", "1") is False
    assert analyzer.pkgbuild_calls == 1

    (tmp_path / "missing.install").write_text("post_install() { :; }\n", encoding="utf-8")
    assert engine.scan_pkgbuild(str(pkgbuild), "demo", "1") is True
    assert analyzer.pkgbuild_calls == 2
    assert analyzer.install_calls == 1


def test_deleted_and_symlinked_hook_states_never_reuse_a_cached_allow(tmp_path):
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text(
        "pkgname=demo\npkgver=1\ninstall=demo.install\n",
        encoding="utf-8",
    )
    hook = tmp_path / "demo.install"
    hook.write_text("post_install() { :; }\n", encoding="utf-8")
    analyzer = HookSpyAnalyzer()
    engine = AuraScanEngine()
    engine.cache = ScanCache(tmp_path / "cache")
    engine.analyzers = [analyzer]

    assert engine.scan_pkgbuild(str(pkgbuild), "demo", "1") is True
    resolved_digest = engine.last_scan_input_digest

    hook.unlink()
    assert engine.scan_pkgbuild(str(pkgbuild), "demo", "1") is False
    missing_digest = engine.last_scan_input_digest
    assert missing_digest != resolved_digest
    assert any(
        item["rule_id"] == "INSTALL-HOOK-UNINSPECTED-001"
        for item in engine.last_report["findings"]
    )

    target = tmp_path / "target.install"
    target.write_text("post_install() { :; }\n", encoding="utf-8")
    hook.symlink_to(target)
    assert engine.scan_pkgbuild(str(pkgbuild), "demo", "1") is False
    assert engine.last_scan_input_digest not in {missing_digest, resolved_digest}
    assert any(
        item["rule_id"] == "INSTALL-HOOK-UNINSPECTED-001"
        for item in engine.last_report["findings"]
    )


def test_new_only_update_cannot_skip_uninspected_install_hook_blocker(tmp_path):
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text(BASE_UPDATE.replace("pkgver=1.0", "pkgver=1.1") + "install=missing.install\n", encoding="utf-8")
    history = accepted_history(tmp_path)
    spy_ai = SpyAIAnalyzer()
    engine = AuraScanEngine(
        update_scan_policy="new-only",
        scan_context="update",
        scan_context_source="test_fixture",
    )
    engine.cache = ScanCache(tmp_path / "cache")
    engine.analyzers = [history, spy_ai]

    assert engine.scan_pkgbuild(str(pkgbuild)) is False

    assert spy_ai.called is False
    assert engine.last_report["fast_path_decision"]["action"] == "skip_update_scan"
    assert engine.last_report["risk_summary"]["blocks_installation"] is True
    assert any(
        finding["rule_id"] == "INSTALL-HOOK-UNINSPECTED-001"
        for finding in engine.last_report["findings"]
    )
    assert history.get_snapshot("demo")["version"] == "1.0"


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


def test_engine_reuses_one_hook_resolution_for_update_and_history_analysis(tmp_path, monkeypatch):
    pkgbuild = tmp_path / "PKGBUILD"
    hook = tmp_path / "demo.install"
    baseline = BASE_UPDATE + "install=demo.install\n"
    pkgbuild.write_text(baseline, encoding="utf-8")
    hook.write_text("post_install() { :; }\n", encoding="utf-8")
    history = HistoryAnalyzer(tmp_path / "history.db")
    history.analyze_pkgbuild(str(pkgbuild), baseline)
    history.commit_pending_snapshots(scan_level="fast_default")

    current = baseline.replace("pkgver=1.0", "pkgver=1.1")
    pkgbuild.write_text(current, encoding="utf-8")

    def unexpected_second_resolution(*args, **kwargs):
        raise AssertionError("HistoryAnalyzer re-resolved an engine-captured hook")

    monkeypatch.setattr(history_module, "resolve_install_hook", unexpected_second_resolution)
    engine = AuraScanEngine(
        update_scan_policy="smart",
        scan_context="update",
        scan_context_source="test_fixture",
    )
    engine.cache = ScanCache(tmp_path / "cache")
    engine.analyzers = [history]

    assert engine.scan_pkgbuild(str(pkgbuild)) is True
    assert engine.last_report["fast_path_decision"] is not None


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

    cached = cached_pkgbuild(engine, pkgbuild)
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

    cached = cached_pkgbuild(engine, pkgbuild)
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

    cached = cached_pkgbuild(engine, pkgbuild)
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

    cached = cached_pkgbuild(engine, pkgbuild)
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

    cached = cached_pkgbuild(engine, pkgbuild)
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

    cached = cached_pkgbuild(engine, pkgbuild)
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

    cached = cached_pkgbuild(engine, pkgbuild)
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

    cached = cached_pkgbuild(engine, pkgbuild)
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

    cached = cached_pkgbuild(engine, pkgbuild)
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

    cached = cached_pkgbuild(engine, pkgbuild)
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

    cached = cached_pkgbuild(engine, pkgbuild)
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

    cached = cached_pkgbuild(engine, pkgbuild)
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

    assert spy_ai.called is True
    assert engine.last_report["fast_path_decision"]["action"] == "use_full_scan"
    assert engine.last_report["fast_path_decision"]["reason_codes"] == ["explicit_deep_static_requested"]
    assert cached_pkgbuild(engine, pkgbuild) is None


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

    cached = cached_pkgbuild(engine, pkgbuild)
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

    cached = cached_pkgbuild(engine, pkgbuild)
    assert spy_ai.called is True
    assert cached["fast_path_decision"]["action"] == "use_full_scan"
    assert "source_host_changed" in cached["fast_path_decision"]["reason_codes"]
