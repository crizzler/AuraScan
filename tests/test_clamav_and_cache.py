from pathlib import Path
import stat
import subprocess

from aurascan.analyzers.clamav import ClamAVAnalyzer
from aurascan.core.cache import ScanCache
from aurascan.core.models import Phase, Severity
from aurascan.core.trusted_tools import TrustedTool, TrustedToolError


def test_parses_infected_clamav_output_without_persisting_raw_output():
    output = "/tmp/pkg/bad: Eicar-Test-Signature FOUND\n"
    parsed = ClamAVAnalyzer().parse_output(1, output, phase=Phase.source_archive_scan)

    assert parsed.is_clean is False
    assert parsed.findings[0].file_path == "/tmp/pkg/bad"
    assert parsed.findings[0].severity == Severity.CRITICAL
    assert parsed.findings[0].phase == Phase.source_archive_scan
    assert parsed.raw_output == ""
    assert parsed.findings[0].raw_output is None
    assert parsed.findings[0].evidence_snippet == "ClamAV reported a matching malware signature"


def test_clamav_finding_includes_file_hash_when_available(tmp_path: Path):
    infected = tmp_path / "bad"
    infected.write_text("harmless test fixture")
    output = f"{infected}: Example-Test-Signature FOUND\n"

    parsed = ClamAVAnalyzer().parse_output(1, output, phase=Phase.unpacked_source_scan)

    assert parsed.findings[0].file_hash is not None
    assert parsed.findings[0].phase == Phase.unpacked_source_scan


def test_parses_clean_clamav_output_without_findings():
    parsed = ClamAVAnalyzer().parse_output(0, "/tmp/pkg: OK\n", phase=Phase.final_package_scan)

    assert parsed.is_clean is True
    assert parsed.findings == []
    assert parsed.raw_output == ""


def test_clamav_refuses_path_shadowing_before_runner(tmp_path: Path):
    calls = []
    analyzer = ClamAVAnalyzer(
        runner=lambda *args, **kwargs: calls.append((args, kwargs)),
        which=lambda _name: str(tmp_path / "clamscan"),
    )

    result = analyzer.analyze_package(str(tmp_path / "fixture.pkg.tar.zst"))

    assert result.is_safe is True
    assert result.msg == "trusted clamscan unavailable"
    assert calls == []


def test_clamav_uses_revalidated_absolute_tool_with_bounded_options(monkeypatch, tmp_path: Path):
    tool = TrustedTool(
        "clamscan",
        "/usr/bin/clamscan",
        1,
        2,
        0,
        0,
        stat.S_IFREG | 0o755,
    )
    calls = []
    monkeypatch.setattr(
        "aurascan.analyzers.clamav.capture_trusted_system_tool",
        lambda *_args, **_kwargs: tool,
    )
    monkeypatch.setattr(
        "aurascan.analyzers.clamav.revalidate_trusted_system_tool",
        lambda observed: observed,
    )

    def runner(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, "fixture: OK\n", "")

    result = ClamAVAnalyzer(runner=runner).analyze_package(str(tmp_path / "fixture"))

    assert result.is_safe is True
    assert len(calls) == 1
    assert calls[0][0][0] == "/usr/bin/clamscan"
    assert "--follow-file-symlinks=0" in calls[0][0]
    assert "--max-scansize=100M" in calls[0][0]
    assert "--alert-exceeds-max=yes" in calls[0][0]
    assert calls[0][0][-2:] == ["--", str(tmp_path / "fixture")]
    assert calls[0][1]["env"] == {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
    assert calls[0][1]["cwd"] == "/"


def test_clamav_terminates_options_before_attacker_controlled_path(monkeypatch):
    tool = TrustedTool(
        "clamscan",
        "/usr/bin/clamscan",
        1,
        2,
        0,
        0,
        stat.S_IFREG | 0o755,
    )
    calls = []
    monkeypatch.setattr(
        "aurascan.analyzers.clamav.capture_trusted_system_tool",
        lambda *_args, **_kwargs: tool,
    )
    monkeypatch.setattr(
        "aurascan.analyzers.clamav.revalidate_trusted_system_tool",
        lambda observed: observed,
    )

    def runner(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, "fixture: OK\n", "")

    result = ClamAVAnalyzer(runner=runner).analyze_package("--remove=yes")

    assert result.is_safe is True
    assert calls[0][-2:] == ["--", "--remove=yes"]


def test_clamav_tool_replacement_fails_before_runner(monkeypatch, tmp_path: Path):
    tool = TrustedTool(
        "clamscan",
        "/usr/bin/clamscan",
        1,
        2,
        0,
        0,
        stat.S_IFREG | 0o755,
    )
    calls = []
    monkeypatch.setattr(
        "aurascan.analyzers.clamav.capture_trusted_system_tool",
        lambda *_args, **_kwargs: tool,
    )
    monkeypatch.setattr(
        "aurascan.analyzers.clamav.revalidate_trusted_system_tool",
        lambda _tool: (_ for _ in ()).throw(TrustedToolError("fixture replacement")),
    )

    result = ClamAVAnalyzer(
        runner=lambda *args, **kwargs: calls.append((args, kwargs)),
    ).analyze_package(str(tmp_path / "fixture"))

    assert result.is_safe is True
    assert result.msg == "trusted clamscan unavailable"
    assert calls == []


def test_clamav_nonzero_error_is_an_incomplete_blocker(monkeypatch, tmp_path: Path):
    tool = TrustedTool(
        "clamscan",
        "/usr/bin/clamscan",
        1,
        2,
        0,
        0,
        stat.S_IFREG | 0o755,
    )
    monkeypatch.setattr(
        "aurascan.analyzers.clamav.capture_trusted_system_tool",
        lambda *_args, **_kwargs: tool,
    )
    monkeypatch.setattr(
        "aurascan.analyzers.clamav.revalidate_trusted_system_tool",
        lambda observed: observed,
    )

    result = ClamAVAnalyzer(
        runner=lambda args, **kwargs: subprocess.CompletedProcess(
            args,
            2,
            "",
            "\x1b[31mhttps://example.invalid/provider-secret\x1b[0m",
        ),
    ).analyze_package(str(tmp_path / "fixture"))

    assert result.is_safe is False
    assert result.findings[0].rule_id == "CLAMAV-INCOMPLETE"
    assert result.findings[0].blocks_installation is True
    assert "example.invalid" not in result.findings[0].explanation


def test_clamav_signature_and_path_are_terminal_safe():
    parsed = ClamAVAnalyzer().parse_output(
        1,
        "\x1b[31m/tmp/fixture\x1b[0m: Bad Signature; curl https://example.invalid FOUND\n",
    )

    finding = parsed.findings[0]
    assert "\x1b" not in finding.file_path
    assert "curl" not in finding.rule_id.lower()
    assert "https" not in finding.rule_id.lower()


def test_cache_hit_for_identical_file_and_clamav_db(tmp_path: Path):
    cache = ScanCache(tmp_path)
    target = tmp_path / "pkg.tar.zst"
    target.write_text("same content")
    result = {"findings": []}

    cache.set_cached_result(str(target), "2.5.0", "1.0.0", result, clamav_db_version="db1", scan_phase="final_package_scan")

    cached = cache.get_cached_result(str(target), "2.5.0", "1.0.0", clamav_db_version="db1", scan_phase="final_package_scan")
    assert cached == result


def test_cache_invalidates_when_clamav_db_changes(tmp_path: Path):
    cache = ScanCache(tmp_path)
    target = tmp_path / "pkg.tar.zst"
    target.write_text("same content")

    cache.set_cached_result(str(target), "2.5.0", "1.0.0", {"findings": []}, clamav_db_version="db1")

    assert cache.get_cached_result(str(target), "2.5.0", "1.0.0", clamav_db_version="db2") is None


def test_cache_invalidates_when_file_hash_changes(tmp_path: Path):
    cache = ScanCache(tmp_path)
    target = tmp_path / "pkg.tar.zst"
    target.write_text("old content")

    cache.set_cached_result(str(target), "2.5.0", "1.0.0", {"findings": []})
    target.write_text("new content")

    assert cache.get_cached_result(str(target), "2.5.0", "1.0.0") is None


def test_cache_uses_precomputed_exact_input_without_reopening_target(tmp_path: Path):
    cache = ScanCache(tmp_path)
    missing_target = tmp_path / "PKGBUILD"
    exact_input_digest = "a" * 64
    result = {"findings": [], "identity": "captured-input"}

    cache.set_cached_result(
        str(missing_target),
        "2.5.0",
        "1.3.0",
        result,
        input_digest=exact_input_digest,
    )

    assert cache.get_cached_result(
        str(missing_target),
        "2.5.0",
        "1.3.0",
        input_digest=exact_input_digest,
    ) == result


def test_cache_invalidates_when_precomputed_exact_input_changes(tmp_path: Path):
    cache = ScanCache(tmp_path)
    target = tmp_path / "PKGBUILD"
    target.write_text("pkgname=demo\n", encoding="utf-8")
    cache.set_cached_result(
        str(target),
        "2.5.0",
        "1.3.0",
        {"findings": []},
        input_digest="a" * 64,
    )

    assert cache.get_cached_result(
        str(target),
        "2.5.0",
        "1.3.0",
        input_digest="b" * 64,
    ) is None
