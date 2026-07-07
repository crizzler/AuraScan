from pathlib import Path

from aurascan.analyzers.clamav import ClamAVAnalyzer
from aurascan.core.cache import ScanCache
from aurascan.core.models import Phase, Severity


def test_parses_infected_clamav_output_with_phase_and_raw_output():
    output = "/tmp/pkg/bad: Eicar-Test-Signature FOUND\n"
    parsed = ClamAVAnalyzer().parse_output(1, output, phase=Phase.source_archive_scan)

    assert parsed.is_clean is False
    assert parsed.findings[0].file_path == "/tmp/pkg/bad"
    assert parsed.findings[0].severity == Severity.CRITICAL
    assert parsed.findings[0].phase == Phase.source_archive_scan
    assert parsed.findings[0].raw_output == output


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
    assert parsed.raw_output == "/tmp/pkg: OK\n"


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
