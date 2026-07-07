import io
import json
import re
import shutil
from pathlib import Path

import pytest

from aurascan.analyzers.deterministic import DeterministicAnalyzer
from aurascan.analyzers.history import HistoryAnalyzer
from aurascan.analyzers.source_metadata import SourceMetadataAnalyzer
from aurascan.core.cache import ScanCache
from aurascan.core.engine import AuraScanEngine
from aurascan.makepkg_wrapper import run as run_makepkg_wrapper


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "curated_packages"
SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
FORBIDDEN_LIVE_DANGER = [
    "rm -rf /",
    "mkfs.",
    "dd if=",
    ":(){",
    "/dev/tcp",
    "nc -e",
    "bash -i",
    "sh -i",
]
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


class Completed:
    def __init__(self, returncode=0):
        self.returncode = returncode


def manifests():
    items = []
    for path in sorted(FIXTURE_ROOT.iterdir()):
        manifest_path = path / "expected.json"
        if manifest_path.exists():
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["path"] = path
            items.append(manifest)
    return items


def manifests_for(mode):
    return [manifest for manifest in manifests() if mode in manifest.get("scan_modes", [])]


def manifest_ids(mode):
    return [manifest["scenario"] for manifest in manifests_for(mode)]


def engine_for(tmp_path, name, analyzers):
    engine = AuraScanEngine()
    engine.cache = ScanCache(tmp_path / f"cache-{name}")
    engine.analyzers = analyzers
    return engine


def rule_ids(report):
    return {finding["rule_id"] for finding in report.get("findings", [])}


def phases(report):
    return {finding["phase"] for finding in report.get("findings", [])}


def assert_report_expectations(report, manifest):
    expected = set(manifest.get("expected_rule_ids", []))
    absent = set(manifest.get("expected_absent_rule_ids", []))
    actual = rule_ids(report)
    assert expected <= actual
    assert absent.isdisjoint(actual)
    assert set(manifest.get("expected_phases", [])) <= phases(report)

    risk = report.get("risk_summary") or {}
    min_severity = manifest.get("expected_min_severity")
    if min_severity:
        assert SEVERITY_ORDER[risk["severity"]] >= SEVERITY_ORDER[min_severity]
    if manifest.get("expected_not_critical"):
        assert risk["severity"] != "CRITICAL"
    if manifest.get("expected_action"):
        assert risk["recommended_action"] == manifest["expected_action"]
    if "expected_manual_review" in manifest:
        assert risk["requires_manual_review"] is manifest["expected_manual_review"]


@pytest.mark.parametrize("manifest", manifests_for("fast"), ids=manifest_ids("fast"))
def test_curated_fast_scan_fixtures(manifest, tmp_path, capsys):
    engine = engine_for(
        tmp_path,
        manifest["scenario"],
        [DeterministicAnalyzer(), SourceMetadataAnalyzer()],
    )
    pkgbuild = manifest["path"] / "PKGBUILD"

    engine.scan_pkgbuild(
        str(pkgbuild),
        pkg_name=manifest["package_name"],
        pkg_ver=manifest.get("package_version", "unknown"),
    )

    output = strip_ansi(capsys.readouterr().out)
    report = engine.last_report
    assert_report_expectations(report, manifest)
    for snippet in manifest.get("expected_terminal_contains", []):
        assert snippet in output
    for expected_rule in manifest.get("expected_rule_ids", []):
        assert expected_rule in rule_ids(report)
        assert expected_rule not in output


@pytest.mark.parametrize("manifest", manifests_for("wrapper"), ids=manifest_ids("wrapper"))
def test_curated_makepkg_wrapper_fixtures(manifest, tmp_path):
    work = tmp_path / manifest["scenario"]
    shutil.copytree(manifest["path"], work)
    makepkg_calls = []

    def factory(**kwargs):
        engine = AuraScanEngine(**kwargs)
        engine.cache = ScanCache(tmp_path / f"wrapper-cache-{manifest['scenario']}")
        engine.analyzers = [DeterministicAnalyzer(), SourceMetadataAnalyzer()]
        return engine

    def runner(argv, **kwargs):
        makepkg_calls.append((argv, kwargs))
        return Completed(0)

    stdout = io.StringIO()
    code = run_makepkg_wrapper(
        ["--aurascan-json"],
        cwd=work,
        engine_factory=factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=runner,
        stdout=stdout,
        stderr=io.StringIO(),
    )
    envelope = json.loads(stdout.getvalue())
    report = envelope["scan_report"]

    assert envelope["action"] == manifest["expected_wrapper_action"]
    assert envelope["makepkg_invoked"] is manifest["expected_makepkg_invoked"]
    assert bool(makepkg_calls) is manifest["expected_makepkg_invoked"]
    if manifest["expected_makepkg_invoked"]:
        assert code == 0
    assert_report_expectations(report, manifest)
    assert set(manifest.get("expected_rule_ids", [])) <= rule_ids(report)
    if manifest.get("expected_manual_review_eligible"):
        assert envelope["review"]["review_eligible"] is True
        assert envelope["review"]["review_token"].startswith("arv-")
    if manifest.get("expected_hard_blocker"):
        assert envelope["review"]["non_acceptance_blockers"]


@pytest.mark.parametrize("manifest", manifests_for("history"), ids=manifest_ids("history"))
def test_curated_history_trust_diff_fixtures(manifest, tmp_path, capsys):
    history = HistoryAnalyzer(tmp_path / f"{manifest['scenario']}.db")
    previous = manifest["path"] / "previous" / "PKGBUILD"
    current = manifest["path"] / "current" / "PKGBUILD"
    history.analyze_pkgbuild(str(previous), previous.read_text(encoding="utf-8"))
    history.commit_pending_snapshots(scan_level="fast_default", scanner_version="test", rule_version="test")

    local_db = tmp_path / f"local-{manifest['scenario']}"
    write_local_db_entry(local_db, manifest["package_name"], manifest["installed_version"])
    engine = AuraScanEngine(
        update_scan_policy="smart",
        scan_context="auto",
        scan_context_source="local_package_db",
        local_package_db_root=local_db,
        version_compare=lambda _installed, _candidate: -1,
    )
    engine.cache = ScanCache(tmp_path / f"history-cache-{manifest['scenario']}")
    engine.analyzers = [history, SourceMetadataAnalyzer(), DeterministicAnalyzer()]

    engine.scan_pkgbuild(
        str(current),
        pkg_name=manifest["package_name"],
        pkg_ver=manifest.get("package_version", "unknown"),
    )

    output = strip_ansi(capsys.readouterr().out)
    report = engine.last_report
    assert_report_expectations(report, manifest)
    decision = report["fast_path_decision"]
    assert decision["action"] == manifest["expected_fast_path_action"]
    if manifest.get("expected_fast_path_allowed"):
        assert decision["action"] == "use_smart_fast_path"
    else:
        assert decision["action"] != "use_smart_fast_path"
    if manifest.get("expected_fast_path_reason"):
        assert manifest["expected_fast_path_reason"] in decision["reason_codes"]
    for snippet in manifest.get("expected_terminal_contains", []):
        assert snippet in output


@pytest.mark.parametrize("manifest", manifests_for("context"), ids=manifest_ids("context"))
def test_curated_context_fixtures(manifest, tmp_path):
    pkgbuild = manifest["path"] / "PKGBUILD"
    local_db = tmp_path / f"local-{manifest['scenario']}"
    write_local_db_entry(local_db, "curated-split", "1.0")
    write_local_db_entry(local_db, "curated-split-libs", "1.0")
    engine = AuraScanEngine(
        update_scan_policy="smart",
        scan_context="auto",
        scan_context_source="local_package_db",
        local_package_db_root=local_db,
        version_compare=lambda _installed, _candidate: -1,
    )
    engine.cache = ScanCache(tmp_path / f"context-cache-{manifest['scenario']}")
    engine.analyzers = [DeterministicAnalyzer(), SourceMetadataAnalyzer()]

    engine.scan_pkgbuild(
        str(pkgbuild),
        pkg_name=manifest["package_name"],
        pkg_ver=manifest.get("package_version", "unknown"),
    )

    report = engine.last_report
    assert_report_expectations(report, manifest)
    assert report["context_eligible_for_fast_path"] is False
    assert manifest["expected_context_error"] in report["context_proof_errors"]


def test_curated_fixture_manifests_are_valid_and_cover_core_categories():
    all_manifests = manifests()
    categories = {manifest["category"] for manifest in all_manifests}
    scan_modes = {mode for manifest in all_manifests for mode in manifest.get("scan_modes", [])}
    covered_rules = {rule for manifest in all_manifests for rule in manifest.get("expected_rule_ids", [])}

    assert {"benign", "suspicious_defanged", "malicious_defanged", "history", "context"} <= categories
    assert {"fast", "wrapper", "history", "context"} <= scan_modes
    assert {
        "NET-EXEC-001",
        "EXEC-B64-001",
        "CRED-SSH-001",
        "SYS-CHMOD-001",
        "SOURCE-META-WEAK-CHECKSUM",
        "HIST-SOURCE-HOST-CHANGED",
        "HIST-COMBINED-SUSPICIOUS-CHANGE",
        "EXEC-EVAL-001",
        "EXEC-EVAL-NET-001",
        "SYS-SYSTEMD-AUTO-001",
        "SYS-CRON-REBOOT-001",
    } <= covered_rules


def test_curated_fixtures_are_defanged_and_use_safe_domains():
    url_re = re.compile(r"\b(?:https?|git\+https)://([^/'\"\s)]+)")
    for path in FIXTURE_ROOT.rglob("*"):
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        lowered = text.lower()
        for forbidden in FORBIDDEN_LIVE_DANGER:
            assert forbidden not in lowered, f"{path} contains forbidden live-danger string {forbidden!r}"
        for host in url_re.findall(text):
            assert host.endswith("example.invalid"), f"{path} uses non-fixture host {host}"


def write_local_db_entry(root, name, version):
    entry = root / f"{name}-{version}"
    entry.mkdir(parents=True)
    (entry / "desc").write_text(f"%NAME%\n{name}\n\n%VERSION%\n{version}\n", encoding="utf-8")
    return entry


def strip_ansi(text):
    return ANSI_RE.sub("", text)
