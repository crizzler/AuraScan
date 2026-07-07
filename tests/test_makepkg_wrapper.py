import io
import json
import os
import shutil
from pathlib import Path

from aurascan.analyzers.deterministic import DeterministicAnalyzer
from aurascan.analyzers.history import HistoryAnalyzer, MANUAL_REVIEW_ACCEPTED_STATUS
from aurascan.analyzers.source_metadata import SourceMetadataAnalyzer
from aurascan.core.cache import ScanCache
from aurascan.core.engine import AuraScanEngine
from aurascan.core.review import ReviewDecisionStore, ScanFingerprint, get_non_acceptance_blockers
from aurascan.makepkg_wrapper import (
    EXIT_MANUAL_REVIEW,
    EXIT_MAKEPKG_NOT_FOUND,
    EXIT_SCAN_BLOCKED,
    EXIT_USAGE,
    locate_real_makepkg,
    parse_args,
    run,
)


FIXTURES = Path(__file__).parent / "fixtures" / "makepkg_wrapper"


class Completed:
    def __init__(self, returncode=0):
        self.returncode = returncode


class FakeEngine:
    def __init__(self, order, *, scan_ok=True, risk=None, report=None, scanner_version="test-scanner", rule_version="test-rules"):
        self.order = order
        self.scan_ok = scan_ok
        self.scanned_paths = []
        self.scanner_version = scanner_version
        self.rule_version = rule_version
        self.last_report = report or {
            "risk_summary": risk or {
                "blocks_installation": False,
                "requires_manual_review": False,
                "recommended_action": "allow",
                "action": "ALLOW",
            }
        }

    def scan_pkgbuild(self, pkgbuild_path):
        self.order.append("scan")
        self.scanned_paths.append(pkgbuild_path)
        return self.scan_ok


def fake_engine_factory(order, **engine_options):
    created = []

    def factory(**kwargs):
        created.append((kwargs, FakeEngine(order, **engine_options)))
        return created[-1][1]

    return factory, created


def fake_makepkg_runner(order, calls, returncode=0):
    def runner(argv, **kwargs):
        order.append("makepkg")
        calls.append((argv, kwargs))
        return Completed(returncode)

    return runner


def copy_fixture(tmp_path, name, child=None):
    source = FIXTURES / name
    if child:
        source = source / child
    target = tmp_path / "work"
    shutil.copytree(source, target)
    return target


def write_local_db_entry(root, name, version):
    entry = root / f"{name}-{version}"
    entry.mkdir(parents=True)
    (entry / "desc").write_text(f"%NAME%\n{name}\n\n%VERSION%\n{version}\n")
    return entry


def real_engine_factory(tmp_path, *, analyzers, local_db=None, version_compare=None):
    created = []

    def factory(**kwargs):
        engine = AuraScanEngine(
            **kwargs,
            local_package_db_root=local_db,
            version_compare=version_compare or (lambda _installed, _candidate: None),
        )
        engine.cache = ScanCache(tmp_path / f"cache-{len(created)}")
        engine.analyzers = analyzers
        created.append(engine)
        return engine

    return factory, created


def accepted_history_from_pkgbuild(tmp_path, pkgbuild_path):
    history = HistoryAnalyzer(tmp_path / f"history-{pkgbuild_path.parent.name}.db")
    history.analyze_pkgbuild(str(pkgbuild_path), pkgbuild_path.read_text())
    history.commit_pending_snapshots(scan_level="fast_default", scanner_version="test", rule_version="test")
    return history


def manual_review_report(*, version="1.0", finding_suffix="", extra_findings=None):
    findings = [{
        "finding_id": f"finding-manual{finding_suffix}",
        "rule_id": "SOURCE-META-VALIDPGPKEYS-MISSING",
        "package_name": "demo",
        "package_version": version,
        "phase": "pkgbuild_static",
        "source": "deterministic_rule",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "evidence_quality": "strong_heuristic",
        "file_path": "PKGBUILD",
        "line_number": 5,
        "evidence_snippet": f"signature present{finding_suffix}",
        "explanation": "Signature is present but signing key metadata is missing.",
        "recommendation": "Review signature metadata.",
        "blocks_installation": False,
        "requires_manual_review": True,
    }]
    findings.extend(extra_findings or [])
    return {
        "schema_version": "1.0",
        "scanner_version": "test-scanner",
        "package_metadata": {"name": "demo", "version": version},
        "risk_summary": {
            "severity": "MEDIUM",
            "action": "MANUAL_REVIEW",
            "recommended_action": "manual_review",
            "requires_manual_review": True,
            "blocks_installation": False,
            "reason": "manual review fixture",
        },
        "findings": findings,
        "messages": [],
        "source_acquisition": [],
    }


def hard_block_report(rule_id="NET-EXEC-001", source="deterministic_rule", severity="CRITICAL"):
    return {
        "schema_version": "1.0",
        "scanner_version": "test-scanner",
        "package_metadata": {"name": "demo", "version": "1.0"},
        "risk_summary": {
            "severity": severity,
            "action": "BLOCKED",
            "recommended_action": "block",
            "requires_manual_review": False,
            "blocks_installation": True,
            "reason": "hard blocker fixture",
        },
        "findings": [{
            "finding_id": "finding-blocker",
            "rule_id": rule_id,
            "package_name": "demo",
            "package_version": "1.0",
            "phase": "pkgbuild_static",
            "source": source,
            "severity": severity,
            "confidence": "CONFIRMED",
            "evidence_quality": "confirmed_static_pattern",
            "file_path": "PKGBUILD",
            "evidence_snippet": "blocked",
            "explanation": "Hard blocker",
            "recommendation": "Do not build.",
            "blocks_installation": True,
            "requires_manual_review": False,
        }],
        "messages": [],
        "source_acquisition": [],
    }


def blocker_finding(rule_id, *, source="deterministic_rule", severity="CRITICAL", blocks=False):
    return {
        "finding_id": f"finding-{rule_id}",
        "rule_id": rule_id,
        "package_name": "demo",
        "package_version": "1.0",
        "phase": "pkgbuild_static",
        "source": source,
        "severity": severity,
        "confidence": "CONFIRMED",
        "evidence_quality": "confirmed_static_pattern",
        "file_path": "PKGBUILD",
        "evidence_snippet": "blocked",
        "explanation": "Hard blocker",
        "recommendation": "Do not build.",
        "blocks_installation": blocks,
        "requires_manual_review": True,
    }


def review_fingerprint(*, package_name="demo", version="1.0", scan_suffix=""):
    return ScanFingerprint(
        package_name=package_name,
        package_version=version,
        pkgbuild_hash=f"pkgbuild-hash{scan_suffix}",
        source_metadata_hash=f"source-hash{scan_suffix}",
        scan_fingerprint=f"scan-fingerprint-{package_name}-{version}{scan_suffix}",
        finding_ids=[f"finding-manual{scan_suffix}"],
        finding_fingerprints=[f"finding-fingerprint{scan_suffix}"],
        scanner_version="test-scanner",
        rule_version="test-rules",
    )


def test_parse_args_strips_aurascan_flags_and_preserves_makepkg_args():
    options = parse_args([
        "--aurascan-deep-static",
        "--aurascan-update-scan-policy=smart",
        "--aurascan-scan-context",
        "auto",
        "--aurascan-trusted-key-dir",
        "/tmp/keydir",
        "--syncdeps",
        "--",
        "--aurascan-json",
    ])

    assert options.deep_static is True
    assert options.update_scan_policy == "smart"
    assert options.scan_context == "auto"
    assert options.trusted_key_dirs == ["/tmp/keydir"]
    assert options.makepkg_args == ["--syncdeps", "--aurascan-json"]


def test_wrapper_finds_pkgbuild_in_current_directory_and_calls_scan_first(tmp_path):
    (tmp_path / "PKGBUILD").write_text("pkgname=demo\npkgver=1\n")
    order = []
    makepkg_calls = []
    factory, created = fake_engine_factory(order)

    code = run(
        ["--syncdeps"],
        cwd=tmp_path,
        engine_factory=factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner(order, makepkg_calls),
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )

    assert code == 0
    assert order == ["scan", "makepkg"]
    assert created[0][1].scanned_paths == [str(tmp_path / "PKGBUILD")]
    assert makepkg_calls[0][0] == ["/usr/bin/makepkg", "--syncdeps"]


def test_wrapper_errors_when_pkgbuild_missing(tmp_path):
    order = []
    factory, _created = fake_engine_factory(order)
    stderr = io.StringIO()

    code = run(
        [],
        cwd=tmp_path,
        engine_factory=factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner(order, []),
        stdout=io.StringIO(),
        stderr=stderr,
    )

    assert code == EXIT_USAGE
    assert "PKGBUILD not found" in stderr.getvalue()
    assert order == []


def test_wrapper_does_not_pass_aurascan_flags_to_makepkg(tmp_path):
    (tmp_path / "PKGBUILD").write_text("pkgname=demo\npkgver=1\n")
    order = []
    makepkg_calls = []
    factory, created = fake_engine_factory(order)

    run(
        [
            "--aurascan-deep-static",
            "--aurascan-offline",
            "--aurascan-no-auto-key-fetch",
            "--aurascan-keyserver",
            "https://keys.example.invalid",
            "--aurascan-verbose",
            "--install",
            "--noconfirm",
        ],
        cwd=tmp_path,
        engine_factory=factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner(order, makepkg_calls),
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )

    kwargs = created[0][0]
    assert kwargs["deep_static"] is True
    assert kwargs["offline"] is True
    assert kwargs["auto_key_fetch"] is False
    assert kwargs["keyserver"] == "https://keys.example.invalid"
    assert kwargs["verbose"] is True
    assert makepkg_calls[0][0] == ["/usr/bin/makepkg", "--install", "--noconfirm"]


def test_wrapper_does_not_call_makepkg_when_scan_blocks(tmp_path):
    (tmp_path / "PKGBUILD").write_text("pkgname=demo\npkgver=1\n")
    order = []
    factory, _created = fake_engine_factory(
        order,
        scan_ok=False,
        risk={"blocks_installation": True, "requires_manual_review": False, "action": "BLOCKED"},
    )
    stdout = io.StringIO()

    code = run(
        [],
        cwd=tmp_path,
        engine_factory=factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner(order, []),
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert code == EXIT_SCAN_BLOCKED
    assert order == ["scan"]
    assert "AuraScan blocked makepkg" in stdout.getvalue()


def test_wrapper_does_not_call_makepkg_when_manual_review_is_needed(tmp_path):
    (tmp_path / "PKGBUILD").write_text("pkgname=demo\npkgver=1\n")
    order = []
    factory, _created = fake_engine_factory(
        order,
        risk={"blocks_installation": False, "requires_manual_review": True, "recommended_action": "manual_review"},
    )
    stdout = io.StringIO()

    code = run(
        [],
        cwd=tmp_path,
        engine_factory=factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner(order, []),
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert code == EXIT_MANUAL_REVIEW
    assert order == ["scan"]
    assert "AuraScan needs review before makepkg" in stdout.getvalue()


def test_wrapper_returns_makepkg_exit_code(tmp_path):
    (tmp_path / "PKGBUILD").write_text("pkgname=demo\npkgver=1\n")
    order = []
    factory, _created = fake_engine_factory(order)

    code = run(
        [],
        cwd=tmp_path,
        engine_factory=factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner(order, [], returncode=42),
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )

    assert code == 42


def test_wrapper_returns_clear_error_when_makepkg_not_found(tmp_path):
    (tmp_path / "PKGBUILD").write_text("pkgname=demo\npkgver=1\n")
    order = []
    factory, _created = fake_engine_factory(order)
    stderr = io.StringIO()

    code = run(
        [],
        cwd=tmp_path,
        engine_factory=factory,
        makepkg_locator=lambda: "",
        subprocess_run=fake_makepkg_runner(order, []),
        stdout=io.StringIO(),
        stderr=stderr,
    )

    assert code == EXIT_MAKEPKG_NOT_FOUND
    assert order == ["scan"]
    assert "Could not locate" in stderr.getvalue()


def test_locate_real_makepkg_avoids_recursion(tmp_path):
    recursive_dir = tmp_path / "recursive"
    real_dir = tmp_path / "real"
    recursive_dir.mkdir()
    real_dir.mkdir()
    recursive = recursive_dir / "makepkg"
    real = real_dir / "makepkg"
    recursive.write_text("#!/bin/sh\n")
    real.write_text("#!/bin/sh\n")
    recursive.chmod(0o755)
    real.chmod(0o755)

    found = locate_real_makepkg(
        current_executable=str(recursive),
        path_env=os.pathsep.join([str(recursive_dir), str(real_dir)]),
    )

    assert found == str(real)


def test_entry_point_is_registered():
    pyproject = Path("pyproject.toml").read_text()

    assert 'aurascan-makepkg = "aurascan.makepkg_wrapper:main"' in pyproject


def test_benign_fixture_allows_makepkg_without_executing_package_code(tmp_path):
    work = copy_fixture(tmp_path, "benign")
    local_db = tmp_path / "local"
    local_db.mkdir()
    factory, created = real_engine_factory(
        tmp_path,
        analyzers=[DeterministicAnalyzer()],
        local_db=local_db,
    )
    makepkg_calls = []

    code = run(
        ["--syncdeps"],
        cwd=work,
        engine_factory=factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner([], makepkg_calls),
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )

    assert code == 0
    assert makepkg_calls
    assert not (work / "package-code-ran").exists()
    assert created[0].last_report["risk_summary"]["blocks_installation"] is False


def test_malicious_build_time_fixture_blocks_before_makepkg(tmp_path):
    work = copy_fixture(tmp_path, "malicious-build-time")
    local_db = tmp_path / "local"
    local_db.mkdir()
    factory, _created = real_engine_factory(
        tmp_path,
        analyzers=[DeterministicAnalyzer()],
        local_db=local_db,
    )
    makepkg_calls = []

    code = run(
        [],
        cwd=work,
        engine_factory=factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner([], makepkg_calls),
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )

    assert code == EXIT_SCAN_BLOCKED
    assert makepkg_calls == []


def test_credential_reference_fixture_blocks_before_makepkg(tmp_path):
    work = copy_fixture(tmp_path, "credential-reference")
    local_db = tmp_path / "local"
    local_db.mkdir()
    factory, _created = real_engine_factory(
        tmp_path,
        analyzers=[DeterministicAnalyzer()],
        local_db=local_db,
    )
    makepkg_calls = []

    code = run(
        [],
        cwd=work,
        engine_factory=factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner([], makepkg_calls),
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )

    assert code == EXIT_SCAN_BLOCKED
    assert makepkg_calls == []


def test_declared_install_hook_fixture_is_scanned_before_makepkg(tmp_path):
    work = copy_fixture(tmp_path, "install-hook")
    local_db = tmp_path / "local"
    local_db.mkdir()
    factory, created = real_engine_factory(
        tmp_path,
        analyzers=[DeterministicAnalyzer()],
        local_db=local_db,
    )
    makepkg_calls = []

    code = run(
        [],
        cwd=work,
        engine_factory=factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner([], makepkg_calls),
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )

    report = created[0].last_report
    assert code == EXIT_SCAN_BLOCKED
    assert makepkg_calls == []
    assert any(finding["phase"] == "install_hook_static" for finding in report["findings"])


def test_wrapper_smart_auto_uses_verified_local_db_context_when_proven(tmp_path):
    work = copy_fixture(tmp_path, "normal-version-bump", "current")
    previous = FIXTURES / "normal-version-bump" / "previous" / "PKGBUILD"
    history = accepted_history_from_pkgbuild(tmp_path, previous)
    local_db = tmp_path / "local"
    write_local_db_entry(local_db, "aurascan-wrapper-normal-bump", "1.0-1")
    factory, created = real_engine_factory(
        tmp_path,
        analyzers=[history, SourceMetadataAnalyzer()],
        local_db=local_db,
        version_compare=lambda _installed, _candidate: -1,
    )

    code = run(
        ["--aurascan-update-scan-policy", "smart"],
        cwd=work,
        engine_factory=factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner([], []),
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )

    report = created[0].last_report
    assert code == 0
    assert report["scan_context_source"] == "local_package_db"
    assert report["context_eligible_for_fast_path"] is True
    assert report["fast_path_decision"]["action"] == "use_smart_fast_path"
    assert report["fast_path_decision"]["technical_details"]["trust_boundary_diff"]["classification"] == "likely_normal_version_bump"


def test_wrapper_suspicious_update_fixture_requires_review_and_skips_makepkg(tmp_path):
    work = copy_fixture(tmp_path, "suspicious-update", "current")
    previous = FIXTURES / "suspicious-update" / "previous" / "PKGBUILD"
    history = accepted_history_from_pkgbuild(tmp_path, previous)
    local_db = tmp_path / "local"
    write_local_db_entry(local_db, "aurascan-wrapper-suspicious-update", "1.0-1")
    factory, created = real_engine_factory(
        tmp_path,
        analyzers=[history, SourceMetadataAnalyzer()],
        local_db=local_db,
        version_compare=lambda _installed, _candidate: -1,
    )
    makepkg_calls = []

    code = run(
        ["--aurascan-update-scan-policy", "smart"],
        cwd=work,
        engine_factory=factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner([], makepkg_calls),
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )

    report = created[0].last_report
    assert code == EXIT_MANUAL_REVIEW
    assert makepkg_calls == []
    assert report["fast_path_decision"]["action"] == "use_full_scan"
    assert "source_host_changed" in report["fast_path_decision"]["reason_codes"]


def test_wrapper_split_package_ambiguity_falls_back_to_normal_scan(tmp_path):
    work = copy_fixture(tmp_path, "split-ambiguous")
    local_db = tmp_path / "local"
    write_local_db_entry(local_db, "aurascan-wrapper-split", "1.0-1")
    write_local_db_entry(local_db, "aurascan-wrapper-split-libs", "1.0-1")
    factory, created = real_engine_factory(
        tmp_path,
        analyzers=[DeterministicAnalyzer()],
        local_db=local_db,
        version_compare=lambda _installed, _candidate: -1,
    )
    makepkg_calls = []

    code = run(
        ["--aurascan-update-scan-policy", "smart"],
        cwd=work,
        engine_factory=factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner([], makepkg_calls),
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )

    report = created[0].last_report
    assert code == 0
    assert makepkg_calls
    assert report["scan_context"] == "unknown"
    assert report["context_eligible_for_fast_path"] is False
    assert "ambiguous_split_package_mapping" in report["context_proof_errors"]


def test_wrapper_user_asserted_context_requires_allow_flag_for_fast_path(tmp_path):
    work = copy_fixture(tmp_path, "normal-version-bump", "current")
    previous = FIXTURES / "normal-version-bump" / "previous" / "PKGBUILD"
    history = accepted_history_from_pkgbuild(tmp_path, previous)
    factory, created = real_engine_factory(
        tmp_path,
        analyzers=[history, SourceMetadataAnalyzer()],
        version_compare=lambda _installed, _candidate: -1,
    )

    code = run(
        ["--aurascan-update-scan-policy", "smart", "--aurascan-scan-context", "update"],
        cwd=work,
        engine_factory=factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner([], []),
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )

    report = created[0].last_report
    assert code == EXIT_MANUAL_REVIEW
    assert report["scan_context_authority"] == "user_asserted"
    assert report["context_eligible_for_fast_path"] is False
    assert report["fast_path_decision"]["action"] == "use_full_scan"
    assert "user_asserted_context_requires_opt_in" in report["context_proof_errors"]


def test_manual_review_report_produces_review_token_and_json_fields(tmp_path):
    (tmp_path / "PKGBUILD").write_text("pkgname=demo\npkgver=1.0\n")
    order = []
    report = manual_review_report()
    factory, created = fake_engine_factory(order, report=report)
    stdout = io.StringIO()

    code = run(
        [],
        cwd=tmp_path,
        engine_factory=factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner(order, []),
        stdout=stdout,
        stderr=io.StringIO(),
    )

    annotated = created[0][1].last_report
    assert code == EXIT_MANUAL_REVIEW
    assert order == ["scan"]
    assert annotated["review_acceptance_required"] is True
    assert annotated["review_acceptance_eligible"] is True
    assert annotated["review_token"].startswith("arv-")
    assert annotated["acceptance_status"] == "review_required"
    assert annotated["acceptance_scope"] == "exact_scan"
    assert annotated["accepted_finding_ids"] == ["finding-manual"]
    assert annotated["non_acceptance_blockers"] == []
    output = stdout.getvalue()
    assert "AuraScan needs review before makepkg" in output
    assert "What AuraScan checked" in output
    assert "Review token:" in output


def test_valid_review_token_allows_makepkg_and_records_sqlite_decision(tmp_path):
    (tmp_path / "PKGBUILD").write_text("pkgname=demo\npkgver=1.0\n")
    store = ReviewDecisionStore(tmp_path / "review.db")
    order = []
    first_factory, first_created = fake_engine_factory(order, report=manual_review_report())

    first_code = run(
        [],
        cwd=tmp_path,
        engine_factory=first_factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner(order, []),
        review_store=store,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )
    token = first_created[0][1].last_report["review_token"]

    makepkg_calls = []
    second_factory, second_created = fake_engine_factory(order, report=manual_review_report())
    second_stdout = io.StringIO()
    second_code = run(
        [
            "--aurascan-accept-review",
            token,
            "--aurascan-review-reason",
            "reviewed upstream change",
            "--install",
            "--noconfirm",
        ],
        cwd=tmp_path,
        engine_factory=second_factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner(order, makepkg_calls),
        review_store=store,
        stdout=second_stdout,
        stderr=io.StringIO(),
    )

    decisions = store.list_decisions()
    assert first_code == EXIT_MANUAL_REVIEW
    assert second_code == 0
    assert makepkg_calls[0][0] == ["/usr/bin/makepkg", "--install", "--noconfirm"]
    assert "Review accepted for this scan" in second_stdout.getvalue()
    assert second_created[0][1].last_report["acceptance_status"] == "accepted_once"
    assert len(decisions) == 1
    assert decisions[0].review_token == token
    assert decisions[0].reason == "reviewed upstream change"
    assert decisions[0].one_time is True
    assert decisions[0].used_at is not None


def test_invalid_review_token_blocks_makepkg(tmp_path):
    (tmp_path / "PKGBUILD").write_text("pkgname=demo\npkgver=1.0\n")
    store = ReviewDecisionStore(tmp_path / "review.db")
    order = []
    makepkg_calls = []
    factory, created = fake_engine_factory(order, report=manual_review_report())
    stdout = io.StringIO()

    code = run(
        ["--aurascan-accept-review", "arv-invalid-token"],
        cwd=tmp_path,
        engine_factory=factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner(order, makepkg_calls),
        review_store=store,
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert code == EXIT_MANUAL_REVIEW
    assert makepkg_calls == []
    assert created[0][1].last_report["acceptance_status"] == "token_mismatch"
    assert "Review acceptance no longer matches this scan" in stdout.getvalue()


def test_review_token_invalid_if_pkgbuild_hash_changes(tmp_path):
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text("pkgname=demo\npkgver=1.0\n")
    store = ReviewDecisionStore(tmp_path / "review.db")
    order = []
    first_factory, first_created = fake_engine_factory(order, report=manual_review_report())

    run(
        [],
        cwd=tmp_path,
        engine_factory=first_factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner(order, []),
        review_store=store,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )
    token = first_created[0][1].last_report["review_token"]
    pkgbuild.write_text("pkgname=demo\npkgver=1.0\npkgrel=2\n")

    makepkg_calls = []
    second_factory, second_created = fake_engine_factory(order, report=manual_review_report())
    code = run(
        ["--aurascan-accept-review", token],
        cwd=tmp_path,
        engine_factory=second_factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner(order, makepkg_calls),
        review_store=store,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )

    assert code == EXIT_MANUAL_REVIEW
    assert makepkg_calls == []
    assert second_created[0][1].last_report["acceptance_status"] == "token_mismatch"


def test_review_token_invalid_if_finding_set_changes(tmp_path):
    (tmp_path / "PKGBUILD").write_text("pkgname=demo\npkgver=1.0\n")
    store = ReviewDecisionStore(tmp_path / "review.db")
    order = []
    first_factory, first_created = fake_engine_factory(order, report=manual_review_report())

    run(
        [],
        cwd=tmp_path,
        engine_factory=first_factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner(order, []),
        review_store=store,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )
    token = first_created[0][1].last_report["review_token"]

    changed = manual_review_report(finding_suffix="-changed")
    second_factory, second_created = fake_engine_factory(order, report=changed)
    code = run(
        ["--aurascan-accept-review", token],
        cwd=tmp_path,
        engine_factory=second_factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner(order, []),
        review_store=store,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )

    assert code == EXIT_MANUAL_REVIEW
    assert second_created[0][1].last_report["acceptance_status"] == "token_mismatch"


def test_review_token_invalid_if_package_version_changes_for_exact_scan(tmp_path):
    (tmp_path / "PKGBUILD").write_text("pkgname=demo\npkgver=1.0\n")
    store = ReviewDecisionStore(tmp_path / "review.db")
    order = []
    first_factory, first_created = fake_engine_factory(order, report=manual_review_report(version="1.0"))

    run(
        [],
        cwd=tmp_path,
        engine_factory=first_factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner(order, []),
        review_store=store,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )
    token = first_created[0][1].last_report["review_token"]

    second_factory, second_created = fake_engine_factory(order, report=manual_review_report(version="2.0"))
    code = run(
        ["--aurascan-accept-review", token],
        cwd=tmp_path,
        engine_factory=second_factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner(order, []),
        review_store=store,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )

    assert code == EXIT_MANUAL_REVIEW
    assert second_created[0][1].last_report["acceptance_status"] == "token_mismatch"


def test_review_token_invalid_if_scanner_or_rule_version_changes(tmp_path):
    (tmp_path / "PKGBUILD").write_text("pkgname=demo\npkgver=1.0\n")
    store = ReviewDecisionStore(tmp_path / "review.db")
    order = []
    first_factory, first_created = fake_engine_factory(
        order,
        report=manual_review_report(),
        scanner_version="scanner-a",
        rule_version="rules-a",
    )

    run(
        [],
        cwd=tmp_path,
        engine_factory=first_factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner(order, []),
        review_store=store,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )
    token = first_created[0][1].last_report["review_token"]

    second_factory, second_created = fake_engine_factory(
        order,
        report=manual_review_report(),
        scanner_version="scanner-b",
        rule_version="rules-a",
    )
    code = run(
        ["--aurascan-accept-review", token],
        cwd=tmp_path,
        engine_factory=second_factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner(order, []),
        review_store=store,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )

    assert code == EXIT_MANUAL_REVIEW
    assert second_created[0][1].last_report["acceptance_status"] == "token_mismatch"


def test_hard_blocker_report_cannot_be_review_accepted(tmp_path):
    (tmp_path / "PKGBUILD").write_text("pkgname=demo\npkgver=1.0\n")
    order = []
    makepkg_calls = []
    factory, created = fake_engine_factory(order, scan_ok=False, report=hard_block_report())
    stdout = io.StringIO()

    code = run(
        ["--aurascan-accept-review", "arv-anything"],
        cwd=tmp_path,
        engine_factory=factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner(order, makepkg_calls),
        stdout=stdout,
        stderr=io.StringIO(),
    )

    report = created[0][1].last_report
    assert code == EXIT_SCAN_BLOCKED
    assert makepkg_calls == []
    assert report["review_acceptance_eligible"] is False
    assert report["acceptance_status"] == "hard_blocker"
    assert report["non_acceptance_blockers"][0]["rule_id"] == "NET-EXEC-001"
    assert "AuraScan cannot accept this review" in stdout.getvalue()


def test_non_acceptance_blockers_include_clamav_checksum_signature_archive_and_blocking_findings():
    report = manual_review_report(extra_findings=[
        blocker_finding("CLAMAV-FOUND", source="clamav", severity="CRITICAL"),
        blocker_finding("SOURCE-CHECKSUM-MISMATCH", severity="HIGH"),
        blocker_finding("SIGNATURE-INVALID", severity="HIGH"),
        blocker_finding("ARCHIVE-PATH-TRAVERSAL", source="source_archive", severity="CRITICAL"),
        blocker_finding("DETERMINISTIC-CRITICAL", severity="CRITICAL"),
        blocker_finding("LOW-BLOCKING", severity="LOW", blocks=True),
    ])

    blockers = get_non_acceptance_blockers(report)
    rule_ids = {item["rule_id"] for item in blockers}

    assert {
        "CLAMAV-FOUND",
        "SOURCE-CHECKSUM-MISMATCH",
        "SIGNATURE-INVALID",
        "ARCHIVE-PATH-TRAVERSAL",
        "DETERMINISTIC-CRITICAL",
        "LOW-BLOCKING",
    } <= rule_ids


def test_one_time_acceptance_cannot_be_reused(tmp_path):
    (tmp_path / "PKGBUILD").write_text("pkgname=demo\npkgver=1.0\n")
    store = ReviewDecisionStore(tmp_path / "review.db")
    order = []
    first_factory, first_created = fake_engine_factory(order, report=manual_review_report())

    run(
        [],
        cwd=tmp_path,
        engine_factory=first_factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner(order, []),
        review_store=store,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )
    token = first_created[0][1].last_report["review_token"]

    makepkg_calls = []
    second_factory, _second_created = fake_engine_factory(order, report=manual_review_report())
    assert run(
        ["--aurascan-accept-review", token],
        cwd=tmp_path,
        engine_factory=second_factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner(order, makepkg_calls),
        review_store=store,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    ) == 0

    third_factory, third_created = fake_engine_factory(order, report=manual_review_report())
    stdout = io.StringIO()
    code = run(
        ["--aurascan-accept-review", token],
        cwd=tmp_path,
        engine_factory=third_factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner(order, makepkg_calls),
        review_store=store,
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert code == EXIT_MANUAL_REVIEW
    assert len(makepkg_calls) == 1
    assert third_created[0][1].last_report["acceptance_status"] == "one_time_acceptance_already_used"
    assert "one_time_acceptance_already_used" in stdout.getvalue()


def test_remembered_exact_scan_acceptance_can_be_reused_for_identical_fingerprint(tmp_path):
    (tmp_path / "PKGBUILD").write_text("pkgname=demo\npkgver=1.0\n")
    store = ReviewDecisionStore(tmp_path / "review.db")
    order = []
    first_factory, first_created = fake_engine_factory(order, report=manual_review_report())

    run(
        [],
        cwd=tmp_path,
        engine_factory=first_factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner(order, []),
        review_store=store,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )
    token = first_created[0][1].last_report["review_token"]

    makepkg_calls = []
    second_factory, _second_created = fake_engine_factory(order, report=manual_review_report())
    third_factory, third_created = fake_engine_factory(order, report=manual_review_report())
    assert run(
        ["--aurascan-accept-review", token, "--aurascan-remember-review"],
        cwd=tmp_path,
        engine_factory=second_factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner(order, makepkg_calls),
        review_store=store,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    ) == 0
    assert run(
        ["--aurascan-accept-review", token, "--aurascan-remember-review"],
        cwd=tmp_path,
        engine_factory=third_factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner(order, makepkg_calls),
        review_store=store,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    ) == 0

    assert len(makepkg_calls) == 2
    assert third_created[0][1].last_report["acceptance_status"] == "accepted_persistent_for_exact_scan"
    assert store.list_decisions()[0].one_time is False


def test_review_acceptance_records_manual_review_history_without_clean_baseline(tmp_path):
    work = copy_fixture(tmp_path, "suspicious-update", "current")
    previous = FIXTURES / "suspicious-update" / "previous" / "PKGBUILD"
    history = accepted_history_from_pkgbuild(tmp_path, previous)
    store = ReviewDecisionStore(tmp_path / "review.db")
    local_db = tmp_path / "local"
    write_local_db_entry(local_db, "aurascan-wrapper-suspicious-update", "1.0-1")
    factory, created = real_engine_factory(
        tmp_path,
        analyzers=[history, SourceMetadataAnalyzer()],
        local_db=local_db,
        version_compare=lambda _installed, _candidate: -1,
    )

    first_code = run(
        ["--aurascan-update-scan-policy", "smart"],
        cwd=work,
        engine_factory=factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner([], []),
        review_store=store,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )
    token = created[0].last_report["review_token"]

    makepkg_calls = []
    second_code = run(
        ["--aurascan-update-scan-policy", "smart", "--aurascan-accept-review", token],
        cwd=work,
        engine_factory=factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner([], makepkg_calls),
        review_store=store,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )

    snapshot = history.get_snapshot("aurascan-wrapper-suspicious-update")
    assert first_code == EXIT_MANUAL_REVIEW
    assert second_code == 0
    assert makepkg_calls
    assert snapshot["scan_status"] == MANUAL_REVIEW_ACCEPTED_STATUS
    assert snapshot["manual_review_resolved"] is True
    assert snapshot["review_decision_id"]
    assert history.get_accepted_snapshot("aurascan-wrapper-suspicious-update") == {}


def test_unresolved_manual_review_does_not_update_baseline(tmp_path):
    work = copy_fixture(tmp_path, "suspicious-update", "current")
    previous = FIXTURES / "suspicious-update" / "previous" / "PKGBUILD"
    history = accepted_history_from_pkgbuild(tmp_path, previous)
    original_snapshot = history.get_snapshot("aurascan-wrapper-suspicious-update")
    local_db = tmp_path / "local"
    write_local_db_entry(local_db, "aurascan-wrapper-suspicious-update", "1.0-1")
    factory, _created = real_engine_factory(
        tmp_path,
        analyzers=[history, SourceMetadataAnalyzer()],
        local_db=local_db,
        version_compare=lambda _installed, _candidate: -1,
    )

    code = run(
        ["--aurascan-update-scan-policy", "smart"],
        cwd=work,
        engine_factory=factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner([], []),
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )

    assert code == EXIT_MANUAL_REVIEW
    assert history.get_snapshot("aurascan-wrapper-suspicious-update") == original_snapshot


def test_non_tty_review_flow_does_not_prompt_interactively(tmp_path):
    (tmp_path / "PKGBUILD").write_text("pkgname=demo\npkgver=1.0\n")
    order = []
    makepkg_calls = []
    factory, _created = fake_engine_factory(order, report=manual_review_report())
    stdout = io.StringIO()

    code = run(
        [],
        cwd=tmp_path,
        engine_factory=factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner(order, makepkg_calls),
        stdout=stdout,
        stderr=io.StringIO(),
    )

    output = stdout.getvalue()
    assert code == EXIT_MANUAL_REVIEW
    assert makepkg_calls == []
    assert "Review token:" in output
    assert "Type" not in output


def test_list_review_decisions_does_not_require_pkgbuild_or_makepkg(tmp_path):
    store = ReviewDecisionStore(tmp_path / "review.db")
    decision = store.record_acceptance(
        review_fingerprint(),
        reason="reviewed source metadata",
        remember=True,
        now=1000,
    )
    stdout = io.StringIO()

    code = run(
        ["--aurascan-list-review-decisions"],
        cwd=tmp_path,
        engine_factory=lambda **_kwargs: (_ for _ in ()).throw(AssertionError("scan should not run")),
        makepkg_locator=lambda: (_ for _ in ()).throw(AssertionError("makepkg lookup should not run")),
        subprocess_run=fake_makepkg_runner([], []),
        review_store=store,
        stdout=stdout,
        stderr=io.StringIO(),
    )

    output = stdout.getvalue()
    assert code == 0
    assert "Review decisions" in output
    assert decision.decision_id in output
    assert "Package: demo 1.0" in output
    assert "reviewed source metadata" in output


def test_list_review_decisions_json_is_structured_and_filtered(tmp_path):
    store = ReviewDecisionStore(tmp_path / "review.db")
    store.record_acceptance(review_fingerprint(package_name="demo"), remember=False, now=1000)
    store.record_acceptance(review_fingerprint(package_name="other", scan_suffix="-other"), remember=True, now=1001)
    stdout = io.StringIO()

    code = run(
        [
            "--aurascan-json",
            "--aurascan-list-review-decisions",
            "--aurascan-review-package",
            "demo",
            "--aurascan-review-status",
            "used",
        ],
        cwd=tmp_path,
        review_store=store,
        stdout=stdout,
        stderr=io.StringIO(),
    )

    data = json.loads(stdout.getvalue())
    assert code == 0
    assert data["action"] == "review_listed"
    assert data["makepkg_invoked"] is False
    assert data["scan_report"] is None
    assert len(data["review_decisions"]) == 1
    assert data["review_decisions"][0]["package_name"] == "demo"
    assert data["review_decisions"][0]["effective_status"] == "used"
    assert "Review decisions" not in stdout.getvalue()


def test_revoke_review_marks_decision_revoked_without_scanning(tmp_path):
    store = ReviewDecisionStore(tmp_path / "review.db")
    decision = store.record_acceptance(review_fingerprint(), remember=True, now=1000)
    stdout = io.StringIO()

    code = run(
        ["--aurascan-revoke-review", decision.decision_id],
        cwd=tmp_path,
        engine_factory=lambda **_kwargs: (_ for _ in ()).throw(AssertionError("scan should not run")),
        makepkg_locator=lambda: (_ for _ in ()).throw(AssertionError("makepkg lookup should not run")),
        subprocess_run=fake_makepkg_runner([], []),
        review_store=store,
        stdout=stdout,
        stderr=io.StringIO(),
    )

    revoked = store.decision_by_id(decision.decision_id)
    assert code == 0
    assert revoked.decision_status.value == "revoked"
    assert revoked.revoked_at is not None
    assert "Review decision revoked" in stdout.getvalue()


def test_revoke_unknown_decision_gives_friendly_error(tmp_path):
    store = ReviewDecisionStore(tmp_path / "review.db")
    stdout = io.StringIO()

    code = run(
        ["--aurascan-revoke-review", "missing-decision"],
        cwd=tmp_path,
        review_store=store,
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert code != 0
    assert "Review decision not found" in stdout.getvalue()


def test_revoked_review_decision_cannot_be_used(tmp_path):
    (tmp_path / "PKGBUILD").write_text("pkgname=demo\npkgver=1.0\n")
    store = ReviewDecisionStore(tmp_path / "review.db")
    order = []
    first_factory, first_created = fake_engine_factory(order, report=manual_review_report())

    run(
        [],
        cwd=tmp_path,
        engine_factory=first_factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner(order, []),
        review_store=store,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )
    token = first_created[0][1].last_report["review_token"]

    makepkg_calls = []
    accept_factory, _accept_created = fake_engine_factory(order, report=manual_review_report())
    assert run(
        ["--aurascan-accept-review", token, "--aurascan-remember-review"],
        cwd=tmp_path,
        engine_factory=accept_factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner(order, makepkg_calls),
        review_store=store,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    ) == 0
    decision_id = store.list_decisions()[0].decision_id
    assert run(
        ["--aurascan-revoke-review", decision_id],
        cwd=tmp_path,
        review_store=store,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    ) == 0

    revoked_factory, revoked_created = fake_engine_factory(order, report=manual_review_report())
    code = run(
        ["--aurascan-accept-review", token, "--aurascan-remember-review"],
        cwd=tmp_path,
        engine_factory=revoked_factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner(order, makepkg_calls),
        review_store=store,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )

    assert code == EXIT_MANUAL_REVIEW
    assert len(makepkg_calls) == 1
    assert revoked_created[0][1].last_report["acceptance_status"] == "decision_revoked"


def test_expired_review_decision_cannot_be_used(tmp_path):
    (tmp_path / "PKGBUILD").write_text("pkgname=demo\npkgver=1.0\n")
    store = ReviewDecisionStore(tmp_path / "review.db")
    order = []
    first_factory, first_created = fake_engine_factory(order, report=manual_review_report())

    run(
        [],
        cwd=tmp_path,
        engine_factory=first_factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner(order, []),
        review_store=store,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )
    token = first_created[0][1].last_report["review_token"]

    makepkg_calls = []
    accept_factory, _accept_created = fake_engine_factory(order, report=manual_review_report())
    assert run(
        [
            "--aurascan-accept-review",
            token,
            "--aurascan-remember-review",
            "--aurascan-review-expire-days",
            "0",
        ],
        cwd=tmp_path,
        engine_factory=accept_factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner(order, makepkg_calls),
        review_store=store,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    ) == 0

    expired_factory, expired_created = fake_engine_factory(order, report=manual_review_report())
    code = run(
        ["--aurascan-accept-review", token, "--aurascan-remember-review"],
        cwd=tmp_path,
        engine_factory=expired_factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner(order, makepkg_calls),
        review_store=store,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )

    assert code == EXIT_MANUAL_REVIEW
    assert len(makepkg_calls) == 1
    assert expired_created[0][1].last_report["acceptance_status"] == "decision_expired"


def test_wrapper_json_manual_review_required_includes_token_and_scan_report(tmp_path):
    (tmp_path / "PKGBUILD").write_text("pkgname=demo\npkgver=1.0\n")
    order = []
    factory, _created = fake_engine_factory(order, report=manual_review_report())
    stdout = io.StringIO()

    code = run(
        ["--aurascan-json"],
        cwd=tmp_path,
        engine_factory=factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner(order, []),
        stdout=stdout,
        stderr=io.StringIO(),
    )

    data = json.loads(stdout.getvalue())
    assert code == EXIT_MANUAL_REVIEW
    assert data["action"] == "manual_review_required"
    assert data["makepkg_invoked"] is False
    assert data["review"]["review_token"].startswith("arv-")
    assert data["scan_report"]["package_metadata"]["name"] == "demo"
    assert "AuraScan needs review" not in stdout.getvalue()


def test_wrapper_json_accepted_review_includes_decision_and_makepkg_status(tmp_path):
    (tmp_path / "PKGBUILD").write_text("pkgname=demo\npkgver=1.0\n")
    store = ReviewDecisionStore(tmp_path / "review.db")
    order = []
    first_factory, first_created = fake_engine_factory(order, report=manual_review_report())

    run(
        [],
        cwd=tmp_path,
        engine_factory=first_factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner(order, []),
        review_store=store,
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )
    token = first_created[0][1].last_report["review_token"]

    makepkg_calls = []
    accept_factory, _accept_created = fake_engine_factory(order, report=manual_review_report())
    stdout = io.StringIO()
    code = run(
        ["--aurascan-json", "--aurascan-accept-review", token, "--install"],
        cwd=tmp_path,
        engine_factory=accept_factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner(order, makepkg_calls),
        review_store=store,
        stdout=stdout,
        stderr=io.StringIO(),
    )

    data = json.loads(stdout.getvalue())
    assert code == 0
    assert data["action"] == "review_accepted"
    assert data["makepkg_invoked"] is True
    assert data["makepkg_exit_code"] == 0
    assert data["review"]["accepted_decision_id"]
    assert data["review"]["decision_status"] == "accepted_once"
    assert data["makepkg_args"] == ["--install"]


def test_wrapper_json_hard_blocker_includes_blockers_and_no_makepkg(tmp_path):
    (tmp_path / "PKGBUILD").write_text("pkgname=demo\npkgver=1.0\n")
    order = []
    makepkg_calls = []
    factory, _created = fake_engine_factory(order, scan_ok=False, report=hard_block_report())
    stdout = io.StringIO()

    code = run(
        ["--aurascan-json", "--aurascan-accept-review", "arv-anything"],
        cwd=tmp_path,
        engine_factory=factory,
        makepkg_locator=lambda: "/usr/bin/makepkg",
        subprocess_run=fake_makepkg_runner(order, makepkg_calls),
        stdout=stdout,
        stderr=io.StringIO(),
    )

    data = json.loads(stdout.getvalue())
    assert code == EXIT_SCAN_BLOCKED
    assert makepkg_calls == []
    assert data["action"] == "scan_blocked"
    assert data["makepkg_invoked"] is False
    assert data["review"]["non_acceptance_blockers"][0]["rule_id"] == "NET-EXEC-001"
    assert data["scan_report"]["acceptance_status"] == "hard_blocker"


def test_revoke_json_output_is_valid_json_only(tmp_path):
    store = ReviewDecisionStore(tmp_path / "review.db")
    decision = store.record_acceptance(review_fingerprint(), remember=True, now=1000)
    stdout = io.StringIO()

    code = run(
        ["--aurascan-json", "--aurascan-revoke-review", decision.decision_id],
        cwd=tmp_path,
        review_store=store,
        stdout=stdout,
        stderr=io.StringIO(),
    )

    data = json.loads(stdout.getvalue())
    assert code == 0
    assert data["action"] == "review_revoked"
    assert data["review"]["decision_status"] == "revoked"
    assert "Review decision revoked" not in stdout.getvalue()


def test_review_store_uses_restrictive_db_file_permissions(tmp_path):
    store = ReviewDecisionStore(tmp_path / "review.db")
    mode = os.stat(store.db_path).st_mode & 0o777

    assert mode == 0o600
