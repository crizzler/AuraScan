import subprocess

from aurascan.core.local_package_db import (
    LocalPackageDbContextProvider,
    compare_versions_with_vercmp,
    parse_pkgbuild_candidate_metadata,
)
from aurascan.core.update_policy import ScanContext, ScanContextSource


def write_local_db_entry(root, name, version, *, malformed=False):
    entry = root / f"{name}-{version}"
    entry.mkdir(parents=True)
    if malformed:
        (entry / "desc").write_text(f"%NAME%\n{name}\n")
    else:
        (entry / "desc").write_text(f"%NAME%\n{name}\n\n%VERSION%\n{version}\n")
    return entry


def provider(tmp_path, content, *, versions=None, compare=None):
    root = tmp_path / "local"
    root.mkdir()
    for name, version in (versions or {}).items():
        write_local_db_entry(root, name, version)
    return LocalPackageDbContextProvider(
        content=content,
        local_db_root=root,
        version_compare=compare or (lambda installed, candidate: -1),
    )


def pkgbuild(name="demo", version="1.1", rel="1"):
    return f"pkgname={name}\npkgver={version}\npkgrel={rel}\n"


def test_installed_absent_is_install_context_not_fast_path_eligible(tmp_path):
    proof = provider(tmp_path, pkgbuild(), versions={}).build_proof()

    assert proof.context == ScanContext.install
    assert proof.source == ScanContextSource.local_package_db
    assert proof.installed_package_present is False
    assert proof.eligible_for_fast_path is False
    assert "local_package_not_installed" in proof.proof_reasons


def test_installed_present_candidate_newer_is_verified_update(tmp_path):
    proof = provider(tmp_path, pkgbuild(), versions={"demo": "1.0-1"}, compare=lambda _a, _b: -1).build_proof()

    assert proof.context == ScanContext.update
    assert proof.source == ScanContextSource.local_package_db
    assert proof.installed_package_present is True
    assert proof.installed_version == "1.0-1"
    assert proof.candidate_version == "1.1-1"
    assert proof.transaction_operation == "upgrade"
    assert proof.eligible_for_fast_path is True


def test_installed_present_candidate_same_is_not_fast_path_eligible(tmp_path):
    proof = provider(tmp_path, pkgbuild(), versions={"demo": "1.1-1"}, compare=lambda _a, _b: 0).build_proof()

    assert proof.context == ScanContext.unknown
    assert proof.eligible_for_fast_path is False
    assert proof.transaction_operation == "reinstall"
    assert "candidate_version_not_newer" in proof.proof_errors


def test_installed_present_candidate_older_is_not_fast_path_eligible(tmp_path):
    proof = provider(tmp_path, pkgbuild(), versions={"demo": "1.2-1"}, compare=lambda _a, _b: 1).build_proof()

    assert proof.context == ScanContext.unknown
    assert proof.eligible_for_fast_path is False
    assert proof.transaction_operation == "downgrade"
    assert "candidate_version_older_than_installed" in proof.proof_errors


def test_missing_local_package_db_is_unknown(tmp_path):
    missing = tmp_path / "missing"
    proof = LocalPackageDbContextProvider(
        content=pkgbuild(),
        local_db_root=missing,
        version_compare=lambda _a, _b: -1,
    ).build_proof()

    assert proof.context == ScanContext.unknown
    assert proof.eligible_for_fast_path is False
    assert "local_package_db_missing" in proof.proof_errors


def test_malformed_local_package_db_is_unknown(tmp_path):
    root = tmp_path / "local"
    root.mkdir()
    write_local_db_entry(root, "demo", "1.0-1", malformed=True)

    proof = LocalPackageDbContextProvider(
        content=pkgbuild(),
        local_db_root=root,
        version_compare=lambda _a, _b: -1,
    ).build_proof()

    assert proof.context == ScanContext.unknown
    assert "malformed_local_package_db" in proof.proof_errors


def test_package_name_parse_failure_is_unknown(tmp_path):
    proof = provider(tmp_path, "pkgname=$pkgbase\npkgver=1.1\npkgrel=1\n", versions={"demo": "1.0-1"}).build_proof()

    assert proof.context == ScanContext.unknown
    assert "package_name_parse_failed" in proof.proof_errors


def test_candidate_version_missing_is_unknown(tmp_path):
    proof = provider(tmp_path, "pkgname=demo\n", versions={"demo": "1.0-1"}).build_proof()

    assert proof.context == ScanContext.unknown
    assert "missing_candidate_version" in proof.proof_errors


def test_dynamic_pkgrel_is_unknown(tmp_path):
    proof = provider(tmp_path, "pkgname=demo\npkgver=1.1\npkgrel=$rel\n", versions={"demo": "1.0-1"}).build_proof()

    assert proof.context == ScanContext.unknown
    assert "missing_candidate_version" in proof.proof_errors


def test_provider_error_is_unknown(tmp_path):
    proof = provider(
        tmp_path,
        pkgbuild(),
        versions={"demo": "1.0-1"},
        compare=lambda _a, _b: (_ for _ in ()).throw(RuntimeError("boom")),
    ).build_proof()

    assert proof.context == ScanContext.unknown
    assert "version_comparison_unavailable" in proof.proof_errors


def test_version_comparison_unavailable_is_conservative(tmp_path):
    proof = provider(tmp_path, pkgbuild(), versions={"demo": "1.0-1"}, compare=lambda _a, _b: None).build_proof()

    assert proof.context == ScanContext.unknown
    assert proof.eligible_for_fast_path is False
    assert "version_comparison_unavailable" in proof.proof_errors


def test_split_package_all_installed_and_newer_is_verified_update(tmp_path):
    content = "pkgbase=demo\npkgname=(demo demo-libs)\npkgver=1.1\npkgrel=1\n"
    proof = provider(
        tmp_path,
        content,
        versions={"demo": "1.0-1", "demo-libs": "1.0-1"},
        compare=lambda _a, _b: -1,
    ).build_proof()

    assert proof.context == ScanContext.update
    assert proof.package_name == "demo demo-libs"
    assert proof.package_base == "demo"
    assert proof.eligible_for_fast_path is True
    assert "split_package_detected" in proof.proof_reasons


def test_split_package_partial_install_is_unknown(tmp_path):
    content = "pkgbase=demo\npkgname=(demo demo-libs)\npkgver=1.1\npkgrel=1\n"
    proof = provider(tmp_path, content, versions={"demo": "1.0-1"}, compare=lambda _a, _b: -1).build_proof()

    assert proof.context == ScanContext.unknown
    assert proof.eligible_for_fast_path is False
    assert "partial_split_package_installed" in proof.proof_errors


def test_split_package_without_pkgbase_is_ambiguous(tmp_path):
    content = "pkgname=(demo demo-libs)\npkgver=1.1\npkgrel=1\n"
    proof = provider(
        tmp_path,
        content,
        versions={"demo": "1.0-1", "demo-libs": "1.0-1"},
        compare=lambda _a, _b: -1,
    ).build_proof()

    assert proof.context == ScanContext.unknown
    assert "ambiguous_split_package_mapping" in proof.proof_errors


def test_pkgbase_only_is_not_enough_to_infer_identity(tmp_path):
    proof = provider(tmp_path, "pkgbase=demo\npkgver=1.1\npkgrel=1\n", versions={"demo": "1.0-1"}).build_proof()

    assert proof.context == ScanContext.unknown
    assert "package_name_parse_failed" in proof.proof_errors


def test_parse_pkgbuild_candidate_metadata_handles_single_package():
    metadata = parse_pkgbuild_candidate_metadata("pkgname=demo\npkgver=1.1\npkgrel=2\nepoch=1\n")

    assert metadata.package_names == ["demo"]
    assert metadata.package_base == "demo"
    assert metadata.candidate_version == "1:1.1-2"
    assert metadata.proof_errors == []


def test_vercmp_wrapper_parses_comparison(monkeypatch):
    class Result:
        stdout = "-1\n"
        returncode = 0

    calls = []

    def fake_run(argv, **_kwargs):
        calls.append(argv)
        return Result()

    monkeypatch.setattr("aurascan.core.local_package_db.shutil.which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr("aurascan.core.local_package_db.subprocess.run", fake_run)

    assert compare_versions_with_vercmp("1.0-1", "1.1-1") == -1
    assert calls == [["/usr/bin/vercmp", "1.0-1", "1.1-1"]]


def test_vercmp_wrapper_unavailable_or_timeout_is_conservative(monkeypatch):
    monkeypatch.setattr("aurascan.core.local_package_db.shutil.which", lambda _name: None)
    assert compare_versions_with_vercmp("1.0-1", "1.1-1") is None

    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("vercmp", 2)

    monkeypatch.setattr("aurascan.core.local_package_db.shutil.which", lambda name: f"/usr/bin/{name}")
    monkeypatch.setattr("aurascan.core.local_package_db.subprocess.run", timeout)

    assert compare_versions_with_vercmp("1.0-1", "1.1-1") is None
