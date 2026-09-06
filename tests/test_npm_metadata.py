import json
from pathlib import Path

import pytest

from aurascan.analyzers.deep_static import DeepStaticAnalyzer
from aurascan.analyzers.npm_metadata import inspect_npm_metadata
from aurascan.core.models import Phase, Severity
from tests.helpers.archive_fixtures import TarEntry, write_tar_archive
from tests.test_deep_static import FakeClamAV


LOCK_RULE = "PNPM-LOCKFILE-PATH-ESCAPE-001"
NAME_RULE = "NPM-MANIFEST-NAME-PATH-ESCAPE-001"
COVERAGE = "NPM-METADATA-INSPECTION-INCOMPLETE-001"


def lockfile(key="@scope/package@1.0.0", version="9.0"):
    return (
        "lockfileVersion: '" + version + "'\n"
        "settings:\n  autoInstallPeers: true\n"
        "importers:\n  .:\n    dependencies:\n"
        "      '@scope/package':\n        specifier: ^1.0.0\n        version: 1.0.0\n"
        "packages:\n  " + json.dumps(key) + ":\n"
        "    resolution: {integrity: sha512-inert-fixture}\n"
        "    engines: {node: '>=18'}\n"
        "    os:\n      - linux\n      - darwin\n"
        "snapshots:\n  " + json.dumps(key) + ": {}\n"
    )


@pytest.mark.parametrize("name", [
    "ordinary", "@scope/package", "package.name", "Uppercase-Legacy",
])
def test_legitimate_names_and_no_lifecycle_scripts_are_neutral(name):
    assert inspect_npm_metadata("package.json", json.dumps({"name": name})) == []
    assert inspect_npm_metadata("pnpm-lock.yaml", lockfile(name + "@1.0.0"), lockfile=True) == []


@pytest.mark.parametrize("name", [
    "../fixture-escape", "@scope/../../fixture-escape", "/fixture-escape",
    "@scope//../../fixture-escape", "..\\fixture-escape", "C:\\fixture-escape",
    "C:/fixture-escape", "@scope/..", "../../fixture-private-marker",
])
def test_path_components_block_without_echoing_hostile_name(name):
    for path, payload, is_lock, rule in (
        ("package.json", json.dumps({"name": name}), False, NAME_RULE),
        ("pnpm-lock.yaml", lockfile(name + "@1.0.0"), True, LOCK_RULE),
    ):
        findings = inspect_npm_metadata(path, payload, lockfile=is_lock)
        assert len(findings) == 1
        finding = findings[0]
        assert finding.rule_id == rule
        assert finding.severity == Severity.CRITICAL
        assert finding.blocks_installation is True
        assert finding.phase == Phase.unpacked_source_scan
        assert name not in json.dumps(finding.to_dict())
        assert "no installation or file write was observed" in finding.explanation
        if is_lock:
            assert finding.line_number == next(
                index for index, line in enumerate(payload.splitlines(), 1)
                if json.dumps(name + "@1.0.0") in line
            )


def test_encoded_json_and_yaml_names_are_decoded_before_validation():
    for payload, is_lock in (
        ('{"name":"\\u002e\\u002e/fixture-escape"}', False),
        ('lockfileVersion: "9.0"\npackages: {"\\u002e\\u002e/fixture@1.0.0": {}}', True),
    ):
        findings = inspect_npm_metadata("metadata", payload, lockfile=is_lock)
        assert findings[0].severity == Severity.CRITICAL


@pytest.mark.parametrize("payload", [
    "{", "[]", '{"name":[]}', '{"name":{}}', '{"name":null}',
    '{"name":"safe", "name":"../fixture"}',
    '{"name":"safe", "custom":{"x":1,"x":2}}', '{"name":NaN}',
    '{"name":"name/child"}', '{"name":"@scope/name/child"}',
    '{"name":"a%2fb"}', '{"name":"\\ud800"}',
])
def test_ambiguous_manifest_is_coverage_not_malware(payload):
    findings = inspect_npm_metadata("package.json", payload)
    assert findings[0].rule_id == COVERAGE
    assert findings[0].severity == Severity.HIGH
    assert findings[0].blocks_installation


@pytest.mark.parametrize("suffix", [
    "packages: &fixture {}", "packages: *fixture", "packages: !!map {}", "settings: %YAML",
    "packages: {<<: {}}", "packages: []", "packages: null",
    "packages: {safe@1.0.0: {}, safe@1.0.0: {}}",
    "packages: {safe@../../fixture: {}}", "packages: {safe@1.0.0(broken: {}}",
    "packages: {safe@1.0.0(peer@1.0.0)trailing: {}}",
    "packages: {safe@1.0.0(../fixture@1.0.0): {}}",
    "packages: {file:../fixture.tgz: {}}",
    "packages: {registry.example.invalid/safe@1.0.0: {}}",
    "importers: {.: {dependencies: []}}", "snapshots: []",
    "packages:\n  safe@1.0.0: {}\n    name: ../fixture",
    "packages:\n\tsafe@1.0.0: {}", "description: |\n  packages: {}",
    "---\npackages: {}", "packages: {}\n...",
])
def test_unsupported_yaml_and_dependency_identity_are_coverage(suffix):
    findings = inspect_npm_metadata("pnpm-lock.yaml", "lockfileVersion: '9.0'\n" + suffix, lockfile=True)
    assert findings[0].rule_id == COVERAGE
    assert findings[0].blocks_installation


@pytest.mark.parametrize("version", ["{}", "[]", "null", "100.0", "", "9.0\nlockfileVersion: 9.0"])
def test_bad_version_shapes_never_crash_or_clear(version):
    findings = inspect_npm_metadata("pnpm-lock.yaml", "lockfileVersion: " + version, lockfile=True)
    assert findings[0].rule_id == COVERAGE


@pytest.mark.parametrize("version,key", [
    ("5.3", "/safe/1.0.0"), ("5.4", "/@scope/package/1.0.0"),
    ("6.0", "/safe@1.0.0"), ("6.0", "/@scope/package@1.0.0"),
    ("9.0", "safe@1.0.0(peer@1.2.3)(@scope/package@2.0.0(peer@1.0.0))"),
])
def test_supported_legacy_and_peer_dependency_paths(version, key):
    assert inspect_npm_metadata("pnpm-lock.yaml", lockfile(key, version), lockfile=True) == []


def test_dependency_alias_and_snapshot_name_are_checked_structurally():
    for suffix in (
        "importers: {.: {dependencies: {'../fixture': {version: 1.0.0}}}}",
        "packages: {safe@1.0.0: {name: '../fixture'}}",
        "snapshots: {safe@1.0.0: {dependencies: {'../fixture': 1.0.0}}}",
    ):
        findings = inspect_npm_metadata("pnpm-lock.yaml", "lockfileVersion: '9.0'\n" + suffix, lockfile=True)
        assert findings[0].rule_id == LOCK_RULE


def test_comments_messages_and_local_references_are_not_package_names():
    text = (
        "# packages: {'../fixture@1.0.0': {}}\n"
        "lockfileVersion: '9.0'\n"
        "description: 'Example ../fixture@1.0.0'\n"
        "importers: {.: {dependencies: {local: {specifier: 'workspace:../local', version: 'link:../local'}}}}\n"
        "packages: {}\n"
    )
    assert inspect_npm_metadata("pnpm-lock.yaml", text, lockfile=True) == []
    assert inspect_npm_metadata("package.json", '{"description":"name: ../fixture"}') == []


@pytest.mark.parametrize("payload", [
    "lockfileVersion: '9.0'\npackages: " + "{" * 60 + "}" * 60,
    "lockfileVersion: '9.0'\ncomment: " + "x" * 17000,
    "lockfileVersion: '9.0'\n" + "# comment\n" * 120000,
])
def test_lockfile_limits_fail_closed(payload):
    assert inspect_npm_metadata("pnpm-lock.yaml", payload, lockfile=True)[0].rule_id == COVERAGE


def test_structurally_normal_dependency_tarball_checks_manifest_without_scripts(tmp_path: Path):
    archive = write_tar_archive(tmp_path / "dependency.tar", [
        TarEntry("package/package.json", b'{"name":"@scope/../../fixture-escape","version":"1.0.0"}'),
        TarEntry("package/index.js", b"// inert fixture\n"),
    ])
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text("pkgname=fixture\nsource=('dependency.tar')\n")
    result = DeepStaticAnalyzer(clamav=FakeClamAV()).analyze_pkgbuild(str(pkgbuild), pkgbuild.read_text())
    assert any(f.rule_id == NAME_RULE and f.blocks_installation for f in result.findings)
    assert not any(f.rule_id.startswith("ARCHIVE-") and f.blocks_installation for f in result.findings)
    assert not any(f.rule_id == "DEEPSTATIC-NPM-INSTALL-SCRIPT" for f in result.findings)
    assert archive.exists()


def test_malformed_manifest_and_lockfile_are_required_deep_evidence(tmp_path: Path):
    (tmp_path / "package.json").write_text("{")
    (tmp_path / "pnpm-lock.yaml").write_text("lockfileVersion: {}")
    findings = DeepStaticAnalyzer(clamav=FakeClamAV()).inspect_source_tree(tmp_path)
    assert sum(f.rule_id == COVERAGE for f in findings) == 2


def test_metadata_symlink_and_oversized_candidates_fail_closed(tmp_path: Path):
    outside = tmp_path / "outside"
    outside.write_text('{"name":"../fixture-private-marker"}')
    root = tmp_path / "source"
    root.mkdir()
    (root / "package.json").symlink_to(outside)
    (root / "pnpm-lock.yaml").write_text("x" * 101)
    findings = DeepStaticAnalyzer(clamav=FakeClamAV(), max_file_size=100).inspect_source_tree(root)
    assert any(f.rule_id == "DEEPSTATIC-INSPECTION-INCOMPLETE-001" for f in findings)
    assert not any(f.rule_id in {NAME_RULE, LOCK_RULE} for f in findings)
