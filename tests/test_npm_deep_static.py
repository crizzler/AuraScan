"""Inert, offline source-tree coverage for npm campaign evidence."""

import bz2
import hashlib
import json
import os
from pathlib import Path

import pytest

from aurascan.analyzers import npm_supply_chain
from aurascan.analyzers.deep_static import DeepStaticAnalyzer
from aurascan.core.models import AnalysisResult, Phase, Severity
from aurascan.core.source_acquisition import SourceFetcher, SourcePolicy
from tests.helpers.archive_fixtures import TarEntry, write_tar_archive


PAYLOAD_RULE = "DEEPSTATIC-NPM-SHAIHULUD-PAYLOAD-001"
INCOMPLETE = "DEEPSTATIC-INSPECTION-INCOMPLETE-001"


class NoClamAV:
    def scan_source_archive(self, *_args):
        return AnalysisResult(True, "inert test", [])

    def scan_unpacked_source(self, *_args):
        return AnalysisResult(True, "inert test", [])


def analyzer(**kwargs):
    return DeepStaticAnalyzer(clamav=NoClamAV(), **kwargs)


def inert_signature(monkeypatch, payload):
    monkeypatch.setattr(npm_supply_chain, "KNOWN_PAYLOAD_SHA256", frozenset({
        hashlib.sha256(payload).hexdigest(),
    }))


@pytest.mark.parametrize("name", ["index.js", "renamed.png", "opaque.dat", "node_modules/fixture/data.bin", ".git/fixture.dat"])
def test_known_payload_matches_captured_bytes_including_renamed_assets(tmp_path, monkeypatch, name):
    payload = b"AURASCAN_INERT_HASH_FIXTURE\x00no executable contents\n"
    inert_signature(monkeypatch, payload)
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    findings = analyzer().inspect_source_tree(tmp_path)
    match = next(item for item in findings if item.rule_id == PAYLOAD_RULE)
    assert match.blocks_installation and match.severity == Severity.CRITICAL
    assert match.phase == Phase.unpacked_source_scan
    assert "AURASCAN_INERT" not in json.dumps(match.to_dict())


def test_noncode_hash_streaming_does_not_expand_text_parser_limit(tmp_path, monkeypatch):
    payload = b"inert asset bytes\n" * 10000
    inert_signature(monkeypatch, payload)
    (tmp_path / "large.png").write_bytes(payload)
    findings = analyzer(max_file_size=32, max_hash_file_size=len(payload)).inspect_source_tree(tmp_path)
    assert any(item.rule_id == PAYLOAD_RULE for item in findings)
    assert not any(item.rule_id == INCOMPLETE for item in findings)


def test_hash_text_mention_or_different_bytes_is_not_payload_match(tmp_path, monkeypatch):
    payload = b"inert exact hash fixture"
    inert_signature(monkeypatch, payload)
    (tmp_path / "index.js").write_text('// ' + hashlib.sha256(payload).hexdigest())
    (tmp_path / "changed.dat").write_bytes(payload + b"changed")
    assert not any(item.rule_id == PAYLOAD_RULE for item in analyzer().inspect_source_tree(tmp_path))


@pytest.mark.parametrize("name", ["nested.tar.bz2", "nested.png", ".git/nested.dat"])
def test_hash_walk_detects_supported_compressed_carriers_without_expansion(tmp_path, name):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bz2.compress(b"inert compressed contents"))
    findings = analyzer().inspect_source_tree(tmp_path)
    assert any(item.rule_id == "DEEPSTATIC-NESTED-ARCHIVE-UNINSPECTED-001" and item.blocks_installation
               for item in findings)
    assert not any(item.rule_id == PAYLOAD_RULE for item in findings)


@pytest.mark.parametrize("limit", ["file", "total", "count"])
def test_hash_coverage_limits_block_without_malware_claim(tmp_path, limit):
    for index in range(3):
        (tmp_path / (str(index) + ".dat")).write_bytes(b"inert" * 10)
    kwargs = {"file": {"max_hash_file_size": 32},
              "total": {"max_total_file_bytes": 60},
              "count": {"max_candidates": 2}}[limit]
    findings = analyzer(**kwargs).inspect_source_tree(tmp_path)
    assert any(item.rule_id == INCOMPLETE and item.blocks_installation for item in findings)
    assert not any(item.rule_id == PAYLOAD_RULE for item in findings)


def test_hash_reader_refuses_symlinks_without_reading_target(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    payload = b"inert outside file"
    inert_signature(monkeypatch, payload)
    target = tmp_path / "private.dat"
    target.write_bytes(payload)
    (source / "link.dat").symlink_to(target)
    original = os.read

    def read(fd, length):
        assert os.fstat(fd).st_ino != target.stat().st_ino
        return original(fd, length)

    monkeypatch.setattr(os, "read", read)
    findings = analyzer().inspect_source_tree(source)
    assert any(item.rule_id == INCOMPLETE for item in findings)
    assert not any(item.rule_id == PAYLOAD_RULE for item in findings)


def test_extensionless_selection_reads_count_against_total_budget(tmp_path, monkeypatch):
    for index in range(3):
        (tmp_path / ("asset" + str(index))).write_bytes(b"inert bytes" * 10)
    original = os.read
    captured = []

    def read(fd, length):
        data = original(fd, length)
        captured.append(len(data))
        return data

    monkeypatch.setattr(os, "read", read)
    findings = analyzer(max_total_file_bytes=10).inspect_source_tree(tmp_path)
    assert sum(captured) <= 10
    assert any(item.rule_id == INCOMPLETE for item in findings)


def test_hash_reader_rejects_replaced_regular_file(tmp_path, monkeypatch):
    payload = b"inert replacement test"
    inert_signature(monkeypatch, payload)
    path = tmp_path / "asset.dat"
    path.write_bytes(payload)
    inode = path.stat().st_ino
    original = os.read
    replaced = []

    def read(fd, length):
        data = original(fd, length)
        if data and not replaced and os.fstat(fd).st_ino == inode:
            other = tmp_path / "replacement"
            other.write_bytes(payload)
            other.replace(path)
            replaced.append(True)
        return data

    monkeypatch.setattr(os, "read", read)
    findings = analyzer().inspect_source_tree(tmp_path)
    assert replaced
    assert any(item.rule_id == INCOMPLETE for item in findings)
    assert not any(item.rule_id == PAYLOAD_RULE for item in findings)


def test_extracted_dependency_exact_tuple_is_blocked_offline(tmp_path):
    archive = write_tar_archive(tmp_path / "source.tar", [
        TarEntry("package/node_modules/blueai-cli/package.json",
                 b'{"name":"blueai-cli","version":"0.7.0"}'),
    ])
    pkgbuild = tmp_path / "PKGBUILD"
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    pkgbuild.write_text("pkgname=fixture\npkgver=1\nsource=(source.tar)\nsha256sums=('" + digest + "')\n")
    result = analyzer(source_fetcher=SourceFetcher(policy=SourcePolicy(
        offline=True, auto_key_fetch=False, key_cache_dir=tmp_path / "keys",
    ))).analyze_pkgbuild(str(pkgbuild), pkgbuild.read_text())
    assert not result.is_safe
    assert any(item.rule_id == "DEEPSTATIC-NPM-SHAIHULUD-20260907" for item in result.findings)


def test_shrinkwrap_exact_resolved_tuple_receives_metadata_inspection(tmp_path):
    (tmp_path / "npm-shrinkwrap.json").write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {"node_modules/blueai-cli": {"version": "0.7.0"}},
    }))
    findings = analyzer().inspect_source_tree(tmp_path)
    assert any(item.rule_id == "DEEPSTATIC-NPM-SHAIHULUD-20260907" for item in findings)


def test_lifecycle_evidence_never_persists_command_or_fake_secret(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({
        "scripts": {"postinstall": "echo AURASCAN_FAKE_PRIVATE_SCRIPT"},
    }))
    findings = analyzer().inspect_source_tree(tmp_path)
    script = next(item for item in findings if item.rule_id == "DEEPSTATIC-NPM-INSTALL-SCRIPT")
    assert "AURASCAN_FAKE_PRIVATE_SCRIPT" not in json.dumps(script.to_dict())


def test_lifecycle_does_not_borrow_another_package_entry_script(tmp_path):
    one = tmp_path / "one"
    two = tmp_path / "two"
    one.mkdir()
    two.mkdir()
    (one / "package.json").write_text('{"scripts":{"preinstall":"bun run index.js"}}')
    (two / "index.js").write_text('fs.readFileSync("/fixture-home/.npmrc");\n')
    findings = analyzer().inspect_source_tree(tmp_path)
    assert not any(item.rule_id in {"NPM-LIFECYCLE-SUPPLYCHAIN-001", "NPM-LIFECYCLE-CREDENTIAL-ACCESS-001"}
                   for item in findings)
    assert any(item.rule_id == "NPM-LIFECYCLE-INSPECTION-INCOMPLETE-001" for item in findings)
