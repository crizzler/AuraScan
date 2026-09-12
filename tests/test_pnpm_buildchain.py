import io
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import aurascan.core.pnpm_buildchain as pnpm
import aurascan.makepkg_wrapper as wrapper
from aurascan.analyzers.history import HistoryAnalyzer
from aurascan.core.cache import ScanCache
from aurascan.core.engine import AuraScanEngine
from aurascan.core.intelligence import bundled_snapshot
from aurascan.core.models import Phase, Severity
from aurascan.core.trusted_tools import TrustedTool


def compare(left, right):
    first, second = tuple(map(int, left.split("."))), tuple(map(int, right.split(".")))
    return (first > second) - (first < second)


def database(tmp_path, version="11.3.0-1"):
    root = tmp_path / "local"
    root.mkdir(exist_ok=True)
    entry = root / ("pnpm-" + version)
    entry.mkdir(exist_ok=True)
    desc = entry / "desc"
    desc.write_text("%NAME%\npnpm\n\n%VERSION%\n" + version + "\n", encoding="utf-8")
    return root


def check(text, root):
    return pnpm.analyze_pnpm_buildchain(
        [("PKGBUILD", text, Phase.pkgbuild_static)],
        local_db_root=root, version_compare=compare,
    )


@pytest.mark.parametrize("version, affected", [
    ("9.15.0-1", True), ("10.34.4-99", True), ("10.34.5-1", False),
    ("10.99.0-1", False), ("11.0.0-1", True), ("11.10.99-2", True),
    ("11.11.0-1", False), ("12.0.0-1", False),
    ("9:11.3.0-99.2", True), ("0:10.34.5-1.1", False),
    ("11.11.0rc1-1", None), ("secret-token", None), ("11.11-1", None),
])
def test_arch_version_thresholds(version, affected):
    assert pnpm.pnpm_version_affected(version, version_compare=compare) is affected


@pytest.mark.parametrize("command", [
    "pnpm install", "pnpm i", "pnpm fetch --offline", "pnpm add dependency",
    "pnpm --filter @scope/package install", "pnpm install --ignore-scripts",
    "env CI=1 pnpm install", "command -- pnpm i", "/usr/bin/pnpm install",
    "pnpm --filter --help install", "pnpm install --filter --help",
    "pnpm --filter --version install", "pnpm install -- --help",
    "pnpm " + "\\" + "\ninstall --ignore-scripts", "pnpm up", "pnpm dedupe", "pnpm dlx dependency",
])
def test_affected_installed_package_blocks_active_dependency_operation(tmp_path, command):
    result = check("build() {\n" + command + "\n}\n", database(tmp_path))
    assert result.relevant
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "PNPM-VULNERABLE-BUILDCHAIN-001"
    assert finding.severity == Severity.HIGH
    assert finding.blocks_installation
    assert finding.line_number == 2
    assert "not evidence of exploitation" in finding.explanation


@pytest.mark.parametrize("text", [
    "# pnpm install\n", "echo 'pnpm install'", "printf '%s' 'pnpm fetch'",
    "command -v pnpm install", "command -V pnpm", "pnpm --version", "pnpm install --help",
    "pnpm run build", "pnpm run install", "pnpm list", "pnpm",
    "source=('pnpm install')", "depends=('pnpm')", "description='pnpm install'",
    "cat <<'DOC'\npnpm install\nDOC\n",
    "env --help pnpm install", "env --version pnpm install",
    "/usr/bin/time --help pnpm install", "/usr/bin/time --version pnpm install",
    "/usr/bin/time -V pnpm install", "command env --help pnpm install",
    "env -S '--help pnpm install'", "env --split-string='--version pnpm install'",
    "corepack use pnpm@11.3.0 --help", "corepack pnpm@11.3.0 --version",
    "corepack --help pnpm install", "corepack pnpm@latest install --help",
])
def test_inert_or_non_resolution_text_never_reads_package_database(monkeypatch, text):
    monkeypatch.setattr(pnpm, "_read_pnpm_version", lambda _root: pytest.fail("unexpected DB read"))
    result = check(text, None)
    assert not result.relevant
    assert not result.findings


@pytest.mark.parametrize("text", [
    "corepack pnpm install", "./node_modules/.bin/pnpm install",
    "pnpm $operation", "pnpm --unknown-option install", "pnpm -- \"$operation\"",
    "pnpm -- '${operation}'", "pnpm install --unknown-option --help",
    "corepack pnpm@11.3.0 install", "corepack pnpm@latest install",
    "corepack use pnpm@11.3.0", "corepack use pnpm@latest",
    "env CI=1 corepack pnpm@11.3.0 install",
])
def test_unresolved_invocation_is_coverage_not_vulnerable_claim(tmp_path, text):
    result = check(text, database(tmp_path, "11.11.0-1"))
    assert result.findings[0].rule_id == "PNPM-BUILDCHAIN-CONTEXT-INCOMPLETE-001"
    assert result.findings[0].blocks_installation


def test_unresolved_corepack_finding_uses_actual_unresolved_line(tmp_path):
    result = check("pnpm install\ncorepack use pnpm@latest\n", database(tmp_path, "11.11.0-1"))
    assert result.findings[0].rule_id == "PNPM-BUILDCHAIN-CONTEXT-INCOMPLETE-001"
    assert result.findings[0].line_number == 2


@pytest.mark.parametrize("text", [
    "env MESSAGE=--help pnpm install", "/usr/bin/time -f --help pnpm install",
    "env --help $(pnpm install)", "env --version; pnpm install",
    "echo --help; pnpm install", "env sh -c 'echo --help'; pnpm install",
    "exec -a --help pnpm install", "pnpm install --message=--help",
])
def test_wrapper_queries_do_not_hide_real_nested_or_following_resolution(tmp_path, text):
    result = check(text, database(tmp_path))
    assert result.relevant
    assert result.findings[0].rule_id == "PNPM-VULNERABLE-BUILDCHAIN-001"


@pytest.mark.parametrize("state", ["missing", "empty", "duplicate", "symlink-desc", "symlink-parent", "oversized", "malformed", "symlink-root"])
def test_local_database_fails_closed_without_following_links(tmp_path, state):
    root = database(tmp_path)
    desc = root / "pnpm-11.3.0-1" / "desc"
    if state == "missing":
        root = tmp_path / "absent"
    elif state == "empty":
        desc.unlink()
        desc.parent.rmdir()
    elif state == "duplicate":
        database(tmp_path, "11.11.0-1")
    elif state == "symlink-desc":
        external = tmp_path / "outside"
        desc.rename(external)
        desc.symlink_to(external)
    elif state == "symlink-parent":
        external = tmp_path / "outside"
        desc.parent.rename(external)
        desc.parent.symlink_to(external, target_is_directory=True)
    elif state == "symlink-root":
        alias = tmp_path / "alias"
        alias.symlink_to(root, target_is_directory=True)
        root = alias
    elif state == "oversized":
        desc.write_bytes(b"x" * (pnpm.MAX_DESC_BYTES + 1))
    elif state == "malformed":
        desc.write_text("%NAME%\npnpm\n\n%VERSION%\n11.3.0-1\n\n%VERSION%\n11.11.0-1\n")
    result = check("pnpm install", root)
    assert result.findings[0].rule_id == "PNPM-BUILDCHAIN-CONTEXT-INCOMPLETE-001"


def test_patched_version_and_hook_phase(tmp_path):
    root = database(tmp_path, "11.11.0-1")
    result = check("pnpm install --ignore-scripts", root)
    assert result.relevant and not result.findings
    result = pnpm.analyze_pnpm_buildchain(
        [(".fixture.install", "post_install() {\npnpm install\n}\n", Phase.install_hook_static)],
        local_db_root=tmp_path / "absent", version_compare=compare,
    )
    assert result.findings[0].phase == Phase.install_hook_static
    assert result.findings[0].line_number == 2


def test_version_helper_uses_only_fixed_trusted_bounded_vercmp(monkeypatch):
    calls = []
    tool = TrustedTool("vercmp", "/usr/bin/vercmp", 1, 2, 0, 0, 0o100755)
    monkeypatch.setattr(pnpm, "capture_trusted_system_tool", lambda name, **_kw: tool)
    monkeypatch.setattr(pnpm, "revalidate_trusted_system_tool", lambda observed: calls.append(observed.path))
    def run(args, **kwargs):
        assert args[0] == "/usr/bin/vercmp"
        assert kwargs["timeout"] == 2
        assert kwargs["env"] == {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
        return SimpleNamespace(returncode=0, stderr="", stdout=str(compare(*args[1:])))
    monkeypatch.setattr(pnpm, "run_bounded_trusted_tool", run)
    assert pnpm.pnpm_version_affected("2:11.3.0-1") is True
    assert calls == ["/usr/bin/vercmp"] * 6


def test_failed_version_comparison_is_unknown():
    assert pnpm.pnpm_version_affected("11.11.0-1", version_compare=lambda _a, _b: None) is None


def test_database_entry_limit_and_replacement_fail_closed(tmp_path, monkeypatch):
    root = database(tmp_path)
    (root / "other").mkdir()
    monkeypatch.setattr(pnpm, "MAX_DB_ENTRIES", 1)
    assert check("pnpm install", root).findings[0].rule_id == "PNPM-BUILDCHAIN-CONTEXT-INCOMPLETE-001"
    monkeypatch.setattr(pnpm, "MAX_DB_ENTRIES", 100)
    original = os.read
    replaced = []
    def read(descriptor, size):
        data = original(descriptor, size)
        if data and not replaced:
            replaced.append(True)
            desc = root / "pnpm-11.3.0-1" / "desc"
            desc.unlink()
            desc.write_bytes(data)
        return data
    monkeypatch.setattr(pnpm.os, "read", read)
    assert check("pnpm install", root).findings[0].rule_id == "PNPM-BUILDCHAIN-CONTEXT-INCOMPLETE-001"


def test_unrelated_ancestor_sibling_activity_does_not_change_database_identity(tmp_path, monkeypatch):
    root = database(tmp_path)
    original = os.read
    changed = []
    def read(descriptor, size):
        data = original(descriptor, size)
        if data and not changed:
            changed.append(True)
            (tmp_path / "unrelated-sibling").write_text("inert")
        return data
    monkeypatch.setattr(pnpm.os, "read", read)
    assert check("pnpm install", root).findings[0].rule_id == "PNPM-VULNERABLE-BUILDCHAIN-001"


def make_engine(tmp_path, root):
    engine = AuraScanEngine(json_output=True, local_package_db_root=root, version_compare=compare)
    engine.analyzers = []
    engine.cache = ScanCache(tmp_path / "cache")
    return engine


def test_engine_never_reuses_or_writes_relevant_cache_allow(tmp_path, monkeypatch):
    package = tmp_path / "package"
    package.mkdir()
    path = package / "PKGBUILD"
    path.write_text("pkgname=fixture\npkgver=1\npkgrel=1\nbuild() { pnpm install; }\n")
    root = database(tmp_path, "11.11.0-1")
    engine = make_engine(tmp_path, root)
    monkeypatch.setattr(engine.cache, "get_cached_result", lambda *a, **kw: pytest.fail("cache read"))
    monkeypatch.setattr(engine.cache, "set_cached_result", lambda *a, **kw: pytest.fail("cache write"))
    assert engine.scan_pkgbuild(str(path))
    assert engine.revalidate_pnpm_buildchain()
    desc = root / "pnpm-11.11.0-1" / "desc"
    desc.unlink()
    desc.parent.rmdir()
    database(tmp_path, "11.3.0-1")
    assert not engine.revalidate_pnpm_buildchain()
    assert not engine.scan_pkgbuild(str(path))
    assert engine.last_report["findings"][0]["rule_id"] == "PNPM-VULNERABLE-BUILDCHAIN-001"


def test_new_only_policy_cannot_skip_vulnerable_buildchain(tmp_path):
    package = tmp_path / "package"
    package.mkdir()
    path = package / "PKGBUILD"
    path.write_text("pkgname=fixture\npkgver=1\npkgrel=1\nbuild() { pnpm install; }\n")
    root = database(tmp_path)
    history = HistoryAnalyzer(tmp_path / "history.db")
    history.analyze_pkgbuild(str(path), path.read_text().replace("pkgver=1", "pkgver=0"))
    history.commit_pending_snapshots(scan_level="fast_default", scanner_version="test", rule_version="test", intelligence_identity=bundled_snapshot().identity)
    engine = AuraScanEngine(
        json_output=True, update_scan_policy="new-only", scan_context="update",
        scan_context_source="test_fixture", local_package_db_root=root,
        version_compare=compare,
    )
    engine.analyzers = [history]
    engine.cache = ScanCache(tmp_path / "cache")
    assert not engine.scan_pkgbuild(str(path))
    assert engine.last_report["fast_path_decision"]["action"] == "skip_update_scan"
    assert engine.last_report["findings"][0]["rule_id"] == "PNPM-VULNERABLE-BUILDCHAIN-001"


def test_wrapper_refuses_toolchain_change_after_scan(tmp_path, monkeypatch):
    package = tmp_path / "package"
    package.mkdir()
    path = package / "PKGBUILD"
    path.write_text("pkgname=fixture\npkgver=1\npkgrel=1\nbuild() { pnpm install; }\n")
    root = database(tmp_path, "11.11.0-1")
    tool = TrustedTool("makepkg", "/usr/bin/makepkg", 1, 2, 0, 0, 0o100755)
    def capture(*_args, **_kwargs):
        desc = root / "pnpm-11.11.0-1" / "desc"
        desc.unlink()
        desc.parent.rmdir()
        database(tmp_path, "11.3.0-1")
        return tool
    monkeypatch.setattr(wrapper, "capture_trusted_system_tool", capture)
    monkeypatch.setattr(wrapper, "revalidate_trusted_system_tool", lambda _tool: None)
    stdout = io.StringIO()
    result = wrapper.run(
        ["--aurascan-json"], cwd=package,
        engine_factory=lambda **_kw: make_engine(tmp_path, root),
        subprocess_run=lambda *_a, **_kw: pytest.fail("makepkg must not run"),
        stdout=stdout, stderr=io.StringIO(),
    )
    assert result == wrapper.EXIT_SCAN_BLOCKED
    report = json.loads(stdout.getvalue())
    assert report["action"] == "scan_input_changed"
    assert not report["makepkg_invoked"]


def test_secret_arguments_are_not_persisted(tmp_path):
    result = check("pnpm install --token=fixture-secret", database(tmp_path))
    assert "fixture-secret" not in json.dumps(result.findings[0].to_dict())
