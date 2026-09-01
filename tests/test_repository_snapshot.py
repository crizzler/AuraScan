import hashlib
import os
import stat
from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

import aurascan.core.repository_provenance as provenance
from aurascan.core.repository_provenance import (
    REPOSITORY_COMPLETE,
    REPOSITORY_UNINSPECTED,
    RepositoryArtifact,
    capture_repository_snapshot,
)


def _pe_fixture() -> bytes:
    payload = bytearray(128)
    payload[:2] = b"MZ"
    payload[0x3C:0x40] = (64).to_bytes(4, "little")
    payload[64:68] = b"PE\x00\x00"
    return bytes(payload)


def _tar_fixture() -> bytes:
    payload = bytearray(512)
    payload[257:263] = b"ustar\x00"
    return bytes(payload)


@pytest.mark.parametrize(
    "kind,payload",
    [
        ("elf", b"\x7fELF" + b"\x00" * 60),
        ("pe", _pe_fixture()),
        ("macho", b"\xfe\xed\xfa\xcf" + b"\x00" * 60),
        ("macho-fat", b"\xca\xfe\xba\xbe\x00\x00\x00\x02" + b"\x00" * 56),
        ("macho-fat", b"\xbe\xba\xfe\xca\x02\x00\x00\x00" + b"\x00" * 56),
        ("macho-fat", b"\xca\xfe\xba\xbf\x00\x00\x00\x02" + b"\x00" * 56),
        ("macho-fat", b"\xbf\xba\xfe\xca\x02\x00\x00\x00" + b"\x00" * 56),
        ("zip", b"PK\x03\x04" + b"\x00" * 60),
        ("gzip", b"\x1f\x8b\x08" + b"\x00" * 61),
        ("bzip2", b"BZh9" + b"\x00" * 60),
        ("xz", b"\xfd7zXZ\x00" + b"\x00" * 58),
        ("zstd", b"\x28\xb5\x2f\xfd" + b"\x00" * 60),
        ("7z", b"7z\xbc\xaf\x27\x1c" + b"\x00" * 58),
        ("rar", b"Rar!\x1a\x07\x01\x00" + b"\x00" * 56),
        ("tar", _tar_fixture()),
        ("ar", b"!<arch>\n" + b"\x00" * 56),
    ],
)
def test_snapshot_classifies_magic_and_hashes_exact_bytes(
    tmp_path: Path,
    kind: str,
    payload: bytes,
):
    candidate = tmp_path / "opaque.fixture"
    candidate.write_bytes(payload)
    candidate.chmod(0o640)

    snapshot = capture_repository_snapshot(tmp_path)

    assert snapshot.status == REPOSITORY_COMPLETE
    assert snapshot.error_code == ""
    assert snapshot.entry_count == 1
    assert len(snapshot.input_digest) == 64
    assert snapshot.artifacts == (
        RepositoryArtifact(
            relative_path="opaque.fixture",
            kind=kind,
            sha256=hashlib.sha256(payload).hexdigest(),
            size=len(payload),
            mode=0o640,
            generated_output=False,
        ),
    )


def test_invalid_dos_header_and_ordinary_data_are_not_artifacts(tmp_path: Path):
    invalid_pe = bytearray(128)
    invalid_pe[:2] = b"MZ"
    invalid_pe[0x3C:0x40] = (64).to_bytes(4, "little")
    (tmp_path / "invalid.exe").write_bytes(bytes(invalid_pe))
    (tmp_path / "icon.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)
    (tmp_path / "notes.txt").write_text("bounded fixture\n", encoding="utf-8")
    (tmp_path / "Fixture.class").write_bytes(
        b"\xca\xfe\xba\xbe\x00\x00\x00\x3d" + b"\x00" * 24
    )
    (tmp_path / "invalid.gz").write_bytes(b"\x1f\x8bnot-a-gzip-header")
    (tmp_path / "invalid.bz2").write_bytes(b"BZh0not-a-bzip-header")

    snapshot = capture_repository_snapshot(tmp_path)

    assert snapshot.status == REPOSITORY_COMPLETE
    assert snapshot.artifacts == ()
    assert snapshot.entry_count == 6


def test_digest_binds_non_artifact_bytes_and_is_creation_order_independent(tmp_path: Path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    (first / "a.txt").write_text("alpha\n", encoding="utf-8")
    (first / "b.txt").write_text("beta\n", encoding="utf-8")
    (second / "b.txt").write_text("beta\n", encoding="utf-8")
    (second / "a.txt").write_text("alpha\n", encoding="utf-8")

    original = capture_repository_snapshot(first)
    same_content = capture_repository_snapshot(second)
    assert original.input_digest == same_content.input_digest

    (second / "a.txt").write_text("changed\n", encoding="utf-8")
    changed = capture_repository_snapshot(second)
    assert changed.input_digest != original.input_digest


def test_excluded_artifact_is_hidden_but_still_bound_into_digest(tmp_path: Path):
    candidate = tmp_path / "declared.bin"
    candidate.write_bytes(b"\x7fELF" + b"A" * 64)

    first = capture_repository_snapshot(
        tmp_path,
        excluded_relative_paths=("declared.bin",),
    )
    assert first.status == REPOSITORY_COMPLETE
    assert first.artifacts == ()

    candidate.write_bytes(b"\x7fELF" + b"B" * 64)
    second = capture_repository_snapshot(
        tmp_path,
        excluded_relative_paths=("declared.bin",),
    )
    assert second.status == REPOSITORY_COMPLETE
    assert second.input_digest != first.input_digest


def test_exclusion_policy_is_bound_into_digest(tmp_path: Path):
    (tmp_path / "declared.bin").write_bytes(b"\x7fELF" + b"A" * 32)

    included = capture_repository_snapshot(tmp_path)
    excluded = capture_repository_snapshot(
        tmp_path,
        excluded_relative_paths=("declared.bin",),
    )

    assert included.input_digest != excluded.input_digest
    assert len(included.artifacts) == 1
    assert excluded.artifacts == ()


def test_independently_bound_file_bytes_do_not_change_repository_identity(tmp_path: Path):
    pkgbuild = tmp_path / "PKGBUILD"
    pkgbuild.write_text("pkgname=one\n", encoding="utf-8")
    first = capture_repository_snapshot(
        tmp_path,
        independently_bound_relative_paths=("PKGBUILD",),
    )

    pkgbuild.write_text("pkgname=two\n", encoding="utf-8")
    second = capture_repository_snapshot(
        tmp_path,
        independently_bound_relative_paths=("PKGBUILD",),
    )

    assert first.status == REPOSITORY_COMPLETE
    assert second.status == REPOSITORY_COMPLETE
    assert first.input_digest == second.input_digest
    assert first.artifacts == second.artifacts == ()


def test_single_string_exclusion_is_one_relative_path(tmp_path: Path):
    (tmp_path / "declared.bin").write_bytes(b"\x7fELF" + b"A" * 32)

    snapshot = capture_repository_snapshot(
        tmp_path,
        excluded_relative_paths="declared.bin",
    )

    assert snapshot.status == REPOSITORY_COMPLETE
    assert snapshot.artifacts == ()


def test_vcs_build_output_dependency_and_cache_directories_are_pruned(tmp_path: Path):
    directories = (".git", ".hg", ".svn", "src", "pkg", "node_modules", "venv", ".cache")
    for name in directories:
        directory = tmp_path / name
        directory.mkdir()
        (directory / "opaque.bin").write_bytes(b"\x7fELF" + b"X" * 32)

    kept = tmp_path / "nested" / "src"
    kept.mkdir(parents=True)
    (kept / "opaque.bin").write_bytes(b"\x7fELF" + b"Y" * 32)

    snapshot = capture_repository_snapshot(tmp_path)

    assert snapshot.status == REPOSITORY_COMPLETE
    assert [artifact.relative_path for artifact in snapshot.artifacts] == [
        "nested/src/opaque.bin",
    ]
    # Eight pruned roots plus the nested/, nested/src/, file chain.
    assert snapshot.entry_count == 11


def test_explicitly_required_artifact_below_pruned_tree_is_still_captured(tmp_path: Path):
    hidden = tmp_path / "src"
    hidden.mkdir()
    payload = b"\x7fELF" + b"R" * 32
    (hidden / "payload").write_bytes(payload)

    snapshot = capture_repository_snapshot(
        tmp_path,
        required_relative_paths=("src/payload",),
    )

    assert snapshot.status == REPOSITORY_COMPLETE
    assert [item.relative_path for item in snapshot.artifacts] == ["src/payload"]
    assert snapshot.artifacts[0].sha256 == hashlib.sha256(payload).hexdigest()


def test_explicitly_required_artifact_overrides_generic_cache_pruning(tmp_path: Path):
    hidden = tmp_path / ".cache" / "nested"
    hidden.mkdir(parents=True)
    payload = b"\x7fELF" + b"C" * 32
    (hidden / "payload").write_bytes(payload)

    snapshot = capture_repository_snapshot(
        tmp_path,
        required_relative_paths=(".cache/nested/payload",),
    )

    assert snapshot.status == REPOSITORY_COMPLETE
    assert [item.relative_path for item in snapshot.artifacts] == [
        ".cache/nested/payload"
    ]
    assert snapshot.artifacts[0].sha256 == hashlib.sha256(payload).hexdigest()


def test_required_directory_overrides_nested_cache_pruning_without_duplicates(
    tmp_path: Path,
):
    hidden = tmp_path / "bundle" / "node_modules"
    hidden.mkdir(parents=True)
    payload = b"\x7fELF" + b"D" * 32
    (hidden / "payload").write_bytes(payload)

    snapshot = capture_repository_snapshot(
        tmp_path,
        required_relative_paths=("bundle",),
    )

    assert snapshot.status == REPOSITORY_COMPLETE
    assert snapshot.entry_count == 3
    assert [item.relative_path for item in snapshot.artifacts] == [
        "bundle/node_modules/payload"
    ]
    assert snapshot.artifacts[0].sha256 == hashlib.sha256(payload).hexdigest()


def test_required_directory_still_never_traverses_vcs_internals(tmp_path: Path):
    hidden = tmp_path / "bundle" / ".git"
    hidden.mkdir(parents=True)
    (hidden / "payload").write_bytes(b"\x7fELF" + b"V" * 32)

    snapshot = capture_repository_snapshot(
        tmp_path,
        required_relative_paths=("bundle",),
    )

    assert snapshot.status == REPOSITORY_COMPLETE
    assert snapshot.artifacts == ()


def test_declared_vcs_cache_subtree_is_source_owned_and_bounded(tmp_path: Path, monkeypatch):
    cache = tmp_path / "upstream"
    cache.mkdir()
    for index in range(4):
        (cache / f"object-{index}").write_bytes(b"\x7fELF" + bytes([index]) * 16)
    monkeypatch.setattr(provenance, "MAX_REPOSITORY_REGULAR_FILES", 1)

    snapshot = capture_repository_snapshot(
        tmp_path,
        excluded_subtree_relative_paths=("upstream",),
    )

    assert snapshot.status == REPOSITORY_COMPLETE
    assert snapshot.entry_count == 1
    assert snapshot.artifacts == ()


def test_required_file_overrides_declared_vcs_cache_subtree(tmp_path: Path):
    cache = tmp_path / "upstream" / "objects"
    cache.mkdir(parents=True)
    payload = b"\x7fELF" + b"R" * 32
    (cache / "payload").write_bytes(payload)

    snapshot = capture_repository_snapshot(
        tmp_path,
        excluded_subtree_relative_paths=("upstream",),
        required_relative_paths=("upstream/objects/payload",),
    )

    assert snapshot.status == REPOSITORY_COMPLETE
    assert [item.relative_path for item in snapshot.artifacts] == [
        "upstream/objects/payload"
    ]
    assert snapshot.artifacts[0].sha256 == hashlib.sha256(payload).hexdigest()


def test_declared_vcs_cache_wrong_type_fails_closed(tmp_path: Path):
    (tmp_path / "upstream").write_bytes(b"\x7fELF" + b"W" * 32)

    snapshot = capture_repository_snapshot(
        tmp_path,
        excluded_subtree_relative_paths=("upstream",),
    )

    assert snapshot.status == REPOSITORY_UNINSPECTED
    assert snapshot.error_code == "excluded_subtree_wrong_type"


def test_missing_required_path_does_not_create_manifest_drift(tmp_path: Path):
    (tmp_path / "notes.txt").write_text("same\n", encoding="utf-8")

    first = capture_repository_snapshot(tmp_path)
    second = capture_repository_snapshot(
        tmp_path,
        required_relative_paths=("missing/payload",),
    )

    assert first.status == second.status == REPOSITORY_COMPLETE
    assert first.input_digest == second.input_digest


def test_required_path_with_symlinked_component_fails_closed(tmp_path: Path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "payload").write_bytes(b"\x7fELF" + b"X" * 32)
    cache = tmp_path / ".cache"
    cache.symlink_to(outside, target_is_directory=True)

    snapshot = capture_repository_snapshot(
        tmp_path,
        required_relative_paths=(".cache/payload",),
    )

    assert snapshot.status == REPOSITORY_UNINSPECTED
    assert snapshot.error_code == "symlink_entry"


def test_backslash_name_fails_closed_instead_of_aliasing_slash_path(tmp_path: Path):
    (tmp_path / "dir\\payload").write_bytes(b"\x7fELF" + b"X" * 32)

    snapshot = capture_repository_snapshot(tmp_path)

    assert snapshot.status == REPOSITORY_UNINSPECTED
    assert snapshot.error_code == "unsafe_name"


def test_root_package_and_source_archives_are_marked_generated(tmp_path: Path):
    (tmp_path / "demo-1-1-any.pkg.tar.zst").write_bytes(
        b"\x28\xb5\x2f\xfd" + b"P" * 32
    )
    (tmp_path / "demo-1-1.src.tar.gz").write_bytes(
        b"\x1f\x8b\x08\x00" + b"\x00" * 6 + b"S" * 32
    )
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "demo-1-1-any.pkg.tar.zst").write_bytes(
        b"\x28\xb5\x2f\xfd" + b"N" * 32
    )

    snapshot = capture_repository_snapshot(tmp_path)

    by_path = {artifact.relative_path: artifact for artifact in snapshot.artifacts}
    assert by_path["demo-1-1-any.pkg.tar.zst"].generated_output is True
    assert by_path["demo-1-1.src.tar.gz"].generated_output is True
    assert by_path["nested/demo-1-1-any.pkg.tar.zst"].generated_output is False


def test_oversized_unreferenced_root_generated_archive_uses_metadata_identity(
    tmp_path: Path,
    monkeypatch,
):
    monkeypatch.setattr(provenance, "MAX_REPOSITORY_FILE_BYTES", 8)
    monkeypatch.setattr(provenance, "MAX_REPOSITORY_TOTAL_BYTES", 4)
    generated = tmp_path / "demo-1-1-any.pkg.tar.zst"
    generated.write_bytes(b"\x28\xb5\x2f\xfd" + b"A" * 8)

    first = capture_repository_snapshot(tmp_path)
    before = generated.stat()
    generated.write_bytes(b"\x28\xb5\x2f\xfd" + b"B" * 8)
    os.utime(str(generated), ns=(before.st_atime_ns, before.st_mtime_ns))
    second = capture_repository_snapshot(tmp_path)

    assert first.status == second.status == REPOSITORY_COMPLETE
    assert first.artifacts == second.artifacts == ()
    assert first.input_digest != second.input_digest


def test_oversized_required_root_generated_archive_fails_closed(
    tmp_path: Path,
    monkeypatch,
):
    monkeypatch.setattr(provenance, "MAX_REPOSITORY_FILE_BYTES", 8)
    generated = tmp_path / "demo-1-1-any.pkg.tar.zst"
    generated.write_bytes(b"\x28\xb5\x2f\xfd" + b"A" * 8)

    snapshot = capture_repository_snapshot(
        tmp_path,
        excluded_relative_paths=(generated.name,),
        required_relative_paths=(generated.name,),
    )

    assert snapshot.status == REPOSITORY_UNINSPECTED
    assert snapshot.error_code == "file_oversized"


@pytest.mark.parametrize("link_to_directory", [False, True])
def test_symlink_entries_fail_closed(tmp_path: Path, link_to_directory: bool):
    outside = tmp_path.parent / (tmp_path.name + "-outside")
    if link_to_directory:
        outside.mkdir()
    else:
        outside.write_bytes(b"\x7fELF" + b"X" * 32)
    (tmp_path / "linked").symlink_to(outside, target_is_directory=link_to_directory)

    snapshot = capture_repository_snapshot(tmp_path)

    assert snapshot.status == REPOSITORY_UNINSPECTED
    assert snapshot.error_code == "symlink_entry"
    assert len(snapshot.input_digest) == 64


def test_symlinked_root_fails_closed(tmp_path: Path):
    actual = tmp_path / "actual"
    actual.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(actual, target_is_directory=True)

    snapshot = capture_repository_snapshot(linked)

    assert snapshot.status == REPOSITORY_UNINSPECTED
    assert snapshot.error_code == "unsafe_root"


def test_special_entry_fails_closed(tmp_path: Path):
    fifo = tmp_path / "fixture.fifo"
    os.mkfifo(fifo)

    snapshot = capture_repository_snapshot(tmp_path)

    assert snapshot.status == REPOSITORY_UNINSPECTED
    assert snapshot.error_code == "special_entry"


def test_file_size_bound_fails_closed(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(provenance, "MAX_REPOSITORY_FILE_BYTES", 8)
    (tmp_path / "large.bin").write_bytes(b"\x7fELF" + b"X" * 8)

    snapshot = capture_repository_snapshot(tmp_path)

    assert snapshot.status == REPOSITORY_UNINSPECTED
    assert snapshot.error_code == "file_oversized"


def test_oversized_excluded_source_uses_stable_metadata_identity(
    tmp_path: Path,
    monkeypatch,
):
    monkeypatch.setattr(provenance, "MAX_REPOSITORY_FILE_BYTES", 8)
    source = tmp_path / "declared.bin"
    source.write_bytes(b"A" * 9)

    first = capture_repository_snapshot(
        tmp_path,
        excluded_relative_paths=("declared.bin",),
    )
    before = source.stat()
    source.write_bytes(b"B" * 9)
    os.utime(str(source), ns=(before.st_atime_ns, before.st_mtime_ns))
    second = capture_repository_snapshot(
        tmp_path,
        excluded_relative_paths=("declared.bin",),
    )

    assert first.status == second.status == REPOSITORY_COMPLETE
    assert first.artifacts == second.artifacts == ()
    assert first.input_digest != second.input_digest


def test_excluded_sources_do_not_consume_repository_total_byte_budget(
    tmp_path: Path,
    monkeypatch,
):
    monkeypatch.setattr(provenance, "MAX_REPOSITORY_TOTAL_BYTES", 8)
    (tmp_path / "declared-one.bin").write_bytes(b"A" * 8)
    (tmp_path / "declared-two.bin").write_bytes(b"B" * 8)
    (tmp_path / "metadata.txt").write_bytes(b"C" * 8)

    snapshot = capture_repository_snapshot(
        tmp_path,
        excluded_relative_paths=("declared-one.bin", "declared-two.bin"),
    )

    assert snapshot.status == REPOSITORY_COMPLETE
    assert snapshot.artifacts == ()


def test_total_size_bound_fails_closed(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(provenance, "MAX_REPOSITORY_TOTAL_BYTES", 10)
    (tmp_path / "one.txt").write_bytes(b"A" * 6)
    (tmp_path / "two.txt").write_bytes(b"B" * 6)

    snapshot = capture_repository_snapshot(tmp_path)

    assert snapshot.status == REPOSITORY_UNINSPECTED
    assert snapshot.error_code == "total_size_limit"


def test_entry_bound_fails_closed(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(provenance, "MAX_REPOSITORY_ENTRIES", 1)
    (tmp_path / "one.txt").write_text("one", encoding="utf-8")
    (tmp_path / "two.txt").write_text("two", encoding="utf-8")

    snapshot = capture_repository_snapshot(tmp_path)

    assert snapshot.status == REPOSITORY_UNINSPECTED
    assert snapshot.error_code == "entry_limit"
    assert snapshot.entry_count == 2


def test_regular_file_candidate_bound_fails_closed(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(provenance, "MAX_REPOSITORY_REGULAR_FILES", 1)
    (tmp_path / "one.txt").write_text("one", encoding="utf-8")
    (tmp_path / "two.txt").write_text("two", encoding="utf-8")

    snapshot = capture_repository_snapshot(tmp_path)

    assert snapshot.status == REPOSITORY_UNINSPECTED
    assert snapshot.error_code == "candidate_limit"


def test_opaque_artifact_bound_fails_closed_without_report_flood(tmp_path: Path, monkeypatch):
    monkeypatch.setattr(provenance, "MAX_REPOSITORY_ARTIFACTS", 1)
    (tmp_path / "one.bin").write_bytes(b"\x7fELF" + b"A" * 16)
    (tmp_path / "two.bin").write_bytes(b"\x7fELF" + b"B" * 16)

    snapshot = capture_repository_snapshot(tmp_path)

    assert snapshot.status == REPOSITORY_UNINSPECTED
    assert snapshot.error_code == "artifact_limit"
    assert len(snapshot.artifacts) == 1


def test_elapsed_time_bound_fails_closed(tmp_path: Path, monkeypatch):
    (tmp_path / "one.txt").write_text("one", encoding="utf-8")
    ticks = iter((10.0, 10.0, 30.0))
    monkeypatch.setattr(provenance, "MAX_REPOSITORY_ELAPSED_SECONDS", 5.0)
    monkeypatch.setattr(provenance.time, "monotonic", lambda: next(ticks, 30.0))

    snapshot = capture_repository_snapshot(tmp_path)

    assert snapshot.status == REPOSITORY_UNINSPECTED
    assert snapshot.error_code == "elapsed_time_limit"


def test_unreadable_regular_file_fails_closed(tmp_path: Path, monkeypatch):
    candidate = tmp_path / "opaque.bin"
    candidate.write_bytes(b"\x7fELF" + b"X" * 32)
    real_open = provenance.os.open

    def refusing_open(path, flags, *args, **kwargs):
        if path == "opaque.bin" and kwargs.get("dir_fd") is not None:
            raise PermissionError("fixture refusal")
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(provenance.os, "open", refusing_open)

    snapshot = capture_repository_snapshot(tmp_path)

    assert snapshot.status == REPOSITORY_UNINSPECTED
    assert snapshot.error_code == "file_unreadable"


def test_mid_read_change_fails_closed(tmp_path: Path, monkeypatch):
    candidate = tmp_path / "opaque.bin"
    original = b"\x7fELF" + b"X" * 70_000
    candidate.write_bytes(original)
    real_read = provenance.os.read
    changed = [False]

    def racing_read(file_descriptor, size):
        chunk = real_read(file_descriptor, size)
        if chunk and not changed[0]:
            changed[0] = True
            candidate.write_bytes(original + b"changed")
        return chunk

    monkeypatch.setattr(provenance.os, "read", racing_read)

    snapshot = capture_repository_snapshot(tmp_path)

    assert snapshot.status == REPOSITORY_UNINSPECTED
    assert snapshot.error_code == "file_changed"


def test_change_after_early_subtree_capture_fails_global_revalidation(
    tmp_path: Path,
    monkeypatch,
):
    early = tmp_path / "early"
    early.mkdir()
    candidate = early / "payload"
    candidate.write_bytes(b"ordinary inert bytes")
    tail = tmp_path / "tail"
    tail.mkdir()
    (tail / "later").write_bytes(b"later")
    original_walk = provenance._walk_child_directory
    changed = [False]

    def changing_walk(parent_fd, name, expected, parts, depth, state, **kwargs):
        original_walk(parent_fd, name, expected, parts, depth, state, **kwargs)
        if name == "early" and not changed[0]:
            changed[0] = True
            candidate.write_bytes(b"\x7fELF" + b"changed after subtree")

    monkeypatch.setattr(provenance, "_walk_child_directory", changing_walk)

    snapshot = capture_repository_snapshot(tmp_path)

    assert changed[0] is True
    assert snapshot.status == REPOSITORY_UNINSPECTED
    assert snapshot.error_code == "file_changed"


def test_invalid_exclusion_fails_closed_without_traversal(tmp_path: Path):
    (tmp_path / "opaque.bin").write_bytes(b"\x7fELF" + b"X" * 32)

    snapshot = capture_repository_snapshot(
        tmp_path,
        excluded_relative_paths=("../opaque.bin",),
    )

    assert snapshot.status == REPOSITORY_UNINSPECTED
    assert snapshot.error_code == "invalid_exclusion"
    assert snapshot.entry_count == 0
    assert snapshot.artifacts == ()


def test_missing_no_follow_support_fails_closed(tmp_path: Path, monkeypatch):
    (tmp_path / "opaque.bin").write_bytes(b"\x7fELF" + b"X" * 32)
    monkeypatch.setattr(provenance.os, "O_NOFOLLOW", 0)

    snapshot = capture_repository_snapshot(tmp_path)

    assert snapshot.status == REPOSITORY_UNINSPECTED
    assert snapshot.error_code == "no_follow_unavailable"
    assert snapshot.entry_count == 0


def test_snapshot_and_artifact_records_are_immutable(tmp_path: Path):
    (tmp_path / "opaque.bin").write_bytes(b"\x7fELF" + b"X" * 32)
    snapshot = capture_repository_snapshot(tmp_path)

    with pytest.raises(FrozenInstanceError):
        snapshot.status = REPOSITORY_UNINSPECTED
    with pytest.raises(FrozenInstanceError):
        snapshot.artifacts[0].kind = "zip"
    assert isinstance(snapshot.artifacts, tuple)
    assert stat.S_IMODE(snapshot.artifacts[0].mode) == 0o644
