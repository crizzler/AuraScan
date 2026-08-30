import io
import os
import stat
import struct
import tarfile
import zipfile
from pathlib import Path

import pytest

from aurascan.core.archive import SafeArchiveExtractor
from aurascan.core.models import Severity


def write_tar(path: Path, entries):
    with tarfile.open(path, "w") as archive:
        for name, content, mode, kind, linkname in entries:
            info = tarfile.TarInfo(name)
            info.mode = mode
            if kind == "dir":
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            elif kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = linkname
                archive.addfile(info)
            elif kind == "hardlink":
                info.type = tarfile.LNKTYPE
                info.linkname = linkname
                archive.addfile(info)
            else:
                data = content.encode()
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))


def write_zip(path: Path, entries):
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, content in entries:
            archive.writestr(name, content)


def test_normal_archive_extracts(tmp_path: Path):
    archive = tmp_path / "src.tar"
    write_tar(archive, [("src/file.txt", "hello", 0o644, "file", "")])

    target, findings = SafeArchiveExtractor().extract(str(archive), str(tmp_path / "out"))

    assert not any(f.blocks_installation for f in findings)
    assert (target / "src/file.txt").read_text() == "hello"


def test_path_traversal_archive_blocks(tmp_path: Path):
    archive = tmp_path / "evil.tar"
    write_tar(archive, [("../escape.txt", "x", 0o644, "file", "")])

    findings = SafeArchiveExtractor().inspect(str(archive))

    assert any(f.rule_id == "ARCHIVE-PATH-TRAVERSAL" for f in findings)


def test_absolute_path_archive_blocks(tmp_path: Path):
    archive = tmp_path / "evil.tar"
    write_tar(archive, [("/etc/passwd", "x", 0o644, "file", "")])

    findings = SafeArchiveExtractor().inspect(str(archive))

    assert any(f.rule_id == "ARCHIVE-PATH-TRAVERSAL" for f in findings)


def test_symlink_escape_blocks(tmp_path: Path):
    archive = tmp_path / "evil.tar"
    write_tar(archive, [("src/link", "", 0o777, "symlink", "../../outside")])

    findings = SafeArchiveExtractor().inspect(str(archive))

    assert any(f.rule_id == "ARCHIVE-SYMLINK-ESCAPE" for f in findings)


def test_hardlink_escape_blocks(tmp_path: Path):
    archive = tmp_path / "evil.tar"
    write_tar(archive, [("src/link", "", 0o777, "hardlink", "/etc/passwd")])

    findings = SafeArchiveExtractor().inspect(str(archive))

    assert any(f.rule_id == "ARCHIVE-HARDLINK-ESCAPE" for f in findings)


@pytest.mark.parametrize("link_kind", ["symlink", "hardlink"])
def test_safe_archive_links_fail_closed_instead_of_being_silently_skipped(
    tmp_path: Path,
    link_kind: str,
):
    archive = tmp_path / "linked.tar"
    write_tar(archive, [
        ("src/target", "content", 0o644, "file", ""),
        ("src/linked", "", 0o777, link_kind, "target"),
    ])

    target, findings = SafeArchiveExtractor().extract(
        str(archive),
        str(tmp_path / "out"),
    )

    assert target == Path()
    assert not (tmp_path / "out").exists()
    assert any(
        finding.rule_id == "ARCHIVE-LINK-UNINSPECTED" and finding.blocks_installation
        for finding in findings
    )


def test_zip_symlink_entry_fails_closed(tmp_path: Path):
    archive = tmp_path / "linked.zip"
    with zipfile.ZipFile(archive, "w") as packaged:
        info = zipfile.ZipInfo("src/linked")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        packaged.writestr(info, "target")

    findings = SafeArchiveExtractor().inspect(str(archive))

    assert any(
        finding.rule_id == "ARCHIVE-LINK-UNINSPECTED" and finding.blocks_installation
        for finding in findings
    )


def test_too_many_files_blocks(tmp_path: Path):
    archive = tmp_path / "many.tar"
    write_tar(archive, [(f"f{idx}", "x", 0o644, "file", "") for idx in range(3)])

    findings = SafeArchiveExtractor(max_files=2).inspect(str(archive))

    assert any(f.rule_id == "ARCHIVE-TOO-MANY-FILES" for f in findings)


def test_zip_with_too_many_entries_blocks(tmp_path: Path):
    archive = tmp_path / "many.zip"
    write_zip(archive, [(f"f{index}", "x") for index in range(3)])

    findings = SafeArchiveExtractor(max_files=2).inspect(str(archive))

    assert any(f.rule_id == "ARCHIVE-TOO-MANY-FILES" for f in findings)


def test_zip_declared_entry_count_is_bounded_before_zipfile_allocation(tmp_path: Path):
    archive = tmp_path / "declared-many.zip"
    write_zip(archive, [("file", "x")])
    payload = bytearray(archive.read_bytes())
    end_record = payload.rindex(b"PK\x05\x06")
    struct.pack_into("<H", payload, end_record + 8, 500)
    struct.pack_into("<H", payload, end_record + 10, 500)
    archive.write_bytes(payload)

    findings = SafeArchiveExtractor(max_files=10).inspect(str(archive))

    assert any(
        finding.rule_id == "ARCHIVE-TOO-MANY-FILES" and finding.blocks_installation
        for finding in findings
    )


def test_metadata_iteration_stops_at_entry_limit(tmp_path: Path):
    archive = tmp_path / "bounded.tar"
    write_tar(archive, [("file", "x", 0o644, "file", "")])

    class CountingEntriesExtractor(SafeArchiveExtractor):
        def __init__(self):
            super().__init__(max_files=2)
            self.entries_read = 0

        def _entries(self, archive_path):
            for index in range(1000):
                self.entries_read += 1
                yield f"file-{index}", 1, 0o644, "file", ""

    extractor = CountingEntriesExtractor()

    findings = extractor.inspect(str(archive))

    assert extractor.entries_read == 3
    assert any(f.rule_id == "ARCHIVE-TOO-MANY-FILES" for f in findings)


def test_oversized_decompressed_content_blocks(tmp_path: Path):
    archive = tmp_path / "big.tar"
    write_tar(archive, [("big", "x" * 20, 0o644, "file", "")])

    findings = SafeArchiveExtractor(max_total_size=10).inspect(str(archive))

    assert any(f.rule_id == "ARCHIVE-OVERSIZED" for f in findings)


@pytest.mark.parametrize("metadata_kind", ["pax", "gnu_longname"])
def test_compressed_tar_extended_metadata_is_bounded_before_tarfile_allocation(
    tmp_path: Path,
    monkeypatch,
    metadata_kind: str,
):
    archive = tmp_path / f"metadata-{metadata_kind}.tar.gz"
    archive_format = tarfile.PAX_FORMAT if metadata_kind == "pax" else tarfile.GNU_FORMAT
    with tarfile.open(archive, "w:gz", format=archive_format) as packaged:
        name = "payload"
        info = tarfile.TarInfo(name)
        if metadata_kind == "pax":
            info.pax_headers = {"comment": "x" * 4096}
        else:
            info.name = "x" * 4096
        info.size = 1
        packaged.addfile(info, io.BytesIO(b"x"))

    assert archive.stat().st_size < 1024

    def unexpected_tarfile_parse(*args, **kwargs):
        raise AssertionError("tarfile parser ran before extended metadata was bounded")

    monkeypatch.setattr("aurascan.core.archive.tarfile.open", unexpected_tarfile_parse)

    findings = SafeArchiveExtractor(max_total_size=1024).inspect(str(archive))

    assert any(
        finding.rule_id == "ARCHIVE-OVERSIZED" and finding.blocks_installation
        for finding in findings
    )


@pytest.mark.parametrize("archive_kind", ["tar", "zip"])
def test_actual_extracted_bytes_enforce_limit_when_metadata_underreports(
    tmp_path: Path,
    archive_kind: str,
):
    archive = tmp_path / f"underreported.{archive_kind}"
    if archive_kind == "tar":
        write_tar(archive, [("payload", "x" * 32, 0o644, "file", "")])
    else:
        write_zip(archive, [("payload", "x" * 32)])

    class UnderreportingExtractor(SafeArchiveExtractor):
        def _entries(self, archive_path):
            for name, _size, mode, kind, linkname in super()._entries(archive_path):
                yield name, 0, mode, kind, linkname

    target = tmp_path / "out"
    extractor = UnderreportingExtractor(max_total_size=8)

    extracted, findings = extractor.extract(str(archive), str(target))

    assert extracted == Path()
    assert not target.exists()
    assert not list(tmp_path.glob(".aurascan-extract-*"))
    assert any(
        finding.rule_id == "ARCHIVE-OVERSIZED" and finding.blocks_installation
        for finding in findings
    )


@pytest.mark.parametrize("archive_kind", ["tar", "zip"])
def test_actual_extracted_entry_count_enforces_limit_when_metadata_underreports(
    tmp_path: Path,
    archive_kind: str,
):
    archive = tmp_path / f"underreported-count.{archive_kind}"
    entries = [(f"file-{index}", "x") for index in range(3)]
    if archive_kind == "tar":
        write_tar(
            archive,
            [(name, content, 0o644, "file", "") for name, content in entries],
        )
    else:
        write_zip(archive, entries)

    class UnderreportingExtractor(SafeArchiveExtractor):
        def _entries(self, archive_path):
            for index, entry in enumerate(super()._entries(archive_path)):
                if index >= 2:
                    break
                yield entry

    target = tmp_path / "out"
    extractor = UnderreportingExtractor(max_files=2)

    extracted, findings = extractor.extract(str(archive), str(target))

    assert extracted == Path()
    assert not target.exists()
    assert not list(tmp_path.glob(".aurascan-extract-*"))
    assert any(
        finding.rule_id == "ARCHIVE-TOO-MANY-FILES" and finding.blocks_installation
        for finding in findings
    )


def test_forged_zip_member_size_fails_closed_and_cleans_output(tmp_path: Path):
    archive = tmp_path / "forged.zip"
    write_zip(archive, [("payload", "x" * 20)])
    payload = bytearray(archive.read_bytes())
    central_header = payload.index(b"PK\x01\x02")
    struct.pack_into("<L", payload, central_header + 24, 50)
    archive.write_bytes(payload)
    target = tmp_path / "out"

    extracted, findings = SafeArchiveExtractor(max_total_size=100).extract(
        str(archive),
        str(target),
    )

    assert extracted == Path()
    assert not target.exists()
    assert not list(tmp_path.glob(".aurascan-extract-*"))
    assert any(
        finding.rule_id == "ARCHIVE-EXTRACTION-FAILED" and finding.blocks_installation
        for finding in findings
    )


def test_nested_archive_depth_exceeded_blocks(tmp_path: Path):
    archive = tmp_path / "nested.tar"
    write_tar(archive, [("inner.zip", "not really zip", 0o644, "file", "")])

    findings = SafeArchiveExtractor(max_depth=0).inspect(str(archive), depth=0)

    assert any(f.rule_id == "ARCHIVE-NESTED-DEPTH" for f in findings)


def test_unsupported_archive_format_blocks(tmp_path: Path):
    archive = tmp_path / "plain.txt"
    archive.write_text("not an archive")

    findings = SafeArchiveExtractor().inspect(str(archive))

    finding = next(f for f in findings if f.rule_id == "ARCHIVE-UNSUPPORTED")
    assert finding.severity == Severity.HIGH
    assert finding.blocks_installation is True


@pytest.mark.parametrize("input_kind", ["symlink", "directory", "fifo"])
def test_archive_input_must_be_a_nofollow_regular_file(tmp_path: Path, input_kind: str):
    archive = tmp_path / "input.tar"
    if input_kind == "symlink":
        target = tmp_path / "target.tar"
        write_tar(target, [("file", "x", 0o644, "file", "")])
        archive.symlink_to(target)
    elif input_kind == "directory":
        archive.mkdir()
    else:
        os.mkfifo(archive)

    findings = SafeArchiveExtractor().inspect(str(archive))

    assert any(
        finding.rule_id == "ARCHIVE-INPUT-UNSAFE" and finding.blocks_installation
        for finding in findings
    )


def test_archive_input_with_symlinked_directory_component_is_rejected(tmp_path: Path):
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    archive = real_dir / "input.tar"
    write_tar(archive, [("file", "x", 0o644, "file", "")])
    linked_dir = tmp_path / "linked"
    linked_dir.symlink_to(real_dir, target_is_directory=True)

    findings = SafeArchiveExtractor().inspect(str(linked_dir / "input.tar"))

    assert any(finding.rule_id == "ARCHIVE-INPUT-UNSAFE" for finding in findings)


def test_oversized_archive_input_is_rejected_before_parsing(tmp_path: Path):
    archive = tmp_path / "input.tar"
    archive.write_bytes(b"x" * 32)

    findings = SafeArchiveExtractor(max_archive_size=8).inspect(str(archive))

    assert any(
        finding.rule_id == "ARCHIVE-INPUT-UNSAFE" and finding.blocks_installation
        for finding in findings
    )


def test_archive_changed_during_snapshot_is_rejected(tmp_path: Path, monkeypatch):
    archive = tmp_path / "input.tar"
    write_tar(archive, [("file", "x" * 70000, 0o644, "file", "")])
    real_read = os.read
    reads = 0

    def changing_read(fd, count):
        nonlocal reads
        payload = real_read(fd, count)
        reads += 1
        if reads == 1:
            with archive.open("r+b") as handle:
                handle.seek(1024)
                handle.write(b"changed")
        return payload

    monkeypatch.setattr("aurascan.core.archive.os.read", changing_read)

    findings = SafeArchiveExtractor().inspect(str(archive))

    assert any(finding.rule_id == "ARCHIVE-INPUT-UNSAFE" for finding in findings)


def test_original_path_replacement_cannot_change_captured_extraction(tmp_path: Path):
    archive = tmp_path / "input.tar"
    replacement = tmp_path / "replacement.tar"
    write_tar(archive, [("original.txt", "original", 0o644, "file", "")])
    write_tar(replacement, [("replacement.txt", "replacement", 0o644, "file", "")])

    class ReplacingExtractor(SafeArchiveExtractor):
        def _inspect_snapshot(self, snapshot_path, display_path, phase, depth):
            findings = super()._inspect_snapshot(snapshot_path, display_path, phase, depth)
            os.replace(str(replacement), str(archive))
            return findings

    target, findings = ReplacingExtractor().extract(str(archive), str(tmp_path / "out"))

    assert not any(finding.blocks_installation for finding in findings)
    assert (target / "original.txt").read_text(encoding="utf-8") == "original"
    assert not (target / "replacement.txt").exists()


def test_snapshot_replacement_fails_closed_and_cleans_output(tmp_path: Path):
    archive = tmp_path / "input.tar"
    replacement = tmp_path / "replacement.tar"
    write_tar(archive, [("original.txt", "original", 0o644, "file", "")])
    write_tar(replacement, [("replacement.txt", "replacement", 0o644, "file", "")])

    class SnapshotReplacingExtractor(SafeArchiveExtractor):
        def _inspect_snapshot(self, snapshot_path, display_path, phase, depth):
            findings = super()._inspect_snapshot(snapshot_path, display_path, phase, depth)
            snapshot_path.chmod(0o600)
            snapshot_path.write_bytes(replacement.read_bytes())
            return findings

    target_path = tmp_path / "out"
    target, findings = SnapshotReplacingExtractor().extract(
        str(archive),
        str(target_path),
    )

    assert target == Path()
    assert not target_path.exists()
    assert not list(tmp_path.glob(".aurascan-extract-*"))
    assert any(finding.rule_id == "ARCHIVE-INPUT-UNSAFE" for finding in findings)


def test_tar_special_file_entry_blocks(tmp_path: Path):
    archive = tmp_path / "special.tar"
    with tarfile.open(archive, "w") as packaged:
        info = tarfile.TarInfo("named-pipe")
        info.type = tarfile.FIFOTYPE
        packaged.addfile(info)

    findings = SafeArchiveExtractor().inspect(str(archive))

    assert any(
        finding.rule_id == "ARCHIVE-SPECIAL-FILE" and finding.blocks_installation
        for finding in findings
    )


def test_suspicious_executable_file_warns(tmp_path: Path):
    archive = tmp_path / "exec.tar"
    write_tar(archive, [("src/run.sh", "echo harmless", 0o755, "file", "")])

    findings = SafeArchiveExtractor().inspect(str(archive))

    assert any(f.rule_id == "ARCHIVE-SUSPICIOUS-FILE" for f in findings)


def test_hidden_suspicious_file_warns_in_zip(tmp_path: Path):
    archive = tmp_path / "hidden.zip"
    with zipfile.ZipFile(archive, "w") as zipped:
        info = zipfile.ZipInfo("src/.hook.sh")
        info.external_attr = (0o644 & 0xFFFF) << 16
        zipped.writestr(info, "echo harmless")

    findings = SafeArchiveExtractor().inspect(str(archive))

    assert any(f.rule_id == "ARCHIVE-SUSPICIOUS-FILE" for f in findings)
