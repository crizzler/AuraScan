import io
import os
import tarfile
import zipfile
from pathlib import Path

from aurascan.core.archive import SafeArchiveExtractor


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


def test_too_many_files_blocks(tmp_path: Path):
    archive = tmp_path / "many.tar"
    write_tar(archive, [(f"f{idx}", "x", 0o644, "file", "") for idx in range(3)])

    findings = SafeArchiveExtractor(max_files=2).inspect(str(archive))

    assert any(f.rule_id == "ARCHIVE-TOO-MANY-FILES" for f in findings)


def test_oversized_decompressed_content_blocks(tmp_path: Path):
    archive = tmp_path / "big.tar"
    write_tar(archive, [("big", "x" * 20, 0o644, "file", "")])

    findings = SafeArchiveExtractor(max_total_size=10).inspect(str(archive))

    assert any(f.rule_id == "ARCHIVE-OVERSIZED" for f in findings)


def test_nested_archive_depth_exceeded_blocks(tmp_path: Path):
    archive = tmp_path / "nested.tar"
    write_tar(archive, [("inner.zip", "not really zip", 0o644, "file", "")])

    findings = SafeArchiveExtractor(max_depth=0).inspect(str(archive), depth=0)

    assert any(f.rule_id == "ARCHIVE-NESTED-DEPTH" for f in findings)


def test_unsupported_archive_format_blocks(tmp_path: Path):
    archive = tmp_path / "plain.txt"
    archive.write_text("not an archive")

    findings = SafeArchiveExtractor().inspect(str(archive))

    assert any(f.rule_id == "ARCHIVE-UNSUPPORTED" for f in findings)


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
