import hashlib
import io
import os
import tarfile
from pathlib import Path

from aurascan.core.pacman_sync_db import (
    OfficialPackageIndex,
    load_official_package_index,
    package_matches_official,
    package_sha256,
)


def _descriptor(filename: str, checksum: str, name: str = "demo", version: str = "1.0-1") -> bytes:
    return (
        f"%FILENAME%\n{filename}\n\n"
        f"%NAME%\n{name}\n\n"
        f"%VERSION%\n{version}\n\n"
        f"%SHA256SUM%\n{checksum}\n\n"
    ).encode("utf-8")


def _write_sync_db(path: Path, descriptors) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for index, (entry_name, payload) in enumerate(descriptors):
            info = tarfile.TarInfo(entry_name)
            info.size = len(payload)
            info.mtime = 1
            archive.addfile(info, io.BytesIO(payload))


def _write_package(path: Path, payload: bytes) -> str:
    path.write_bytes(payload)
    return hashlib.sha256(payload).hexdigest()


def test_official_index_binds_repository_filename_to_sha256(tmp_path):
    package = tmp_path / "demo-1.0-1-x86_64.pkg.tar.zst"
    checksum = _write_package(package, b"official-package-bytes")
    _write_sync_db(
        tmp_path / "extra.db",
        [("demo-1.0-1/desc", _descriptor(package.name, checksum))],
    )

    index = load_official_package_index(tmp_path)

    assert index.complete is True
    assert index.filenames == {package.name: frozenset({checksum})}
    assert index.providers == {}
    assert package_matches_official(package, index) is True


def test_official_index_maps_soname_provides_to_package(tmp_path):
    payload = (
        "%FILENAME%\nsimdutf-9.2.1-2-x86_64.pkg.tar.zst\n\n"
        "%NAME%\nsimdutf\n\n"
        "%VERSION%\n9.2.1-2\n\n"
        "%SHA256SUM%\n" + "a" * 64 + "\n\n"
        "%PROVIDES%\nlibsimdutf.so=36-64\n\n"
    ).encode("utf-8")
    _write_sync_db(tmp_path / "extra.db", [("simdutf-9.2.1-2/desc", payload)])

    index = load_official_package_index(tmp_path)

    assert index.providers["libsimdutf.so.36"] == frozenset({"simdutf"})
    assert index.providers["libsimdutf.so"] == frozenset({"simdutf"})


def test_official_index_accepts_duplicate_filename_from_another_repository(tmp_path):
    package = tmp_path / "demo-1.0-1-x86_64.pkg.tar.zst"
    repository_checksum = _write_package(package, b"rebuild-bytes")
    other_checksum = hashlib.sha256(b"upstream-bytes").hexdigest()
    _write_sync_db(
        tmp_path / "extra.db",
        [("demo-1.0-1/desc", _descriptor(package.name, other_checksum))],
    )
    _write_sync_db(
        tmp_path / "cachyos.db",
        [("demo-1.0-1/desc", _descriptor(package.name, repository_checksum))],
    )

    index = load_official_package_index(tmp_path)

    assert index.filenames == {package.name: frozenset({other_checksum, repository_checksum})}
    assert package_matches_official(package, index) is True


def test_official_index_rejects_changed_package_bytes(tmp_path):
    package = tmp_path / "demo-1.0-1-x86_64.pkg.tar.zst"
    checksum = _write_package(package, b"original-bytes")
    _write_sync_db(
        tmp_path / "extra.db",
        [("demo-1.0-1/desc", _descriptor(package.name, checksum))],
    )
    index = load_official_package_index(tmp_path)
    package.write_bytes(b"replaced-bytes")

    assert package_matches_official(package, index) is False


def test_official_index_ignores_unknown_archive(tmp_path):
    package = tmp_path / "local-1.0-1-x86_64.pkg.tar.zst"
    _write_package(package, b"local")
    _write_sync_db(
        tmp_path / "core.db",
        [("demo-1.0-1/desc", _descriptor("demo-1.0-1-x86_64.pkg.tar.zst", "a" * 64))],
    )

    index = load_official_package_index(tmp_path)

    assert package_matches_official(package, index) is False


def test_official_index_marks_corrupt_database_incomplete_but_keeps_known_entries(tmp_path):
    package = tmp_path / "demo-1.0-1-x86_64.pkg.tar.zst"
    checksum = _write_package(package, b"official")
    _write_sync_db(
        tmp_path / "core.db",
        [("demo-1.0-1/desc", _descriptor(package.name, checksum))],
    )
    (tmp_path / "extra.db").write_bytes(b"not a tar archive")

    index = load_official_package_index(tmp_path)

    assert index.complete is False
    assert "could not be read" in index.reason
    assert package_matches_official(package, index) is True


def test_official_index_without_databases_is_incomplete(tmp_path):
    index = load_official_package_index(tmp_path)

    assert index.complete is False
    assert index.filenames == {}
    assert "no sync databases" in index.reason


def test_package_sha256_refuses_non_regular_file(tmp_path):
    target = tmp_path / "target.pkg.tar.zst"
    target.write_bytes(b"target")
    link = tmp_path / "link.pkg.tar.zst"
    os.symlink(target, link)

    assert package_sha256(link) == ""


def test_official_index_rejects_malformed_checksum(tmp_path):
    package = tmp_path / "demo-1.0-1-x86_64.pkg.tar.zst"
    _write_package(package, b"official")
    _write_sync_db(
        tmp_path / "core.db",
        [("demo-1.0-1/desc", _descriptor(package.name, "not-a-checksum"))],
    )

    index = load_official_package_index(tmp_path)

    assert index.filenames == {}
    assert package_matches_official(package, index) is False
