#!/usr/bin/python3
"""Minimal trust bootstrap for the root recovery smoke supervisor."""

import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path


SCHEMA = "aurascan_recovery_validation_attestation/1.0"
LIMIT = 256 * 1024
ROLES = {
    "smoke_bootstrap",
    "smoke_launcher",
    "secure_boot_preparer",
    "qemu_iso_harness",
    "qemu_uki_harness",
    "smoke_tool_guard",
    "smoke_guard",
    "smoke_marker_asset",
    "smoke_marker_iso_profile",
    "smoke_marker_expanded_iso",
    "smoke_marker_validation_uki_overlay",
    "iso",
    "iso_sha256",
    "iso_packages",
    "validation_uki",
    "validation_uki_sha256",
}
ENTRY_FIELDS = {
    "path",
    "sha256",
    "size",
    "device",
    "inode",
    "mode",
    "uid",
    "gid",
    "mtime_ns",
    "ctime_ns",
}


class Refusal(RuntimeError):
    pass


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise Refusal("private validation attestation contains duplicate keys")
        value[key] = item
    return value


def _identity(metadata):
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _safe_path(value):
    if not isinstance(value, str) or not value.startswith("/") or "," in value:
        raise Refusal("attested smoke path is unsafe")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise Refusal("attested smoke path is unsafe")
    path = Path(os.path.abspath(value))
    if str(path) != value:
        raise Refusal("attested smoke path is not canonical")
    return path


def _root_chain(path, include_final=False):
    path = _safe_path(str(path))
    current = Path(path.parts[0])
    stop = len(path.parts) if include_final else len(path.parts) - 1
    for component in path.parts[1:stop]:
        current /= component
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise Refusal("attested smoke path is not rooted in trusted directories")
        if current != path and not stat.S_ISDIR(metadata.st_mode):
            raise Refusal("attested smoke path component is not a directory")


def _open(path, maximum):
    _root_chain(path)
    before = path.lstat()
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != 0
        or before.st_mode & 0o022
        or before.st_size < 1
        or before.st_size >= maximum
    ):
        raise Refusal("attested smoke file identity is unsafe")
    descriptor = os.open(
        str(path),
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    if _identity(os.fstat(descriptor)) != _identity(before):
        os.close(descriptor)
        raise Refusal("attested smoke file changed while opening")
    return descriptor, before


def _read(descriptor, metadata, maximum, digest=False):
    chunks = []
    hasher = hashlib.sha256()
    consumed = 0
    while consumed < metadata.st_size:
        chunk = os.pread(
            descriptor, min(1024 * 1024, metadata.st_size - consumed), consumed
        )
        if not chunk:
            raise Refusal("attested smoke file ended while reading")
        if digest:
            hasher.update(chunk)
        else:
            chunks.append(chunk)
        consumed += len(chunk)
        if consumed >= maximum:
            raise Refusal("attested smoke file exceeds its bound")
    if _identity(os.fstat(descriptor)) != _identity(metadata):
        raise Refusal("attested smoke file changed while reading")
    return hasher.hexdigest() if digest else b"".join(chunks)


def _entry_shape(entry):
    if not isinstance(entry, dict) or set(entry) != ENTRY_FIELDS:
        raise Refusal("attested smoke file record is malformed")
    if not isinstance(entry["sha256"], str) or re.fullmatch(
        r"[0-9a-f]{64}", entry["sha256"]
    ) is None:
        raise Refusal("attested smoke digest is malformed")
    for key in ENTRY_FIELDS - {"path", "sha256"}:
        if type(entry[key]) is not int or entry[key] < 0:
            raise Refusal("attested smoke file record is malformed")
    return entry


def _verify(entry, expected=None):
    entry = _entry_shape(entry)
    path = _safe_path(entry["path"])
    if expected is not None and path != expected:
        raise Refusal("running smoke component is not the attested path")
    descriptor, metadata = _open(path, 4 * 1024 * 1024)
    try:
        digest = _read(descriptor, metadata, 4 * 1024 * 1024, digest=True)
    finally:
        os.close(descriptor)
    observed = {
        "path": str(path),
        "sha256": digest,
        "size": metadata.st_size,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mtime_ns": metadata.st_mtime_ns,
        "ctime_ns": metadata.st_ctime_ns,
    }
    if observed != entry:
        raise Refusal("attested smoke component changed")
    return path


def main():
    try:
        if os.geteuid() != 0:
            raise Refusal("recovery smoke bootstrap must start as root")
        try:
            attestation_index = sys.argv.index("--attestation")
            receipt_path = _safe_path(sys.argv[attestation_index + 1])
        except (ValueError, IndexError) as exc:
            raise Refusal("--attestation must select the private builder receipt") from exc
        kinds = [(index, value) for index, value in enumerate(sys.argv) if value in {"iso", "uki"}]
        if len(kinds) != 1:
            raise Refusal("smoke bootstrap requires one artifact kind")
        harness_role = "qemu_iso_harness" if kinds[0][1] == "iso" else "qemu_uki_harness"
        descriptor, metadata = _open(receipt_path, LIMIT)
        try:
            if stat.S_IMODE(metadata.st_mode) != 0o400:
                raise Refusal("private builder attestation must have mode 0400")
            raw = _read(descriptor, metadata, LIMIT)
        finally:
            os.close(descriptor)
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_unique)
        if not isinstance(value, dict) or set(value) != {
            "schema",
            "version",
            "source_commit",
            "files",
            "firmware",
            "run_inputs",
            "run",
        }:
            raise Refusal("private builder attestation has an unsupported shape")
        if (
            value["schema"] != SCHEMA
            or value["firmware"] != {}
            or value["run_inputs"] != {}
            or value["run"] is not None
            or not isinstance(value["files"], dict)
            or set(value["files"]) != ROLES
        ):
            raise Refusal("private builder attestation is not the exact base receipt")
        running = Path(__file__).resolve(strict=True)
        _verify(value["files"]["smoke_bootstrap"], running)
        launcher = _verify(value["files"]["smoke_launcher"])
        _verify(value["files"][harness_role])
        _verify(value["files"]["smoke_tool_guard"])
        _verify(value["files"]["smoke_guard"])
        python = Path(sys.executable).resolve(strict=True)
        _root_chain(python, include_final=True)
        python_metadata = python.lstat()
        if (
            not stat.S_ISREG(python_metadata.st_mode)
            or python_metadata.st_uid != 0
            or python_metadata.st_mode & 0o022
            or not os.access(str(python), os.X_OK)
        ):
            raise Refusal("trusted isolated Python is unavailable")
        environment = {
            "PATH": "/usr/bin:/bin",
            "HOME": "/root",
            "USER": "root",
            "LOGNAME": "root",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "TZ": "UTC",
        }
        timeout = os.environ.get("AURASCAN_QEMU_TIMEOUT_SECONDS")
        if timeout is not None:
            if not timeout.isdigit() or not 30 <= int(timeout) <= 900:
                raise Refusal("AURASCAN_QEMU_TIMEOUT_SECONDS is invalid")
            environment["AURASCAN_QEMU_TIMEOUT_SECONDS"] = timeout
        os.execve(
            str(python),
            [str(python), "-I", "-S", str(launcher)] + sys.argv[1:],
            environment,
        )
    except (Refusal, OSError, TypeError, UnicodeError, ValueError) as exc:
        print("Recovery smoke bootstrap refused: {}".format(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
