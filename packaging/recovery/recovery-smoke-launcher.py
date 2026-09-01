#!/usr/bin/env python3
"""Root preflight for an attested, unprivileged recovery smoke run.

The launcher is intentionally independent from the candidate smoke guard.  It
opens the root-only build receipt with no-follow semantics, verifies the exact
candidate harness and guards before Bash reads them, binds the selected
firmware and other per-run inputs, and then drops to an unmapped UID through a
fixed trusted ``setpriv`` before executing the harness.
"""

from __future__ import annotations

import argparse
import ctypes
import grp
import hashlib
import json
import os
import pwd
import re
import resource
import secrets
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Dict, Mapping, Optional, Sequence, Tuple


SCHEMA = "aurascan_recovery_validation_attestation/1.0"
RECEIPT_LIMIT = 256 * 1024
FILE_LIMIT = 2 * 1024 * 1024 * 1024
UKI_FILE_LIMIT = 512 * 1024 * 1024
DROP_UID = 60998
DROP_GID = 60998
BASE_ROLES = {
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
TOP_FIELDS = {
    "schema",
    "version",
    "source_commit",
    "files",
    "firmware",
    "run_inputs",
    "run",
}
RUN_FIELDS = {
    "kind",
    "mode",
    "base_attestation",
    "runtime_root",
    "secure_preparation",
}
_HEX64 = re.compile(r"[0-9a-f]{64}")
_COMMIT = re.compile(r"[0-9a-f]{40}")
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
OVMF_CODE = "/usr/share/edk2/x64/OVMF_CODE.4m.fd"
OVMF_VARS = "/usr/share/edk2/x64/OVMF_VARS.4m.fd"
OVMF_SECURE_CODE = "/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd"
SMOKE_RESULT_SCHEMA = "aurascan_recovery_smoke_result/1.0"
SMOKE_RESULT_NAME = "recovery-smoke-result.json"
SMOKE_RESULT_LIMIT = 64 * 1024
SERIAL_LOG_LIMIT = 16 * 1024 * 1024
SMOKE_RESULT_FIELDS = {
    "schema",
    "kind",
    "mode",
    "outcome",
    "ready_marker",
    "unsigned_rejection",
    "serial_evidence",
}
SERIAL_EVIDENCE_FIELDS = {"role", "expect", "file", "sha256", "size"}
_READY_LINE = re.compile(
    rb"(?m)^(?:AURASCAN_RECOVERY_READY|"
    rb"\[ *[0-9]+\.[0-9]{6}\] aurascan-recovery-marker\[[1-9][0-9]*\]: "
    rb"AURASCAN_RECOVERY_READY)\r?$"
)
_FIRMWARE_REJECTION = re.compile(
    rb"(?m)^BdsDxe: failed to load Boot[0-9A-Fa-f]{4} [^\r\n]*: "
    rb"(?:Security Violation|Access Denied -- rejected probably by Secure Boot)\r?$"
)


class LaunchRefusal(RuntimeError):
    """A release-validation trust boundary could not be established."""


def _smoke_file_limit(kind: str) -> int:
    """Return the same exclusive artifact ceiling enforced by the guard."""

    if kind == "iso":
        return FILE_LIMIT
    if kind == "uki":
        return UKI_FILE_LIMIT
    raise LaunchRefusal("smoke artifact kind is unsupported")


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise LaunchRefusal("validation attestation contains duplicate keys")
        value[key] = item
    return value


def _identity(metadata: os.stat_result) -> Tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _safe_absolute(path: Path) -> Path:
    text = os.fspath(path)
    if not text.startswith("/") or "," in text or any(
        ord(character) < 0x20 or ord(character) == 0x7F for character in text
    ):
        raise LaunchRefusal("validation input path is not a safe absolute path")
    normalized = Path(os.path.abspath(text))
    if os.fspath(normalized) != text:
        raise LaunchRefusal("validation input path is not canonical")
    return normalized


def _root_safe_components(path: Path, *, include_final: bool) -> None:
    path = _safe_absolute(path)
    parts = path.parts
    stop = len(parts) if include_final else len(parts) - 1
    current = Path(parts[0])
    for part in parts[1:stop]:
        current /= part
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise LaunchRefusal("validation input path is unavailable") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise LaunchRefusal("validation input has a symlinked path component")
        if metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise LaunchRefusal(
                "validation input is not rooted in root-owned non-writable paths"
            )
        if current != path and not stat.S_ISDIR(metadata.st_mode):
            raise LaunchRefusal("validation input has a non-directory path component")


def _open_root_regular(path: Path, limit: int, *, require_world_read: bool = False):
    path = _safe_absolute(path)
    _root_safe_components(path, include_final=False)
    try:
        before = path.lstat()
    except OSError as exc:
        raise LaunchRefusal("validation input is unavailable") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise LaunchRefusal("validation input is not a no-follow regular file")
    if before.st_uid != 0 or before.st_mode & 0o022:
        raise LaunchRefusal("validation input is not root-owned and non-writable")
    if require_world_read and not before.st_mode & stat.S_IROTH:
        raise LaunchRefusal("validation input is unreadable after the privilege drop")
    if before.st_size < 1 or before.st_size >= limit:
        raise LaunchRefusal("validation input exceeds its bounded size")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(str(path), flags)
        opened = os.fstat(descriptor)
    except OSError as exc:
        raise LaunchRefusal("validation input could not be opened safely") from exc
    if not stat.S_ISREG(opened.st_mode) or _identity(opened) != _identity(before):
        os.close(descriptor)
        raise LaunchRefusal("validation input changed while opening")
    return descriptor, before


def _read_descriptor(descriptor: int, before: os.stat_result, limit: int) -> bytes:
    chunks = []
    consumed = 0
    while consumed < before.st_size:
        chunk = os.pread(descriptor, min(1024 * 1024, before.st_size - consumed), consumed)
        if not chunk:
            raise LaunchRefusal("validation input ended while reading")
        chunks.append(chunk)
        consumed += len(chunk)
        if consumed >= limit:
            raise LaunchRefusal("validation input exceeds its bounded size")
    if consumed != before.st_size or _identity(os.fstat(descriptor)) != _identity(before):
        raise LaunchRefusal("validation input changed while reading")
    return b"".join(chunks)


def _hash_descriptor(descriptor: int, before: os.stat_result, limit: int) -> str:
    digest = hashlib.sha256()
    consumed = 0
    while consumed < before.st_size:
        chunk = os.pread(descriptor, min(1024 * 1024, before.st_size - consumed), consumed)
        if not chunk:
            raise LaunchRefusal("validation input ended while hashing")
        digest.update(chunk)
        consumed += len(chunk)
        if consumed >= limit:
            raise LaunchRefusal("validation input exceeds its bounded size")
    if consumed != before.st_size or _identity(os.fstat(descriptor)) != _identity(before):
        raise LaunchRefusal("validation input changed while hashing")
    return digest.hexdigest()


def _entry(path: Path, *, require_world_read: bool = True) -> Dict[str, object]:
    descriptor, metadata = _open_root_regular(
        path, FILE_LIMIT, require_world_read=require_world_read
    )
    try:
        digest = _hash_descriptor(descriptor, metadata, FILE_LIMIT)
    finally:
        os.close(descriptor)
    return {
        "path": os.fspath(path),
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


def _validate_entry_shape(value: object) -> Mapping[str, object]:
    if not isinstance(value, dict) or set(value) != ENTRY_FIELDS:
        raise LaunchRefusal("validation attestation file identity is malformed")
    if not isinstance(value["path"], str) or not isinstance(value["sha256"], str):
        raise LaunchRefusal("validation attestation file identity is malformed")
    if _HEX64.fullmatch(value["sha256"]) is None:
        raise LaunchRefusal("validation attestation digest is malformed")
    for field in ENTRY_FIELDS - {"path", "sha256"}:
        if (
            not isinstance(value[field], int)
            or isinstance(value[field], bool)
            or value[field] < 0
        ):
            raise LaunchRefusal("validation attestation file identity is malformed")
    if value["size"] < 1 or value["mode"] > 0o7777:
        raise LaunchRefusal("validation attestation file identity is malformed")
    return value


def _verify_entry(value: object, *, require_world_read: bool = True) -> None:
    record = _validate_entry_shape(value)
    current = _entry(Path(record["path"]), require_world_read=require_world_read)
    if current != record:
        raise LaunchRefusal("an attested validation file changed")


def _parse_receipt(descriptor: int, path: Path, before: os.stat_result):
    raw = _read_descriptor(descriptor, before, RECEIPT_LIMIT)
    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_unique_object)
    except LaunchRefusal:
        raise
    except (UnicodeError, TypeError, ValueError) as exc:
        raise LaunchRefusal("validation attestation is not strict JSON") from exc
    if not isinstance(value, dict) or set(value) != TOP_FIELDS:
        raise LaunchRefusal("validation attestation has an unsupported schema shape")
    if value["schema"] != SCHEMA:
        raise LaunchRefusal("validation attestation schema is unsupported")
    if not isinstance(value["version"], str) or _VERSION.fullmatch(value["version"]) is None:
        raise LaunchRefusal("validation attestation version is malformed")
    if not isinstance(value["source_commit"], str) or _COMMIT.fullmatch(
        value["source_commit"]
    ) is None:
        raise LaunchRefusal("validation attestation source commit is malformed")
    if not isinstance(value["files"], dict) or set(value["files"]) != BASE_ROLES:
        raise LaunchRefusal("validation attestation file set is incomplete")
    if not isinstance(value["firmware"], dict) or not isinstance(value["run_inputs"], dict):
        raise LaunchRefusal("validation attestation extension map is malformed")
    for mapping in (value["files"], value["firmware"], value["run_inputs"]):
        for role, record in mapping.items():
            if not isinstance(role, str) or not role or len(role) > 64:
                raise LaunchRefusal("validation attestation role is malformed")
            _validate_entry_shape(record)
    run = value["run"]
    if run is not None:
        if not isinstance(run, dict) or set(run) != RUN_FIELDS:
            raise LaunchRefusal("validation attestation run binding is malformed")
        if run["kind"] not in {"iso", "uki"} or run["mode"] not in {
            "bios",
            "uefi",
            "secure-boot",
        }:
            raise LaunchRefusal("validation attestation run binding is malformed")
        if not isinstance(run["runtime_root"], str):
            raise LaunchRefusal("validation attestation runtime root is malformed")
        _safe_absolute(Path(run["runtime_root"]))
        _validate_entry_shape(run["base_attestation"])
        if run["secure_preparation"] is not None:
            _validate_entry_shape(run["secure_preparation"])
    return value


def _open_receipt(path: Path):
    descriptor, before = _open_root_regular(path, RECEIPT_LIMIT)
    if stat.S_IMODE(before.st_mode) != 0o400:
        os.close(descriptor)
        raise LaunchRefusal("validation attestation must be root-owned mode 0400")
    value = _parse_receipt(descriptor, path, before)
    try:
        after = path.lstat()
    except OSError as exc:
        os.close(descriptor)
        raise LaunchRefusal("validation attestation disappeared") from exc
    if _identity(after) != _identity(before):
        os.close(descriptor)
        raise LaunchRefusal("validation attestation changed while reading")
    return descriptor, before, value


def _write_run_receipt(destination: Path, base_entry, value):
    run_value = dict(value)
    run_value["run"] = dict(run_value["run"])
    run_value["run"]["base_attestation"] = base_entry
    path = _safe_absolute(destination)
    _root_safe_components(path.parent, include_final=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(str(path), flags, 0o400)
    except OSError as exc:
        raise LaunchRefusal("could not allocate a private per-run attestation") from exc
    try:
        encoded = (json.dumps(run_value, sort_keys=True, separators=(",", ":")) + "\n").encode(
            "utf-8"
        )
        if len(encoded) >= RECEIPT_LIMIT:
            raise LaunchRefusal("per-run validation attestation exceeds its size limit")
        view = memoryview(encoded)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise LaunchRefusal("per-run validation attestation write was incomplete")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    read_descriptor, _before, parsed = _open_receipt(path)
    if parsed != run_value:
        os.close(read_descriptor)
        raise LaunchRefusal("per-run validation attestation verification failed")
    os.set_inheritable(read_descriptor, True)
    return path, read_descriptor, run_value


def _snapshot_input(source: Path, destination: Path) -> Dict[str, object]:
    descriptor, before = _open_root_regular(source, FILE_LIMIT)
    destination = _safe_absolute(destination)
    _root_safe_components(destination.parent, include_final=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        output = os.open(str(destination), flags, 0o444)
    except OSError as exc:
        os.close(descriptor)
        raise LaunchRefusal("private validation input snapshot could not be created") from exc
    digest = hashlib.sha256()
    consumed = 0
    try:
        while consumed < before.st_size:
            chunk = os.pread(
                descriptor, min(1024 * 1024, before.st_size - consumed), consumed
            )
            if not chunk:
                raise LaunchRefusal("validation input ended while snapshotting")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(output, view)
                if written <= 0:
                    raise LaunchRefusal("validation input snapshot write was incomplete")
                view = view[written:]
            consumed += len(chunk)
        if _identity(os.fstat(descriptor)) != _identity(before):
            raise LaunchRefusal("validation input changed while snapshotting")
        os.fsync(output)
        os.fchmod(output, 0o444)
    finally:
        os.close(output)
        os.close(descriptor)
    result = _entry(destination)
    if result["sha256"] != digest.hexdigest() or result["size"] != before.st_size:
        raise LaunchRefusal("private validation input snapshot could not be verified")
    return result


def _create_run_root(parent: Path) -> Tuple[Path, Path, Path]:
    _root_safe_components(parent, include_final=True)
    for _attempt in range(16):
        root = parent / ("recovery-validation-run-{}".format(secrets.token_hex(12)))
        try:
            os.mkdir(str(root), 0o711)
        except FileExistsError:
            continue
        os.mkdir(str(root / "inputs"), 0o755)
        os.mkdir(str(root / "runtime"), 0o700)
        os.chown(str(root / "runtime"), DROP_UID, DROP_GID)
        return root, root / "inputs", root / "runtime"
    raise LaunchRefusal("could not allocate a private validation run root")


def _remove_run_root(root: Path) -> None:
    root = _safe_absolute(root)
    if not root.name.startswith("recovery-validation-run-"):
        raise LaunchRefusal("refusing an unexpected validation cleanup target")
    for directory, directory_names, filenames in os.walk(str(root), topdown=False, followlinks=False):
        current = Path(directory)
        for name in filenames:
            target = current / name
            os.unlink(str(target))
        for name in directory_names:
            target = current / name
            metadata = target.lstat()
            if stat.S_ISLNK(metadata.st_mode):
                os.unlink(str(target))
            elif stat.S_ISDIR(metadata.st_mode):
                os.rmdir(str(target))
            else:
                os.unlink(str(target))
    os.rmdir(str(root))


def _retire_drop_uid() -> None:
    for _attempt in range(50):
        found = subprocess.run(
            ["/usr/bin/pgrep", "-u", str(DROP_UID)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            timeout=2,
            check=False,
        )
        if found.returncode == 1:
            return
        if found.returncode not in {0, 1}:
            raise LaunchRefusal("could not audit isolated smoke-test processes")
        subprocess.run(
            ["/usr/bin/pkill", "-KILL", "-u", str(DROP_UID)],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            timeout=2,
            check=False,
        )
        time.sleep(0.1)
    raise LaunchRefusal("could not retire isolated smoke-test processes")


def _read_isolated_regular(runtime: Path, relative: str, limit: int) -> bytes:
    if (
        not isinstance(relative, str)
        or not relative
        or len(relative) > 1024
        or relative.startswith("/")
    ):
        raise LaunchRefusal("smoke evidence path is malformed")
    parts = Path(relative).parts
    if not parts or any(
        part in {"", ".", ".."}
        or re.fullmatch(r"[A-Za-z0-9._+-]{1,160}", part) is None
        for part in parts
    ):
        raise LaunchRefusal("smoke evidence path is malformed")
    current = runtime
    for part in parts[:-1]:
        current /= part
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise LaunchRefusal("smoke evidence directory is unavailable") from exc
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != DROP_UID
            or metadata.st_gid != DROP_GID
            or metadata.st_mode & 0o022
        ):
            raise LaunchRefusal("smoke evidence directory is unsafe")
    path = runtime.joinpath(*parts)
    try:
        before = path.lstat()
    except OSError as exc:
        raise LaunchRefusal("smoke evidence is unavailable") from exc
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != DROP_UID
        or before.st_gid != DROP_GID
        or before.st_mode & 0o022
        or before.st_size < 1
        or before.st_size >= limit
    ):
        raise LaunchRefusal("smoke evidence is not a bounded private regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(str(path), flags)
    except OSError as exc:
        raise LaunchRefusal("smoke evidence could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if _identity(opened) != _identity(before):
            raise LaunchRefusal("smoke evidence changed while opening")
        raw = _read_descriptor(descriptor, before, limit)
        after = path.lstat()
        if _identity(after) != _identity(before):
            raise LaunchRefusal("smoke evidence changed while reading")
        return raw
    finally:
        os.close(descriptor)


def _read_smoke_result(runtime: Path, kind: str, mode: str):
    raw = _read_isolated_regular(runtime, SMOKE_RESULT_NAME, SMOKE_RESULT_LIMIT)
    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_unique_object)
    except LaunchRefusal:
        raise
    except (UnicodeError, TypeError, ValueError) as exc:
        raise LaunchRefusal("smoke result is not strict JSON") from exc
    if not isinstance(value, dict) or set(value) != SMOKE_RESULT_FIELDS:
        raise LaunchRefusal("smoke result schema shape is invalid")
    secure = mode == "secure-boot"
    expected_outcome = (
        "unsigned-rejection-and-signed-readiness" if secure else "service-readiness"
    )
    if (
        value["schema"] != SMOKE_RESULT_SCHEMA
        or value["kind"] != kind
        or value["mode"] != mode
        or value["outcome"] != expected_outcome
        or value["ready_marker"] is not True
        or value["unsigned_rejection"] is not secure
        or not isinstance(value["serial_evidence"], list)
    ):
        raise LaunchRefusal("smoke result does not match the requested validation")
    expected_evidence = [("readiness", "ready")]
    if secure:
        expected_evidence.append(("unsigned-rejection", "firmware-rejection"))
    if len(value["serial_evidence"]) != len(expected_evidence):
        raise LaunchRefusal("smoke result evidence set is incomplete")
    retained_evidence = []
    for record, (role, expectation) in zip(value["serial_evidence"], expected_evidence):
        if (
            not isinstance(record, dict)
            or set(record) != SERIAL_EVIDENCE_FIELDS
            or record["role"] != role
            or record["expect"] != expectation
            or not isinstance(record["sha256"], str)
            or _HEX64.fullmatch(record["sha256"]) is None
            or not isinstance(record["size"], int)
            or isinstance(record["size"], bool)
            or not 1 <= record["size"] < SERIAL_LOG_LIMIT
        ):
            raise LaunchRefusal("smoke result evidence is malformed")
        log = _read_isolated_regular(runtime, record["file"], SERIAL_LOG_LIMIT)
        if len(log) != record["size"] or hashlib.sha256(log).hexdigest() != record["sha256"]:
            raise LaunchRefusal("smoke result serial evidence changed")
        ready = _READY_LINE.search(log) is not None
        if expectation == "ready" and not ready:
            raise LaunchRefusal("smoke result lacks independent readiness evidence")
        if expectation == "firmware-rejection" and (
            ready or _FIRMWARE_REJECTION.search(log) is None
        ):
            raise LaunchRefusal("smoke result lacks independent unsigned-rejection evidence")
        retained_evidence.append(
            {
                "role": role,
                "expect": expectation,
                "sha256": record["sha256"],
                "size": record["size"],
            }
        )
    return {
        "schema": value["schema"],
        "kind": kind,
        "mode": mode,
        "outcome": expected_outcome,
        "ready_marker": True,
        "unsigned_rejection": secure,
        "serial_evidence": retained_evidence,
    }


def _expected_harness_output(kind: str, mode: str) -> bytes:
    outputs = {
        ("iso", "bios"): b"Recovery ISO bios smoke test passed: recovery service reached the boot-readiness marker\n",
        ("iso", "uefi"): b"Recovery ISO uefi smoke test passed: recovery service reached the boot-readiness marker\n",
        ("uki", "uefi"): b"Ordinary UEFI UKI smoke test passed: recovery service reached the boot-readiness marker\n",
        ("uki", "secure-boot"): b"Secure Boot UKI smoke test passed: payload-bound unsigned rejection and signed recovery readiness were both proven\n",
    }
    try:
        return outputs[(kind, mode)]
    except KeyError as exc:
        raise LaunchRefusal("smoke harness output mode is invalid") from exc


def _validated_smoke_outcome(
    status: int,
    output_size: int,
    captured: bytes,
    runtime: Path,
    kind: str,
    mode: str,
):
    if (
        status != 0
        or output_size > 1024 * 1024
        or len(captured) > 1024 * 1024
    ):
        raise LaunchRefusal(
            "isolated smoke validation failed or exceeded its output bound"
        )
    expected_output = _expected_harness_output(kind, mode)
    if captured != expected_output:
        raise LaunchRefusal(
            "isolated smoke validation returned incomplete outcome evidence"
        )
    outcome = _read_smoke_result(runtime, kind, mode)
    outcome["harness_output_sha256"] = hashlib.sha256(captured).hexdigest()
    outcome["harness_output_size"] = len(captured)
    return outcome


def _write_pass_receipt(
    parent: Path,
    run_record,
    run_attestation,
    kind: str,
    mode: str,
    outcome,
) -> Path:
    result = {
        "schema": "aurascan_recovery_validation_result/1.0",
        "version": run_attestation["version"],
        "source_commit": run_attestation["source_commit"],
        "kind": kind,
        "mode": mode,
        "result": "PASS",
        "run_attestation": run_record,
        "evidence": run_attestation,
        "outcome": outcome,
    }
    encoded = (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )
    if len(encoded) >= RECEIPT_LIMIT:
        raise LaunchRefusal("validation result receipt exceeds its bounded size")
    for _attempt in range(16):
        destination = parent / ("recovery-validation-pass-{}.json".format(secrets.token_hex(12)))
        try:
            descriptor = os.open(
                str(destination),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o400,
            )
        except FileExistsError:
            continue
        try:
            view = memoryview(encoded)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise LaunchRefusal("validation result receipt write was incomplete")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        recorded = _entry(destination, require_world_read=False)
        if recorded["mode"] != 0o400 or recorded["size"] != len(encoded):
            raise LaunchRefusal("validation result receipt could not be verified")
        return destination
    raise LaunchRefusal("could not record the successful validation result")


def _trusted_tool(path: str) -> None:
    record = _entry(Path(path), require_world_read=True)
    if not os.access(path, os.X_OK) or not stat.S_ISREG(Path(path).lstat().st_mode):
        raise LaunchRefusal("required trusted launcher tool is unavailable")
    if record["uid"] != 0:
        raise LaunchRefusal("required trusted launcher tool is unavailable")


def _bounded_pacman(arguments: Sequence[str]) -> str:
    try:
        result = subprocess.run(
            ["/usr/bin/pacman"] + list(arguments),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise LaunchRefusal("packaged firmware verification could not run") from exc
    if result.returncode != 0 or len(result.stdout) >= 64 * 1024:
        raise LaunchRefusal("packaged firmware verification failed or reached its bound")
    try:
        return result.stdout.decode("utf-8", "strict")
    except UnicodeError as exc:
        raise LaunchRefusal("packaged firmware verification returned invalid text") from exc


def _verify_packaged_firmware(paths: Sequence[str]) -> None:
    for path in paths:
        if _bounded_pacman(["-Qqo", "--", path]) != "edk2-ovmf\n":
            raise LaunchRefusal("selected OVMF input is not owned by edk2-ovmf")
    package_check = _bounded_pacman(["-Qkk", "edk2-ovmf"])
    if re.fullmatch(r"edk2-ovmf: [1-9][0-9]* total files, 0 altered files\n", package_check) is None:
        raise LaunchRefusal("the installed edk2-ovmf package did not pass integrity verification")


def _read_secure_preparation(path: Path, base_receipt, base_record):
    descriptor, metadata = _open_root_regular(path, RECEIPT_LIMIT)
    try:
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise LaunchRefusal("secure-boot preparation receipt must be root-owned mode 0600")
        raw = _read_descriptor(descriptor, metadata, RECEIPT_LIMIT)
        digest = _hash_descriptor(descriptor, metadata, RECEIPT_LIMIT)
    finally:
        os.close(descriptor)
    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_unique_object)
    except LaunchRefusal:
        raise
    except (UnicodeError, TypeError, ValueError) as exc:
        raise LaunchRefusal("secure-boot preparation receipt is not strict JSON") from exc
    fields = {
        "schema",
        "version",
        "source_commit",
        "created_at",
        "builder_attestation",
        "unsigned_validation_uki",
        "firmware_inputs",
        "tools",
        "certificates",
        "enrolled_variables",
        "outputs",
        "private_keys_deleted",
        "network_namespace",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise LaunchRefusal("secure-boot preparation receipt has an unsupported shape")
    if value["schema"] != "aurascan_recovery_secure_boot_preparation/1.0":
        raise LaunchRefusal("secure-boot preparation receipt schema is unsupported")
    if (
        value["version"] != base_receipt["version"]
        or value["source_commit"] != base_receipt["source_commit"]
    ):
        raise LaunchRefusal("secure-boot preparation does not bind the build candidate")
    if not isinstance(value.get("created_at"), str) or re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
        value["created_at"],
    ) is None:
        raise LaunchRefusal("secure-boot preparation timestamp is malformed")
    identity_fields = {
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
    builder_identity = value["builder_attestation"]
    if not isinstance(builder_identity, dict) or set(builder_identity) != identity_fields:
        raise LaunchRefusal("secure-boot preparation builder identity is malformed")
    expected_builder = {key: base_record[key] for key in identity_fields}
    if builder_identity != expected_builder:
        raise LaunchRefusal("secure-boot preparation names a different build attestation")
    unsigned = value["unsigned_validation_uki"]
    if not isinstance(unsigned, dict) or set(unsigned) != {
        "filename",
        "sha256",
        "size",
        "builder_identity",
    }:
        raise LaunchRefusal("secure-boot preparation unsigned UKI identity is malformed")
    base_uki = base_receipt["files"]["validation_uki"]
    uki_identity_fields = {
        "device",
        "inode",
        "mode",
        "uid",
        "gid",
        "mtime_ns",
        "ctime_ns",
    }
    if (
        unsigned["filename"] != Path(base_uki["path"]).name
        or unsigned["sha256"] != base_uki["sha256"]
        or unsigned["size"] != base_uki["size"]
        or not isinstance(unsigned["builder_identity"], dict)
        or set(unsigned["builder_identity"]) != uki_identity_fields
        or unsigned["builder_identity"]
        != {key: base_uki[key] for key in uki_identity_fields}
    ):
        raise LaunchRefusal("secure-boot preparation names a different unsigned UKI")
    for supporting in ("firmware_inputs", "tools", "certificates", "enrolled_variables"):
        if not isinstance(value[supporting], (dict, list)):
            raise LaunchRefusal("secure-boot preparation supporting evidence is malformed")
    if value["private_keys_deleted"] is not True:
        raise LaunchRefusal("secure-boot preparation did not prove private-key deletion")
    if value["network_namespace"] != "isolated-by-root-launcher":
        raise LaunchRefusal("secure-boot preparation lacks its isolated-network binding")
    outputs = value["outputs"]
    if not isinstance(outputs, dict) or set(outputs) != {
        "signed_uki",
        "signed_uki_sha256",
        "enrolled_vars",
        "secure_code",
    }:
        raise LaunchRefusal("secure-boot preparation output set is incomplete")
    output_fields = {
        "filename",
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
    resolved = {}
    for role, output in outputs.items():
        if not isinstance(output, dict) or set(output) != output_fields:
            raise LaunchRefusal("secure-boot preparation output identity is malformed")
        filename = output["filename"]
        if not isinstance(filename, str) or Path(filename).name != filename:
            raise LaunchRefusal("secure-boot preparation output filename is unsafe")
        output_path = path.parent / filename
        observed = _entry(output_path)
        expected = {"filename": filename}
        expected.update({key: observed[key] for key in output_fields - {"filename"}})
        if output != expected:
            raise LaunchRefusal("secure-boot preparation output changed after root reclaim")
        resolved[role] = output_path
    receipt_record = {
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
    return value, resolved, receipt_record


def _uid_is_idle(uid: int) -> bool:
    for candidate in Path("/proc").iterdir():
        if not candidate.name.isdigit():
            continue
        try:
            raw = (candidate / "status").read_text(encoding="ascii", errors="strict")
        except (OSError, UnicodeError):
            continue
        for line in raw.splitlines():
            if line.startswith("Uid:"):
                fields = line.split()[1:]
                if any(field.isdigit() and int(field) == uid for field in fields):
                    return False
                break
    return True


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attestation", required=True)
    parser.add_argument("kind", choices=("iso", "uki"))
    parser.add_argument("input")
    parser.add_argument("mode", choices=("bios", "uefi", "secure-boot"))
    parser.add_argument("--firmware-code")
    parser.add_argument("--firmware-vars")
    parser.add_argument("--secure-preparation-receipt")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    run_root = None
    run_fd = None
    process = None
    isolation_started = False
    uid_retired = False
    try:
        args = _build_parser().parse_args(argv)
        if os.geteuid() != 0:
            raise LaunchRefusal("the attested smoke launcher must start as root")
        os.umask(0o022)
        if (args.kind, args.mode) not in {
            ("iso", "bios"),
            ("iso", "uefi"),
            ("uki", "uefi"),
            ("uki", "secure-boot"),
        }:
            raise LaunchRefusal("the selected artifact and boot mode are incompatible")
        if args.mode == "bios":
            if args.firmware_code or args.firmware_vars:
                raise LaunchRefusal("BIOS validation does not accept firmware paths")
        elif not args.firmware_code or not args.firmware_vars:
            raise LaunchRefusal("UEFI validation requires exact code and variables images")
        if args.mode == "secure-boot" and not args.secure_preparation_receipt:
            raise LaunchRefusal("Secure Boot validation requires its private preparation receipt")
        if args.mode != "secure-boot" and args.secure_preparation_receipt:
            raise LaunchRefusal("a Secure Boot preparation receipt is invalid for this mode")

        receipt_path = _safe_absolute(Path(args.attestation))
        base_fd, base_metadata, receipt = _open_receipt(receipt_path)
        try:
            if receipt["run"] is not None or receipt["firmware"] or receipt["run_inputs"]:
                raise LaunchRefusal("the launcher requires the builder's base attestation")
            for role in BASE_ROLES:
                _verify_entry(receipt["files"][role])
            launcher_record = receipt["files"]["smoke_launcher"]
            if Path(launcher_record["path"]) != Path(__file__).resolve():
                raise LaunchRefusal("the running launcher is not the attested launcher")
            base_record = {
                "path": os.fspath(receipt_path),
                "sha256": _hash_descriptor(base_fd, base_metadata, RECEIPT_LIMIT),
                "size": base_metadata.st_size,
                "device": base_metadata.st_dev,
                "inode": base_metadata.st_ino,
                "mode": stat.S_IMODE(base_metadata.st_mode),
                "uid": base_metadata.st_uid,
                "gid": base_metadata.st_gid,
                "mtime_ns": base_metadata.st_mtime_ns,
                "ctime_ns": base_metadata.st_ctime_ns,
            }

            input_path = _safe_absolute(Path(args.input))
            if args.kind == "iso":
                harness_role = "qemu_iso_harness"
                expected_input = receipt["files"]["iso"]["path"]
            else:
                harness_role = "qemu_uki_harness"
                expected_input = receipt["files"]["validation_uki"]["path"]
            if args.mode != "secure-boot" and os.fspath(input_path) != expected_input:
                raise LaunchRefusal("the selected smoke input is not the attested build artifact")
            secure_preparation_record = None
            secure_outputs = {}
            if args.mode == "secure-boot":
                _preparation, secure_outputs, secure_preparation_record = (
                    _read_secure_preparation(
                        _safe_absolute(Path(args.secure_preparation_receipt)),
                        receipt,
                        base_record,
                    )
                )
                if (
                    input_path != secure_outputs["signed_uki"]
                    or Path(str(input_path) + ".sha256")
                    != secure_outputs["signed_uki_sha256"]
                    or _safe_absolute(Path(args.firmware_code)) != secure_outputs["secure_code"]
                    or _safe_absolute(Path(args.firmware_vars)) != secure_outputs["enrolled_vars"]
                ):
                    raise LaunchRefusal(
                        "Secure Boot inputs are not the exact preparation-receipt outputs"
                    )

            run_root, inputs_root, runtime_root = _create_run_root(receipt_path.parent)
            harness_input = inputs_root / input_path.name
            run_inputs = {
                "selected_input": _snapshot_input(input_path, harness_input),
                "selected_input_sha256": _snapshot_input(
                    Path(str(input_path) + ".sha256"),
                    Path(str(harness_input) + ".sha256"),
                ),
            }
            if args.kind == "iso":
                run_inputs["iso_packages"] = _snapshot_input(
                    Path(str(input_path) + ".packages.txt"),
                    Path(str(harness_input) + ".packages.txt"),
                )
                for run_role, base_role in (
                    ("selected_input", "iso"),
                    ("selected_input_sha256", "iso_sha256"),
                    ("iso_packages", "iso_packages"),
                ):
                    if run_inputs[run_role]["sha256"] != receipt["files"][base_role][
                        "sha256"
                    ]:
                        raise LaunchRefusal("private ISO snapshot differs from its base attestation")
            elif args.mode != "secure-boot":
                for run_role, base_role in (
                    ("selected_input", "validation_uki"),
                    ("selected_input_sha256", "validation_uki_sha256"),
                ):
                    if run_inputs[run_role]["sha256"] != receipt["files"][base_role][
                        "sha256"
                    ]:
                        raise LaunchRefusal("private UKI snapshot differs from its base attestation")
            firmware = {}
            firmware_paths = {}
            if args.mode != "bios":
                if args.mode == "secure-boot":
                    expected_code = OVMF_SECURE_CODE
                    packaged_paths = [expected_code]
                else:
                    expected_code = OVMF_CODE
                    if args.firmware_code != expected_code or args.firmware_vars != OVMF_VARS:
                        raise LaunchRefusal("the selected OVMF path is not the fixed validated input")
                    packaged_paths = [expected_code, OVMF_VARS]
                _trusted_tool("/usr/bin/pacman")
                _verify_packaged_firmware(packaged_paths)
                code_role = "ovmf_secure_code" if args.mode == "secure-boot" else "ovmf_code"
                vars_role = (
                    "ovmf_enrolled_vars_template"
                    if args.mode == "secure-boot"
                    else "ovmf_vars_template"
                )
                source_code = _safe_absolute(Path(args.firmware_code))
                source_vars = _safe_absolute(Path(args.firmware_vars))
                if args.mode == "secure-boot":
                    packaged_secure = _entry(Path(OVMF_SECURE_CODE))
                    if packaged_secure["sha256"] != _entry(source_code)["sha256"]:
                        raise LaunchRefusal(
                            "prepared Secure Boot code differs from packaged edk2-ovmf"
                        )
                copied_code = inputs_root / source_code.name
                copied_vars = inputs_root / source_vars.name
                if copied_code == copied_vars:
                    raise LaunchRefusal("firmware inputs do not have distinct basenames")
                firmware[code_role] = _snapshot_input(source_code, copied_code)
                firmware[vars_role] = _snapshot_input(source_vars, copied_vars)
                firmware_paths = {"code": copied_code, "vars": copied_vars}

            receipt["firmware"] = firmware
            receipt["run_inputs"] = run_inputs
            receipt["run"] = {
                "kind": args.kind,
                "mode": args.mode,
                "base_attestation": None,
                "runtime_root": os.fspath(runtime_root),
                "secure_preparation": secure_preparation_record,
            }
            run_path, run_fd, run_attestation = _write_run_receipt(
                inputs_root / "recovery-validation-attestation.json", base_record, receipt
            )
        finally:
            os.close(base_fd)

        for tool in (
            "/usr/bin/setpriv",
            "/usr/bin/env",
            "/usr/bin/bash",
            "/usr/bin/setsid",
            "/usr/bin/timeout",
            "/usr/bin/unshare",
            "/usr/bin/pkill",
            "/usr/bin/pgrep",
        ):
            _trusted_tool(tool)
        try:
            pwd.getpwuid(DROP_UID)
        except KeyError:
            pass
        else:
            raise LaunchRefusal("the fixed smoke-test UID is assigned on this host")
        try:
            grp.getgrgid(DROP_GID)
        except KeyError:
            pass
        else:
            raise LaunchRefusal("the fixed smoke-test GID is assigned on this host")
        if not _uid_is_idle(DROP_UID):
            raise LaunchRefusal("the fixed smoke-test UID is already active")

        harness = receipt["files"][harness_role]["path"]
        environment = {
            "PATH": "/usr/bin:/bin",
            "HOME": "/nonexistent",
            "USER": "aurascan",
            "LOGNAME": "aurascan",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "TZ": "UTC",
            "AURASCAN_RECOVERY_SMOKE_CLEAN_ENV": "1",
            "AURASCAN_RECOVERY_ATTESTATION_PATH": os.fspath(run_path),
            "AURASCAN_RECOVERY_ATTESTATION_FD": str(run_fd),
            "TMPDIR": os.fspath(runtime_root),
            "AURASCAN_AI_ENABLED": "0",
            "AURASCAN_INSTRUCTION_AI_ENABLED": "0",
            "AURASCAN_INCIDENT_AI_ENABLED": "0",
            "AURASCAN_RECOVERY_AI_ENABLED": "0",
        }
        if args.mode != "bios":
            if args.mode == "secure-boot":
                environment["AURASCAN_OVMF_SECURE_CODE"] = os.fspath(firmware_paths["code"])
                environment["AURASCAN_OVMF_ENROLLED_VARS_TEMPLATE"] = os.fspath(
                    firmware_paths["vars"]
                )
            else:
                environment["AURASCAN_OVMF_CODE"] = os.fspath(firmware_paths["code"])
                environment["AURASCAN_OVMF_VARS_TEMPLATE"] = os.fspath(
                    firmware_paths["vars"]
                )
        timeout_value = os.environ.get("AURASCAN_QEMU_TIMEOUT_SECONDS", "300")
        if not timeout_value.isdigit() or not 30 <= int(timeout_value) <= 900:
            raise LaunchRefusal("AURASCAN_QEMU_TIMEOUT_SECONDS must be between 30 and 900")
        environment["AURASCAN_QEMU_TIMEOUT_SECONDS"] = timeout_value
        dropped_arguments = [
            "/usr/bin/setpriv",
            "--reuid={}".format(DROP_UID),
            "--regid={}".format(DROP_GID),
            "--clear-groups",
            "--no-new-privs",
            "--bounding-set=-all",
            "--inh-caps=-all",
            "--ambient-caps=-all",
            "--pdeathsig=KILL",
            "--",
            "/usr/bin/env",
            "-i",
        ]
        dropped_arguments.extend(
            "{}={}".format(key, value) for key, value in environment.items()
        )
        dropped_arguments.extend(
            [
                "/usr/bin/bash",
                "--noprofile",
                "--norc",
                "--",
                harness,
                os.fspath(harness_input),
                args.mode,
            ]
        )
        outer_timeout = int(timeout_value) * (2 if args.mode == "secure-boot" else 1) + 240
        child_file_limit = _smoke_file_limit(args.kind)
        parent_pid = os.getpid()
        libc = ctypes.CDLL(None, use_errno=True)
        command = [
            "/usr/bin/setpriv",
            "--pdeathsig=KILL",
            "--",
            "/usr/bin/setsid",
            "/usr/bin/unshare",
            "--net",
            "--fork",
            "--kill-child=TERM",
            "--forward-signals",
            "--",
            "/usr/bin/timeout",
            "--signal=TERM",
            "--kill-after=20s",
            "{}s".format(outer_timeout),
        ] + dropped_arguments

        def child_limits():
            # Close the fork-to-exec parent-death race before the first fixed
            # setpriv repeats this setting across the exec chain.
            if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
                os._exit(125)
            if os.getppid() != parent_pid:
                os._exit(125)
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            resource.setrlimit(resource.RLIMIT_AS, (8 * 1024**3, 8 * 1024**3))
            resource.setrlimit(
                resource.RLIMIT_CPU, (outer_timeout + 120, outer_timeout + 120)
            )
            # The unprivileged harness must make one private byte-for-byte
            # snapshot of the selected artifact before QEMU starts.  Keep the
            # operating-system ceiling aligned with the stricter per-kind
            # guard instead of making every valid ISO/UKI impossible to test.
            resource.setrlimit(
                resource.RLIMIT_FSIZE, (child_file_limit, child_file_limit)
            )
            resource.setrlimit(resource.RLIMIT_NOFILE, (1024, 1024))
            resource.setrlimit(resource.RLIMIT_NPROC, (2048, 2048))

        with tempfile.TemporaryFile(mode="w+b") as output:
            # From this point onward cleanup must prove that the isolated UID
            # has no survivors before touching its private runtime tree, even
            # when Popen itself raises after a child may have been created.
            isolation_started = True
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
                env={},
                cwd=os.fspath(runtime_root),
                close_fds=True,
                pass_fds=(run_fd,),
                preexec_fn=child_limits,
            )
            def stop_isolated_run(signum, _frame):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except OSError:
                    pass
                raise LaunchRefusal(
                    "isolated smoke validation received signal {}".format(signum)
                )

            for handled_signal in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
                signal.signal(handled_signal, stop_isolated_run)
            try:
                status = process.wait(timeout=outer_timeout + 30)
            except (KeyboardInterrupt, subprocess.TimeoutExpired):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except OSError:
                    pass
                process.wait()
                raise LaunchRefusal("isolated smoke validation was interrupted or timed out")
            output_size = output.tell()
            output.seek(0)
            captured = output.read(1024 * 1024 + 1)
        outcome = _validated_smoke_outcome(
            status,
            output_size,
            captured,
            runtime_root,
            args.kind,
            args.mode,
        )
        os.close(run_fd)
        run_fd = None
        _retire_drop_uid()
        uid_retired = True
        run_record = _entry(run_path, require_world_read=False)
        _remove_run_root(run_root)
        run_root = None
        result_path = _write_pass_receipt(
            receipt_path.parent,
            run_record,
            run_attestation,
            args.kind,
            args.mode,
            outcome,
        )
        if captured:
            print(
                "Isolated validation emitted {} bytes; its untrusted terminal "
                "output was suppressed.".format(len(captured))
            )
        print("Private validation PASS receipt: {}".format(result_path))
        return 0
    except (LaunchRefusal, OSError, TypeError, ValueError, subprocess.SubprocessError) as exc:
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
            process.wait()
        if isolation_started:
            try:
                _retire_drop_uid()
                uid_retired = True
            except (LaunchRefusal, OSError, subprocess.SubprocessError):
                pass
        if run_fd is not None:
            os.close(run_fd)
        if run_root is not None and (not isolation_started or uid_retired):
            try:
                _remove_run_root(run_root)
            except (LaunchRefusal, OSError):
                pass
        elif run_root is not None:
            print(
                "Recovery smoke run root retained because isolated-process "
                "retirement could not be proven: {}".format(run_root),
                file=sys.stderr,
            )
        print("Recovery smoke launch refused: {}".format(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
