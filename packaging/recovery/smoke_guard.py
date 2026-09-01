#!/usr/bin/env python3
"""Bounded, no-follow input guards for recovery QEMU smoke tests."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Optional, Sequence, Tuple


ISO_LIMIT = 2 * 1024 * 1024 * 1024
# A UKI contains one kernel, one initramfs and small PE sections. A strict
# 512-MiB ceiling leaves ample room for the recovery image while keeping native
# PE parser and QEMU input substantially below the GitHub ISO asset boundary.
UKI_LIMIT = 512 * 1024 * 1024
FIRMWARE_LIMIT = 32 * 1024 * 1024
SIDECAR_LIMIT = 256
SIGNATURE_OUTPUT_LIMIT = 64 * 1024
SERIAL_LOG_LIMIT = 16 * 1024 * 1024
SMOKE_RESULT_LIMIT = 64 * 1024
SMOKE_RESULT_SCHEMA = "aurascan_recovery_smoke_result/1.0"
SMOKE_RESULT_NAME = "recovery-smoke-result.json"
CHUNK_SIZE = 1024 * 1024
ATTESTATION_LIMIT = 256 * 1024
ATTESTATION_SCHEMA = "aurascan_recovery_validation_attestation/1.0"
ATTESTATION_FIELDS = {
    "schema",
    "version",
    "source_commit",
    "files",
    "firmware",
    "run_inputs",
    "run",
}
ATTESTED_FILE_FIELDS = {
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
ATTESTED_BASE_ROLES = {
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

_ISO_NAME = re.compile(r"aurascan-recovery-[0-9]+\.[0-9]+\.[0-9]+-x86_64\.iso")
_UKI_NAME = re.compile(r"[A-Za-z0-9._+-]+\.efi")
_SIDECAR = re.compile(r"(?P<digest>[0-9a-f]{64})  (?P<name>[^\r\n]+)\n")
_SIGNED_INVENTORY = re.compile(r"signature [1-9][0-9]*")
_FIRMWARE_REJECTION = re.compile(
    rb"(?m)^BdsDxe: failed to load Boot[0-9A-Fa-f]{4} [^\r\n]*: "
    rb"(?:Security Violation|Access Denied -- rejected probably by Secure Boot)\r?$"
)
_READY_LINE = re.compile(
    rb"(?m)^(?:\[ *[0-9]+\.[0-9]{6}\] )?"
    rb"aurascan-recovery-marker\[[1-9][0-9]*\]: "
    rb"AURASCAN_RECOVERY_READY\r{0,2}$"
)


class GuardFailure(RuntimeError):
    """A smoke-test input or observed outcome failed closed."""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise GuardFailure("validation attestation contains duplicate keys")
        result[key] = value
    return result


def _safe_drive_path(path: Path) -> Path:
    text = os.fspath(path)
    if "," in text or any(ord(character) < 0x20 or ord(character) == 0x7F for character in text):
        raise GuardFailure("QEMU input path contains a comma or control character")
    return Path(os.path.abspath(text))


def _reject_symlinked_components(path: Path, *, include_final: bool) -> None:
    absolute = _safe_drive_path(path)
    parts = absolute.parts
    current = Path(parts[0])
    stop = len(parts) if include_final else len(parts) - 1
    for part in parts[1:stop]:
        current /= part
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise GuardFailure("smoke-test input path is unavailable") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise GuardFailure("smoke-test input has a symlinked path component")


def _require_root_safe_components(path: Path, *, include_final: bool) -> None:
    absolute = _safe_drive_path(path)
    if os.fspath(absolute) != os.fspath(path):
        raise GuardFailure("validation attestation path is not canonical")
    parts = absolute.parts
    current = Path(parts[0])
    stop = len(parts) if include_final else len(parts) - 1
    for part in parts[1:stop]:
        current /= part
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise GuardFailure("attested validation path is unavailable") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise GuardFailure("attested validation path has a symlinked component")
        if metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise GuardFailure(
                "attested validation path is not root-owned and non-writable"
            )
        if current != absolute and not stat.S_ISDIR(metadata.st_mode):
            raise GuardFailure("attested validation path component is not a directory")


def _identity(metadata: os.stat_result) -> Tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _open_stable_regular(path: Path, max_bytes: int) -> Tuple[int, os.stat_result]:
    path = _safe_drive_path(path)
    _reject_symlinked_components(path, include_final=False)
    try:
        before = path.lstat()
    except OSError as exc:
        raise GuardFailure("smoke-test input is unavailable") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise GuardFailure("smoke-test input is not a no-follow regular file")
    if before.st_size < 1 or before.st_size >= max_bytes:
        raise GuardFailure("smoke-test input exceeds its bounded size")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(str(path), flags)
        opened = os.fstat(descriptor)
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise GuardFailure("smoke-test input could not be opened safely") from exc
    if not stat.S_ISREG(opened.st_mode) or _identity(opened) != _identity(before):
        os.close(descriptor)
        raise GuardFailure("smoke-test input was replaced while opening")
    return descriptor, before


def _revalidate_path(path: Path, before: os.stat_result, descriptor: int) -> None:
    try:
        opened_after = os.fstat(descriptor)
        path_after = path.lstat()
    except OSError as exc:
        raise GuardFailure("smoke-test input changed while reading") from exc
    if _identity(opened_after) != _identity(before) or _identity(path_after) != _identity(before):
        raise GuardFailure("smoke-test input changed while reading")


def _hash_stable(path: Path, max_bytes: int) -> Tuple[str, int, bytes]:
    path = _safe_drive_path(path)
    descriptor, before = _open_stable_regular(path, max_bytes)
    digest = hashlib.sha256()
    total = 0
    prefix = b""
    try:
        while True:
            chunk = os.read(descriptor, CHUNK_SIZE)
            if not chunk:
                break
            if not prefix:
                prefix = chunk[:2]
            total += len(chunk)
            if total >= max_bytes:
                raise GuardFailure("smoke-test input exceeds its bounded size")
            digest.update(chunk)
        _revalidate_path(path, before, descriptor)
    finally:
        os.close(descriptor)
    if total != before.st_size:
        raise GuardFailure("smoke-test input changed while reading")
    return digest.hexdigest(), total, prefix


def _read_stable(path: Path, max_bytes: int) -> bytes:
    path = _safe_drive_path(path)
    descriptor, before = _open_stable_regular(path, max_bytes + 1)
    chunks = []
    total = 0
    try:
        while True:
            chunk = os.read(descriptor, min(CHUNK_SIZE, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise GuardFailure("smoke-test metadata exceeds its bounded size")
        _revalidate_path(path, before, descriptor)
    finally:
        os.close(descriptor)
    if total != before.st_size:
        raise GuardFailure("smoke-test metadata changed while reading")
    return b"".join(chunks)


def _read_attestation(path: Path, descriptor: int):
    path = _safe_drive_path(path)
    _require_root_safe_components(path, include_final=False)
    try:
        path_metadata = path.lstat()
        opened = os.fstat(descriptor)
    except OSError as exc:
        raise GuardFailure("validation attestation is unavailable") from exc
    if (
        stat.S_ISLNK(path_metadata.st_mode)
        or not stat.S_ISREG(path_metadata.st_mode)
        or not stat.S_ISREG(opened.st_mode)
        or _identity(path_metadata) != _identity(opened)
        or path_metadata.st_uid != 0
        or stat.S_IMODE(path_metadata.st_mode) != 0o400
        or path_metadata.st_size < 1
        or path_metadata.st_size >= ATTESTATION_LIMIT
    ):
        raise GuardFailure("validation attestation identity is unsafe")
    chunks = []
    consumed = 0
    while consumed < opened.st_size:
        try:
            chunk = os.pread(
                descriptor, min(CHUNK_SIZE, opened.st_size - consumed), consumed
            )
        except OSError as exc:
            raise GuardFailure("validation attestation could not be read") from exc
        if not chunk:
            raise GuardFailure("validation attestation ended while reading")
        chunks.append(chunk)
        consumed += len(chunk)
    try:
        after_path = path.lstat()
        after_opened = os.fstat(descriptor)
    except OSError as exc:
        raise GuardFailure("validation attestation changed while reading") from exc
    if _identity(after_path) != _identity(path_metadata) or _identity(after_opened) != _identity(
        opened
    ):
        raise GuardFailure("validation attestation changed while reading")
    try:
        value = json.loads(
            b"".join(chunks).decode("utf-8", "strict"), object_pairs_hook=_unique_object
        )
    except GuardFailure:
        raise
    except (UnicodeError, TypeError, ValueError) as exc:
        raise GuardFailure("validation attestation is not strict JSON") from exc
    if not isinstance(value, dict) or set(value) != ATTESTATION_FIELDS:
        raise GuardFailure("validation attestation has an unsupported shape")
    if value["schema"] != ATTESTATION_SCHEMA:
        raise GuardFailure("validation attestation schema is unsupported")
    if not isinstance(value.get("version"), str) or re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+", value["version"]
    ) is None:
        raise GuardFailure("validation attestation version is malformed")
    if not isinstance(value.get("source_commit"), str) or re.fullmatch(
        r"[0-9a-f]{40}", value["source_commit"]
    ) is None:
        raise GuardFailure("validation attestation source commit is malformed")
    if not isinstance(value["files"], dict) or set(value["files"]) != ATTESTED_BASE_ROLES:
        raise GuardFailure("validation attestation file set is incomplete")
    for mapping_name in ("files", "firmware", "run_inputs"):
        mapping = value[mapping_name]
        if not isinstance(mapping, dict):
            raise GuardFailure("validation attestation extension map is malformed")
        for role, record in mapping.items():
            if not isinstance(role, str) or not role or len(role) > 64:
                raise GuardFailure("validation attestation role is malformed")
            _validate_attested_record(record)
    run = value["run"]
    if not isinstance(run, dict) or set(run) != {
        "kind",
        "mode",
        "base_attestation",
        "runtime_root",
        "secure_preparation",
    }:
        raise GuardFailure("validation attestation lacks a per-run binding")
    if run["kind"] not in {"iso", "uki"} or run["mode"] not in {
        "bios",
        "uefi",
        "secure-boot",
    }:
        raise GuardFailure("validation attestation run selection is malformed")
    _validate_attested_record(run["base_attestation"])
    _verify_attested_record(run["base_attestation"], hash_content=False)
    if run["secure_preparation"] is not None:
        _validate_attested_record(run["secure_preparation"])
        _verify_attested_record(run["secure_preparation"], hash_content=False)
    runtime = _safe_drive_path(Path(run["runtime_root"]))
    if os.fspath(runtime) != run["runtime_root"]:
        raise GuardFailure("validation runtime root is not canonical")
    _require_root_safe_components(runtime, include_final=False)
    try:
        runtime_metadata = runtime.lstat()
    except OSError as exc:
        raise GuardFailure("validation runtime root is unavailable") from exc
    if (
        stat.S_ISLNK(runtime_metadata.st_mode)
        or not stat.S_ISDIR(runtime_metadata.st_mode)
        or runtime_metadata.st_uid != 60998
        or runtime_metadata.st_gid != 60998
        or stat.S_IMODE(runtime_metadata.st_mode) != 0o700
    ):
        raise GuardFailure("validation runtime root has an unsafe identity")
    return value


def _validate_attested_record(value):
    if not isinstance(value, dict) or set(value) != ATTESTED_FILE_FIELDS:
        raise GuardFailure("validation attestation file identity is malformed")
    if not isinstance(value["path"], str) or not isinstance(value["sha256"], str):
        raise GuardFailure("validation attestation file identity is malformed")
    if re.fullmatch(r"[0-9a-f]{64}", value["sha256"]) is None:
        raise GuardFailure("validation attestation digest is malformed")
    for field in ATTESTED_FILE_FIELDS - {"path", "sha256"}:
        if (
            not isinstance(value[field], int)
            or isinstance(value[field], bool)
            or value[field] < 0
        ):
            raise GuardFailure("validation attestation file identity is malformed")
    if value["size"] < 1 or value["mode"] > 0o7777:
        raise GuardFailure("validation attestation file identity is malformed")
    return value


def _record_metadata(metadata: os.stat_result):
    return {
        "size": metadata.st_size,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mtime_ns": metadata.st_mtime_ns,
        "ctime_ns": metadata.st_ctime_ns,
    }


def _verify_attested_record(value, *, expected_path: Optional[Path] = None, hash_content=True):
    record = _validate_attested_record(value)
    path = _safe_drive_path(Path(record["path"]))
    if os.fspath(path) != record["path"]:
        raise GuardFailure("attested validation path is not canonical")
    if expected_path is not None and path != _safe_drive_path(expected_path):
        raise GuardFailure("selected validation input is not the attested path")
    _require_root_safe_components(path, include_final=False)
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise GuardFailure("attested validation input is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise GuardFailure("attested validation input is not a regular no-follow file")
    if metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise GuardFailure("attested validation input is not root-owned and non-writable")
    if _record_metadata(metadata) != {
        key: record[key] for key in _record_metadata(metadata)
    }:
        raise GuardFailure("attested validation input identity changed")
    if hash_content:
        digest, _size, _prefix = _hash_stable(path, ISO_LIMIT)
        if digest != record["sha256"]:
            raise GuardFailure("attested validation input digest changed")


def verify_attestation(
    path: Path,
    descriptor: int,
    harness_role: str,
    harness: Path,
    tool_guard: Path,
    guard: Path,
    kind: str,
    mode: str,
    selected_input: Path,
) -> None:
    value = _read_attestation(path, descriptor)
    if value["run"]["kind"] != kind or value["run"]["mode"] != mode:
        raise GuardFailure("validation attestation does not bind the selected run")
    if (mode == "secure-boot") != (value["run"]["secure_preparation"] is not None):
        raise GuardFailure("validation attestation preparation binding is inconsistent")
    expected_harness_role = "qemu_iso_harness" if kind == "iso" else "qemu_uki_harness"
    if harness_role != expected_harness_role:
        raise GuardFailure("validation attestation harness role is inconsistent")
    files = value["files"]
    _verify_attested_record(files[harness_role], expected_path=harness)
    _verify_attested_record(files["smoke_tool_guard"], expected_path=tool_guard)
    _verify_attested_record(files["smoke_guard"], expected_path=guard)
    _verify_attested_record(files["smoke_bootstrap"])
    _verify_attested_record(files["secure_boot_preparer"])
    _verify_attested_record(files["smoke_marker_asset"])
    _verify_attested_record(files["smoke_marker_iso_profile"])
    _verify_attested_record(files["smoke_marker_expanded_iso"])
    _verify_attested_record(files["smoke_marker_validation_uki_overlay"])
    marker_digests = {
        files[role]["sha256"]
        for role in (
            "smoke_marker_asset",
            "smoke_marker_iso_profile",
            "smoke_marker_expanded_iso",
            "smoke_marker_validation_uki_overlay",
        )
    }
    if len(marker_digests) != 1:
        raise GuardFailure("attested readiness marker units differ")
    expected_run_inputs = {"selected_input", "selected_input_sha256"}
    if kind == "iso":
        expected_run_inputs.add("iso_packages")
    if set(value["run_inputs"]) != expected_run_inputs:
        raise GuardFailure("validation run input set is incomplete")
    _verify_attested_record(
        value["run_inputs"]["selected_input"], expected_path=selected_input
    )
    _verify_attested_record(
        value["run_inputs"]["selected_input_sha256"],
        expected_path=Path(str(selected_input) + ".sha256"),
    )
    if kind == "iso":
        _verify_attested_record(files["iso"])
        _verify_attested_record(files["iso_sha256"])
        _verify_attested_record(files["iso_packages"])
        _verify_attested_record(
            value["run_inputs"]["iso_packages"],
            expected_path=Path(str(selected_input) + ".packages.txt"),
        )
        for run_role, base_role in (
            ("selected_input", "iso"),
            ("selected_input_sha256", "iso_sha256"),
            ("iso_packages", "iso_packages"),
        ):
            if value["run_inputs"][run_role]["sha256"] != files[base_role]["sha256"]:
                raise GuardFailure("private ISO input differs from the base attestation")
    elif mode == "secure-boot":
        _verify_attested_record(files["validation_uki"])
        _verify_attested_record(files["validation_uki_sha256"])
    else:
        _verify_attested_record(files["validation_uki"])
        _verify_attested_record(files["validation_uki_sha256"])
        for run_role, base_role in (
            ("selected_input", "validation_uki"),
            ("selected_input_sha256", "validation_uki_sha256"),
        ):
            if value["run_inputs"][run_role]["sha256"] != files[base_role]["sha256"]:
                raise GuardFailure("private UKI input differs from the base attestation")
    expected_firmware = set()
    if mode == "uefi":
        expected_firmware = {"ovmf_code", "ovmf_vars_template"}
    elif mode == "secure-boot":
        expected_firmware = {"ovmf_secure_code", "ovmf_enrolled_vars_template"}
    if set(value["firmware"]) != expected_firmware:
        raise GuardFailure("validation attestation firmware set is incomplete")
    for record in value["firmware"].values():
        _verify_attested_record(record)


def attested_digest(path: Path, descriptor: int, mapping: str, role: str) -> str:
    value = _read_attestation(path, descriptor)
    if mapping not in {"files", "firmware", "run_inputs"}:
        raise GuardFailure("validation attestation map is invalid")
    selected = value[mapping]
    if role not in selected:
        raise GuardFailure("validation attestation does not contain the selected role")
    _verify_attested_record(selected[role])
    return selected[role]["sha256"]


def _snapshot(source: Path, destination: Path, max_bytes: int) -> Tuple[str, int, bytes]:
    source = _safe_drive_path(source)
    destination = _safe_drive_path(destination)
    descriptor, before = _open_stable_regular(source, max_bytes)
    _reject_symlinked_components(destination, include_final=False)
    destination_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        destination_flags |= os.O_NOFOLLOW
    try:
        output = os.open(str(destination), destination_flags, 0o600)
    except OSError as exc:
        os.close(descriptor)
        raise GuardFailure("private smoke-test snapshot could not be created") from exc
    digest = hashlib.sha256()
    total = 0
    prefix = b""
    try:
        while True:
            chunk = os.read(descriptor, CHUNK_SIZE)
            if not chunk:
                break
            if not prefix:
                prefix = chunk[:2]
            total += len(chunk)
            if total >= max_bytes:
                raise GuardFailure("smoke-test input exceeds its bounded size")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(output, view)
                if written <= 0:
                    raise GuardFailure("private smoke-test snapshot write was incomplete")
                view = view[written:]
        _revalidate_path(source, before, descriptor)
        os.fsync(output)
        os.fchmod(output, 0o400)
    finally:
        os.close(output)
        os.close(descriptor)
    if total != before.st_size:
        raise GuardFailure("smoke-test input changed while snapshotting")
    return digest.hexdigest(), total, prefix


def snapshot_release(kind: str, source: Path, destination: Path) -> str:
    source = _safe_drive_path(source)
    pattern, limit = (_ISO_NAME, ISO_LIMIT) if kind == "iso" else (_UKI_NAME, UKI_LIMIT)
    if pattern.fullmatch(source.name) is None:
        raise GuardFailure("release input filename is invalid")
    sidecar = Path(str(source) + ".sha256")
    raw_sidecar = _read_stable(sidecar, SIDECAR_LIMIT)
    try:
        sidecar_text = raw_sidecar.decode("ascii", errors="strict")
    except UnicodeError as exc:
        raise GuardFailure("release checksum sidecar is not strict ASCII") from exc
    match = _SIDECAR.fullmatch(sidecar_text)
    if match is None or match.group("name") != source.name:
        raise GuardFailure("release checksum sidecar does not bind the exact input")
    digest, _size, prefix = _snapshot(source, destination, limit)
    if digest != match.group("digest"):
        raise GuardFailure("release input checksum verification failed")
    if kind == "uki" and prefix != b"MZ":
        raise GuardFailure("UKI input is not a PE/COFF image")
    return digest


def snapshot_opaque(source: Path, destination: Path) -> str:
    digest, _size, _prefix = _snapshot(source, destination, FIRMWARE_LIMIT)
    return digest


def verify_snapshot(path: Path, expected_digest: str, kind: str) -> None:
    if re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None:
        raise GuardFailure("snapshot digest is invalid")
    limit = {"iso": ISO_LIMIT, "uki": UKI_LIMIT, "firmware": FIRMWARE_LIMIT}[kind]
    digest, _size, prefix = _hash_stable(path, limit)
    if digest != expected_digest:
        raise GuardFailure("immutable smoke-test snapshot changed")
    if kind == "uki" and prefix != b"MZ":
        raise GuardFailure("UKI snapshot is not a PE/COFF image")


def check_signature_inventory(path: Path, expected: str) -> None:
    raw = _read_stable(path, SIGNATURE_OUTPUT_LIMIT)
    if len(raw) >= SIGNATURE_OUTPUT_LIMIT:
        raise GuardFailure("UKI signature inventory reached its truncation boundary")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise GuardFailure("UKI signature inventory is not bounded UTF-8 text") from exc
    lines = text.splitlines()
    unsigned = lines == ["No signature table present"]
    signed = (
        "No signature table present" not in lines
        and any(_SIGNED_INVENTORY.fullmatch(line) for line in lines)
        and "image signature certificates:" in lines
    )
    if (expected == "signed" and not signed) or (expected == "unsigned" and not unsigned):
        raise GuardFailure("UKI signature inventory did not match the required state")


def evaluate_log(path: Path, expected: str) -> None:
    log = _read_stable(path, SERIAL_LOG_LIMIT)
    if len(log) >= SERIAL_LOG_LIMIT:
        raise GuardFailure("QEMU serial log reached its truncation boundary")
    ready = _READY_LINE.search(log) is not None
    if expected == "ready":
        if not ready:
            raise GuardFailure("bounded recovery readiness marker was not observed")
        return
    if ready:
        raise GuardFailure("unsigned Secure Boot control reached the recovery readiness marker")
    if _FIRMWARE_REJECTION.search(log) is None:
        raise GuardFailure("firmware-attributable unsigned-image rejection was not observed")


def write_smoke_result(
    destination: Path,
    kind: str,
    mode: str,
    ready_log: Path,
    rejection_log: Optional[Path] = None,
) -> None:
    runtime_text = os.environ.get("TMPDIR", "")
    if not runtime_text:
        raise GuardFailure("private smoke runtime is unavailable")
    runtime = _safe_drive_path(Path(runtime_text))
    destination = _safe_drive_path(destination)
    if destination != runtime / SMOKE_RESULT_NAME:
        raise GuardFailure("smoke result must use the fixed private runtime path")
    if kind == "iso" and mode not in {"bios", "uefi"}:
        raise GuardFailure("ISO smoke result mode is invalid")
    if kind == "uki" and mode not in {"uefi", "secure-boot"}:
        raise GuardFailure("UKI smoke result mode is invalid")
    if (mode == "secure-boot") != (rejection_log is not None):
        raise GuardFailure("Secure Boot result requires exactly two controls")

    def write_private_file(path: Path, content: bytes, label: str) -> None:
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(str(path), flags, 0o400)
        except OSError as exc:
            raise GuardFailure("private {} could not be created".format(label)) from exc
        try:
            view = memoryview(content)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise GuardFailure("private {} write was incomplete".format(label))
                view = view[written:]
            os.fsync(descriptor)
            os.fchmod(descriptor, 0o400)
        finally:
            os.close(descriptor)

    evidence = []
    logs = [("readiness", "ready", ready_log)]
    if rejection_log is not None:
        logs.append(("unsigned-rejection", "firmware-rejection", rejection_log))
    for role, expected, log_path in logs:
        log_path = _safe_drive_path(log_path)
        try:
            relative = log_path.relative_to(runtime)
        except ValueError as exc:
            raise GuardFailure("serial evidence escaped the private runtime") from exc
        if not relative.parts or ".." in relative.parts:
            raise GuardFailure("serial evidence path is invalid")
        evaluate_log(log_path, expected)
        serial = _read_stable(log_path, SERIAL_LOG_LIMIT)
        evidence_name = "recovery-smoke-{}.log".format(role)
        evidence_path = runtime / evidence_name
        write_private_file(evidence_path, serial, "serial evidence")
        evaluate_log(evidence_path, expected)
        digest, size, _prefix = _hash_stable(evidence_path, SERIAL_LOG_LIMIT)
        evidence.append(
            {
                "role": role,
                "expect": expected,
                "file": evidence_name,
                "sha256": digest,
                "size": size,
            }
        )

    result = {
        "schema": SMOKE_RESULT_SCHEMA,
        "kind": kind,
        "mode": mode,
        "outcome": (
            "unsigned-rejection-and-signed-readiness"
            if mode == "secure-boot"
            else "service-readiness"
        ),
        "ready_marker": True,
        "unsigned_rejection": mode == "secure-boot",
        "serial_evidence": evidence,
    }
    encoded = (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )
    if len(encoded) >= SMOKE_RESULT_LIMIT:
        raise GuardFailure("smoke result exceeds its bounded size")
    write_private_file(destination, encoded, "smoke result")
    if _read_stable(destination, SMOKE_RESULT_LIMIT) != encoded:
        raise GuardFailure("private smoke result verification failed")


def verify_payload_binding(signed: Path, unsigned: Path, reattached: Path) -> None:
    signed_digest, signed_size, signed_prefix = _hash_stable(signed, UKI_LIMIT)
    unsigned_digest, _unsigned_size, unsigned_prefix = _hash_stable(unsigned, UKI_LIMIT)
    reattached_digest, reattached_size, reattached_prefix = _hash_stable(
        reattached, UKI_LIMIT
    )
    if signed_prefix != b"MZ" or unsigned_prefix != b"MZ" or reattached_prefix != b"MZ":
        raise GuardFailure("payload-binding input is not a PE/COFF image")
    if signed_digest == unsigned_digest:
        raise GuardFailure("signature removal did not change the signed UKI")
    if signed_size != reattached_size or signed_digest != reattached_digest:
        raise GuardFailure("removed signature could not recreate the exact signed UKI")


def snapshot_digest(path: Path, kind: str) -> str:
    limit = {"iso": ISO_LIMIT, "uki": UKI_LIMIT, "firmware": FIRMWARE_LIMIT}[kind]
    digest, _size, prefix = _hash_stable(path, limit)
    if kind == "uki" and prefix != b"MZ":
        raise GuardFailure("UKI snapshot is not a PE/COFF image")
    return digest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    snapshot = subparsers.add_parser("snapshot-release")
    snapshot.add_argument("--kind", choices=("iso", "uki"), required=True)
    snapshot.add_argument("--source", required=True)
    snapshot.add_argument("--destination", required=True)

    opaque = subparsers.add_parser("snapshot-opaque")
    opaque.add_argument("--source", required=True)
    opaque.add_argument("--destination", required=True)

    verify = subparsers.add_parser("verify-snapshot")
    verify.add_argument("--kind", choices=("iso", "uki", "firmware"), required=True)
    verify.add_argument("--path", required=True)
    verify.add_argument("--sha256", required=True)

    digest = subparsers.add_parser("snapshot-digest")
    digest.add_argument("--kind", choices=("iso", "uki", "firmware"), required=True)
    digest.add_argument("--path", required=True)

    signature = subparsers.add_parser("check-signature")
    signature.add_argument("--inventory", required=True)
    signature.add_argument("--expect", choices=("signed", "unsigned"), required=True)

    log = subparsers.add_parser("evaluate-log")
    log.add_argument("--log", required=True)
    log.add_argument("--expect", choices=("ready", "firmware-rejection"), required=True)

    result = subparsers.add_parser("write-result")
    result.add_argument("--destination", required=True)
    result.add_argument("--kind", choices=("iso", "uki"), required=True)
    result.add_argument("--mode", choices=("bios", "uefi", "secure-boot"), required=True)
    result.add_argument("--ready-log", required=True)
    result.add_argument("--rejection-log")

    payload = subparsers.add_parser("verify-payload-binding")
    payload.add_argument("--signed", required=True)
    payload.add_argument("--unsigned", required=True)
    payload.add_argument("--reattached", required=True)

    attestation = subparsers.add_parser("verify-attestation")
    attestation.add_argument("--attestation", required=True)
    attestation.add_argument("--fd", type=int, required=True)
    attestation.add_argument(
        "--harness-role", choices=("qemu_iso_harness", "qemu_uki_harness"), required=True
    )
    attestation.add_argument("--harness", required=True)
    attestation.add_argument("--tool-guard", required=True)
    attestation.add_argument("--guard", required=True)
    attestation.add_argument("--kind", choices=("iso", "uki"), required=True)
    attestation.add_argument("--mode", choices=("bios", "uefi", "secure-boot"), required=True)
    attestation.add_argument("--input", required=True)

    attested = subparsers.add_parser("attested-digest")
    attested.add_argument("--attestation", required=True)
    attested.add_argument("--fd", type=int, required=True)
    attested.add_argument("--mapping", choices=("files", "firmware", "run_inputs"), required=True)
    attested.add_argument("--role", required=True)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        if args.command == "snapshot-release":
            print(snapshot_release(args.kind, Path(args.source), Path(args.destination)))
        elif args.command == "snapshot-opaque":
            print(snapshot_opaque(Path(args.source), Path(args.destination)))
        elif args.command == "verify-snapshot":
            verify_snapshot(Path(args.path), args.sha256, args.kind)
        elif args.command == "snapshot-digest":
            print(snapshot_digest(Path(args.path), args.kind))
        elif args.command == "check-signature":
            check_signature_inventory(Path(args.inventory), args.expect)
        elif args.command == "evaluate-log":
            evaluate_log(Path(args.log), args.expect)
        elif args.command == "write-result":
            write_smoke_result(
                Path(args.destination),
                args.kind,
                args.mode,
                Path(args.ready_log),
                Path(args.rejection_log) if args.rejection_log else None,
            )
        elif args.command == "verify-payload-binding":
            verify_payload_binding(
                Path(args.signed), Path(args.unsigned), Path(args.reattached)
            )
        elif args.command == "verify-attestation":
            verify_attestation(
                Path(args.attestation),
                args.fd,
                args.harness_role,
                Path(args.harness),
                Path(args.tool_guard),
                Path(args.guard),
                args.kind,
                args.mode,
                Path(args.input),
            )
        elif args.command == "attested-digest":
            print(attested_digest(Path(args.attestation), args.fd, args.mapping, args.role))
        else:  # pragma: no cover - argparse owns this boundary.
            raise GuardFailure("unknown smoke-guard action")
    except (GuardFailure, KeyError, TypeError, ValueError) as exc:
        print(f"Recovery smoke guard failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
