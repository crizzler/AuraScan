#!/usr/bin/python3
"""Prepare disposable, attested Secure Boot inputs for recovery QEMU gates.

The public entry point is deliberately root-only: it opens the private builder
attestation without parsing it, creates a fresh root-controlled output boundary,
then executes this file's private worker as an unmapped UID in a new network
namespace.  The worker performs every data parse, key operation, firmware
enrollment, and signature check.  Root only revalidates and reclaims a fixed set
of regular output files after the worker succeeds.
"""

from __future__ import annotations

import argparse
import ctypes
import datetime as dt
import hashlib
import json
import os
import pwd
import grp
import re
import resource
import secrets
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


ATTESTATION_SCHEMA = "aurascan_recovery_validation_attestation/1.0"
RECEIPT_SCHEMA = "aurascan_recovery_secure_boot_preparation/1.0"
EVIDENCE_SCHEMA = "aurascan_recovery_secure_boot_worker_evidence/1.0"
BUILD_BASE = Path("/var/lib/aurascan-recovery-builder")
VALIDATION_UID = 60998
VALIDATION_GID = 60998
MAX_ATTESTATION_BYTES = 256 * 1024
MAX_UKI_BYTES = 512 * 1024 * 1024
MAX_FIRMWARE_BYTES = 32 * 1024 * 1024
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_NATIVE_OUTPUT = 256 * 1024
MAX_WORKER_OUTPUT = 64 * 1024
NATIVE_TIMEOUT_SECONDS = 30
WORKER_TIMEOUT_SECONDS = 180
CHUNK_SIZE = 1024 * 1024

OVMF_CODE = Path("/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd")
OVMF_VARS = Path("/usr/share/edk2/x64/OVMF_VARS.4m.fd")

TOOLS = {
    "openssl": ("/usr/bin/openssl", "openssl"),
    "pacman": ("/usr/bin/pacman", "pacman"),
    "pgrep": ("/usr/bin/pgrep", "procps-ng"),
    "pkill": ("/usr/bin/pkill", "procps-ng"),
    "python": ("/usr/bin/python3", "python"),
    "sbverify": ("/usr/bin/sbverify", "sbsigntools"),
    "sbsign": ("/usr/bin/sbsign", "sbsigntools"),
    "setpriv": ("/usr/bin/setpriv", "util-linux"),
    "unshare": ("/usr/bin/unshare", "util-linux"),
    "virt_fw_vars": ("/usr/bin/virt-fw-vars", "virt-firmware"),
}
PACKAGE_SET = tuple(sorted({package for _path, package in TOOLS.values()} | {"edk2-ovmf"}))

OUTPUT_NAMES = {
    "signed_uki": "aurascan-recovery-validation-signed.efi",
    "signed_uki_sha256": "aurascan-recovery-validation-signed.efi.sha256",
    "enrolled_vars": "OVMF_VARS.aurascan-secure-boot.4m.fd",
    "secure_code": "OVMF_CODE.aurascan-secure-boot.4m.fd",
    "receipt": "secure-boot-preparation-receipt.json",
}
EVIDENCE_NAME = ".secure-boot-worker-evidence.json"
PUBLIC_OUTPUT_ROLES = ("signed_uki", "signed_uki_sha256", "enrolled_vars", "secure_code")

_HEX64 = re.compile(r"[0-9a-f]{64}")
_COMMIT = re.compile(r"[0-9a-f]{40}")
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
_PACMAN_VERSION = re.compile(r"(?P<package>[a-z0-9@._+:-]+) (?P<version>[^\s\x00-\x1f\x7f]{1,128})\n")
_PACMAN_INTEGRITY = re.compile(
    r"(?P<package>[a-z0-9@._+:-]+): [1-9][0-9]* total files, 0 altered files"
)
_PACMAN_BACKUP_NOTICE = re.compile(
    r"backup file: pacman: /etc/pacman\.conf "
    r"\((?:Modification time|Size|SHA256 checksum) mismatch\)"
)
_SIGNED_INVENTORY = re.compile(r"signature 1")


class PreparationRefusal(RuntimeError):
    """The preparation boundary could not establish a required property."""


sys.dont_write_bytecode = True


def _reject_duplicate_pairs(pairs: Sequence[Tuple[str, Any]]) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PreparationRefusal("JSON input contains duplicate keys")
        result[key] = value
    return result


def _strict_json(raw: bytes, *, maximum: int, label: str) -> Any:
    if not raw or len(raw) > maximum:
        raise PreparationRefusal("{} is empty or exceeds its byte bound".format(label))
    try:
        text = raw.decode("utf-8", errors="strict")
        return json.loads(text, object_pairs_hook=_reject_duplicate_pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PreparationRefusal("{} is not strict JSON".format(label)) from exc


def _identity(metadata: os.stat_result) -> Tuple[int, int, int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
        metadata.st_gid,
        stat.S_IFMT(metadata.st_mode),
    )


def _metadata_dict(metadata: os.stat_result) -> Dict[str, int]:
    return {
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "size": metadata.st_size,
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mtime_ns": metadata.st_mtime_ns,
        "ctime_ns": metadata.st_ctime_ns,
    }


def _path_text(path: Path) -> str:
    value = os.fspath(path)
    if not value.startswith("/") or "," in value or any(
        ord(character) < 0x20 or ord(character) == 0x7F for character in value
    ):
        raise PreparationRefusal("preparation path is not a safe absolute path")
    if os.fspath(Path(os.path.abspath(value))) != value:
        raise PreparationRefusal("preparation path is not canonical")
    return value


def _validate_component_chain(
    path: Path,
    *,
    final_regular: bool,
    final_executable: bool = False,
    required_uid: int = 0,
) -> os.stat_result:
    text = _path_text(path)
    parts = Path(text).parts
    current = Path(parts[0])
    final_metadata: Optional[os.stat_result] = None
    for index, component in enumerate(parts[1:]):
        if component in ("", ".", ".."):
            raise PreparationRefusal("preparation path contains an unsafe component")
        current /= component
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise PreparationRefusal("required preparation path is unavailable") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise PreparationRefusal("required preparation path has a symlinked component")
        if metadata.st_uid != required_uid or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise PreparationRefusal("required preparation path is not owner-controlled")
        is_final = index + 1 == len(parts) - 1
        if is_final:
            final_metadata = metadata
        elif not stat.S_ISDIR(metadata.st_mode):
            raise PreparationRefusal("required preparation path component is not a directory")
    if final_metadata is None:
        final_metadata = Path("/").lstat()
    if final_regular and not stat.S_ISREG(final_metadata.st_mode):
        raise PreparationRefusal("required preparation input is not a regular file")
    if final_executable and not (final_metadata.st_mode & 0o111):
        raise PreparationRefusal("required preparation tool is not executable")
    return final_metadata


def _resolved_trusted_tool(path: str) -> Tuple[Path, os.stat_result]:
    requested = Path(path)
    try:
        resolved = requested.resolve(strict=True)
    except OSError as exc:
        raise PreparationRefusal("required preparation tool is unavailable") from exc
    if not (str(resolved).startswith("/usr/bin/") or str(resolved).startswith("/usr/sbin/")):
        raise PreparationRefusal("required preparation tool resolved outside a system directory")
    metadata = _validate_component_chain(
        resolved, final_regular=True, final_executable=True, required_uid=0
    )
    return resolved, metadata


def _open_nofollow(
    path: Path, *, maximum: int, allow_empty: bool = False
) -> Tuple[int, os.stat_result]:
    _path_text(path)
    try:
        before = path.lstat()
    except OSError as exc:
        raise PreparationRefusal("required preparation input is unavailable") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise PreparationRefusal("required preparation input is not a no-follow regular file")
    if (before.st_size < 1 and not allow_empty) or before.st_size >= maximum:
        raise PreparationRefusal("required preparation input exceeds its size bound")
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
        raise PreparationRefusal("required preparation input could not be opened safely") from exc
    if not stat.S_ISREG(opened.st_mode) or _identity(opened) != _identity(before):
        os.close(descriptor)
        raise PreparationRefusal("required preparation input changed while opening")
    return descriptor, before


def _revalidate_open(path: Path, descriptor: int, before: os.stat_result) -> None:
    try:
        opened_after = os.fstat(descriptor)
        path_after = path.lstat()
    except OSError as exc:
        raise PreparationRefusal("required preparation input changed while reading") from exc
    if _identity(opened_after) != _identity(before) or _identity(path_after) != _identity(before):
        raise PreparationRefusal("required preparation input changed while reading")


def _read_nofollow(
    path: Path, *, maximum: int, allow_empty: bool = False
) -> Tuple[bytes, os.stat_result]:
    descriptor, before = _open_nofollow(
        path, maximum=maximum, allow_empty=allow_empty
    )
    chunks: List[bytes] = []
    total = 0
    try:
        while True:
            chunk = os.read(descriptor, min(CHUNK_SIZE, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise PreparationRefusal("required preparation input exceeds its size bound")
        _revalidate_open(path, descriptor, before)
    finally:
        os.close(descriptor)
    if total != before.st_size:
        raise PreparationRefusal("required preparation input changed while reading")
    return b"".join(chunks), before


def _prefix_nofollow(path: Path, *, maximum: int, length: int) -> bytes:
    descriptor, before = _open_nofollow(path, maximum=maximum)
    try:
        prefix = os.read(descriptor, length)
        _revalidate_open(path, descriptor, before)
    finally:
        os.close(descriptor)
    return prefix


def _copy_nofollow(
    source: Path,
    destination: Path,
    *,
    maximum: int,
    expected: Optional[Mapping[str, int]] = None,
) -> Tuple[str, int, os.stat_result]:
    descriptor, before = _open_nofollow(source, maximum=maximum)
    if expected is not None and _metadata_dict(before) != dict(expected):
        os.close(descriptor)
        raise PreparationRefusal("builder-attested input identity no longer matches")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        output = os.open(str(destination), flags, 0o600)
    except OSError as exc:
        os.close(descriptor)
        raise PreparationRefusal("private preparation output could not be created") from exc
    digest = hashlib.sha256()
    total = 0
    try:
        while True:
            chunk = os.read(descriptor, CHUNK_SIZE)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise PreparationRefusal("required preparation input exceeds its size bound")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                written = os.write(output, view)
                if written <= 0:
                    raise PreparationRefusal("private preparation output write was incomplete")
                view = view[written:]
        _revalidate_open(source, descriptor, before)
        os.fsync(output)
    finally:
        os.close(output)
        os.close(descriptor)
    if total != before.st_size:
        raise PreparationRefusal("required preparation input changed while copying")
    return digest.hexdigest(), total, before


def _hash_nofollow(path: Path, *, maximum: int) -> Tuple[str, int, os.stat_result]:
    descriptor, before = _open_nofollow(path, maximum=maximum)
    digest = hashlib.sha256()
    total = 0
    try:
        while True:
            chunk = os.read(descriptor, CHUNK_SIZE)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise PreparationRefusal("required preparation input exceeds its size bound")
            digest.update(chunk)
        _revalidate_open(path, descriptor, before)
    finally:
        os.close(descriptor)
    return digest.hexdigest(), total, before


def _read_inherited_attestation(
    descriptor: int, path: Path
) -> Tuple[bytes, os.stat_result, str]:
    try:
        before = os.fstat(descriptor)
    except OSError as exc:
        raise PreparationRefusal("inherited builder attestation descriptor is unavailable") from exc
    if not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0:
        raise PreparationRefusal("builder attestation is not a private root-owned regular file")
    if stat.S_IMODE(before.st_mode) != 0o400 or before.st_size < 1 or before.st_size > MAX_ATTESTATION_BYTES:
        raise PreparationRefusal("builder attestation permissions or size are invalid")
    try:
        path_metadata = path.lstat()
    except OSError as exc:
        raise PreparationRefusal("builder attestation path is unavailable") from exc
    if stat.S_ISLNK(path_metadata.st_mode) or _identity(path_metadata) != _identity(before):
        raise PreparationRefusal("inherited descriptor does not bind the selected attestation path")
    digest = hashlib.sha256()
    chunks: List[bytes] = []
    total = 0
    offset = 0
    while total <= MAX_ATTESTATION_BYTES:
        chunk = os.pread(descriptor, min(CHUNK_SIZE, MAX_ATTESTATION_BYTES + 1 - total), offset)
        if not chunk:
            break
        chunks.append(chunk)
        digest.update(chunk)
        total += len(chunk)
        offset += len(chunk)
    try:
        after = os.fstat(descriptor)
        path_after = path.lstat()
    except OSError as exc:
        raise PreparationRefusal("builder attestation changed while reading") from exc
    if total != before.st_size or total > MAX_ATTESTATION_BYTES:
        raise PreparationRefusal("builder attestation size changed or exceeds its bound")
    if _identity(after) != _identity(before) or _identity(path_after) != _identity(before):
        raise PreparationRefusal("builder attestation changed while reading")
    return b"".join(chunks), before, digest.hexdigest()


def _validate_file_entry(
    value: Any,
    role: str,
    *,
    allowed_modes: Sequence[int] = (0o644,),
    maximum: int = MAX_UKI_BYTES,
) -> Dict[str, Any]:
    required = {"path", "sha256", "size", "device", "inode", "mode", "uid", "gid", "mtime_ns", "ctime_ns"}
    if not isinstance(value, dict) or set(value) != required:
        raise PreparationRefusal("builder attestation has an invalid {} entry".format(role))
    if not isinstance(value["path"], str):
        raise PreparationRefusal("builder attestation path is invalid")
    path = Path(value["path"])
    _path_text(path)
    if not isinstance(value["sha256"], str) or _HEX64.fullmatch(value["sha256"]) is None:
        raise PreparationRefusal("builder attestation digest is invalid")
    integer_keys = required - {"path", "sha256"}
    if any(type(value[key]) is not int or value[key] < 0 for key in integer_keys):
        raise PreparationRefusal("builder attestation file metadata is invalid")
    if value["size"] < 1 or value["size"] >= maximum:
        raise PreparationRefusal("builder-attested input exceeds its size bound")
    if value["uid"] != 0 or value["gid"] != 0 or value["mode"] not in allowed_modes:
        raise PreparationRefusal("builder-attested validation input is not root-owned read-only data")
    return dict(value)


def _parse_base_attestation(raw: bytes) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    parsed = _strict_json(raw, maximum=MAX_ATTESTATION_BYTES, label="builder attestation")
    required = {"schema", "version", "source_commit", "files", "firmware", "run_inputs", "run"}
    if not isinstance(parsed, dict) or set(parsed) != required:
        raise PreparationRefusal("builder attestation schema fields are invalid")
    if parsed["schema"] != ATTESTATION_SCHEMA:
        raise PreparationRefusal("builder attestation schema is unsupported")
    if not isinstance(parsed["version"], str) or _VERSION.fullmatch(parsed["version"]) is None:
        raise PreparationRefusal("builder attestation version is invalid")
    if not isinstance(parsed["source_commit"], str) or _COMMIT.fullmatch(parsed["source_commit"]) is None:
        raise PreparationRefusal("builder attestation source commit is invalid")
    if parsed["firmware"] != {} or parsed["run_inputs"] != {} or parsed["run"] is not None:
        raise PreparationRefusal("a per-run extension cannot replace the base builder attestation")
    files = parsed["files"]
    if not isinstance(files, dict):
        raise PreparationRefusal("builder attestation file inventory is invalid")
    try:
        uki = _validate_file_entry(files["validation_uki"], "validation UKI")
        sidecar = _validate_file_entry(files["validation_uki_sha256"], "validation UKI sidecar")
    except KeyError as exc:
        raise PreparationRefusal("builder attestation omits validation UKI evidence") from exc
    return parsed, uki, sidecar


def _verify_attested_self(attestation: Mapping[str, Any]) -> Dict[str, Any]:
    try:
        entry = _validate_file_entry(
            attestation["files"]["secure_boot_preparer"],
            "Secure Boot preparer",
            allowed_modes=(0o755,),
            maximum=2 * 1024 * 1024,
        )
    except (KeyError, TypeError) as exc:
        raise PreparationRefusal("builder attestation omits the Secure Boot preparer") from exc
    try:
        running = Path(__file__).resolve(strict=True)
    except OSError as exc:
        raise PreparationRefusal("running Secure Boot preparer path is unavailable") from exc
    if str(running) != entry["path"]:
        raise PreparationRefusal("running Secure Boot preparer is not the attested snapshot helper")
    metadata = _validate_component_chain(
        running, final_regular=True, final_executable=True, required_uid=0
    )
    digest, size, after = _hash_nofollow(running, maximum=2 * 1024 * 1024)
    expected_metadata = {
        key: entry[key]
        for key in ("device", "inode", "size", "mode", "uid", "gid", "mtime_ns", "ctime_ns")
    }
    if (
        _identity(metadata) != _identity(after)
        or _metadata_dict(after) != expected_metadata
        or digest != entry["sha256"]
        or size != entry["size"]
    ):
        raise PreparationRefusal("running Secure Boot preparer no longer matches its attested identity")
    return entry


def _bounded_process(
    command: Sequence[str],
    *,
    work: Path,
    label: str,
    timeout: int = NATIVE_TIMEOUT_SECONDS,
    output_limit: int = MAX_NATIVE_OUTPUT,
    pass_fds: Sequence[int] = (),
    environment: Optional[Mapping[str, str]] = None,
    validate_tool: bool = True,
    artifact_limit: Optional[int] = None,
) -> bytes:
    if not command or not str(command[0]).startswith("/"):
        raise PreparationRefusal("bounded preparation command is not absolute")
    tool_identity: Optional[os.stat_result] = None
    if validate_tool:
        resolved_tool, tool_identity = _resolved_trusted_tool(str(command[0]))
        if str(resolved_tool) != str(command[0]):
            raise PreparationRefusal("bounded preparation command did not use its resolved tool path")
    expected_parent_pid = os.getpid()
    file_size_limit = artifact_limit if artifact_limit is not None else output_limit
    if (
        output_limit < 1
        or file_size_limit < 1
        or file_size_limit > MAX_UKI_BYTES
    ):
        raise PreparationRefusal("bounded preparation artifact limit is invalid")

    def _limits() -> None:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_FSIZE, (file_size_limit, file_size_limit))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
        resource.setrlimit(resource.RLIMIT_AS, (2 * 1024 * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_CPU, (timeout + 5, timeout + 5))
        libc = ctypes.CDLL(None, use_errno=True)
        if (
            libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0
            or os.getppid() != expected_parent_pid
        ):
            os._exit(125)

    process: Optional[subprocess.Popen] = None
    selector: Optional[selectors.BaseSelector] = None
    captured = bytearray()
    try:
        try:
            process = subprocess.Popen(
                list(command),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=dict(environment or _worker_environment()),
                close_fds=True,
                pass_fds=tuple(pass_fds),
                start_new_session=True,
                preexec_fn=_limits,
            )
        except OSError as exc:
            raise PreparationRefusal("{} could not be started".format(label)) from exc
        if process.stdout is None:  # pragma: no cover - Popen owns this invariant.
            raise PreparationRefusal("{} output pipe is unavailable".format(label))
        os.set_blocking(process.stdout.fileno(), False)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        reached_eof = False
        while not (process.poll() is not None and reached_eof):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired as exc:
                        raise PreparationRefusal(
                            "{} could not be retired after its runtime bound".format(label)
                        ) from exc
                raise PreparationRefusal("{} exceeded its runtime bound".format(label))
            for key, _events in selector.select(timeout=min(0.05, remaining)):
                try:
                    chunk = os.read(key.fd, min(64 * 1024, output_limit + 1))
                except BlockingIOError:
                    continue
                if not chunk:
                    reached_eof = True
                    try:
                        selector.unregister(process.stdout)
                    except KeyError:
                        pass
                    continue
                captured.extend(chunk)
                if len(captured) >= output_limit:
                    if process.poll() is None:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired as exc:
                        raise PreparationRefusal(
                            "{} could not be retired after reaching its output bound".format(label)
                        ) from exc
                    raise PreparationRefusal("{} reached its output bound".format(label))
        if process.returncode != 0:
            raise PreparationRefusal("{} failed inside its bounded execution".format(label))
        if validate_tool and tool_identity is not None:
            _resolved, after_tool = _resolved_trusted_tool(str(command[0]))
            if _identity(after_tool) != _identity(tool_identity):
                raise PreparationRefusal("{} tool identity changed during execution".format(label))
        return bytes(captured)
    finally:
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=2)
            except subprocess.SubprocessError:
                pass
        if selector is not None:
            selector.close()
        if process is not None and process.stdout is not None:
            process.stdout.close()


def _worker_environment() -> Dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "USER": "aurascan-validation",
        "LOGNAME": "aurascan-validation",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "AURASCAN_AI_ENABLED": "0",
        "AURASCAN_INSTRUCTION_AI_ENABLED": "0",
        "AURASCAN_INCIDENT_AI_ENABLED": "0",
        "AURASCAN_RECOVERY_AI_ENABLED": "0",
    }


def _hash_record(path: Path, maximum: int) -> Dict[str, Any]:
    digest, size, _metadata = _hash_nofollow(path, maximum=maximum)
    return {"filename": path.name, "sha256": digest, "size": size}


def _collect_tool_records(work: Path) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    resolved: Dict[str, Tuple[Path, os.stat_result, str]] = {}
    for name, (path, package) in TOOLS.items():
        tool_path, metadata = _resolved_trusted_tool(path)
        resolved[name] = (tool_path, metadata, package)
    pacman = str(resolved["pacman"][0])
    versions: Dict[str, str] = {}
    for package in PACKAGE_SET:
        raw = _bounded_process(
            [pacman, "-Q", "--", package], work=work, label="package-version"
        )
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise PreparationRefusal("package version output is not strict UTF-8") from exc
        match = _PACMAN_VERSION.fullmatch(text)
        if match is None or match.group("package") != package:
            raise PreparationRefusal("package version output is not exact")
        versions[package] = match.group("version")
    raw_integrity = _bounded_process(
        [pacman, "-Qkk", *PACKAGE_SET], work=work, label="package-integrity"
    )
    try:
        lines = raw_integrity.decode("utf-8", errors="strict").splitlines()
    except UnicodeError as exc:
        raise PreparationRefusal("package integrity output is not strict UTF-8") from exc
    observed = set()
    summary_count = 0
    for line in lines:
        if _PACMAN_BACKUP_NOTICE.fullmatch(line):
            continue
        match = _PACMAN_INTEGRITY.fullmatch(line)
        if match is None:
            raise PreparationRefusal("package integrity output reported an unexpected condition")
        observed.add(match.group("package"))
        summary_count += 1
    if observed != set(PACKAGE_SET) or summary_count != len(PACKAGE_SET):
        raise PreparationRefusal("package integrity output is incomplete")

    records: Dict[str, Dict[str, Any]] = {}
    for name, (tool_path, original_metadata, package) in resolved.items():
        digest, size, metadata = _hash_nofollow(tool_path, maximum=128 * 1024 * 1024)
        if _identity(metadata) != _identity(original_metadata):
            raise PreparationRefusal("trusted preparation tool changed during verification")
        records[name] = {
            "path": str(tool_path),
            "sha256": digest,
            "size": size,
            "package": package,
            "package_version": versions[package],
        }
    return records, versions


def _validate_package_managed_firmware(
    path: Path, expected_package_version: str, work: Path, pacman: str
) -> Dict[str, Any]:
    metadata = _validate_component_chain(path, final_regular=True, required_uid=0)
    if metadata.st_gid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
        raise PreparationRefusal("OVMF input is not root-owned non-writable data")
    owner = _bounded_process(
        [pacman, "-Qqo", "--", str(path)], work=work, label="firmware-owner"
    )
    if owner != b"edk2-ovmf\n":
        raise PreparationRefusal("OVMF input is not owned by the expected package")
    digest, size, after = _hash_nofollow(path, maximum=MAX_FIRMWARE_BYTES)
    if _identity(after) != _identity(metadata):
        raise PreparationRefusal("OVMF input changed during verification")
    return {
        "filename": path.name,
        "sha256": digest,
        "size": size,
        "package": "edk2-ovmf",
        "package_version": expected_package_version,
    }


def _certificate_command(role: str, key: Path, certificate: Path) -> List[str]:
    return [
        str(_resolved_trusted_tool(TOOLS["openssl"][0])[0]),
        "req",
        "-new",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-sha256",
        "-days",
        "2",
        "-noenc",
        "-batch",
        "-subj",
        "/CN=AuraScan disposable {}/".format(role),
        "-addext",
        "basicConstraints=critical,CA:FALSE",
        "-addext",
        "keyUsage=critical,digitalSignature",
        "-addext",
        "extendedKeyUsage=codeSigning",
        "-keyout",
        str(key),
        "-out",
        str(certificate),
    ]


def _validate_vars_json(raw: bytes) -> Dict[str, Dict[str, Any]]:
    parsed = _strict_json(raw, maximum=MAX_JSON_BYTES, label="OVMF variable inventory")
    if not isinstance(parsed, dict) or set(parsed) != {"version", "variables"}:
        raise PreparationRefusal("OVMF variable inventory has an unsupported shape")
    if parsed["version"] != 2 or not isinstance(parsed["variables"], list):
        raise PreparationRefusal("OVMF variable inventory has an unsupported version")
    if not 1 <= len(parsed["variables"]) <= 2048:
        raise PreparationRefusal("OVMF variable inventory exceeds its entry bound")
    variables: Dict[str, str] = {}
    for value in parsed["variables"]:
        if not isinstance(value, dict) or not {"name", "guid", "attr", "data"}.issubset(value):
            raise PreparationRefusal("OVMF variable entry is malformed")
        if set(value) - {"name", "guid", "attr", "data", "time"}:
            raise PreparationRefusal("OVMF variable entry has unexpected fields")
        name = value["name"]
        data = value["data"]
        if not isinstance(name, str) or not isinstance(data, str):
            raise PreparationRefusal("OVMF variable name or data is invalid")
        if name in variables:
            raise PreparationRefusal("OVMF variable inventory contains duplicate names")
        if len(data) > 512 * 1024 or len(data) % 2 or re.fullmatch(r"[0-9a-f]*", data) is None:
            raise PreparationRefusal("OVMF variable data is not bounded lowercase hexadecimal")
        variables[name] = data
    required = ("PK", "KEK", "db", "dbx", "SecureBootEnable", "CustomMode")
    if any(name not in variables for name in required):
        raise PreparationRefusal("OVMF variable inventory omits Secure Boot state")
    if any(not variables[name] for name in ("PK", "KEK", "db", "dbx")):
        raise PreparationRefusal("OVMF Secure Boot signature database is empty")
    if variables["SecureBootEnable"] != "01" or variables["CustomMode"] != "00":
        raise PreparationRefusal("OVMF Secure Boot mode flags are not exact")
    return {
        name: {
            "sha256": hashlib.sha256(bytes.fromhex(variables[name])).hexdigest(),
            "size": len(variables[name]) // 2,
            **({"data": variables[name]} if name in ("SecureBootEnable", "CustomMode") else {}),
        }
        for name in required
    }


def _write_exact(path: Path, data: bytes, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(str(path), flags, mode)
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise PreparationRefusal("preparation receipt write was incomplete")
            view = view[written:]
        os.fsync(descriptor)
        os.fchmod(descriptor, mode)
    finally:
        os.close(descriptor)


def _unlink_private(paths: Iterable[Path]) -> None:
    for path in paths:
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise PreparationRefusal("private key cleanup could not inspect its exact target") from exc
        if stat.S_ISDIR(metadata.st_mode):
            raise PreparationRefusal("private key cleanup target unexpectedly became a directory")
        try:
            path.unlink()
        except OSError as exc:
            raise PreparationRefusal("private key cleanup failed") from exc


def _validate_worker_context(staging: Path, *, require_empty: bool) -> None:
    if os.geteuid() == 0 or os.geteuid() != VALIDATION_UID or os.getegid() != VALIDATION_GID:
        raise PreparationRefusal("Secure Boot preparation worker requires the unmapped validation UID")
    expected_environment = _worker_environment()
    if set(os.environ) != set(expected_environment) or any(
        os.environ.get(key) != value for key, value in expected_environment.items()
    ):
        raise PreparationRefusal("Secure Boot preparation worker environment is not minimal")
    staging_metadata = staging.lstat()
    if (
        not stat.S_ISDIR(staging_metadata.st_mode)
        or stat.S_ISLNK(staging_metadata.st_mode)
        or staging_metadata.st_uid != VALIDATION_UID
        or staging_metadata.st_gid != VALIDATION_GID
        or stat.S_IMODE(staging_metadata.st_mode) != 0o700
    ):
        raise PreparationRefusal("Secure Boot staging directory is not private to the validation UID")
    if require_empty and next(staging.iterdir(), None) is not None:
        raise PreparationRefusal("Secure Boot staging directory must start empty")
    os.umask(0o077)


def _prepare_worker(
    *,
    attestation_fd: int,
    attestation_path: Path,
    staging: Path,
) -> Dict[str, Any]:
    _validate_worker_context(staging, require_empty=True)

    raw_attestation, _attestation_metadata, attestation_digest = _read_inherited_attestation(
        attestation_fd, attestation_path
    )
    attestation, uki_entry, sidecar_entry = _parse_base_attestation(raw_attestation)
    _verify_attested_self(attestation)

    _validate_component_chain(
        Path(uki_entry["path"]),
        final_regular=True,
        required_uid=0,
    )
    _validate_component_chain(
        Path(sidecar_entry["path"]),
        final_regular=True,
        required_uid=0,
    )

    unsigned = staging / ".unsigned-validation.efi"
    keys = [staging / ".PK.key", staging / ".KEK.key", staging / ".db.key"]
    certificates = [staging / ".PK.crt", staging / ".KEK.crt", staging / ".db.crt"]
    variables_json = staging / ".variables.json"
    vars_snapshot = staging / ".OVMF_VARS.base.fd"
    sensitive = list(keys)
    transient = [unsigned, variables_json, vars_snapshot, *certificates]
    evidence: Dict[str, Any]
    try:
        tool_records, package_versions = _collect_tool_records(staging)
        pacman = tool_records["pacman"]["path"]
        firmware_code = _validate_package_managed_firmware(
            OVMF_CODE, package_versions["edk2-ovmf"], staging, pacman
        )
        firmware_vars = _validate_package_managed_firmware(
            OVMF_VARS, package_versions["edk2-ovmf"], staging, pacman
        )
        vars_digest, vars_size, _ = _copy_nofollow(
            OVMF_VARS, vars_snapshot, maximum=MAX_FIRMWARE_BYTES
        )
        if vars_digest != firmware_vars["sha256"] or vars_size != firmware_vars["size"]:
            raise PreparationRefusal("OVMF variables template changed while snapshotting")

        copied_digest, copied_size, copied_metadata = _copy_nofollow(
            Path(uki_entry["path"]),
            unsigned,
            maximum=MAX_UKI_BYTES,
            expected={
                key: uki_entry[key]
                for key in ("device", "inode", "size", "mode", "uid", "gid", "mtime_ns", "ctime_ns")
            },
        )
        if copied_metadata.st_uid != 0 or copied_metadata.st_gid != 0:
            raise PreparationRefusal("builder-attested validation UKI owner changed")
        if copied_digest != uki_entry["sha256"] or copied_size != uki_entry["size"]:
            raise PreparationRefusal("copied validation UKI does not match the builder attestation")
        if _prefix_nofollow(unsigned, maximum=MAX_UKI_BYTES, length=2) != b"MZ":
            raise PreparationRefusal("builder-attested validation UKI is not PE/COFF data")

        sidecar_raw, sidecar_metadata = _read_nofollow(
            Path(sidecar_entry["path"]), maximum=256
        )
        if _metadata_dict(sidecar_metadata) != {
            key: sidecar_entry[key]
            for key in ("device", "inode", "size", "mode", "uid", "gid", "mtime_ns", "ctime_ns")
        }:
            raise PreparationRefusal("builder-attested validation sidecar identity changed")
        expected_sidecar = "{}  {}\n".format(copied_digest, Path(uki_entry["path"]).name).encode("ascii")
        if sidecar_raw != expected_sidecar:
            raise PreparationRefusal("builder-attested validation sidecar does not bind the UKI")

        unsigned_inventory = _bounded_process(
            [tool_records["sbverify"]["path"], "--list", str(unsigned)],
            work=staging,
            label="unsigned-signature-inventory",
        )
        if unsigned_inventory != b"No signature table present\n":
            raise PreparationRefusal("builder-attested validation UKI is not exactly unsigned")

        certificate_records: Dict[str, Dict[str, Any]] = {}
        for role, key, certificate in zip(("PK", "KEK", "db"), keys, certificates):
            _bounded_process(
                _certificate_command(role, key, certificate),
                work=staging,
                label="certificate-{}".format(role.lower()),
            )
            key_meta = key.lstat()
            if (
                not stat.S_ISREG(key_meta.st_mode)
                or stat.S_ISLNK(key_meta.st_mode)
                or not 512 <= key_meta.st_size < 64 * 1024
                or stat.S_IMODE(key_meta.st_mode) & 0o077
            ):
                raise PreparationRefusal("disposable private key was not created as a regular file")
            os.chmod(key, 0o600, follow_symlinks=False)
            certificate_records[role] = _hash_record(certificate, 256 * 1024)

        owner_guid = str(uuid.UUID(bytes=secrets.token_bytes(16), version=4))
        enrolled_vars = staging / OUTPUT_NAMES["enrolled_vars"]
        _bounded_process(
            [
                tool_records["virt_fw_vars"]["path"],
                "--input",
                str(vars_snapshot),
                "--output",
                str(enrolled_vars),
                "--delete",
                "PK",
                "--delete",
                "KEK",
                "--delete",
                "db",
                "--delete",
                "dbx",
                "--set-pk",
                owner_guid,
                str(certificates[0]),
                "--add-kek",
                owner_guid,
                str(certificates[1]),
                "--add-db",
                owner_guid,
                str(certificates[2]),
                "--secure-boot",
            ],
            work=staging,
            label="firmware-enrollment",
            artifact_limit=MAX_FIRMWARE_BYTES,
        )
        _bounded_process(
            [
                tool_records["virt_fw_vars"]["path"],
                "--input",
                str(enrolled_vars),
                "--output-json",
                str(variables_json),
            ],
            work=staging,
            label="firmware-inventory",
            artifact_limit=MAX_JSON_BYTES,
        )
        variables_raw, _ = _read_nofollow(variables_json, maximum=MAX_JSON_BYTES)
        variable_summary = _validate_vars_json(variables_raw)

        signed = staging / OUTPUT_NAMES["signed_uki"]
        _bounded_process(
            [
                tool_records["sbsign"]["path"],
                "--key",
                str(keys[2]),
                "--cert",
                str(certificates[2]),
                "--output",
                str(signed),
                str(unsigned),
            ],
            work=staging,
            label="uki-signing",
            artifact_limit=MAX_UKI_BYTES,
        )
        _bounded_process(
            [tool_records["sbverify"]["path"], "--cert", str(certificates[2]), str(signed)],
            work=staging,
            label="signed-certificate-verification",
        )
        signed_inventory = _bounded_process(
            [tool_records["sbverify"]["path"], "--list", str(signed)],
            work=staging,
            label="signed-signature-inventory",
        )
        try:
            signed_text = signed_inventory.decode("utf-8", errors="strict").splitlines()
        except UnicodeError as exc:
            raise PreparationRefusal("signed UKI inventory is not strict UTF-8") from exc
        if (
            "No signature table present" in signed_text
            or sum(1 for line in signed_text if _SIGNED_INVENTORY.fullmatch(line)) != 1
            or "image signature certificates:" not in signed_text
        ):
            raise PreparationRefusal("signed UKI does not contain exactly one inventoried signature")

        signed_record = _hash_record(signed, MAX_UKI_BYTES)
        if signed_record["sha256"] == copied_digest:
            raise PreparationRefusal("UKI signing did not change the exact unsigned candidate")
        sidecar = staging / OUTPUT_NAMES["signed_uki_sha256"]
        _write_exact(
            sidecar,
            "{}  {}\n".format(signed_record["sha256"], signed.name).encode("ascii"),
            0o444,
        )

        secure_code = staging / OUTPUT_NAMES["secure_code"]
        secure_code_digest, secure_code_size, _ = _copy_nofollow(
            OVMF_CODE, secure_code, maximum=MAX_FIRMWARE_BYTES
        )
        if secure_code_digest != firmware_code["sha256"] or secure_code_size != firmware_code["size"]:
            raise PreparationRefusal("Secure Boot OVMF code snapshot changed")

        # Key cleanup is a gate, not a best-effort epilogue.  Receipt creation
        # and success happen only after every private-key pathname is absent.
        _unlink_private(keys)
        if any(path.exists() or path.is_symlink() for path in keys):
            raise PreparationRefusal("disposable private key remained after cleanup")

        for path in (signed, sidecar, enrolled_vars, secure_code):
            os.chmod(path, 0o444, follow_symlinks=False)
        outputs = {
            "signed_uki": _hash_record(signed, MAX_UKI_BYTES),
            "signed_uki_sha256": _hash_record(sidecar, 256),
            "enrolled_vars": _hash_record(enrolled_vars, MAX_FIRMWARE_BYTES),
            "secure_code": _hash_record(secure_code, MAX_FIRMWARE_BYTES),
        }
        evidence = {
            "schema": EVIDENCE_SCHEMA,
            "version": attestation["version"],
            "source_commit": attestation["source_commit"],
            "created_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "builder_attestation": {
                "sha256": attestation_digest,
                **{
                    key: getattr(_attestation_metadata, "st_{}".format(key))
                    for key in ("size", "uid", "gid", "mtime_ns", "ctime_ns")
                },
                "device": _attestation_metadata.st_dev,
                "inode": _attestation_metadata.st_ino,
                "mode": stat.S_IMODE(_attestation_metadata.st_mode),
            },
            "unsigned_validation_uki": {
                "filename": Path(uki_entry["path"]).name,
                "sha256": copied_digest,
                "size": copied_size,
                "builder_identity": {key: uki_entry[key] for key in ("device", "inode", "mode", "uid", "gid", "mtime_ns", "ctime_ns")},
            },
            "firmware_inputs": {"secure_code": firmware_code, "vars_template": firmware_vars},
            "tools": tool_records,
            "certificates": certificate_records,
            "enrolled_variables": variable_summary,
            "outputs": outputs,
            "private_keys_deleted": True,
            "network_namespace": "isolated-by-root-launcher",
        }
        evidence_path = staging / EVIDENCE_NAME
        encoded = (json.dumps(evidence, sort_keys=True, indent=2) + "\n").encode("utf-8")
        if len(encoded) >= MAX_ATTESTATION_BYTES:
            raise PreparationRefusal("Secure Boot worker evidence exceeds its byte bound")
        _write_exact(evidence_path, encoded, 0o400)
        return evidence
    finally:
        _unlink_private(sensitive)
        _unlink_private(transient)


def _final_output_entry(path: Path, maximum: int) -> Dict[str, Any]:
    digest, size, metadata = _hash_nofollow(path, maximum=maximum)
    if (
        metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o644
    ):
        raise PreparationRefusal("prepared Secure Boot output was not safely reclaimed by root")
    return {
        "filename": path.name,
        "sha256": digest,
        "size": size,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mtime_ns": metadata.st_mtime_ns,
        "ctime_ns": metadata.st_ctime_ns,
    }


def _validate_worker_evidence(value: Any) -> Dict[str, Any]:
    required = {
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
    if not isinstance(value, dict) or set(value) != required:
        raise PreparationRefusal("Secure Boot worker evidence has an unsupported shape")
    if value["schema"] != EVIDENCE_SCHEMA:
        raise PreparationRefusal("Secure Boot worker evidence schema is unsupported")
    if not isinstance(value["version"], str) or _VERSION.fullmatch(value["version"]) is None:
        raise PreparationRefusal("Secure Boot worker evidence version is invalid")
    if not isinstance(value["source_commit"], str) or _COMMIT.fullmatch(value["source_commit"]) is None:
        raise PreparationRefusal("Secure Boot worker evidence commit is invalid")
    if value["private_keys_deleted"] is not True or value["network_namespace"] != "isolated-by-root-launcher":
        raise PreparationRefusal("Secure Boot worker evidence does not prove its isolation/cleanup gate")
    if not isinstance(value["outputs"], dict) or set(value["outputs"]) != set(PUBLIC_OUTPUT_ROLES):
        raise PreparationRefusal("Secure Boot worker evidence output set is invalid")
    for role in PUBLIC_OUTPUT_ROLES:
        record = value["outputs"][role]
        if not isinstance(record, dict) or set(record) != {"filename", "sha256", "size"}:
            raise PreparationRefusal("Secure Boot worker evidence output identity is invalid")
        if record["filename"] != OUTPUT_NAMES[role]:
            raise PreparationRefusal("Secure Boot worker evidence output filename is invalid")
        if not isinstance(record["sha256"], str) or _HEX64.fullmatch(record["sha256"]) is None:
            raise PreparationRefusal("Secure Boot worker evidence output digest is invalid")
        if type(record["size"]) is not int or record["size"] < 1:
            raise PreparationRefusal("Secure Boot worker evidence output size is invalid")
    return dict(value)


def _finalize_receipt_worker(
    *, attestation_fd: int, attestation_path: Path, staging: Path
) -> Dict[str, Any]:
    _validate_worker_context(staging, require_empty=False)
    expected_intermediate = {EVIDENCE_NAME} | {
        OUTPUT_NAMES[role] for role in PUBLIC_OUTPUT_ROLES
    }
    if {entry.name for entry in os.scandir(staging)} != expected_intermediate:
        raise PreparationRefusal("Secure Boot intermediate output inventory is not exact")

    raw_attestation, attestation_metadata, attestation_digest = _read_inherited_attestation(
        attestation_fd, attestation_path
    )
    attestation, uki_entry, _sidecar_entry = _parse_base_attestation(raw_attestation)
    _verify_attested_self(attestation)
    evidence_path = staging / EVIDENCE_NAME
    raw_evidence, evidence_metadata = _read_nofollow(
        evidence_path, maximum=MAX_ATTESTATION_BYTES
    )
    if (
        evidence_metadata.st_uid != VALIDATION_UID
        or evidence_metadata.st_gid != VALIDATION_GID
        or stat.S_IMODE(evidence_metadata.st_mode) != 0o400
    ):
        raise PreparationRefusal("Secure Boot worker evidence is not private to its validation UID")
    evidence = _validate_worker_evidence(
        _strict_json(
            raw_evidence,
            maximum=MAX_ATTESTATION_BYTES,
            label="Secure Boot worker evidence",
        )
    )
    current_attestation = {
        "sha256": attestation_digest,
        "size": attestation_metadata.st_size,
        "device": attestation_metadata.st_dev,
        "inode": attestation_metadata.st_ino,
        "mode": stat.S_IMODE(attestation_metadata.st_mode),
        "uid": attestation_metadata.st_uid,
        "gid": attestation_metadata.st_gid,
        "mtime_ns": attestation_metadata.st_mtime_ns,
        "ctime_ns": attestation_metadata.st_ctime_ns,
    }
    if evidence["builder_attestation"] != current_attestation:
        raise PreparationRefusal("builder attestation changed between preparation phases")
    if evidence["version"] != attestation["version"] or evidence["source_commit"] != attestation["source_commit"]:
        raise PreparationRefusal("Secure Boot worker evidence is not bound to the base attestation")
    unsigned = evidence["unsigned_validation_uki"]
    expected_unsigned = {
        "filename": Path(uki_entry["path"]).name,
        "sha256": uki_entry["sha256"],
        "size": uki_entry["size"],
        "builder_identity": {
            key: uki_entry[key]
            for key in ("device", "inode", "mode", "uid", "gid", "mtime_ns", "ctime_ns")
        },
    }
    if unsigned != expected_unsigned:
        raise PreparationRefusal("prepared Secure Boot payload is not bound to the validation UKI")

    limits = {
        "signed_uki": MAX_UKI_BYTES,
        "signed_uki_sha256": 256,
        "enrolled_vars": MAX_FIRMWARE_BYTES,
        "secure_code": MAX_FIRMWARE_BYTES,
    }
    outputs = {
        role: _final_output_entry(staging / OUTPUT_NAMES[role], limits[role])
        for role in PUBLIC_OUTPUT_ROLES
    }
    for role in PUBLIC_OUTPUT_ROLES:
        initial = evidence["outputs"][role]
        if any(outputs[role][field] != initial[field] for field in ("filename", "sha256", "size")):
            raise PreparationRefusal("prepared Secure Boot output changed during root reclaim")
    signed = outputs["signed_uki"]
    sidecar_raw, _ = _read_nofollow(
        staging / OUTPUT_NAMES["signed_uki_sha256"], maximum=256
    )
    expected_sidecar = "{}  {}\n".format(signed["sha256"], signed["filename"]).encode("ascii")
    if sidecar_raw != expected_sidecar:
        raise PreparationRefusal("prepared signed UKI sidecar is no longer exact")

    receipt = dict(evidence)
    receipt["schema"] = RECEIPT_SCHEMA
    receipt["outputs"] = outputs
    receipt_path = staging / OUTPUT_NAMES["receipt"]
    encoded = (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode("utf-8")
    if len(encoded) >= MAX_ATTESTATION_BYTES:
        raise PreparationRefusal("Secure Boot preparation receipt exceeds its byte bound")
    _write_exact(receipt_path, encoded, 0o400)
    _unlink_private((evidence_path,))
    return receipt


def _root_environment_is_minimal() -> bool:
    expected = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/root",
        "USER": "root",
        "LOGNAME": "root",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
    }
    allowed = set(expected) | {"PWD", "SHLVL", "_"}
    return not (set(os.environ) - allowed) and all(os.environ.get(key) == value for key, value in expected.items())


def _uid_is_unmapped(uid: int, gid: int) -> bool:
    try:
        pwd.getpwuid(uid)
    except KeyError:
        pass
    else:
        return False
    try:
        grp.getgrgid(gid)
    except KeyError:
        return True
    return False


def _uid_has_processes(uid: int) -> bool:
    proc = Path("/proc")
    for child in proc.iterdir():
        if not child.name.isdigit():
            continue
        try:
            raw = (child / "status").read_bytes()
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        for line in raw.splitlines():
            if line.startswith(b"Uid:"):
                fields = line.split()[1:]
                if any(field == str(uid).encode("ascii") for field in fields):
                    return True
                break
    return False


def _retire_validation_uid(tools: Mapping[str, Path]) -> None:
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "USER": "root",
        "LOGNAME": "root",
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
    }
    for _attempt in range(50):
        try:
            found = subprocess.run(
                [str(tools["pgrep"]), "-u", str(VALIDATION_UID)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=environment,
                timeout=2,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise PreparationRefusal("could not audit Secure Boot validation processes") from exc
        if found.returncode == 1:
            return
        if found.returncode != 0:
            raise PreparationRefusal("could not audit Secure Boot validation processes")
        try:
            killed = subprocess.run(
                [str(tools["pkill"]), "-KILL", "-u", str(VALIDATION_UID)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=environment,
                timeout=2,
                check=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise PreparationRefusal("could not retire Secure Boot validation processes") from exc
        if killed.returncode not in (0, 1):
            raise PreparationRefusal("could not retire Secure Boot validation processes")
        time.sleep(0.1)
    raise PreparationRefusal("could not retire Secure Boot validation processes")


def _cleanup_root(path: Path, *, required_uid: int = 0) -> None:
    try:
        parent = path.parent.resolve(strict=True)
    except OSError as exc:
        raise PreparationRefusal("preparation cleanup parent is unavailable") from exc
    if parent != BUILD_BASE or not path.name.startswith("secure-boot-prep."):
        raise PreparationRefusal("refusing cleanup outside the exact preparation boundary")
    if not path.exists() and not path.is_symlink():
        return
    metadata = path.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != required_uid
    ):
        raise PreparationRefusal("refusing cleanup of a replaced preparation boundary")
    shutil.rmtree(path)


def _root_prepare(attestation_path: Path) -> Path:
    if os.geteuid() != 0:
        raise PreparationRefusal("Secure Boot preparation launcher must run as root")
    if not _root_environment_is_minimal():
        raise PreparationRefusal("Secure Boot preparation launcher requires the documented minimal environment")
    if not _uid_is_unmapped(VALIDATION_UID, VALIDATION_GID) or _uid_has_processes(VALIDATION_UID):
        raise PreparationRefusal("fresh unmapped Secure Boot validation identity is unavailable")
    os.umask(0o077)

    script = Path(__file__).resolve(strict=True)
    _validate_component_chain(script, final_regular=True, final_executable=True, required_uid=0)
    tools = {name: _resolved_trusted_tool(path)[0] for name, (path, _package) in TOOLS.items()}
    base_meta = _validate_component_chain(BUILD_BASE, final_regular=False, required_uid=0)
    if not stat.S_ISDIR(base_meta.st_mode):
        raise PreparationRefusal("recovery builder base is unavailable")
    attestation_meta = _validate_component_chain(
        attestation_path, final_regular=True, required_uid=0
    )
    if attestation_meta.st_gid != 0 or stat.S_IMODE(attestation_meta.st_mode) != 0o400:
        raise PreparationRefusal("builder attestation must remain private root:root mode 0400")
    try:
        attestation_fd = os.open(
            str(attestation_path),
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
    except OSError as exc:
        raise PreparationRefusal("builder attestation could not be opened safely") from exc
    if _identity(os.fstat(attestation_fd)) != _identity(attestation_meta):
        os.close(attestation_fd)
        raise PreparationRefusal("builder attestation changed while opening")

    preparation_root: Optional[Path] = None
    try:
        for _attempt in range(32):
            candidate = BUILD_BASE / ("secure-boot-prep." + secrets.token_hex(8))
            try:
                candidate.mkdir(mode=0o711)
            except FileExistsError:
                continue
            os.chmod(candidate, 0o711)
            preparation_root = candidate
            break
        if preparation_root is None:
            raise PreparationRefusal("fresh Secure Boot preparation directory could not be allocated")
        staging = preparation_root / "staging"
        staging.mkdir(mode=0o700)
        os.chown(staging, VALIDATION_UID, VALIDATION_GID)

        def worker_command(action: str) -> List[str]:
            return [
                str(tools["unshare"]),
                "--net",
                "--fork",
                "--kill-child=KILL",
                "--forward-signals",
                str(tools["setpriv"]),
                "--reuid={}".format(VALIDATION_UID),
                "--regid={}".format(VALIDATION_GID),
                "--clear-groups",
                "--no-new-privs",
                "--bounding-set=-all",
                "--inh-caps=-all",
                "--ambient-caps=-all",
                "--pdeathsig=KILL",
                "--",
                str(tools["python"]),
                "-I",
                "-S",
                "-B",
                str(script),
                action,
                "--attestation-fd",
                str(attestation_fd),
                "--attestation-path",
                str(attestation_path),
                "--staging",
                str(staging),
            ]

        output = _bounded_process(
            worker_command("_worker"),
            work=preparation_root,
            label="secure-boot-worker",
            timeout=WORKER_TIMEOUT_SECONDS,
            output_limit=MAX_WORKER_OUTPUT,
            pass_fds=(attestation_fd,),
            environment=_worker_environment(),
            artifact_limit=MAX_UKI_BYTES,
        )
        if output != b"Secure Boot preparation worker completed\n":
            raise PreparationRefusal("Secure Boot preparation worker returned unexpected output")
        if _identity(attestation_path.lstat()) != _identity(attestation_meta) or _identity(os.fstat(attestation_fd)) != _identity(attestation_meta):
            raise PreparationRefusal("builder attestation changed during Secure Boot preparation")
        _retire_validation_uid(tools)
        if _uid_has_processes(VALIDATION_UID):
            raise PreparationRefusal("Secure Boot validation process did not retire")

        entries = {entry.name: entry for entry in os.scandir(staging)}
        expected_names = {EVIDENCE_NAME} | {
            OUTPUT_NAMES[role] for role in PUBLIC_OUTPUT_ROLES
        }
        if set(entries) != expected_names:
            raise PreparationRefusal("Secure Boot worker output inventory is not exact")
        evidence_metadata = (staging / EVIDENCE_NAME).lstat()
        if (
            stat.S_ISLNK(evidence_metadata.st_mode)
            or not stat.S_ISREG(evidence_metadata.st_mode)
            or evidence_metadata.st_uid != VALIDATION_UID
            or evidence_metadata.st_gid != VALIDATION_GID
            or stat.S_IMODE(evidence_metadata.st_mode) != 0o400
        ):
            raise PreparationRefusal("Secure Boot worker evidence is unsafe")
        for role in PUBLIC_OUTPUT_ROLES:
            filename = OUTPUT_NAMES[role]
            path = staging / filename
            metadata = path.lstat()
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != VALIDATION_UID
                or metadata.st_gid != VALIDATION_GID
                or stat.S_IMODE(metadata.st_mode) != 0o444
            ):
                raise PreparationRefusal("Secure Boot worker produced an unsafe output")
            os.chown(path, 0, 0, follow_symlinks=False)
            os.chmod(path, 0o644, follow_symlinks=False)

        output = _bounded_process(
            worker_command("_receipt_worker"),
            work=preparation_root,
            label="secure-boot-receipt-worker",
            timeout=30,
            output_limit=MAX_WORKER_OUTPUT,
            pass_fds=(attestation_fd,),
            environment=_worker_environment(),
            artifact_limit=MAX_ATTESTATION_BYTES,
        )
        if output != b"Secure Boot preparation receipt completed\n":
            raise PreparationRefusal("Secure Boot receipt worker returned unexpected output")
        _retire_validation_uid(tools)
        if _uid_has_processes(VALIDATION_UID):
            raise PreparationRefusal("Secure Boot receipt process did not retire")
        if {entry.name for entry in os.scandir(staging)} != set(OUTPUT_NAMES.values()):
            raise PreparationRefusal("final Secure Boot output inventory is not exact")
        receipt_path = staging / OUTPUT_NAMES["receipt"]
        receipt_metadata = receipt_path.lstat()
        if (
            stat.S_ISLNK(receipt_metadata.st_mode)
            or not stat.S_ISREG(receipt_metadata.st_mode)
            or receipt_metadata.st_uid != VALIDATION_UID
            or receipt_metadata.st_gid != VALIDATION_GID
            or stat.S_IMODE(receipt_metadata.st_mode) != 0o400
        ):
            raise PreparationRefusal("final Secure Boot preparation receipt is unsafe")
        os.chown(receipt_path, 0, 0, follow_symlinks=False)
        os.chmod(receipt_path, 0o600, follow_symlinks=False)
        if _identity(attestation_path.lstat()) != _identity(attestation_meta) or _identity(os.fstat(attestation_fd)) != _identity(attestation_meta):
            raise PreparationRefusal("builder attestation changed during receipt finalization")
        os.chown(staging, 0, 0)
        os.chmod(staging, 0o755)
        artifacts = preparation_root / "artifacts"
        staging.rename(artifacts)
        return artifacts
    except BaseException:
        if preparation_root is not None:
            try:
                _retire_validation_uid(tools)
            except PreparationRefusal as exc:
                raise PreparationRefusal(
                    "Secure Boot validation processes could not be retired; "
                    "the fresh preparation directory was retained"
                ) from exc
            _cleanup_root(preparation_root)
        raise
    finally:
        os.close(attestation_fd)


def _worker_main(args: argparse.Namespace) -> int:
    try:
        _prepare_worker(
            attestation_fd=args.attestation_fd,
            attestation_path=Path(args.attestation_path),
            staging=Path(args.staging),
        )
    except PreparationRefusal as exc:
        print("Secure Boot preparation failed: {}".format(exc), file=sys.stderr)
        return 1
    print("Secure Boot preparation worker completed")
    return 0


def _receipt_worker_main(args: argparse.Namespace) -> int:
    try:
        _finalize_receipt_worker(
            attestation_fd=args.attestation_fd,
            attestation_path=Path(args.attestation_path),
            staging=Path(args.staging),
        )
    except PreparationRefusal as exc:
        print("Secure Boot preparation failed: {}".format(exc), file=sys.stderr)
        return 1
    print("Secure Boot preparation receipt completed")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command")
    for action in ("_worker", "_receipt_worker"):
        worker = subparsers.add_parser(action, help=argparse.SUPPRESS)
        worker.add_argument("--attestation-fd", type=int, required=True)
        worker.add_argument("--attestation-path", required=True)
        worker.add_argument("--staging", required=True)
    parser.add_argument("--attestation")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "_worker":
        return _worker_main(args)
    if args.command == "_receipt_worker":
        return _receipt_worker_main(args)
    if not args.attestation:
        print("--attestation is required", file=sys.stderr)
        return 2
    try:
        artifacts = _root_prepare(Path(args.attestation))
    except PreparationRefusal as exc:
        print("Secure Boot preparation failed: {}".format(exc), file=sys.stderr)
        return 1
    print("Secure Boot preparation artifacts: {}".format(artifacts))
    for role in ("secure_code", "enrolled_vars", "signed_uki", "signed_uki_sha256", "receipt"):
        print("{}: {}".format(role.replace("_", " ").title(), artifacts / OUTPUT_NAMES[role]))
    assignments = (
        ("SECURE_PREPARATION_RECEIPT", "receipt"),
        ("SIGNED_RECOVERY_UKI", "signed_uki"),
        ("PREPARED_SECURE_CODE", "secure_code"),
        ("PREPARED_ENROLLED_VARS", "enrolled_vars"),
    )
    for variable, role in assignments:
        print("{}='{}'".format(variable, artifacts / OUTPUT_NAMES[role]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
