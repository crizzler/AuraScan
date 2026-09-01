#!/usr/bin/env python3
"""Strict recovery release-candidate and validation-UKI build helper.

This helper is invoked only by the root-owned recovery builder.  It never
downloads release inputs itself and it never signs or publishes an artifact.
"""

import argparse
import hashlib
import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import resource
from pathlib import Path


MANIFEST_SCHEMA = "aurascan_recovery_iso/2.0"
ATTESTATION_SCHEMA = "aurascan_recovery_validation_attestation/1.0"
MANIFEST_FIELDS = {
    "schema",
    "application_version",
    "release_disposition",
    "version",
    "architecture",
    "filename",
    "released_at",
    "url",
    "sha256",
    "status",
}
MAX_CONTROL_BYTES = 256 * 1024
MAX_MOUNT_SNAPSHOT_BYTES = 4 * 1024 * 1024
MAX_MOUNT_ENTRIES = 65536
MAX_UKI_BYTES = 512 * 1024 * 1024
MAX_NATIVE_OUTPUT_BYTES = 1024 * 1024
MAX_ATTESTATION_BYTES = 256 * 1024
ATTESTATION_FILE_LIMIT = 2 * 1024 * 1024 * 1024


class BuildRefusal(RuntimeError):
    """A deterministic release-builder precondition was not satisfied."""


def _read_regular(path: Path, *, limit: int = MAX_CONTROL_BYTES) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise BuildRefusal("required candidate file is unavailable") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise BuildRefusal("required candidate file is not a no-follow regular file")
    if before.st_size > limit:
        raise BuildRefusal("required candidate file exceeds its size limit")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(str(path), flags)
    except OSError as exc:
        raise BuildRefusal("required candidate file could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino, opened.st_size)
            != (before.st_dev, before.st_ino, before.st_size)
        ):
            raise BuildRefusal("required candidate file changed while opening")
        chunks = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                raise BuildRefusal("required candidate file ended while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
    finally:
        os.close(descriptor)
    try:
        after = path.lstat()
    except OSError as exc:
        raise BuildRefusal("required candidate file disappeared while reading") from exc
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise BuildRefusal("required candidate file changed while reading")
    return b"".join(chunks)


def _hash_regular(path: Path, *, limit: int) -> str:
    try:
        before = path.lstat()
    except OSError as exc:
        raise BuildRefusal("validation artifact is unavailable") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise BuildRefusal("validation artifact is not a no-follow regular file")
    if before.st_size > limit:
        raise BuildRefusal("validation artifact exceeds its size limit")
    descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    digest = hashlib.sha256()
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino, opened.st_size)
            != (before.st_dev, before.st_ino, before.st_size)
        ):
            raise BuildRefusal("validation artifact changed while opening")
        consumed = 0
        while consumed < before.st_size:
            chunk = os.read(descriptor, min(1024 * 1024, before.st_size - consumed))
            if not chunk:
                raise BuildRefusal("validation artifact ended while hashing")
            digest.update(chunk)
            consumed += len(chunk)
    finally:
        os.close(descriptor)
    after = path.lstat()
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise BuildRefusal("validation artifact changed while hashing")
    return digest.hexdigest()


def _root_safe_components(path: Path, *, include_final: bool) -> None:
    if not path.is_absolute() or Path(os.path.abspath(str(path))) != path:
        raise BuildRefusal("validation attestation path is not canonical and absolute")
    current = Path(path.parts[0])
    stop = len(path.parts) if include_final else len(path.parts) - 1
    for component in path.parts[1:stop]:
        current /= component
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise BuildRefusal("validation attestation path is unavailable") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise BuildRefusal("validation attestation path contains a symlink")
        if metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise BuildRefusal(
                "validation attestation path is not root-owned and non-writable"
            )
        if current != path and not stat.S_ISDIR(metadata.st_mode):
            raise BuildRefusal("validation attestation path component is not a directory")


def _attested_file(path: Path, *, limit: int = ATTESTATION_FILE_LIMIT):
    path = Path(os.path.abspath(str(path)))
    _root_safe_components(path, include_final=False)
    try:
        before = path.lstat()
    except OSError as exc:
        raise BuildRefusal("validation attestation input is unavailable") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise BuildRefusal("validation attestation input is not a no-follow regular file")
    if before.st_uid != 0 or before.st_mode & 0o022:
        raise BuildRefusal("validation attestation input is not root-owned and non-writable")
    if before.st_size < 1 or before.st_size >= limit:
        raise BuildRefusal("validation attestation input exceeds its bounded size")
    digest = _hash_regular(path, limit=limit)
    after = path.lstat()
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise BuildRefusal("validation attestation input changed while being recorded")
    return {
        "path": str(path),
        "sha256": digest,
        "size": before.st_size,
        "device": before.st_dev,
        "inode": before.st_ino,
        "mode": stat.S_IMODE(before.st_mode),
        "uid": before.st_uid,
        "gid": before.st_gid,
        "mtime_ns": before.st_mtime_ns,
        "ctime_ns": before.st_ctime_ns,
    }


def write_validation_attestation(
    snapshot: Path,
    iso: Path,
    validation_uki: Path,
    destination: Path,
    version: str,
    source_commit: str,
) -> None:
    """Write the immutable root-only base receipt used by smoke launchers."""

    if os.geteuid() != 0:
        raise BuildRefusal("validation attestation construction must run as root")
    if len(source_commit) != 40 or any(ch not in "0123456789abcdef" for ch in source_commit):
        raise BuildRefusal("validation attestation source commit is invalid")
    version_parts = version.split(".")
    if len(version_parts) != 3 or not all(part.isdigit() and part for part in version_parts):
        raise BuildRefusal("validation attestation version is invalid")
    snapshot = Path(os.path.abspath(str(snapshot)))
    iso = Path(os.path.abspath(str(iso)))
    validation_uki = Path(os.path.abspath(str(validation_uki)))
    destination = Path(os.path.abspath(str(destination)))
    roles = {
        "smoke_bootstrap": snapshot / "packaging/recovery/recovery-smoke-bootstrap.py",
        "smoke_launcher": snapshot / "packaging/recovery/recovery-smoke-launcher.py",
        "secure_boot_preparer": snapshot / "packaging/recovery/prepare-secure-boot.py",
        "qemu_iso_harness": snapshot / "packaging/recovery/qemu-smoke.sh",
        "qemu_uki_harness": snapshot / "packaging/recovery/qemu-uki-smoke.sh",
        "smoke_tool_guard": snapshot / "packaging/recovery/smoke-tool-guard.sh",
        "smoke_guard": snapshot / "packaging/recovery/smoke_guard.py",
        "smoke_marker_asset": (
            snapshot / "aurascan/assets/aurascan-recovery-smoke-marker.service"
        ),
        "smoke_marker_iso_profile": (
            snapshot
            / "packaging/recovery/archiso/airootfs/usr/lib/systemd/system/"
            "aurascan-recovery-smoke-marker.service"
        ),
        "smoke_marker_expanded_iso": (
            destination.parent
            / "x86_64/airootfs/usr/lib/systemd/system/"
            "aurascan-recovery-smoke-marker.service"
        ),
        "smoke_marker_validation_uki_overlay": (
            destination.parent
            / "validation-uki/overlay/usr/lib/systemd/system/"
            "aurascan-recovery-smoke-marker.service"
        ),
        "iso": iso,
        "iso_sha256": Path(str(iso) + ".sha256"),
        "iso_packages": Path(str(iso) + ".packages.txt"),
        "validation_uki": validation_uki,
        "validation_uki_sha256": Path(str(validation_uki) + ".sha256"),
    }
    files = {role: _attested_file(path) for role, path in roles.items()}
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
        raise BuildRefusal("built ISO and local-UKI readiness marker units differ")
    receipt = {
        "schema": ATTESTATION_SCHEMA,
        "version": version,
        "source_commit": source_commit,
        "files": files,
        # Per-run launch receipts populate these strict extension maps with
        # root-attested OVMF/signed-image identities before dropping privilege.
        "firmware": {},
        "run_inputs": {},
        "run": None,
    }
    encoded = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )
    if len(encoded) >= MAX_ATTESTATION_BYTES:
        raise BuildRefusal("validation attestation exceeds its bounded size")
    _root_safe_components(destination.parent, include_final=True)
    if destination.exists() or destination.is_symlink():
        raise BuildRefusal("validation attestation destination must be absent")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(str(destination), flags, 0o400)
    try:
        view = memoryview(encoded)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise BuildRefusal("validation attestation write was incomplete")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    written = _read_regular(destination, limit=MAX_ATTESTATION_BYTES)
    if written != encoded or stat.S_IMODE(destination.lstat().st_mode) != 0o400:
        raise BuildRefusal("validation attestation could not be verified after writing")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BuildRefusal("recovery ISO manifest contains duplicate keys")
        result[key] = value
    return result


def _unique_mount_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BuildRefusal("mount-table snapshot contains duplicate keys")
        result[key] = value
    return result


def _parse_mount_snapshot(raw: bytes, expanded_root: Path) -> None:
    """Prove that a complete, strict findmnt snapshot has no target below root."""

    if not raw or len(raw) > MAX_MOUNT_SNAPSHOT_BYTES:
        raise BuildRefusal("mount-table snapshot is empty or exceeds its size bound")
    expanded_root = Path(expanded_root)
    if (
        not expanded_root.is_absolute()
        or str(expanded_root).startswith("//")
        or expanded_root == Path("/")
        or Path(os.path.normpath(str(expanded_root))) != expanded_root
    ):
        raise BuildRefusal("expanded recovery root is not a canonical absolute path")
    try:
        document = json.loads(
            raw.decode("utf-8", "strict"), object_pairs_hook=_unique_mount_object
        )
    except BuildRefusal:
        raise
    except (TypeError, UnicodeError, ValueError) as exc:
        raise BuildRefusal("mount-table snapshot is not strict UTF-8 JSON") from exc
    if not isinstance(document, dict) or set(document) != {"filesystems"}:
        raise BuildRefusal("mount-table snapshot does not have the exact schema")
    filesystems = document["filesystems"]
    if (
        not isinstance(filesystems, list)
        or not filesystems
        or len(filesystems) > MAX_MOUNT_ENTRIES
    ):
        raise BuildRefusal("mount-table snapshot has an invalid entry count")

    saw_system_root = False
    root_text = str(expanded_root)
    descendant_prefix = root_text + "/"
    for row in filesystems:
        if not isinstance(row, dict) or set(row) != {"target"}:
            raise BuildRefusal("mount-table snapshot contains an invalid entry")
        target = row["target"]
        try:
            encoded_target = target.encode("utf-8", "strict") if isinstance(target, str) else b""
        except UnicodeError as exc:
            raise BuildRefusal("mount-table snapshot contains an unsafe target") from exc
        if (
            not isinstance(target, str)
            or not target
            or len(encoded_target) > 4096
            or not target.startswith("/")
            or target.startswith("//")
            or any(ord(character) < 32 or ord(character) == 127 for character in target)
            or os.path.normpath(target) != target
        ):
            raise BuildRefusal("mount-table snapshot contains an unsafe target")
        if target == "/":
            saw_system_root = True
        if target == root_text or target.startswith(descendant_prefix):
            raise BuildRefusal("Archiso left a live mount below the expanded root")
    if not saw_system_root:
        raise BuildRefusal("mount-table snapshot is incomplete")


def verify_no_mounts(snapshot: Path, expanded_root: Path) -> None:
    """Read and validate the root-owned mount snapshot captured by the builder."""

    if os.geteuid() != 0:
        raise BuildRefusal("mount-table verification must run as root")
    snapshot = Path(snapshot)
    expanded_root = Path(expanded_root)
    if (
        not snapshot.is_absolute()
        or str(snapshot).startswith("//")
        or Path(os.path.normpath(str(snapshot))) != snapshot
        or not expanded_root.is_absolute()
        or str(expanded_root).startswith("//")
        or Path(os.path.normpath(str(expanded_root))) != expanded_root
    ):
        raise BuildRefusal("mount-table verification paths are not canonical and absolute")
    _root_safe_components(snapshot, include_final=False)
    _root_safe_components(expanded_root, include_final=True)
    try:
        root_metadata = expanded_root.lstat()
    except OSError as exc:
        raise BuildRefusal("expanded recovery root is unavailable") from exc
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        raise BuildRefusal("expanded recovery root is not a no-follow directory")
    try:
        metadata = snapshot.lstat()
    except OSError as exc:
        raise BuildRefusal("mount-table snapshot is unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & 0o077
    ):
        raise BuildRefusal("mount-table snapshot is not a private root-owned regular file")
    raw = _read_regular(snapshot, limit=MAX_MOUNT_SNAPSHOT_BYTES)
    _parse_mount_snapshot(raw, expanded_root)


def validate_candidate(root: Path, version: str, released_at: str) -> None:
    expected_filename = "aurascan-recovery-{}-x86_64.iso".format(version)
    manifest_path = root / "aurascan/assets/aurascan-recovery-iso.json"
    pkgbuild_path = root / "packaging/arch/PKGBUILD"
    srcinfo_path = root / "packaging/arch/.SRCINFO"
    try:
        manifest_text = _read_regular(manifest_path).decode("utf-8", "strict")
        pkgbuild = _read_regular(pkgbuild_path).decode("utf-8", "strict")
        srcinfo = _read_regular(srcinfo_path).decode("utf-8", "strict")
    except UnicodeError as exc:
        raise BuildRefusal("candidate release control file is not strict UTF-8") from exc
    try:
        manifest = json.loads(manifest_text, object_pairs_hook=_unique_object)
    except BuildRefusal:
        raise
    except (TypeError, ValueError) as exc:
        raise BuildRefusal("recovery ISO manifest is invalid JSON") from exc
    expected_manifest = {
        "schema": MANIFEST_SCHEMA,
        "application_version": version,
        "release_disposition": "recovery-bearing",
        "version": version,
        "architecture": "x86_64",
        "filename": expected_filename,
        "released_at": released_at,
        "url": "",
        "sha256": "",
        "status": "build-required",
    }
    if not isinstance(manifest, dict) or set(manifest) != MANIFEST_FIELDS:
        raise BuildRefusal("recovery ISO manifest does not have the exact candidate schema")
    if manifest != expected_manifest:
        raise BuildRefusal(
            "recovery ISO manifest is not the exact recovery-bearing build-required candidate"
        )

    expected_pkg_lines = {
        "pkgver={}".format(version): 1,
        "pkgrel=1": 1,
        "sha256sums=('SKIP')": 1,
    }
    pkg_lines = pkgbuild.splitlines()
    for line, count in expected_pkg_lines.items():
        if pkg_lines.count(line) != count:
            raise BuildRefusal("PKGBUILD is not in the exact release-candidate state")
    if sum(1 for line in pkg_lines if line.startswith("pkgver=")) != 1:
        raise BuildRefusal("PKGBUILD has an ambiguous package version")
    if sum(1 for line in pkg_lines if line.startswith("pkgrel=")) != 1:
        raise BuildRefusal("PKGBUILD has an ambiguous package release")
    if sum(1 for line in pkg_lines if line.startswith("sha256sums=")) != 1:
        raise BuildRefusal("PKGBUILD has an ambiguous source checksum")

    srcinfo_lines = [line.strip() for line in srcinfo.splitlines()]
    for line in ("pkgver = {}".format(version), "pkgrel = 1", "sha256sums = SKIP"):
        if srcinfo_lines.count(line) != 1:
            raise BuildRefusal(".SRCINFO is not synchronized to the release candidate")


def _ensure_root_owned_tree(root: Path, *, reject_symlinks: bool = False) -> None:
    try:
        root_stat = root.lstat()
    except OSError as exc:
        raise BuildRefusal("validation UKI work directory is unavailable") from exc
    if not stat.S_ISDIR(root_stat.st_mode) or stat.S_ISLNK(root_stat.st_mode):
        raise BuildRefusal("validation UKI work path is not a no-follow directory")
    for directory, directory_names, filenames in os.walk(str(root), followlinks=False):
        current = Path(directory)
        entries = [current] + [current / item for item in directory_names + filenames]
        for entry in entries:
            metadata = entry.lstat()
            if reject_symlinks and stat.S_ISLNK(metadata.st_mode):
                raise BuildRefusal("exact candidate snapshot contains a symlink")
            if metadata.st_uid != 0:
                raise BuildRefusal("validation UKI input is not root-owned")
            if not stat.S_ISLNK(metadata.st_mode) and metadata.st_mode & 0o022:
                raise BuildRefusal("validation UKI input is group/world writable")


def _identity_markers(snapshot: Path, work: Path):
    values = {
        str(snapshot).encode("utf-8", "strict"),
        str(work).encode("utf-8", "strict"),
        b"AURASCAN_RECOVERY_BUILDER_IDENTITY_V1",
    }
    hostname = socket.gethostname().strip().encode("utf-8", "replace")
    if len(hostname) >= 4 and hostname not in {b"localhost", b"aurascan-recovery"}:
        values.add(hostname)
    try:
        machine_id = _read_regular(Path("/etc/machine-id"), limit=4096).strip()
    except BuildRefusal:
        machine_id = b""
    if len(machine_id) >= 8:
        values.add(machine_id)
    return tuple(sorted(value for value in values if len(value) >= 4))


def _bounded_tool_run(command, *, timeout: int, output_limit: int = MAX_NATIVE_OUTPUT_BYTES):
    if timeout < 1 or timeout > 300 or output_limit < 1024:
        raise BuildRefusal("native validation bound is invalid")

    def set_output_limit():
        resource.setrlimit(resource.RLIMIT_FSIZE, (output_limit + 1, output_limit + 1))

    with tempfile.TemporaryFile(mode="w+b") as output:
        try:
            process = subprocess.Popen(
                command,
                stdout=output,
                stderr=subprocess.STDOUT,
                close_fds=True,
                preexec_fn=set_output_limit,
            )
            try:
                returncode = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired as exc:
                process.kill()
                process.wait()
                raise BuildRefusal("trusted native UKI validation exceeded its runtime bound") from exc
        except OSError as exc:
            raise BuildRefusal("trusted native UKI validation could not start") from exc
        size = output.tell()
        if size > output_limit or returncode != 0:
            raise BuildRefusal("trusted native UKI validation failed or exceeded its output bound")
        output.seek(0)
        captured = output.read(output_limit + 1)
    return subprocess.CompletedProcess(
        command,
        returncode,
        stdout=captured.decode("utf-8", "replace"),
        stderr="",
    )


def build_validation_uki(
    snapshot: Path,
    work: Path,
    version: str,
    source_commit: str,
    source_date_epoch: str,
    mkosi: Path,
    ukify: Path,
) -> Path:
    if os.geteuid() != 0:
        raise BuildRefusal("validation UKI construction must run as root")
    if len(source_commit) != 40 or any(ch not in "0123456789abcdef" for ch in source_commit):
        raise BuildRefusal("validation UKI source commit is invalid")
    if not source_date_epoch.isdigit() or int(source_date_epoch) < 1:
        raise BuildRefusal("validation UKI source date is invalid")
    _ensure_root_owned_tree(snapshot, reject_symlinks=True)
    _ensure_root_owned_tree(work)
    for tool in (mkosi, ukify):
        metadata = tool.stat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0:
            raise BuildRefusal("validation UKI tool is not a root-owned regular file")
        if metadata.st_mode & 0o022 or not os.access(str(tool), os.X_OK):
            raise BuildRefusal("validation UKI tool has unsafe permissions")

    sys.dont_write_bytecode = True
    sys.path.insert(0, str(snapshot))
    from aurascan.core import recovery_boot, recovery_cli  # pylint: disable=import-outside-toplevel

    expected_cli = snapshot / "aurascan/core/recovery_cli.py"
    expected_boot = snapshot / "aurascan/core/recovery_boot.py"
    if Path(recovery_cli.__file__).resolve() != expected_cli.resolve():
        raise BuildRefusal("recovery overlay code did not load from the exact candidate")
    if Path(recovery_boot.__file__).resolve() != expected_boot.resolve():
        raise BuildRefusal("recovery image code did not load from the exact candidate")
    recovery_cli.recovery_version = lambda: version

    uki_root = work / "validation-uki"
    if uki_root.exists() or uki_root.is_symlink():
        raise BuildRefusal("validation UKI output must not pre-exist")
    uki_root.mkdir(mode=0o755)
    overlay = uki_root / "overlay"
    recovery_cli.create_recovery_overlay(overlay)
    issue = _read_regular(overlay / "etc/issue", limit=4096).decode("utf-8", "strict")
    if "AuraScan Recovery {}\n".format(version) not in issue:
        raise BuildRefusal("validation UKI overlay does not identify the exact candidate version")

    kernel_version, _pkgbase = recovery_boot.choose_recovery_kernel()
    if not kernel_version:
        raise BuildRefusal("no supported host kernel is available for validation UKI construction")
    _ensure_root_owned_tree(Path("/usr/lib/modules") / kernel_version)
    _ensure_root_owned_tree(Path("/usr/lib/firmware"))
    output = uki_root / "aurascan-recovery-{}-{}-validation-unsigned.efi".format(
        version, source_commit
    )
    profile = snapshot / "aurascan/assets/aurascan-recovery-mkosi.conf"
    command = recovery_boot.build_uki_command(
        output,
        kernel_version,
        mkosi=str(mkosi),
        profile_path=profile,
        extra_tree=overlay,
    )
    if command[0] != str(mkosi):
        raise BuildRefusal("validation UKI command did not retain the trusted mkosi identity")
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/root",
        "USER": "root",
        "LOGNAME": "root",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "SOURCE_DATE_EPOCH": source_date_epoch,
        "AURASCAN_AI_ENABLED": "0",
        "AURASCAN_INSTRUCTION_AI_ENABLED": "0",
        "AURASCAN_INCIDENT_AI_ENABLED": "0",
        "AURASCAN_RECOVERY_AI_ENABLED": "0",
    }
    try:
        built = subprocess.run(command, env=environment, timeout=3600, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise BuildRefusal("mkosi could not build the exact-candidate validation UKI") from exc
    if built.returncode != 0:
        raise BuildRefusal("mkosi failed while building the exact-candidate validation UKI")
    normalized, reason = recovery_cli._normalize_mkosi_output(output)
    if not normalized:
        raise BuildRefusal(reason)

    try:
        uki_size = output.lstat().st_size
    except OSError as exc:
        raise BuildRefusal("validation UKI is unavailable after mkosi") from exc
    if uki_size < 1 or uki_size >= MAX_UKI_BYTES:
        raise BuildRefusal("validation UKI is outside the smoke-test size boundary")

    trusted_which = lambda name: str(ukify) if name == "ukify" else None
    native_calls = []

    def bounded_runner(command, **kwargs):
        del kwargs
        if list(command[:2]) != [str(ukify), "inspect"] or len(command) != 3:
            raise BuildRefusal("recovery image validation requested an unexpected native tool")
        result = _bounded_tool_run(command, timeout=60)
        native_calls.append(result)
        return result

    valid, errors = recovery_boot.validate_recovery_image(
        output,
        runner=bounded_runner,
        which=trusted_which,
        expected_kernel_version=kernel_version,
        forbidden_markers=_identity_markers(snapshot, work),
    )
    if not valid:
        raise BuildRefusal("validation UKI failed deterministic image validation: {}".format("; ".join(errors)))
    if len(native_calls) != 1:
        raise BuildRefusal("validation UKI did not receive exactly one bounded ukify inspection")
    inspection = native_calls[0].stdout
    if kernel_version not in inspection:
        raise BuildRefusal("ukify did not report the selected validation kernel")
    if "systemd.wants=aurascan-recovery.service" not in inspection:
        raise BuildRefusal("ukify did not report the recovery service boot request")

    digest = _hash_regular(output, limit=4 * 1024 * 1024 * 1024)
    sidecar = Path(str(output) + ".sha256")
    sidecar.write_text("{}  {}\n".format(digest, output.name), encoding="ascii")
    os.chmod(output, 0o644)
    os.chmod(sidecar, 0o644)
    _ensure_root_owned_tree(uki_root)
    return output


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    candidate = subparsers.add_parser("validate-candidate")
    candidate.add_argument("--root", type=Path, required=True)
    candidate.add_argument("--version", required=True)
    candidate.add_argument("--released-at", required=True)
    uki = subparsers.add_parser("build-validation-uki")
    uki.add_argument("--snapshot", type=Path, required=True)
    uki.add_argument("--work", type=Path, required=True)
    uki.add_argument("--version", required=True)
    uki.add_argument("--source-commit", required=True)
    uki.add_argument("--source-date-epoch", required=True)
    uki.add_argument("--mkosi", type=Path, required=True)
    uki.add_argument("--ukify", type=Path, required=True)
    attestation = subparsers.add_parser("write-validation-attestation")
    attestation.add_argument("--snapshot", type=Path, required=True)
    attestation.add_argument("--iso", type=Path, required=True)
    attestation.add_argument("--validation-uki", type=Path, required=True)
    attestation.add_argument("--destination", type=Path, required=True)
    attestation.add_argument("--version", required=True)
    attestation.add_argument("--source-commit", required=True)
    mounts = subparsers.add_parser("verify-no-mounts")
    mounts.add_argument("--snapshot", type=Path, required=True)
    mounts.add_argument("--root", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "validate-candidate":
            validate_candidate(args.root, args.version, args.released_at)
            print("Validated exact recovery-bearing build-required candidate {}".format(args.version))
        elif args.command == "build-validation-uki":
            output = build_validation_uki(
                args.snapshot,
                args.work,
                args.version,
                args.source_commit,
                args.source_date_epoch,
                args.mkosi,
                args.ukify,
            )
            digest = _hash_regular(output, limit=4 * 1024 * 1024 * 1024)
            print("Validation UKI: {}".format(output))
            print("Validation UKI SHA-256: {}".format(digest))
        elif args.command == "write-validation-attestation":
            write_validation_attestation(
                args.snapshot,
                args.iso,
                args.validation_uki,
                args.destination,
                args.version,
                args.source_commit,
            )
            print("Validation attestation: {}".format(args.destination))
        else:
            verify_no_mounts(args.snapshot, args.root)
            print("Verified that the expanded recovery root has no live mounts")
        return 0
    except (BuildRefusal, OSError, ValueError) as exc:
        print("Recovery build refused: {}".format(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
