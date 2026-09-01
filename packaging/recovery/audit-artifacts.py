#!/usr/bin/env python3
"""Fail-closed release checks for AuraScan recovery image artifacts.

The auditor never extracts or executes image content.  It validates the three
release files, scans regular files with bounded no-follow reads, and can inspect
a root-created tar stream of the expanded Archiso filesystem without running
repository code as root.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import os
import re
import stat
import sys
import tarfile
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Dict, Iterable, List, Optional, Sequence, Tuple


GITHUB_RELEASE_ASSET_LIMIT = 2 * 1024 * 1024 * 1024
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_SCAN_ENTRIES = 750_000
MAX_SCAN_BYTES = 48 * 1024 * 1024 * 1024
MAX_FILE_BYTES = 4 * 1024 * 1024 * 1024
MAX_SYMLINK_TARGET_BYTES = 4096
READ_CHUNK_BYTES = 1024 * 1024
CAPTURE_BYTES = 4096
MAX_MARKERS = 64
MIN_MARKER_BYTES = 8
MAX_METADATA_FIELD_BYTES = 256 * 1024
MAX_PAX_HEADERS_PER_ENTRY = 256
RECOVERY_HOSTNAME = b"aurascan-recovery\n"
MACHINE_ID_FIRST_BOOT = b"uninitialized\n"

_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
_SIDECAR_RE = re.compile(
    r"^(?P<digest>[0-9a-f]{64})  (?P<name>aurascan-recovery-[0-9]+\.[0-9]+\.[0-9]+-x86_64\.iso)\n$"
)
_SECRET_ENV_NAMES = {
    "ANTHROPIC_API_KEY",
    "DEEPSEEK_API_KEY",
    "GEMINI_API_KEY",
    "GH_TOKEN",
    "GITHUB_TOKEN",
    "OPENAI_API_KEY",
    "OPENROUTER_API_KEY",
}
_SECRET_ENV_RE = re.compile(
    r"^(?:AURASCAN_.+(?:API_KEY|AUTH_KEY|PASSWORD|TOKEN)|"
    r"(?:AWS|AZURE|GOOGLE)_.+(?:KEY|PASSWORD|TOKEN))$"
)
_FIXED_CREDENTIAL_LABELS = (
    b"ANTHROPIC_API_KEY",
    b"AURASCAN_AI_KEY",
    b"AURASCAN_ANTHROPIC_API_KEY",
    b"AURASCAN_DEEPSEEK_API_KEY",
    b"AURASCAN_GEMINI_API_KEY",
    b"AURASCAN_LOCAL_AI_API_KEY",
    b"AURASCAN_OPENAI_API_KEY",
    b"AURASCAN_OPENROUTER_API_KEY",
    b"DEEPSEEK_API_KEY",
    b"GEMINI_API_KEY",
    b"OPENAI_API_KEY",
    b"OPENROUTER_API_KEY",
)
_FIXED_CREDENTIAL_VALUE_MARKERS = (
    b"AIzaSy",
    b"github_pat_",
    b"sk-ant-api",
    b"sk-proj-",
)
_CREDENTIAL_ASSIGNMENT_RE = re.compile(
    rb"(?<![A-Z0-9_])(?:"
    + b"|".join(re.escape(label) for label in _FIXED_CREDENTIAL_LABELS)
    + rb")[ \t]{0,16}=[ \t]{0,16}[\"']?[A-Za-z0-9_./+~:@%=-]{8,}"
)
_FIXED_CREDENTIAL_OVERLAP = max(len(label) for label in _FIXED_CREDENTIAL_LABELS) + 48
_LIBARCHIVE_BASE64_RE = re.compile(rb"[A-Za-z0-9+/]*={0,2}")


class AuditFailure(RuntimeError):
    """A release artifact failed a deterministic gate."""


class Bounds:
    def __init__(self) -> None:
        self.entries = 0
        self.bytes = 0

    def add_entry(self, size: int = 0) -> None:
        self.entries += 1
        if self.entries > MAX_SCAN_ENTRIES:
            raise AuditFailure("artifact audit entry limit exceeded")
        if size < 0 or size > MAX_FILE_BYTES:
            raise AuditFailure("artifact audit encountered an oversized file")
        self.bytes += size
        if self.bytes > MAX_SCAN_BYTES:
            raise AuditFailure("artifact audit byte limit exceeded")


def _contains_private_material(content: bytes, markers: Sequence[bytes]) -> bool:
    return (
        any(marker in content for marker in markers)
        or any(marker in content for marker in _FIXED_CREDENTIAL_VALUE_MARKERS)
        or _CREDENTIAL_ASSIGNMENT_RE.search(content) is not None
    )


def _regular_file(path: Path, label: str) -> os.stat_result:
    try:
        before = path.lstat()
    except OSError as exc:
        raise AuditFailure(f"{label} is unavailable") from exc
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise AuditFailure(f"{label} is not a no-follow regular file")
    return before


def _read_small_regular(path: Path, label: str, limit: int) -> bytes:
    before = _regular_file(path, label)
    if before.st_size > limit:
        raise AuditFailure(f"{label} exceeds its size limit")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(str(path), flags)
    except OSError as exc:
        raise AuditFailure(f"{label} could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise AuditFailure(f"{label} changed type while opening")
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise AuditFailure(f"{label} was replaced while opening")
        data = b""
        while len(data) <= limit:
            chunk = os.read(descriptor, min(READ_CHUNK_BYTES, limit + 1 - len(data)))
            if not chunk:
                break
            data += chunk
    finally:
        os.close(descriptor)
    try:
        after = path.lstat()
    except OSError as exc:
        raise AuditFailure(f"{label} disappeared while reading") from exc
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if identity_before != identity_after or len(data) != before.st_size:
        raise AuditFailure(f"{label} changed while reading")
    if len(data) > limit:
        raise AuditFailure(f"{label} exceeds its size limit")
    return data


def _scan_stream(
    stream: BinaryIO,
    size: int,
    markers: Sequence[bytes],
    *,
    digest: bool = False,
) -> Tuple[Optional[str], bytes, bool]:
    remaining = size
    overlap = max(
        max((len(value) for value in markers), default=1),
        max(len(value) for value in _FIXED_CREDENTIAL_VALUE_MARKERS),
        _FIXED_CREDENTIAL_OVERLAP,
    ) - 1
    previous = b""
    hasher = hashlib.sha256() if digest else None
    captured = bytearray()
    has_non_whitespace = False
    while remaining:
        chunk = stream.read(min(READ_CHUNK_BYTES, remaining))
        if not chunk:
            raise AuditFailure("artifact content ended before its declared size")
        remaining -= len(chunk)
        if hasher is not None:
            hasher.update(chunk)
        if not has_non_whitespace and chunk.strip(b"\x00\r\n\t "):
            has_non_whitespace = True
        combined = previous + chunk
        if _contains_private_material(combined, markers):
            raise AuditFailure("private build or credential material was found in an artifact")
        if len(captured) < CAPTURE_BYTES:
            captured.extend(chunk[: CAPTURE_BYTES - len(captured)])
        previous = combined[-overlap:] if overlap else b""
    return (
        hasher.hexdigest() if hasher is not None else None,
        bytes(captured),
        has_non_whitespace,
    )


def _scan_link_target(target: bytes, markers: Sequence[bytes], bounds: Bounds) -> None:
    if len(target) > MAX_SYMLINK_TARGET_BYTES:
        raise AuditFailure("artifact audit encountered an oversized symlink target")
    bounds.bytes += len(target)
    if bounds.bytes > MAX_SCAN_BYTES:
        raise AuditFailure("artifact audit byte limit exceeded")
    if _contains_private_material(target, markers):
        raise AuditFailure("private build or credential material was found in artifact metadata")


def _metadata_bytes(value: str) -> bytes:
    if not isinstance(value, str):
        raise AuditFailure("artifact metadata is not bounded text")
    try:
        encoded = value.encode("utf-8", errors="surrogateescape")
    except UnicodeError as exc:
        raise AuditFailure("artifact metadata is not bounded text") from exc
    if len(encoded) > MAX_METADATA_FIELD_BYTES:
        raise AuditFailure("artifact metadata exceeds its size limit")
    return encoded


def _scan_metadata_bytes(
    content: bytes, markers: Sequence[bytes], bounds: Bounds
) -> None:
    if len(content) > MAX_METADATA_FIELD_BYTES:
        raise AuditFailure("artifact metadata exceeds its size limit")
    bounds.bytes += len(content)
    if bounds.bytes > MAX_SCAN_BYTES:
        raise AuditFailure("artifact audit byte limit exceeded")
    if _contains_private_material(content, markers):
        raise AuditFailure(
            "private build or credential material was found in artifact metadata"
        )


def _scan_tar_metadata(member, markers: Sequence[bytes], bounds: Bounds) -> None:
    for value in (member.name, member.uname, member.gname):
        if value:
            _scan_metadata_bytes(_metadata_bytes(value), markers, bounds)
    headers = member.pax_headers
    if not isinstance(headers, dict) or len(headers) > MAX_PAX_HEADERS_PER_ENTRY:
        raise AuditFailure("expanded-root PAX metadata is malformed or excessive")
    for key, value in sorted(headers.items()):
        key_bytes = _metadata_bytes(key)
        value_bytes = _metadata_bytes(value)
        combined = key_bytes + b"=" + value_bytes
        if len(combined) > MAX_METADATA_FIELD_BYTES:
            raise AuditFailure("artifact metadata exceeds its size limit")
        _scan_metadata_bytes(combined, markers, bounds)
        if key.startswith("LIBARCHIVE.xattr."):
            if (
                _LIBARCHIVE_BASE64_RE.fullmatch(value_bytes) is None
                or len(value_bytes) % 4 == 1
                or (b"=" in value_bytes and len(value_bytes) % 4 != 0)
            ):
                raise AuditFailure(
                    "expanded-root libarchive xattr metadata is malformed"
                )
            padded = value_bytes + b"=" * ((-len(value_bytes)) % 4)
            try:
                decoded = base64.b64decode(padded, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise AuditFailure(
                    "expanded-root libarchive xattr metadata is malformed"
                ) from exc
            _scan_metadata_bytes(decoded, markers, bounds)


def _open_and_scan_regular(
    path: Path,
    markers: Sequence[bytes],
    bounds: Bounds,
    *,
    digest: bool = False,
) -> Tuple[Optional[str], bytes, bool]:
    before = _regular_file(path, "artifact file")
    bounds.add_entry(before.st_size)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(str(path), flags)
    except OSError as exc:
        raise AuditFailure("artifact file could not be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise AuditFailure("artifact file changed type while opening")
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
        ) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
        ):
            raise AuditFailure("artifact file was replaced while opening")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            result = _scan_stream(handle, before.st_size, markers, digest=digest)
    finally:
        os.close(descriptor)
    try:
        after = path.lstat()
    except OSError as exc:
        raise AuditFailure("artifact file disappeared while reading") from exc
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
        raise AuditFailure("artifact file changed while reading")
    return result


def _normalized_member_name(name: str) -> str:
    candidate = PurePosixPath(name)
    parts = tuple(part for part in candidate.parts if part not in ("", "."))
    if candidate.is_absolute() or any(part == ".." for part in parts):
        raise AuditFailure("expanded-root archive contains an unsafe member path")
    return "/".join(parts)


def _normalized_link_destination(member_name: str, linkname: str, *, hardlink: bool) -> str:
    if not isinstance(linkname, str) or not linkname or "\x00" in linkname:
        raise AuditFailure("expanded-root archive contains an unsafe link target")
    target = PurePosixPath(linkname)
    if hardlink and target.is_absolute():
        raise AuditFailure("expanded-root archive contains an unsafe link target")
    parts = (
        []
        if hardlink or target.is_absolute()
        else list(PurePosixPath(member_name).parent.parts)
    )
    for part in target.parts:
        if part in {"", ".", "/"}:
            continue
        if part == "..":
            if not parts:
                raise AuditFailure("expanded-root archive link target escapes its root")
            parts.pop()
            continue
        parts.append(part)
    if not parts:
        raise AuditFailure("expanded-root archive contains an unsafe link target")
    return "/".join(parts)


def _check_private_path(
    relative: str,
    has_non_whitespace: Optional[bool] = None,
    content: Optional[bytes] = None,
    *,
    validate_identity_value: bool = True,
) -> None:
    lower = relative.lower()
    private_exact = {
        "etc/aurascan/.env",
        "root/.bash_history",
        "root/.zsh_history",
        "root/.config/aurascan/.env",
    }
    if lower in private_exact:
        raise AuditFailure("expanded recovery root contains private runtime state")
    if lower.startswith("home/"):
        raise AuditFailure("expanded recovery root contains a populated home directory")
    if lower.startswith("root/.ssh/"):
        raise AuditFailure("expanded recovery root contains SSH identity material")
    if lower.startswith("etc/networkmanager/system-connections/"):
        raise AuditFailure("expanded recovery root contains a saved network profile")
    if lower.startswith("var/lib/iwd/") and lower.endswith((".psk", ".8021x")):
        raise AuditFailure("expanded recovery root contains a saved wireless profile")
    if lower == "etc/hostname" and validate_identity_value:
        if content != RECOVERY_HOSTNAME:
            raise AuditFailure("expanded recovery root contains persistent host identity")
        return
    if (
        lower == "etc/machine-id"
        and validate_identity_value
        and has_non_whitespace is not False
        and content != MACHINE_ID_FIRST_BOOT
    ):
        raise AuditFailure("expanded recovery root contains persistent host identity")


def _audit_tree(root: Path, markers: Sequence[bytes], bounds: Bounds) -> None:
    try:
        root_stat = root.lstat()
    except OSError as exc:
        raise AuditFailure("artifact scan root is unavailable") from exc
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        raise AuditFailure("artifact scan root is not a no-follow directory")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        directory_flags |= os.O_NOFOLLOW
    try:
        root_fd = os.open(str(root), directory_flags)
    except OSError as exc:
        raise AuditFailure("artifact scan root could not be opened safely") from exc
    pending = [(root_fd, "")]
    while pending:
        directory_fd, relative_directory = pending.pop()
        try:
            with os.scandir(directory_fd) as iterator:
                entries = sorted(iterator, key=lambda item: os.fsencode(item.name))
        except OSError as exc:
            os.close(directory_fd)
            raise AuditFailure("artifact scan root could not be traversed completely") from exc
        try:
            for entry in entries:
                bounds.add_entry()
                relative = f"{relative_directory}/{entry.name}".lstrip("/")
                _scan_metadata_bytes(os.fsencode(relative), markers, bounds)
                try:
                    item_stat = entry.stat(follow_symlinks=False)
                except OSError as exc:
                    raise AuditFailure("artifact entry could not be inspected") from exc
                if stat.S_ISDIR(item_stat.st_mode):
                    _check_private_path(relative)
                    try:
                        child_fd = os.open(entry.name, directory_flags, dir_fd=directory_fd)
                        child_stat = os.fstat(child_fd)
                    except OSError as exc:
                        raise AuditFailure("artifact directory changed during traversal") from exc
                    if (
                        not stat.S_ISDIR(child_stat.st_mode)
                        or (child_stat.st_dev, child_stat.st_ino)
                        != (item_stat.st_dev, item_stat.st_ino)
                    ):
                        os.close(child_fd)
                        raise AuditFailure("artifact directory was replaced during traversal")
                    pending.append((child_fd, relative))
                elif stat.S_ISREG(item_stat.st_mode):
                    if item_stat.st_size > MAX_FILE_BYTES:
                        raise AuditFailure("artifact audit encountered an oversized file")
                    bounds.bytes += item_stat.st_size
                    if bounds.bytes > MAX_SCAN_BYTES:
                        raise AuditFailure("artifact audit byte limit exceeded")
                    file_flags = os.O_RDONLY
                    if hasattr(os, "O_NOFOLLOW"):
                        file_flags |= os.O_NOFOLLOW
                    try:
                        descriptor = os.open(entry.name, file_flags, dir_fd=directory_fd)
                        opened = os.fstat(descriptor)
                    except OSError as exc:
                        raise AuditFailure("artifact file could not be opened safely") from exc
                    try:
                        if (
                            not stat.S_ISREG(opened.st_mode)
                            or (opened.st_dev, opened.st_ino, opened.st_size)
                            != (item_stat.st_dev, item_stat.st_ino, item_stat.st_size)
                        ):
                            raise AuditFailure("artifact file was replaced while opening")
                        with os.fdopen(descriptor, "rb", closefd=False) as handle:
                            _, captured, has_non_whitespace = _scan_stream(
                                handle, item_stat.st_size, markers
                            )
                        opened_after = os.fstat(descriptor)
                    finally:
                        os.close(descriptor)
                    try:
                        path_after = os.stat(
                            entry.name, dir_fd=directory_fd, follow_symlinks=False
                        )
                    except OSError as exc:
                        raise AuditFailure("artifact file disappeared while reading") from exc
                    identity_before = (
                        item_stat.st_dev,
                        item_stat.st_ino,
                        item_stat.st_size,
                        item_stat.st_mtime_ns,
                        item_stat.st_ctime_ns,
                    )
                    if identity_before != (
                        opened_after.st_dev,
                        opened_after.st_ino,
                        opened_after.st_size,
                        opened_after.st_mtime_ns,
                        opened_after.st_ctime_ns,
                    ) or identity_before != (
                        path_after.st_dev,
                        path_after.st_ino,
                        path_after.st_size,
                        path_after.st_mtime_ns,
                        path_after.st_ctime_ns,
                    ):
                        raise AuditFailure("artifact file changed while reading")
                    _check_private_path(relative, has_non_whitespace, captured)
                elif stat.S_ISLNK(item_stat.st_mode):
                    _check_private_path(relative)
                    if item_stat.st_size > MAX_SYMLINK_TARGET_BYTES:
                        raise AuditFailure(
                            "artifact audit encountered an oversized symlink target"
                        )
                    try:
                        target = os.readlink(
                            entry.name, dir_fd=directory_fd
                        ).encode(sys.getfilesystemencoding(), errors="surrogateescape")
                        path_after = os.stat(
                            entry.name, dir_fd=directory_fd, follow_symlinks=False
                        )
                    except (OSError, UnicodeError) as exc:
                        raise AuditFailure(
                            "artifact symlink changed while reading its target"
                        ) from exc
                    identity_before = (
                        item_stat.st_dev,
                        item_stat.st_ino,
                        item_stat.st_size,
                        item_stat.st_mtime_ns,
                        item_stat.st_ctime_ns,
                    )
                    if identity_before != (
                        path_after.st_dev,
                        path_after.st_ino,
                        path_after.st_size,
                        path_after.st_mtime_ns,
                        path_after.st_ctime_ns,
                    ) or len(target) != item_stat.st_size:
                        raise AuditFailure(
                            "artifact symlink changed while reading its target"
                        )
                    _scan_link_target(target, markers, bounds)
                    try:
                        target_text = target.decode(
                            sys.getfilesystemencoding(), errors="surrogateescape"
                        )
                    except UnicodeError as exc:
                        raise AuditFailure(
                            "artifact symlink target is not bounded text"
                        ) from exc
                    resolved_target = _normalized_link_destination(
                        relative, target_text, hardlink=False
                    )
                    # A link destination names a path but does not carry that
                    # target's bytes.  The target entry is audited separately;
                    # do not mistake the standard dbus -> /etc/machine-id link
                    # for a populated machine identity.  Path-only privacy
                    # controls (home, SSH, and saved network state) still apply.
                    _check_private_path(
                        resolved_target, validate_identity_value=False
                    )
                else:
                    raise AuditFailure(
                        "artifact scan root contains an unsupported special file type"
                    )
        finally:
            os.close(directory_fd)


def _audit_tar_stream(stream: BinaryIO, markers: Sequence[bytes], bounds: Bounds) -> None:
    try:
        with tarfile.open(fileobj=stream, mode="r|*") as archive:
            for member in archive:
                bounds.add_entry(member.size if member.isfile() else 0)
                relative = _normalized_member_name(member.name)
                _scan_tar_metadata(member, markers, bounds)
                if member.issym() or member.islnk():
                    _check_private_path(relative)
                    try:
                        target = member.linkname.encode(
                            "utf-8", errors="surrogateescape"
                        )
                    except UnicodeError as exc:
                        raise AuditFailure(
                            "expanded-root link target is not bounded text"
                        ) from exc
                    _scan_link_target(target, markers, bounds)
                    target_relative = _normalized_link_destination(
                        relative, member.linkname, hardlink=member.islnk()
                    )
                    _check_private_path(
                        target_relative, validate_identity_value=False
                    )
                    continue
                if member.isdir():
                    _check_private_path(relative)
                    continue
                if not member.isfile():
                    raise AuditFailure(
                        "expanded-root archive contains an unsupported special file type"
                    )
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise AuditFailure("expanded-root member could not be read")
                _, captured, has_non_whitespace = _scan_stream(
                    extracted, member.size, markers
                )
                _check_private_path(relative, has_non_whitespace, captured)
    except (tarfile.TarError, OSError, EOFError) as exc:
        raise AuditFailure("expanded-root archive stream is invalid or incomplete") from exc


def _marker_values(
    explicit: Iterable[str],
    *,
    identity_paths: Sequence[Path] = (Path("/etc/hostname"), Path("/etc/machine-id")),
) -> Tuple[bytes, ...]:
    values: List[bytes] = []
    candidates: List[Tuple[str, str]] = [
        ("explicit private", value) for value in explicit
    ]
    for name, value in os.environ.items():
        if name in _SECRET_ENV_NAMES or _SECRET_ENV_RE.fullmatch(name):
            candidates.append(("sensitive environment", value))
    for identity_path in identity_paths:
        try:
            identity_path.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise AuditFailure("host identity marker could not be inspected") from exc
        try:
            identity = _read_small_regular(
                identity_path, "host identity marker", 4096
            ).decode("utf-8", errors="strict").strip()
        except UnicodeError as exc:
            raise AuditFailure("host identity marker is not bounded UTF-8 text") from exc
        if identity_path.name == "hostname" and identity == RECOVERY_HOSTNAME.decode(
            "ascii"
        ).strip():
            continue
        if identity_path.name == "machine-id" and identity == MACHINE_ID_FIRST_BOOT.decode(
            "ascii"
        ).strip():
            continue
        candidates.append(("host identity", identity))
    seen = set()
    for source, candidate in candidates:
        if not candidate:
            if source == "explicit private":
                raise AuditFailure("an explicit private marker was empty")
            continue
        encoded = os.fsencode(candidate)
        if len(encoded) < MIN_MARKER_BYTES:
            article = "an" if source == "explicit private" else "a"
            raise AuditFailure(
                "{} {} marker is too short for an unambiguous artifact audit".format(
                    article, source
                )
            )
        if encoded in seen:
            continue
        seen.add(encoded)
        values.append(encoded)
        if len(values) > MAX_MARKERS:
            raise AuditFailure("too many private markers were supplied to the artifact audit")
    return tuple(values)


def audit(args: argparse.Namespace) -> str:
    if not _VERSION_RE.fullmatch(args.version):
        raise AuditFailure("release version is invalid")
    iso = Path(args.iso)
    expected_name = f"aurascan-recovery-{args.version}-x86_64.iso"
    if iso.name != expected_name:
        raise AuditFailure("recovery ISO does not have the exact release filename")
    iso_stat = _regular_file(iso, "recovery ISO")
    if iso_stat.st_size >= GITHUB_RELEASE_ASSET_LIMIT:
        raise AuditFailure("recovery ISO is not strictly smaller than the 2 GiB release limit")

    markers = _marker_values(args.forbid)
    bounds = Bounds()
    digest, _, _ = _open_and_scan_regular(iso, markers, bounds, digest=True)
    assert digest is not None

    sidecar = Path(str(iso) + ".sha256")
    sidecar_text = _read_small_regular(sidecar, "ISO checksum sidecar", 256).decode(
        "ascii", errors="strict"
    )
    match = _SIDECAR_RE.fullmatch(sidecar_text)
    if match is None or match.group("name") != expected_name or match.group("digest") != digest:
        raise AuditFailure("ISO checksum sidecar does not bind the exact release image")

    manifest = Path(str(iso) + ".packages.txt")
    manifest_bytes = _read_small_regular(
        manifest, "ISO package manifest", MAX_MANIFEST_BYTES
    )
    try:
        manifest_text = manifest_bytes.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise AuditFailure("ISO package manifest is not UTF-8 text") from exc
    if not manifest_text.endswith("\n"):
        raise AuditFailure("ISO package manifest must end with a newline")
    lines = manifest_text.splitlines()
    if not lines or any(not line.strip() for line in lines):
        raise AuditFailure("ISO package manifest is empty or contains blank entries")
    if lines != sorted(set(lines), key=lambda line: line.encode("utf-8")):
        raise AuditFailure("ISO package manifest is not bytewise sorted and unique")

    for tree in args.scan_root:
        _audit_tree(Path(tree), markers, bounds)
    if args.tar_stream:
        _audit_tar_stream(sys.stdin.buffer, markers, bounds)
    return digest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iso", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--scan-root", action="append", default=[])
    parser.add_argument("--forbid", action="append", default=[])
    parser.add_argument(
        "--tar-stream",
        action="store_true",
        help="also audit a no-follow expanded-root tar stream from standard input",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        digest = audit(args)
    except (AuditFailure, UnicodeError) as exc:
        print(f"Recovery artifact audit failed: {exc}", file=sys.stderr)
        return 1
    print(f"Recovery artifact audit passed: sha256 {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
