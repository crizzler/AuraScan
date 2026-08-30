"""Bounded, no-follow reads of package metadata members through system bsdtar."""

import os
import selectors
import signal
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

from aurascan.core.config import MAX_SCRIPT_SIZE


PACKAGE_HOOK_RESOLVED = "resolved"
PACKAGE_HOOK_ABSENT = "absent"
PACKAGE_HOOK_UNINSPECTABLE = "uninspectable"
PACKAGE_IDENTITY_RESOLVED = "resolved"
PACKAGE_IDENTITY_UNINSPECTABLE = "uninspectable"
_BSDTAR = Path("/usr/bin/bsdtar")
_MAX_LISTING_BYTES = 5 * 1024 * 1024
_MAX_ERROR_BYTES = 4096
_ARCHIVE_TIMEOUT_SECONDS = 10
_MAX_IDENTITY_VALUE_BYTES = 1024
_TRUSTED_TOOL_ENV = {
    "PATH": "/usr/bin:/bin",
    "LANG": "C",
    "LC_ALL": "C",
}


@dataclass(frozen=True)
class PackageInstallHookCapture:
    status: str
    content: str = ""
    reason: str = ""

    @property
    def inspectable(self) -> bool:
        return self.status == PACKAGE_HOOK_RESOLVED


@dataclass(frozen=True)
class PackageIdentityCapture:
    status: str
    name: str = ""
    version: str = ""
    reason: str = ""

    @property
    def inspectable(self) -> bool:
        return self.status == PACKAGE_IDENTITY_RESOLVED


def capture_package_identity(
    package_path: Path,
    *,
    bsdtar_path: Path = _BSDTAR,
    timeout: int = _ARCHIVE_TIMEOUT_SECONDS,
) -> PackageIdentityCapture:
    """Capture the bounded package identity from a stable `.PKGINFO` member."""

    archive_fd = -1
    bsdtar_fd = -1
    try:
        try:
            archive_fd = _open_regular_nofollow(package_path)
            archive_before = os.fstat(archive_fd)
        except (OSError, ValueError):
            return PackageIdentityCapture(
                PACKAGE_IDENTITY_UNINSPECTABLE,
                reason="package_open_failed",
            )
        try:
            bsdtar_fd = _open_trusted_bsdtar(bsdtar_path)
            bsdtar_before = os.fstat(bsdtar_fd)
        except (OSError, ValueError):
            return PackageIdentityCapture(
                PACKAGE_IDENTITY_UNINSPECTABLE,
                reason="bsdtar_unavailable",
            )

        listing, _error, returncode, run_status = _run_bsdtar(
            archive_fd,
            bsdtar_fd,
            ("-tf",),
            _MAX_LISTING_BYTES,
            timeout,
        )
        if run_status != "ok" or returncode != 0:
            return PackageIdentityCapture(
                PACKAGE_IDENTITY_UNINSPECTABLE,
                reason="archive_listing_" + run_status,
            )
        try:
            names = listing.decode("utf-8", errors="strict").splitlines()
        except UnicodeDecodeError:
            return PackageIdentityCapture(
                PACKAGE_IDENTITY_UNINSPECTABLE,
                reason="invalid_member_name_encoding",
            )
        identity_names = [name for name in names if name in {".PKGINFO", "./.PKGINFO"}]
        if len(identity_names) != 1:
            reason = "missing_pkginfo" if not identity_names else "duplicate_pkginfo"
            return PackageIdentityCapture(PACKAGE_IDENTITY_UNINSPECTABLE, reason=reason)

        payload, _error, returncode, run_status = _run_bsdtar(
            archive_fd,
            bsdtar_fd,
            ("-xOf", identity_names[0]),
            MAX_SCRIPT_SIZE,
            timeout,
        )
        if run_status != "ok" or returncode != 0 or not payload:
            return PackageIdentityCapture(
                PACKAGE_IDENTITY_UNINSPECTABLE,
                reason="pkginfo_read_" + run_status,
            )
        if b"\x00" in payload:
            return PackageIdentityCapture(
                PACKAGE_IDENTITY_UNINSPECTABLE,
                reason="pkginfo_binary",
            )
        try:
            content = payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return PackageIdentityCapture(
                PACKAGE_IDENTITY_UNINSPECTABLE,
                reason="pkginfo_invalid_encoding",
            )
        identity = _parse_package_identity(content)
        if identity is None:
            return PackageIdentityCapture(
                PACKAGE_IDENTITY_UNINSPECTABLE,
                reason="pkginfo_identity_invalid",
            )
        result = PackageIdentityCapture(
            PACKAGE_IDENTITY_RESOLVED,
            name=identity[0],
            version=identity[1],
        )
        if not _capture_is_stable(
            package_path,
            archive_fd,
            archive_before,
            bsdtar_fd,
            bsdtar_before,
        ):
            return PackageIdentityCapture(
                PACKAGE_IDENTITY_UNINSPECTABLE,
                reason="package_replaced_during_read",
            )
        return result
    finally:
        if bsdtar_fd >= 0:
            os.close(bsdtar_fd)
        if archive_fd >= 0:
            os.close(archive_fd)


def capture_package_install_hook(
    package_path: Path,
    *,
    bsdtar_path: Path = _BSDTAR,
    timeout: int = _ARCHIVE_TIMEOUT_SECONDS,
) -> PackageInstallHookCapture:
    """Capture `.INSTALL` without following the package path or trusting names."""

    fd = -1
    bsdtar_fd = -1
    try:
        try:
            fd = _open_regular_nofollow(package_path)
            before = os.fstat(fd)
        except (OSError, ValueError):
            return PackageInstallHookCapture(
                PACKAGE_HOOK_UNINSPECTABLE,
                reason="package_open_failed",
            )
        try:
            bsdtar_fd = _open_trusted_bsdtar(bsdtar_path)
            bsdtar_before = os.fstat(bsdtar_fd)
        except (OSError, ValueError):
            return PackageInstallHookCapture(PACKAGE_HOOK_UNINSPECTABLE, reason="bsdtar_unavailable")

        listing, _error, returncode, run_status = _run_bsdtar(
            fd,
            bsdtar_fd,
            ("-tf",),
            _MAX_LISTING_BYTES,
            timeout,
        )
        if run_status != "ok" or returncode != 0:
            return PackageInstallHookCapture(
                PACKAGE_HOOK_UNINSPECTABLE,
                reason="archive_listing_" + run_status,
            )
        try:
            names = listing.decode("utf-8", errors="strict").splitlines()
        except UnicodeDecodeError:
            return PackageInstallHookCapture(PACKAGE_HOOK_UNINSPECTABLE, reason="invalid_member_name_encoding")
        hook_names = [name for name in names if name in {".INSTALL", "./.INSTALL"}]
        if not hook_names:
            result = PackageInstallHookCapture(PACKAGE_HOOK_ABSENT)
            if not _capture_is_stable(
                package_path,
                fd,
                before,
                bsdtar_fd,
                bsdtar_before,
            ):
                return PackageInstallHookCapture(
                    PACKAGE_HOOK_UNINSPECTABLE,
                    reason="package_replaced_during_read",
                )
            return result
        if len(hook_names) != 1:
            return PackageInstallHookCapture(PACKAGE_HOOK_UNINSPECTABLE, reason="duplicate_install_hook")

        payload, _error, returncode, run_status = _run_bsdtar(
            fd,
            bsdtar_fd,
            ("-xOf", hook_names[0]),
            MAX_SCRIPT_SIZE,
            timeout,
        )
        if run_status != "ok" or returncode != 0:
            return PackageInstallHookCapture(
                PACKAGE_HOOK_UNINSPECTABLE,
                reason="install_hook_read_" + run_status,
            )
        if b"\x00" in payload:
            return PackageInstallHookCapture(PACKAGE_HOOK_UNINSPECTABLE, reason="install_hook_binary")
        try:
            content = payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return PackageInstallHookCapture(PACKAGE_HOOK_UNINSPECTABLE, reason="install_hook_invalid_encoding")
        if not _capture_is_stable(
            package_path,
            fd,
            before,
            bsdtar_fd,
            bsdtar_before,
        ):
            return PackageInstallHookCapture(
                PACKAGE_HOOK_UNINSPECTABLE,
                reason="package_replaced_during_read",
            )
        return PackageInstallHookCapture(PACKAGE_HOOK_RESOLVED, content=content)
    finally:
        if bsdtar_fd >= 0:
            os.close(bsdtar_fd)
        if fd >= 0:
            os.close(fd)


def _capture_is_stable(
    package_path: Path,
    archive_fd: int,
    archive_before: os.stat_result,
    bsdtar_fd: int,
    bsdtar_before: os.stat_result,
) -> bool:
    reopened_fd = -1
    try:
        archive_after = os.fstat(archive_fd)
        bsdtar_after = os.fstat(bsdtar_fd)
        reopened_fd = _open_regular_nofollow(package_path)
        path_after = os.fstat(reopened_fd)
    except (OSError, ValueError):
        return False
    finally:
        if reopened_fd >= 0:
            os.close(reopened_fd)
    return bool(
        _stat_identity(archive_before) == _stat_identity(archive_after)
        and _stat_identity(archive_before) == _stat_identity(path_after)
        and _stat_identity(bsdtar_before) == _stat_identity(bsdtar_after)
    )


def _parse_package_identity(content: str) -> Optional[Tuple[str, str]]:
    values = {"pkgname": [], "pkgver": []}
    for line in content.splitlines():
        if "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        if key in values:
            values[key].append(value)
    if len(values["pkgname"]) != 1 or len(values["pkgver"]) != 1:
        return None
    name = values["pkgname"][0]
    version = values["pkgver"][0]
    if not _bounded_identity_value(name) or not _bounded_identity_value(version):
        return None
    return name, version


def _bounded_identity_value(value: str) -> bool:
    if not value or len(value.encode("utf-8")) > _MAX_IDENTITY_VALUE_BYTES:
        return False
    return all(
        0x21 <= ord(character) <= 0x7E and character not in {"/", "\\"}
        for character in value
    )


def _open_trusted_bsdtar(path: Path) -> int:
    if not path.is_absolute():
        raise ValueError("bsdtar path is not absolute")
    fd = _open_regular_nofollow(path, require_trusted_parents=True)
    try:
        metadata = os.fstat(fd)
        if (
            metadata.st_uid != 0
            or metadata.st_mode & 0o022
            or not metadata.st_mode & 0o111
        ):
            raise ValueError("bsdtar identity is not trusted")
        return fd
    except Exception:
        os.close(fd)
        raise


def _open_regular_nofollow(
    path: Path,
    *,
    require_trusted_parents: bool = False,
) -> int:
    value = os.fspath(path)
    candidate = Path(value)
    parts = list(candidate.parts)
    if not value or not parts or any(part == ".." for part in parts):
        raise ValueError("unsafe package path")

    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    file_flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    directory_fd = -1
    try:
        if candidate.is_absolute():
            directory_fd = os.open(candidate.anchor or os.sep, directory_flags)
            parts = parts[1:]
        else:
            directory_fd = os.open(".", directory_flags)
        if require_trusted_parents and not _trusted_directory_fd(directory_fd):
            raise ValueError("trusted tool parent directory is unsafe")
        if not parts or parts[-1] in {"", ".", ".."}:
            raise ValueError("package path has no file component")
        for part in parts[:-1]:
            if part in {"", ".", ".."}:
                raise ValueError("unsafe package path component")
            child_fd = os.open(part, directory_flags, dir_fd=directory_fd)
            os.close(directory_fd)
            directory_fd = child_fd
            if require_trusted_parents and not _trusted_directory_fd(directory_fd):
                raise ValueError("trusted tool parent directory is unsafe")
        source_fd = os.open(parts[-1], file_flags, dir_fd=directory_fd)
        try:
            metadata = os.fstat(source_fd)
        except OSError:
            os.close(source_fd)
            raise
        if not stat.S_ISREG(metadata.st_mode):
            os.close(source_fd)
            raise ValueError("package path is not a regular file")
        return source_fd
    finally:
        if directory_fd >= 0:
            os.close(directory_fd)


def _trusted_directory_fd(fd: int) -> bool:
    metadata = os.fstat(fd)
    return bool(
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == 0
        and not metadata.st_mode & 0o022
    )


def _stat_identity(metadata: os.stat_result) -> Tuple[int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        getattr(metadata, "st_mtime_ns", int(metadata.st_mtime * 1_000_000_000)),
        getattr(metadata, "st_ctime_ns", int(metadata.st_ctime * 1_000_000_000)),
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
    )


def _run_bsdtar(
    fd: int,
    bsdtar_fd: int,
    arguments: Tuple[str, ...],
    max_stdout: int,
    timeout: int,
) -> Tuple[bytes, bytes, int, str]:
    try:
        os.lseek(fd, 0, os.SEEK_SET)
        process = subprocess.Popen(
            [
                f"/proc/self/fd/{bsdtar_fd}",
                arguments[0],
                f"/proc/self/fd/{fd}",
                *arguments[1:],
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=(fd, bsdtar_fd),
            start_new_session=True,
            cwd=os.sep,
            env=_TRUSTED_TOOL_ENV,
        )
    except (OSError, ValueError):
        return b"", b"", 127, "failed"

    selector = selectors.DefaultSelector()
    stdout = bytearray()
    stderr = bytearray()
    streams = {}
    if process.stdout is not None:
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        streams[process.stdout.fileno()] = process.stdout
    if process.stderr is not None:
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        streams[process.stderr.fileno()] = process.stderr
    deadline = time.monotonic() + max(1, timeout)
    status = "ok"
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                status = "timeout"
                break
            for key, _events in selector.select(min(0.1, remaining)):
                try:
                    chunk = os.read(key.fd, 65536)
                except OSError:
                    chunk = b""
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.data == "stdout":
                    stdout.extend(chunk)
                    if len(stdout) > max_stdout:
                        status = "oversized"
                        break
                elif len(stderr) < _MAX_ERROR_BYTES:
                    stderr.extend(chunk[: _MAX_ERROR_BYTES - len(stderr)])
            if status != "ok":
                break
        if status != "ok":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                process.kill()
        try:
            returncode = process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            process.kill()
            returncode = process.wait()
            status = "timeout"
    finally:
        selector.close()
        for stream in streams.values():
            stream.close()
    if len(stdout) > max_stdout:
        stdout = stdout[:max_stdout]
    return bytes(stdout), bytes(stderr), int(returncode), status
