import bz2
import gzip
import hashlib
import lzma
import os
import shutil
import stat
import struct
import tarfile
import tempfile
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, List, Optional, Tuple

from aurascan.core.models import Confidence, EvidenceQuality, Finding, Phase, Severity, Source

try:
    from compression import zstd as _zstd
except ImportError:  # Python 3.8-3.13 do not provide the optional stdlib decoder.
    _zstd = None


class SafeArchiveExtractor:
    def __init__(
        self,
        max_total_size: int = 100 * 1024 * 1024,
        max_files: int = 10000,
        max_depth: int = 2,
        max_archive_size: int = 128 * 1024 * 1024,
    ):
        self.max_total_size = max_total_size
        self.max_files = max_files
        self.max_depth = max_depth
        self.max_archive_size = max_archive_size

    def inspect(self, archive_path: str, phase: Phase = Phase.source_archive_scan, depth: int = 0) -> List[Finding]:
        snapshot, findings = self._capture_snapshot(archive_path, phase)
        if snapshot is None:
            return findings
        try:
            findings.extend(self._inspect_snapshot(snapshot.path, archive_path, phase, depth))
            if not self._snapshot_matches(snapshot):
                findings.append(self._input_unsafe_finding(archive_path, phase))
            return findings
        finally:
            shutil.rmtree(snapshot.directory, ignore_errors=True)

    def _inspect_snapshot(
        self,
        snapshot_path: Path,
        display_path: str,
        phase: Phase,
        depth: int,
    ) -> List[Finding]:
        findings: List[Finding] = []
        try:
            _validated_archive_kind(
                snapshot_path,
                self.max_files,
                self.max_total_size,
                self.max_archive_size,
            )
            entries = self._entries(str(snapshot_path))
            total_size = 0
            entry_count = 0
            try:
                for name, size, mode, kind, linkname in entries:
                    entry_count += 1
                    if entry_count > self.max_files:
                        findings.append(self._finding(
                            "ARCHIVE-TOO-MANY-FILES",
                            display_path,
                            phase,
                            Severity.HIGH,
                            "Archive contains more entries than the inspection limit.",
                            "Do not install until the complete archive can be inspected safely.",
                            True,
                            "archive entry limit exceeded",
                        ))
                        break
                    total_size += max(size, 0)
                    if total_size > self.max_total_size:
                        findings.append(self._finding(
                            "ARCHIVE-OVERSIZED",
                            display_path,
                            phase,
                            Severity.HIGH,
                            "Archive metadata exceeds the decompressed-size limit.",
                            "Do not install until the complete archive can be inspected safely.",
                            True,
                            "archive expansion limit exceeded",
                        ))
                        break
                    if self._unsafe_path(name):
                        findings.append(self._finding("ARCHIVE-PATH-TRAVERSAL", display_path, phase, Severity.CRITICAL, "Archive entry would escape extraction directory.", "Reject this archive.", True, name))
                    link_escapes = kind in {"symlink", "hardlink"} and (
                        self._unsafe_path(linkname) or self._link_escapes(name, linkname)
                    )
                    if kind == "symlink" and link_escapes:
                        findings.append(self._finding("ARCHIVE-SYMLINK-ESCAPE", display_path, phase, Severity.CRITICAL, "Archive symlink can escape extraction directory.", "Reject this archive.", True, f"{name} -> {linkname}"))
                    if kind == "hardlink" and link_escapes:
                        findings.append(self._finding("ARCHIVE-HARDLINK-ESCAPE", display_path, phase, Severity.CRITICAL, "Archive hardlink can escape extraction directory.", "Reject this archive.", True, f"{name} -> {linkname}"))
                    if kind in {"symlink", "hardlink"} and not link_escapes:
                        findings.append(self._finding(
                            "ARCHIVE-LINK-UNINSPECTED",
                            display_path,
                            phase,
                            Severity.HIGH,
                            "Archive contains a link entry AuraScan deliberately did not materialize for static inspection.",
                            "Do not install until the link target and build-time behavior have been inspected independently.",
                            True,
                            "archive link was not materialized",
                        ))
                    if kind == "special":
                        findings.append(self._finding(
                            "ARCHIVE-SPECIAL-FILE",
                            display_path,
                            phase,
                            Severity.HIGH,
                            "Archive contains a special device, FIFO, or unsupported entry type.",
                            "Do not extract this archive automatically; inspect its provenance and contents independently.",
                            True,
                            name,
                        ))
                    if self._is_nested_archive(name) and depth >= self.max_depth:
                        findings.append(self._finding("ARCHIVE-NESTED-DEPTH", display_path, phase, Severity.HIGH, "Nested archive depth limit exceeded.", "Inspect nested archive manually.", True, name))
                    if self._is_suspicious_file(name, mode):
                        findings.append(self._finding("ARCHIVE-SUSPICIOUS-FILE", display_path, phase, Severity.MEDIUM, "Archive contains a suspicious executable or hidden script.", "Review this file before trusting the source.", False, name))
            finally:
                close = getattr(entries, "close", None)
                if close is not None:
                    close()
        except _ArchiveLimitError as exc:
            if exc.kind == "files":
                return [self._finding(
                    "ARCHIVE-TOO-MANY-FILES",
                    display_path,
                    phase,
                    Severity.HIGH,
                    "Archive entries or extended-metadata records exceed the inspection limit.",
                    "Do not install until the complete archive can be inspected safely.",
                    True,
                    "archive entry limit exceeded before parser metadata allocation",
                )]
            return [self._finding(
                "ARCHIVE-OVERSIZED",
                display_path,
                phase,
                Severity.HIGH,
                "Archive payload or extended metadata exceeds the decompressed-size limit.",
                "Do not install until the complete archive can be inspected safely.",
                True,
                "archive byte limit exceeded before parser metadata allocation",
            )]
        except (
            OSError,
            EOFError,
            RuntimeError,
            NotImplementedError,
            tarfile.TarError,
            zipfile.BadZipFile,
            zlib.error,
            ValueError,
            _ArchiveContentError,
            _ArchiveInputError,
        ):
            return [self._finding(
                "ARCHIVE-UNSUPPORTED",
                display_path,
                phase,
                Severity.HIGH,
                "The declared source was not a supported archive, so deep-static inspection is incomplete.",
                "Do not build or install until this source can be inspected safely as its actual file type.",
                True,
                "declared source content was not inspected",
            )]
        return findings

    def extract(self, archive_path: str, target_dir: str = None, depth: int = 0) -> Tuple[Path, List[Finding]]:
        phase = Phase.source_archive_scan
        snapshot, findings = self._capture_snapshot(archive_path, phase)
        if snapshot is None:
            return Path(), findings
        staging: Optional[Path] = None
        try:
            findings.extend(self._inspect_snapshot(snapshot.path, archive_path, phase, depth))
            if not self._snapshot_matches(snapshot):
                findings.append(self._input_unsafe_finding(archive_path, phase))
            if any(f.blocks_installation for f in findings):
                return Path(), findings

            if target_dir is None:
                staging = Path(tempfile.mkdtemp(prefix="aurascan-extract-"))
            else:
                requested_target = Path(target_dir)
                requested_target.parent.mkdir(parents=True, exist_ok=True)
                staging = Path(tempfile.mkdtemp(
                    prefix=".aurascan-extract-",
                    dir=str(requested_target.parent),
                ))

            budget = _ExtractionBudget(self.max_files, self.max_total_size)
            archive_kind = _validated_archive_kind(
                snapshot.path,
                self.max_files,
                self.max_total_size,
                self.max_archive_size,
            )
            if archive_kind == "tar":
                with tarfile.open(str(snapshot.path), "r:*") as archive:
                    for member in archive:
                        budget.add_entry()
                        self._extract_tar_member(archive, member, staging, budget)
            elif archive_kind == "zip":
                with zipfile.ZipFile(str(snapshot.path)) as archive:
                    for info in archive.filelist:
                        budget.add_entry()
                        self._extract_zip_member(archive, info, staging, budget)
            else:
                raise _ArchiveContentError("unsupported archive format")

            if not self._snapshot_matches(snapshot):
                raise _ArchiveContentError("archive snapshot changed during extraction")

            if target_dir is None:
                target = staging
                staging = None
                return target, findings

            target = Path(target_dir)
            if target.exists() or target.is_symlink():
                metadata = target.lstat()
                if not stat.S_ISDIR(metadata.st_mode) or any(target.iterdir()):
                    findings.append(self._extraction_failed_finding(archive_path, phase))
                    return Path(), findings
                target.rmdir()
            os.replace(str(staging), str(target))
            staging = None
            return target, findings
        except _ArchiveLimitError as exc:
            rule_id = "ARCHIVE-TOO-MANY-FILES" if exc.kind == "files" else "ARCHIVE-OVERSIZED"
            explanation = (
                "Archive extraction exceeded the actual entry-count limit."
                if exc.kind == "files"
                else "Archive extraction exceeded the actual decompressed-byte limit."
            )
            findings.append(self._finding(
                rule_id,
                archive_path,
                phase,
                Severity.HIGH,
                explanation,
                "Do not install until the complete archive can be inspected within configured safety limits.",
                True,
                "actual extraction limit exceeded",
            ))
            return Path(), findings
        except (
            OSError,
            EOFError,
            RuntimeError,
            NotImplementedError,
            tarfile.TarError,
            zipfile.BadZipFile,
            zlib.error,
            ValueError,
            _ArchiveContentError,
            _ArchiveInputError,
        ):
            findings.append(self._extraction_failed_finding(archive_path, phase))
            return Path(), findings
        finally:
            if staging is not None:
                shutil.rmtree(staging, ignore_errors=True)
            shutil.rmtree(snapshot.directory, ignore_errors=True)

    def _capture_snapshot(
        self,
        archive_path: str,
        phase: Phase,
    ) -> Tuple[Optional["_ArchiveSnapshot"], List[Finding]]:
        snapshot_dir = Path(tempfile.mkdtemp(prefix="aurascan-archive-snapshot-"))
        snapshot_path = snapshot_dir / "archive.bin"
        source_fd = -1
        destination_fd = -1
        try:
            source_fd = _open_regular_nofollow(Path(archive_path), self.max_archive_size)
            before = os.fstat(source_fd)
            destination_fd = os.open(
                str(snapshot_path),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                0o600,
            )
            digest = hashlib.sha256()
            copied = 0
            while True:
                remaining = self.max_archive_size + 1 - copied
                chunk = os.read(source_fd, min(65536, remaining))
                if not chunk:
                    break
                copied += len(chunk)
                if copied > self.max_archive_size:
                    raise _ArchiveInputError("oversized")
                digest.update(chunk)
                _write_all(destination_fd, chunk)
            after = os.fstat(source_fd)
            if _stat_identity(before) != _stat_identity(after) or copied != after.st_size:
                raise _ArchiveInputError("changed")
            os.fchmod(destination_fd, 0o400)
            completed_fd = destination_fd
            destination_fd = -1
            os.close(completed_fd)
            metadata = snapshot_path.lstat()
            return _ArchiveSnapshot(
                snapshot_dir,
                snapshot_path,
                copied,
                digest.hexdigest(),
                _stat_identity(metadata),
            ), []
        except (OSError, _ArchiveInputError):
            shutil.rmtree(snapshot_dir, ignore_errors=True)
            return None, [self._input_unsafe_finding(archive_path, phase)]
        finally:
            if destination_fd >= 0:
                os.close(destination_fd)
            if source_fd >= 0:
                os.close(source_fd)

    def _snapshot_matches(self, snapshot: "_ArchiveSnapshot") -> bool:
        source_fd = -1
        try:
            source_fd = _open_regular_nofollow(snapshot.path, self.max_archive_size)
            before = os.fstat(source_fd)
            if _stat_identity(before) != snapshot.identity:
                return False
            digest = hashlib.sha256()
            size = 0
            while True:
                remaining = self.max_archive_size + 1 - size
                chunk = os.read(source_fd, min(65536, remaining))
                if not chunk:
                    break
                size += len(chunk)
                if size > self.max_archive_size:
                    return False
                digest.update(chunk)
            after = os.fstat(source_fd)
            return (
                _stat_identity(before) == _stat_identity(after)
                and size == snapshot.size
                and digest.hexdigest() == snapshot.sha256
            )
        except (OSError, _ArchiveInputError):
            return False
        finally:
            if source_fd >= 0:
                os.close(source_fd)

    def _input_unsafe_finding(self, archive_path: str, phase: Phase) -> Finding:
        return self._finding(
            "ARCHIVE-INPUT-UNSAFE",
            archive_path,
            phase,
            Severity.HIGH,
            "Archive input was missing, linked, non-regular, oversized, or changed while AuraScan captured it.",
            "Do not install until an unchanged regular archive can be inspected safely.",
            True,
            "archive input could not be bound to a stable snapshot",
        )

    def _extraction_failed_finding(self, archive_path: str, phase: Phase) -> Finding:
        return self._finding(
            "ARCHIVE-EXTRACTION-FAILED",
            archive_path,
            phase,
            Severity.HIGH,
            "Archive extraction did not complete safely, so deep-static inspection is incomplete.",
            "Do not build or install until the complete source archive can be inspected independently.",
            True,
            "transactional archive extraction failed closed",
        )

    def _entries(self, archive_path: str) -> Iterable[Tuple[str, int, int, str, str]]:
        archive_kind = _validated_archive_kind(
            Path(archive_path),
            self.max_files,
            self.max_total_size,
            self.max_archive_size,
        )
        if archive_kind == "tar":
            with tarfile.open(archive_path, "r:*") as archive:
                for member in archive:
                    kind = (
                        "symlink" if member.issym()
                        else "hardlink" if member.islnk()
                        else "dir" if member.isdir()
                        else "file" if member.isfile()
                        else "special"
                    )
                    yield member.name, member.size, member.mode, kind, member.linkname or ""
            return
        if archive_kind == "zip":
            with zipfile.ZipFile(archive_path) as archive:
                for info in archive.filelist:
                    mode = (info.external_attr >> 16) & 0o777777
                    file_type = stat.S_IFMT(mode)
                    kind = (
                        "dir" if info.is_dir()
                        else "symlink" if stat.S_ISLNK(mode)
                        else "special" if file_type and not stat.S_ISREG(mode)
                        else "file"
                    )
                    yield info.filename, info.file_size, mode, kind, ""
            return
        raise ValueError("Unsupported archive format.")

    def _extract_tar_member(
        self,
        archive: tarfile.TarFile,
        member: tarfile.TarInfo,
        target: Path,
        budget: "_ExtractionBudget",
    ) -> None:
        destination = self._safe_destination(target, member.name)
        if member.isdir():
            destination.mkdir(parents=True, exist_ok=True)
            return
        if member.issym() or member.islnk():
            return
        if not member.isfile():
            raise _ArchiveContentError("unsupported tar entry type")
        destination.parent.mkdir(parents=True, exist_ok=True)
        src = archive.extractfile(member)
        if src is None:
            raise _ArchiveContentError("tar member content unavailable")
        destination_fd = _open_new_output(destination)
        try:
            with src:
                copied = _copy_bounded(src, destination_fd, budget)
            if copied != member.size:
                raise _ArchiveContentError("tar member size did not match extracted bytes")
        finally:
            os.close(destination_fd)
        os.chmod(destination, member.mode & 0o777)

    def _extract_zip_member(
        self,
        archive: zipfile.ZipFile,
        info: zipfile.ZipInfo,
        target: Path,
        budget: "_ExtractionBudget",
    ) -> None:
        destination = self._safe_destination(target, info.filename)
        if info.is_dir():
            destination.mkdir(parents=True, exist_ok=True)
            return
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination_fd = _open_new_output(destination)
        try:
            with archive.open(info) as src:
                copied = _copy_bounded(src, destination_fd, budget)
            if copied != info.file_size:
                raise _ArchiveContentError("zip member size did not match extracted bytes")
        finally:
            os.close(destination_fd)

    def _safe_destination(self, target: Path, name: str) -> Path:
        destination = (target / name).resolve()
        target_resolved = target.resolve()
        if not str(destination).startswith(str(target_resolved) + os.sep) and destination != target_resolved:
            raise ValueError("Archive extraction would escape target directory.")
        return destination

    def _unsafe_path(self, name: str) -> bool:
        path = PurePosixPath(name)
        return path.is_absolute() or ".." in path.parts or name.startswith("\\")

    def _link_escapes(self, name: str, linkname: str) -> bool:
        if not linkname:
            return False
        base = PurePosixPath(name).parent
        normalized = PurePosixPath("/") / base / linkname
        return ".." in PurePosixPath(linkname).parts or PurePosixPath(linkname).is_absolute() or ".." in normalized.parts

    def _is_nested_archive(self, name: str) -> bool:
        return name.endswith((".tar", ".tar.gz", ".tgz", ".tar.xz", ".tar.zst", ".zip"))

    def _is_suspicious_file(self, name: str, mode: int) -> bool:
        basename = PurePosixPath(name).name
        executable = bool(mode & stat.S_IXUSR)
        hidden_script = basename.startswith(".") and basename.endswith((".sh", ".bash", ".py", ".pl"))
        return executable or hidden_script

    def _finding(self, rule_id: str, archive_path: str, phase: Phase, severity: Severity, explanation: str, recommendation: str, blocks: bool, evidence: str = "") -> Finding:
        return Finding(
            rule_id=rule_id,
            package_name="unknown",
            package_version="unknown",
            phase=phase,
            source=Source.deterministic_rule,
            severity=severity,
            confidence=Confidence.CONFIRMED if blocks else Confidence.HIGH,
            evidence_quality=EvidenceQuality.confirmed_static_pattern if blocks else EvidenceQuality.strong_heuristic,
            file_path=str(archive_path),
            explanation=explanation,
            recommendation=recommendation,
            blocks_installation=blocks,
            requires_manual_review=True,
            evidence_snippet=evidence,
        )


@dataclass(frozen=True)
class _ArchiveSnapshot:
    directory: Path
    path: Path
    size: int
    sha256: str
    identity: Tuple[int, int, int, int, int, int, int]


class _ArchiveInputError(Exception):
    pass


class _ArchiveContentError(Exception):
    pass


class _ArchiveLimitError(Exception):
    def __init__(self, kind: str):
        super().__init__(kind)
        self.kind = kind


@dataclass
class _ExtractionBudget:
    max_files: int
    max_bytes: int
    files: int = 0
    copied_bytes: int = 0

    def add_entry(self) -> None:
        self.files += 1
        if self.files > self.max_files:
            raise _ArchiveLimitError("files")

    def add_bytes(self, count: int) -> None:
        self.copied_bytes += count
        if self.copied_bytes > self.max_bytes:
            raise _ArchiveLimitError("bytes")


_TAR_BLOCK_SIZE = 512
_TAR_ZERO_BLOCK = b"\0" * _TAR_BLOCK_SIZE
_TAR_EXTENDED_TYPES = {b"g", b"x", b"K", b"L"}
_TAR_PAX_TYPES = {b"g", b"x"}
_TAR_UNSUPPORTED_SPARSE_TYPE = b"S"
_MAX_TAR_EXTENDED_METADATA_BYTES = 1024 * 1024


def _validated_archive_kind(
    path: Path,
    max_files: int,
    max_total_size: int,
    max_archive_size: int,
) -> str:
    """Validate bounded parser metadata before invoking ZipFile or TarFile."""

    if zipfile.is_zipfile(str(path)):
        _validate_zip_central_directory(path, max_files, max_archive_size)
        return "zip"
    _validate_tar_stream(path, max_files, max_total_size, max_archive_size)
    return "tar"


def _validate_tar_stream(
    path: Path,
    max_files: int,
    max_total_size: int,
    max_archive_size: int,
) -> None:
    """Stream over tar records without retaining attacker-sized metadata.

    ``tarfile`` consumes PAX and GNU long-name records while constructing the
    first ``TarInfo`` object.  Validate and charge those physical records
    before calling ``tarfile.open`` so a compressed metadata bomb cannot evade
    the extraction budget merely because the records are not yielded as files.
    """

    stream = None
    raw_stream = None
    entry_count = 0
    payload_bytes = 0
    metadata_bytes = 0
    pax_records = 0
    saw_header = False
    try:
        stream, raw_stream = _open_tar_payload_stream(path, max_archive_size)
        while True:
            header = _read_exact(stream, _TAR_BLOCK_SIZE)
            if not header:
                if saw_header:
                    return
                raise _ArchiveContentError("tar header was missing")
            if len(header) != _TAR_BLOCK_SIZE:
                raise _ArchiveContentError("tar header was truncated")
            if header == _TAR_ZERO_BLOCK:
                return
            if not _tar_header_checksum_valid(header):
                raise _ArchiveContentError("tar header checksum was invalid")

            saw_header = True
            entry_count += 1
            if entry_count > max_files:
                raise _ArchiveLimitError("files")
            size = _tar_number(header[124:136])
            if size < 0:
                raise _ArchiveContentError("tar entry size was negative")
            typeflag = header[156:157]
            if typeflag == _TAR_UNSUPPORTED_SPARSE_TYPE:
                raise _ArchiveContentError("GNU sparse tar metadata is unsupported")

            if typeflag in _TAR_EXTENDED_TYPES:
                metadata_bytes += size
                metadata_limit = min(max_total_size, _MAX_TAR_EXTENDED_METADATA_BYTES)
                if metadata_bytes > metadata_limit:
                    raise _ArchiveLimitError("bytes")
                metadata = _read_exact(stream, size)
                if len(metadata) != size:
                    raise _ArchiveContentError("tar extended metadata was truncated")
                if typeflag in _TAR_PAX_TYPES:
                    pax_records += _validate_pax_records(metadata)
                    if pax_records > max_files:
                        raise _ArchiveLimitError("files")
            else:
                payload_bytes += size
                if payload_bytes > max_total_size:
                    raise _ArchiveLimitError("bytes")
                _discard_exact(stream, size)

            padding = (-size) % _TAR_BLOCK_SIZE
            if padding:
                _discard_exact(stream, padding)
    except (_ArchiveContentError, _ArchiveLimitError):
        raise
    except Exception as exc:
        raise _ArchiveContentError("tar stream could not be decoded") from exc
    finally:
        if stream is not None and stream is not raw_stream:
            stream.close()
        if raw_stream is not None:
            raw_stream.close()


def _open_tar_payload_stream(path: Path, max_archive_size: int):
    source_fd = _open_regular_nofollow(path, max_archive_size)
    raw_stream = os.fdopen(source_fd, "rb")
    try:
        magic = raw_stream.read(6)
        raw_stream.seek(0)
        if magic.startswith(b"\x1f\x8b"):
            return gzip.GzipFile(fileobj=raw_stream, mode="rb"), raw_stream
        if magic.startswith(b"BZh"):
            return bz2.BZ2File(raw_stream, mode="rb"), raw_stream
        if magic.startswith(b"\xfd7zXZ\x00"):
            return lzma.LZMAFile(raw_stream, mode="rb"), raw_stream
        if magic.startswith(b"\x28\xb5\x2f\xfd"):
            if _zstd is None:
                raise _ArchiveContentError("zstd-compressed tar is unsupported by this Python runtime")
            return _zstd.ZstdFile(raw_stream, mode="rb"), raw_stream
        return raw_stream, raw_stream
    except Exception:
        raw_stream.close()
        raise


def _read_exact(stream, size: int) -> bytes:
    payload = bytearray()
    while len(payload) < size:
        chunk = stream.read(min(65536, size - len(payload)))
        if not chunk:
            break
        payload.extend(chunk)
    return bytes(payload)


def _discard_exact(stream, size: int) -> None:
    remaining = size
    while remaining:
        chunk = stream.read(min(65536, remaining))
        if not chunk:
            raise _ArchiveContentError("tar entry payload was truncated")
        remaining -= len(chunk)


def _tar_number(field: bytes) -> int:
    if not field:
        raise _ArchiveContentError("tar numeric field was missing")
    if field[0] == 0x80:
        return int.from_bytes(field[1:], byteorder="big", signed=False)
    if field[0] == 0xFF:
        return int.from_bytes(field[1:], byteorder="big", signed=False) - (256 ** (len(field) - 1))
    if field[0] & 0x80:
        raise _ArchiveContentError("tar base-256 field was invalid")
    stripped = field.rstrip(b"\0 ").lstrip(b" ")
    if not stripped:
        return 0
    if any(value < ord("0") or value > ord("7") for value in stripped):
        raise _ArchiveContentError("tar numeric field was invalid")
    return int(stripped, 8)


def _tar_header_checksum_valid(header: bytes) -> bool:
    expected = _tar_number(header[148:156])
    checksum_field_as_spaces = header[:148] + (b" " * 8) + header[156:]
    unsigned = sum(checksum_field_as_spaces)
    signed = sum(value if value < 128 else value - 256 for value in checksum_field_as_spaces)
    return expected in {unsigned, signed}


def _validate_pax_records(payload: bytes) -> int:
    offset = 0
    records = 0
    while offset < len(payload):
        separator = payload.find(b" ", offset)
        if separator < 0:
            raise _ArchiveContentError("PAX record length was missing")
        length_field = payload[offset:separator]
        if (
            not length_field
            or len(length_field) > len(str(len(payload))) + 1
            or not length_field.isdigit()
        ):
            raise _ArchiveContentError("PAX record length was invalid")
        record_length = int(length_field)
        record_end = offset + record_length
        if record_length <= separator - offset + 2 or record_end > len(payload):
            raise _ArchiveContentError("PAX record exceeded its metadata entry")
        record = payload[separator + 1:record_end]
        if not record.endswith(b"\n") or b"=" not in record[:-1]:
            raise _ArchiveContentError("PAX record syntax was invalid")
        key = record.split(b"=", 1)[0]
        if key == b"size" or key.startswith(b"GNU.sparse.") or key == b"SCHILY.realsize":
            raise _ArchiveContentError("structural or sparse PAX metadata is unsupported")
        records += 1
        offset = record_end
    return records


def _validate_zip_central_directory(path: Path, max_files: int, max_archive_size: int) -> None:
    """Count ZIP entries from bounded central-directory records before ZipFile allocates them."""

    source_fd = -1
    try:
        source_fd = _open_regular_nofollow(path, max_archive_size)
        size = os.fstat(source_fd).st_size
        tail_size = min(size, 22 + 65535)
        tail = os.pread(source_fd, tail_size, size - tail_size)
        eocd_index = tail.rfind(b"PK\x05\x06")
        if eocd_index < 0 or len(tail) - eocd_index < 22:
            raise _ArchiveContentError("ZIP end record missing")
        eocd_offset = size - tail_size + eocd_index
        (
            disk_number,
            central_disk,
            _disk_entries,
            declared_entries,
            central_size,
            central_offset,
            comment_size,
        ) = struct.unpack_from("<4H2LH", tail, eocd_index + 4)
        if eocd_index + 22 + comment_size != len(tail):
            raise _ArchiveContentError("ZIP comment exceeded input")
        if disk_number != 0 or central_disk != 0:
            raise _ArchiveContentError("multi-disk ZIP is unsupported")
        if declared_entries == 0xFFFF or central_size == 0xFFFFFFFF or central_offset == 0xFFFFFFFF:
            raise _ArchiveLimitError("files")
        if declared_entries > max_files:
            raise _ArchiveLimitError("files")

        concatenated_prefix = eocd_offset - central_size - central_offset
        actual_offset = central_offset + concatenated_prefix
        central_end = actual_offset + central_size
        if actual_offset < 0 or central_end != eocd_offset:
            raise _ArchiveContentError("ZIP central-directory bounds were invalid")

        cursor = actual_offset
        counted = 0
        while cursor < central_end:
            signature = os.pread(source_fd, 4, cursor)
            if signature == b"PK\x01\x02":
                header = os.pread(source_fd, 46, cursor)
                if len(header) != 46:
                    raise _ArchiveContentError("ZIP central header was truncated")
                name_size, extra_size, entry_comment_size = struct.unpack_from("<3H", header, 28)
                cursor += 46 + name_size + extra_size + entry_comment_size
                counted += 1
                if counted > max_files:
                    raise _ArchiveLimitError("files")
                continue
            if signature == b"PK\x05\x05":
                header = os.pread(source_fd, 6, cursor)
                if len(header) != 6:
                    raise _ArchiveContentError("ZIP central signature was truncated")
                signature_size = struct.unpack_from("<H", header, 4)[0]
                cursor += 6 + signature_size
                continue
            raise _ArchiveContentError("ZIP central-directory record was invalid")
        if cursor != central_end or counted != declared_entries:
            raise _ArchiveContentError("ZIP central-directory count did not match")
    except OSError as exc:
        raise _ArchiveContentError("ZIP metadata could not be read") from exc
    finally:
        if source_fd >= 0:
            os.close(source_fd)


def _open_regular_nofollow(path: Path, max_bytes: int) -> int:
    value = os.fspath(path)
    candidate = Path(value)
    parts = list(candidate.parts)
    if not value or not parts or any(part == ".." for part in parts):
        raise _ArchiveInputError("unsafe path")

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
        if not parts:
            raise _ArchiveInputError("archive path has no file component")
        for part in parts[:-1]:
            if part in {"", ".", ".."}:
                raise _ArchiveInputError("unsafe path component")
            try:
                child_fd = os.open(part, directory_flags, dir_fd=directory_fd)
            except OSError as exc:
                raise _ArchiveInputError("unsafe path component") from exc
            os.close(directory_fd)
            directory_fd = child_fd
        try:
            source_fd = os.open(parts[-1], file_flags, dir_fd=directory_fd)
        except OSError as exc:
            raise _ArchiveInputError("archive could not be opened") from exc
        try:
            metadata = os.fstat(source_fd)
        except OSError as exc:
            os.close(source_fd)
            raise _ArchiveInputError("archive metadata was unavailable") from exc
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > max_bytes:
            os.close(source_fd)
            raise _ArchiveInputError("archive is not a bounded regular file")
        return source_fd
    except OSError as exc:
        raise _ArchiveInputError("archive path could not be opened") from exc
    finally:
        if directory_fd >= 0:
            os.close(directory_fd)


def _stat_identity(metadata: os.stat_result) -> Tuple[int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
    )


def _write_all(fd: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(fd, payload[offset:])
        if written <= 0:
            raise OSError("short archive snapshot write")
        offset += written


def _open_new_output(destination: Path) -> int:
    return os.open(
        str(destination),
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )


def _copy_bounded(source, destination_fd: int, budget: _ExtractionBudget) -> int:
    copied = 0
    while True:
        chunk = source.read(65536)
        if not chunk:
            break
        budget.add_bytes(len(chunk))
        copied += len(chunk)
        _write_all(destination_fd, chunk)
    return copied
