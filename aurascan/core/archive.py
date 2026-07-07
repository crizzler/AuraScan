import os
import shutil
import stat
import tarfile
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Iterable, List, Tuple

from aurascan.core.models import Confidence, EvidenceQuality, Finding, Phase, Severity, Source


class SafeArchiveExtractor:
    def __init__(self, max_total_size: int = 100 * 1024 * 1024, max_files: int = 10000, max_depth: int = 2):
        self.max_total_size = max_total_size
        self.max_files = max_files
        self.max_depth = max_depth

    def inspect(self, archive_path: str, phase: Phase = Phase.source_archive_scan, depth: int = 0) -> List[Finding]:
        findings: List[Finding] = []
        try:
            entries = list(self._entries(archive_path))
        except ValueError as exc:
            return [self._finding("ARCHIVE-UNSUPPORTED", archive_path, phase, Severity.MEDIUM, str(exc), "Use a supported archive format.", True)]

        total_size = 0
        if len(entries) > self.max_files:
            findings.append(self._finding("ARCHIVE-TOO-MANY-FILES", archive_path, phase, Severity.HIGH, "Archive contains too many files.", "Inspect archive manually.", True))

        for name, size, mode, kind, linkname in entries:
            total_size += max(size, 0)
            if total_size > self.max_total_size:
                findings.append(self._finding("ARCHIVE-OVERSIZED", archive_path, phase, Severity.HIGH, "Archive exceeds decompressed size limit.", "Inspect archive manually.", True, name))
                break
            if self._unsafe_path(name):
                findings.append(self._finding("ARCHIVE-PATH-TRAVERSAL", archive_path, phase, Severity.CRITICAL, "Archive entry would escape extraction directory.", "Reject this archive.", True, name))
            if kind == "symlink" and (self._unsafe_path(linkname) or self._link_escapes(name, linkname)):
                findings.append(self._finding("ARCHIVE-SYMLINK-ESCAPE", archive_path, phase, Severity.CRITICAL, "Archive symlink can escape extraction directory.", "Reject this archive.", True, f"{name} -> {linkname}"))
            if kind == "hardlink" and (self._unsafe_path(linkname) or self._link_escapes(name, linkname)):
                findings.append(self._finding("ARCHIVE-HARDLINK-ESCAPE", archive_path, phase, Severity.CRITICAL, "Archive hardlink can escape extraction directory.", "Reject this archive.", True, f"{name} -> {linkname}"))
            if self._is_nested_archive(name) and depth >= self.max_depth:
                findings.append(self._finding("ARCHIVE-NESTED-DEPTH", archive_path, phase, Severity.HIGH, "Nested archive depth limit exceeded.", "Inspect nested archive manually.", True, name))
            if self._is_suspicious_file(name, mode):
                findings.append(self._finding("ARCHIVE-SUSPICIOUS-FILE", archive_path, phase, Severity.MEDIUM, "Archive contains a suspicious executable or hidden script.", "Review this file before trusting the source.", False, name))

        return findings

    def extract(self, archive_path: str, target_dir: str = None, depth: int = 0) -> Tuple[Path, List[Finding]]:
        findings = self.inspect(archive_path, depth=depth)
        if any(f.blocks_installation for f in findings):
            return Path(target_dir) if target_dir else Path(), findings

        if target_dir is None:
            target = Path(tempfile.mkdtemp(prefix="aurascan-extract-"))
        else:
            target = Path(target_dir)
            target.mkdir(parents=True, exist_ok=True)

        try:
            if tarfile.is_tarfile(archive_path):
                with tarfile.open(archive_path, "r:*") as archive:
                    for member in archive.getmembers():
                        self._extract_tar_member(archive, member, target)
            elif zipfile.is_zipfile(archive_path):
                with zipfile.ZipFile(archive_path) as archive:
                    for info in archive.infolist():
                        self._extract_zip_member(archive, info, target)
            else:
                raise ValueError("Unsupported archive format.")
        except Exception:
            if target_dir is None and target.exists():
                shutil.rmtree(target, ignore_errors=True)
            raise
        return target, findings

    def _entries(self, archive_path: str) -> Iterable[Tuple[str, int, int, str, str]]:
        if tarfile.is_tarfile(archive_path):
            with tarfile.open(archive_path, "r:*") as archive:
                for member in archive.getmembers():
                    kind = "symlink" if member.issym() else "hardlink" if member.islnk() else "dir" if member.isdir() else "file"
                    yield member.name, member.size, member.mode, kind, member.linkname or ""
            return
        if zipfile.is_zipfile(archive_path):
            with zipfile.ZipFile(archive_path) as archive:
                for info in archive.infolist():
                    mode = (info.external_attr >> 16) & 0o777777
                    kind = "dir" if info.is_dir() else "file"
                    yield info.filename, info.file_size, mode, kind, ""
            return
        raise ValueError("Unsupported archive format.")

    def _extract_tar_member(self, archive: tarfile.TarFile, member: tarfile.TarInfo, target: Path) -> None:
        destination = self._safe_destination(target, member.name)
        if member.isdir():
            destination.mkdir(parents=True, exist_ok=True)
            return
        if member.issym() or member.islnk():
            return
        destination.parent.mkdir(parents=True, exist_ok=True)
        src = archive.extractfile(member)
        if src is None:
            return
        with src, destination.open("wb") as out:
            shutil.copyfileobj(src, out)
        os.chmod(destination, member.mode & 0o777)

    def _extract_zip_member(self, archive: zipfile.ZipFile, info: zipfile.ZipInfo, target: Path) -> None:
        destination = self._safe_destination(target, info.filename)
        if info.is_dir():
            destination.mkdir(parents=True, exist_ok=True)
            return
        destination.parent.mkdir(parents=True, exist_ok=True)
        with archive.open(info) as src, destination.open("wb") as out:
            shutil.copyfileobj(src, out)

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
