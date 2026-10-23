"""Bounded pacman sync-database provenance for pacman-hook scans.

The hook receives package names, resolves them to cached archives, and needs a
trustworthy way to distinguish an official repository archive from an
arbitrary local or AUR build.  A bare filename is not enough: the package cache
is not a trust boundary.  This module reads the root-owned sync databases and
binds the archive filename to the repository's SHA-256 value.  An archive is
treated as official only when both the filename and the bytes match.

The reader never invokes pacman, never extracts package contents, and bounds
every database, description, entry count, and package hash read.
"""

import hashlib
import re
import stat
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Mapping, Optional

SYNC_DB_DIR = Path("/var/lib/pacman/sync")
MAX_DB_BYTES = 128 * 1024 * 1024
MAX_DB_ENTRIES = 200_000
MAX_DESC_BYTES = 64 * 1024
MAX_PACKAGE_BYTES = 8 * 1024 * 1024 * 1024
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class OfficialPackageIndex:
    """Repository filename -> SHA-256 bindings from the pacman sync databases."""

    filenames: Mapping[str, str]
    complete: bool
    reason: str = ""


def _parse_desc(data: bytes) -> Dict[str, str]:
    fields: Dict[str, str] = {}
    current = ""
    for line in data.decode("utf-8", "replace").splitlines():
        if len(line) >= 2 and line.startswith("%") and line.endswith("%"):
            current = line.strip("%").lower()
            continue
        if current and line:
            fields[current] = line
    return fields


def load_official_package_index(
    sync_dir: Path = SYNC_DB_DIR,
) -> OfficialPackageIndex:
    """Read repository ``%FILENAME%``/``%SHA256SUM%`` bindings.

    A corrupt, oversized, or unreadable database marks the result incomplete.
    Callers must treat an archive not found in the mapping as non-official and
    continue with the full scan.  A partial index is still useful for the
    packages it does contain, but it must never turn an unknown archive into an
    official one.
    """

    filenames: Dict[str, str] = {}
    problems = []
    try:
        databases = sorted(sync_dir.glob("*.db"))
    except OSError:
        return OfficialPackageIndex({}, False, "sync directory unreadable")
    if not databases:
        return OfficialPackageIndex({}, False, "no sync databases found")

    try:
        for database in databases:
            try:
                if database.stat().st_size > MAX_DB_BYTES:
                    problems.append("sync database exceeds its size bound")
                    continue
                with tarfile.open(database, "r:*") as archive:
                    entries = 0
                    for member in archive:
                        entries += 1
                        if entries > MAX_DB_ENTRIES:
                            problems.append("sync database entry bound exceeded")
                            break
                        if not member.isfile() or not member.name.endswith("/desc"):
                            continue
                        if member.size > MAX_DESC_BYTES:
                            problems.append("description exceeds its size bound")
                            continue
                        extracted = archive.extractfile(member)
                        if extracted is None:
                            problems.append("description could not be read")
                            continue
                        fields = _parse_desc(extracted.read(MAX_DESC_BYTES))
                        filename = fields.get("filename", "")
                        checksum = fields.get("sha256sum", "").lower()
                        if filename and _HASH_RE.match(checksum):
                            filenames[Path(filename).name] = checksum
            except (OSError, tarfile.TarError, EOFError, ValueError):
                problems.append("sync database could not be read")
    except OSError:
        problems.append("sync database could not be read")

    return OfficialPackageIndex(
        filenames=filenames,
        complete=not problems,
        reason="; ".join(dict.fromkeys(problems))[:300],
    )


def package_sha256(path: Path) -> str:
    """Return a streamed package SHA-256, or ``""`` when it cannot be read."""

    try:
        file_stat = path.lstat()
        if not stat.S_ISREG(file_stat.st_mode):
            return ""
        if file_stat.st_size > MAX_PACKAGE_BYTES:
            return ""
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return ""


def package_matches_official(path: Path, index: OfficialPackageIndex) -> bool:
    """Return True only when the archive filename and bytes match a repo entry."""

    expected = index.filenames.get(path.name)
    if not expected:
        return False
    observed = package_sha256(path)
    return bool(observed) and observed == expected
