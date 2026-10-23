"""Bounded, static runtime-link inspection for installed packages.

A package can be upgraded with an ELF ``DT_NEEDED`` entry for a shared library
that its packaging metadata does not declare.  The dynamic linker then aborts
before the application can start.  This module reads ELF headers and dynamic
sections only; it never executes the inspected binary and never invokes the
dynamic loader.
"""

import os
import re
import stat
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from aurascan.core.bounded_process import CommandOutput, run_bounded_command


MAX_ELF_BYTES = 512 * 1024 * 1024
MAX_PROGRAM_HEADERS = 4096
MAX_DYNAMIC_BYTES = 1024 * 1024
MAX_DYNSTR_BYTES = 1024 * 1024
MAX_SONAME_CHARS = 256
MAX_PACKAGE_FILES = 4000
MAX_SCAN_FILES = 500
MAX_PACKAGE_LIST_BYTES = 4 * 1024 * 1024
_ELF_MAGIC = b"\x7fELF"
_SONAME_RE = re.compile(r"^[A-Za-z0-9@._+:-]+\Z")
_NEEDED_RE = re.compile(r"\(NEEDED\)\s+Shared library: \[([^]]+)\]")
_ELF_CLASS_32 = 1
_ELF_CLASS_64 = 2
_ELF_DATA_LSB = 1
_ELF_DATA_MSB = 2
_PT_LOAD = 1
_PT_DYNAMIC = 2
_DT_NULL = 0
_DT_NEEDED = 1
_DT_STRTAB = 5
_DT_STRSZ = 10
_ELF_PATH_PREFIXES = ("/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/lib32/", "/opt/")
_ELF_PATH_EXCLUDES = (
    "/usr/lib/debug/",
    "/usr/lib/modules/",
    "/usr/lib/python",
    "/usr/share/",
    "/usr/include/",
    "/usr/src/",
)


@dataclass(frozen=True)
class RuntimeLinkIssue:
    package: str
    file_path: str
    soname: str
    providers: Tuple[str, ...] = ()


@dataclass(frozen=True)
class RuntimeLinkScan:
    issues: List[RuntimeLinkIssue]
    notes: List[str]
    checked_files: int


def _u16(data: bytes, offset: int, endian: str) -> int:
    if offset < 0 or offset + 2 > len(data):
        return 0
    return struct.unpack_from(endian + "H", data, offset)[0]


def _u32(data: bytes, offset: int, endian: str) -> int:
    if offset < 0 or offset + 4 > len(data):
        return 0
    return struct.unpack_from(endian + "I", data, offset)[0]


def _u64(data: bytes, offset: int, endian: str) -> int:
    if offset < 0 or offset + 8 > len(data):
        return 0
    return struct.unpack_from(endian + "Q", data, offset)[0]


def _read_at(fd: int, offset: int, size: int) -> bytes:
    if size <= 0 or size > MAX_DYNSTR_BYTES:
        return b""
    try:
        return os.pread(fd, size, offset)
    except OSError:
        return b""


def read_elf_needed(path: Path) -> List[str]:
    """Return bounded ``DT_NEEDED`` sonames from a regular ELF file.

    The parser follows PT_LOAD/PT_DYNAMIC metadata and reads only the dynamic
    string table.  Malformed, truncated, non-ELF, symlinked, or oversized files
    produce an empty result; this is evidence collection, not a validator.
    """

    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError:
        return []
    try:
        try:
            metadata = os.fstat(fd)
        except OSError:
            return []
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 16 or metadata.st_size > MAX_ELF_BYTES:
            return []
        ident = _read_at(fd, 0, 16)
        if len(ident) < 16 or ident[:4] != _ELF_MAGIC:
            return []
        elf_class = ident[4]
        data_encoding = ident[5]
        if data_encoding == _ELF_DATA_LSB:
            endian = "<"
        elif data_encoding == _ELF_DATA_MSB:
            endian = ">"
        else:
            return []
        if elf_class == _ELF_CLASS_64:
            header_size = 64
            program_header_size = 56
            header = _read_at(fd, 0, header_size)
            if len(header) < header_size:
                return []
            phoff = _u64(header, 32, endian)
            phentsize = _u16(header, 54, endian)
            phnum = _u16(header, 56, endian)
            if phentsize < program_header_size or phnum == 0 or phnum > MAX_PROGRAM_HEADERS:
                return []
            table_size = phentsize * phnum
            table = _read_at(fd, phoff, min(table_size, MAX_DYNAMIC_BYTES))
            if len(table) < table_size:
                return []
            loads = []
            dynamic = None
            for index in range(phnum):
                offset = index * phentsize
                p_type = _u32(table, offset, endian)
                p_offset = _u64(table, offset + 8, endian)
                p_vaddr = _u64(table, offset + 16, endian)
                p_filesz = _u64(table, offset + 32, endian)
                if p_type == _PT_LOAD:
                    loads.append((p_vaddr, p_offset, p_filesz))
                elif p_type == _PT_DYNAMIC:
                    dynamic = (p_offset, p_filesz)
        elif elf_class == _ELF_CLASS_32:
            header_size = 52
            program_header_size = 32
            header = _read_at(fd, 0, header_size)
            if len(header) < header_size:
                return []
            phoff = _u32(header, 28, endian)
            phentsize = _u16(header, 42, endian)
            phnum = _u16(header, 44, endian)
            if phentsize < program_header_size or phnum == 0 or phnum > MAX_PROGRAM_HEADERS:
                return []
            table_size = phentsize * phnum
            table = _read_at(fd, phoff, min(table_size, MAX_DYNAMIC_BYTES))
            if len(table) < table_size:
                return []
            loads = []
            dynamic = None
            for index in range(phnum):
                offset = index * phentsize
                p_type = _u32(table, offset, endian)
                p_offset = _u32(table, offset + 4, endian)
                p_vaddr = _u32(table, offset + 8, endian)
                p_filesz = _u32(table, offset + 16, endian)
                if p_type == _PT_LOAD:
                    loads.append((p_vaddr, p_offset, p_filesz))
                elif p_type == _PT_DYNAMIC:
                    dynamic = (p_offset, p_filesz)
        else:
            return []
        if dynamic is None or not loads:
            return []
        dyn_offset, dyn_size = dynamic
        dyn_size = min(dyn_size, MAX_DYNAMIC_BYTES)
        dynamic_data = _read_at(fd, dyn_offset, dyn_size)
        if not dynamic_data:
            return []
        entry_size = 16 if elf_class == _ELF_CLASS_64 else 8
        needed_offsets: List[int] = []
        strtab = 0
        strsz = 0
        for offset in range(0, len(dynamic_data) - entry_size + 1, entry_size):
            if elf_class == _ELF_CLASS_64:
                tag = _u64(dynamic_data, offset, endian)
                value = _u64(dynamic_data, offset + 8, endian)
            else:
                tag = _u32(dynamic_data, offset, endian)
                value = _u32(dynamic_data, offset + 4, endian)
            if tag == _DT_NULL:
                break
            if tag == _DT_NEEDED:
                needed_offsets.append(value)
            elif tag == _DT_STRTAB:
                strtab = value
            elif tag == _DT_STRSZ:
                strsz = value
        if not needed_offsets or not strtab:
            return []
        strtab_offset = None
        for vaddr, file_offset, filesz in loads:
            if vaddr <= strtab < vaddr + filesz:
                strtab_offset = file_offset + (strtab - vaddr)
                break
        if strtab_offset is None:
            return []
        strsz = min(strsz or MAX_DYNSTR_BYTES, MAX_DYNSTR_BYTES)
        strings = _read_at(fd, strtab_offset, strsz)
        if not strings:
            return []
        result: List[str] = []
        for needed in needed_offsets:
            if needed >= len(strings):
                continue
            raw = strings[needed:]
            end = raw.find(b"\x00")
            if end < 0:
                continue
            try:
                soname = raw[:end].decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                continue
            if len(soname) > MAX_SONAME_CHARS or not _SONAME_RE.fullmatch(soname):
                continue
            if soname not in result:
                result.append(soname)
        return result
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def linker_cache_sonames(text: str) -> Set[str]:
    """Extract sonames from ``ldconfig -p`` output without executing anything."""

    names: Set[str] = set()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("libs found"):
            continue
        if " => " not in stripped:
            continue
        name = stripped.split(" ", 1)[0].strip()
        if name and _SONAME_RE.fullmatch(name):
            names.add(name)
    return names


def load_linker_cache(runner: Callable, *, ldconfig_path: Path = Path("/usr/bin/ldconfig")) -> Tuple[Set[str], str]:
    output = run_bounded_command(
        runner,
        [str(ldconfig_path), "-p"],
        max_chars=MAX_PACKAGE_LIST_BYTES,
        timeout=30,
    )
    if output.returncode != 0:
        return set(), "ldconfig cache could not be read"
    return linker_cache_sonames(output.stdout), ""


def package_file_paths(
    package: str,
    *,
    query_runner: Callable,
) -> Tuple[List[str], str]:
    output: CommandOutput = run_bounded_command(
        query_runner,
        ["pacman", "-Ql", package],
        max_chars=MAX_PACKAGE_LIST_BYTES,
        timeout=30,
    )
    if output.returncode != 0:
        return [], "package file list could not be read"
    if output.truncated:
        return [], "package file list exceeded its size bound"
    paths: List[str] = []
    for line in output.stdout.splitlines():
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        path = parts[1].strip()
        if path.startswith("/") and len(path) <= 4096:
            paths.append(path)
        if len(paths) >= MAX_PACKAGE_FILES:
            return paths, "package file list exceeded its entry bound"
    return paths, ""


def _candidate_files(paths: Iterable[str], root: Path) -> List[str]:
    candidates: List[str] = []
    for path in paths:
        if not path.startswith(_ELF_PATH_PREFIXES):
            continue
        if path.startswith(_ELF_PATH_EXCLUDES):
            continue
        if ".." in Path(path).parts:
            continue
        candidates.append(path)
    return candidates


def _regular_path(path: Path) -> bool:
    try:
        return stat.S_ISREG(path.lstat().st_mode)
    except OSError:
        return False


def collect_runtime_link_issues(
    packages: Sequence[str],
    *,
    query_runner: Callable,
    linker_cache: Set[str],
    providers: Mapping[str, frozenset],
    root: Path = Path("/"),
    max_files: int = MAX_SCAN_FILES,
) -> RuntimeLinkScan:
    """Find missing ELF dependencies in the installed files of ``packages``.

    ``query_runner`` must be the already-authorized pacman query runner.  File
    reads stay below ``root`` and use no-follow regular-file checks.  The scan
    is deliberately conservative: an unreadable file list or ELF file becomes a
    coverage note, not an assertion that the package is broken.
    """

    issues: List[RuntimeLinkIssue] = []
    notes: List[str] = []
    seen: Set[Tuple[str, str, str]] = set()
    checked = 0
    for package in sorted(set(packages)):
        paths, note = package_file_paths(package, query_runner=query_runner)
        if note:
            notes.append(f"{package}: {note}")
            continue
        bundled = {Path(path).name for path in paths}
        candidates = _candidate_files(paths, root)
        for relative in candidates:
            if checked >= max_files:
                notes.append("ELF inspection stopped at its file bound")
                return RuntimeLinkScan(issues, notes, checked)
            absolute = root / relative.lstrip("/")
            if not _regular_path(absolute):
                continue
            needed = read_elf_needed(absolute)
            checked += 1
            for soname in needed:
                if soname in linker_cache or soname in bundled:
                    continue
                key = (package, relative, soname)
                if key in seen:
                    continue
                seen.add(key)
                issues.append(
                    RuntimeLinkIssue(
                        package=package,
                        file_path=relative,
                        soname=soname,
                        providers=tuple(sorted(providers.get(soname, ()))),
                    )
                )
    return RuntimeLinkScan(issues, notes, checked)


def missing_provider_candidates(
    issues: Sequence[RuntimeLinkIssue],
    installed_versions: Mapping[str, str],
) -> List[str]:
    candidates: Set[str] = set()
    for issue in issues:
        for provider in issue.providers:
            if provider and provider not in installed_versions:
                candidates.add(provider)
    return sorted(candidates)
