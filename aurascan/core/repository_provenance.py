"""Bounded immutable snapshots of opaque files in a package directory.

This module is deliberately a byte collector, not a package evaluator.  It
does not invoke Git, inspect archive members, source PKGBUILDs, or execute any
file it encounters.  Every non-pruned regular file is hashed through an
already-opened no-follow descriptor so the resulting digest can be bound to a
later scan or review decision.
"""

import hashlib
import json
import os
import re
import stat
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Dict, Iterable, List, Sequence, Set, Tuple


REPOSITORY_COMPLETE = "complete"
REPOSITORY_UNINSPECTED = "uninspected"
REPOSITORY_SNAPSHOT_VERSION = "1.0"

MAX_REPOSITORY_ENTRIES = 20_000
MAX_REPOSITORY_REGULAR_FILES = 4_096
MAX_REPOSITORY_ARTIFACTS = 128
MAX_REPOSITORY_DEPTH = 64
MAX_REPOSITORY_FILE_BYTES = 128 * 1024 * 1024
MAX_REPOSITORY_TOTAL_BYTES = 256 * 1024 * 1024
MAX_REPOSITORY_PATH_BYTES = 4096
MAX_REQUIRED_RELATIVE_PATHS = 256
MAX_MAGIC_BYTES = 4096
MAX_REPOSITORY_ELAPSED_SECONDS = 15.0

_VCS_DIRECTORIES = frozenset({".git", ".hg", ".svn", ".bzr"})
_GENERATED_ROOT_DIRECTORIES = frozenset({"src", "pkg"})
_GENERATED_OR_CACHE_DIRECTORIES = frozenset({
    ".cache",
    ".gradle",
    ".mypy_cache",
    ".nox",
    ".npm",
    ".pnpm-store",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    ".yarn",
    "__pycache__",
    "cache",
    "node_modules",
    "venv",
    "virtualenv",
})
_GENERATED_ARCHIVE_RE = re.compile(
    r".+\.(?:pkg|src)\.tar(?:\.(?:bz2|gz|lrz|lzo|xz|zst|Z))?\Z"
)

_MACHO_MAGICS = frozenset({
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
})
_MACHO_FAT_MAGICS = frozenset({
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
})


@dataclass(frozen=True)
class RepositoryArtifact:
    relative_path: str
    kind: str
    sha256: str
    size: int
    mode: int
    generated_output: bool = False


@dataclass(frozen=True)
class RepositorySnapshot:
    status: str
    input_digest: str
    artifacts: Tuple[RepositoryArtifact, ...]
    error_code: str = ""
    entry_count: int = 0


@dataclass
class _CaptureState:
    excluded_paths: Set[str]
    excluded_subtree_paths: Set[str]
    independently_bound_paths: Set[str]
    required_paths: Set[str]
    entries: List[Dict[str, object]]
    artifacts: List[RepositoryArtifact]
    deadline: float
    visited_paths: Set[str]
    pruned_paths: Set[str]
    entry_indexes: Dict[str, int]
    validation_records: Dict[str, "_ValidationRecord"]
    entry_count: int = 0
    regular_file_count: int = 0
    total_bytes: int = 0


@dataclass(frozen=True)
class _ValidationRecord:
    relative_path: str
    entry_type: str
    identity: Tuple[int, ...]


class _CaptureFailure(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def capture_repository_snapshot(
    root: Path,
    excluded_relative_paths: Iterable[object] = (),
    excluded_subtree_relative_paths: Iterable[object] = (),
    independently_bound_relative_paths: Iterable[object] = (),
    required_relative_paths: Iterable[object] = (),
    required_paths_complete: bool = True,
) -> RepositorySnapshot:
    """Capture a stable, no-follow package-directory identity.

    Explicit exclusions suppress artifact classification only.  Bounded
    exclusions retain their exact bytes in the private digest material;
    oversized declared source files retain a stable no-follow metadata
    identity because their checksum contract is bound separately by the
    captured PKGBUILD.
    """

    root = Path(root)
    entries: List[Dict[str, object]] = []
    artifacts: List[RepositoryArtifact] = []
    entry_count = 0
    if not getattr(os, "O_NOFOLLOW", 0) or not getattr(os, "O_DIRECTORY", 0):
        return _build_snapshot(
            REPOSITORY_UNINSPECTED,
            "no_follow_unavailable",
            entries,
            artifacts,
            entry_count,
            (),
            (),
        )
    try:
        excluded_paths = _normalize_exclusions(excluded_relative_paths)
        excluded_subtree_paths = _normalize_exclusions(
            excluded_subtree_relative_paths
        )
        independently_bound_paths = _normalize_exclusions(
            independently_bound_relative_paths
        )
        required_paths = _normalize_exclusions(required_relative_paths)
        if len(required_paths) > MAX_REQUIRED_RELATIVE_PATHS:
            raise _CaptureFailure("required_path_limit")
        if not required_paths_complete:
            raise _CaptureFailure("required_path_ambiguous")
    except _CaptureFailure as exc:
        return _build_snapshot(
            REPOSITORY_UNINSPECTED,
            exc.code,
            entries,
            artifacts,
            entry_count,
            (),
            (),
            (),
        )

    state = _CaptureState(
        excluded_paths,
        excluded_subtree_paths,
        independently_bound_paths,
        required_paths,
        entries,
        artifacts,
        time.monotonic() + MAX_REPOSITORY_ELAPSED_SECONDS,
        set(),
        set(),
        {},
        {},
    )
    root_fd = -1
    root_before = None
    try:
        try:
            root_metadata = root.lstat()
        except OSError as exc:
            raise _CaptureFailure("root_unavailable") from exc
        if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
            raise _CaptureFailure("unsafe_root")
        root_fd = os.open(
            str(root),
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        root_before = os.fstat(root_fd)
        if (
            not stat.S_ISDIR(root_before.st_mode)
            or _directory_identity(root_metadata) != _directory_identity(root_before)
        ):
            raise _CaptureFailure("unsafe_root")

        _walk_directory(root_fd, (), 0, state)
        for required_path in sorted(required_paths):
            _capture_required_path(root_fd, required_path, state)

        # Revalidate every captured path after the complete traversal.  This
        # detects a one-time replacement or in-place mutation that happens
        # after an early subtree was read.  It is not an atomic filesystem
        # snapshot: an actively racing same-UID process can still change bytes
        # after revalidation and before a later consumer opens them.
        _revalidate_captured_paths(root_fd, state)

        root_after = os.fstat(root_fd)
        try:
            root_current = root.lstat()
        except OSError as exc:
            raise _CaptureFailure("root_changed") from exc
        if (
            _directory_identity(root_before) != _directory_identity(root_after)
            or _directory_identity(root_after) != _directory_identity(root_current)
        ):
            raise _CaptureFailure("root_changed")
    except _CaptureFailure as exc:
        return _build_snapshot(
            REPOSITORY_UNINSPECTED,
            exc.code,
            state.entries,
            state.artifacts,
            state.entry_count,
            sorted(excluded_paths),
            sorted(excluded_subtree_paths),
            sorted(independently_bound_paths),
            sorted(required_paths),
        )
    except OSError:
        return _build_snapshot(
            REPOSITORY_UNINSPECTED,
            "root_unavailable" if root_before is None else "repository_unreadable",
            state.entries,
            state.artifacts,
            state.entry_count,
            sorted(excluded_paths),
            sorted(excluded_subtree_paths),
            sorted(independently_bound_paths),
            sorted(required_paths),
        )
    finally:
        if root_fd >= 0:
            try:
                os.close(root_fd)
            except OSError:
                pass

    return _build_snapshot(
        REPOSITORY_COMPLETE,
        "",
        state.entries,
        state.artifacts,
        state.entry_count,
        sorted(excluded_paths),
        sorted(excluded_subtree_paths),
        sorted(independently_bound_paths),
        sorted(required_paths),
    )


def _walk_directory(
    directory_fd: int,
    relative_parts: Tuple[str, ...],
    depth: int,
    state: _CaptureState,
    *,
    required_traversal: bool = False,
) -> None:
    _check_deadline(state)
    if depth > MAX_REPOSITORY_DEPTH:
        raise _CaptureFailure("depth_limit")
    directory_before = os.fstat(directory_fd)
    if not stat.S_ISDIR(directory_before.st_mode):
        raise _CaptureFailure("directory_changed")
    try:
        iterator = os.scandir(directory_fd)
    except OSError as exc:
        raise _CaptureFailure("directory_unreadable") from exc

    with iterator:
        for entry in iterator:
            _check_deadline(state)
            name = entry.name
            if _unsafe_component(name):
                raise _CaptureFailure("unsafe_name")
            parts = relative_parts + (name,)
            relative_path = PurePosixPath(*parts).as_posix()
            if len(os.fsencode(relative_path)) > MAX_REPOSITORY_PATH_BYTES:
                raise _CaptureFailure("path_too_long")
            first_visit = relative_path not in state.visited_paths
            if first_visit:
                state.entry_count += 1
                if state.entry_count > MAX_REPOSITORY_ENTRIES:
                    raise _CaptureFailure("entry_limit")
                state.visited_paths.add(relative_path)
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError as exc:
                raise _CaptureFailure("entry_unreadable") from exc
            mode = stat.S_IMODE(metadata.st_mode)

            if stat.S_ISLNK(metadata.st_mode):
                _record_manifest_entry(
                    state,
                    _manifest_entry(relative_path, "symlink", mode=mode),
                )
                raise _CaptureFailure("symlink_entry")
            if stat.S_ISDIR(metadata.st_mode):
                if _is_vcs_directory(parts):
                    state.pruned_paths.add(relative_path)
                    continue
                if (
                    not required_traversal
                    and relative_path in state.excluded_subtree_paths
                ):
                    state.pruned_paths.add(relative_path)
                    _record_manifest_entry(
                        state,
                        _manifest_entry(
                            relative_path,
                            "source-owned-directory",
                            mode=mode,
                        ),
                    )
                    _remember_directory_validation(state, relative_path, metadata)
                    continue
                if _skip_directory(parts) and not required_traversal:
                    state.pruned_paths.add(relative_path)
                    continue
                state.pruned_paths.discard(relative_path)
                _record_manifest_entry(
                    state,
                    _manifest_entry(relative_path, "directory", mode=mode),
                )
                _walk_child_directory(
                    directory_fd,
                    name,
                    metadata,
                    parts,
                    depth + 1,
                    state,
                    required_traversal=required_traversal,
                )
                _remember_directory_validation(state, relative_path, metadata)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                _record_manifest_entry(
                    state,
                    _manifest_entry(relative_path, "special", mode=mode),
                )
                raise _CaptureFailure("special_entry")

            if relative_path in state.excluded_subtree_paths:
                # A statically declared VCS cache path is directory-shaped.
                # Treating a same-named regular file as an excluded tree would
                # hide opaque bytes and diverge from makepkg's path contract.
                _record_manifest_entry(
                    state,
                    _manifest_entry(
                        relative_path,
                        "source-owned-wrong-type",
                        mode=mode,
                    ),
                )
                raise _CaptureFailure("excluded_subtree_wrong_type")

            if not first_visit:
                # Required directory traversal may revisit an already captured
                # ordinary subtree to reach a nested path that was pruned on
                # the first pass.  Do not double-count or duplicate its files.
                continue

            state.regular_file_count += 1
            if state.regular_file_count > MAX_REPOSITORY_REGULAR_FILES:
                raise _CaptureFailure("candidate_limit")

            if relative_path in state.independently_bound_paths:
                # PKGBUILD and install-hook bytes are captured through their
                # own stronger snapshot readers.  Record only the stable path
                # role here so changing those bytes does not masquerade as a
                # repository-only trust-boundary change.
                _record_manifest_entry(
                    state,
                    _manifest_entry(relative_path, "independently-bound-regular"),
                )
                _remember_file_validation(state, relative_path, metadata)
                continue

            excluded = relative_path in state.excluded_paths
            generated_output = _is_generated_output(parts)
            unreferenced_generated_archive = (
                _is_root_generated_archive(parts)
                and relative_path not in state.required_paths
            )
            digest, prefix, pe_valid, size, opened_mode, entry_type = (
                _capture_regular_entry(
                    directory_fd,
                    name,
                    metadata,
                    state,
                    excluded=excluded,
                    unreferenced_generated_archive=unreferenced_generated_archive,
                    require_full_capture=relative_path in state.required_paths,
                )
            )
            kind = _classify_artifact(prefix, pe_valid=pe_valid) if prefix else ""
            _record_manifest_entry(
                state,
                _manifest_entry(
                    relative_path,
                    entry_type,
                    sha256=digest,
                    size=size,
                    mode=opened_mode,
                    artifact_kind=kind,
                    generated_output=generated_output,
                    excluded=excluded,
                ),
            )
            _remember_file_validation(state, relative_path, metadata)
            if kind and not excluded:
                if len(state.artifacts) >= MAX_REPOSITORY_ARTIFACTS:
                    raise _CaptureFailure("artifact_limit")
                state.artifacts.append(RepositoryArtifact(
                    relative_path=relative_path,
                    kind=kind,
                    sha256=digest,
                    size=size,
                    mode=opened_mode,
                    generated_output=generated_output,
                ))

    directory_after = os.fstat(directory_fd)
    if _directory_identity(directory_before) != _directory_identity(directory_after):
        raise _CaptureFailure("directory_changed")


def _capture_regular_entry(
    directory_fd: int,
    name: str,
    expected: os.stat_result,
    state: _CaptureState,
    *,
    excluded: bool,
    unreferenced_generated_archive: bool = False,
    require_full_capture: bool = False,
) -> Tuple[str, bytes, bool, int, int, str]:
    """Capture content, or stable metadata for an independently bounded file.

    Declared makepkg source files and their integrity metadata are already
    represented by the separately bound PKGBUILD and remain owned by the
    source-provenance workflow. Reading an exact local source must not consume
    the unrelated-repository byte budget, and an
    oversized exact source is bound by its no-follow file identity rather than
    being mislabeled as incomplete repository provenance.  An unreferenced
    root makepkg output archive receives the same treatment when it exceeds
    the payload bound and never consumes the unrelated repository byte budget.
    A statically required control path always receives normal full capture.
    """

    metadata_only = (
        not require_full_capture
        and expected.st_size > MAX_REPOSITORY_FILE_BYTES
        and (excluded or unreferenced_generated_archive)
    )
    if metadata_only:
        digest, size, opened_mode = _read_stable_metadata_entry(
            directory_fd,
            name,
            expected,
            state,
        )
        entry_type = (
            "generated-archive-metadata"
            if unreferenced_generated_archive
            else "excluded-large-regular"
        )
        return digest, b"", False, size, opened_mode, entry_type
    digest, prefix, pe_valid, size, opened_mode = _read_regular_entry(
        directory_fd,
        name,
        expected,
        state,
        count_toward_total=(
            require_full_capture
            or (not excluded and not unreferenced_generated_archive)
        ),
    )
    return digest, prefix, pe_valid, size, opened_mode, "regular"


def _capture_required_path(
    root_fd: int,
    relative_path: str,
    state: _CaptureState,
) -> None:
    """Capture one explicitly referenced file even below a pruned tree."""

    parts = PurePosixPath(relative_path).parts
    if any(part in _VCS_DIRECTORIES for part in parts):
        raise _CaptureFailure("required_path_unsafe")
    if len(parts) > MAX_REPOSITORY_DEPTH:
        raise _CaptureFailure("depth_limit")
    directory_fds = [os.dup(root_fd)]
    component_records: List[Tuple[int, str, int, os.stat_result]] = []
    try:
        for component_index, component in enumerate(parts[:-1]):
            _check_deadline(state)
            directory_fd = directory_fds[-1]
            parent_before = os.fstat(directory_fd)
            component_path = PurePosixPath(
                *parts[: component_index + 1]
            ).as_posix()
            try:
                metadata = os.stat(
                    component,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                _revalidate_required_components(component_records)
                if _directory_identity(parent_before) != _directory_identity(
                    os.fstat(directory_fd)
                ):
                    raise _CaptureFailure("required_path_unsafe")
                return
            except OSError as exc:
                raise _CaptureFailure("required_path_unsafe") from exc
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise _CaptureFailure("required_path_unsafe")
            try:
                child_fd = os.open(
                    component,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=directory_fd,
                )
            except OSError as exc:
                raise _CaptureFailure("required_path_unsafe") from exc
            opened = os.fstat(child_fd)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or _directory_identity(metadata) != _directory_identity(opened)
                or _directory_identity(parent_before) != _directory_identity(
                    os.fstat(directory_fd)
                )
            ):
                os.close(child_fd)
                raise _CaptureFailure("required_path_unsafe")
            directory_fds.append(child_fd)
            component_records.append((directory_fd, component, child_fd, opened))
            _mark_path_visited(state, component_path)
            state.pruned_paths.discard(component_path)
            _record_manifest_entry(
                state,
                _manifest_entry(
                    component_path,
                    "directory",
                    mode=stat.S_IMODE(opened.st_mode),
                ),
            )
            _remember_directory_validation(state, component_path, opened)

        directory_fd = directory_fds[-1]
        parent_before = os.fstat(directory_fd)
        name = parts[-1]
        try:
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            _revalidate_required_components(component_records)
            if _directory_identity(parent_before) != _directory_identity(
                os.fstat(directory_fd)
            ):
                raise _CaptureFailure("required_path_unsafe")
            return
        except OSError as exc:
            raise _CaptureFailure("required_path_unsafe") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise _CaptureFailure("required_path_unsafe")
        if stat.S_ISDIR(metadata.st_mode):
            _mark_path_visited(state, relative_path)
            try:
                child_fd = os.open(
                    name,
                    os.O_RDONLY
                    | getattr(os, "O_DIRECTORY", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=directory_fd,
                )
            except OSError as exc:
                raise _CaptureFailure("required_path_unsafe") from exc
            opened = os.fstat(child_fd)
            if (
                not stat.S_ISDIR(opened.st_mode)
                or _directory_identity(metadata) != _directory_identity(opened)
            ):
                os.close(child_fd)
                raise _CaptureFailure("required_path_unsafe")
            directory_fds.append(child_fd)
            component_records.append((directory_fd, name, child_fd, opened))
            state.pruned_paths.discard(relative_path)
            _record_manifest_entry(
                state,
                _manifest_entry(
                    relative_path,
                    "directory",
                    mode=stat.S_IMODE(opened.st_mode),
                ),
            )
            _remember_directory_validation(state, relative_path, opened)
            _walk_directory(
                child_fd,
                tuple(parts),
                len(parts),
                state,
                required_traversal=True,
            )
            _revalidate_required_components(component_records)
            if _directory_identity(parent_before) != _directory_identity(
                os.fstat(directory_fd)
            ):
                raise _CaptureFailure("required_path_unsafe")
            return
        if not stat.S_ISREG(metadata.st_mode):
            raise _CaptureFailure("required_path_unsafe")

        if relative_path in state.excluded_subtree_paths:
            raise _CaptureFailure("excluded_subtree_wrong_type")

        if relative_path in state.visited_paths:
            _revalidate_required_components(component_records)
            if _directory_identity(parent_before) != _directory_identity(
                os.fstat(directory_fd)
            ):
                raise _CaptureFailure("required_path_unsafe")
            return

        _mark_path_visited(state, relative_path)
        state.regular_file_count += 1
        if state.regular_file_count > MAX_REPOSITORY_REGULAR_FILES:
            raise _CaptureFailure("candidate_limit")
        state.visited_paths.add(relative_path)

        if relative_path in state.independently_bound_paths:
            _record_manifest_entry(
                state,
                _manifest_entry(relative_path, "independently-bound-regular"),
            )
            _remember_file_validation(state, relative_path, metadata)
            _revalidate_required_components(component_records)
            return
        excluded = relative_path in state.excluded_paths
        generated_output = _is_generated_output(parts)
        digest, prefix, pe_valid, size, opened_mode, entry_type = (
            _capture_regular_entry(
                directory_fd,
                name,
                metadata,
                state,
                excluded=excluded,
                require_full_capture=True,
            )
        )
        kind = _classify_artifact(prefix, pe_valid=pe_valid) if prefix else ""
        _record_manifest_entry(
            state,
            _manifest_entry(
                relative_path,
                entry_type,
                sha256=digest,
                size=size,
                mode=opened_mode,
                artifact_kind=kind,
                generated_output=generated_output,
                excluded=excluded,
            ),
        )
        _remember_file_validation(state, relative_path, metadata)
        if kind and not excluded:
            if len(state.artifacts) >= MAX_REPOSITORY_ARTIFACTS:
                raise _CaptureFailure("artifact_limit")
            state.artifacts.append(RepositoryArtifact(
                relative_path=relative_path,
                kind=kind,
                sha256=digest,
                size=size,
                mode=opened_mode,
                generated_output=generated_output,
            ))
        _revalidate_required_components(component_records)
        if _directory_identity(parent_before) != _directory_identity(
            os.fstat(directory_fd)
        ):
            raise _CaptureFailure("required_path_unsafe")
    finally:
        for file_descriptor in reversed(directory_fds):
            os.close(file_descriptor)


def _revalidate_required_components(
    records: Sequence[Tuple[int, str, int, os.stat_result]],
) -> None:
    for parent_fd, component, child_fd, opened in records:
        try:
            current = os.stat(
                component,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
            after = os.fstat(child_fd)
        except OSError as exc:
            raise _CaptureFailure("required_path_unsafe") from exc
        if (
            _directory_identity(opened) != _directory_identity(after)
            or _directory_identity(after) != _directory_identity(current)
        ):
            raise _CaptureFailure("required_path_unsafe")


def _mark_path_visited(state: _CaptureState, relative_path: str) -> bool:
    if relative_path in state.visited_paths:
        return False
    state.visited_paths.add(relative_path)
    state.entry_count += 1
    if state.entry_count > MAX_REPOSITORY_ENTRIES:
        raise _CaptureFailure("entry_limit")
    return True


def _record_manifest_entry(
    state: _CaptureState,
    entry: Dict[str, object],
) -> None:
    relative_path = str(entry.get("relative_path", ""))
    existing = state.entry_indexes.get(relative_path)
    if existing is None:
        state.entry_indexes[relative_path] = len(state.entries)
        state.entries.append(entry)
    else:
        state.entries[existing] = entry


def _remember_file_validation(
    state: _CaptureState,
    relative_path: str,
    metadata: os.stat_result,
) -> None:
    state.validation_records[relative_path] = _ValidationRecord(
        relative_path,
        "file",
        _file_identity(metadata),
    )


def _remember_directory_validation(
    state: _CaptureState,
    relative_path: str,
    metadata: os.stat_result,
) -> None:
    state.validation_records[relative_path] = _ValidationRecord(
        relative_path,
        "directory",
        _directory_identity(metadata),
    )


def _revalidate_captured_paths(root_fd: int, state: _CaptureState) -> None:
    """Re-open every captured path without following links and compare state."""

    for relative_path in sorted(state.validation_records):
        _check_deadline(state)
        record = state.validation_records[relative_path]
        parts = PurePosixPath(relative_path).parts
        directory_fds = [os.dup(root_fd)]
        try:
            current_fd = directory_fds[-1]
            for component in parts[:-1]:
                try:
                    next_fd = os.open(
                        component,
                        os.O_RDONLY
                        | getattr(os, "O_DIRECTORY", 0)
                        | getattr(os, "O_NOFOLLOW", 0)
                        | getattr(os, "O_CLOEXEC", 0),
                        dir_fd=current_fd,
                    )
                except OSError as exc:
                    raise _CaptureFailure(
                        "file_changed"
                        if record.entry_type == "file"
                        else "directory_changed"
                    ) from exc
                opened = os.fstat(next_fd)
                if not stat.S_ISDIR(opened.st_mode):
                    os.close(next_fd)
                    raise _CaptureFailure(
                        "file_changed"
                        if record.entry_type == "file"
                        else "directory_changed"
                    )
                directory_fds.append(next_fd)
                current_fd = next_fd

            try:
                current = os.stat(
                    parts[-1],
                    dir_fd=current_fd,
                    follow_symlinks=False,
                )
            except OSError as exc:
                raise _CaptureFailure(
                    "file_changed"
                    if record.entry_type == "file"
                    else "directory_changed"
                ) from exc
            if record.entry_type == "file":
                if (
                    not stat.S_ISREG(current.st_mode)
                    or _file_identity(current) != record.identity
                ):
                    raise _CaptureFailure("file_changed")
            elif (
                not stat.S_ISDIR(current.st_mode)
                or _directory_identity(current) != record.identity
            ):
                raise _CaptureFailure("directory_changed")
        finally:
            for file_descriptor in reversed(directory_fds):
                os.close(file_descriptor)


def _walk_child_directory(
    parent_fd: int,
    name: str,
    expected: os.stat_result,
    parts: Tuple[str, ...],
    depth: int,
    state: _CaptureState,
    *,
    required_traversal: bool = False,
) -> None:
    child_fd = -1
    try:
        try:
            child_fd = os.open(
                name,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent_fd,
            )
        except OSError as exc:
            raise _CaptureFailure("directory_unreadable") from exc
        opened = os.fstat(child_fd)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or _directory_identity(expected) != _directory_identity(opened)
        ):
            raise _CaptureFailure("directory_changed")
        _walk_directory(
            child_fd,
            parts,
            depth,
            state,
            required_traversal=required_traversal,
        )
        after = os.fstat(child_fd)
        try:
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise _CaptureFailure("directory_changed") from exc
        if (
            _directory_identity(opened) != _directory_identity(after)
            or _directory_identity(after) != _directory_identity(current)
        ):
            raise _CaptureFailure("directory_changed")
    finally:
        if child_fd >= 0:
            os.close(child_fd)


def _read_regular_entry(
    directory_fd: int,
    name: str,
    expected: os.stat_result,
    state: _CaptureState,
    *,
    count_toward_total: bool = True,
) -> Tuple[str, bytes, bool, int, int]:
    file_fd = -1
    try:
        try:
            file_fd = os.open(
                name,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=directory_fd,
            )
        except OSError as exc:
            raise _CaptureFailure("file_unreadable") from exc
        before = os.fstat(file_fd)
        if not stat.S_ISREG(before.st_mode) or _file_identity(expected) != _file_identity(before):
            raise _CaptureFailure("file_changed")
        if before.st_size < 0 or before.st_size > MAX_REPOSITORY_FILE_BYTES:
            raise _CaptureFailure("file_oversized")
        if count_toward_total and state.total_bytes + before.st_size > MAX_REPOSITORY_TOTAL_BYTES:
            raise _CaptureFailure("total_size_limit")

        digest = hashlib.sha256()
        prefix = bytearray()
        total = 0
        while True:
            _check_deadline(state)
            try:
                chunk = os.read(
                    file_fd,
                    min(65536, MAX_REPOSITORY_FILE_BYTES + 1 - total),
                )
            except InterruptedError:
                continue
            except OSError as exc:
                raise _CaptureFailure("file_unreadable") from exc
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_REPOSITORY_FILE_BYTES:
                raise _CaptureFailure("file_oversized")
            if count_toward_total and state.total_bytes + total > MAX_REPOSITORY_TOTAL_BYTES:
                raise _CaptureFailure("total_size_limit")
            digest.update(chunk)
            if len(prefix) < MAX_MAGIC_BYTES:
                prefix.extend(chunk[: MAX_MAGIC_BYTES - len(prefix)])

        pe_valid = _valid_pe_signature(file_fd, bytes(prefix), total)
        after = os.fstat(file_fd)
        try:
            current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            raise _CaptureFailure("file_changed") from exc
        if (
            total != after.st_size
            or _file_identity(before) != _file_identity(after)
            or _file_identity(after) != _file_identity(current)
        ):
            raise _CaptureFailure("file_changed")
        if count_toward_total:
            state.total_bytes += total
        return (
            digest.hexdigest(),
            bytes(prefix),
            pe_valid,
            total,
            stat.S_IMODE(after.st_mode),
        )
    finally:
        if file_fd >= 0:
            os.close(file_fd)


def _read_stable_metadata_entry(
    directory_fd: int,
    name: str,
    expected: os.stat_result,
    state: _CaptureState,
) -> Tuple[str, int, int]:
    """Bind an exact oversized declared source without reading its payload."""

    _check_deadline(state)
    file_fd = -1
    try:
        try:
            file_fd = os.open(
                name,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=directory_fd,
            )
        except OSError as exc:
            raise _CaptureFailure("file_unreadable") from exc
        before = os.fstat(file_fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or _file_identity(expected) != _file_identity(before)
        ):
            raise _CaptureFailure("file_changed")
        try:
            current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as exc:
            raise _CaptureFailure("file_changed") from exc
        after = os.fstat(file_fd)
        if (
            _file_identity(before) != _file_identity(after)
            or _file_identity(after) != _file_identity(current)
        ):
            raise _CaptureFailure("file_changed")
        material = json.dumps(
            {"identity": list(_file_identity(after)), "version": "stable-metadata/1"},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return (
            hashlib.sha256(material).hexdigest(),
            int(after.st_size),
            stat.S_IMODE(after.st_mode),
        )
    finally:
        if file_fd >= 0:
            os.close(file_fd)


def _valid_pe_signature(file_fd: int, prefix: bytes, size: int) -> bool:
    if len(prefix) < 64 or prefix[:2] != b"MZ":
        return False
    offset = int.from_bytes(prefix[0x3C:0x40], "little")
    if offset < 64 or offset + 4 > size or offset > MAX_REPOSITORY_FILE_BYTES:
        return False
    if offset + 4 <= len(prefix):
        return prefix[offset:offset + 4] == b"PE\x00\x00"
    pread = getattr(os, "pread", None)
    if pread is None:
        return False
    try:
        return pread(file_fd, 4, offset) == b"PE\x00\x00"
    except OSError:
        return False


def _check_deadline(state: _CaptureState) -> None:
    if time.monotonic() > state.deadline:
        raise _CaptureFailure("elapsed_time_limit")


def _classify_artifact(prefix: bytes, *, pe_valid: bool) -> str:
    if prefix.startswith(b"\x7fELF"):
        return "elf"
    if pe_valid:
        return "pe"
    if prefix[:4] in _MACHO_MAGICS:
        return "macho"
    if prefix[:4] in _MACHO_FAT_MAGICS and _valid_macho_fat_header(prefix):
        return "macho-fat"
    if prefix.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "zip"
    if (
        len(prefix) >= 10
        and prefix[:3] == b"\x1f\x8b\x08"
        and prefix[3] & 0xE0 == 0
    ):
        return "gzip"
    if len(prefix) >= 4 and prefix[:3] == b"BZh" and prefix[3:4] in b"123456789":
        return "bzip2"
    if prefix.startswith(b"\xfd7zXZ\x00"):
        return "xz"
    if prefix.startswith(b"\x28\xb5\x2f\xfd"):
        return "zstd"
    if prefix.startswith(b"7z\xbc\xaf\x27\x1c"):
        return "7z"
    if prefix.startswith((b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00")):
        return "rar"
    if prefix.startswith(b"!<arch>\n"):
        return "ar"
    if len(prefix) >= 265 and prefix[257:262] == b"ustar":
        return "tar"
    return ""


def _valid_macho_fat_header(prefix: bytes) -> bool:
    """Disambiguate universal Mach-O from Java's shared CAFEBABE magic."""

    if len(prefix) < 8:
        return False
    byteorder = "big" if prefix[:4] in {b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"} else "little"
    architecture_count = int.from_bytes(prefix[4:8], byteorder)
    return 1 <= architecture_count <= 32


def _normalize_exclusions(values: Iterable[object]) -> Set[str]:
    normalized: Set[str] = set()
    if isinstance(values, (str, Path, PurePosixPath)):
        values = (values,)
    for value in values:
        raw = str(value).replace(os.sep, "/")
        path = PurePosixPath(raw)
        if (
            not raw
            or path.is_absolute()
            or not path.parts
            or any(part in {"", ".", ".."} or _unsafe_component(part) for part in path.parts)
        ):
            raise _CaptureFailure("invalid_exclusion")
        rendered = path.as_posix()
        if len(os.fsencode(rendered)) > MAX_REPOSITORY_PATH_BYTES:
            raise _CaptureFailure("invalid_exclusion")
        normalized.add(rendered)
    return normalized


def _skip_directory(parts: Sequence[str]) -> bool:
    name = parts[-1]
    if name in _VCS_DIRECTORIES or name in _GENERATED_OR_CACHE_DIRECTORIES:
        return True
    return len(parts) == 1 and name in _GENERATED_ROOT_DIRECTORIES


def _is_vcs_directory(parts: Sequence[str]) -> bool:
    return bool(parts and parts[-1] in _VCS_DIRECTORIES)


def _is_generated_output(parts: Sequence[str]) -> bool:
    return (
        bool(parts and parts[0] in _GENERATED_ROOT_DIRECTORIES)
        or _is_root_generated_archive(parts)
    )


def _is_root_generated_archive(parts: Sequence[str]) -> bool:
    return len(parts) == 1 and bool(_GENERATED_ARCHIVE_RE.fullmatch(parts[0]))


def _unsafe_component(value: str) -> bool:
    return (
        value in {"", ".", ".."}
        or "/" in value
        or "\\" in value
        or "\x00" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    )


def _file_identity(metadata: os.stat_result) -> Tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
    )


def _directory_identity(metadata: os.stat_result) -> Tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
        metadata.st_gid,
    )


def _manifest_entry(
    relative_path: str,
    entry_type: str,
    *,
    sha256: str = "",
    size: int = 0,
    mode: int = 0,
    artifact_kind: str = "",
    generated_output: bool = False,
    excluded: bool = False,
) -> Dict[str, object]:
    return {
        "artifact_kind": artifact_kind,
        "excluded": bool(excluded),
        "generated_output": bool(generated_output),
        "mode": int(mode),
        "relative_path": relative_path,
        "sha256": sha256,
        "size": int(size),
        "type": entry_type,
    }


def _build_snapshot(
    status: str,
    error_code: str,
    entries: Sequence[Dict[str, object]],
    artifacts: Sequence[RepositoryArtifact],
    entry_count: int,
    excluded_paths: Sequence[str],
    excluded_subtree_paths: Sequence[str] = (),
    independently_bound_paths: Sequence[str] = (),
    required_paths: Sequence[str] = (),
) -> RepositorySnapshot:
    ordered_entries = sorted(
        (dict(entry) for entry in entries),
        key=lambda item: (str(item.get("relative_path", "")), str(item.get("type", ""))),
    )
    material = {
        # Pruned VCS/build/cache paths remain subject to the traversal entry
        # bound but do not participate in the trusted repository identity.
        "manifest_entry_count": len(ordered_entries),
        "entries": ordered_entries,
        "error_code": error_code,
        # Requested paths are derived from the separately bound PKGBUILD and
        # hook snapshots.  Bind only entries actually observed; absent remote
        # cache filenames must not masquerade as a filesystem provenance
        # change during an ordinary version bump.
        "snapshot_version": REPOSITORY_SNAPSHOT_VERSION,
        "status": status,
    }
    encoded = json.dumps(
        material,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return RepositorySnapshot(
        status=status,
        input_digest=hashlib.sha256(encoded).hexdigest(),
        artifacts=tuple(sorted(
            artifacts,
            key=lambda artifact: (artifact.relative_path, artifact.kind, artifact.sha256),
        )),
        error_code=error_code,
        entry_count=int(entry_count),
    )
