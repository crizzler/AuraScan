"""Local, static pnpm advisory checks; neither pnpm nor package code is run.

The installed package record is evidence about the local system package, not
proof of the executable selected by a future shell, Corepack, or project pin.
Upstream advisories: GHSA-c59q-g84q-2gj5 and GHSA-vq4v-j7r6-jq4m.
"""

import hashlib
import os
import re
import shlex
import stat
from dataclasses import dataclass
from itertools import chain
from pathlib import Path
from typing import Callable, List, Optional, Sequence, Tuple

from aurascan.analyzers.aur_propagation import (
    _active_shell_text, _line_starts, _logical_shell_views,
)
from aurascan.analyzers.remote_stage import _bounded_env_split_tokens, _collect_commands
from aurascan.core.models import (
    Confidence, EvidenceQuality, Finding, Phase, Severity, Source,
)
from aurascan.core.trusted_tools import (
    TrustedToolError, capture_trusted_system_tool,
    revalidate_trusted_system_tool, run_bounded_trusted_tool,
)


DEFAULT_PNPM_DB_ROOT = Path("/var/lib/pacman/local")
MAX_DB_ENTRIES = 32768
MAX_DESC_BYTES = 64 * 1024
MAX_CONTROL_BYTES = 5 * 1024 * 1024
_VERSION = re.compile(r"(?:(?:0|[1-9][0-9]*):)?(?P<upstream>[0-9]+\.[0-9]+\.[0-9]+)(?:-[0-9]+(?:\.[0-9]+)*)?\Z")
_OPERATIONS = {"install", "i", "add", "a", "fetch", "update", "up", "upgrade", "import", "dedupe", "dlx"}
_VALUE_OPTIONS = {"-C", "--dir", "--filter", "-F", "--workspace-root-dir"}
_FLAG_OPTIONS = {"-r", "--recursive", "-w", "--workspace-root", "--offline", "--ignore-scripts", "--frozen-lockfile", "--prefer-offline", "--silent"}


@dataclass(frozen=True)
class PnpmBuildchainCheck:
    relevant: bool
    identity: str
    findings: Tuple[Finding, ...]


@dataclass(frozen=True)
class _Invocation:
    path: str
    line: int
    phase: Phase
    ambiguous: bool


def analyze_pnpm_buildchain(
    controls: Sequence[Tuple[str, str, Phase]],
    *,
    local_db_root: Optional[Path] = None,
    version_compare: Optional[Callable[[str, str], Optional[int]]] = None,
) -> PnpmBuildchainCheck:
    """Review captured control text using bounded local package DB evidence.

    Call on shell control text only, never arbitrary documentation or JSON.
    An unknown state is coverage failure, not a vulnerable-version assertion.
    """
    invocations: List[_Invocation] = []
    for path, text, phase in controls:
        if len(text) > MAX_CONTROL_BYTES:
            invocations.append(_Invocation(path, 1, phase, True))
            continue
        active = _active_shell_text(text)
        raw, command_view = _logical_shell_views(active)
        raw, command_view = _mask_wrapper_queries(raw, command_view)
        commands, complete = _collect_commands(raw, command_view, _line_starts(text))
        if not complete:
            # The shared deterministic control parser also reports incomplete
            # coverage. Never consult the package database for inert mentions.
            if re.search(r"\bpnpm\b", command_view):
                invocations.append(_Invocation(path, 1, phase, True))
            continue
        for command in commands:
            executable = command.executable
            arguments = list(command.arguments)
            corepack = executable in {"corepack", "/usr/bin/corepack"}
            if corepack:
                if arguments and _pnpm_selector(arguments[0]):
                    arguments = arguments[1:]
                elif len(arguments) >= 2 and arguments[0] == "use" and _pnpm_selector(arguments[1]):
                    # Corepack `use` updates the project pin and automatically
                    # installs dependencies with the selected package manager.
                    if any(value in {"--help", "-h"} for value in arguments[2:]):
                        continue
                    invocations.append(_Invocation(path, command.line_number, phase, True))
                    continue
                else:
                    continue
            elif Path(executable).name != "pnpm":
                continue
            operation, ambiguous = _operation(arguments)
            if not operation and not ambiguous:
                continue
            invocations.append(_Invocation(
                path, command.line_number, phase,
                ambiguous or corepack or executable not in {"pnpm", "/usr/bin/pnpm"},
            ))
    if not invocations:
        return PnpmBuildchainCheck(False, "not-applicable", ())

    if any(invocation.ambiguous for invocation in invocations):
        return _result(invocations, "unresolved-invocation", "", False)
    version, identity = _read_pnpm_version(local_db_root)
    if not version:
        return _result(invocations, identity, "", False)
    affected = pnpm_version_affected(version, version_compare=version_compare)
    if affected is None:
        return _result(invocations, identity + ":version-unresolved", "", False)
    if affected:
        return _result(invocations, identity, version, True)
    return PnpmBuildchainCheck(True, identity, ())


def _pnpm_selector(value: str) -> bool:
    return value == "pnpm" or value.startswith("pnpm@")


def _mask_wrapper_queries(raw: str, command_view: str) -> Tuple[str, str]:
    """Mask inert GNU wrapper queries without hiding nested substitutions.

    The shared correlation parser unwraps env/time. Their help/version options
    instead exit before launching any following executable. Work on the same
    bounded command segments so `env --help $(pnpm install)` still exposes the
    substitution, and never inspect arguments after a different executable.
    """
    if not any(option in raw for option in ("--help", "--version", "-V")):
        return raw, command_view
    raw_chars, view_chars = list(raw), list(command_view)
    start = 0
    boundaries = ((item.start(), item.end()) for item in re.finditer(r"\$\(|\x1f|[;|&)]+", command_view))
    for count, (end, next_start) in enumerate(chain(boundaries, [(len(raw), len(raw))]), 1):
        if count > 65536:
            # The shared collector reports this command stream incomplete.
            return raw, command_view
        segment = raw[start:end]
        try:
            tokens = shlex.split(segment, comments=False, posix=True)
        except ValueError:
            tokens = []
        if _wrapper_query(tokens):
            raw_chars[start:end] = " " * (end - start)
            view_chars[start:end] = " " * (end - start)
        start = next_start
    return "".join(raw_chars), "".join(view_chars)


def _wrapper_query(tokens: Sequence[str]) -> bool:
    values = list(tokens)
    index = 0
    steps = 0
    while index < len(values) and steps < 256:
        steps += 1
        value = values[index]
        if value in {"!", "(", "{", "do", "elif", "else", "if", "then", "until", "while"} or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", value, re.S):
            index += 1
            continue
        name = Path(value).name
        if name not in {"command", "exec", "env", "time"}:
            return False
        index += 1
        while index < len(values) and steps < 256:
            steps += 1
            value = values[index]
            if value == "--":
                index += 1
                break
            if name in {"env", "time"} and value in {"--help", "--version"}:
                return True
            if name == "time" and value == "-V":
                return True
            if name == "env" and (value in {"-S", "--split-string"} or value.startswith("--split-string=")):
                inline = value.startswith("--split-string=")
                if not inline and index + 1 >= len(values):
                    return False
                argument = value.split("=", 1)[1] if inline else values[index + 1]
                expanded = _bounded_env_split_tokens(argument)
                if expanded is None or len(values) + len(expanded) > 1024:
                    return False
                values[index:index + (1 if inline else 2)] = expanded
                continue
            options_with_values = {
                "env": {"-C", "--chdir", "-u", "--unset", "-a", "--argv0"},
                "time": {"-o", "--output", "-f", "--format"},
                "exec": {"-a"}, "command": set(),
            }[name]
            if value in options_with_values:
                index += 2
                continue
            if value.startswith("-") or (name == "env" and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", value, re.S)):
                index += 1
                continue
            break
    return False


def _operation(arguments: Sequence[str]) -> Tuple[bool, bool]:
    index = 0
    operation = False
    options_ended = False
    while index < len(arguments):
        token = arguments[index]
        if not options_ended and token in {"--help", "-h", "--version", "-v"}:
            return False, False
        if not options_ended and token in _VALUE_OPTIONS:
            if index + 1 >= len(arguments):
                return False, True
            index += 2
            continue
        if not options_ended and token.startswith("--") and "=" in token:
            # Attached values cannot consume a later help flag or command.
            index += 1
            continue
        if not options_ended and token in _FLAG_OPTIONS:
            index += 1
            continue
        if not options_ended and token == "--":
            options_ended = True
            index += 1
            continue
        if not options_ended and token.startswith("-"):
            # Unknown option arity may hide the command or consume a help
            # string as data. Neither case supports an inert conclusion.
            return False, True
        if operation:
            index += 1
            continue
        if "$" in token or "`" in token:
            return False, True
        # Other commands, including `run install` and command lookup, are not
        # dependency resolution. Their script contents are a different surface.
        if token not in _OPERATIONS:
            return False, False
        operation = True
        index += 1
    # Bare pnpm displays help rather than resolving dependencies.
    return operation, False


def pnpm_version_affected(
    version: str,
    *,
    version_compare: Optional[Callable[[str, str], Optional[int]]] = None,
) -> Optional[bool]:
    """Compare the upstream part of a supported Arch epoch:pkgver-pkgrel.

    Epoch and pkgrel order distro revisions; neither changes the upstream
    vulnerability range. Unsupported prerelease/custom versions stay unknown.
    Native comparison uses only the bounded trusted absolute Arch vercmp.
    """
    if len(version) > 128:
        return None
    match = _VERSION.fullmatch(version)
    if not match:
        return None
    upstream = match.group("upstream")
    compare = version_compare or _trusted_vercmp
    try:
        lower = compare(upstream, "10.34.5")
        eleven = compare(upstream, "11.0.0")
        patched = compare(upstream, "11.11.0")
    except Exception:
        return None
    if any(type(value) is not int or value not in {-1, 0, 1} for value in (lower, eleven, patched)):
        return None
    return lower < 0 or (eleven >= 0 and patched < 0)


def _trusted_vercmp(left: str, right: str) -> Optional[int]:
    try:
        tool = capture_trusted_system_tool("vercmp", which=lambda _name: "/usr/bin/vercmp")
        if tool is None:
            return None
        revalidate_trusted_system_tool(tool)
        result = run_bounded_trusted_tool(
            [tool.path, left, right], capture_output=True, text=True,
            timeout=2, check=False, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        revalidate_trusted_system_tool(tool)
        if result.returncode or result.stderr or result.stdout.strip() not in {"-1", "0", "1"}:
            return None
        return int(result.stdout.strip())
    except (OSError, ValueError, TrustedToolError):
        return None


def _identity(metadata: os.stat_result) -> Tuple[int, ...]:
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid,
            metadata.st_gid, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)


def _read_pnpm_version(local_db_root: Optional[Path]) -> Tuple[str, str]:
    root = Path(local_db_root) if local_db_root is not None else DEFAULT_PNPM_DB_ROOT
    strict_owner = local_db_root is None
    descriptors: List[int] = []
    chain = []
    try:
        if not root.is_absolute() or ".." in root.parts or not hasattr(os, "O_NOFOLLOW"):
            return "", "database-unavailable"
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        parent = os.open("/", flags)
        descriptors.append(parent)
        for component in root.parts[1:]:
            child = os.open(component, flags, dir_fd=parent)
            descriptors.append(child)
            metadata = os.fstat(child)
            if strict_owner and (metadata.st_uid != 0 or metadata.st_mode & 0o022):
                return "", "database-unsafe"
            # Ancestor sibling activity is unrelated to this database. Bind
            # their inode and permissions; bind complete content metadata for
            # the selected DB root and pnpm entry separately below.
            chain.append((parent, component, child, _identity(metadata)[:5]))
            parent = child
        before = _identity(os.fstat(parent))
        candidates = []
        with os.scandir(parent) as entries:
            for count, entry in enumerate(entries, 1):
                if count > MAX_DB_ENTRIES:
                    return "", "database-limit"
                if entry.name.startswith("pnpm-"):
                    candidates.append(entry.name)
                    if len(candidates) > 8:
                        return "", "database-ambiguous"
        records = []
        for name in candidates:
            directory = os.open(name, flags, dir_fd=parent)
            descriptors.append(directory)
            directory_before = _identity(os.fstat(directory))
            descriptor = os.open("desc", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory)
            descriptors.append(descriptor)
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_DESC_BYTES:
                return "", "database-unsafe"
            if strict_owner and any(item.st_uid != 0 or item.st_mode & 0o022 for item in (metadata, os.fstat(directory))):
                return "", "database-unsafe"
            data = bytearray()
            while len(data) <= MAX_DESC_BYTES:
                chunk = os.read(descriptor, min(16384, MAX_DESC_BYTES + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            if (len(data) > MAX_DESC_BYTES or _identity(os.fstat(descriptor)) != _identity(metadata)
                    or _identity(os.stat("desc", dir_fd=directory, follow_symlinks=False)) != _identity(metadata)
                    or _identity(os.fstat(directory)) != directory_before
                    or _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != directory_before):
                return "", "database-changed"
            package, version = _parse_desc(bytes(data))
            if not package or not version:
                return "", "database-malformed"
            if package == "pnpm":
                if name != "pnpm-" + version:
                    return "", "database-malformed"
                records.append((version, hashlib.sha256(bytes(data)).hexdigest(), _identity(metadata)))
        if _identity(os.fstat(parent)) != before:
            return "", "database-changed"
        for parent_fd, component, child_fd, identity in chain:
            if (_identity(os.fstat(child_fd))[:5] != identity
                    or _identity(os.stat(component, dir_fd=parent_fd, follow_symlinks=False))[:5] != identity):
                return "", "database-changed"
        if len(records) != 1:
            return "", "database-missing-pnpm" if not records else "database-ambiguous"
        version, digest, identity = records[0]
        return version, hashlib.sha256(repr((version, digest, identity)).encode("ascii")).hexdigest()
    except (OSError, ValueError, UnicodeError):
        return "", "database-unavailable"
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _parse_desc(data: bytes) -> Tuple[str, str]:
    text = data.decode("utf-8", errors="strict")
    fields = {}
    for section in text.strip().split("\n\n"):
        lines = section.splitlines()
        if lines and lines[0] in {"%NAME%", "%VERSION%"}:
            if len(lines) != 2 or lines[0] in fields:
                return "", ""
            fields[lines[0]] = lines[1]
    name, version = fields.get("%NAME%", ""), fields.get("%VERSION%", "")
    if not re.fullmatch(r"[a-z0-9@._+-]{1,128}", name) or not _VERSION.fullmatch(version) or len(version) > 128:
        return "", ""
    return name, version


def _result(invocations: Sequence[_Invocation], identity: str, version: str, affected: bool) -> PnpmBuildchainCheck:
    invocation = next((item for item in invocations if item.ambiguous), invocations[0])
    if affected:
        rule_id = "PNPM-VULNERABLE-BUILDCHAIN-001"
        explanation = (
            "Package control text invokes pnpm dependency resolution and the local pacman database "
            "records pnpm " + version + " in the affected upstream ranges for CVE-2026-82392 "
            "and CVE-2026-82393. Hostile lockfile or dependency metadata can redirect writes; "
            "--ignore-scripts does not remove the latter risk. This is not evidence of exploitation "
            "or proof of the executable a future build selects."
        )
        recommendation = "Use a verified patched build environment before processing untrusted dependencies; the upstream fixes are 10.34.5 and 11.11.0."
    else:
        rule_id = "PNPM-BUILDCHAIN-CONTEXT-INCOMPLETE-001"
        explanation = (
            "Package control text references a pnpm operation whose installed build-tool version "
            "could not be established from bounded local evidence. Missing, ambiguous, custom, "
            "or redirected toolchain context does not establish a vulnerable version or exploitation."
        )
        recommendation = "Establish a verified patched pnpm installation and a stable local package database, then repeat the scan in the intended build environment."
    finding = Finding(
        rule_id=rule_id, package_name="unknown", package_version="unknown",
        phase=invocation.phase, source=Source.deterministic_rule, severity=Severity.HIGH,
        confidence=Confidence.HIGH, evidence_quality=EvidenceQuality.confirmed_static_pattern,
        file_path=invocation.path, explanation=explanation, recommendation=recommendation,
        blocks_installation=True, requires_manual_review=False, line_number=invocation.line,
        evidence_snippet="active pnpm dependency operation; " + ("affected installed package version" if affected else "incomplete local build-tool evidence"),
    )
    return PnpmBuildchainCheck(True, identity, (finding,))
