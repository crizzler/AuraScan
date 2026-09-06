"""Bounded, data-only checks for package names used as filesystem components.

The lockfile reader deliberately supports a small YAML subset, not YAML object
construction. Unsupported syntax and ambiguous shapes are coverage failures.
No registry, package manager, YAML dependency, or package code is invoked.
"""

import json
import ntpath
import posixpath
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from aurascan.core.models import (
    Confidence, EvidenceQuality, Finding, Phase, Severity, Source,
)

MAX_METADATA_BYTES = 1024 * 1024
MAX_NODES = 30000
MAX_DEPTH = 48
MAX_SCALAR = 16384
_COMPONENT = re.compile(r"[A-Za-z0-9~][A-Za-z0-9._~!()*-]*\Z")
_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?\Z")


class MetadataIncomplete(ValueError):
    """An input is outside the supported, unambiguous metadata grammar."""


def strict_json_object(text: str) -> Dict[str, Any]:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise MetadataIncomplete("duplicate field")
            result[key] = value
        return result

    def reject_constant(_value):
        raise MetadataIncomplete("non-JSON constant")

    try:
        if len(text.encode("utf-8")) > MAX_METADATA_BYTES:
            raise MetadataIncomplete("metadata size")
        value = json.loads(text, object_pairs_hook=unique, parse_constant=reject_constant)
    except (ValueError, RecursionError, UnicodeError):
        raise MetadataIncomplete("invalid JSON") from None
    if not isinstance(value, dict):
        raise MetadataIncomplete("expected object")
    return value


def package_name_status(value: Any) -> str:
    """Return valid, unsafe-path, or unsupported; never expose the value."""
    if not isinstance(value, str) or not value or len(value) > MAX_SCALAR:
        return "unsupported"
    # Check path semantics independently of npm identifier syntax. A scope is
    # the one supported two-component spelling; no other separators are valid.
    parts = value.split("/")
    expected_parts = 2 if value.startswith("@") else 1
    base = "/node_modules"
    joined = posixpath.normpath(posixpath.join(base, value))
    if (
        "\\" in value or ntpath.splitdrive(value)[0]
        or value.startswith("/")
        or any(part in {".", ".."} for part in parts)
        or not joined.startswith(base + "/")
    ):
        return "unsafe-path"
    if len(parts) != expected_parts or any(not part for part in parts):
        return "unsupported"
    if value.startswith("@"):
        parts[0] = parts[0][1:]
    if len(value) > 214 or not all(_COMPONENT.fullmatch(part) for part in parts):
        return "unsupported"
    return "valid"


@dataclass
class _Node:
    value: Any
    line: int


class _LockfileReader:
    """Literal block/flow mappings, scalar sequences, and quoted/plain scalars.

    Anchors, aliases, tags, merge keys, directives, multiline scalars/flows,
    implicit complex keys, duplicate keys, and multiple documents are refused.
    Scalar values stay strings: no YAML implicit typing or construction occurs.
    """

    def __init__(self, text: str):
        if len(text.encode("utf-8")) > MAX_METADATA_BYTES:
            raise MetadataIncomplete("metadata size")
        self.lines = []  # type: List[Tuple[int, int, str]]
        self.nodes = 0
        for number, raw in enumerate(text.split("\n"), 1):
            raw = raw[:-1] if raw.endswith("\r") else raw
            if any(ord(char) < 32 and char != "\t" for char in raw):
                raise MetadataIncomplete("control character")
            content = raw.lstrip(" ")
            if not content or content.startswith("#"):
                continue
            if "\t" in raw or len(raw) > MAX_SCALAR:
                raise MetadataIncomplete("unsupported line")
            if content in {"---", "..."} or content.startswith("%"):
                raise MetadataIncomplete("document syntax")
            self.lines.append((len(raw) - len(content), number, content))
            if len(self.lines) > MAX_NODES:
                raise MetadataIncomplete("line bound")

    def node(self, value: Any, line: int) -> _Node:
        self.nodes += 1
        if self.nodes > MAX_NODES:
            raise MetadataIncomplete("node bound")
        return _Node(value, line)

    def scalar(self, text: str, pos: int, key: bool) -> Tuple[str, int]:
        start = pos
        if pos >= len(text):
            raise MetadataIncomplete("missing scalar")
        quote = text[pos] if text[pos] in "\"'" else ""
        if quote:
            pos += 1
            while pos < len(text):
                if quote == '"' and text[pos] == "\\":
                    pos += 2
                    continue
                if text[pos] == quote:
                    if quote == "'" and text[pos:pos + 2] == "''":
                        pos += 2
                        continue
                    token = text[start:pos + 1]
                    try:
                        value = json.loads(token) if quote == '"' else token[1:-1].replace("''", "'")
                    except (ValueError, RecursionError):
                        raise MetadataIncomplete("quoted scalar") from None
                    return value, pos + 1
                pos += 1
            raise MetadataIncomplete("unterminated scalar")
        if text[pos] in "&*!|>{[?`@%" or text[pos:] == "-":
            # Plain scoped npm names start with @; YAML requires these keys to
            # be quoted, as the pnpm writer does.
            raise MetadataIncomplete("unsupported scalar")
        while pos < len(text):
            char = text[pos]
            if char in ",{}[]" or (char == "#" and (pos == start or text[pos - 1].isspace())):
                break
            if char == ":" and (key or pos + 1 == len(text) or text[pos + 1].isspace()):
                break
            pos += 1
        value = text[start:pos].strip()
        if not value or value == "<<":
            raise MetadataIncomplete("unsupported scalar")
        return value, pos

    @staticmethod
    def spaces(text: str, pos: int) -> int:
        while pos < len(text) and text[pos] == " ":
            pos += 1
        return pos

    def inline(self, text: str, pos: int, line: int, depth: int) -> Tuple[_Node, int]:
        if depth > MAX_DEPTH:
            raise MetadataIncomplete("depth bound")
        pos = self.spaces(text, pos)
        if pos == len(text) or text[pos] == "#":
            return self.node(None, line), pos
        if text[pos] not in "{[":
            value, pos = self.scalar(text, pos, False)
            return self.node(value, line), pos
        mapping = text[pos] == "{"
        closing = "}" if mapping else "]"
        container = {} if mapping else []
        pos = self.spaces(text, pos + 1)
        while pos < len(text) and text[pos] != closing:
            if mapping:
                key, pos = self.scalar(text, pos, True)
                pos = self.spaces(text, pos)
                if key == "<<" or key in container or pos == len(text) or text[pos] != ":":
                    raise MetadataIncomplete("mapping key")
                pos += 1
            value, pos = self.inline(text, pos, line, depth + 1)
            if mapping:
                container[key] = value
            else:
                container.append(value)
            pos = self.spaces(text, pos)
            if pos < len(text) and text[pos] == closing:
                break
            if pos == len(text) or text[pos] != ",":
                raise MetadataIncomplete("flow separator")
            pos = self.spaces(text, pos + 1)
        if pos == len(text):
            raise MetadataIncomplete("unterminated flow")
        return self.node(container, line), pos + 1

    def block(self, index: int, indent: int, depth: int) -> Tuple[_Node, int]:
        if depth > MAX_DEPTH:
            raise MetadataIncomplete("depth bound")
        sequence = self.lines[index][2].startswith("- ")
        result = [] if sequence else {}
        first_line = self.lines[index][1]
        while index < len(self.lines):
            actual_indent, line, text = self.lines[index]
            if actual_indent < indent:
                break
            if actual_indent != indent:
                raise MetadataIncomplete("inconsistent indentation")
            if sequence:
                if not text.startswith("- "):
                    raise MetadataIncomplete("mixed sequence")
                pos = 2
            else:
                key, pos = self.scalar(text, 0, True)
                pos = self.spaces(text, pos)
                if key == "<<" or key in result or pos == len(text) or text[pos] != ":":
                    raise MetadataIncomplete("mapping key")
                pos += 1
                if pos < len(text) and text[pos] != " ":
                    raise MetadataIncomplete("block separator")
            value, pos = self.inline(text, pos, line, depth + 1)
            pos = self.spaces(text, pos)
            if pos < len(text) and text[pos] != "#":
                raise MetadataIncomplete("trailing scalar")
            index += 1
            if index < len(self.lines) and self.lines[index][0] > indent:
                if value.value is not None:
                    raise MetadataIncomplete("scalar with children")
                value, index = self.block(index, self.lines[index][0], depth + 1)
                value.line = line
            if sequence:
                result.append(value)
            else:
                result[key] = value
        return self.node(result, first_line), index

    def read(self) -> _Node:
        if not self.lines or self.lines[0][0] != 0:
            raise MetadataIncomplete("missing root")
        result, index = self.block(0, 0, 0)
        if index != len(self.lines) or not isinstance(result.value, dict):
            raise MetadataIncomplete("invalid root")
        return result


def _mapping(node: _Node) -> Dict[str, _Node]:
    if not isinstance(node.value, dict):
        raise MetadataIncomplete("expected mapping")
    return node.value


def _dependency_path(key: str, legacy: bool, depth: int = 0) -> str:
    if depth > MAX_DEPTH:
        raise MetadataIncomplete("peer depth")
    if legacy:
        parts = key.split("/")
        count = 2 if key.startswith("@") else 1
        if len(parts) != count + 1:
            raise MetadataIncomplete("unsupported legacy dependency path")
        name, suffix = "/".join(parts[:count]), parts[-1]
    else:
        split_at = key.find("@", 1)
        if split_at < 0 or split_at == len(key) - 1:
            raise MetadataIncomplete("unsupported dependency path")
        name, suffix = key[:split_at], key[split_at + 1:]
    # Preserve a directly observed traversal-shaped name even if its opaque
    # resolution suffix is unsupported; it is still a decoded name field.
    if package_name_status(name) == "unsafe-path":
        return name
    version = suffix.split("(", 1)[0]
    if not _VERSION.fullmatch(version):
        raise MetadataIncomplete("unsupported version or source reference")
    pos = len(version)
    while pos < len(suffix):
        if suffix[pos] != "(":
            raise MetadataIncomplete("unsupported peer suffix")
        start = pos + 1
        nesting = 1
        pos += 1
        while pos < len(suffix) and nesting:
            nesting += (suffix[pos] == "(") - (suffix[pos] == ")")
            if nesting > MAX_DEPTH:
                raise MetadataIncomplete("peer depth")
            pos += 1
        if nesting:
            raise MetadataIncomplete("unterminated peer suffix")
        peer = _dependency_path(suffix[start:pos - 1], False, depth + 1)
        if package_name_status(peer) != "valid":
            raise MetadataIncomplete("unsupported peer identifier")
    return name


def _lockfile_names(text: str) -> List[Tuple[Any, int]]:
    root = _mapping(_LockfileReader(text).read())
    version = root.get("lockfileVersion", _Node(None, 1)).value
    if not isinstance(version, str) or version not in {"5.3", "5.4", "6.0", "9.0"}:
        raise MetadataIncomplete("unsupported lockfile version")
    names = []  # type: List[Tuple[Any, int]]

    def dependencies(node: _Node):
        for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            if field in _mapping(node):
                names.extend((name, value.line) for name, value in _mapping(node.value[field]).items())

    dependencies(_Node(root, 1))
    for importer in _mapping(root.get("importers", _Node({}, 1))).values():
        dependencies(importer)
    for field in ("packages", "snapshots"):
        for key, value in _mapping(root.get(field, _Node({}, 1))).items():
            entry = _mapping(value)
            candidate = key
            if version in {"5.3", "5.4", "6.0"} and candidate.startswith("/"):
                candidate = candidate[1:]
            name = _dependency_path(candidate, version in {"5.3", "5.4"})
            names.append((name, value.line))
            if "name" in entry:
                names.append((entry["name"].value, entry["name"].line))
            dependencies(value)
    return names


def _finding(rule_id: str, path: str, severity: Severity, line: Optional[int], explanation: str) -> Finding:
    return Finding(
        rule_id=rule_id, package_name="unknown", package_version="unknown",
        phase=Phase.unpacked_source_scan, source=Source.deterministic_rule,
        severity=severity, confidence=Confidence.HIGH,
        evidence_quality=EvidenceQuality.confirmed_static_pattern if severity == Severity.CRITICAL else EvidenceQuality.strong_heuristic,
        file_path=path, line_number=line,
        evidence_snippet="bounded package metadata field validation",
        explanation=explanation,
        recommendation="Do not build until the package metadata and dependency provenance have been independently reviewed. Disabling lifecycle scripts does not prevent metadata-driven file writes.",
        blocks_installation=True, requires_manual_review=False,
    )


def inspect_npm_metadata(path: str, text: str, *, lockfile: bool = False) -> List[Finding]:
    """Check only structural name fields, with fixed, secret-free findings."""
    try:
        if lockfile:
            names = _lockfile_names(text)
        else:
            manifest = strict_json_object(text)
            names = [(manifest["name"], None)] if "name" in manifest else []
        for value, line in names:
            status = package_name_status(value)
            if status == "unsafe-path":
                return [_finding(
                    "PNPM-LOCKFILE-PATH-ESCAPE-001" if lockfile else "NPM-MANIFEST-NAME-PATH-ESCAPE-001",
                    path, Severity.CRITICAL, line,
                    "A decoded package-name field contains traversal, an absolute path, or filesystem components outside supported npm scope/name syntax. This is static metadata evidence; no installation or file write was observed.",
                )]
            if status != "valid":
                raise MetadataIncomplete("unsupported package identifier")
    except (MetadataIncomplete, UnicodeError, RecursionError):
        return [_finding(
            "NPM-METADATA-INSPECTION-INCOMPLETE-001", path, Severity.HIGH, None,
            "Package metadata could not be completely inspected within the bounded JSON or supported literal pnpm YAML grammar. This is missing coverage, not evidence of malicious behavior.",
        )]
    return []
