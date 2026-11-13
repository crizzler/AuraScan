"""Read-only blast-radius facts for external AI coding agents.

This module is deliberately not a model scanner. It reports the execution
authority and project secret classes visible to one explicitly selected agent
surface. It never imports, runs or contacts the agent, a model, an MCP server,
or the selected project's code.

The report is a snapshot. Same-UID code can change the files after capture; the
digest is a consistency check, not proof of authenticity.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass, field
from datetime import datetime, timezone

from aurascan.core.agent import (
    AGENT_FORBIDDEN_PROGRAMS,
    AGENT_REMOTE_REFERENCE_RE,
    AGENT_SENSITIVE_PATH_RE,
)
from aurascan.core.rule_metadata import RULE_METADATA
from aurascan.core.text_safety import sanitize_terminal_text

SCHEMA = "agent-runtime-audit/1.0"
MAX_CONFIG_BYTES = 262144
MAX_JSON_NODES = 20000
MAX_JSON_DEPTH = 64
MAX_TOML_LINES = 4096
MAX_TOML_VALUE_LINES = 64

EXIT_CLEAR = 0
EXIT_AUTHORITY = 1
EXIT_USAGE = 2
EXIT_INCOMPLETE = 3
EXIT_SCHEMA = 4

MODEL_SAFETY_BANNER = (
    "This is not a model-safety verdict. A backdoored model can pass every "
    "configuration check. This report describes execution authority and readable "
    "secrets within the inspected scope."
)

SURFACE_FILES = {
    "codex": (
        (".codex/config.toml", "toml"),
    ),
    "claude": (
        (".claude/settings.json", "jsonc"),
        (".claude/settings.local.json", "jsonc"),
    ),
    "cursor": (
        (".cursor/mcp.json", "jsonc"),
        (".cursor/permissions.json", "jsonc"),
        (".cursor/hooks.json", "jsonc"),
    ),
    "mcp": (
        (".mcp.json", "jsonc"),
    ),
}
BUILTIN_SHELL_SURFACES = frozenset({"codex", "claude", "cursor"})

# Exact project-relative candidates. No directory walk is performed. The
# report never emits these paths, values, sizes or digests.
SECRET_CANDIDATES = (
    ("project-env", (
        ".env", ".env.local", ".env.development", ".env.production",
        ".env.test", ".env.staging", ".envrc",
    )),
    ("vcs-credential", (
        ".git-credentials", ".npmrc", ".pypirc", ".netrc", ".authinfo",
    )),
    ("agent-auth", (
        ".claude/.credentials.json", ".claude.json", ".codex/auth.json",
        ".cursor/cli-config.json", ".config/gh/hosts.yml",
        ".docker/config.json",
    )),
    ("ssh-private-key", (
        ".ssh/id_rsa", ".ssh/id_ed25519", ".ssh/id_ecdsa", ".ssh/id_dsa",
    )),
    ("cloud-credential", (
        ".aws/credentials",
        ".config/gcloud/application_default_credentials.json",
        ".azure/accessTokens.json",
    )),
)
NON_SECRET_ENV_EXAMPLES = frozenset({
    ".env.example", ".env.template", ".env.sample",
})

# This is the vocabulary A0 actually relies on for its built-in shell
# statement and its read-only reuse of the repair agent's policy. The category
# map and the required set are checked in both directions by the parity test.
AGENT_AUDIT_PROGRAM_CATEGORIES = {
    "shell": frozenset({"bash", "sh", "zsh", "fish", "dash", "ksh"}),
    "interpreter": frozenset({
        "python", "python3", "perl", "ruby", "php", "node", "deno", "lua",
    }),
    "network": frozenset({
        "curl", "wget", "ssh", "scp", "sftp", "nc", "ncat", "socat", "telnet",
    }),
}
AGENT_AUDIT_REQUIRED_PROGRAMS = frozenset().union(
    *AGENT_AUDIT_PROGRAM_CATEGORIES.values()
)

_VALID_SURFACES = frozenset(SURFACE_FILES)
_SECRET_PATH_COMPONENT_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


class AgentAuditError(Exception):
    """Base exception for a typed audit failure."""


class AgentAuditUsageError(AgentAuditError):
    """The caller supplied an invalid root or surface."""


class AgentAuditSchemaError(AgentAuditError):
    """The report could not be serialized into the fixed schema."""


class _ParseError(ValueError):
    """A fixed, secret-free parser failure."""

    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class AuditInput:
    path: str
    device: int = 0
    inode: int = 0
    size: int = 0
    sha256: str = ""
    status: str = "missing"

    def to_dict(self):
        return {
            "path": self.path,
            "device": self.device,
            "inode": self.inode,
            "size": self.size,
            "sha256": self.sha256,
            "status": self.status,
        }


@dataclass(frozen=True)
class SourceLocation:
    path: str
    line_start: int = 1
    line_end: int = 1
    sha256: str = ""

    def to_dict(self):
        return {
            "path": self.path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class ExecutionChannel:
    kind: str
    source: SourceLocation

    def to_dict(self):
        return {"kind": self.kind, "source": self.source.to_dict()}


@dataclass(frozen=True)
class ApprovalMode:
    normalized: str = "default"
    raw: str = "<default>"
    evidence: str = "default"

    def to_dict(self):
        return {
            "normalized": self.normalized,
            "raw": self.raw,
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class SecretClass:
    secret_class: str
    scope: str = "project"
    count: int = 1
    evidence: str = "observed"

    def to_dict(self):
        return {
            "class": self.secret_class,
            "scope": self.scope,
            "count": self.count,
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class FindingRecord:
    rule_id: str
    severity: str
    confidence: str
    evidence: str
    reason_id: str
    source: SourceLocation

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "reason_id": self.reason_id,
            "source": self.source.to_dict(),
        }


@dataclass
class AuditReport:
    root: str
    surface: str
    captured_at: str
    inputs: list[AuditInput] = field(default_factory=list)
    channels: list[ExecutionChannel] = field(default_factory=list)
    approval: ApprovalMode = field(default_factory=ApprovalMode)
    secrets: list[SecretClass] = field(default_factory=list)
    findings: list[FindingRecord] = field(default_factory=list)
    selected: list[str] = field(default_factory=list)
    parsed: list[str] = field(default_factory=list)
    incomplete: list[str] = field(default_factory=list)
    not_inspected: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    coverage_complete: bool = False
    not_verified: list[str] = field(default_factory=list)
    evidence_digest: str = ""

    @property
    def execution_authority(self):
        return bool(self.channels)

    @property
    def aggregate_status(self):
        if not self.execution_authority or not self.secrets:
            return "not-observed"
        # A0 has no OS-level proof of isolation. It never upgrades a declared
        # sandbox flag into evidence, so the honest aggregate is unresolved.
        return "cannot-rule-out"

    @property
    def exit_code(self):
        if not self.coverage_complete:
            return EXIT_INCOMPLETE
        if self.execution_authority:
            return EXIT_AUTHORITY
        return EXIT_CLEAR

    def to_dict(self):
        facts = {
            "execution_authority": {
                "observed": self.execution_authority,
                "channels": [item.to_dict() for item in self.channels],
                "approval_mode": self.approval.to_dict(),
            },
            "secret_classes_readable": [item.to_dict() for item in self.secrets],
            "host_isolation": {"state": "unknown", "evidence": "unknown"},
        }
        aggregate = {
            "rule_id": "AGENT-CREDENTIAL-EXFIL-RISK-001",
            "status": self.aggregate_status,
            "contributing": (
                ["AGENT-EXEC-AUTHORITY-001", "AGENT-SECRET-CLASS-READABLE-001"]
                if self.execution_authority and self.secrets else []
            ),
        }
        data = {
            "schema": SCHEMA,
            "banner": MODEL_SAFETY_BANNER,
            "root": sanitize_terminal_text(self.root),
            "surface": self.surface,
            "captured_at": self.captured_at,
            "inputs": [item.to_dict() for item in self.inputs],
            "facts": facts,
            "findings": [item.to_dict() for item in self.findings],
            "aggregate": aggregate,
            "coverage": {
                "selected": list(self.selected),
                "parsed": list(self.parsed),
                "incomplete": list(self.incomplete),
                "not_inspected": list(self.not_inspected),
                "coverage_complete": self.coverage_complete,
                "reasons": list(self.reasons),
            },
            "not_verified": list(self.not_verified),
        }
        return data

    def with_digest(self):
        data = self.to_dict()
        encoded = json.dumps(
            data, sort_keys=True, ensure_ascii=True, separators=(",", ":")
        ).encode("utf-8")
        self.evidence_digest = hashlib.sha256(encoded).hexdigest()
        return self

    def serializable(self):
        data = self.to_dict()
        data["evidence_digest"] = self.evidence_digest
        return data


def _now_utc():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _safe_relative(relative):
    if not isinstance(relative, str) or not relative:
        raise AgentAuditUsageError("surface path is empty")
    parts = relative.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise AgentAuditUsageError("surface path is not bounded")
    if not all(_SECRET_PATH_COMPONENT_RE.fullmatch(part) for part in parts):
        raise AgentAuditUsageError("surface path contains unsupported characters")
    return "/".join(parts)


def _open_root(root):
    if not isinstance(root, str) or not root:
        raise AgentAuditUsageError("root is empty")
    root = os.path.abspath(root)
    try:
        fd = os.open(
            root,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
        )
    except OSError:
        raise AgentAuditUsageError("root is not a readable directory")
    try:
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode):
            raise AgentAuditUsageError("root is not a directory")
    except Exception:
        os.close(fd)
        raise
    return root, fd


def _read_bounded(root, relative):
    """Read one regular file without following any symlink component.

    Returns (bytes, device, inode, size, sha256) on success. Raises a fixed
    ``_ParseError`` for every mismatch so callers never see a raw path or errno.
    """
    parts = relative.split("/")
    current = None
    try:
        current = os.open(
            root,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        for component in parts[:-1]:
            next_fd = os.open(
                component,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                dir_fd=current,
            )
            os.close(current)
            current = next_fd
        file_fd = os.open(
            parts[-1],
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0),
            dir_fd=current,
        )
    except OSError as exc:
        if getattr(exc, "errno", None) in (2, 20, 40):
            raise _ParseError("path-missing-or-link")
        raise _ParseError("path-unreadable")
    finally:
        if current is not None:
            try:
                os.close(current)
            except OSError:
                pass
    try:
        before = os.fstat(file_fd)
        if not stat.S_ISREG(before.st_mode):
            raise _ParseError("path-not-regular")
        if before.st_size > MAX_CONFIG_BYTES:
            raise _ParseError("path-too-large")
        chunks = []
        total = 0
        while True:
            chunk = os.read(file_fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_CONFIG_BYTES:
                raise _ParseError("path-too-large")
            chunks.append(chunk)
        after = os.fstat(file_fd)
        if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            raise _ParseError("path-changed")
        data = b"".join(chunks)
        if len(data) != before.st_size:
            raise _ParseError("path-changed")
        return data, before.st_dev, before.st_ino, before.st_size, hashlib.sha256(data).hexdigest()
    except _ParseError:
        raise
    except OSError:
        raise _ParseError("path-unreadable")
    finally:
        try:
            os.close(file_fd)
        except OSError:
            pass


def _decode_config(data):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise _ParseError("invalid-utf8")
    if "\x00" in text:
        raise _ParseError("nul-byte")
    return text


def _json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _ParseError("duplicate-key")
        result[key] = value
    return result


def _json_constant(value):
    raise _ParseError("nonfinite-number")


def _strip_jsonc(text):
    out = []
    index = 0
    length = len(text)
    in_string = False
    quote = ""
    escape = False
    while index < length:
        char = text[index]
        if in_string:
            out.append(char)
            if escape:
                escape = False
            elif char == "\\" and quote == '"':
                escape = True
            elif char == quote:
                in_string = False
                quote = ""
            index += 1
            continue
        if char in ('"', "'"):
            in_string = True
            quote = char
            out.append(char)
            index += 1
            continue
        if char == "/" and index + 1 < length:
            if text[index + 1] == "/":
                out.append(" ")
                index += 2
                while index < length and text[index] not in "\r\n":
                    out.append(" ")
                    index += 1
                continue
            if text[index + 1] == "*":
                out.append("  ")
                index += 2
                closed = False
                while index < length:
                    if text[index] == "*" and index + 1 < length and text[index + 1] == "/":
                        out.append("  ")
                        index += 2
                        closed = True
                        break
                    out.append("\n" if text[index] in "\r\n" else " ")
                    index += 1
                if not closed:
                    raise _ParseError("unterminated-comment")
                continue
        out.append(char)
        index += 1
    if in_string:
        raise _ParseError("unterminated-string")
    stripped = "".join(out)
    # JSONC trailing commas. Replace only a comma immediately before a closer.
    result = []
    in_string = False
    quote = ""
    escape = False
    index = 0
    while index < len(stripped):
        char = stripped[index]
        if in_string:
            result.append(char)
            if escape:
                escape = False
            elif char == "\\" and quote == '"':
                escape = True
            elif char == quote:
                in_string = False
            index += 1
            continue
        if char in ('"', "'"):
            in_string = True
            quote = char
            result.append(char)
            index += 1
            continue
        if char == ",":
            next_index = index + 1
            while next_index < len(stripped) and stripped[next_index] in " \t\r\n":
                next_index += 1
            if next_index < len(stripped) and stripped[next_index] in "}]":
                result.append(" ")
                index += 1
                continue
        result.append(char)
        index += 1
    return "".join(result)


def _parse_json(text, jsonc=False):
    if len(text) > MAX_CONFIG_BYTES:
        raise _ParseError("too-large")
    source = _strip_jsonc(text) if jsonc else text
    try:
        value = json.loads(
            source,
            object_pairs_hook=_json_pairs,
            parse_constant=_json_constant,
        )
    except _ParseError:
        raise
    except RecursionError:
        raise _ParseError("too-deep")
    except (ValueError, TypeError):
        raise _ParseError("invalid-json")
    _check_json_bounds(value)
    return value


def _check_json_bounds(value):
    stack = [(value, 1)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise _ParseError("json-bounds")
        if isinstance(item, dict):
            for child in item.values():
                stack.append((child, depth + 1))
        elif isinstance(item, list):
            for child in item:
                stack.append((child, depth + 1))


def _strip_comment(line):
    out = []
    quote = ""
    escape = False
    index = 0
    while index < len(line):
        char = line[index]
        if quote:
            out.append(char)
            if escape:
                escape = False
            elif char == "\\" and quote == '"':
                escape = True
            elif char == quote:
                quote = ""
            index += 1
            continue
        if char in ('"', "'"):
            quote = char
            out.append(char)
        elif char == "#":
            break
        else:
            out.append(char)
        index += 1
    if quote:
        raise _ParseError("unterminated-string")
    return "".join(out)


def _parse_key_path(value):
    parts = []
    current = []
    quote = ""
    escape = False
    index = 0
    while index < len(value):
        char = value[index]
        if quote:
            current.append(char)
            if escape:
                escape = False
            elif char == "\\" and quote == '"':
                escape = True
            elif char == quote:
                quote = ""
            index += 1
            continue
        if char in ('"', "'"):
            quote = char
            current.append(char)
            index += 1
            continue
        if char == ".":
            part = "".join(current).strip()
            if not part:
                raise _ParseError("invalid-key")
            parts.append(_parse_key(part))
            current = []
            index += 1
            continue
        current.append(char)
        index += 1
    if quote:
        raise _ParseError("unterminated-string")
    part = "".join(current).strip()
    if not part:
        raise _ParseError("invalid-key")
    parts.append(_parse_key(part))
    return tuple(parts)


def _parse_key(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
        return _parse_string(value)
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise _ParseError("invalid-key")
    return value


def _parse_string(value):
    if len(value) < 2 or value[0] not in ('"', "'") or value[-1] != value[0]:
        raise _ParseError("invalid-string")
    if value.startswith(('"""', "'''")):
        raise _ParseError("unsupported-string")
    quote = value[0]
    body = value[1:-1]
    if "\n" in body or "\r" in body:
        raise _ParseError("multiline-string")
    if quote == "'":
        return body
    out = []
    index = 0
    escapes = {
        "b": "\b", "t": "\t", "n": "\n", "f": "\f", "r": "\r",
        '"': '"', "\\": "\\", "/": "/",
    }
    while index < len(body):
        char = body[index]
        if char != "\\":
            out.append(char)
            index += 1
            continue
        index += 1
        if index >= len(body):
            raise _ParseError("invalid-escape")
        escape = body[index]
        index += 1
        if escape in escapes:
            out.append(escapes[escape])
        elif escape in ("u", "U"):
            width = 4 if escape == "u" else 8
            digits = body[index:index + width]
            if len(digits) != width or not re.fullmatch(r"[0-9a-fA-F]+", digits):
                raise _ParseError("invalid-escape")
            codepoint = int(digits, 16)
            if codepoint > 0x10FFFF or 0xD800 <= codepoint <= 0xDFFF:
                raise _ParseError("invalid-escape")
            out.append(chr(codepoint))
            index += width
        else:
            raise _ParseError("invalid-escape")
    return "".join(out)


def _split_commas(value):
    parts = []
    current = []
    depth = 0
    quote = ""
    escape = False
    for char in value:
        if quote:
            current.append(char)
            if escape:
                escape = False
            elif char == "\\" and quote == '"':
                escape = True
            elif char == quote:
                quote = ""
            continue
        if char in ('"', "'"):
            quote = char
            current.append(char)
        elif char == "[":
            depth += 1
            current.append(char)
        elif char == "]":
            depth -= 1
            if depth < 0:
                raise _ParseError("invalid-array")
            current.append(char)
        elif char == "," and depth == 0:
            part = "".join(current).strip()
            if part:
                parts.append(part)
            current = []
        else:
            current.append(char)
    if quote:
        raise _ParseError("unterminated-string")
    if depth != 0:
        raise _ParseError("invalid-array")
    part = "".join(current).strip()
    if part:
        parts.append(part)
    return parts


def _parse_toml_value(value):
    value = value.strip()
    if not value:
        raise _ParseError("empty-value")
    if value.startswith("{"):
        raise _ParseError("inline-table")
    if value.startswith("["):
        if not value.endswith("]"):
            raise _ParseError("unterminated-array")
        inner = value[1:-1].strip()
        if not inner:
            return ()
        return tuple(_parse_toml_value(part) for part in _split_commas(inner))
    if value.startswith(('"', "'")):
        return _parse_string(value)
    if value in ("true", "false"):
        return value == "true"
    if re.fullmatch(r"[+-]?(?:0|[1-9][0-9_]*)(?:\.[0-9_]+)?(?:[eE][+-]?[0-9]+)?", value):
        return _Number(value)
    raise _ParseError("unsupported-value")


class _Number:
    def __init__(self, value):
        self.value = value


def _bracket_balance(value):
    depth = 0
    quote = ""
    escape = False
    for char in value:
        if quote:
            if escape:
                escape = False
            elif char == "\\" and quote == '"':
                escape = True
            elif char == quote:
                quote = ""
            continue
        if char in ('"', "'"):
            quote = char
        elif char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth < 0:
                raise _ParseError("invalid-array")
    if quote:
        raise _ParseError("unterminated-string")
    return depth


def _split_assignment(line):
    quote = ""
    escape = False
    for index, char in enumerate(line):
        if quote:
            if escape:
                escape = False
            elif char == "\\" and quote == '"':
                escape = True
            elif char == quote:
                quote = ""
            continue
        if char in ('"', "'"):
            quote = char
        elif char == "=":
            return line[:index].strip(), line[index + 1:].strip()
    raise _ParseError("invalid-assignment")


def _parse_toml(text):
    if len(text) > MAX_CONFIG_BYTES:
        raise _ParseError("too-large")
    text = text.replace("\r\n", "\n")
    if "\r" in text:
        raise _ParseError("invalid-newline")
    lines = text.split("\n")
    if len(lines) > MAX_TOML_LINES:
        raise _ParseError("too-many-lines")
    values = {}
    tables = set()
    section = ()
    index = 0
    while index < len(lines):
        line = _strip_comment(lines[index]).strip()
        line_number = index + 1
        index += 1
        if not line:
            continue
        if line.startswith("[["):
            raise _ParseError("array-of-tables")
        if line.startswith("["):
            if not line.endswith("]"):
                raise _ParseError("invalid-table")
            table = _parse_key_path(line[1:-1].strip())
            if not table or table in tables:
                raise _ParseError("duplicate-table")
            section = table
            tables.add(table)
            continue
        left, right = _split_assignment(line)
        key_path = _parse_key_path(left)
        if len(key_path) != 1:
            raise _ParseError("dotted-key")
        full = section + key_path
        if full in values or full in tables:
            raise _ParseError("duplicate-key")
        balance = _bracket_balance(right)
        if balance > 0:
            collected = [right]
            while balance > 0:
                if index >= len(lines) or index >= MAX_TOML_LINES:
                    raise _ParseError("unterminated-array")
                next_text = _strip_comment(lines[index]).strip()
                index += 1
                collected.append(next_text)
                balance = _bracket_balance(" ".join(collected))
                if len(collected) > MAX_TOML_VALUE_LINES:
                    raise _ParseError("array-too-long")
            right = " ".join(collected)
        values[full] = (_parse_toml_value(right), line_number)
    return values, tables


def _read_document(root, relative, kind):
    try:
        data, device, inode, size, digest = _read_bounded(root, relative)
    except _ParseError as exc:
        return None, AuditInput(relative, status=exc.reason), exc.reason
    text = _decode_config(data)
    try:
        if kind == "toml":
            value = _parse_toml(text)
        elif kind == "jsonc":
            value = _parse_json(text, jsonc=True)
        else:
            value = _parse_json(text, jsonc=False)
    except _ParseError as exc:
        return None, AuditInput(relative, device, inode, size, digest, "incomplete"), exc.reason
    return (value, text, relative, digest), AuditInput(
        relative, device, inode, size, digest, "parsed"
    ), ""


def _line_for_key(text, key):
    match = re.search(r'["\']' + re.escape(key) + r'["\']\s*[:=]', text)
    if not match:
        return 1
    return text.count("\n", 0, match.start()) + 1


def _source(relative, line=1, digest=""):
    return SourceLocation(
        sanitize_terminal_text(relative), max(1, min(int(line), 1000000)), max(1, min(int(line), 1000000)), digest
    )


def _builtin_source(relative, digest):
    if relative:
        return _source(relative, 1, digest)
    return SourceLocation("<surface-built-in>", 1, 1, "")


def _approval_from_value(value):
    if not isinstance(value, str):
        return ApprovalMode()
    lowered = value.strip().lower()
    if lowered in ("never", "bypasspermissions", "bypass_permissions", "unrestricted"):
        return ApprovalMode("never", sanitize_terminal_text(lowered[:64]), "observed")
    if lowered in (
        "on-request", "on_request", "on-failure", "on_failure",
        "untrusted", "ask", "default", "plan", "acceptedits",
    ):
        return ApprovalMode("ask", sanitize_terminal_text(lowered[:64]), "observed")
    return ApprovalMode("unknown", sanitize_terminal_text(lowered[:64]), "observed")


def _merge_approval(current, candidate):
    rank = {"unknown": 0, "default": 1, "ask": 2, "never": 3}
    if rank.get(candidate.normalized, 0) > rank.get(current.normalized, 0):
        return candidate
    return current


def _json_mcp_channels(document, relative, digest, text):
    channels = []
    reasons = []
    if not isinstance(document, dict):
        return channels, reasons
    servers = document.get("mcpServers")
    if servers is None:
        return channels, reasons
    if not isinstance(servers, dict):
        return channels, ["mcp-servers-not-object"]
    if len(servers) > 64:
        return channels, ["mcp-servers-too-many"]
    for name, server in servers.items():
        if not isinstance(name, str) or not isinstance(server, dict):
            reasons.append("mcp-server-shape")
            continue
        command = server.get("command")
        if command is not None and (not isinstance(command, str) or not command.strip()):
            reasons.append("mcp-command-shape")
            continue
        if command:
            channels.append(ExecutionChannel(
                "mcp-stdio-command",
                _source(relative, _line_for_key(text, "command"), digest),
            ))
        if "args" in server:
            args = server.get("args")
            if not isinstance(args, list) or any(not isinstance(item, str) for item in args):
                reasons.append("mcp-args-shape")
        for unsupported in ("shell", "script", "run", "commands", "exec"):
            if unsupported in server:
                reasons.append("mcp-unknown-execution-key")
        if "url" in server and not isinstance(server.get("url"), str):
            reasons.append("mcp-url-shape")
        if not command and not server.get("url"):
            reasons.append("mcp-server-no-transport")
    return channels, reasons


def _json_hook_channels(document, relative, digest, text):
    channels = []
    reasons = []

    def walk(value, depth=0):
        if depth > MAX_JSON_DEPTH:
            reasons.append("hook-depth")
            return
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "command":
                    if isinstance(child, str) and child.strip():
                        channels.append(ExecutionChannel(
                            "hook-command",
                            _source(relative, _line_for_key(text, "command"), digest),
                        ))
                    else:
                        reasons.append("hook-command-shape")
                else:
                    walk(child, depth + 1)
        elif isinstance(value, list):
            for child in value:
                walk(child, depth + 1)

    hooks = document.get("hooks") if isinstance(document, dict) else None
    if hooks is None and "hook" in relative and isinstance(document, (dict, list)):
        hooks = document
    if hooks is not None:
        if not isinstance(hooks, (dict, list)):
            reasons.append("hooks-shape")
        else:
            walk(hooks)
    return channels, reasons


def _json_approval(document, surface):
    if not isinstance(document, dict):
        return ApprovalMode()
    if surface == "codex":
        for key in ("approval_policy", "approvalPolicy"):
            if key in document:
                return _approval_from_value(document.get(key))
    for container in (document, document.get("permissions")):
        if not isinstance(container, dict):
            continue
        for key in ("approval_policy", "approvalPolicy", "defaultMode", "approvalMode"):
            if key in container:
                return _approval_from_value(container.get(key))
        if container.get("autoRun") is True:
            return ApprovalMode("never", "autoRun=true", "observed")
    return ApprovalMode()


def _toml_mcp_channels(values, relative, digest):
    channels = []
    reasons = []
    for path, (value, line_number) in values.items():
        if len(path) < 3 or path[0] != "mcp_servers":
            continue
        key = path[-1]
        if key == "command":
            if not isinstance(value, str) or not value.strip():
                reasons.append("mcp-command-shape")
            else:
                channels.append(ExecutionChannel(
                    "mcp-stdio-command", _source(relative, line_number, digest)
                ))
        elif key == "args":
            if not isinstance(value, tuple) or any(not isinstance(item, str) for item in value):
                reasons.append("mcp-args-shape")
        elif key in ("shell", "script", "run", "commands", "exec"):
            reasons.append("mcp-unknown-execution-key")
        elif key == "url" and not isinstance(value, str):
            reasons.append("mcp-url-shape")
    return channels, reasons


def _toml_approval(values):
    for path, (value, _line) in values.items():
        if path == ("approval_policy",):
            return _approval_from_value(value)
    return ApprovalMode()


def _secret_readable(root, relative):
    """Return True only for a readable regular file, without reading its bytes."""
    parts = relative.split("/")
    current = None
    file_fd = None
    try:
        current = os.open(
            root,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        for component in parts[:-1]:
            next_fd = os.open(
                component,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                dir_fd=current,
            )
            os.close(current)
            current = next_fd
        file_fd = os.open(
            parts[-1],
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0),
            dir_fd=current,
        )
        info = os.fstat(file_fd)
        return stat.S_ISREG(info.st_mode) and info.st_size > 0
    except OSError:
        return False
    finally:
        if file_fd is not None:
            try:
                os.close(file_fd)
            except OSError:
                pass
        if current is not None:
            try:
                os.close(current)
            except OSError:
                pass


def _secret_inventory(root):
    classes = {}
    for secret_class, candidates in SECRET_CANDIDATES:
        count = 0
        for relative in candidates:
            if _secret_readable(root, relative):
                count += 1
        if count:
            classes[secret_class] = SecretClass(secret_class, "project", count)
    return [classes[key] for key in sorted(classes)]


def _validate_surface(surface):
    if surface not in _VALID_SURFACES:
        raise AgentAuditUsageError("unknown surface")
    return SURFACE_FILES[surface]


def build_report(root, surface, *, captured_at=None):
    """Build one report. No process, network, model or project code is used."""
    if surface not in _VALID_SURFACES:
        raise AgentAuditUsageError("unknown surface")
    root_path, root_fd = _open_root(root)
    os.close(root_fd)
    files = SURFACE_FILES[surface]
    report = AuditReport(
        root=root_path,
        surface=surface,
        captured_at=captured_at or _now_utc(),
    )
    report.selected = [relative for relative, _kind in files]
    report.not_inspected = [
        "User, home and system-wide agent configuration outside --root",
        "Inherited environment variables and process secrets",
        "Socket, keyring and agent credential services",
        "Files outside the selected project root",
    ]
    report.not_verified = [
        "Model identity, weights, adapters, tokenizer and publisher were not inspected.",
        "No agent, model endpoint, MCP server or project code was executed or contacted.",
        "Declared sandbox, approval or egress settings are claims, not proof of host isolation.",
        "Known non-secret environment examples were excluded from the project-env class: "
        + ", ".join(sorted(NON_SECRET_ENV_EXAMPLES)) + ".",
        "A backdoored model can pass every configuration check; this report is not a model-safety verdict.",
    ]

    documents = []
    present = 0
    for relative, kind in files:
        document, input_record, reason = _read_document(root_path, relative, kind)
        report.inputs.append(input_record)
        if input_record.status == "missing" or (
            input_record.status in ("path-missing-or-link", "path-unreadable")
        ):
            if input_record.status == "missing":
                report.reasons.append("surface-config-not-found")
            else:
                report.incomplete.append(relative)
                report.reasons.append(reason)
            continue
        present += 1
        if document is None:
            report.incomplete.append(relative)
            report.reasons.append(reason)
            continue
        report.parsed.append(relative)
        documents.append(document)
    if present == 0:
        report.coverage_complete = False
        if "surface-config-not-found" not in report.reasons:
            report.reasons.append("surface-config-not-found")
    else:
        report.coverage_complete = not report.incomplete

    first_relative = report.parsed[0] if report.parsed else (report.selected[0] if report.selected else "")
    first_digest = ""
    if report.parsed:
        first_digest = next(
            (item.sha256 for item in report.inputs if item.path == report.parsed[0]), ""
        )

    if surface in BUILTIN_SHELL_SURFACES:
        report.channels.append(ExecutionChannel(
            "shell-tool", _builtin_source(first_relative, first_digest)
        ))

    approval = ApprovalMode()
    for document in documents:
        value, text, relative, digest = document
        reason_count = len(report.reasons)
        if isinstance(value, dict):
            approval = _merge_approval(approval, _json_approval(value, surface))
            if surface in ("mcp", "claude", "cursor") or relative.endswith("mcp.json"):
                mcp_channels, mcp_reasons = _json_mcp_channels(value, relative, digest, text)
                report.channels.extend(mcp_channels)
                report.reasons.extend(mcp_reasons)
            if surface in ("claude", "cursor") or "hook" in relative:
                hook_channels, hook_reasons = _json_hook_channels(value, relative, digest, text)
                report.channels.extend(hook_channels)
                report.reasons.extend(hook_reasons)
        elif isinstance(value, tuple) and len(value) == 2:
            values, _tables = value
            if surface == "codex":
                approval = _merge_approval(approval, _toml_approval(values))
                mcp_channels, mcp_reasons = _toml_mcp_channels(values, relative, digest)
                report.channels.extend(mcp_channels)
                report.reasons.extend(mcp_reasons)
        else:
            report.reasons.append("config-top-level-shape")
        if len(report.reasons) > reason_count and relative not in report.incomplete:
            report.incomplete.append(relative)
    report.approval = approval
    if report.reasons:
        report.coverage_complete = False

    report.secrets = _secret_inventory(root_path)

    if report.channels:
        source = report.channels[0].source
        report.findings.append(FindingRecord(
            "AGENT-EXEC-AUTHORITY-001", "HIGH", "high", "observed",
            "execution-authority-observed", source,
        ))
    if report.secrets:
        report.findings.append(FindingRecord(
            "AGENT-SECRET-CLASS-READABLE-001", "MEDIUM", "high", "observed",
            "project-secret-class-readable",
            SourceLocation("<secret-inventory>", 1, 1, ""),
        ))
    if not report.coverage_complete:
        source = _source(report.incomplete[0] if report.incomplete else "<surface>")
        report.findings.append(FindingRecord(
            "AGENT-RUNTIME-CONFIG-INCOMPLETE-001", "MEDIUM", "high", "unknown",
            "bounded-configuration-incomplete", source,
        ))
    if report.execution_authority and report.secrets:
        report.findings.append(FindingRecord(
            "AGENT-CREDENTIAL-EXFIL-RISK-001", "HIGH", "medium",
            "observed",
            "execution-and-project-secret-observed",
            report.channels[0].source,
        ))
    # Ensure every catalogued rule ID is actually covered by this module.
    for rule_id in (
        "AGENT-EXEC-AUTHORITY-001",
        "AGENT-SECRET-CLASS-READABLE-001",
        "AGENT-RUNTIME-CONFIG-INCOMPLETE-001",
        "AGENT-CREDENTIAL-EXFIL-RISK-001",
    ):
        if rule_id not in RULE_METADATA:
            raise AgentAuditSchemaError("rule metadata missing")
    report.with_digest()
    return report


def vocabulary_parity_errors():
    """Return deterministic drift errors for the shared repair-agent vocabulary."""
    errors = []
    missing = sorted(AGENT_AUDIT_REQUIRED_PROGRAMS - AGENT_FORBIDDEN_PROGRAMS)
    if missing:
        errors.append("repair agent vocabulary is missing: " + ", ".join(missing))
    for category, programs in sorted(AGENT_AUDIT_PROGRAM_CATEGORIES.items()):
        if not programs:
            errors.append("audit program category is empty: " + category)
    if len(AGENT_AUDIT_REQUIRED_PROGRAMS) != sum(
        len(programs) for programs in AGENT_AUDIT_PROGRAM_CATEGORIES.values()
    ):
        errors.append("audit program categories overlap")
    if not AGENT_REMOTE_REFERENCE_RE.search("https://example.invalid/path"):
        errors.append("repair agent remote-reference policy did not match a URL")
    if not AGENT_SENSITIVE_PATH_RE.search(".ssh/id_ed25519"):
        errors.append("repair agent sensitive-path policy did not match an SSH key")
    return errors
