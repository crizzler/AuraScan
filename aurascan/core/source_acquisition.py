import errno
import hashlib
import ipaddress
import os
import re
import shlex
import shutil
import stat
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from aurascan.core.models import Confidence, EvidenceQuality, Finding, Phase, Severity, Source
from aurascan.core.install_hook import _iter_shell_segments, _mask_heredoc_bodies
from aurascan.core.text_safety import sanitize_terminal_text
from aurascan.core.trusted_tools import (
    TrustedToolError,
    capture_trusted_system_tool,
    revalidate_trusted_system_tool,
    run_bounded_trusted_tool,
)


class SourceKind(Enum):
    local = "local"
    http = "http"
    git_https = "git_https"
    signature = "signature"
    unsupported = "unsupported"
    ambiguous = "ambiguous"


CHECKSUM_FAMILIES = (
    ("b2sums", "b2"),
    ("sha512sums", "sha512"),
    ("sha384sums", "sha384"),
    ("sha256sums", "sha256"),
    ("sha224sums", "sha224"),
    ("sha1sums", "sha1"),
    ("md5sums", "md5"),
)
_MAX_PGP_KEY_BYTES = 1024 * 1024
_GPG_STATUS_KEYWORDS = frozenset({
    "BADSIG",
    "ERRSIG",
    "EXPKEYSIG",
    "EXPSIG",
    "GOODSIG",
    "IMPORT_OK",
    "IMPORT_PROBLEM",
    "NEWSIG",
    "NO_PUBKEY",
    "REVKEYSIG",
    "TRUST_EXPIRED",
    "TRUST_FULLY",
    "TRUST_MARGINAL",
    "TRUST_NEVER",
    "TRUST_ULTIMATE",
    "TRUST_UNDEFINED",
    "VALIDSIG",
})
_GPG_STATUS_FINGERPRINT = re.compile(r"[0-9A-Fa-f]{16,64}\Z")
_MAX_GPG_STATUS_LINES = 32


@dataclass
class SourceReference:
    original: str
    resolved: str
    index: int
    filename: str
    checksum_index: int
    checksum: Optional[str] = None
    checksum_algorithm: Optional[str] = None
    kind: SourceKind = SourceKind.unsupported
    fragment_type: Optional[str] = None
    fragment_value: Optional[str] = None
    validpgpkeys: List[str] = field(default_factory=list)

    @property
    def is_signature(self) -> bool:
        return self.filename.endswith((".sig", ".asc")) or self.resolved.endswith((".sig", ".asc"))


@dataclass
class SourceAcquisitionResult:
    reference: SourceReference
    local_path: Optional[Path] = None
    final_url: Optional[str] = None
    size: int = 0
    sha256: Optional[str] = None
    status: str = "skipped"
    findings: List[Finding] = field(default_factory=list)
    pgp_verification: Optional[Dict[str, object]] = None

    def to_dict(self) -> Dict[str, object]:
        return {
            "original": _redact_source_reference(self.reference.original),
            "resolved": _redact_source_reference(self.reference.resolved),
            "index": self.reference.index,
            "filename": self.reference.filename,
            "kind": self.reference.kind.value,
            "checksum_index": self.reference.checksum_index,
            "checksum_algorithm": self.reference.checksum_algorithm,
            "checksum": self.reference.checksum,
            "local_path": str(self.local_path) if self.local_path else None,
            "final_url": _redact_source_reference(self.final_url) if self.final_url else None,
            "size": self.size,
            "sha256": self.sha256,
            "status": self.status,
            "findings": [finding.to_dict() for finding in self.findings],
            "pgp_verification": self.pgp_verification,
        }


class SourcePolicy:
    def __init__(
        self,
        max_download_size: int = 100 * 1024 * 1024,
        timeout: int = 30,
        max_redirects: int = 5,
        auto_key_fetch: bool = True,
        offline: bool = False,
        keyserver: str = "https://keys.openpgp.org",
        trusted_key_dirs: Optional[List[Path]] = None,
        key_cache_dir: Optional[Path] = None,
    ):
        self.max_download_size = max_download_size
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.allowed_redirect_schemes = {"http", "https"}
        self.auto_key_fetch = auto_key_fetch
        self.offline = offline
        self.keyserver = keyserver.rstrip("/")
        self.trusted_key_dirs = [Path(p) for p in (trusted_key_dirs or [])]
        self.key_cache_dir = Path(key_cache_dir) if key_cache_dir else Path.home() / ".cache" / "aurascan" / "pgp-keys"


class SourceParser:
    def parse(self, pkgbuild_path: str, content: str) -> Tuple[List[SourceReference], List[Finding]]:
        # The caller supplies the exact PKGBUILD snapshot bound to the scan
        # identity.  A sibling .SRCINFO is generated metadata which may be
        # stale, forged, symlinked, or replaced independently; never let it
        # substitute different source declarations implicitly.  Integrations
        # that already possess trusted .SRCINFO bytes may still call the
        # explicit parse_srcinfo() API.
        return self.parse_pkgbuild(content, pkgbuild_path)

    def parse_srcinfo(self, content: str, path: str = ".SRCINFO") -> Tuple[List[SourceReference], List[Finding]]:
        sources: List[str] = []
        checksum_values: Dict[str, List[str]] = {}
        validpgpkeys: List[str] = []
        for line in content.splitlines():
            stripped = line.strip()
            if self._srcinfo_source_key(stripped):
                sources.append(stripped.split("=", 1)[1].strip())
            elif self._srcinfo_checksum_key(stripped):
                key = self._srcinfo_checksum_key(stripped)
                checksum_values.setdefault(key, []).append(stripped.split("=", 1)[1].strip())
            elif stripped.startswith("validpgpkeys = "):
                validpgpkeys.append(stripped.split("=", 1)[1].strip())
        checksum_algorithm, checksums = self._choose_checksums(checksum_values)
        refs = self._references_from_tokens(sources, checksums, validpgpkeys, checksum_algorithm)
        return refs, self._signature_metadata_findings(refs, validpgpkeys, path)

    def parse_pkgbuild(self, content: str, path: str = "PKGBUILD") -> Tuple[List[SourceReference], List[Finding]]:
        variables = self._parse_basic_variables(content)
        source_bodies, source_parse_error = self._parse_source_bodies(content)
        if source_parse_error:
            return [], [_finding(
                "SOURCE-PARSER-AMBIGUOUS",
                path,
                Severity.HIGH,
                "PKGBUILD source declarations could not be represented safely without evaluating Bash.",
                "Do not build or install until every source declaration and mutation has been resolved and inspected independently.",
                True,
                "source declaration syntax was not inspected",
            )]
        if not source_bodies:
            return [], []

        findings: List[Finding] = []
        joined_source_body = "\n".join(source_bodies)
        if "$(" in joined_source_body or "`" in joined_source_body or re.search(r"\$\{[^}]+:[^}]+}", joined_source_body):
            findings.append(_finding(
                "SOURCE-PARSER-AMBIGUOUS",
                path,
                Severity.HIGH,
                "PKGBUILD source array contains dynamic Bash syntax AuraScan will not evaluate.",
                "Do not build or install until every dynamic source declaration has been resolved and inspected independently.",
                True,
                "dynamic source declaration was not inspected",
            ))
            return [], findings

        source_tokens: List[str] = []
        for source_body in source_bodies:
            source_tokens.extend(self._tokenize_array(source_body))
        source_tokens = [self._interpolate(token, variables) for token in source_tokens]
        checksum_algorithm, checksums = self._parse_checksum_arrays(content)
        validpgpkeys = self._parse_checksums(content, "validpgpkeys")
        refs = self._references_from_tokens(source_tokens, checksums, validpgpkeys, checksum_algorithm)
        findings.extend(self._signature_metadata_findings(refs, validpgpkeys, path))
        return refs, findings

    def _references_from_tokens(self, tokens: List[str], checksums: List[str], validpgpkeys: Optional[List[str]] = None, checksum_algorithm: Optional[str] = None) -> List[SourceReference]:
        refs: List[SourceReference] = []
        normalized_keys = [PgpKeyNormalizer.normalize(key) for key in (validpgpkeys or []) if PgpKeyNormalizer.normalize(key)]
        for index, token in enumerate(tokens):
            original = token
            filename, resolved = self._split_renamed(token)
            checksum = checksums[index] if index < len(checksums) else None
            ref = SourceReference(
                original=original,
                resolved=resolved,
                index=index,
                filename=filename or self._filename_from_source(resolved),
                checksum_index=index,
                checksum=checksum,
                checksum_algorithm=checksum_algorithm if checksum is not None else None,
                validpgpkeys=normalized_keys,
            )
            ref.kind, ref.fragment_type, ref.fragment_value = self._classify(ref)
            refs.append(ref)
        return refs

    def _parse_basic_variables(self, content: str) -> Dict[str, str]:
        variables: Dict[str, str] = {}
        for key in ("pkgname", "pkgver", "pkgrel", "pkgbase"):
            match = re.search(rf"^{key}=([^\n]+)", content, re.M)
            if match:
                value = match.group(1).strip().strip("'\"()")
                if re.search(r"[$`(]", value):
                    continue
                variables[key] = value
        return variables

    def _parse_checksums(self, content: str, key: str) -> List[str]:
        match = re.search(rf"^{key}=\((?P<body>.*?)\)", content, re.M | re.S)
        if match:
            return self._tokenize_array(match.group("body"))
        scalar = re.search(rf"^{key}=([^\n]+)", content, re.M)
        return [scalar.group(1).strip().strip("'\"()")] if scalar else []

    def _parse_checksum_arrays(self, content: str) -> Tuple[Optional[str], List[str]]:
        for prefix, algorithm in CHECKSUM_FAMILIES:
            values: List[str] = []
            for key in self._pkgbuild_checksum_keys(content, prefix):
                values.extend(self._parse_checksums(content, key))
            if values:
                return algorithm, values
        return None, []

    def _pkgbuild_checksum_keys(self, content: str, prefix: str) -> List[str]:
        keys: List[str] = []
        pattern = rf"^({re.escape(prefix)}(?:_[A-Za-z0-9_]+)?)="
        for match in re.finditer(pattern, content, re.M):
            key = match.group(1)
            if key not in keys:
                keys.append(key)
        return keys

    def _parse_source_bodies(self, content: str) -> Tuple[List[str], bool]:
        bodies: List[str] = []
        prepared = _mask_heredoc_bodies(content).content
        prepared, function_parse_error, defined_functions = self._mask_function_bodies(prepared)
        if function_parse_error:
            return [], True
        assignment_pattern = re.compile(
            r"^\s*(?:(?:declare|export|local|readonly|typeset)\s+(?:-[A-Za-z]+\s+)*)?"
            r"(?P<name>source(?:_[A-Za-z0-9_]+)?)(?P<subscript>\[[^\]]*\])?"
            r"(?P<operator>\+=|=)(?P<value>.*)$",
            re.S,
        )
        for segment, _line_number in _iter_shell_segments(prepared):
            match = assignment_pattern.match(segment)
            if match is None:
                if self._segment_may_mutate_sources(segment, defined_functions):
                    return [], True
                continue
            if match.group("subscript"):
                return [], True
            value = match.group("value").strip()
            if value.startswith("("):
                body = self._balanced_array_body(value)
                if body is None:
                    return [], True
            else:
                try:
                    scalar_tokens = shlex.split(value, comments=True, posix=True)
                except ValueError:
                    return [], True
                if len(scalar_tokens) != 1:
                    return [], True
                body = value
            try:
                shlex.split(body, comments=True, posix=True)
            except ValueError:
                return [], True
            bodies.append(body)
        return bodies, False

    def _mask_function_bodies(self, content: str) -> Tuple[str, bool, set]:
        """Remove inert function definitions from top-level source parsing.

        makepkg evaluates top-level metadata while defining, but not invoking,
        package functions.  Commands such as ``eval`` inside ``package()`` do
        not mutate the source array used for acquisition.  Mask complete,
        syntactically bounded function bodies while preserving newlines; an
        unterminated body remains ambiguous and fails closed.
        """
        function_start = re.compile(
            r"(?m)^[ \t]*(?:(?:function[ \t]+(?P<function_name>[A-Za-z_]"
            r"[A-Za-z0-9_]*)(?:[ \t]*\([ \t]*\))?)|(?:(?P<plain_name>"
            r"[A-Za-z_][A-Za-z0-9_]*)[ \t]*\([ \t]*\)))[ \t]*"
            r"(?:\n[ \t]*)?\{"
        )
        masked = list(content)
        defined_functions = set()
        search_at = 0
        while True:
            match = function_start.search(content, search_at)
            if match is None:
                break
            opening = content.rfind("{", match.start(), match.end())
            closing = self._matching_function_brace(content, opening)
            if closing is None:
                return content, True, set()
            defined_functions.add(match.group("function_name") or match.group("plain_name"))
            for index in range(match.start(), closing + 1):
                if masked[index] not in {"\n", "\r"}:
                    masked[index] = " "
            search_at = closing + 1
        return "".join(masked), False, defined_functions

    def _matching_function_brace(self, content: str, opening: int) -> Optional[int]:
        depth = 0
        quote = ""
        escaped = False
        comment = False
        for index in range(opening, len(content)):
            char = content[index]
            if comment:
                if char == "\n":
                    comment = False
                continue
            if quote:
                if quote == "'":
                    if char == "'":
                        quote = ""
                elif escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = ""
                continue
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if char in {"'", '"', "`"}:
                quote = char
                continue
            if char == "#":
                comment = True
                continue
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return index
                if depth < 0:
                    return None
        return None

    def _balanced_array_body(self, value: str) -> Optional[str]:
        quote = ""
        escaped = False
        depth = 0
        for index, char in enumerate(value):
            if quote:
                if quote == "'":
                    if char == "'":
                        quote = ""
                elif escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = ""
                continue
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if char in {"'", '"'}:
                quote = char
                continue
            if char == "(":
                depth += 1
                continue
            if char == ")":
                depth -= 1
                if depth < 0:
                    return None
                if depth == 0:
                    if value[index + 1:].strip():
                        return None
                    return value[1:index]
        return None

    def _segment_may_mutate_sources(self, segment: str, defined_functions: Optional[set] = None) -> bool:
        raw_assignment = re.search(
            r"(?:^|[;&|(){}\s])source(?:_[A-Za-z0-9_]+)?(?:\[[^\]]*\])?\s*(?:\+?=)",
            segment,
        )
        if re.search(r"\$\{\s*source(?:\[[^\]]*\])?\s*(?::?=)", segment):
            return True
        try:
            tokens = shlex.split(segment, comments=False, posix=True)
        except ValueError:
            return raw_assignment is not None
        if not tokens:
            return False
        command_index = 0
        while command_index < len(tokens) and tokens[command_index] in {
            "!", "do", "elif", "else", "if", "then", "time", "until", "while",
        }:
            command_index += 1
        while command_index < len(tokens) and re.fullmatch(
            r"[A-Za-z_][A-Za-z0-9_]*=.*",
            tokens[command_index],
            re.S,
        ):
            command_index += 1
        if command_index >= len(tokens):
            return raw_assignment is not None
        command_token = tokens[command_index]
        if "$" in command_token or "`" in command_token:
            # A dynamically selected top-level command can invoke a locally
            # defined helper that mutates global source metadata.  Do not
            # execute Bash to resolve it.
            return True
        command = command_token.rsplit("/", 1)[-1]
        bypass_functions = False
        if command in {"builtin", "command"}:
            bypass_functions = True
            command_index += 1
            while command_index < len(tokens) and tokens[command_index].startswith("-"):
                command_index += 1
            if command_index >= len(tokens):
                return False
            command_token = tokens[command_index]
            if "$" in command_token or "`" in command_token:
                return True
            command = command_token.rsplit("/", 1)[-1]
        if defined_functions and not bypass_functions and command in defined_functions:
            # Calling a locally defined shell function while makepkg sources
            # the PKGBUILD can mutate global metadata through behavior hidden
            # in that function.  AuraScan does not execute it to find out.
            return True
        if command in {"source", ".", "eval"}:
            return True
        if command in {"declare", "export", "local", "readonly", "typeset", "unset"}:
            if command in {"declare", "local", "typeset"} and any(
                token == "--nameref"
                or bool(re.fullmatch(r"-[A-Za-z]*n[A-Za-z]*", token))
                for token in tokens[1:]
                if token.startswith("-")
            ):
                # A nameref can mutate any source array through an unrelated
                # identifier in a later statement.  Static source collection
                # cannot establish that alias safely without evaluating Bash.
                return True
            return any(
                token == "source"
                or token.startswith("source[")
                or token.startswith("source=")
                or token.startswith("source+=")
                or token.startswith("source_")
                or "$" in token
                or "`" in token
                for token in tokens[1:]
                if not token.startswith("-")
            )
        if command == "printf":
            for index in range(1, len(tokens) - 1):
                if tokens[index] not in {"-v", "--variable"}:
                    continue
                target = tokens[index + 1]
                if (
                    target == "source"
                    or target.startswith("source[")
                    or "$" in target
                    or "`" in target
                ):
                    return True
            return False
        if command in {"read", "mapfile", "readarray"}:
            return any(
                token == "source"
                or token.startswith("source[")
                or "$" in token
                or "`" in token
                for token in tokens[1:]
                if not token.startswith("-")
            )
        # A source-looking string passed to echo/printf/documentation is inert;
        # an assignment token in command-prefix position is not.
        prefix_tokens = []
        for token in tokens:
            if re.match(r"^[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=", token):
                prefix_tokens.append(token)
                continue
            break
        return any(
            re.match(r"^source(?:_[A-Za-z0-9_]+)?(?:\[[^\]]*\])?\+?=", token)
            for token in prefix_tokens
        )

    def _srcinfo_source_key(self, line: str) -> Optional[str]:
        key = line.split("=", 1)[0].strip() if "=" in line else ""
        return key if key == "source" or key.startswith("source_") else None

    def _srcinfo_checksum_key(self, line: str) -> Optional[str]:
        key = line.split("=", 1)[0].strip() if "=" in line else ""
        for prefix, _algorithm in CHECKSUM_FAMILIES:
            if key == prefix or key.startswith(prefix + "_"):
                return key
        return None

    def _choose_checksums(self, checksum_values: Dict[str, List[str]]) -> Tuple[Optional[str], List[str]]:
        for prefix, algorithm in CHECKSUM_FAMILIES:
            selected: List[str] = []
            for key, values in checksum_values.items():
                if key == prefix or key.startswith(prefix + "_"):
                    selected.extend(values)
            if selected:
                return algorithm, selected
        return None, []

    def _signature_metadata_findings(self, refs: List[SourceReference], validpgpkeys: List[str], path: str) -> List[Finding]:
        findings: List[Finding] = []
        weak_keys = [key for key in validpgpkeys if PgpKeyNormalizer.is_weak(key)]
        for key in weak_keys:
            findings.append(_finding(
                "SOURCE-VALIDPGPKEY-WEAK",
                path,
                Severity.MEDIUM,
                "validpgpkeys contains a short or weak key ID.",
                "Use a full 40-hex-character fingerprint as the trust anchor.",
                False,
                key,
            ))
        if not any(ref.kind == SourceKind.signature for ref in refs):
            if validpgpkeys:
                findings.append(_finding(
                    "SIGNATURE-MISSING",
                    path,
                    Severity.MEDIUM,
                    "validpgpkeys is declared but no detached source signature was found.",
                    "Review whether the source is expected to be signature-verified.",
                    False,
                    ", ".join(validpgpkeys),
                ))
            return findings
        if validpgpkeys:
            finding = _finding(
                "SOURCE-VALIDPGPKEYS-DETECTED",
                path,
                Severity.LOW,
                "Detached signature source and validpgpkeys metadata were detected.",
                "AuraScan will verify detached signatures in an isolated keyring during source acquisition.",
                False,
                ", ".join(validpgpkeys),
                EvidenceQuality.weak_heuristic,
            )
            finding.requires_manual_review = False
            findings.append(finding)
            return findings
        findings.append(_finding(
            "SOURCE-SIGNATURE-WITHOUT-VALIDPGPKEYS",
            path,
            Severity.MEDIUM,
            "Detached signature source was detected without validpgpkeys metadata.",
            "Manually verify the signature and expected signer identity.",
            False,
            "",
        ))
        return findings

    def _tokenize_array(self, body: str) -> List[str]:
        try:
            return shlex.split(body, comments=True, posix=True)
        except ValueError:
            return []

    def _interpolate(self, token: str, variables: Dict[str, str]) -> str:
        for key, value in variables.items():
            token = token.replace(f"${key}", value).replace(f"${{{key}}}", value)
        return token

    def _split_renamed(self, token: str) -> Tuple[str, str]:
        if "::" not in token:
            return "", token
        filename, resolved = token.split("::", 1)
        return _safe_filename(filename), resolved

    def _filename_from_source(self, source: str) -> str:
        parsed = urllib.parse.urlparse(source)
        name = Path(parsed.path).name if parsed.path else Path(source).name
        return _safe_filename(name or "source")

    def _classify(self, ref: SourceReference) -> Tuple[SourceKind, Optional[str], Optional[str]]:
        if ref.is_signature:
            return SourceKind.signature, None, None
        source = ref.resolved
        if source.startswith("git+https://"):
            parsed = urllib.parse.urlparse(source[4:])
            fragment = urllib.parse.parse_qs(parsed.fragment)
            for key in ("commit", "tag", "branch"):
                if key in fragment:
                    return SourceKind.git_https, key, fragment[key][0]
            return SourceKind.git_https, None, None
        parsed = urllib.parse.urlparse(source)
        if parsed.scheme in {"http", "https"}:
            return SourceKind.http, None, None
        if parsed.scheme in {"git", "ssh", "svn", "hg", "bzr"} or source.startswith(("git+ssh://", "ssh://")):
            return SourceKind.unsupported, None, None
        if parsed.scheme and parsed.scheme not in {"file"}:
            return SourceKind.unsupported, None, None
        return SourceKind.local, None, None


class PgpKeyNormalizer:
    @staticmethod
    def normalize(value: str) -> str:
        return re.sub(r"[^0-9A-Fa-f]", "", value).upper()

    @staticmethod
    def is_full_fingerprint(value: str) -> bool:
        return bool(re.fullmatch(r"[0-9A-F]{40}", PgpKeyNormalizer.normalize(value)))

    @staticmethod
    def is_weak(value: str) -> bool:
        normalized = PgpKeyNormalizer.normalize(value)
        return bool(normalized) and len(normalized) < 40


@dataclass
class PublicKeySource:
    fingerprint: str
    path: Optional[Path] = None
    source_type: str = "unavailable"
    error: Optional[str] = None
    data: Optional[bytes] = field(default=None, repr=False)


@dataclass
class PublicKeyImportResult:
    fingerprint: str
    imported: bool
    key_source: Optional[PublicKeySource] = None
    gpg_status: str = ""
    error: Optional[str] = None


def _prepare_private_key_cache(path: Path) -> bool:
    try:
        path.mkdir(parents=True, mode=0o700, exist_ok=True)
        metadata = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o022
        ):
            return False
        os.chmod(str(path), 0o700)
        return True
    except OSError:
        return False


def _read_key_candidate(path: Path) -> Tuple[str, Optional[bytes]]:
    """Read one stable, bounded, non-link public-key file."""

    descriptor = -1
    try:
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            return "absent", None
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_mode & 0o022
        ):
            return "unsafe", None
        descriptor = os.open(
            str(path),
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size > _MAX_PGP_KEY_BYTES
            or before.st_mode & 0o022
        ):
            return "unsafe", None
        payload = bytearray()
        while len(payload) <= _MAX_PGP_KEY_BYTES:
            chunk = os.read(
                descriptor,
                min(65536, _MAX_PGP_KEY_BYTES + 1 - len(payload)),
            )
            if not chunk:
                break
            payload.extend(chunk)
        after = os.fstat(descriptor)
        if (
            len(payload) > _MAX_PGP_KEY_BYTES
            or _file_snapshot_identity(before) != _file_snapshot_identity(after)
        ):
            return "unsafe", None
        return "resolved", bytes(payload)
    except OSError:
        return "unsafe", None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _write_private_key_cache(path: Path, payload: bytes) -> None:
    if len(payload) > _MAX_PGP_KEY_BYTES or not _prepare_private_key_cache(path.parent):
        raise ValueError("public-key cache was unsafe")
    directory_fd = -1
    temporary_name = ".key-" + uuid.uuid4().hex
    descriptor = -1
    try:
        directory_fd = os.open(
            str(path.parent),
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        directory_metadata = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(directory_metadata.st_mode)
            or directory_metadata.st_uid != os.geteuid()
            or directory_metadata.st_mode & 0o077
        ):
            raise ValueError("public-key cache directory was unsafe")
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_fd,
        )
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        # Hard-link creation is an atomic no-replace publish.  A malicious or
        # stale cache entry, including a symlink, is never followed or replaced.
        os.link(
            temporary_name,
            path.name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
            follow_symlinks=False,
        )
        os.unlink(temporary_name, dir_fd=directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if directory_fd >= 0:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except OSError:
                pass
            os.close(directory_fd)


@dataclass
class PgpVerificationResult:
    signature_path: str
    signed_file_path: str
    verification_status: str
    signer_fingerprint: Optional[str] = None
    normalized_validpgpkeys: List[str] = field(default_factory=list)
    matched_validpgpkey: bool = False
    key_source: Optional[str] = None
    key_fetch_attempted: bool = False
    key_fetch_provider: Optional[str] = None
    key_fetch_error: Optional[str] = None
    gpg_status: str = ""
    related_finding_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "signature_path": _redact_source_reference(self.signature_path),
            "signed_file_path": _redact_source_reference(self.signed_file_path),
            "verification_status": self.verification_status,
            "signer_fingerprint": self.signer_fingerprint,
            "normalized_validpgpkeys": self.normalized_validpgpkeys,
            "matched_validpgpkey": self.matched_validpgpkey,
            "key_source": self.key_source,
            "key_fetch_attempted": self.key_fetch_attempted,
            "key_fetch_provider": self.key_fetch_provider,
            "key_fetch_error": self.key_fetch_error,
            "gpg_status": self.gpg_status,
            "related_finding_ids": self.related_finding_ids,
        }


class PublicKeyProvider:
    def get_key(self, fingerprint: str) -> PublicKeySource:
        return PublicKeySource(fingerprint=PgpKeyNormalizer.normalize(fingerprint), error="KEY_UNAVAILABLE")


class TrustedKeyDirectoryProvider(PublicKeyProvider):
    def __init__(
        self,
        policy: Optional[SourcePolicy] = None,
        opener: Optional[urllib.request.OpenerDirector] = None,
    ):
        self.policy = policy or SourcePolicy()
        self.opener = opener or urllib.request.build_opener(_SafeRedirectHandler(self.policy))
        self._cache_safe = _prepare_private_key_cache(self.policy.key_cache_dir)

    def get_key(self, fingerprint: str) -> PublicKeySource:
        normalized = PgpKeyNormalizer.normalize(fingerprint)
        cached = self.policy.key_cache_dir / f"{normalized}.asc"
        if self._cache_safe:
            cached_state, cached_data = _read_key_candidate(cached)
            if cached_state == "resolved":
                return PublicKeySource(normalized, cached, "cache", data=cached_data)
            if cached_state == "unsafe":
                return PublicKeySource(normalized, error="KEY_CACHE_UNSAFE")
        for directory in self.policy.trusted_key_dirs:
            for suffix in (".asc", ".gpg", ".pgp"):
                candidate = directory / f"{normalized}{suffix}"
                candidate_state, candidate_data = _read_key_candidate(candidate)
                if candidate_state == "resolved":
                    return PublicKeySource(
                        normalized,
                        candidate,
                        "trusted_key_dir",
                        data=candidate_data,
                    )
                if candidate_state == "unsafe":
                    return PublicKeySource(normalized, error="KEY_FILE_UNSAFE")
        if self.policy.offline or not self.policy.auto_key_fetch:
            return PublicKeySource(normalized, error="KEY_UNAVAILABLE")
        if not PgpKeyNormalizer.is_full_fingerprint(normalized):
            return PublicKeySource(normalized, error="WEAK_KEY_ID")
        if not self._cache_safe:
            return PublicKeySource(normalized, error="KEY_CACHE_UNSAFE")
        url = f"{self.policy.keyserver}/pks/lookup?op=get&options=mr&search=0x{normalized}"
        try:
            _validate_public_remote_url(url, self.policy.allowed_redirect_schemes)
            request = urllib.request.Request(url, headers={"User-Agent": "AuraScan/0.1"})
            with self.opener.open(request, timeout=self.policy.timeout) as response:
                if hasattr(response, "geturl"):
                    _validate_public_remote_url(
                        str(response.geturl()),
                        self.policy.allowed_redirect_schemes,
                    )
                payload = response.read(_MAX_PGP_KEY_BYTES + 1)
            if len(payload) > _MAX_PGP_KEY_BYTES:
                return PublicKeySource(normalized, error="KEY_FETCH_OVERSIZED")
            _write_private_key_cache(cached, payload)
        except (OSError, urllib.error.URLError, ValueError):
            return PublicKeySource(normalized, error="KEY_FETCH_FAILED")
        return PublicKeySource(normalized, cached, "keyserver", data=payload)


class ChecksumVerifier:
    def verify(self, result: SourceAcquisitionResult) -> List[Finding]:
        ref = result.reference
        if ref.kind == SourceKind.signature:
            return []
        if ref.checksum is None:
            return [_finding(
                "SOURCE-CHECKSUM-MISSING",
                ref.original,
                Severity.MEDIUM,
                "No checksum was declared for this source.",
                "Add or verify an integrity checksum before trusting this source.",
                False,
                ref.original,
            )]
        if ref.checksum.upper() == "SKIP":
            return [self._skip_finding(ref)]
        if not result.local_path or not result.local_path.exists():
            return []
        digest = _hash_file(result.local_path, ref.checksum_algorithm or "sha256")
        if digest != ref.checksum.lower():
            return [_finding(
                "SOURCE-CHECKSUM-MISMATCH",
                str(result.local_path),
                Severity.CRITICAL,
                f"Downloaded source {ref.checksum_algorithm or 'sha256'} does not match the declared checksum.",
                "Do not install. Treat this as tampering or an invalid PKGBUILD until proven otherwise.",
                True,
                f"expected {ref.checksum}; got {digest}",
                EvidenceQuality.confirmed_static_pattern,
            )]
        finding = _finding(
            "SOURCE-CHECKSUM-MATCH",
            str(result.local_path),
            Severity.LOW,
            f"Declared {ref.checksum_algorithm or 'sha256'} checksum matched the acquired source.",
            "Checksum confirms integrity against the PKGBUILD, but it is not proof the source is safe.",
            False,
            digest,
            EvidenceQuality.confirmed_static_pattern,
        )
        finding.requires_manual_review = False
        return [finding]

    def _skip_finding(self, ref: SourceReference) -> Finding:
        if ref.kind == SourceKind.git_https and ref.fragment_type == "commit" and _is_full_commit(ref.fragment_value or ""):
            severity = Severity.LOW
            explanation = "Checksum is SKIP, but git source is pinned to a full commit hash."
        elif ref.kind == SourceKind.git_https and ref.fragment_type == "tag":
            severity = Severity.MEDIUM
            explanation = "Checksum is SKIP for a git tag source; signed tag verification is not implemented yet."
        elif ref.kind == SourceKind.git_https:
            severity = Severity.HIGH
            explanation = "Checksum is SKIP for an unpinned or branch-based git source."
        elif ref.kind == SourceKind.http:
            severity = Severity.HIGH
            explanation = "Checksum is SKIP for an HTTP/HTTPS source archive."
        else:
            severity = Severity.MEDIUM
            explanation = "Checksum is SKIP for this source."
        return _finding(
            "SOURCE-CHECKSUM-SKIP",
            ref.original,
            severity,
            explanation,
            "Manually verify source provenance and integrity.",
            False,
            ref.original,
            EvidenceQuality.weak_heuristic if severity == Severity.LOW else EvidenceQuality.strong_heuristic,
        )


class SignatureVerifier:
    def __init__(
        self,
        policy: Optional[SourcePolicy] = None,
        key_provider: Optional[PublicKeyProvider] = None,
        runner: Optional[Callable] = None,
    ):
        self.policy = policy or SourcePolicy()
        self.key_provider = key_provider or TrustedKeyDirectoryProvider(self.policy)
        self.runner = runner or run_bounded_trusted_tool
        self.last_result: Optional[PgpVerificationResult] = None

    def verify(
        self,
        source: SourceReference,
        signature: SourceReference,
        source_path: Optional[Path] = None,
        signature_path: Optional[Path] = None,
    ) -> Tuple[List[Finding], Optional[PgpVerificationResult]]:
        valid_keys = [key for key in source.validpgpkeys if PgpKeyNormalizer.is_full_fingerprint(key)]
        if not signature_path or not source_path:
            result = self._result(source, signature, "signature_unavailable", valid_keys)
            finding = _finding(
                "SIGNATURE-FILE-MISSING",
                source.original,
                Severity.MEDIUM,
                "A detached signature was declared but the signature file was not acquired.",
                "Acquire the signature and verify it manually.",
                False,
                signature.original,
            )
            result.related_finding_ids.append(finding.finding_id)
            self.last_result = result
            return [finding], result
        if not source.validpgpkeys:
            result = self._result(source, signature, "missing_validpgpkeys", [])
            finding = _finding(
                "SOURCE-SIGNATURE-WITHOUT-VALIDPGPKEYS",
                source.original,
                Severity.MEDIUM,
                "Detached signature is present but validpgpkeys is missing.",
                "Review signer identity manually; AuraScan has no fingerprint trust anchor.",
                False,
                str(signature_path),
            )
            result.related_finding_ids.append(finding.finding_id)
            self.last_result = result
            return [finding], result
        weak_keys = [key for key in source.validpgpkeys if not PgpKeyNormalizer.is_full_fingerprint(key)]
        if weak_keys and not valid_keys:
            result = self._result(source, signature, "weak_validpgpkeys", source.validpgpkeys)
            finding = _finding(
                "SOURCE-VALIDPGPKEY-WEAK",
                source.original,
                Severity.MEDIUM,
                "validpgpkeys contains only short or weak key IDs.",
                "Use a full 40-hex-character fingerprint before automatic PGP verification.",
                False,
                ", ".join(weak_keys),
            )
            result.related_finding_ids.append(finding.finding_id)
            self.last_result = result
            return [finding], result
        try:
            gpg_tool = capture_trusted_system_tool("gpg")
        except TrustedToolError:
            gpg_tool = None
        if gpg_tool is None:
            result = self._result(source, signature, "gpg_unavailable", valid_keys)
            finding = _finding(
                "SIGNATURE-VERIFICATION-UNAVAILABLE",
                source.original,
                Severity.MEDIUM,
                "A trusted system GnuPG executable is unavailable, so AuraScan could not verify the detached signature.",
                "Install the distribution GnuPG package, repair PATH or executable permissions, or verify the signature independently.",
                False,
                "trusted GnuPG verification was unavailable",
            )
            result.related_finding_ids.append(finding.finding_id)
            self.last_result = result
            return [finding], result

        key_sources: List[PublicKeySource] = []
        key_findings: List[Finding] = []
        for fingerprint in valid_keys:
            key_source = self.key_provider.get_key(fingerprint)
            if key_source.data is None and key_source.path is not None:
                key_state, key_payload = _read_key_candidate(key_source.path)
                if key_state == "resolved":
                    key_source.data = key_payload
                else:
                    key_source.error = "KEY_FILE_UNSAFE"
            key_sources.append(key_source)
            if key_source.data is None:
                finding = _finding(
                    "KEY_UNAVAILABLE",
                    source.original,
                    Severity.MEDIUM,
                    "Public key for validpgpkeys fingerprint is unavailable.",
                    "AuraScan could not complete signature verification. Review manually or retry with key fetching enabled.",
                    False,
                    key_source.error or fingerprint,
                )
                key_findings.append(finding)
        if not any(item.data is not None for item in key_sources):
            result = self._result(source, signature, "key_unavailable", valid_keys)
            result.key_fetch_attempted = any(item.source_type == "keyserver" or item.error not in (None, "KEY_UNAVAILABLE", "WEAK_KEY_ID") for item in key_sources)
            result.key_fetch_provider = self.policy.keyserver if self.policy.auto_key_fetch and not self.policy.offline else None
            result.key_fetch_error = "; ".join(filter(None, [item.error for item in key_sources])) or None
            result.related_finding_ids.extend(f.finding_id for f in key_findings)
            self.last_result = result
            return key_findings, result

        gnupg_home = Path(tempfile.mkdtemp(prefix="aurascan-gnupg-"))
        os.chmod(gnupg_home, 0o700)
        try:
            import_status = ""
            imported_source = None
            for key_index, key_source in enumerate(key_sources):
                key_payload = key_source.data
                if key_payload is None and key_source.path is not None:
                    key_state, key_payload = _read_key_candidate(key_source.path)
                    if key_state != "resolved":
                        key_payload = None
                if key_payload is None:
                    continue
                import_path = gnupg_home / f"key-{key_index:04d}.asc"
                import_fd = os.open(
                    str(import_path),
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                try:
                    _write_all(import_fd, key_payload)
                    os.fsync(import_fd)
                finally:
                    os.close(import_fd)
                imported_source = key_source
                revalidate_trusted_system_tool(gpg_tool)
                import_proc = self.runner(
                    [gpg_tool.path, "--homedir", str(gnupg_home), "--batch", "--no-tty", "--import", str(import_path)],
                    capture_output=True,
                    text=True,
                    timeout=self.policy.timeout,
                    check=False,
                    env=self._gpg_env(gnupg_home),
                )
                import_status += (import_proc.stdout or "") + (import_proc.stderr or "")
            revalidate_trusted_system_tool(gpg_tool)
            verify_proc = self.runner(
                [gpg_tool.path, "--homedir", str(gnupg_home), "--batch", "--no-tty", "--status-fd", "1", "--no-auto-key-retrieve", "--verify", str(signature_path), str(source_path)],
                capture_output=True,
                text=True,
                timeout=self.policy.timeout,
                check=False,
                env=self._gpg_env(gnupg_home),
            )
        except (OSError, subprocess.SubprocessError, TrustedToolError):
            result = self._result(source, signature, "verification_error", valid_keys)
            finding = _finding(
                "SIGNATURE-VERIFICATION-ERROR",
                source.original,
                Severity.MEDIUM,
                "Detached signature verification could not run through the captured trusted executable.",
                "Review the source signature manually.",
                False,
                str(signature_path),
            )
            result.related_finding_ids.append(finding.finding_id)
            self.last_result = result
            return [finding], result
        finally:
            shutil.rmtree(gnupg_home, ignore_errors=True)

        gpg_status = (verify_proc.stdout or "") + (verify_proc.stderr or "")
        signer = self._parse_signer_fingerprint(gpg_status)
        matched = signer in valid_keys if signer else False
        result = self._result(source, signature, "valid" if verify_proc.returncode == 0 else "invalid", valid_keys)
        result.signer_fingerprint = signer
        result.matched_validpgpkey = matched
        result.key_source = imported_source.source_type if imported_source else None
        result.key_fetch_attempted = any(item.source_type == "keyserver" for item in key_sources)
        result.key_fetch_provider = self.policy.keyserver if result.key_fetch_attempted else None
        result.gpg_status = self._sanitize_status(import_status + gpg_status)

        if verify_proc.returncode != 0:
            finding = _finding(
                "SIGNATURE-INVALID",
                source.original,
                Severity.CRITICAL,
                "Detached source signature is invalid.",
                "Do not install. Treat this as tampering or an invalid source until proven otherwise.",
                True,
                str(signature_path),
                EvidenceQuality.confirmed_static_pattern,
            )
        elif not matched:
            result.verification_status = "fingerprint_mismatch"
            finding = _finding(
                "SIGNATURE-FINGERPRINT-MISMATCH",
                source.original,
                Severity.HIGH,
                "Detached signature is valid, but signer fingerprint does not match validpgpkeys.",
                "Review signer identity manually before trusting this source.",
                False,
                signer or "unknown signer",
            )
        else:
            finding = _finding(
                "SIGNATURE-VERIFIED",
                source.original,
                Severity.LOW,
                "Detached signature is valid and signer fingerprint matches validpgpkeys.",
                "Signature confirms integrity against the declared signer, but it is not proof the source is safe.",
                False,
                signer or "",
                EvidenceQuality.confirmed_static_pattern,
            )
            finding.requires_manual_review = False
        result.related_finding_ids.append(finding.finding_id)
        self.last_result = result
        return key_findings + [finding], result

    def _result(self, source: SourceReference, signature: SourceReference, status: str, valid_keys: List[str]) -> PgpVerificationResult:
        return PgpVerificationResult(
            signature_path=signature.original,
            signed_file_path=source.original,
            verification_status=status,
            normalized_validpgpkeys=valid_keys,
        )

    def _gpg_env(self, gnupg_home: Path) -> Dict[str, str]:
        return {
            "GNUPGHOME": str(gnupg_home),
            "HOME": str(gnupg_home),
            "GPG_TTY": "",
        }

    def _parse_signer_fingerprint(self, status: str) -> Optional[str]:
        for line in status.splitlines():
            if line.startswith("[GNUPG:] VALIDSIG "):
                parts = line.split()
                if len(parts) >= 3:
                    return PgpKeyNormalizer.normalize(parts[2])
        for line in status.splitlines():
            if line.startswith("[GNUPG:] GOODSIG "):
                parts = line.split()
                if len(parts) >= 3:
                    return PgpKeyNormalizer.normalize(parts[2])
        return None

    def _sanitize_status(self, status: str) -> str:
        # GnuPG status output may contain an attacker-controlled user ID after
        # GOODSIG/BADSIG and its ordinary diagnostics can echo filenames or
        # other package-controlled text.  Persist only allowlisted machine
        # status names and an optional hexadecimal key identifier.  Never
        # retain human-readable `gpg:` diagnostics or the remainder of a
        # status line.
        sanitized: List[str] = []
        for line in status.splitlines():
            if len(sanitized) >= _MAX_GPG_STATUS_LINES:
                break
            if not line.startswith("[GNUPG:] "):
                continue
            fields = line[len("[GNUPG:] "):].split()
            if not fields or fields[0] not in _GPG_STATUS_KEYWORDS:
                continue
            rendered = fields[0]
            for token in fields[1:]:
                if _GPG_STATUS_FINGERPRINT.fullmatch(token):
                    rendered += " " + token.upper()
                    break
            sanitized.append(rendered)
        return "\n".join(sanitized)[:2000]


class HttpSourceFetcher:
    def __init__(self, policy: Optional[SourcePolicy] = None, opener: Optional[urllib.request.OpenerDirector] = None):
        self.policy = policy or SourcePolicy()
        self.opener = opener or urllib.request.build_opener(_SafeRedirectHandler(self.policy))

    def fetch(self, ref: SourceReference, output_dir: Path) -> SourceAcquisitionResult:
        if self.policy.offline:
            return _offline_acquisition_result(ref)
        output_path = output_dir / _safe_filename(ref.filename)
        digest = hashlib.sha256()
        size = 0
        try:
            _validate_public_remote_url(ref.resolved, self.policy.allowed_redirect_schemes)
            request = urllib.request.Request(ref.resolved, headers={"User-Agent": "AuraScan/0.1"})
            with self.opener.open(request, timeout=self.policy.timeout) as response, output_path.open("xb") as handle:
                final_url = response.geturl()
                _validate_public_remote_url(final_url, self.policy.allowed_redirect_schemes)
                while True:
                    chunk = response.read(65536)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > self.policy.max_download_size:
                        raise ValueError("download exceeded maximum size")
                    digest.update(chunk)
                    handle.write(chunk)
        except (OSError, urllib.error.URLError, ValueError):
            if output_path.exists():
                output_path.unlink()
            return SourceAcquisitionResult(
                reference=ref,
                status="failed",
                findings=[_finding(
                    "SOURCE-HTTP-FETCH-FAILED",
                    "declared remote source",
                    Severity.HIGH,
                    "HTTP/HTTPS source acquisition failed, so deep-static inspection is incomplete.",
                    "Do not build or install until every declared source can be acquired and inspected safely.",
                    True,
                    "declared remote source was not acquired",
                )],
            )
        return SourceAcquisitionResult(ref, output_path, final_url, size, digest.hexdigest(), "acquired", [])


class GitSourceFetcher:
    def __init__(self, policy: Optional[SourcePolicy] = None, runner: Optional[Callable] = None):
        self.policy = policy or SourcePolicy()
        self.runner = runner or run_bounded_trusted_tool

    def fetch(self, ref: SourceReference, output_dir: Path) -> SourceAcquisitionResult:
        findings = self.classification_findings(ref)
        if self.policy.offline:
            findings.append(_offline_finding(ref))
            return SourceAcquisitionResult(ref, status="offline", findings=findings)
        if ref.fragment_type == "commit" and not _is_full_commit(ref.fragment_value or ""):
            findings.append(_finding(
                "SOURCE-GIT-COMMIT-NOT-FULL",
                "declared Git source",
                Severity.HIGH,
                "git+https source commit fragment is not a full 40-character commit hash.",
                "Pin to a full commit hash and inspect that exact revision before building or installing.",
                True,
                "Git source revision could not be acquired safely",
            ))
            return SourceAcquisitionResult(ref, status="skipped", findings=findings)
        try:
            git_tool = capture_trusted_system_tool("git")
        except TrustedToolError:
            git_tool = None
        if git_tool is None:
            findings.append(_finding(
                "SOURCE-GIT-UNAVAILABLE",
                "declared Git source",
                Severity.HIGH,
                "A trusted system Git executable is unavailable, so AuraScan could not acquire this source.",
                "Install the distribution Git package, repair PATH or executable permissions, or inspect the exact revision independently.",
                True,
                "declared Git source was not acquired",
            ))
            return SourceAcquisitionResult(ref, status="skipped", findings=findings)

        repo_url = self._repo_url(ref)
        checkout_dir = output_dir / _safe_filename(ref.filename)
        env = {
            "HOME": str(output_dir / "empty-home"),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "true",
            "SSH_AUTH_SOCK": "",
            "GIT_LFS_SKIP_SMUDGE": "1",
        }
        Path(env["HOME"]).mkdir(parents=True, exist_ok=True)
        try:
            _validate_public_remote_url(repo_url, {"https"})
            revalidate_trusted_system_tool(git_tool)
            self.runner(
                [git_tool.path, "-c", "credential.helper=", "-c", "core.hooksPath=/dev/null", "clone", "--no-recurse-submodules", "--filter=blob:none", repo_url, str(checkout_dir)],
                capture_output=True,
                text=True,
                timeout=self.policy.timeout,
                env=env,
                check=True,
            )
            if ref.fragment_type in {"commit", "tag", "branch"} and ref.fragment_value:
                revalidate_trusted_system_tool(git_tool)
                self.runner(
                    [git_tool.path, "-C", str(checkout_dir), "-c", "credential.helper=", "-c", "core.hooksPath=/dev/null", "checkout", "--detach" if ref.fragment_type != "branch" else ref.fragment_value, ref.fragment_value] if ref.fragment_type != "branch" else [git_tool.path, "-C", str(checkout_dir), "-c", "credential.helper=", "-c", "core.hooksPath=/dev/null", "checkout", ref.fragment_value],
                    capture_output=True,
                    text=True,
                    timeout=self.policy.timeout,
                    env=env,
                    check=True,
                )
        except (subprocess.SubprocessError, OSError, ValueError, TrustedToolError):
            shutil.rmtree(checkout_dir, ignore_errors=True)
            findings.append(_finding(
                "SOURCE-GIT-FETCH-FAILED",
                "declared Git source",
                Severity.HIGH,
                "Git source acquisition failed, so deep-static inspection is incomplete.",
                "Do not build or install until the exact declared revision can be acquired and inspected safely.",
                True,
                "declared Git source was not acquired",
            ))
            return SourceAcquisitionResult(ref, status="failed", findings=findings)
        return SourceAcquisitionResult(ref, checkout_dir, ref.resolved, 0, None, "acquired", findings)

    def classification_findings(self, ref: SourceReference) -> List[Finding]:
        if ref.fragment_type == "commit" and _is_full_commit(ref.fragment_value or ""):
            return [_finding(
                "SOURCE-GIT-PINNED-COMMIT",
                ref.original,
                Severity.LOW,
                "git+https source is pinned to a full commit hash.",
                "Pinned commits reduce source drift risk, but do not prove safety.",
                False,
                ref.fragment_value or "",
                EvidenceQuality.weak_heuristic,
            )]
        if ref.fragment_type == "tag":
            return [_finding(
                "SOURCE-GIT-TAG",
                ref.original,
                Severity.MEDIUM,
                "git+https source is pinned to a tag; signed tag verification is not implemented.",
                "Verify tag provenance manually.",
                False,
                ref.fragment_value or "",
            )]
        if ref.fragment_type == "branch":
            return [_finding(
                "SOURCE-GIT-BRANCH",
                ref.original,
                Severity.HIGH,
                "git+https source tracks a branch, which can change over time.",
                "Prefer a full commit hash or manually review the exact revision.",
                False,
                ref.fragment_value or "",
            )]
        return [_finding(
            "SOURCE-GIT-UNPINNED",
            ref.original,
            Severity.HIGH,
            "git+https source has no commit, tag, or branch fragment.",
            "Pin the source before relying on automated acquisition.",
            False,
            ref.original,
        )]

    def _repo_url(self, ref: SourceReference) -> str:
        parsed = urllib.parse.urlparse(ref.resolved[4:] if ref.resolved.startswith("git+") else ref.resolved)
        return urllib.parse.urlunparse(parsed._replace(fragment=""))


class SourceFetcher:
    def __init__(
        self,
        policy: Optional[SourcePolicy] = None,
        http_fetcher: Optional[HttpSourceFetcher] = None,
        git_fetcher: Optional[GitSourceFetcher] = None,
        checksum_verifier: Optional[ChecksumVerifier] = None,
        signature_verifier: Optional[SignatureVerifier] = None,
    ):
        self.policy = policy or SourcePolicy()
        self.http_fetcher = http_fetcher or HttpSourceFetcher(self.policy)
        self.git_fetcher = git_fetcher or GitSourceFetcher(self.policy)
        self.checksum_verifier = checksum_verifier or ChecksumVerifier()
        self.signature_verifier = signature_verifier or SignatureVerifier(self.policy)
        self.last_output_dir: Optional[Path] = None

    def acquire_all(self, refs: List[SourceReference], pkg_dir: Path) -> List[SourceAcquisitionResult]:
        output_dir = Path(tempfile.mkdtemp(prefix="aurascan-sources-"))
        self.last_output_dir = output_dir
        results: List[SourceAcquisitionResult] = []
        for ordinal, ref in enumerate(refs):
            # Each declaration receives its own private destination.  Distinct
            # URLs and renamed sources can normalize to the same basename; a
            # shared path would let a later source overwrite bytes recorded for
            # an earlier acquisition before content analysis begins.
            ref_output_dir = output_dir / f"source-{ordinal:04d}-{ref.index:04d}"
            ref_output_dir.mkdir(mode=0o700)
            result = self.acquire(ref, pkg_dir, ref_output_dir)
            if result.status != "acquired" and not any(
                finding.blocks_installation for finding in result.findings
            ):
                result.findings.append(_uninspected_source_finding(ref))
            result.findings.extend(self.checksum_verifier.verify(result))
            results.append(result)
        by_ref_index = {result.reference.index: result for result in results}
        for source_ref, signature_ref in self._matched_signatures(refs):
            source_result = by_ref_index.get(source_ref.index)
            signature_result = by_ref_index.get(signature_ref.index)
            if source_result is None:
                continue
            findings, pgp_result = self.signature_verifier.verify(
                source_ref,
                signature_ref,
                source_result.local_path,
                signature_result.local_path if signature_result else None,
            )
            if pgp_result:
                source_result.pgp_verification = pgp_result.to_dict()
            source_result.findings.extend(findings)
            if pgp_result and pgp_result.verification_status == "valid" and pgp_result.matched_validpgpkey:
                source_result.findings = [
                    finding for finding in source_result.findings
                    if finding.rule_id != "SOURCE-CHECKSUM-SKIP"
                ]
        return results

    def acquire(self, ref: SourceReference, pkg_dir: Path, output_dir: Path) -> SourceAcquisitionResult:
        if ref.kind == SourceKind.local:
            return self._acquire_local_file(ref, pkg_dir, output_dir)
        if ref.kind == SourceKind.http:
            if self.policy.offline:
                return _offline_acquisition_result(ref)
            return self.http_fetcher.fetch(ref, output_dir)
        if ref.kind == SourceKind.git_https:
            if self.policy.offline:
                return _offline_acquisition_result(ref)
            return self.git_fetcher.fetch(ref, output_dir)
        if ref.kind == SourceKind.signature:
            acquired = self._acquire_signature(ref, pkg_dir, output_dir)
            acquired.findings.append(_finding(
                "SOURCE-SIGNATURE-DETECTED",
                ref.original,
                Severity.LOW,
                "Detached signature source detected.",
                "AuraScan will verify it in an isolated keyring when the signed source is also available.",
                False,
                ref.original,
                EvidenceQuality.weak_heuristic,
            ))
            acquired.findings[-1].requires_manual_review = False
            return acquired
        return SourceAcquisitionResult(ref, status="unsupported", findings=[_finding(
            "SOURCE-UNSUPPORTED",
            "declared source",
            Severity.HIGH,
            "A declared source uses a scheme or VCS type AuraScan cannot inspect safely.",
            "Do not build or install until every declared source has been inspected independently.",
            True,
            "declared source was not inspected",
        )])

    def _acquire_signature(self, ref: SourceReference, pkg_dir: Path, output_dir: Path) -> SourceAcquisitionResult:
        parsed = urllib.parse.urlparse(ref.resolved)
        if parsed.scheme in {"http", "https"}:
            if self.policy.offline:
                return _offline_acquisition_result(ref)
            temp_ref = SourceReference(
                ref.original,
                ref.resolved,
                ref.index,
                ref.filename,
                ref.checksum_index,
                ref.checksum,
                ref.checksum_algorithm,
                SourceKind.http,
                validpgpkeys=ref.validpgpkeys,
            )
            result = self.http_fetcher.fetch(temp_ref, output_dir)
            result.reference = ref
            return result
        return self._acquire_local_file(ref, pkg_dir, output_dir)

    def _acquire_local_file(
        self,
        ref: SourceReference,
        pkg_dir: Path,
        output_dir: Path,
    ) -> SourceAcquisitionResult:
        try:
            source_fd = _open_bounded_local_source(
                pkg_dir,
                ref.resolved,
                max_bytes=self.policy.max_download_size,
            )
        except _LocalSourceError as exc:
            rule_id = "SOURCE-LOCAL-MISSING" if exc.code == "missing" else "SOURCE-LOCAL-UNSAFE"
            explanation = (
                "A declared local source file is missing, so deep-static inspection is incomplete."
                if exc.code == "missing"
                else "A declared local source could not be opened as a bounded, unchanged regular file inside the package directory."
            )
            return SourceAcquisitionResult(ref, status="failed", findings=[_finding(
                rule_id,
                "declared local source",
                Severity.HIGH,
                explanation,
                "Do not build or install until the complete local source set can be inspected safely.",
                True,
                "declared local source was not inspected",
            )])

        destination = output_dir / _safe_filename(ref.filename)
        digest = hashlib.sha256()
        copied = 0
        before = os.fstat(source_fd)
        destination_fd = -1
        try:
            destination_fd = os.open(
                str(destination),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
                0o600,
            )
            while True:
                chunk = os.read(source_fd, min(65536, self.policy.max_download_size + 1 - copied))
                if not chunk:
                    break
                copied += len(chunk)
                if copied > self.policy.max_download_size:
                    raise _LocalSourceError("oversized")
                digest.update(chunk)
                _write_all(destination_fd, chunk)
            after = os.fstat(source_fd)
            if _file_snapshot_identity(before) != _file_snapshot_identity(after) or copied != after.st_size:
                raise _LocalSourceError("changed")
        except (OSError, _LocalSourceError) as exc:
            if destination_fd >= 0:
                os.close(destination_fd)
                destination_fd = -1
            destination.unlink(missing_ok=True)
            code = exc.code if isinstance(exc, _LocalSourceError) else "read_error"
            return SourceAcquisitionResult(ref, status="failed", findings=[_finding(
                "SOURCE-LOCAL-UNSAFE",
                "declared local source",
                Severity.HIGH,
                "A declared local source changed, exceeded the size bound, or could not be copied safely for inspection.",
                "Do not build or install until the complete local source set can be inspected safely.",
                True,
                f"local source snapshot failed: {code}",
            )])
        finally:
            if destination_fd >= 0:
                os.close(destination_fd)
            os.close(source_fd)

        return SourceAcquisitionResult(
            ref,
            destination,
            None,
            copied,
            digest.hexdigest(),
            "acquired",
            [],
        )

    def _matched_signatures(self, refs: List[SourceReference]) -> List[Tuple[SourceReference, SourceReference]]:
        signatures = [ref for ref in refs if ref.kind == SourceKind.signature]
        sources = [ref for ref in refs if ref.kind != SourceKind.signature]
        matches: List[Tuple[SourceReference, SourceReference]] = []
        for signature in signatures:
            sig_base = self._signature_base(signature.filename) or self._signature_base(Path(urllib.parse.urlparse(signature.resolved).path).name)
            matched = next((source for source in sources if source.filename == sig_base), None)
            if matched is None:
                matched = next((source for source in sources if source.index == signature.index - 1), None)
            if matched:
                matches.append((matched, signature))
        return matches

    def _signature_base(self, name: str) -> str:
        for suffix in (".sig", ".asc"):
            if name.endswith(suffix):
                return name[:-len(suffix)]
        return ""


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, policy: SourcePolicy):
        self.policy = policy
        self.redirect_count = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        redirect_count = int(getattr(req, "_aurascan_redirect_count", 0)) + 1
        if redirect_count > self.policy.max_redirects:
            raise urllib.error.HTTPError(req.full_url, code, "too many redirects", headers, fp)
        try:
            _validate_public_remote_url(newurl, self.policy.allowed_redirect_schemes)
        except ValueError as exc:
            raise urllib.error.HTTPError(req.full_url, code, str(exc), headers, fp)
        redirected = super().redirect_request(req, fp, code, msg, headers, newurl)
        setattr(redirected, "_aurascan_redirect_count", redirect_count)
        return redirected


class _LocalSourceError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _open_bounded_local_source(pkg_dir: Path, value: str, *, max_bytes: int) -> int:
    """Open one relative regular file beneath pkg_dir without following links."""

    candidate = Path(value)
    parts = candidate.parts
    if (
        not value
        or candidate.is_absolute()
        or not parts
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise _LocalSourceError("unsafe_path")

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
        directory_fd = os.open(str(pkg_dir), directory_flags)
        if not stat.S_ISDIR(os.fstat(directory_fd).st_mode):
            raise _LocalSourceError("unsafe_root")
        for part in parts[:-1]:
            try:
                child_fd = os.open(part, directory_flags, dir_fd=directory_fd)
            except OSError as exc:
                raise _LocalSourceError(
                    "missing" if exc.errno == errno.ENOENT else "unsafe_component"
                ) from exc
            os.close(directory_fd)
            directory_fd = child_fd
            if not stat.S_ISDIR(os.fstat(directory_fd).st_mode):
                raise _LocalSourceError("unsafe_component")
        try:
            source_fd = os.open(parts[-1], file_flags, dir_fd=directory_fd)
        except OSError as exc:
            raise _LocalSourceError(
                "missing" if exc.errno == errno.ENOENT else "unsafe_file"
            ) from exc
        metadata = os.fstat(source_fd)
        if not stat.S_ISREG(metadata.st_mode):
            os.close(source_fd)
            raise _LocalSourceError("not_regular")
        if metadata.st_size > max_bytes:
            os.close(source_fd)
            raise _LocalSourceError("oversized")
        return source_fd
    except OSError as exc:
        raise _LocalSourceError(
            "missing" if exc.errno == errno.ENOENT else "unsafe_root"
        ) from exc
    finally:
        if directory_fd >= 0:
            os.close(directory_fd)


def _file_snapshot_identity(metadata: os.stat_result) -> Tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _write_all(fd: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(fd, payload[offset:])
        if written <= 0:
            raise OSError("short write while snapshotting local source")
        offset += written


def _offline_finding(ref: SourceReference) -> Finding:
    return _finding(
        "SOURCE-OFFLINE-UNINSPECTED",
        "declared remote source",
        Severity.HIGH,
        "Offline mode refused network acquisition of a declared remote source, so deep-static inspection is incomplete.",
        "Inspect a trusted local copy or rerun explicit deep-static acquisition with network access before building or installing.",
        True,
        "offline mode made no source network request",
    )


def _offline_acquisition_result(ref: SourceReference) -> SourceAcquisitionResult:
    return SourceAcquisitionResult(
        ref,
        status="offline",
        findings=[_offline_finding(ref)],
    )


def _uninspected_source_finding(ref: SourceReference) -> Finding:
    return _finding(
        "SOURCE-UNINSPECTED",
        "declared source",
        Severity.HIGH,
        "A declared source was not acquired as inspectable content, so deep-static inspection is incomplete.",
        "Do not build or install until every declared source can be inspected safely.",
        True,
        "declared source was not inspected",
    )


def _safe_filename(name: str) -> str:
    name = Path(name).name
    name = re.sub(r"[^A-Za-z0-9._+-]", "_", name)
    return "source" if name in {"", ".", ".."} else name


def _validate_public_remote_url(value: str, allowed_schemes: Iterable[str]) -> None:
    """Reject source URLs that can directly address local/private services.

    This is a lexical boundary around attacker-supplied package metadata.  It
    rejects embedded credentials, localhost names, and non-global IP literals
    for both the first request and every observed redirect.  It deliberately
    does not claim to solve DNS rebinding; the explicit deep-static network
    workflow remains a higher-risk opt-in operation.
    """

    parsed = urllib.parse.urlparse(value)
    if parsed.scheme not in set(allowed_schemes):
        raise ValueError("unsupported remote source scheme")
    if not parsed.hostname:
        raise ValueError("remote source URL has no host")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("remote source URL contains embedded credentials")
    hostname = parsed.hostname.rstrip(".").lower()
    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise ValueError("remote source URL targets localhost")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return
    if not address.is_global:
        raise ValueError("remote source URL targets a non-public address")


def _redact_source_reference(value: str) -> str:
    """Return bounded source metadata without URL credentials or query data."""

    safe_value = sanitize_terminal_text(str(value), max_chars=1024, single_line=True)
    rename = ""
    candidate = safe_value
    if "::" in candidate:
        rename, candidate = candidate.split("::", 1)
        rename = _safe_filename(rename) + "::"
    git_prefix = "git+" if candidate.startswith("git+") else ""
    parsed_value = candidate[4:] if git_prefix else candidate
    parsed = urllib.parse.urlparse(parsed_value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return safe_value
    host = parsed.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    try:
        port = f":{parsed.port}" if parsed.port is not None else ""
    except ValueError:
        port = ""
    redacted = urllib.parse.urlunparse(
        parsed._replace(netloc=host + port, query="", fragment="")
    )
    return rename + git_prefix + redacted


def _sha256_file(path: Path) -> str:
    return _hash_file(path, "sha256")


def _hash_file(path: Path, algorithm: str) -> str:
    if algorithm == "sha512":
        digest = hashlib.sha512()
    elif algorithm == "sha384":
        digest = hashlib.sha384()
    elif algorithm == "sha256":
        digest = hashlib.sha256()
    elif algorithm == "sha224":
        digest = hashlib.sha224()
    elif algorithm == "sha1":
        digest = hashlib.sha1()
    elif algorithm == "md5":
        digest = hashlib.md5()
    elif algorithm == "b2":
        digest = hashlib.blake2b()
    else:
        raise ValueError(f"unsupported checksum algorithm: {algorithm}")
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_full_commit(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{40}", value))


def _finding(
    rule_id: str,
    file_path: str,
    severity: Severity,
    explanation: str,
    recommendation: str,
    blocks: bool,
    evidence: str = "",
    evidence_quality: EvidenceQuality = EvidenceQuality.strong_heuristic,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        package_name="unknown",
        package_version="unknown",
        phase=Phase.source_archive_scan,
        source=Source.deterministic_rule,
        severity=severity,
        confidence=Confidence.CONFIRMED if evidence_quality == EvidenceQuality.confirmed_static_pattern else Confidence.HIGH,
        evidence_quality=evidence_quality,
        file_path=_redact_source_reference(file_path),
        explanation=explanation,
        recommendation=recommendation,
        blocks_installation=blocks,
        requires_manual_review=not blocks,
        evidence_snippet=_redact_source_reference(evidence),
    )
