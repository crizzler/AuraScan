import hashlib
import json
import os
import re
import shlex
import stat
import urllib.parse
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable, List, NamedTuple, Optional, Sequence, Tuple

from aurascan.core.config import MAX_SCRIPT_SIZE
from aurascan.core.repository_provenance import (
    RepositorySnapshot,
    capture_repository_snapshot,
)


INSTALL_HOOK_RESOLVER_VERSION = "1.0"
PACKAGE_SCAN_INPUT_VERSION = "2.0"
INSTALL_HOOK_NONE = "none"
INSTALL_HOOK_RESOLVED = "resolved"
INSTALL_HOOK_UNINSPECTED = "uninspected"
LEGACY_INSTALL_FILENAME = ".INSTALL"

_ASSIGNMENT_TOKEN_RE = re.compile(
    r"^(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?P<subscript>\[[^\]]*\])?"
    r"(?P<operator>\+=|=)(?P<value>.*)$",
    re.DOTALL,
)
_DECLARATION_BUILTINS = {"declare", "export", "local", "readonly", "typeset"}
_LEADING_RESERVED_WORDS = {"!", "do", "elif", "else", "if", "then", "until", "while"}
_MAX_RELATIVE_PATH_BYTES = 4096
_MAX_PATH_COMPONENTS = 64
_SIMPLE_STDOUT_REDIRECTION_MARKER = "\x00AURASCAN_STDOUT_REDIRECTION\x00"


@dataclass(frozen=True)
class InstallHookResolution:
    status: str
    declared: bool
    legacy: bool
    input_digest: str = ""
    content_sha256: str = ""
    path: Optional[Path] = None
    content: str = ""
    error_code: str = ""
    declaration_line: Optional[int] = None

    @property
    def inspectable(self) -> bool:
        return self.status == INSTALL_HOOK_RESOLVED and self.path is not None


@dataclass(frozen=True)
class PackageScanInput:
    """One immutable package-repository snapshot used by a scan decision."""

    pkgbuild_bytes: bytes
    pkgbuild_content: str
    install_hook: InstallHookResolution
    repository_snapshot: RepositorySnapshot
    input_digest: str


class PackageScanInputError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class _InstallDeclaration(NamedTuple):
    value: str
    operator: str
    declaration_hash: str
    line_number: int
    error_code: str = ""


class _HeredocLexState(NamedTuple):
    quote: str = ""
    arithmetic_depth: int = 0
    bracket_arithmetic_depth: int = 0
    test_expression: bool = False


class _PreparedShellText(NamedTuple):
    content: str
    dynamic_install_lines: Tuple[int, ...] = ()


class _DeclaredSourceCheckoutPaths(NamedTuple):
    files: Tuple[str, ...]
    vcs_directories: Tuple[str, ...]


def capture_package_scan_input(
    pkgbuild_path: Path,
    *,
    allow_legacy_install: bool = False,
    max_bytes: int = MAX_SCRIPT_SIZE,
) -> PackageScanInput:
    """Capture the exact bounded input identity shared by scan and wrapper."""

    pkgbuild_path = Path(pkgbuild_path)
    pkgbuild_bytes = _read_pkgbuild_snapshot(pkgbuild_path, max_bytes=max_bytes)
    content = pkgbuild_bytes.decode("utf-8", errors="replace")
    resolution = resolve_install_hook(
        pkgbuild_path,
        content,
        allow_legacy_install=allow_legacy_install,
        max_bytes=max_bytes,
    )
    excluded_paths = {pkgbuild_path.name}
    if resolution.inspectable and resolution.path is not None:
        try:
            excluded_paths.add(str(resolution.path.relative_to(pkgbuild_path.parent)))
        except ValueError:
            # The resolver already constrains literal hooks beneath the package
            # directory.  Preserve a fail-closed repository capture if that
            # invariant is ever violated rather than broadening an exclusion.
            pass
    declared_source_paths = _declared_source_checkout_paths(
        pkgbuild_path,
        content,
    )
    from aurascan.analyzers.repository_provenance import (
        collect_required_repository_paths,
    )

    required_repository_paths = collect_required_repository_paths(
        (
            content,
            resolution.content if resolution.inspectable else "",
        ),
        pkgbuild_path.parent,
    )
    repository_snapshot = capture_repository_snapshot(
        pkgbuild_path.parent,
        excluded_relative_paths=declared_source_paths.files,
        excluded_subtree_relative_paths=declared_source_paths.vcs_directories,
        independently_bound_relative_paths=excluded_paths,
        required_relative_paths=required_repository_paths.paths,
        required_paths_complete=required_repository_paths.complete,
    )
    try:
        verified_pkgbuild_bytes = _read_pkgbuild_snapshot(
            pkgbuild_path,
            max_bytes=max_bytes,
        )
    except PackageScanInputError as exc:
        raise PackageScanInputError("replaced_during_capture") from exc
    if verified_pkgbuild_bytes != pkgbuild_bytes:
        raise PackageScanInputError("replaced_during_capture")
    verified_resolution = resolve_install_hook(
        pkgbuild_path,
        content,
        allow_legacy_install=allow_legacy_install,
        max_bytes=max_bytes,
    )
    if verified_resolution.input_digest != resolution.input_digest:
        raise PackageScanInputError("replaced_during_capture")
    return PackageScanInput(
        pkgbuild_bytes=pkgbuild_bytes,
        pkgbuild_content=content,
        install_hook=resolution,
        repository_snapshot=repository_snapshot,
        input_digest=build_scan_input_digest(
            pkgbuild_bytes,
            resolution,
            repository_snapshot,
        ),
    )


def _declared_source_checkout_paths(
    pkgbuild_path: Path,
    content: str,
) -> _DeclaredSourceCheckoutPaths:
    """Return only makepkg checkout-root filenames proven by static parsing.

    ``source_acquisition`` imports shell-token helpers from this module, so the
    parser import must remain local to avoid a module-import cycle.  An
    ambiguous declaration deliberately yields no exclusions: repository
    artifacts then remain visible to the provenance analyzer while the source
    parser's own blocker reports the incomplete metadata inspection.
    """

    from aurascan.core.source_acquisition import SourceParser

    references, findings = SourceParser().parse(str(pkgbuild_path), content)
    if any(finding.rule_id == "SOURCE-PARSER-AMBIGUOUS" for finding in findings):
        return _DeclaredSourceCheckoutPaths((), ())

    filenames = set()
    vcs_directories = set()
    for reference in references:
        filename = _makepkg_checkout_relative_path(reference)
        if filename:
            if _reference_uses_vcs_directory(reference):
                vcs_directories.add(filename)
            else:
                filenames.add(filename)
    return _DeclaredSourceCheckoutPaths(
        tuple(sorted(filenames)),
        tuple(sorted(vcs_directories)),
    )


def _declared_source_filenames(pkgbuild_path: Path, content: str) -> Tuple[str, ...]:
    """Compatibility helper returning source-owned regular checkout files."""

    return _declared_source_checkout_paths(pkgbuild_path, content).files


def _reference_uses_vcs_directory(reference: object) -> bool:
    resolved = str(getattr(reference, "resolved", "") or "")
    kind_value = str(getattr(getattr(reference, "kind", ""), "value", ""))
    if kind_value.startswith("git"):
        return True
    parsed = urllib.parse.urlparse(resolved)
    protocol = parsed.scheme.lower().split("+", 1)[0]
    return protocol in {"bzr", "git", "hg", "svn"}


def _makepkg_checkout_relative_path(reference: object) -> str:
    """Model makepkg get_filename/get_filepath without sanitizing aliases."""

    original = str(getattr(reference, "original", "") or "")
    resolved = str(getattr(reference, "resolved", "") or "")
    unexpanded = str(
        getattr(reference, "unexpanded_original", original) or original
    )
    proven_static = getattr(reference, "checkout_name_proven_static", None)
    if proven_static is False:
        return ""
    if proven_static is None and any(
        marker in original or marker in resolved or marker in unexpanded
        for marker in ("$", "`")
    ):
        return ""
    if "::" in original:
        candidate = original.split("::", 1)[0]
    else:
        kind_value = str(getattr(getattr(reference, "kind", ""), "value", ""))
        parsed = urllib.parse.urlparse(resolved)
        vcs_protocol = (
            kind_value.startswith("git")
            or parsed.scheme.split("+", 1)[0]
            in {"bzr", "fossil", "git", "hg", "svn"}
        )
        if vcs_protocol:
            protocol = parsed.scheme.split("+", 1)[0]
            candidate = resolved.split("#", 1)[0].split("?", 1)[0].rstrip("/")
            candidate = candidate.rsplit("/", 1)[-1]
            if protocol == "bzr" and "lp:" in candidate:
                candidate = candidate.split("lp:", 1)[-1]
            if protocol == "fossil":
                candidate += ".fossil"
            if (kind_value.startswith("git") or protocol == "git") and ".git" in candidate:
                candidate = candidate.split(".git", 1)[0]
        else:
            # Match makepkg's literal ${netfile##*/}; ordinary URLs retain a
            # query/fragment and a trailing slash produces no filename.
            candidate = resolved.rsplit("/", 1)[-1]
    if not candidate or candidate.startswith("/") or "\\" in candidate:
        return ""
    path = PurePosixPath(candidate)
    if (
        not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(
            ord(character) < 32 or ord(character) == 127
            for character in candidate
        )
    ):
        return ""
    try:
        encoded = os.fsencode(candidate)
    except UnicodeError:
        return ""
    return candidate if len(encoded) <= _MAX_RELATIVE_PATH_BYTES else ""


def resolve_install_hook(
    pkgbuild_path: Path,
    pkgbuild_content: str,
    *,
    allow_legacy_install: bool = False,
    max_bytes: int = MAX_SCRIPT_SIZE,
) -> InstallHookResolution:
    """Resolve and read a literal local install hook without following links.

    This function treats PKGBUILD and hook contents only as bytes/text. It does
    not source the PKGBUILD, expand shell values, or execute the hook.
    """
    pkgbuild_path = Path(pkgbuild_path)
    declarations = list(_find_install_declarations(pkgbuild_content))
    if len(declarations) > 1:
        declaration_hash = _hash_text(
            "\n".join(declaration.declaration_hash for declaration in declarations)
        )
        return _uninspected(
            declared=True,
            legacy=False,
            error_code="ambiguous_declaration",
            declaration_hash=declaration_hash,
            declaration_line=declarations[0].line_number,
        )

    if declarations:
        declaration = declarations[0]
        if declaration.error_code:
            return _uninspected(
                declared=True,
                legacy=False,
                error_code=declaration.error_code,
                declaration_hash=declaration.declaration_hash,
                declaration_line=declaration.line_number,
            )
        relative_path, error_code = _parse_literal_relative_path(
            declaration.value,
            operator=declaration.operator,
        )
        if relative_path is None:
            return _uninspected(
                declared=True,
                legacy=False,
                error_code=error_code,
                declaration_hash=declaration.declaration_hash,
                declaration_line=declaration.line_number,
            )
        return _resolve_relative_file(
            pkgbuild_path.parent,
            relative_path,
            declared=True,
            legacy=False,
            declaration_hash=declaration.declaration_hash,
            declaration_line=declaration.line_number,
            max_bytes=max_bytes,
        )

    if allow_legacy_install:
        legacy_path = pkgbuild_path.parent / LEGACY_INSTALL_FILENAME
        if os.path.lexists(str(legacy_path)):
            return _resolve_relative_file(
                pkgbuild_path.parent,
                Path(LEGACY_INSTALL_FILENAME),
                declared=False,
                legacy=True,
                declaration_hash="",
                declaration_line=None,
                max_bytes=max_bytes,
            )

    return InstallHookResolution(
        status=INSTALL_HOOK_NONE,
        declared=False,
        legacy=False,
    )


def build_scan_input_digest(
    pkgbuild_bytes: bytes,
    resolution: InstallHookResolution,
    repository_snapshot: Optional[RepositorySnapshot] = None,
) -> str:
    """Bind a cache/review input identity to the exact bytes that were scanned."""
    material = {
        "install_hook_input_digest": resolution.input_digest,
        "package_scan_input_version": PACKAGE_SCAN_INPUT_VERSION,
        "pkgbuild_sha256": hashlib.sha256(pkgbuild_bytes).hexdigest(),
        "repository_input_digest": (
            repository_snapshot.input_digest if repository_snapshot is not None else ""
        ),
        "repository_status": (
            repository_snapshot.status if repository_snapshot is not None else "legacy"
        ),
        "resolver_version": INSTALL_HOOK_RESOLVER_VERSION,
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _parse_literal_relative_path(value: str, *, operator: str) -> Tuple[Optional[Path], str]:
    if operator != "=":
        return None, "unsupported_assignment"
    if not value:
        return None, "empty_declaration"
    if "$" in value or "`" in value or value.startswith("~"):
        return None, "dynamic_declaration"
    if value.startswith("("):
        return None, "ambiguous_declaration"
    token = value
    if not token or any(ord(character) < 32 or ord(character) == 127 for character in token):
        return None, "invalid_path"
    try:
        encoded_token = os.fsencode(token)
    except UnicodeError:
        return None, "invalid_path"
    if len(encoded_token) > _MAX_RELATIVE_PATH_BYTES:
        return None, "path_too_long"
    relative_path = Path(token)
    parts = relative_path.parts
    if relative_path.is_absolute() or not parts or len(parts) > _MAX_PATH_COMPONENTS:
        return None, "unsafe_path"
    if any(part in ("", ".", "..") for part in parts):
        return None, "unsafe_path"
    return relative_path, ""


def _find_install_declarations(content: str) -> Iterable[_InstallDeclaration]:
    prepared = _mask_heredoc_bodies(content)
    for line_number in prepared.dynamic_install_lines:
        yield _InstallDeclaration(
            "",
            "=",
            _hash_text("unquoted-heredoc-install-mutation"),
            line_number,
            "dynamic_declaration",
        )
    for segment, line_number in _iter_shell_segments(prepared.content):
        if not segment.strip():
            continue
        try:
            tokens = shlex.split(segment, comments=False, posix=True)
        except ValueError:
            if _segment_may_assign_install(segment):
                yield _InstallDeclaration(
                    "",
                    "=",
                    _hash_text(segment),
                    line_number,
                    "invalid_declaration",
                )
            continue
        if not tokens:
            continue

        index = 0
        while index < len(tokens) and tokens[index] in _LEADING_RESERVED_WORDS:
            index += 1
        if index >= len(tokens):
            continue

        if tokens[index] in _DECLARATION_BUILTINS:
            index += 1
            while index < len(tokens) and tokens[index].startswith("-"):
                index += 1
            for token in tokens[index:]:
                assignment = _assignment_from_token(token)
                if assignment is None:
                    if token == "install":
                        yield _InstallDeclaration(
                            "",
                            "=",
                            _hash_text(segment),
                            line_number,
                            "dynamic_declaration",
                        )
                    continue
                name, subscript, operator, value = assignment
                if name == "install":
                    yield _declaration_from_assignment(
                        segment,
                        line_number,
                        subscript,
                        operator,
                        value,
                    )
            continue

        segment_declarations: List[_InstallDeclaration] = []
        while index < len(tokens):
            assignment = _assignment_from_token(tokens[index])
            if assignment is None:
                if segment_declarations:
                    yield _InstallDeclaration(
                        "",
                        "=",
                        _hash_text(segment),
                        line_number,
                        "ambiguous_declaration",
                    )
                    segment_declarations = []
                    break
                if tokens[index] == "install" and index + 1 < len(tokens):
                    following = tokens[index + 1]
                    if following == "=" or following.startswith("=") or following == "+=":
                        yield _InstallDeclaration(
                            "",
                            "=",
                            _hash_text(segment),
                            line_number,
                            "invalid_declaration",
                        )
                break
            name, subscript, operator, value = assignment
            if name == "install":
                segment_declarations.append(_declaration_from_assignment(
                    segment,
                    line_number,
                    subscript,
                    operator,
                    value,
                ))
            if value.startswith("("):
                break
            index += 1
        for declaration in segment_declarations:
            yield declaration
        if not segment_declarations and index < len(tokens) and _mutates_install_noncanonically(tokens[index:]):
            yield _InstallDeclaration(
                "",
                "=",
                _hash_text(segment),
                line_number,
                "dynamic_declaration",
            )


def _assignment_from_token(token: str) -> Optional[Tuple[str, str, str, str]]:
    match = _ASSIGNMENT_TOKEN_RE.match(token)
    if match is None:
        return None
    return (
        match.group("name"),
        match.group("subscript") or "",
        match.group("operator"),
        match.group("value"),
    )


def _declaration_from_assignment(
    segment: str,
    line_number: int,
    subscript: str,
    operator: str,
    value: str,
) -> _InstallDeclaration:
    return _InstallDeclaration(
        value,
        operator,
        _hash_text(segment),
        line_number,
        "ambiguous_declaration" if subscript else "",
    )


def _mutates_install_noncanonically(tokens: Sequence[str]) -> bool:
    index = 0
    while index < len(tokens) and tokens[index] in {"builtin", "command"}:
        index += 1
        while index < len(tokens) and tokens[index].startswith("-"):
            index += 1
    if index >= len(tokens):
        return False
    command = tokens[index].rsplit("/", 1)[-1]
    arguments = list(tokens[index + 1:])
    if command == "printf":
        for argument_index, argument in enumerate(arguments):
            if argument == "-v" and argument_index + 1 < len(arguments):
                return arguments[argument_index + 1] == "install"
            if argument == "-vinstall":
                return True
        return False
    if command == "read":
        return any(argument == "install" for argument in arguments if not argument.startswith("-"))
    if command == "unset":
        return "install" in arguments
    if command == "eval":
        return any(re.search(r"(?:^|[;&|(){}\s])install(?:\[[^\]]*\])?\s*\+?=", argument) for argument in arguments)
    return False


def _segment_may_assign_install(segment: str) -> bool:
    return re.search(
        r"(?:^|[;&|(){}\s])install(?:\[[^\]]*\])?\s*(?:\+?=)",
        segment,
    ) is not None


def _iter_shell_segments(
    content: str,
    *,
    preserve_simple_stdout_redirections: bool = False,
) -> Iterable[Tuple[str, int]]:
    """Yield bounded shell segments without evaluating their contents.

    Most callers deliberately discard redirections because they are not part
    of assignment discovery.  The repository-provenance analyzer has one
    narrower need: recognizing an exact ``cat SOURCE > DESTINATION`` copy.  A
    caller may therefore retain only a plain stdout ``>`` and its single
    operand.  Descriptor redirects, append/clobber forms, heredocs, and every
    input redirect keep the historical stripping behavior.
    """
    buffer: List[str] = []
    quote = ""
    escaped = False
    array_depth = 0
    line_number = 1
    segment_line = 1
    at_word_start = True

    def flush() -> Optional[Tuple[str, int]]:
        nonlocal buffer, segment_line
        value = "".join(buffer)
        start = segment_line
        buffer = []
        segment_line = line_number
        if value.strip():
            return value, start
        return None

    index = 0
    while index < len(content):
        char = content[index]
        if quote:
            if (
                quote == '"'
                and char == "\\"
                and index + 1 < len(content)
                and content[index + 1] == "\n"
            ):
                line_number += 1
                index += 2
                continue
            buffer.append(char)
            if char == "\n":
                line_number += 1
            if quote == "'":
                if char == "'":
                    quote = ""
            elif escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            index += 1
            continue
        if char == "\\" and index + 1 < len(content) and content[index + 1] == "\n":
            line_number += 1
            index += 2
            continue
        if escaped:
            buffer.append(char)
            if char == "\n":
                line_number += 1
            escaped = False
            at_word_start = False
            index += 1
            continue
        if char == "\\":
            buffer.append(char)
            escaped = True
            index += 1
            continue
        if char in {"'", '"'}:
            buffer.append(char)
            quote = char
            at_word_start = False
            index += 1
            continue
        if char == "#" and at_word_start:
            while index < len(content) and content[index] != "\n":
                index += 1
            continue
        if char == "(" and _buffer_ends_assignment(buffer):
            array_depth += 1
            buffer.append(char)
            at_word_start = True
            index += 1
            continue
        if array_depth:
            buffer.append(char)
            if char == "(":
                array_depth += 1
            elif char == ")":
                array_depth -= 1
            if char == "\n":
                line_number += 1
                at_word_start = True
            else:
                at_word_start = char.isspace() or char in ";|&(){}"
            index += 1
            continue
        if char == "\n":
            item = flush()
            if item is not None:
                yield item
            line_number += 1
            segment_line = line_number
            at_word_start = True
            index += 1
            continue
        if (
            char in "<>" or (char == "&" and content.startswith("&>", index))
        ) and array_depth == 0:
            redirection_end = _skip_redirection(content, index)
            adjacent_descriptor = (
                char == ">"
                and index > 0
                and content[index - 1].isdigit()
                and re.search(r"(?:^|\s)[0-9]+$", "".join(buffer)) is not None
            )
            plain_stdout = (
                preserve_simple_stdout_redirections
                and char == ">"
                and not adjacent_descriptor
                and not content.startswith((">>", ">&", ">|"), index)
            )
            if plain_stdout:
                buffer.append(" ")
                buffer.extend(_SIMPLE_STDOUT_REDIRECTION_MARKER)
                buffer.append(" ")
                buffer.extend(content[index + 1:redirection_end])
                buffer.append(" ")
                at_word_start = True
                index = redirection_end
                continue
            if buffer:
                joined = "".join(buffer)
                trimmed = re.sub(r"(?:^|\s)[0-9]+$", " ", joined)
                buffer = list(trimmed)
            buffer.append(" ")
            at_word_start = True
            index = redirection_end
            continue
        brace_operator = (
            char in "{}"
            and at_word_start
            and (
                index + 1 >= len(content)
                or content[index + 1].isspace()
                or content[index + 1] in ";|&(){}"
            )
        )
        if char == "{" and content.startswith("{}", index):
            if not buffer:
                segment_line = line_number
            buffer.extend(("{", "}"))
            at_word_start = False
            index += 2
            continue
        if char in ";|&()" or brace_operator:
            item = flush()
            if item is not None:
                yield item
            at_word_start = True
            index += 1
            continue
        if not buffer and not char.isspace():
            segment_line = line_number
        buffer.append(char)
        at_word_start = char.isspace()
        index += 1

    item = flush()
    if item is not None:
        yield item


def _buffer_ends_assignment(buffer: Sequence[str]) -> bool:
    return re.search(r"(?:^|\s)[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=\s*$", "".join(buffer)) is not None


def _skip_redirection(content: str, start: int) -> int:
    operators = (
        "&>>", "<<<", "<<-", "<<", ">>", "<>", ">&", "<&", ">|", "&>", "<", ">",
    )
    operator = next(
        (value for value in operators if content.startswith(value, start)),
        content[start],
    )
    index = start + len(operator)
    while index < len(content) and content[index] in " \t":
        index += 1

    quote = ""
    escaped = False
    while index < len(content):
        char = content[index]
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
            index += 1
            continue
        if escaped:
            escaped = False
            index += 1
            continue
        if char == "\\":
            escaped = True
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            index += 1
            continue
        if char.isspace() or char in ";|&(){}<>":
            break
        index += 1
    return index


def _mask_heredoc_bodies(content: str) -> _PreparedShellText:
    """Mask here-document bodies without changing offsets or line count."""

    lines = content.splitlines(keepends=True)
    output: List[str] = []
    pending: List[Tuple[str, bool, bool]] = []
    dynamic_install_lines: List[int] = []
    state = _HeredocLexState()
    for line_number, line in enumerate(lines, 1):
        if pending:
            delimiter, strip_tabs, quoted = pending[0]
            candidate = line.rstrip("\r\n")
            if strip_tabs:
                candidate = candidate.lstrip("\t")
            if candidate != delimiter and not quoted and _heredoc_expansion_mutates_install(line):
                dynamic_install_lines.append(line_number)
            output.append("".join("\n" if char == "\n" else "\r" if char == "\r" else " " for char in line))
            if candidate == delimiter:
                pending.pop(0)
            continue

        output.append(line)
        delimiters, state = _heredoc_delimiters(line, state)
        pending.extend(delimiters)
    return _PreparedShellText(
        "".join(output),
        tuple(dynamic_install_lines),
    )


def _heredoc_delimiters(
    line: str,
    initial_state: _HeredocLexState,
) -> Tuple[List[Tuple[str, bool, bool]], _HeredocLexState]:
    found: List[Tuple[str, bool, bool]] = []
    quote = initial_state.quote
    arithmetic_depth = initial_state.arithmetic_depth
    bracket_arithmetic_depth = initial_state.bracket_arithmetic_depth
    test_expression = initial_state.test_expression
    escaped = False
    at_word_start = True
    index = 0
    while index < len(line):
        char = line[index]
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
            index += 1
            continue
        if escaped:
            escaped = False
            at_word_start = False
            index += 1
            continue
        if char == "\\":
            escaped = True
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            at_word_start = False
            index += 1
            continue
        if char == "#" and at_word_start:
            break
        if arithmetic_depth:
            if char == "(":
                arithmetic_depth += 1
            elif char == ")":
                arithmetic_depth -= 1
            index += 1
            continue
        if bracket_arithmetic_depth:
            if char == "[":
                bracket_arithmetic_depth += 1
            elif char == "]":
                bracket_arithmetic_depth -= 1
            index += 1
            continue
        if test_expression:
            if line.startswith("]]", index):
                test_expression = False
                index += 2
            else:
                index += 1
            continue
        if line.startswith("$((", index):
            arithmetic_depth = 2
            index += 3
            continue
        if line.startswith("((", index):
            arithmetic_depth = 2
            index += 2
            continue
        if line.startswith("$[", index):
            bracket_arithmetic_depth = 1
            index += 2
            continue
        if line.startswith("[[", index):
            test_expression = True
            index += 2
            continue
        if line.startswith("<<", index) and not line.startswith("<<<", index):
            cursor = index + 2
            strip_tabs = cursor < len(line) and line[cursor] == "-"
            if strip_tabs:
                cursor += 1
            while cursor < len(line) and line[cursor] in " \t":
                cursor += 1
            delimiter, cursor, quoted = _read_heredoc_word(line, cursor)
            if delimiter:
                found.append((delimiter, strip_tabs, quoted))
            index = max(cursor, index + 2)
            continue
        at_word_start = char.isspace() or char in ";|&(){}"
        index += 1
    return found, _HeredocLexState(
        quote=quote,
        arithmetic_depth=arithmetic_depth,
        bracket_arithmetic_depth=bracket_arithmetic_depth,
        test_expression=test_expression,
    )


def _read_heredoc_word(line: str, start: int) -> Tuple[str, int, bool]:
    value: List[str] = []
    quote = ""
    escaped = False
    quoted = False
    index = start
    while index < len(line):
        char = line[index]
        if quote:
            if quote == "'":
                if char == "'":
                    quote = ""
                else:
                    value.append(char)
            elif escaped:
                value.append(char)
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            else:
                value.append(char)
            index += 1
            continue
        if escaped:
            value.append(char)
            escaped = False
            index += 1
            continue
        if char == "\\":
            quoted = True
            escaped = True
            index += 1
            continue
        if char in {"'", '"'}:
            quoted = True
            quote = char
            index += 1
            continue
        if char.isspace() or char in ";|&(){}<>":
            break
        value.append(char)
        index += 1
    return "".join(value), index, quoted


def _heredoc_expansion_mutates_install(line: str) -> bool:
    parameter_assignment = re.search(
        r"\$\{[ \t]*install(?:\[[^\]\r\n]*\])?[ \t]*(?::?=)",
        line,
    )
    if parameter_assignment is not None:
        return True
    arithmetic_assignment = re.search(
        r"(?:\$\(\([^\r\n]*|\$\[[^\r\n]*)"
        r"\binstall(?:\[[^\]\r\n]*\])?[ \t]*"
        r"(?:\+\+|--|(?:<<|>>|[+\-*/%&|^])?=)",
        line,
    )
    return arithmetic_assignment is not None


def _resolve_relative_file(
    root: Path,
    relative_path: Path,
    *,
    declared: bool,
    legacy: bool,
    declaration_hash: str,
    declaration_line: Optional[int],
    max_bytes: int,
) -> InstallHookResolution:
    relative_text = relative_path.as_posix()
    try:
        raw_content = _read_regular_file_no_follow(root, relative_path.parts, max_bytes=max_bytes)
    except _InstallHookReadError as exc:
        return _uninspected(
            declared=declared,
            legacy=legacy,
            error_code=exc.code,
            declaration_hash=declaration_hash,
            relative_path=relative_text,
            declaration_line=declaration_line,
        )

    content_sha256 = hashlib.sha256(raw_content).hexdigest()
    input_digest = _input_digest(
        status=INSTALL_HOOK_RESOLVED,
        declared=declared,
        legacy=legacy,
        error_code="",
        declaration_hash=declaration_hash,
        relative_path=relative_text,
        content_sha256=content_sha256,
    )
    return InstallHookResolution(
        status=INSTALL_HOOK_RESOLVED,
        declared=declared,
        legacy=legacy,
        input_digest=input_digest,
        content_sha256=content_sha256,
        path=root / relative_path,
        content=raw_content.decode("utf-8", errors="replace"),
        declaration_line=declaration_line,
    )


def _uninspected(
    *,
    declared: bool,
    legacy: bool,
    error_code: str,
    declaration_hash: str,
    relative_path: str = "",
    declaration_line: Optional[int] = None,
) -> InstallHookResolution:
    return InstallHookResolution(
        status=INSTALL_HOOK_UNINSPECTED,
        declared=declared,
        legacy=legacy,
        input_digest=_input_digest(
            status=INSTALL_HOOK_UNINSPECTED,
            declared=declared,
            legacy=legacy,
            error_code=error_code,
            declaration_hash=declaration_hash,
            relative_path=relative_path,
            content_sha256="",
        ),
        error_code=error_code,
        declaration_line=declaration_line,
    )


def _input_digest(
    *,
    status: str,
    declared: bool,
    legacy: bool,
    error_code: str,
    declaration_hash: str,
    relative_path: str,
    content_sha256: str,
) -> str:
    material = {
        "content_sha256": content_sha256,
        "declaration_sha256": declaration_hash,
        "declared": declared,
        "error_code": error_code,
        "legacy": legacy,
        "relative_path_sha256": _hash_text(relative_path) if relative_path else "",
        "resolver_version": INSTALL_HOOK_RESOLVER_VERSION,
        "status": status,
    }
    encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _line_number(content: str, offset: int) -> int:
    return content.count("\n", 0, offset) + 1


class _InstallHookReadError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _read_pkgbuild_snapshot(path: Path, *, max_bytes: int) -> bytes:
    try:
        return _read_regular_file_no_follow(
            path.parent,
            (path.name,),
            max_bytes=max_bytes,
        )
    except _InstallHookReadError as exc:
        raise PackageScanInputError(exc.code) from exc


def _read_regular_file_no_follow(root: Path, parts: Sequence[str], *, max_bytes: int) -> bytes:
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    if not no_follow or not directory_flag:
        raise _InstallHookReadError("no_follow_unavailable")

    directory_fds = []
    file_fd = None
    try:
        try:
            current_fd = os.open(
                str(root),
                os.O_RDONLY | directory_flag | no_follow | getattr(os, "O_CLOEXEC", 0),
            )
        except OSError:
            raise _InstallHookReadError("root_unavailable")
        directory_fds.append(current_fd)

        for component in parts[:-1]:
            try:
                next_fd = os.open(
                    component,
                    os.O_RDONLY | directory_flag | no_follow | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=current_fd,
                )
            except OSError:
                raise _InstallHookReadError("unsafe_parent")
            try:
                if not stat.S_ISDIR(os.fstat(next_fd).st_mode):
                    raise _InstallHookReadError("unsafe_parent")
            except (OSError, _InstallHookReadError):
                try:
                    os.close(next_fd)
                except OSError:
                    pass
                raise _InstallHookReadError("unsafe_parent")
            directory_fds.append(next_fd)
            current_fd = next_fd

        final_name = parts[-1]
        try:
            before_path = os.stat(final_name, dir_fd=current_fd, follow_symlinks=False)
        except OSError:
            raise _InstallHookReadError("missing_or_unreadable")
        if stat.S_ISLNK(before_path.st_mode):
            raise _InstallHookReadError("symlink")
        if not stat.S_ISREG(before_path.st_mode):
            raise _InstallHookReadError("not_regular")
        if before_path.st_size < 0 or before_path.st_size > max_bytes:
            raise _InstallHookReadError("oversized")

        try:
            file_fd = os.open(
                final_name,
                os.O_RDONLY
                | no_follow
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NONBLOCK", 0),
                dir_fd=current_fd,
            )
        except OSError:
            raise _InstallHookReadError("missing_or_unreadable")
        try:
            opened = os.fstat(file_fd)
        except OSError:
            raise _InstallHookReadError("missing_or_unreadable")
        if not stat.S_ISREG(opened.st_mode):
            raise _InstallHookReadError("not_regular")
        if _file_identity(before_path) != _file_identity(opened):
            raise _InstallHookReadError("replaced_during_read")

        chunks = []
        total = 0
        while True:
            try:
                chunk = os.read(file_fd, min(65536, max_bytes + 1 - total))
            except InterruptedError:
                continue
            except OSError:
                raise _InstallHookReadError("read_failed")
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise _InstallHookReadError("oversized")

        try:
            after_fd = os.fstat(file_fd)
            after_path = os.stat(final_name, dir_fd=current_fd, follow_symlinks=False)
        except OSError:
            raise _InstallHookReadError("replaced_during_read")
        if not stat.S_ISREG(after_path.st_mode):
            raise _InstallHookReadError("replaced_during_read")
        if _file_state(opened) != _file_state(after_fd) or _file_state(after_fd) != _file_state(after_path):
            raise _InstallHookReadError("replaced_during_read")
        return b"".join(chunks)
    finally:
        if file_fd is not None:
            try:
                os.close(file_fd)
            except OSError:
                pass
        for directory_fd in reversed(directory_fds):
            try:
                os.close(directory_fd)
            except OSError:
                pass


def _file_identity(metadata: os.stat_result) -> Tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def _file_state(metadata: os.stat_result) -> Tuple[int, int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        getattr(metadata, "st_mtime_ns", int(metadata.st_mtime * 1_000_000_000)),
        getattr(metadata, "st_ctime_ns", int(metadata.st_ctime * 1_000_000_000)),
    )
