"""Correlate opaque package-checkout artifacts with active package logic.

This module consumes an immutable repository snapshot captured elsewhere.  It
never opens an artifact, evaluates PKGBUILD syntax, or executes package code.
The shell view is the same bounded, quote-aware command view used by the
remote-stage analyzer.
"""

import os
import posixpath
import re
import shlex
from pathlib import Path, PurePosixPath
from typing import Dict, Iterable, List, NamedTuple, Optional, Sequence, Set, Tuple

from aurascan.analyzers.aur_propagation import _active_shell_text
from aurascan.analyzers.remote_access import mask_shell_quoted_text
from aurascan.analyzers.remote_stage import (
    _basename,
    _commands_and_constants,
    _executed_path_status,
    _resolve as _resolve_named_variables,
)
from aurascan.core.install_hook import (
    INSTALL_HOOK_RESOLVED,
    InstallHookResolution,
    _SIMPLE_STDOUT_REDIRECTION_MARKER,
    _iter_shell_segments,
    _makepkg_checkout_relative_path,
)
from aurascan.core.models import (
    AnalysisResult,
    Confidence,
    EvidenceQuality,
    Finding,
    Phase,
    Severity,
    Source,
)
from aurascan.core.repository_provenance import (
    REPOSITORY_COMPLETE,
    RepositoryArtifact,
    RepositorySnapshot,
)
from aurascan.core.source_acquisition import SourceParser


_TRANSFER_COMMANDS = {
    "bsdtar", "cat", "cp", "dd", "install", "ln", "mv", "rsync", "tar",
    "unzip",
}
_TRANSFER_OPTIONS_WITH_VALUE = {
    "cp": {"-S", "--suffix", "-t", "--target-directory"},
    "install": {
        "-g",
        "--group",
        "-m",
        "--mode",
        "-o",
        "--owner",
        "-S",
        "--suffix",
        "--strip-program",
        "-t",
        "--target-directory",
    },
    "mv": {"-S", "--suffix", "-t", "--target-directory"},
    "ln": {"-S", "--suffix", "-t", "--target-directory"},
}
_TARGET_DIRECTORY_OPTIONS = {"-t", "--target-directory"}
_KNOWN_REPOSITORY_PREFIXES = (
    "$startdir/",
    "${startdir}/",
    "$pkgbuilddir/",
    "${pkgbuilddir}/",
)
_KNOWN_SRCDIR_PARENT_PREFIXES = (
    "$srcdir/../",
    "${srcdir}/../",
)
_KNOWN_SRCDIR_PREFIXES = ("$srcdir/", "${srcdir}/")
_KNOWN_CWD_PREFIXES = ("$PWD/", "${PWD}/")
_SUID_NUMERIC_MODE = re.compile(r"0?[2-7][0-7]{3}\Z")
_SUID_SYMBOLIC_MODE = re.compile(
    r"(?:\+s|[ugoa]*[ug][ugoa]*\+s|a\+s)\Z",
    re.IGNORECASE,
)
_MAX_RESOLUTION_PASSES = 4
_MAX_CORRELATION_OPERATIONS = 262_144
_LITERAL_SHELL_WORK_CHARS = 256
_FUNCTION_NAME_PATTERN = (
    r"(?:package_[A-Za-z0-9@._+\-]+|[A-Za-z_][A-Za-z0-9_]*)"
)
_FUNCTION_START = re.compile(
    r"^[ \t]*(?:"
    r"function[ \t]+(?P<function_name>" + _FUNCTION_NAME_PATTERN + r")"
    r"(?:[ \t]*\(\))?"
    r"|(?P<plain_name>" + _FUNCTION_NAME_PATTERN + r")[ \t]*\(\)"
    r")[ \t]*\{",
    re.MULTILINE,
)
_SIMPLE_ASSIGNMENT = re.compile(
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?P<operator>\+=|=)(?P<value>.*)",
    re.DOTALL,
)
_VARIABLE_REFERENCE = re.compile(
    r"\$(?:\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)\}|"
    r"(?P<plain>[A-Za-z_][A-Za-z0-9_]*))"
)
_TAINTED_VARIABLE_REFERENCE = re.compile(
    r"\$(?:\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\[[^]}]*\])?\}|(?P<plain>[A-Za-z_][A-Za-z0-9_]*))"
)
_POSITIONAL_REFERENCE = re.compile(
    r"\$(?:\{(?P<braced>[1-9][0-9]*)\}|(?P<plain>[1-9]))"
)
_DECLARATION_COMMANDS = {"declare", "export", "local", "readonly", "typeset"}
_SPECIAL_PATH_VARIABLES = {"pkgbuilddir", "pkgdir", "srcdir", "startdir"}
_MAX_SCOPED_COMMANDS = 16_384
_MAX_SCOPED_CONSTANTS = 4_096
_MAX_FUNCTION_SCOPES = 512
_MAX_FUNCTION_INVOCATIONS = 1_024
_MAX_FUNCTION_ARGUMENTS = 64
_PKGBUILD_LIFECYCLE_FUNCTIONS = {
    "build", "check", "package", "pkgver", "prepare", "verify",
}
_INSTALL_HOOK_LIFECYCLE_FUNCTIONS = {
    "post_install",
    "post_remove",
    "post_transaction",
    "post_upgrade",
    "pre_install",
    "pre_remove",
    "pre_transaction",
    "pre_upgrade",
}
_PACKAGE_NAME = re.compile(r"[A-Za-z0-9@._+][A-Za-z0-9@._+\-]*\Z")
_FUNCTION_BYPASS_WRAPPERS = {"builtin", "command", "env", "exec"}
_EXECUTION_WRAPPERS = {
    "chroot",
    "chrt",
    "doas",
    "ionice",
    "nice",
    "nohup",
    "pkexec",
    "prlimit",
    "runuser",
    "setarch",
    "setsid",
    "stdbuf",
    "sudo",
    "systemd-run",
    "taskset",
    "timeout",
}
_EXECUTION_WRAPPER_OPTIONS_WITH_VALUE = {
    "-a",
    "-C",
    "-D",
    "-g",
    "-h",
    "-p",
    "-R",
    "-T",
    "-u",
    "--chdir",
    "--close-from",
    "--group",
    "--host",
    "--prompt",
    "--root",
    "--role",
    "--type",
    "--unit",
    "--user",
    "--working-directory",
}
_SETARCH_NAMES = {
    "athlon",
    "i386",
    "i486",
    "i586",
    "i686",
    "linux32",
    "linux64",
    "x86_64",
}
_DYNAMIC_LOADER_OPTIONS_WITH_VALUE = {
    "--argv0",
    "--audit",
    "--library-path",
    "--preload",
}
_QEMU_OPTIONS_WITH_VALUE = {
    "-0",
    "-B",
    "-D",
    "-E",
    "-L",
    "-R",
    "-U",
    "-cpu",
}
_CODE_LOADING_ASSIGNMENTS = {"LD_AUDIT", "LD_PRELOAD"}
_COMMAND_CONSUMERS = {"find", "parallel", "watch", "xargs"}
_SHELL_BUILTINS = {
    ".", ":", "[", "alias", "bg", "bind", "break", "builtin", "caller",
    "cd", "command", "compgen", "complete", "continue", "declare", "dirs",
    "disown", "echo", "enable", "eval", "exec", "exit", "export", "false",
    "fc", "fg", "getopts", "hash", "help", "history", "jobs", "kill", "let",
    "local", "logout", "mapfile", "popd", "printf", "pushd", "pwd", "read",
    "readarray", "readonly", "return", "set", "shift", "shopt", "source",
    "suspend", "test", "times", "trap", "true", "type", "typeset", "ulimit",
    "umask", "unalias", "unset", "wait",
}


class _Transfer(NamedTuple):
    sources: Tuple[str, ...]
    destination: str
    target_directory: bool
    suid_mode: bool
    destination_exact: bool
    no_target_directory: bool
    recursive: bool
    preserves_mode: bool


class _Correlation(NamedTuple):
    rule_id: str
    phase: Phase
    file_path: str
    line_number: Optional[int]
    evidence: str


class _ExecutionCandidate(NamedTuple):
    path: str
    allow_bare: bool


class _ScopedCommand(NamedTuple):
    command: object
    constants: Dict[str, str]
    scope_id: int
    repository_cwd: Optional[str]
    repository_cwd_possible: bool
    exported_loaders: Tuple[Tuple[str, Optional[str]], ...]
    lifecycle_root: str
    function_dispatch_allowed: bool
    tainted_constants: Tuple[str, ...]


class _FunctionRegion(NamedTuple):
    name: str
    start: int
    line_number: int
    body_start: int
    body_end: int
    end: int


class _FunctionInvocation(NamedTuple):
    name: str
    arguments: Tuple[str, ...]
    constants: Tuple[Tuple[str, str], ...]
    exported_loaders: Tuple[Tuple[str, Optional[str]], ...]
    repository_cwd: Optional[str]
    repository_cwd_possible: bool
    tainted_constants: Tuple[str, ...]


class RequiredRepositoryPaths(NamedTuple):
    paths: Tuple[str, ...]
    complete: bool


def _resolve(token: str, constants: Dict[str, str]) -> str:
    """Resolve bounded named and positional constants in one shell token."""

    resolved = _resolve_named_variables(token, constants)
    if not resolved or len(resolved) > 8192:
        return resolved
    output: List[str] = []
    cursor = 0
    size = 0
    for match in _POSITIONAL_REFERENCE.finditer(resolved):
        literal = resolved[cursor:match.start()]
        name = match.group("braced") or match.group("plain") or ""
        replacement = constants.get(name, match.group(0))
        size += len(literal) + len(replacement)
        if size > 8192:
            return resolved
        output.extend((literal, replacement))
        cursor = match.end()
    suffix = resolved[cursor:]
    if size + len(suffix) > 8192:
        return resolved
    output.append(suffix)
    return "".join(output)


def _function_regions(active_text: str) -> Optional[List[_FunctionRegion]]:
    """Locate top-level shell function bodies without evaluating them."""

    regions: List[_FunctionRegion] = []
    cursor = 0
    while True:
        match = _FUNCTION_START.search(active_text, cursor)
        if match is None:
            return regions
        if len(regions) >= _MAX_FUNCTION_SCOPES:
            return None
        opening = match.end() - 1
        closing = _matching_function_brace(active_text, opening)
        if closing is None:
            return None
        name = match.group("function_name") or match.group("plain_name") or ""
        if not name:
            return None
        regions.append(
            _FunctionRegion(
                name,
                match.start(),
                active_text.count("\n", 0, match.start()) + 1,
                opening + 1,
                closing,
                closing + 1,
            )
        )
        cursor = closing + 1


def _matching_function_brace(text: str, opening: int) -> Optional[int]:
    depth = 0
    quote = ""
    escaped = False
    index = opening
    while index < len(text):
        character = text[index]
        if quote:
            if quote == "'":
                if character == "'":
                    quote = ""
            elif escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = ""
            index += 1
            continue
        if escaped:
            escaped = False
            index += 1
            continue
        if character == "\\":
            escaped = True
            index += 1
            continue
        if character in {"'", '"'}:
            quote = character
            index += 1
            continue
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return index
            if depth < 0:
                return None
        index += 1
    return None


def _scoped_commands(
    text: str,
    checkout_dir: Path,
    *,
    top_level_repository_cwd: bool = False,
    lifecycle_kind: str = "pkgbuild",
) -> Optional[List[_ScopedCommand]]:
    """Return reachable commands with constants valid at that point.

    Top-level assignments are evaluated sequentially and their final bounded
    values seed lifecycle functions.  Helper bodies are instantiated only
    after a bounded static call from top-level or reachable lifecycle logic;
    positional values are propagated per invocation.  Function-local
    assignments do not leak into a different invocation, and a later
    assignment never resolves an earlier command.
    """

    if lifecycle_kind not in {"install_hook", "pkgbuild"}:
        return None
    if (
        _SIMPLE_STDOUT_REDIRECTION_MARKER in text
        or _commands_and_constants(text) is None
    ):
        return None
    active = _active_shell_text(text)
    regions = _function_regions(mask_shell_quoted_text(active))
    if regions is None:
        return None
    definitions: Dict[str, _FunctionRegion] = {}
    for region in regions:
        if region.name in definitions:
            # Bash permits replacement definitions, but call ordering then
            # matters.  Do not guess which body is reachable.
            return None
        definitions[region.name] = region

    top_level = list(active)
    top_level_original = list(text)
    for region in regions:
        for index in range(region.start, region.end):
            if top_level[index] not in {"\n", "\r"}:
                top_level[index] = " "
            if top_level_original[index] not in {"\n", "\r"}:
                top_level_original[index] = " "
    (
        top_commands,
        globals_after,
        exported_after,
        tainted_after,
    ) = _sequential_scope_commands(
        "".join(top_level),
        {},
        {},
        set(),
        checkout_dir,
        scope_id=0,
        line_offset=0,
        initial_repository_cwd="" if top_level_repository_cwd else None,
        initial_repository_cwd_possible=False,
        lifecycle_root="top-level",
    )
    if top_commands is None:
        return None

    split_lifecycle_roots = (
        _declared_split_package_functions(
            "".join(top_level_original),
            definitions,
        )
        if lifecycle_kind == "pkgbuild"
        else set()
    )
    if split_lifecycle_roots is None:
        return None

    collected: List[_ScopedCommand] = []
    invocation_count = 0

    def expand_invocation(
        invocation: _FunctionInvocation,
        flow_id: int,
        active_calls: Set[_FunctionInvocation],
        lifecycle_root: str,
    ) -> bool:
        nonlocal invocation_count
        invocation_count += 1
        if invocation_count > _MAX_FUNCTION_INVOCATIONS:
            return False
        if invocation in active_calls:
            # Recursive shell flow can execute an unbounded number of helper
            # commands and cannot be flattened into a finite temporal proof.
            return False
        region = definitions.get(invocation.name)
        if region is None:
            return False
        body = active[region.body_start:region.body_end]
        if _FUNCTION_START.search(mask_shell_quoted_text(body)):
            return False
        line_offset = active.count("\n", 0, region.body_start)
        invocation_constants = {
            name: value
            for name, value in invocation.constants
            if not name.isdigit()
        }
        for position, argument in enumerate(invocation.arguments, 1):
            if position > _MAX_FUNCTION_ARGUMENTS:
                return False
            static_argument = _static_function_argument(
                argument,
                dict(invocation.constants),
            )
            if static_argument is not None:
                invocation_constants[str(position)] = static_argument
        (
            function_commands,
            _function_constants,
            _function_exported,
            _function_tainted,
        ) = (
            _sequential_scope_commands(
                body,
                invocation_constants,
                dict(invocation.exported_loaders),
                set(invocation.tainted_constants),
                checkout_dir,
                scope_id=flow_id,
                line_offset=line_offset,
                initial_repository_cwd=invocation.repository_cwd,
                initial_repository_cwd_possible=(
                    invocation.repository_cwd_possible
                ),
                lifecycle_root=lifecycle_root,
            )
        )
        if function_commands is None:
            return False
        nested_active = set(active_calls)
        nested_active.add(invocation)
        return expand_commands(
            function_commands,
            flow_id,
            nested_active,
            lifecycle_root,
        )

    def expand_commands(
        commands: Sequence[_ScopedCommand],
        flow_id: int,
        active_calls: Set[_FunctionInvocation],
        lifecycle_root: str,
    ) -> bool:
        for scoped in commands:
            flattened = scoped._replace(scope_id=flow_id)
            collected.append(flattened)
            if len(collected) > _MAX_SCOPED_COMMANDS:
                return False
            nested = _reachable_function_invocations(
                (flattened,),
                definitions,
            )
            if nested is None:
                return False
            for invocation in nested:
                if not expand_invocation(
                    invocation,
                    flow_id,
                    active_calls,
                    lifecycle_root,
                ):
                    return False
        return True

    if not expand_commands(top_commands, 0, set(), "top-level"):
        return None

    next_flow_id = 1
    for name in sorted(definitions):
        if not _is_lifecycle_function(
            name,
            lifecycle_kind,
            split_lifecycle_roots,
        ):
            continue
        lifecycle_cwd = (
            ""
            if lifecycle_kind == "pkgbuild" and name == "verify"
            else None
        )
        root = _FunctionInvocation(
            name,
            (),
            tuple(sorted(globals_after.items())),
            tuple(sorted(exported_after.items())),
            lifecycle_cwd,
            False,
            tuple(sorted(tainted_after)),
        )
        if not expand_invocation(root, next_flow_id, set(), name):
            return None
        next_flow_id += 1
    return collected


def _declared_split_package_functions(
    top_level: str,
    definitions: Dict[str, _FunctionRegion],
) -> Optional[Set[str]]:
    """Return only split-package functions proven reachable by ``pkgname``.

    makepkg invokes ``package_$pkgname`` only for declared split package names.
    Treating every similarly named helper as a lifecycle root would let dead
    release/test helpers manufacture execution or installation correlations.
    This intentionally accepts only one bounded literal scalar/array
    declaration.  If split functions exist but their reachability is dynamic,
    correlation coverage is incomplete rather than guessed.
    """

    available = {
        name for name in definitions if name.startswith("package_")
    }
    if not available:
        return set()

    declarations: List[str] = []
    suspicious_mutation = False
    for segment, _line in _iter_shell_segments(top_level):
        stripped = segment.strip()
        if not re.search(r"(?:^|[^A-Za-z0-9_])pkgname", stripped):
            continue
        match = re.fullmatch(r"pkgname[ \t]*=[ \t]*(.*)", stripped, re.DOTALL)
        if match is None:
            suspicious_mutation = True
            continue
        declarations.append(match.group(1).strip())
    if suspicious_mutation or len(declarations) != 1:
        return None

    raw_value = declarations[0]
    if (
        not raw_value
        or any(marker in raw_value for marker in ("$", "`", "$(", ";", "|", "&"))
    ):
        return None
    if raw_value.startswith("("):
        if not raw_value.endswith(")"):
            return None
        raw_value = raw_value[1:-1].strip()
    elif "(" in raw_value or ")" in raw_value:
        return None
    try:
        names = shlex.split(raw_value, comments=False, posix=True)
    except ValueError:
        return None
    if not names or len(names) > _MAX_FUNCTION_SCOPES:
        return None
    if any(_PACKAGE_NAME.fullmatch(name) is None for name in names):
        return None
    return {
        "package_" + name
        for name in names
        if "package_" + name in available
    }


def _is_lifecycle_function(
    name: str,
    lifecycle_kind: str,
    split_lifecycle_roots: Set[str],
) -> bool:
    if lifecycle_kind == "install_hook":
        return name in _INSTALL_HOOK_LIFECYCLE_FUNCTIONS
    return (
        name in _PKGBUILD_LIFECYCLE_FUNCTIONS
        or name in split_lifecycle_roots
    )


def _reachable_function_invocations(
    commands: Sequence[_ScopedCommand],
    definitions: Dict[str, _FunctionRegion],
) -> Optional[List[_FunctionInvocation]]:
    invocations: List[_FunctionInvocation] = []
    for scoped in commands:
        command = scoped.command
        executable = _resolve(str(command.executable), scoped.constants)
        definition = definitions.get(executable)
        definition_is_available = (
            definition is not None
            and (
                scoped.lifecycle_root != "top-level"
                or definition.line_number < command.line_number
            )
        )
        if (
            definition_is_available
            and scoped.function_dispatch_allowed
            and "/" not in executable
        ):
            arguments = tuple(str(value) for value in command.arguments)
            if len(arguments) > _MAX_FUNCTION_ARGUMENTS:
                return None
            resolved_arguments = tuple(
                _resolve_function_argument(value, scoped.constants)
                for value in arguments
            )
            invocations.append(
                _FunctionInvocation(
                    executable,
                    resolved_arguments,
                    tuple(
                        sorted(
                            (name, value)
                            for name, value in scoped.constants.items()
                            if not name.isdigit()
                        )
                    ),
                    scoped.exported_loaders,
                    scoped.repository_cwd,
                    scoped.repository_cwd_possible,
                    scoped.tainted_constants,
                )
            )
            continue
        if _dynamic_function_call_requires_failure(scoped, executable):
            return None
    return invocations


def _function_dispatch_allowed(segment: str) -> bool:
    """Return whether the shell spelling may dispatch a shell function.

    The shared command parser deliberately unwraps execution prefixes.  Shell
    functions are nevertheless bypassed by ``command``, ``env``, ``exec`` and
    ``builtin``; retaining this one bit prevents the reachability layer from
    inlining a body which Bash would not call.  ``time`` still permits normal
    function dispatch.
    """

    try:
        tokens = shlex.split(segment, comments=False, posix=True)
    except ValueError:
        return False
    index = 0
    while index < len(tokens) and tokens[index] in {
        "!", "(", "{", "do", "elif", "else", "if", "then", "until", "while",
    }:
        index += 1
    while index < len(tokens) and _SIMPLE_ASSIGNMENT.fullmatch(tokens[index]):
        index += 1
    while index < len(tokens):
        name = _basename(tokens[index]).lower()
        if name in _FUNCTION_BYPASS_WRAPPERS:
            return False
        if name != "time":
            return True
        index += 1
        while index < len(tokens) and tokens[index].startswith("-"):
            index += 1
    return True


def _resolve_function_argument(value: str, constants: Dict[str, str]) -> str:
    resolved = value
    for _index in range(_MAX_RESOLUTION_PASSES):
        updated = _resolve(resolved, constants)
        if updated == resolved:
            break
        resolved = updated
    return resolved


def _static_function_argument(
    value: str,
    constants: Dict[str, str],
) -> Optional[str]:
    resolved = _resolve_function_argument(value, constants)
    if not resolved or len(resolved) > 4096 or "`" in resolved:
        return None
    for match in _VARIABLE_REFERENCE.finditer(resolved):
        name = match.group("braced") or match.group("plain") or ""
        if name not in _SPECIAL_PATH_VARIABLES:
            return None
    if _POSITIONAL_REFERENCE.search(resolved):
        return None
    masked = _VARIABLE_REFERENCE.sub("", resolved)
    if "$" in masked or any(marker in masked for marker in ("*", "?", "[", "{")):
        return None
    return resolved


def _dynamic_function_call_requires_failure(
    scoped: _ScopedCommand,
    executable: str,
) -> bool:
    """Fail only dynamic calls tied to repository-relevant operands.

    An ordinary unresolved tool variable such as ``$CC`` is not itself
    evidence that a shell helper ran.  A dynamic command position inherited
    from an unresolved helper positional can hide such a call and therefore
    leaves the bounded reachability proof incomplete.  Mutated command
    variables are handled separately by the scope's explicit taint state.
    """

    if not any(marker in executable for marker in ("$", "`")):
        return False
    if _POSITIONAL_REFERENCE.search(executable):
        return True
    if executable.startswith(
        _KNOWN_REPOSITORY_PREFIXES
        + _KNOWN_SRCDIR_PARENT_PREFIXES
        + _KNOWN_SRCDIR_PREFIXES
        + ("$pkgdir/", "${pkgdir}/")
    ):
        return False
    return False


def _sequential_scope_commands(
    content: str,
    initial_constants: Dict[str, str],
    initial_exported_loaders: Dict[str, Optional[str]],
    initial_tainted_constants: Set[str],
    checkout_dir: Path,
    *,
    scope_id: int,
    line_offset: int,
    initial_repository_cwd: Optional[str],
    initial_repository_cwd_possible: bool,
    lifecycle_root: str,
) -> Tuple[
    Optional[List[_ScopedCommand]],
    Dict[str, str],
    Dict[str, Optional[str]],
    Set[str],
]:
    if (
        _commands_and_constants(content) is None
        or _has_relevant_extglob_operand(content)
    ):
        return None, {}, {}, set()
    constants = dict(initial_constants)
    exported_loaders = dict(initial_exported_loaders)
    tainted_constants = set(initial_tainted_constants)
    collected: List[_ScopedCommand] = []
    repository_cwd = initial_repository_cwd
    track_repository_cwd = _linear_scope_allows_cwd_tracking(content)
    possible_repository_cwd = initial_repository_cwd_possible
    for segment, segment_line in _iter_shell_segments(
        content,
        preserve_simple_stdout_redirections=True,
    ):
        assignment, updates, exports, unexports = _constant_assignment_statement(
            segment,
            constants,
        )
        if assignment:
            nameref_names = _nameref_declaration_names(segment)
            for name, value in updates.items():
                if value is None:
                    constants.pop(name, None)
                    tainted_constants.add(name)
                else:
                    constants[name] = value
                    tainted_constants.discard(name)
                if name in exported_loaders:
                    exported_loaders[name] = value
            if nameref_names:
                # A nameref changes the meaning of later assignments and
                # reads.  The bounded scalar table does not emulate Bash
                # indirection, so any later variable-derived path is tainted.
                tainted_constants.add("*")
                for name in nameref_names:
                    constants.pop(name, None)
                    tainted_constants.add(name)
            for name in exports:
                if name in _CODE_LOADING_ASSIGNMENTS:
                    exported_loaders[name] = constants.get(name)
            for name in unexports:
                if name in _CODE_LOADING_ASSIGNMENTS:
                    exported_loaders.pop(name, None)
            if len(constants) > _MAX_SCOPED_CONSTANTS:
                return None, {}, {}, set()
            continue

        parsed = _commands_and_constants(segment)
        if parsed is None:
            return None, {}, {}, set()
        commands, _unused_constants = parsed
        dispatch_allowed = _function_dispatch_allowed(segment)
        for command in commands:
            adjusted = command._replace(
                line_number=line_offset + segment_line + command.line_number - 1
            )
            collected.append(
                _ScopedCommand(
                    adjusted,
                    dict(constants),
                    scope_id,
                    repository_cwd if track_repository_cwd else None,
                    possible_repository_cwd if track_repository_cwd else False,
                    tuple(sorted(exported_loaders.items())),
                    lifecycle_root,
                    dispatch_allowed,
                    tuple(sorted(tainted_constants)),
                )
            )
            if len(collected) > _MAX_SCOPED_COMMANDS:
                return None, {}, {}, set()
            if _tainted_command_requires_failure(collected[-1]):
                return None, {}, {}, set()
            if track_repository_cwd:
                repository_cwd = _updated_repository_cwd(
                    adjusted,
                    constants,
                    checkout_dir,
                    repository_cwd,
                )
                if _command_changes_cwd(adjusted, constants):
                    possible_repository_cwd = (
                        _command_uses_layout_dependent_srcdir(
                            adjusted,
                            constants,
                        )
                        or (
                            repository_cwd is None
                            and _command_may_enter_repository(
                            adjusted,
                            constants,
                            checkout_dir,
                            )
                        )
                    )
            if not _invalidate_command_mutations(
                adjusted,
                constants,
                exported_loaders,
                tainted_constants,
            ):
                return None, {}, {}, set()
    if not track_repository_cwd:
        possible = (
            initial_repository_cwd_possible
            or initial_repository_cwd is not None
            or any(
            _command_may_enter_repository(
                item.command,
                item.constants,
                checkout_dir,
            )
            for item in collected
            )
        )
        if possible:
            collected = [
                item._replace(repository_cwd_possible=True)
                for item in collected
            ]
    return collected, constants, exported_loaders, tainted_constants


def _linear_scope_allows_cwd_tracking(content: str) -> bool:
    """Accept only a straight-line shell scope for cwd state propagation.

    The ordinary command analyzer intentionally over-approximates shell control
    flow.  A cwd correlation is stronger: carrying a directory across a branch,
    pipeline, subshell, or loop could manufacture an artifact identity that is
    not true on every path.  Quoted text is masked before this conservative
    syntax check so documentation strings do not disable an otherwise simple
    scope.
    """

    masked = mask_shell_quoted_text(content)
    if any(marker in masked for marker in ("&&", "||", "|", "&", "(", ")", "`")):
        return False
    return re.search(
        r"(?:^|[;\n\r \t])(?:if|then|elif|else|fi|for|while|until|case|esac|"
        r"select|do|done|return|exit|break|continue)(?=$|[;\n\r \t])",
        masked,
    ) is None


def _updated_repository_cwd(
    command: object,
    constants: Dict[str, str],
    checkout_dir: Path,
    current: Optional[str],
) -> Optional[str]:
    """Return an exact cwd or a capture-only ``srcdir`` projection."""

    executable, arguments = _cwd_command_parts(command, constants)
    if executable in {".", "eval", "popd", "pushd", "source"}:
        return None
    if executable != "cd":
        return current

    positionals: List[str] = []
    after_terminator = False
    for raw_value in arguments:
        value = _resolve(raw_value, constants)
        if not after_terminator and value == "--":
            after_terminator = True
            continue
        if not after_terminator and value in {"-L", "-P", "-e"}:
            continue
        if not after_terminator and value.startswith("-"):
            return None
        positionals.append(value)
    if len(positionals) != 1 or positionals[0] == "-":
        return None

    target = positionals[0]
    for _index in range(_MAX_RESOLUTION_PASSES):
        resolved = _resolve(target, constants)
        if resolved == target:
            break
        target = resolved
    root_tokens = {
        "$startdir",
        "${startdir}",
        "$pkgbuilddir",
        "${pkgbuilddir}",
        "$srcdir/..",
        "${srcdir}/..",
    }
    if target.rstrip("/") in {"$srcdir", "${srcdir}"}:
        return "src"
    if target.rstrip("/") in root_tokens:
        return ""
    for prefix in _KNOWN_REPOSITORY_PREFIXES + _KNOWN_SRCDIR_PARENT_PREFIXES:
        if target.startswith(prefix):
            return _safe_repository_cwd(target[len(prefix) :])
    for prefix in _KNOWN_SRCDIR_PREFIXES:
        if target.startswith(prefix):
            suffix = _safe_repository_cwd(target[len(prefix) :])
            return "src" if suffix == "" else (
                posixpath.join("src", suffix) if suffix is not None else None
            )
    if "$" in target or "`" in target or "\\" in target:
        return None

    checkout = os.path.abspath(str(checkout_dir))
    if os.path.isabs(target):
        absolute = os.path.abspath(target)
        try:
            relative = os.path.relpath(absolute, checkout)
        except ValueError:
            return None
        if relative == ".":
            return ""
        return _safe_repository_cwd(relative)

    if current is None:
        return None
    joined = posixpath.normpath(posixpath.join(current or ".", target))
    if joined == ".":
        return ""
    return _safe_repository_cwd(joined)


def _command_uses_layout_dependent_srcdir(
    command: object,
    constants: Dict[str, str],
) -> bool:
    executable, arguments = _cwd_command_parts(command, constants)
    if executable != "cd":
        return False
    positionals = [
        _resolve(value, constants)
        for value in arguments
        if value != "--" and not value.startswith("-")
    ]
    if len(positionals) != 1:
        return False
    target = positionals[0].rstrip("/")
    return target in {
        "$srcdir",
        "${srcdir}",
        "$srcdir/..",
        "${srcdir}/..",
    } or positionals[0].startswith(
        _KNOWN_SRCDIR_PREFIXES + _KNOWN_SRCDIR_PARENT_PREFIXES
    )


def _cwd_command_parts(
    command: object,
    constants: Dict[str, str],
) -> Tuple[str, Tuple[str, ...]]:
    executable = _basename(
        _resolve(str(getattr(command, "executable", "")), constants)
    ).lower()
    arguments = tuple(str(value) for value in getattr(command, "arguments", ()))
    if executable in {"builtin", "command"} and arguments:
        nested = _basename(_resolve(arguments[0], constants)).lower()
        if nested in {"cd", "popd", "pushd"}:
            return nested, arguments[1:]
    return executable, arguments


def _command_changes_cwd(command: object, constants: Dict[str, str]) -> bool:
    executable, _arguments = _cwd_command_parts(command, constants)
    return executable in {"cd", "popd", "pushd"}


def _command_may_enter_repository(
    command: object,
    constants: Dict[str, str],
    checkout_dir: Path,
) -> bool:
    """Conservatively identify a cwd change that may enter the checkout.

    This is coverage state, not an exact path correlation.  It is used only to
    withhold a clear result when nonlinear shell flow or directory-stack
    operations make a later relative control path capable of reaching a
    normally pruned checkout subtree.
    """

    executable, arguments = _cwd_command_parts(command, constants)
    if executable == "popd":
        return True
    if executable not in {"cd", "pushd"}:
        return False

    positionals: List[str] = []
    after_terminator = False
    for raw_value in arguments:
        value = _resolve(raw_value, constants)
        if not after_terminator and value == "--":
            after_terminator = True
            continue
        if not after_terminator and executable == "cd" and value in {"-L", "-P", "-e"}:
            continue
        if not after_terminator and executable == "pushd" and value == "-n":
            return False
        if not after_terminator and value.startswith(("+", "-")):
            # Directory-stack indexes and unknown options are invocation-
            # dependent.  They may restore a checkout directory.
            return True
        positionals.append(value)
    if len(positionals) != 1:
        return True

    target = positionals[0]
    for _index in range(_MAX_RESOLUTION_PASSES):
        resolved = _resolve(target, constants)
        if resolved == target:
            break
        target = resolved
    root_tokens = {
        "$startdir",
        "${startdir}",
        "$pkgbuilddir",
        "${pkgbuilddir}",
        "$srcdir/..",
        "${srcdir}/..",
    }
    stripped = target.rstrip("/")
    if stripped in root_tokens or target.startswith(
        _KNOWN_REPOSITORY_PREFIXES + _KNOWN_SRCDIR_PARENT_PREFIXES
    ):
        return True
    if stripped in {"$srcdir", "${srcdir}"} or target.startswith(
        _KNOWN_SRCDIR_PREFIXES
    ):
        return True
    if "$" in target or "`" in target or "\\" in target:
        return True
    if os.path.isabs(target):
        checkout = os.path.abspath(str(checkout_dir))
        absolute = os.path.abspath(target)
        try:
            relative = os.path.relpath(absolute, checkout)
        except ValueError:
            return False
        return relative == "." or not relative.startswith("../")
    return False


def _safe_repository_cwd(value: str) -> Optional[str]:
    if not value or value == ".":
        return ""
    if "\\" in value or "$" in value or "`" in value or value.startswith("/"):
        return None
    normalized = posixpath.normpath(value)
    if normalized in {"..", ""} or normalized.startswith("../"):
        return None
    return normalized[2:] if normalized.startswith("./") else normalized


def _relative_path_requires_cwd(
    value: str,
    constants: Dict[str, str],
) -> bool:
    """Return whether a control operand needs an uncertain working directory."""

    resolved = value
    for _index in range(_MAX_RESOLUTION_PASSES):
        updated = _resolve(resolved, constants)
        if updated == resolved:
            break
        resolved = updated
    if (
        not resolved
        or resolved.startswith("-")
        or "://" in resolved
        or os.path.isabs(resolved)
        or resolved.startswith(
            _KNOWN_REPOSITORY_PREFIXES + _KNOWN_SRCDIR_PARENT_PREFIXES
        )
        or resolved.startswith(
            (
                "$pkgdir",
                "${pkgdir}",
                "$srcdir",
                "${srcdir}",
            )
        )
    ):
        return False
    if "$" in resolved or "`" in resolved or "\\" in resolved:
        return True
    normalized = posixpath.normpath(resolved)
    return normalized not in {"", ".", ".."} and not normalized.startswith("../")


def _has_relevant_extglob_operand(content: str) -> bool:
    """Detect active extglob operands the bounded shell view cannot expand.

    Parentheses are command boundaries in the shared conservative parser, so
    treating a split extglob as ordinary commands could silently lose a path
    below a pruned checkout directory.  We fail only command-position or
    execution/transfer operands; quoted documentation and message arguments
    remain inert for repository capture.
    """

    masked = mask_shell_quoted_text(_active_shell_text(content))
    relevant = (
        _TRANSFER_COMMANDS
        | _EXECUTION_WRAPPERS
        | {
            ".", "chmod", "dotnet", "eval", "java", "mono", "source",
            "wasmer", "wasmtime", "wine", "wine64",
            "ash", "bash", "bun", "dash", "jsc", "lua", "luajit", "node",
            "nodejs", "perl", "php", "python", "python2", "python3", "qjs",
            "quickjs", "rscript", "ruby", "sh", "tclsh", "wish", "zsh",
        }
    )
    for match in re.finditer(r"[@+?!*]\(", masked):
        boundary = max(
            masked.rfind(marker, 0, match.start())
            for marker in (";", "\n", "&&", "||", "|", "&", "{", "}")
        )
        prefix = masked[boundary + 1 : match.start()]
        parsed = _commands_and_constants(prefix)
        if parsed is None:
            return True
        commands, _constants = parsed
        if not commands:
            return True
        executable = _basename(commands[-1].executable).lower()
        if executable in relevant or executable.startswith(("ld-linux", "qemu-")):
            return True
    return False


def _constant_assignment_statement(
    segment: str,
    constants: Dict[str, str],
) -> Tuple[
    bool,
    Dict[str, Optional[str]],
    Set[str],
    Set[str],
]:
    """Recognize bounded assignment-only statements and resolve in order."""

    try:
        tokens = shlex.split(segment, comments=False, posix=True)
    except ValueError:
        return False, {}, set(), set()
    if not tokens:
        return False, {}, set(), set()
    declaration_name = _basename(tokens[0]).lower()
    declaration = declaration_name in _DECLARATION_COMMANDS
    index = 1 if declaration else 0
    declaration_options: List[str] = []
    if declaration:
        while index < len(tokens) and tokens[index].startswith("-"):
            declaration_options.append(tokens[index])
            index += 1
    if index >= len(tokens):
        return declaration, {}, set(), set()

    updates: Dict[str, Optional[str]] = {}
    exports: Set[str] = set()
    unexports: Set[str] = set()
    recognized = declaration
    working = dict(constants)
    export_declaration = declaration_name == "export" or (
        declaration_name in {"declare", "local", "readonly", "typeset"}
        and any("x" in value.lstrip("-") for value in declaration_options)
    )
    unexport_declaration = (
        declaration_name == "export"
        and any("n" in value.lstrip("-") for value in declaration_options)
    )
    for token in tokens[index:]:
        match = _SIMPLE_ASSIGNMENT.fullmatch(token)
        if match is None:
            if declaration and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token):
                if unexport_declaration:
                    unexports.add(token)
                elif export_declaration:
                    exports.add(token)
                else:
                    updates[token] = None
                    working.pop(token, None)
                continue
            return False, {}, set(), set()
        recognized = True
        name = match.group("name")
        if match.group("operator") != "=":
            updates[name] = None
            working.pop(name, None)
            if export_declaration:
                exports.add(name)
            continue
        value = _static_assignment_value(
            match.group("value"),
            segment,
            working,
        )
        updates[name] = value
        if value is None:
            working.pop(name, None)
        else:
            working[name] = value
        if unexport_declaration:
            unexports.add(name)
        elif export_declaration:
            exports.add(name)
    return recognized, updates, exports, unexports


def _static_assignment_value(
    value: str,
    raw_segment: str,
    constants: Dict[str, str],
) -> Optional[str]:
    if len(value) > 4096 or any(marker in raw_segment for marker in ("$(", "`")):
        return None
    # shlex removes quote syntax.  A single-quoted or escaped dollar is a
    # literal, so declining to resolve it avoids manufacturing a path root.
    if ("'" in raw_segment and "$" in raw_segment) or "\\$" in raw_segment:
        return None
    resolved = value
    for _index in range(_MAX_RESOLUTION_PASSES):
        updated = _resolve(resolved, constants)
        if updated == resolved:
            break
        resolved = updated
    for match in _VARIABLE_REFERENCE.finditer(resolved):
        name = match.group("braced") or match.group("plain") or ""
        if name not in _SPECIAL_PATH_VARIABLES:
            return None
    if "$" in _VARIABLE_REFERENCE.sub("", resolved) or len(resolved) > 4096:
        return None
    return resolved


def _nameref_declaration_names(segment: str) -> Set[str]:
    """Return names declared through a statically recognizable nameref."""

    try:
        tokens = shlex.split(segment, comments=False, posix=True)
    except ValueError:
        return set()
    if not tokens or _basename(tokens[0]).lower() not in {
        "declare", "local", "readonly", "typeset",
    }:
        return set()
    index = 1
    nameref = False
    while index < len(tokens) and tokens[index].startswith("-"):
        option = tokens[index]
        if "n" in option.lstrip("-+"):
            nameref = not option.startswith("+")
        index += 1
    if not nameref:
        return set()
    names: Set[str] = set()
    for value in tokens[index:]:
        name = value.partition("=")[0]
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            names.add(name)
    return names


def _referenced_variable_names(value: str) -> Set[str]:
    return {
        match.group("braced") or match.group("plain") or ""
        for match in _TAINTED_VARIABLE_REFERENCE.finditer(value)
    }


def _references_tainted_variable(value: str, tainted: Set[str]) -> bool:
    names = _referenced_variable_names(value)
    return bool(names and ("*" in tainted or names.intersection(tainted)))


def _tainted_command_requires_failure(scoped: _ScopedCommand) -> bool:
    """Withhold exact correlation when a mutated variable controls a path.

    A normal unresolved environment command such as ``$CC`` remains outside
    this rule.  Taint is introduced only by observed dynamic mutation (read,
    printf -v, nameref, sourced/evaluated state), and is consumed only in a
    command position or an analyzer-relevant path position.
    """

    tainted = set(scoped.tainted_constants)
    if not tainted:
        return False
    raw_executable = str(getattr(scoped.command, "executable", ""))
    if _references_tainted_variable(raw_executable, tainted):
        return True
    executable = _basename(_resolve(raw_executable, scoped.constants)).lower()
    path_sensitive = (
        executable in (
            _TRANSFER_COMMANDS
            | _EXECUTION_WRAPPERS
            | _COMMAND_CONSUMERS
            | {
                ".", "ash", "bash", "bun", "cd", "chmod", "dash", "dd",
                "dotnet", "eval", "java", "jsc", "lua", "luajit", "mono",
                "node", "nodejs", "perl", "php", "popd", "pushd", "python",
                "python2", "python3", "qjs", "quickjs", "rm", "rmdir",
                "rscript", "ruby", "sh", "source", "tclsh", "unlink",
                "wasmer", "wasmtime", "wine", "wine64", "wish", "zsh",
            }
        )
        or executable.startswith(("ld-linux", "qemu-"))
    )
    if path_sensitive and any(
        _references_tainted_variable(str(value), tainted)
        for value in getattr(scoped.command, "arguments", ())
    ):
        return True
    return any(
        assignment.partition("=")[0] in _CODE_LOADING_ASSIGNMENTS
        and _references_tainted_variable(assignment.partition("=")[2], tainted)
        for assignment in getattr(scoped.command, "assignments", ())
        if "=" in assignment
    )


def _mutation_target_names(
    executable: str,
    arguments: Sequence[str],
) -> Tuple[Set[str], bool]:
    """Return definitely mutated shell names and whether targeting is known."""

    names: Set[str] = set()
    if executable == "printf":
        index = 0
        while index < len(arguments):
            value = arguments[index]
            if value == "-v":
                if index + 1 >= len(arguments):
                    return names, False
                target = arguments[index + 1]
                if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", target):
                    return names, False
                names.add(target)
                index += 2
                continue
            if value.startswith("-v") and len(value) > 2:
                target = value[2:]
                if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", target):
                    return names, False
                names.add(target)
            index += 1
        return names, True

    if executable == "read":
        options_with_value = {"-a", "-d", "-i", "-n", "-N", "-p", "-t", "-u"}
        positionals: List[str] = []
        index = 0
        while index < len(arguments):
            value = arguments[index]
            if value == "--":
                positionals.extend(arguments[index + 1 :])
                break
            if value in options_with_value:
                if index + 1 >= len(arguments):
                    return names, False
                if value == "-a":
                    target = arguments[index + 1]
                    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", target):
                        return names, False
                    names.add(target)
                index += 2
                continue
            if value.startswith("-"):
                index += 1
                continue
            positionals.append(value)
            index += 1
        if not positionals and not names:
            names.add("REPLY")
        for target in positionals:
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", target):
                return names, False
            names.add(target)
        return names, True

    if executable in {"mapfile", "readarray"}:
        options_with_value = {"-c", "-C", "-n", "-O", "-s", "-u"}
        positionals: List[str] = []
        index = 0
        while index < len(arguments):
            value = arguments[index]
            if value == "--":
                positionals.extend(arguments[index + 1 :])
                break
            if value in options_with_value:
                if index + 1 >= len(arguments):
                    return names, False
                index += 2
                continue
            if value.startswith("-"):
                index += 1
                continue
            positionals.append(value)
            index += 1
        if len(positionals) > 1:
            return names, False
        target = positionals[0] if positionals else "MAPFILE"
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", target):
            return names, False
        names.add(target)
        return names, True
    return names, True


def _invalidate_command_mutations(
    command: object,
    constants: Dict[str, str],
    exported_loaders: Dict[str, Optional[str]],
    tainted_constants: Set[str],
) -> bool:
    executable = _basename(str(getattr(command, "executable", ""))).lower()
    arguments = tuple(str(value) for value in getattr(command, "arguments", ()))
    if executable == "builtin" and arguments:
        executable = _basename(arguments[0]).lower()
        arguments = arguments[1:]
    if executable in {".", "eval", "source"}:
        constants.clear()
        tainted_constants.add("*")
        for name in tuple(exported_loaders):
            exported_loaders[name] = None
        return True
    if executable == "unset":
        for value in arguments:
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value):
                constants.pop(value, None)
                tainted_constants.add(value)
                exported_loaders.pop(value, None)
        return True
    if executable in {"printf", "read", "mapfile", "readarray"}:
        names, complete = _mutation_target_names(executable, arguments)
        if not complete:
            return False
        for name in names:
            constants.pop(name, None)
            tainted_constants.add(name)
            if name in exported_loaders:
                exported_loaders[name] = None
        return True
    if executable in {"declare", "local", "readonly", "typeset"} and any(
        "n" in value.lstrip("-+")
        for value in arguments
        if value.startswith(("-", "+"))
    ):
        tainted_constants.add("*")
    return True


def collect_required_repository_paths(
    contents: Iterable[str],
    checkout_dir: Path,
) -> RequiredRepositoryPaths:
    """Collect bounded explicit checkout paths that cross a pruned directory.

    This is a discovery aid only: the snapshot still validates every component
    without following links and the analyzer still requires an exact behavior
    correlation.  Missing paths are harmless.  Returning one item beyond the
    snapshot limit deliberately makes capture fail closed rather than silently
    truncating attacker-controlled command operands.
    """

    analyzer = RepositoryProvenanceAnalyzer()
    paths: Set[str] = set()
    complete = True
    for content_index, content in enumerate(contents):
        scoped_commands = _scoped_commands(
            content,
            checkout_dir,
            top_level_repository_cwd=content_index == 0,
            lifecycle_kind=(
                "pkgbuild" if content_index == 0 else "install_hook"
            ),
        )
        if scoped_commands is None:
            complete = False
            continue
        pending = [
            (
                item.command,
                item.constants,
                item.repository_cwd,
                item.repository_cwd_possible,
                item.exported_loaders,
                0,
            )
            for item in scoped_commands
        ]
        pending_index = 0
        nested_expansion_work = 0
        while pending_index < len(pending):
            (
                command,
                command_constants,
                repository_cwd,
                repository_cwd_possible,
                exported_loaders,
                depth,
            ) = pending[pending_index]
            pending_index += 1
            effective_executable, effective_arguments, wrapper_complete = (
                analyzer._effective_command_status(command, command_constants)
            )
            relevant_arguments = _basename(effective_executable).lower() in (
                _TRANSFER_COMMANDS
                | _EXECUTION_WRAPPERS
                | _CODE_LOADING_ASSIGNMENTS
                | {
                    ".", "chmod", "dotnet", "eval", "java", "mono", "source",
                    "wasmer", "wasmtime", "wine", "wine64",
                }
                | {
                    "ash", "bash", "bun", "dash", "jsc", "lua", "luajit",
                    "node", "nodejs", "perl", "php", "python", "python2",
                    "python3", "qjs", "quickjs", "rscript", "ruby", "sh",
                    "tclsh", "wish", "zsh",
                }
            ) or _basename(effective_executable).lower().startswith(
                ("ld-linux", "qemu-")
            )
            loading_values: List[str] = []
            for assignment in getattr(command, "assignments", ()):
                name, separator, raw_value = assignment.partition("=")
                if separator and name in _CODE_LOADING_ASSIGNMENTS:
                    loading_values.extend(raw_value.split(":"))
            external_loader_command = analyzer._external_command_can_load(
                effective_executable,
            )
            for _name, raw_value in exported_loaders:
                if raw_value is None:
                    if external_loader_command:
                        complete = False
                    continue
                if external_loader_command:
                    loading_values.extend(raw_value.split(":"))
            repository_path_operands: List[str] = list(loading_values)
            effective_basename = _basename(effective_executable).lower()
            if effective_basename in _TRANSFER_COMMANDS:
                transfer = analyzer._parse_command_transfer(
                    effective_basename,
                    effective_arguments,
                    command_constants,
                )
                if transfer is not None:
                    repository_path_operands.extend(transfer.sources)
            else:
                execution_candidates, _execution_complete = (
                    analyzer._execution_candidates(
                        command,
                        command_constants,
                        exported_loaders,
                    )
                )
                repository_path_operands.extend(
                    candidate.path
                    for candidate in execution_candidates
                    if "/" in candidate.path
                    or any(marker in candidate.path for marker in ("$", "`"))
                    or candidate.path.startswith(
                        _KNOWN_REPOSITORY_PREFIXES
                        + _KNOWN_SRCDIR_PARENT_PREFIXES
                        + _KNOWN_SRCDIR_PREFIXES
                    )
                )
                interpreter_path = analyzer._raw_interpreter_candidate(
                    effective_executable,
                    effective_arguments,
                    command_constants,
                )
                if interpreter_path:
                    repository_path_operands.append(interpreter_path)
            if effective_basename == "chmod":
                resolved_arguments = [
                    analyzer._resolve_constants(value, command_constants)
                    for value in effective_arguments
                ]
                mode_status = analyzer._chmod_mode_status(resolved_arguments)
                if mode_status is not None:
                    mode_index, _recursive = mode_status
                    repository_path_operands.extend(
                        value
                        for value in resolved_arguments[mode_index + 1 :]
                        if value != "--" and not value.startswith("-")
                    )
            if repository_cwd_possible and any(
                _relative_path_requires_cwd(value, command_constants)
                for value in repository_path_operands
            ):
                complete = False
            resolved_path_operands = {
                analyzer._resolve_constants(value, command_constants)
                for value in repository_path_operands
            }
            tokens = (
                (command.executable,)
                + tuple(command.arguments)
                + tuple(loading_values)
            )
            for token_index, token in enumerate(tokens):
                resolved = analyzer._resolve_constants(token, command_constants)
                token_is_repository_operand = (
                    (
                        token_index == 0
                        and re.match(
                            r"[A-Za-z_][A-Za-z0-9_]*(?:\[[^]]+\])?\+?=",
                            resolved,
                        )
                        is None
                    )
                    or resolved in resolved_path_operands
                    or token_index >= 1 + len(command.arguments)
                )
                token_ambiguous = analyzer._repository_token_ambiguous(
                    resolved,
                    command_constants,
                )
                ambiguous_root = token_ambiguous and resolved.startswith(
                    _KNOWN_REPOSITORY_PREFIXES + _KNOWN_SRCDIR_PARENT_PREFIXES
                )
                ambiguous_relative_path = (
                    token_ambiguous
                    and "://" not in resolved
                    and not os.path.isabs(resolved)
                    and (
                        "/" in resolved
                        or repository_cwd is not None
                        or repository_cwd_possible
                    )
                    and (
                        any(marker in resolved for marker in ("*", "?", "[", "{"))
                        or (
                            any(marker in resolved for marker in ("$", "`"))
                            and (
                                repository_cwd is not None
                                or repository_cwd_possible
                            )
                        )
                    )
                )
                if (
                    ambiguous_root or ambiguous_relative_path
                ) and token_is_repository_operand:
                    complete = False
                if (
                    not resolved
                    or "://" in resolved
                    or not (
                        "/" in resolved
                        or resolved.startswith(
                            ("$startdir", "${startdir}", "$pkgbuilddir", "${pkgbuilddir}")
                        )
                        or (
                            repository_cwd is not None
                            and token_index > 0
                            and not resolved.startswith("-")
                            and token_is_repository_operand
                        )
                    )
                ):
                    continue
                relative = analyzer._repository_relative_path(
                    resolved,
                    checkout_dir,
                    command_constants,
                    allow_bare=True,
                    repository_cwd=repository_cwd,
                    capture_layout_dependent=True,
                )
                if relative:
                    paths.add(relative)
                if len(paths) > 256:
                    return RequiredRepositoryPaths(tuple(sorted(paths)), complete)
            if not wrapper_complete and relevant_arguments:
                complete = False
            nested_commands, nested_complete, nested_work = analyzer._literal_shell_commands(
                effective_executable,
                effective_arguments,
                command_constants,
                command.line_number,
            )
            nested_expansion_work += nested_work
            if nested_expansion_work > _MAX_CORRELATION_OPERATIONS:
                complete = False
                break
            complete = complete and nested_complete
            if depth < 2:
                pending.extend(
                    (
                        nested_command,
                        nested_constants,
                        repository_cwd,
                        repository_cwd_possible,
                        exported_loaders,
                        depth + 1,
                    )
                    for nested_command, nested_constants in nested_commands
                )
            elif nested_commands:
                complete = False
    return RequiredRepositoryPaths(tuple(sorted(paths)), complete)


class RepositoryProvenanceAnalyzer:
    """Analyze already captured package-checkout artifacts as inert evidence."""

    def __init__(self, source_parser: Optional[SourceParser] = None):
        self.source_parser = source_parser or SourceParser()

    def analyze_scan_input(
        self,
        pkgbuild_path: str,
        pkgbuild_content: str,
        install_hook: InstallHookResolution,
        repository_snapshot: RepositorySnapshot,
        pkg_name: str = "unknown",
        pkg_ver: str = "unknown",
    ) -> AnalysisResult:
        checkout_dir = Path(pkgbuild_path).parent
        if repository_snapshot.status != REPOSITORY_COMPLETE:
            finding = self._incomplete_finding(
                pkgbuild_path,
                pkg_name,
                pkg_ver,
                repository_snapshot.error_code,
            )
            return AnalysisResult(
                False,
                "Package-checkout provenance inspection did not complete.",
                [finding],
            )

        references, parser_findings = self.source_parser.parse(
            pkgbuild_path,
            pkgbuild_content,
        )
        if any(
            finding.rule_id == "SOURCE-PARSER-AMBIGUOUS"
            for finding in parser_findings
        ):
            # Do not turn source-parser uncertainty into an undeclared-file
            # accusation.  Opaque bytes are nevertheless mandatory evidence,
            # so an ambiguous declaration leaves provenance inspection
            # incomplete and must remain a hard blocker.
            opaque_artifacts = [
                artifact
                for artifact in repository_snapshot.artifacts
            ]
            if opaque_artifacts:
                finding = self._incomplete_finding(
                    pkgbuild_path,
                    pkg_name,
                    pkg_ver,
                    "source_mapping_ambiguous",
                )
                return AnalysisResult(
                    False,
                    "Package-checkout provenance inspection did not complete.",
                    [finding],
                )
            return AnalysisResult(
                True,
                "Repository provenance assertion withheld because source declarations were ambiguous.",
                [],
            )

        declared_paths = self._declared_checkout_paths(references)
        artifacts = [
            artifact
            for artifact in repository_snapshot.artifacts
            if self._artifact_relative_path(artifact) not in declared_paths
        ]
        if not artifacts:
            return AnalysisResult(
                True,
                "No undeclared opaque checkout artifacts were found.",
                [],
            )

        pkgbuild_commands = _scoped_commands(
            pkgbuild_content,
            checkout_dir,
            top_level_repository_cwd=True,
            lifecycle_kind="pkgbuild",
        )
        if pkgbuild_commands is None:
            finding = self._incomplete_finding(
                pkgbuild_path,
                pkg_name,
                pkg_ver,
                "command_parser_limit",
            )
            return AnalysisResult(
                False,
                "Package-checkout provenance correlation did not complete.",
                [finding],
            )
        hook_commands: List[_ScopedCommand] = []
        hook_path = str(install_hook.path or pkgbuild_path)
        if install_hook.status == INSTALL_HOOK_RESOLVED:
            scoped_hook = _scoped_commands(
                install_hook.content,
                checkout_dir,
                top_level_repository_cwd=False,
                lifecycle_kind="install_hook",
            )
            if scoped_hook is None:
                finding = self._incomplete_finding(
                    pkgbuild_path,
                    pkg_name,
                    pkg_ver,
                    "command_parser_limit",
                )
                return AnalysisResult(
                    False,
                    "Package-checkout provenance correlation did not complete.",
                    [finding],
                )
            hook_commands = scoped_hook

        transfers = self._collect_transfers(pkgbuild_commands)
        transfer_source_count = sum(
            len(transfer.sources)
            for _command, _constants, _repository_cwd, transfer in transfers
        )
        all_commands = tuple(pkgbuild_commands) + tuple(hook_commands)
        nested_expansion_work = self._nested_shell_expansion_work(all_commands)
        if nested_expansion_work > _MAX_CORRELATION_OPERATIONS:
            finding = self._incomplete_finding(
                pkgbuild_path,
                pkg_name,
                pkg_ver,
                "analysis_limit",
            )
            return AnalysisResult(
                False,
                "Package-checkout provenance correlation exceeded its bound.",
                [finding],
            )
        command_count = len(all_commands) + nested_expansion_work
        operation_count = len(artifacts) * max(
            1,
            (command_count * 4) + transfer_source_count,
        )
        if operation_count > _MAX_CORRELATION_OPERATIONS:
            finding = self._incomplete_finding(
                pkgbuild_path,
                pkg_name,
                pkg_ver,
                "analysis_limit",
            )
            return AnalysisResult(
                False,
                "Package-checkout provenance correlation exceeded its bound.",
                [finding],
            )
        if self._has_layout_dependent_checkout_transfer(
            artifacts,
            pkgbuild_commands,
            transfers,
            checkout_dir,
        ):
            finding = self._incomplete_finding(
                pkgbuild_path,
                pkg_name,
                pkg_ver,
                "command_parser_limit",
            )
            return AnalysisResult(
                False,
                "Package-checkout transfer correlation was layout-dependent.",
                [finding],
            )
        if any(
            self._repository_token_ambiguous(source, constants)
            and not self._installed_path(source, constants)
            for _command, constants, _repository_cwd, transfer in transfers
            for source in transfer.sources
        ):
            finding = self._incomplete_finding(
                pkgbuild_path,
                pkg_name,
                pkg_ver,
                "command_parser_limit",
            )
            return AnalysisResult(
                False,
                "Package-checkout transfer correlation was ambiguous.",
                [finding],
            )

        findings: List[Finding] = []
        installed_destinations: Dict[str, Set[str]] = {}
        surviving_installed_destinations: Dict[str, Set[str]] = {}
        installed_destination_origins: Dict[
            str,
            Dict[str, Set[Tuple[int, int]]],
        ] = {}
        command_positions = {
            id(scoped.command): (
                scoped.scope_id,
                index,
                scoped.lifecycle_root,
            )
            for index, scoped in enumerate(pkgbuild_commands)
        }

        if self._has_ambiguous_checkout_execution(
            artifacts,
            pkgbuild_commands,
            checkout_dir,
        ) or (
            hook_commands
            and self._has_ambiguous_checkout_execution(
                artifacts,
                hook_commands,
                checkout_dir,
            )
        ):
            finding = self._incomplete_finding(
                pkgbuild_path,
                pkg_name,
                pkg_ver,
                "command_parser_limit",
            )
            return AnalysisResult(
                False,
                "Package-checkout execution correlation was ambiguous.",
                [finding],
            )

        for artifact in sorted(
            artifacts,
            key=lambda item: (self._artifact_relative_path(item), item.kind),
        ):
            relative_path = self._artifact_relative_path(artifact)
            if not relative_path:
                continue

            critical = self._pkgbuild_execution_correlation(
                artifact,
                pkgbuild_commands,
                pkgbuild_path,
                checkout_dir,
            )
            high: Optional[_Correlation] = None

            for command, command_constants, repository_cwd, transfer in transfers:
                matched_transfer = next(
                    (
                        (source_path, descendant_suffix)
                        for source_path in transfer.sources
                        for descendant_suffix in (
                            self._repository_transfer_suffix(
                                source_path,
                                relative_path,
                                checkout_dir,
                                command_constants,
                                recursive=transfer.recursive,
                                repository_cwd=repository_cwd,
                            ),
                        )
                        if descendant_suffix is not None
                    ),
                    None,
                )
                if matched_transfer is None:
                    continue
                matched_source, descendant_suffix = matched_transfer
                destination = self._installed_destination(
                    transfer.destination,
                    matched_source,
                    transfer.target_directory,
                    command_constants,
                    descendant_suffix=descendant_suffix,
                )
                if not destination:
                    if self._known_pkgdir_parent_escape(
                        transfer.destination,
                        command_constants,
                    ):
                        continue
                    if "$pkgdir" in transfer.destination or "${pkgdir" in transfer.destination:
                        finding = self._incomplete_finding(
                            pkgbuild_path,
                            pkg_name,
                            pkg_ver,
                            "command_parser_limit",
                        )
                        return AnalysisResult(
                            False,
                            "Package payload destination correlation was ambiguous.",
                            [finding],
                        )
                    continue
                # A recursive directory operand proves that the descendant is
                # included in the package payload (HIGH), but an otherwise
                # unknown destination may be either a rename or an existing
                # directory.  Only feed later execution/SUID correlation when
                # -T or statically known target-directory semantics prove the
                # installed child path.
                exact_installed_mapping = transfer.destination_exact and (
                    not descendant_suffix
                    or transfer.target_directory
                    or transfer.no_target_directory
                )
                if exact_installed_mapping:
                    installed_destinations.setdefault(relative_path, set()).add(destination)
                    origin = command_positions.get(id(command))
                    if origin is not None:
                        installed_destination_origins.setdefault(
                            relative_path,
                            {},
                        ).setdefault(destination, set()).add(origin[:2])
                    if (
                        origin is not None
                        and (
                            origin[2] == "package"
                            or origin[2].startswith("package_")
                        )
                        and self._installed_destination_survives(
                            destination,
                            command,
                            pkgbuild_commands,
                        )
                    ):
                        surviving_installed_destinations.setdefault(
                            relative_path,
                            set(),
                        ).add(destination)
                preserves_setid = (
                    transfer.preserves_mode
                    and transfer.destination_exact
                    and bool(artifact.mode & 0o6000)
                )
                if (transfer.suid_mode or preserves_setid) and critical is None:
                    critical = _Correlation(
                        "AUR-REPO-OPAQUE-BINARY-EXEC-001",
                        Phase.pkgbuild_static,
                        pkgbuild_path,
                        command.line_number,
                        "Correlated signals: undeclared opaque checkout artifact; set-user-ID or set-group-ID package installation",
                    )
                if high is None:
                    high = _Correlation(
                        "AUR-REPO-OPAQUE-BINARY-001",
                        Phase.pkgbuild_static,
                        pkgbuild_path,
                        command.line_number,
                        "Correlated signals: undeclared opaque checkout artifact; copy or install into the package payload",
                    )

            chmod_correlation = self._suid_chmod_correlation(
                artifact,
                pkgbuild_commands,
                pkgbuild_path,
                checkout_dir,
                installed_destinations.get(relative_path, set()),
                installed_destination_origins.get(relative_path, {}),
            )
            if critical is None and chmod_correlation is not None:
                critical = chmod_correlation

            if critical is None:
                installed_execution = self._installed_execution_correlation(
                    installed_destinations.get(relative_path, set()),
                    pkgbuild_commands,
                    pkgbuild_path,
                    Phase.pkgbuild_static,
                    "Correlated signals: undeclared opaque checkout artifact; installed destination; execution in package control text",
                    origin_positions=installed_destination_origins.get(
                        relative_path,
                        {},
                    ),
                )
                if installed_execution is not None:
                    critical = installed_execution

            if critical is None and hook_commands:
                hook_correlation = self._installed_execution_correlation(
                    surviving_installed_destinations.get(relative_path, set()),
                    hook_commands,
                    hook_path,
                    Phase.install_hook_static,
                    "Correlated signals: undeclared opaque checkout artifact; installed destination; install-hook execution",
                )
                if hook_correlation is not None:
                    critical = hook_correlation

            if critical is None and hook_commands:
                hook_setid = self._suid_chmod_correlation(
                    artifact,
                    hook_commands,
                    hook_path,
                    checkout_dir,
                    surviving_installed_destinations.get(relative_path, set()),
                    phase=Phase.install_hook_static,
                )
                if hook_setid is not None:
                    critical = hook_setid

            correlation = critical or high
            if correlation is None:
                if not artifact.generated_output:
                    findings.append(
                        self._presence_finding(
                            artifact,
                            checkout_dir,
                            pkg_name,
                            pkg_ver,
                        )
                    )
            else:
                findings.append(
                    self._correlated_finding(
                        artifact,
                        correlation,
                        pkg_name,
                        pkg_ver,
                    )
                )

        safe = not any(finding.blocks_installation for finding in findings)
        return AnalysisResult(
            safe,
            "Package-checkout provenance analysis complete.",
            findings,
        )

    def _declared_checkout_paths(self, references: Iterable[object]) -> Set[str]:
        paths: Set[str] = set()
        for reference in references:
            filename = self._safe_relative_path(
                _makepkg_checkout_relative_path(reference)
            )
            if filename:
                # makepkg's get_filename/get_filepath contract resolves every
                # source through its checkout-root filename (including local
                # paths and explicit name::source renames).  Excluding the
                # parser's nested `resolved` spelling instead would let an
                # unrelated nested artifact inherit the root cache file's
                # declaration.
                paths.add(filename)
        return paths

    def _collect_transfers(self, commands: Sequence[_ScopedCommand]):
        collected = []
        known_directories = {"/"}
        previous_scope = None
        for scoped in commands:
            command = scoped.command
            constants = scoped.constants
            if scoped.scope_id != previous_scope:
                known_directories = {"/"}
                previous_scope = scoped.scope_id
            executable_value, arguments = self._effective_command(command, constants)
            executable = _basename(executable_value).lower()
            for removed, recursive in self._pkgdir_path_invalidations(
                executable,
                arguments,
                constants,
            ):
                if recursive:
                    prefix = removed.rstrip("/") + "/"
                    known_directories = {
                        path
                        for path in known_directories
                        if path != removed and not path.startswith(prefix)
                    }
                else:
                    known_directories.discard(removed)
            if executable == "mkdir" or (
                executable == "install"
                and any(value in {"-d", "--directory"} for value in arguments)
            ):
                known_directories.update(
                    self._declared_pkgdir_directories(arguments, constants)
                )
            if executable not in _TRANSFER_COMMANDS:
                continue
            transfer = self._parse_command_transfer(
                executable,
                arguments,
                constants,
            )
            if transfer is not None:
                installed_destination = self._installed_path(
                    transfer.destination,
                    constants,
                )
                if installed_destination in known_directories:
                    if not transfer.no_target_directory:
                        transfer = transfer._replace(target_directory=True)
                collected.append(
                    (
                        command,
                        constants,
                        (
                            None
                            if scoped.repository_cwd_possible
                            else scoped.repository_cwd
                        ),
                        transfer,
                    )
                )
                if executable == "install" and any(
                    value.startswith("-")
                    and not value.startswith("--")
                    and "D" in value[1:]
                    for value in arguments
                ):
                    installed_destination = self._installed_path(
                        transfer.destination,
                        constants,
                    )
                    if installed_destination:
                        known_directories.add(posixpath.dirname(installed_destination))
        return collected

    def _has_layout_dependent_checkout_transfer(
        self,
        artifacts: Sequence[RepositoryArtifact],
        commands: Sequence[_ScopedCommand],
        transfers: Sequence[Tuple[object, Dict[str, str], Optional[str], _Transfer]],
        checkout_dir: Path,
    ) -> bool:
        scoped_by_command = {id(item.command): item for item in commands}
        artifact_paths = {
            self._artifact_relative_path(artifact)
            for artifact in artifacts
            if self._artifact_relative_path(artifact)
        }
        for command, constants, _exact_cwd, transfer in transfers:
            scoped = scoped_by_command.get(id(command))
            if scoped is None:
                continue
            for source in transfer.sources:
                resolved = self._resolve_constants(source, constants)
                direct_layout = resolved.rstrip("/") in {
                    "$srcdir",
                    "${srcdir}",
                    "$srcdir/..",
                    "${srcdir}/..",
                } or resolved.startswith(
                    _KNOWN_SRCDIR_PARENT_PREFIXES + _KNOWN_SRCDIR_PREFIXES
                )
                cwd_layout = (
                    scoped.repository_cwd_possible
                    and _relative_path_requires_cwd(source, constants)
                )
                if not direct_layout and not cwd_layout:
                    continue
                projected = self._repository_relative_path(
                    source,
                    checkout_dir,
                    constants,
                    allow_bare=True,
                    repository_cwd=scoped.repository_cwd,
                    capture_layout_dependent=True,
                )
                if not projected:
                    return bool(artifact_paths)
                if projected in artifact_paths:
                    return True
                if transfer.recursive and any(
                    path.startswith(projected.rstrip("/") + "/")
                    for path in artifact_paths
                ):
                    return True
        return False

    def _pkgdir_path_invalidations(
        self,
        executable: str,
        arguments: Sequence[str],
        constants: Dict[str, str],
        *,
        include_overwrites: bool = False,
    ) -> List[Tuple[str, bool]]:
        """Return exact package-payload paths removed or moved away.

        These mutations update only deterministic destination-shape and hook
        reachability state.  They do not erase the earlier HIGH transfer
        evidence, and no static match claims that a filesystem command
        succeeded.
        """

        resolved = [self._resolve_constants(value, constants) for value in arguments]
        invalidations: List[Tuple[str, bool]] = []
        if executable in {"rm", "rmdir", "unlink"}:
            recursive = executable == "rmdir" or any(
                value in {"-r", "-R", "--recursive"}
                or (
                    value.startswith("-")
                    and not value.startswith("--")
                    and any(flag in value[1:] for flag in "rR")
                )
                for value in resolved
            )
            values: List[str] = []
            after_terminator = False
            for value in resolved:
                if value == "--" and not after_terminator:
                    after_terminator = True
                    continue
                if not after_terminator and value.startswith("-"):
                    continue
                values.append(value)
            invalidations.extend(
                (installed, recursive)
                for installed in (
                    self._installed_path(value, constants) for value in values
                )
                if installed
            )
        if executable == "mv":
            transfer = self._parse_transfer("mv", arguments, constants)
            if transfer is not None:
                invalidations.extend(
                    (installed, True)
                    for installed in (
                        self._installed_path(value, constants)
                        for value in transfer.sources
                    )
                    if installed
                )
        if not include_overwrites:
            return list(dict.fromkeys(invalidations))

        for index, value in enumerate(resolved):
            if value != _SIMPLE_STDOUT_REDIRECTION_MARKER:
                continue
            if index + 1 < len(resolved):
                installed = self._installed_path(resolved[index + 1], constants)
                if installed:
                    invalidations.append((installed, False))

        if executable == "truncate":
            invalidations.extend(
                (installed, False)
                for installed in self._truncate_installed_targets(
                    arguments,
                    constants,
                )
            )

        if executable in {"cat", "cp", "dd", "install", "mv", "rsync"}:
            transfer = self._parse_command_transfer(
                executable,
                arguments,
                constants,
            )
            if transfer is not None and transfer.destination_exact:
                if transfer.target_directory:
                    for source in transfer.sources:
                        installed = self._installed_destination(
                            transfer.destination,
                            source,
                            True,
                            constants,
                        )
                        if installed:
                            invalidations.append((installed, transfer.recursive))
                else:
                    installed = self._installed_path(
                        transfer.destination,
                        constants,
                    )
                    if installed:
                        invalidations.append((installed, transfer.recursive))
        return list(dict.fromkeys(invalidations))

    def _truncate_installed_targets(
        self,
        arguments: Sequence[str],
        constants: Dict[str, str],
    ) -> List[str]:
        """Return exact staged paths modified by a bounded truncate command."""

        resolved = [self._resolve_constants(value, constants) for value in arguments]
        value_options = {"-r", "--reference", "-s", "--size"}
        targets: List[str] = []
        index = 0
        after_terminator = False
        while index < len(resolved):
            value = resolved[index]
            if value == "--" and not after_terminator:
                after_terminator = True
                index += 1
                continue
            if not after_terminator and value in value_options:
                if index + 1 >= len(resolved):
                    return []
                index += 2
                continue
            if not after_terminator and value.startswith(
                ("--reference=", "--size=")
            ):
                index += 1
                continue
            if not after_terminator and value.startswith(("-r", "-s")) and value not in {
                "-r", "-s",
            }:
                index += 1
                continue
            if not after_terminator and value.startswith("-"):
                index += 1
                continue
            installed = self._installed_path(value, constants)
            if installed:
                targets.append(installed)
            index += 1
        return targets

    def _pkgdir_overwrite_is_ambiguous(
        self,
        executable: str,
        arguments: Sequence[str],
        constants: Dict[str, str],
    ) -> bool:
        """Withhold hook provenance when a later staged overwrite is unresolved."""

        resolved = [self._resolve_constants(value, constants) for value in arguments]
        possible_destinations: List[str] = []
        for index, value in enumerate(resolved):
            if (
                value == _SIMPLE_STDOUT_REDIRECTION_MARKER
                and index + 1 < len(resolved)
            ):
                possible_destinations.append(resolved[index + 1])
        if executable not in {
            "cat", "cp", "dd", "install", "mv", "printf", "rsync", "truncate",
        } and not possible_destinations:
            return False
        transfer = self._parse_command_transfer(executable, arguments, constants)
        if transfer is not None:
            possible_destinations.append(transfer.destination)
            if transfer.target_directory and any(
                not self._safe_relative_path(posixpath.basename(source.rstrip("/")))
                for source in transfer.sources
            ):
                return True
        if executable == "truncate":
            possible_destinations.extend(
                value
                for value in resolved
                if not value.startswith("-") and value != "--"
            )
        return any(
            ("$pkgdir" in value or "${pkgdir" in value)
            and not self._installed_path(value, constants)
            for value in possible_destinations
        )

    def _installed_destination_survives(
        self,
        destination: str,
        transfer_command: object,
        commands: Sequence[_ScopedCommand],
    ) -> bool:
        """Keep hook mapping only while later same-scope mutations preserve it."""

        found_transfer = False
        transfer_scope = -1
        for scoped in commands:
            if not found_transfer:
                if scoped.command is transfer_command:
                    found_transfer = True
                    transfer_scope = scoped.scope_id
                continue
            if scoped.scope_id != transfer_scope:
                continue
            executable_value, arguments = self._effective_command(
                scoped.command,
                scoped.constants,
            )
            executable = _basename(executable_value).lower()
            if self._pkgdir_overwrite_is_ambiguous(
                executable,
                arguments,
                scoped.constants,
            ):
                return False
            for removed, recursive in self._pkgdir_path_invalidations(
                executable,
                arguments,
                scoped.constants,
                include_overwrites=True,
            ):
                prefix = removed.rstrip("/") + "/"
                if destination == removed or (
                    recursive and destination.startswith(prefix)
                ):
                    return False
        return True

    def _declared_pkgdir_directories(
        self,
        arguments: Sequence[str],
        constants: Dict[str, str],
    ) -> Set[str]:
        resolved = [self._resolve_constants(value, constants) for value in arguments]
        directories: Set[str] = set()
        options_with_value = {
            "-g", "--group", "-m", "--mode", "-o", "--owner",
            "-Z", "--context",
        }
        index = 0
        while index < len(resolved):
            value = resolved[index]
            if value in options_with_value:
                index += 2
                continue
            if value == "--":
                index += 1
                while index < len(resolved):
                    installed = self._installed_path(resolved[index], constants)
                    if installed:
                        directories.add(installed)
                    index += 1
                break
            if value.startswith("-"):
                index += 1
                continue
            installed = self._installed_path(value, constants)
            if installed:
                directories.add(installed)
            index += 1
        return directories

    def _parse_command_transfer(
        self,
        executable: str,
        arguments: Sequence[str],
        constants: Dict[str, str],
    ) -> Optional[_Transfer]:
        if executable == "cat":
            return self._parse_cat_transfer(arguments, constants)
        if executable == "dd":
            return self._parse_dd_transfer(arguments, constants)
        if executable == "rsync":
            return self._parse_rsync_transfer(arguments, constants)
        if executable in {"tar", "bsdtar", "unzip"}:
            return self._parse_archive_deployment(
                executable,
                arguments,
                constants,
            )
        if executable in {"cp", "install", "ln", "mv"}:
            return self._parse_transfer(executable, arguments, constants)
        return None

    def _parse_dd_transfer(
        self,
        arguments: Sequence[str],
        constants: Dict[str, str],
    ) -> Optional[_Transfer]:
        resolved = [self._resolve_constants(value, constants) for value in arguments]
        source = ""
        destination = ""
        for value in resolved:
            if value.startswith("if="):
                if source:
                    return None
                source = value[3:]
            elif value.startswith("of="):
                if destination:
                    return None
                destination = value[3:]
            elif value.startswith(("conv=", "count=", "skip=", "seek=")):
                return None
            elif "=" not in value or value.startswith("-"):
                return None
        if not source or not destination:
            return None
        return _Transfer(
            (source,),
            destination,
            False,
            False,
            True,
            True,
            False,
            False,
        )

    def _parse_rsync_transfer(
        self,
        arguments: Sequence[str],
        constants: Dict[str, str],
    ) -> Optional[_Transfer]:
        resolved = [self._resolve_constants(value, constants) for value in arguments]
        value_options = {
            "-e", "--rsh", "--rsync-path", "--password-file", "--exclude",
            "--exclude-from", "--include", "--include-from", "--filter",
            "--files-from", "--max-size", "--min-size", "--bwlimit", "--timeout",
            "--contimeout", "--chmod", "--chown", "--usermap", "--groupmap",
            "--temp-dir", "--backup-dir", "--suffix", "--out-format",
            "--log-file", "--log-file-format", "--remote-option",
        }
        positionals: List[str] = []
        recursive = False
        preserves_mode = False
        index = 0
        after_terminator = False
        while index < len(resolved):
            value = resolved[index]
            if value == "--" and not after_terminator:
                after_terminator = True
                index += 1
                continue
            if not after_terminator and value in value_options:
                if index + 1 >= len(resolved):
                    return None
                index += 2
                continue
            if not after_terminator and any(
                value.startswith(option + "=")
                for option in value_options
                if option.startswith("--")
            ):
                index += 1
                continue
            if not after_terminator and value.startswith("-"):
                if not value.startswith("--"):
                    recursive = recursive or any(flag in value[1:] for flag in "ar")
                    preserves_mode = preserves_mode or any(
                        flag in value[1:] for flag in "ap"
                    )
                    index += 1
                    continue
                if value in {
                    "--archive", "--recursive", "--perms", "--links", "--hard-links",
                    "--times", "--devices", "--specials", "--delete", "--compress",
                    "--protect-args", "--relative",
                }:
                    recursive = recursive or value in {"--archive", "--recursive"}
                    preserves_mode = preserves_mode or value in {"--archive", "--perms"}
                    index += 1
                    continue
                return None
            positionals.append(value)
            index += 1
        if len(positionals) < 2 or any(
            "://" in value or re.match(r"(?:[^/]+@)?[^/]+:", value)
            for value in positionals
        ):
            return None
        return _Transfer(
            tuple(positionals[:-1]),
            positionals[-1],
            len(positionals) > 2 or positionals[-1].endswith("/"),
            False,
            True,
            False,
            recursive,
            preserves_mode,
        )

    def _parse_archive_deployment(
        self,
        executable: str,
        arguments: Sequence[str],
        constants: Dict[str, str],
    ) -> Optional[_Transfer]:
        resolved = [self._resolve_constants(value, constants) for value in arguments]
        archive = ""
        destination = ""
        if executable == "unzip":
            positionals: List[str] = []
            index = 0
            while index < len(resolved):
                value = resolved[index]
                if value in {"-l", "-t", "-v", "-z", "--list", "--test"}:
                    return None
                if value in {"-d", "--directory"}:
                    if index + 1 >= len(resolved):
                        return None
                    destination = resolved[index + 1]
                    index += 2
                    continue
                if value.startswith("-d") and value != "-d":
                    destination = value[2:]
                    index += 1
                    continue
                if value.startswith("-"):
                    index += 1
                    continue
                positionals.append(value)
                index += 1
            if len(positionals) != 1:
                return None
            archive = positionals[0]
        else:
            extracting = False
            index = 0
            while index < len(resolved):
                value = resolved[index]
                if value in {"-x", "--extract", "--get"} or (
                    value.startswith("-")
                    and not value.startswith("--")
                    and "x" in value[1:]
                ):
                    extracting = True
                if value in {"-t", "--list", "-c", "--create"} or (
                    value.startswith("-")
                    and not value.startswith("--")
                    and any(flag in value[1:] for flag in "tc")
                ):
                    return None
                if value in {"-f", "--file"}:
                    if index + 1 >= len(resolved):
                        return None
                    archive = resolved[index + 1]
                    index += 2
                    continue
                if value.startswith("--file="):
                    archive = value.split("=", 1)[1]
                    index += 1
                    continue
                if value.startswith("-") and not value.startswith("--") and "f" in value[1:]:
                    if index + 1 >= len(resolved):
                        return None
                    archive = resolved[index + 1]
                    index += 2
                    continue
                if value in {"-C", "--directory"}:
                    if index + 1 >= len(resolved):
                        return None
                    destination = resolved[index + 1]
                    index += 2
                    continue
                if value.startswith("--directory="):
                    destination = value.split("=", 1)[1]
                    index += 1
                    continue
                index += 1
            if not extracting:
                return None
        if not archive or not destination or not self._installed_path(
            destination,
            constants,
        ):
            return None
        return _Transfer(
            (archive,),
            destination,
            True,
            False,
            False,
            False,
            False,
            False,
        )

    def _parse_cat_transfer(
        self,
        arguments: Sequence[str],
        constants: Dict[str, str],
    ) -> Optional[_Transfer]:
        """Parse only an exact, single-source stdout replacement.

        Redirection retention is deliberately limited by
        ``_iter_shell_segments``.  This second gate rejects options, append or
        descriptor spellings, multiple inputs, and additional operands so a
        diagnostic redirect cannot be mistaken for package installation.
        """

        resolved = [self._resolve_constants(value, constants) for value in arguments]
        if not resolved:
            return None
        positionals: List[str] = []
        destination = ""
        after_terminator = False
        index = 0
        while index < len(resolved):
            value = resolved[index]
            if not destination and value == _SIMPLE_STDOUT_REDIRECTION_MARKER:
                if index + 1 >= len(resolved):
                    return None
                destination = resolved[index + 1]
                index += 2
                if index != len(resolved):
                    return None
                break
            if value == "--" and not after_terminator:
                after_terminator = True
                index += 1
                continue
            if not after_terminator and value.startswith("-"):
                return None
            positionals.append(value)
            index += 1
        if len(positionals) != 1 or not destination or positionals[0] == "-":
            return None
        if not self._installed_path(destination, constants) and not destination.startswith(
            ("$pkgdir/", "${pkgdir}/")
        ):
            return None
        return _Transfer(
            (positionals[0],),
            destination,
            False,
            False,
            True,
            True,
            False,
            False,
        )

    def _parse_transfer(
        self,
        executable: str,
        arguments: Sequence[str],
        constants: Dict[str, str],
    ) -> Optional[_Transfer]:
        resolved = [self._resolve_constants(value, constants) for value in arguments]
        positionals: List[str] = []
        target_directory = ""
        mode_values: List[str] = []
        destination_exact = True
        no_target_directory = False
        recursive = executable == "mv"
        preserves_mode = executable in {"ln", "mv"}
        after_terminator = False
        index = 0
        options_with_value = _TRANSFER_OPTIONS_WITH_VALUE[executable]
        while index < len(resolved):
            value = resolved[index]
            if after_terminator:
                positionals.append(value)
                index += 1
                continue
            if value == "--":
                after_terminator = True
                index += 1
                continue
            if value in options_with_value:
                if index + 1 >= len(resolved):
                    return None
                operand = resolved[index + 1]
                if value in _TARGET_DIRECTORY_OPTIONS:
                    target_directory = operand
                elif value in {"-m", "--mode"}:
                    mode_values.append(operand)
                index += 2
                continue
            long_option = next(
                (
                    option
                    for option in options_with_value
                    if option.startswith("--") and value.startswith(option + "=")
                ),
                "",
            )
            if long_option:
                operand = value.split("=", 1)[1]
                if long_option in _TARGET_DIRECTORY_OPTIONS:
                    target_directory = operand
                elif long_option == "--mode":
                    mode_values.append(operand)
                index += 1
                continue
            if value.startswith("-t") and not value.startswith("--") and len(value) > 2:
                target_directory = value[2:]
                index += 1
                continue
            if executable == "install" and value in {"-d", "--directory"}:
                # Directory creation has no source operand.  Treating its
                # first path as an artifact would invent a copy operation.
                return None
            if executable == "ln" and (
                value == "--symbolic"
                or (
                    value.startswith("-")
                    and not value.startswith("--")
                    and "s" in value[1:]
                )
            ):
                return None
            if value in {"-T", "--no-target-directory"}:
                no_target_directory = True
                index += 1
                continue
            if executable == "cp" and value == "--parents":
                destination_exact = False
            if executable == "cp" and value == "--attributes-only":
                return None
            if executable == "cp" and value in {"-a", "--archive", "-p"}:
                preserves_mode = True
            if executable == "cp" and value == "--preserve":
                preserves_mode = True
            if executable == "cp" and value.startswith("--preserve="):
                attributes = {
                    item.strip().lower()
                    for item in value.split("=", 1)[1].split(",")
                }
                preserves_mode = preserves_mode or bool(
                    attributes & {"all", "mode"}
                )
            if executable == "cp" and value.startswith("--no-preserve="):
                attributes = {
                    item.strip().lower()
                    for item in value.split("=", 1)[1].split(",")
                }
                if attributes & {"all", "mode"}:
                    preserves_mode = False
                index += 1
                continue
            if executable == "cp" and value in {
                "-a",
                "--archive",
                "-r",
                "-R",
                "--recursive",
            }:
                recursive = True
                index += 1
                continue
            if (
                executable == "cp"
                and value.startswith("-")
                and not value.startswith("--")
                and any(option in value[1:] for option in "aRr")
            ):
                recursive = True
            if (
                executable == "cp"
                and value.startswith("-")
                and not value.startswith("--")
                and any(option in value[1:] for option in "ap")
            ):
                preserves_mode = True
            if executable == "install":
                attached_mode = re.search(
                    r"m(0?[0-7]{3,4}|(?:[ugoa]*[ug][ugoa]*|a)\+s|\+s)\Z",
                    value,
                    re.IGNORECASE,
                )
                if value.startswith("-") and attached_mode:
                    mode_values.append(attached_mode.group(1))
            if value.startswith("-"):
                index += 1
                continue
            positionals.append(value)
            index += 1

        if target_directory:
            if not positionals:
                return None
            return _Transfer(
                tuple(positionals),
                target_directory,
                True,
                any(self._is_suid_mode(value) for value in mode_values),
                destination_exact,
                no_target_directory,
                recursive,
                preserves_mode,
            )
        if len(positionals) < 2:
            return None
        return _Transfer(
            tuple(positionals[:-1]),
            positionals[-1],
            False if no_target_directory else (
                len(positionals) > 2 or positionals[-1].endswith("/")
            ),
            any(self._is_suid_mode(value) for value in mode_values),
            destination_exact,
            no_target_directory,
            recursive,
            preserves_mode,
        )

    def _pkgbuild_execution_correlation(
        self,
        artifact: RepositoryArtifact,
        commands: Sequence[_ScopedCommand],
        pkgbuild_path: str,
        checkout_dir: Path,
    ) -> Optional[_Correlation]:
        relative_path = self._artifact_relative_path(artifact)
        for scoped in commands:
            command = scoped.command
            constants = scoped.constants
            candidates, complete = self._execution_candidates(
                command,
                constants,
                scoped.exported_loaders,
            )
            if not complete:
                continue
            if any(
                self._matches_repository_artifact(
                    candidate.path,
                    relative_path,
                    checkout_dir,
                    constants,
                    allow_bare=candidate.allow_bare,
                    repository_cwd=(
                        None
                        if scoped.repository_cwd_possible
                        else scoped.repository_cwd
                    ),
                )
                for candidate in candidates
                if candidate.path
            ):
                return _Correlation(
                    "AUR-REPO-OPAQUE-BINARY-EXEC-001",
                    Phase.pkgbuild_static,
                    pkgbuild_path,
                    command.line_number,
                    "Correlated signals: undeclared opaque checkout artifact; execution or code loading in package control text",
                )
        return None

    def _suid_chmod_correlation(
        self,
        artifact: RepositoryArtifact,
        commands: Sequence[_ScopedCommand],
        pkgbuild_path: str,
        checkout_dir: Path,
        installed_destinations: Set[str],
        origin_positions: Optional[
            Dict[str, Set[Tuple[int, int]]]
        ] = None,
        *,
        phase: Phase = Phase.pkgbuild_static,
    ) -> Optional[_Correlation]:
        relative_path = self._artifact_relative_path(artifact)
        for command_index, scoped in enumerate(commands):
            command = scoped.command
            constants = scoped.constants
            executable_value, arguments = self._effective_command(command, constants)
            if _basename(executable_value).lower() != "chmod":
                continue
            resolved = [self._resolve_constants(value, constants) for value in arguments]
            mode_status = self._chmod_mode_status(resolved)
            if mode_status is None:
                continue
            mode_index, recursive = mode_status
            if not self._is_suid_mode(resolved[mode_index]):
                continue
            targets = [
                value
                for value in resolved[mode_index + 1 :]
                if value != "--" and not value.startswith("-")
            ]
            if any(
                (
                    self._installed_path(target, constants)
                    or (
                        self._ordinary_installed_path(target, constants)
                        if phase == Phase.install_hook_static
                        else ""
                    )
                ) in installed_destinations
                or (
                    recursive
                    and self._installed_target_contains_artifact(
                        target,
                        constants,
                        installed_destinations,
                        allow_ordinary=phase == Phase.install_hook_static,
                    )
                )
                for target in targets
            ) and (
                origin_positions is None
                or any(
                    scope_id == scoped.scope_id and origin_index < command_index
                    for destination in installed_destinations
                    for scope_id, origin_index in origin_positions.get(
                        destination,
                        set(),
                    )
                )
            ):
                return _Correlation(
                    "AUR-REPO-OPAQUE-BINARY-EXEC-001",
                    phase,
                    pkgbuild_path,
                    command.line_number,
                    "Correlated signals: undeclared opaque checkout artifact; set-user-ID or set-group-ID permission change",
                )
        return None

    def _chmod_mode_status(
        self,
        arguments: Sequence[str],
    ) -> Optional[Tuple[int, bool]]:
        recursive = False
        before_terminator = True
        for value in arguments:
            if value == "--":
                before_terminator = False
                continue
            if not before_terminator:
                continue
            if value == "--reference" or value.startswith("--reference="):
                # A copied mode provides no static proof that either set-ID bit
                # is requested, even when another token resembles a mode.
                return None
            if value in {"-R", "--recursive"}:
                recursive = True
            elif value.startswith("-") and not value.startswith("--"):
                # GNU chmod permits clustered no-value options such as -Rv.
                recursive = recursive or "R" in value[1:]

        index = 0
        after_terminator = False
        while index < len(arguments):
            value = arguments[index]
            if value == "--":
                after_terminator = True
                index += 1
                continue
            if not after_terminator and value.startswith("-"):
                index += 1
                continue
            return index, recursive
        return None

    def _installed_target_contains_artifact(
        self,
        target: str,
        constants: Dict[str, str],
        installed_destinations: Set[str],
        *,
        allow_ordinary: bool,
    ) -> bool:
        installed_target = (
            self._installed_path(target, constants)
            or (
                self._ordinary_installed_path(target, constants)
                if allow_ordinary
                else ""
            )
        )
        if not installed_target:
            return False
        prefix = installed_target.rstrip("/")
        if not prefix:
            return bool(installed_destinations)
        return any(
            destination == prefix or destination.startswith(prefix + "/")
            for destination in installed_destinations
        )

    def _installed_execution_correlation(
        self,
        installed_destinations: Set[str],
        commands: Sequence[_ScopedCommand],
        control_path: str,
        phase: Phase,
        evidence: str,
        *,
        origin_positions: Optional[
            Dict[str, Set[Tuple[int, int]]]
        ] = None,
    ) -> Optional[_Correlation]:
        if not installed_destinations:
            return None
        for command_index, scoped in enumerate(commands):
            command = scoped.command
            constants = scoped.constants
            candidates, complete = self._execution_candidates(
                command,
                constants,
                scoped.exported_loaders,
            )
            if not complete:
                continue
            for candidate in candidates:
                installed = (
                    self._installed_path(candidate.path, constants)
                    or (
                        self._ordinary_installed_path(candidate.path, constants)
                        if phase == Phase.install_hook_static
                        else ""
                    )
                )
                if (
                    installed
                    and installed in installed_destinations
                    and (
                        origin_positions is None
                        or any(
                            scope_id == scoped.scope_id
                            and origin_index < command_index
                            for scope_id, origin_index in origin_positions.get(
                                installed,
                                set(),
                            )
                        )
                    )
                ):
                    return _Correlation(
                        "AUR-REPO-OPAQUE-BINARY-EXEC-001",
                        phase,
                        control_path,
                        command.line_number,
                        evidence,
                    )
        return None

    def _execution_candidates(
        self,
        command,
        constants: Dict[str, str],
        exported_loaders: Sequence[Tuple[str, Optional[str]]] = (),
        *,
        depth: int = 0,
    ):
        original_executable = self._resolve_constants(command.executable, constants)
        original_arguments = tuple(command.arguments)
        executable, arguments, wrapper_complete = self._effective_command_status(
            command,
            constants,
        )
        effective = command._replace(executable=executable, arguments=tuple(arguments))
        executed_path, complete = _executed_path_status(effective, constants)
        resolved_executable = self._resolve_constants(executable, constants)
        candidates: List[_ExecutionCandidate] = []
        effective_basename = _basename(executable).lower()
        external_loader_command = self._external_command_can_load(executable)
        for _name, raw_value in exported_loaders:
            if raw_value is None:
                if external_loader_command:
                    complete = False
                continue
            if not external_loader_command:
                continue
            resolved_value = self._resolve_constants(raw_value, constants)
            for path in resolved_value.split(":"):
                if path:
                    candidates.append(_ExecutionCandidate(path, False))
        for assignment in getattr(command, "assignments", ()):
            name, separator, raw_value = assignment.partition("=")
            if (
                separator
                and name in _CODE_LOADING_ASSIGNMENTS
                and (
                    effective_basename not in _SHELL_BUILTINS
                    or "/" in executable
                )
            ):
                resolved_value = self._resolve_constants(raw_value, constants)
                for path in resolved_value.split(":"):
                    if path:
                        candidates.append(_ExecutionCandidate(path, False))
        original_basename = _basename(original_executable).lower()
        if original_basename.startswith("ld-linux"):
            resolved_original_arguments = [
                self._resolve_constants(value, constants)
                for value in original_arguments
            ]
            for index, value in enumerate(resolved_original_arguments):
                if value in {"--audit", "--preload"} and index + 1 < len(
                    resolved_original_arguments
                ):
                    for path in resolved_original_arguments[index + 1].split(":"):
                        if path:
                            candidates.append(_ExecutionCandidate(path, False))
                elif value.startswith(("--audit=", "--preload=")):
                    for path in value.split("=", 1)[1].split(":"):
                        if path:
                            candidates.append(_ExecutionCandidate(path, False))
        if executed_path:
            # This is a command-position executable, source target, or
            # interpreter input.  A normalized bare path remains ineligible
            # for checkout-root matching because makepkg functions start in
            # $srcdir rather than beside PKGBUILD.
            candidates.append(_ExecutionCandidate(executed_path, False))
        interpreter_candidate = self._raw_interpreter_candidate(
            executable,
            arguments,
            constants,
        )
        if interpreter_candidate:
            candidates.append(_ExecutionCandidate(interpreter_candidate, False))
        consumer_candidates, consumer_complete = self._command_consumer_candidates(
            executable,
            arguments,
            constants,
        )
        candidates.extend(
            _ExecutionCandidate(path, False)
            for path in consumer_candidates
        )
        complete = complete and consumer_complete
        if resolved_executable:
            # Retain the raw command-position token for special roots such as
            # $startdir and $pkgdir, but do not treat a bare system command name
            # as a checkout-relative artifact.
            candidates.append(_ExecutionCandidate(resolved_executable, False))
        if not wrapper_complete:
            for value in arguments:
                resolved_value = self._resolve_constants(value, constants)
                if resolved_value.startswith(
                    _KNOWN_REPOSITORY_PREFIXES + _KNOWN_SRCDIR_PARENT_PREFIXES
                ) or os.path.isabs(resolved_value):
                    candidates.append(_ExecutionCandidate(resolved_value, False))
        nested_commands, nested_complete, _nested_work = self._literal_shell_commands(
            executable,
            arguments,
            constants,
            command.line_number,
        )
        complete = complete and nested_complete
        if depth < 2:
            for nested_command, nested_constants in nested_commands:
                nested_candidates, candidate_complete = self._execution_candidates(
                    nested_command,
                    nested_constants,
                    exported_loaders,
                    depth=depth + 1,
                )
                candidates.extend(nested_candidates)
                complete = complete and candidate_complete
        elif nested_commands:
            complete = False
        return list(dict.fromkeys(candidates)), complete and wrapper_complete

    def _command_consumer_candidates(
        self,
        executable: str,
        arguments: Sequence[str],
        constants: Dict[str, str],
    ) -> Tuple[List[str], bool]:
        """Parse bounded command operands of standard command consumers."""

        basename = _basename(executable).lower()
        if basename not in _COMMAND_CONSUMERS:
            return [], True
        resolved = [self._resolve_constants(value, constants) for value in arguments]

        if basename == "find":
            candidates: List[str] = []
            complete = True
            for index, value in enumerate(resolved):
                if value not in {"-exec", "-execdir", "-ok", "-okdir"}:
                    continue
                if index + 1 >= len(resolved):
                    complete = False
                    continue
                candidates.append(resolved[index + 1])
                if not any(
                    terminator in {";", "+"}
                    for terminator in resolved[index + 2 :]
                ):
                    complete = False
            return candidates, complete

        if basename == "xargs":
            index = self._known_wrapper_option_end(
                resolved,
                value_options={
                    "-a", "--arg-file", "-d", "--delimiter", "-E", "-e",
                    "--eof", "-I", "-i", "--replace", "-L", "-l",
                    "--max-lines", "-n", "--max-args", "-P", "--max-procs",
                    "-s", "--max-chars", "--process-slot-var",
                },
                flag_options={
                    "-0", "--null", "-o", "--open-tty", "-p", "--interactive",
                    "-r", "--no-run-if-empty", "-t", "--verbose", "-x",
                    "--exit",
                },
                attached_short_options={"-d", "-E", "-e", "-I", "-i", "-L", "-l", "-n", "-P", "-s"},
            )
            if index is None:
                return [], not resolved
            return [resolved[index]], True

        if basename == "watch":
            index = self._known_wrapper_option_end(
                resolved,
                value_options={"-n", "--interval"},
                flag_options={
                    "-b", "--beep", "-c", "--color", "-d", "--differences",
                    "-e", "--errexit", "-g", "--chgexit", "-p", "--precise",
                    "-q", "--equexit", "-r", "--no-rerun",
                    "-t", "--no-title", "-w", "--no-wrap", "-x", "--exec",
                },
                attached_short_options={"-n"},
            )
            if index is None:
                return [], not resolved
            return [resolved[index]], True

        index = self._known_wrapper_option_end(
            resolved,
            value_options={
                "-a", "--arg-file", "--bar", "--basefile", "--bf", "-C",
                "--cleanup", "--colsep", "--delay", "--env", "--eta", "-j",
                "--jobs", "--joblog", "--load", "--max-line-length", "--memfree",
                "--nice", "--results", "--resume-from", "--retries", "--sshlogin",
                "--sshloginfile", "--timeout", "--tmpdir", "--workdir",
            },
            flag_options={
                "-0", "--null", "--dry-run", "--halt-now", "--keep-order", "-k",
                "--line-buffer", "--no-notice", "--pipe", "--plain", "--progress",
                "--resume", "--tag", "--verbose",
            },
            attached_short_options={"-j"},
        )
        if index is None or resolved[index] in {":::", "::::"}:
            return [], not resolved
        return [resolved[index]], True

    def _external_command_can_load(self, executable: str) -> bool:
        """Return whether the resolved command can consume loader variables.

        Bash builtins do not start a dynamic executable, while an absolute or
        relative path with the same basename as a builtin does.  This keeps a
        persistent exported loader value evidence-bound to a later process
        launch instead of treating ``true`` or ``printf`` as code loading.
        """

        value = str(executable or "")
        if not value:
            return False
        return _basename(value).lower() not in _SHELL_BUILTINS or "/" in value

    def _literal_shell_commands(
        self,
        executable: str,
        arguments: Sequence[str],
        constants: Dict[str, str],
        outer_line: int,
    ):
        basename = _basename(executable).lower()
        if basename == "eval":
            resolved = [self._resolve_constants(value, constants) for value in arguments]
            code = " ".join(resolved)
        elif basename in {"ash", "bash", "dash", "sh", "zsh"}:
            resolved = [self._resolve_constants(value, constants) for value in arguments]
            code = ""
            for index, value in enumerate(resolved):
                if value == "-c":
                    if index + 1 >= len(resolved):
                        return [], False, 0
                    code = resolved[index + 1]
                    break
                if value.startswith("-c") and len(value) > 2:
                    code = value[2:]
                    break
        elif basename == "trap":
            resolved = [self._resolve_constants(value, constants) for value in arguments]
            if not resolved or any(value in {"-l", "-p"} for value in resolved):
                return [], True, 0
            index = 1 if resolved[0] == "--" else 0
            if index >= len(resolved):
                return [], True, 0
            action = resolved[index]
            conditions = {
                (
                    value.upper()[3:]
                    if value.upper().startswith("SIG")
                    else value.upper()
                )
                for value in resolved[index + 1 :]
            }
            if not conditions & {"DEBUG", "RETURN"} or action in {"", "-"}:
                return [], True, 0
            code = action
        else:
            return [], True, 0
        if not code:
            return [], True, 0
        unresolved_names = {
            (match.group("braced") or match.group("plain") or "")
            for match in _VARIABLE_REFERENCE.finditer(code)
        } - (_SPECIAL_PATH_VARIABLES | {"PWD"})
        if (
            code.strip().startswith(("$", "`"))
            or "$(" in code
            or "`" in code
            or unresolved_names
        ):
            return [], False, 0
        parsed = _commands_and_constants(code)
        if parsed is None:
            return [], False, 0
        commands, inner_constants = parsed
        merged_constants = dict(constants)
        merged_constants.update(inner_constants)
        nested_commands = [
            (command._replace(line_number=outer_line), merged_constants)
            for command in commands
        ]
        character_work = (len(code) + _LITERAL_SHELL_WORK_CHARS - 1) // (
            _LITERAL_SHELL_WORK_CHARS
        )
        return nested_commands, True, character_work + len(nested_commands)

    def _nested_shell_expansion_work(
        self,
        commands: Sequence[_ScopedCommand],
    ) -> int:
        """Preflight literal shell expansion against the analysis-wide bound.

        Literal ``eval`` and ``sh -c`` bodies are parsed again while matching
        each artifact.  Count every generated command, including two bounded
        recursive levels, before entering those per-artifact loops so a set of
        large quoted command streams cannot evade the correlation budget.
        """

        pending = [
            (item.command, item.constants, 0)
            for item in commands
        ]
        pending_index = 0
        expanded_work = 0
        while pending_index < len(pending):
            command, constants, depth = pending[pending_index]
            pending_index += 1
            executable, arguments, _wrapper_complete = self._effective_command_status(
                command,
                constants,
            )
            nested_commands, _nested_complete, nested_work = self._literal_shell_commands(
                executable,
                arguments,
                constants,
                command.line_number,
            )
            expanded_work += nested_work
            if expanded_work > _MAX_CORRELATION_OPERATIONS:
                return expanded_work
            if depth < 2:
                pending.extend(
                    (nested_command, nested_constants, depth + 1)
                    for nested_command, nested_constants in nested_commands
                )
        return expanded_work

    def _has_ambiguous_checkout_execution(
        self,
        artifacts: Sequence[RepositoryArtifact],
        commands: Sequence[_ScopedCommand],
        checkout_dir: Path,
    ) -> bool:
        for scoped in commands:
            command = scoped.command
            constants = scoped.constants
            candidates, complete = self._execution_candidates(
                command,
                constants,
                scoped.exported_loaders,
            )
            for candidate in candidates:
                resolved_candidate = self._resolve_constants(
                    candidate.path,
                    constants,
                )
                layout_dependent = resolved_candidate.startswith(
                    _KNOWN_SRCDIR_PARENT_PREFIXES + _KNOWN_SRCDIR_PREFIXES
                ) or (
                    scoped.repository_cwd_possible
                    and _relative_path_requires_cwd(candidate.path, constants)
                )
                if not layout_dependent:
                    continue
                projected = self._repository_relative_path(
                    candidate.path,
                    checkout_dir,
                    constants,
                    allow_bare=True,
                    repository_cwd=scoped.repository_cwd,
                    capture_layout_dependent=True,
                )
                if not projected:
                    return bool(artifacts)
                if any(
                    self._artifact_relative_path(artifact) == projected
                    for artifact in artifacts
                ):
                    return True
            if complete:
                continue
            if any(value is None for _name, value in scoped.exported_loaders):
                # An active external command with an exported but statically
                # unresolved loader path may select any opaque checkout
                # artifact.  Withhold an exact execution claim and fail the
                # bounded correlation closed instead.
                return True
            for artifact in artifacts:
                relative_path = self._artifact_relative_path(artifact)
                if any(
                    self._matches_repository_artifact(
                        candidate.path,
                        relative_path,
                        checkout_dir,
                        constants,
                        allow_bare=candidate.allow_bare,
                        repository_cwd=(
                            None
                            if scoped.repository_cwd_possible
                            else scoped.repository_cwd
                        ),
                    )
                    for candidate in candidates
                ):
                    return True
        return False

    def _raw_interpreter_candidate(
        self,
        executable: str,
        arguments: Sequence[str],
        constants: Dict[str, str],
    ) -> str:
        basename = _basename(executable).lower()
        resolved = [self._resolve_constants(value, constants) for value in arguments]
        if re.fullmatch(r"python(?:\d+(?:\.\d+)*)?", basename):
            no_value = {
                "-b", "-B", "-d", "-E", "-h", "--help", "-i", "-I",
                "-O", "-OO", "-P", "-q", "-s", "-S", "-u", "-v", "-V",
                "--version", "-x",
            }
            value_options = {"-W", "-X", "--check-hash-based-pycs"}
        elif basename in {
            "ash", "bash", "bun", "dash", "jsc", "lua", "luajit", "node",
            "nodejs", "perl", "php", "qjs", "quickjs", "rscript", "ruby",
            "sh", "tclsh", "wish", "zsh",
        }:
            no_value = {"-u", "--"}
            value_options = {"-O", "-o", "--init-file", "--rcfile"}
        elif basename == "java":
            for index, value in enumerate(resolved):
                if value == "-jar" and index + 1 < len(resolved):
                    return resolved[index + 1]
            return ""
        elif basename == "dotnet":
            index = 1 if resolved and resolved[0] == "exec" else 0
            value_options = {
                "--additional-deps",
                "--additionalprobingpath",
                "--depsfile",
                "--fx-version",
                "--roll-forward",
                "--runtimeconfig",
            }
            while index < len(resolved):
                value = resolved[index]
                if value == "--":
                    return resolved[index + 1] if index + 1 < len(resolved) else ""
                if value in value_options:
                    index += 2
                    continue
                if any(value.startswith(option + "=") for option in value_options):
                    index += 1
                    continue
                if value.startswith("-"):
                    index += 1
                    continue
                return value
            return ""
        elif basename in {"mono", "wasmer", "wasmtime"}:
            no_value = {"--"}
            value_options = set()
        else:
            return ""

        index = 0
        while index < len(resolved):
            value = resolved[index]
            if value == "--":
                return resolved[index + 1] if index + 1 < len(resolved) else ""
            if value in {"-c", "-e", "-m"} or value.startswith(("-c", "-e", "-m")):
                return ""
            if value in value_options:
                index += 2
                continue
            if value in no_value or value.startswith("-"):
                index += 1
                continue
            return value
        return ""

    def _effective_command(
        self,
        command,
        constants: Dict[str, str],
    ) -> Tuple[str, Sequence[str]]:
        executable, arguments, _complete = self._effective_command_status(
            command,
            constants,
        )
        return executable, arguments

    def _effective_command_status(
        self,
        command,
        constants: Dict[str, str],
    ) -> Tuple[str, Sequence[str], bool]:
        executable = self._resolve_constants(command.executable, constants)
        arguments: Sequence[str] = command.arguments
        for _index in range(_MAX_RESOLUTION_PASSES):
            basename = _basename(executable).lower()
            if not (
                basename in _EXECUTION_WRAPPERS
                or basename.startswith(("ld-linux", "qemu-"))
                or basename in {"wine", "wine64"}
            ):
                break
            wrapped_index = self._first_wrapped_command_index(
                arguments,
                constants,
                basename,
            )
            if wrapped_index is None:
                break
            executable = self._resolve_constants(arguments[wrapped_index], constants)
            arguments = arguments[wrapped_index + 1 :]
        basename = _basename(executable).lower()
        complete = not (
            basename in _EXECUTION_WRAPPERS
            or basename.startswith(("ld-linux", "qemu-"))
            or basename in {"wine", "wine64"}
        )
        return executable, arguments, complete

    def _first_wrapped_command_index(
        self,
        arguments: Sequence[str],
        constants: Dict[str, str],
        wrapper_name: str,
    ) -> Optional[int]:
        resolved = [self._resolve_constants(value, constants) for value in arguments]
        standard = self._standard_wrapper_command_index(resolved, wrapper_name)
        if standard is not NotImplemented:
            return standard
        options_with_value = set(_EXECUTION_WRAPPER_OPTIONS_WITH_VALUE)
        if wrapper_name.startswith("ld-linux"):
            options_with_value.update(_DYNAMIC_LOADER_OPTIONS_WITH_VALUE)
        elif wrapper_name.startswith("qemu-"):
            options_with_value.update(_QEMU_OPTIONS_WITH_VALUE)
        index = 0
        while index < len(resolved):
            value = resolved[index]
            if value == "--":
                return index + 1 if index + 1 < len(resolved) else None
            if value in options_with_value:
                if index + 1 >= len(resolved):
                    return None
                index += 2
                continue
            if any(
                value.startswith(option + "=")
                for option in options_with_value
                if option.startswith("--")
            ):
                index += 1
                continue
            if value.startswith("-"):
                index += 1
                continue
            return index
        return None

    def _standard_wrapper_command_index(
        self,
        arguments: Sequence[str],
        wrapper_name: str,
    ):
        """Return a proven command index for common execution wrappers.

        ``None`` means the recognized wrapper syntax is incomplete or
        ambiguous.  ``NotImplemented`` delegates older wrappers to the
        conservative generic parser.  Option operands are consumed before a
        command can be selected so a path-shaped mode, user, root, CPU mask,
        or limit is never mislabeled as executed code.
        """

        if wrapper_name == "timeout":
            index = self._known_wrapper_option_end(
                arguments,
                value_options={"-k", "--kill-after", "-s", "--signal"},
                flag_options={"-f", "--foreground", "--preserve-status", "-v", "--verbose"},
                attached_short_options={"-k", "-s"},
            )
            if index is None or index + 1 >= len(arguments):
                return None
            return index + 1

        if wrapper_name == "nice":
            index = 0
            while index < len(arguments):
                value = arguments[index]
                if value == "--":
                    return index + 1 if index + 1 < len(arguments) else None
                if value in {"-n", "--adjustment"}:
                    if index + 1 >= len(arguments):
                        return None
                    index += 2
                    continue
                if value.startswith("--adjustment=") or (
                    value.startswith("-n") and value != "-n"
                ) or re.fullmatch(r"-[0-9]+", value):
                    index += 1
                    continue
                if value.startswith("-"):
                    return None
                return index
            return None

        if wrapper_name == "ionice":
            index = 0
            process_selector = False
            while index < len(arguments):
                value = arguments[index]
                if value == "--":
                    return None if process_selector else (
                        index + 1 if index + 1 < len(arguments) else None
                    )
                option = next(
                    (
                        name
                        for name in (
                            "--classdata", "--class", "--pgid", "--pid", "--uid",
                            "-c", "-n", "-P", "-p", "-u",
                        )
                        if value == name or value.startswith(name + "=")
                    ),
                    "",
                )
                if option:
                    if option in {"--pgid", "--pid", "--uid", "-P", "-p", "-u"}:
                        process_selector = True
                    if value == option:
                        if index + 1 >= len(arguments):
                            return None
                        index += 2
                    else:
                        index += 1
                    continue
                attached = next(
                    (name for name in ("-c", "-n", "-P", "-p", "-u") if value.startswith(name) and value != name),
                    "",
                )
                if attached:
                    if attached in {"-P", "-p", "-u"}:
                        process_selector = True
                    index += 1
                    continue
                if value in {"-t", "--ignore"}:
                    index += 1
                    continue
                if value.startswith("-"):
                    return None
                return None if process_selector else index
            return None

        if wrapper_name == "stdbuf":
            return self._known_wrapper_option_end(
                arguments,
                value_options={"-e", "--error", "-i", "--input", "-o", "--output"},
                flag_options=set(),
                attached_short_options={"-e", "-i", "-o"},
            )

        if wrapper_name == "chrt":
            if any(value in {"-p", "--pid"} for value in arguments):
                return None
            index = self._known_wrapper_option_end(
                arguments,
                value_options={
                    "-D", "--sched-deadline", "-P", "--sched-period",
                    "-T", "--sched-runtime",
                },
                flag_options={
                    "-a", "--all-tasks", "-b", "--batch", "-d", "--deadline",
                    "-f", "--fifo", "-i", "--idle", "-m", "--max", "-o",
                    "--other", "-r", "--rr", "-R", "--reset-on-fork", "-v",
                    "--verbose",
                },
                attached_short_options={"-D", "-P", "-T"},
            )
            if index is None or index + 1 >= len(arguments):
                return None
            # The scheduling priority precedes the wrapped command.
            return index + 1

        if wrapper_name == "taskset":
            if any(value in {"-p", "--pid"} for value in arguments):
                return None
            index = self._known_wrapper_option_end(
                arguments,
                value_options=set(),
                flag_options={"-a", "--all-tasks", "-c", "--cpu-list"},
            )
            if index is None or index + 1 >= len(arguments):
                return None
            # The mask or CPU list precedes the wrapped command.
            return index + 1

        if wrapper_name == "setarch":
            if any(value in {"--list", "-h", "--help", "-V", "--version"} for value in arguments):
                return None
            index = 0
            if arguments and arguments[0].lower() in _SETARCH_NAMES:
                index = 1
            elif arguments and not arguments[0].startswith("-"):
                # An unknown first positional may be an architecture name.
                return None
            option_end = self._known_wrapper_option_end(
                arguments[index:],
                value_options=set(),
                flag_options={
                    "-3", "--3gb", "-B", "--32bit", "-F", "--fdpic-funcptrs",
                    "-I", "--short-inode", "-L", "--addr-compat-layout", "-R",
                    "--addr-no-randomize", "-T", "--sticky-timeouts", "-X",
                    "--read-implies-exec", "-Z", "--mmap-page-zero", "--uname-2.6",
                    "-v", "--verbose",
                },
            )
            return None if option_end is None else index + option_end

        if wrapper_name == "prlimit":
            if any(
                value in {"-p", "--pid"} or value.startswith("--pid=")
                for value in arguments
            ):
                return None
            resource_names = {
                "--as", "--core", "--cpu", "--data", "--fsize", "--locks",
                "--memlock", "--msgqueue", "--nice", "--nofile", "--nproc",
                "--rss", "--rtprio", "--rttime", "--sigpending", "--stack",
            }
            return self._known_wrapper_option_end(
                arguments,
                value_options=resource_names | {"-o", "--output"},
                flag_options={"--noheadings", "--raw", "--verbose"},
            )

        if wrapper_name == "chroot":
            index = self._known_wrapper_option_end(
                arguments,
                value_options={"--groups", "--userspec"},
                flag_options={"--skip-chdir"},
            )
            if index is None or index + 1 >= len(arguments):
                return None
            # NEWROOT is data; COMMAND follows it.
            return index + 1

        if wrapper_name == "runuser":
            index = 0
            user_form = False
            while index < len(arguments):
                value = arguments[index]
                if value == "--":
                    return (
                        index + 1
                        if user_form and index + 1 < len(arguments)
                        else None
                    )
                if value in {"-u", "--user"}:
                    if index + 1 >= len(arguments):
                        return None
                    user_form = True
                    index += 2
                    continue
                if value.startswith("--user="):
                    user_form = True
                    index += 1
                    continue
                if value in {
                    "-g", "--group", "-G", "--supp-group", "-w",
                    "--whitelist-environment",
                }:
                    if index + 1 >= len(arguments):
                        return None
                    index += 2
                    continue
                if value.startswith(
                    ("--group=", "--supp-group=", "--whitelist-environment=")
                ):
                    index += 1
                    continue
                if value in {"-l", "--login", "-m", "-p", "--preserve-environment", "-P", "--pty"}:
                    index += 1
                    continue
                if value.startswith("-") or not user_form:
                    return None
                return index
            return None

        return NotImplemented

    def _known_wrapper_option_end(
        self,
        arguments: Sequence[str],
        *,
        value_options: Set[str],
        flag_options: Set[str],
        attached_short_options: Sequence[str] = (),
    ) -> Optional[int]:
        index = 0
        while index < len(arguments):
            value = arguments[index]
            if value == "--":
                return index + 1 if index + 1 < len(arguments) else None
            if value in value_options:
                if index + 1 >= len(arguments):
                    return None
                index += 2
                continue
            if any(
                value.startswith(option + "=")
                for option in value_options
                if option.startswith("--")
            ) or any(
                value.startswith(option) and value != option
                for option in attached_short_options
            ):
                index += 1
                continue
            if value in flag_options:
                index += 1
                continue
            if value.startswith("-"):
                return None
            return index
        return None

    def _installed_destination(
        self,
        destination: str,
        source_path: str,
        target_directory: bool,
        constants: Dict[str, str],
        *,
        descendant_suffix: str = "",
    ) -> str:
        installed = self._installed_path(destination, constants)
        if not installed:
            return ""
        if target_directory:
            source_name = posixpath.basename(
                self._resolve_constants(source_path, constants).rstrip("/")
            )
            if source_name:
                installed = posixpath.join(installed, source_name)
        if descendant_suffix:
            safe_suffix = self._safe_relative_path(descendant_suffix)
            if not safe_suffix:
                return ""
            installed = posixpath.join(installed, safe_suffix)
        return self._normalize_installed_path(installed)

    def _installed_path(self, value: str, constants: Dict[str, str]) -> str:
        resolved = self._resolve_constants(value, constants)
        prefixes = ("$pkgdir", "${pkgdir}")
        for prefix in prefixes:
            if resolved == prefix:
                return "/"
            if resolved.startswith(prefix + "/"):
                return self._normalize_installed_path(resolved[len(prefix) :])
        return ""

    def _known_pkgdir_parent_escape(
        self,
        value: str,
        constants: Dict[str, str],
    ) -> bool:
        """Return true only for a literal path known to leave ``$pkgdir``."""

        resolved = self._resolve_constants(value, constants)
        for prefix in ("$pkgdir", "${pkgdir}"):
            if not resolved.startswith(prefix + "/"):
                continue
            remainder = resolved[len(prefix) + 1 :]
            if "$" in remainder or "`" in remainder or "\\" in remainder:
                return False
            normalized = posixpath.normpath(remainder)
            return normalized == ".." or normalized.startswith("../")
        return False

    def _ordinary_installed_path(self, value: str, constants: Dict[str, str]) -> str:
        resolved = self._resolve_constants(value, constants)
        if not resolved.startswith("/") or "$" in resolved or "`" in resolved:
            return ""
        return self._normalize_installed_path(resolved)

    def _matches_repository_artifact(
        self,
        value: str,
        relative_path: str,
        checkout_dir: Path,
        constants: Dict[str, str],
        *,
        allow_bare: bool,
        repository_cwd: Optional[str] = None,
    ) -> bool:
        candidate = self._repository_relative_path(
            value,
            checkout_dir,
            constants,
            allow_bare=allow_bare,
            repository_cwd=repository_cwd,
        )
        return bool(candidate and candidate == relative_path)

    def _repository_transfer_suffix(
        self,
        value: str,
        relative_path: str,
        checkout_dir: Path,
        constants: Dict[str, str],
        *,
        recursive: bool,
        repository_cwd: Optional[str] = None,
    ) -> Optional[str]:
        """Map an exact file or recursively copied directory to an artifact.

        The returned suffix is the artifact path beneath the statically
        resolved transfer source.  No filesystem access occurs here; the core
        snapshot has already established that the descendant artifact exists.
        """

        candidate = self._repository_relative_path(
            value,
            checkout_dir,
            constants,
            allow_bare=False,
            repository_cwd=repository_cwd,
        )
        if not candidate:
            return None
        if candidate == relative_path:
            return ""
        prefix = candidate.rstrip("/")
        if not recursive or not prefix or not relative_path.startswith(prefix + "/"):
            return None
        suffix = relative_path[len(prefix) + 1 :]
        return suffix if self._safe_relative_path(suffix) == suffix else None

    def _repository_relative_path(
        self,
        value: str,
        checkout_dir: Path,
        constants: Dict[str, str],
        *,
        allow_bare: bool,
        repository_cwd: Optional[str] = None,
        capture_layout_dependent: bool = False,
    ) -> str:
        resolved = self._resolve_constants(value, constants)
        if not resolved or "`" in resolved:
            return ""
        stripped = resolved.rstrip("/")
        if stripped in {"$srcdir", "${srcdir}"}:
            return "src" if capture_layout_dependent else ""
        if stripped in {"$srcdir/..", "${srcdir}/.."}:
            return ""
        for prefix in _KNOWN_REPOSITORY_PREFIXES:
            if resolved.startswith(prefix):
                return self._safe_relative_path(resolved[len(prefix) :])
        for prefix in _KNOWN_SRCDIR_PARENT_PREFIXES:
            if resolved.startswith(prefix):
                if not capture_layout_dependent:
                    return ""
                return self._safe_relative_path(resolved[len(prefix) :])
        for prefix in _KNOWN_SRCDIR_PREFIXES:
            if resolved.startswith(prefix):
                if not capture_layout_dependent:
                    return ""
                suffix = self._safe_relative_path(resolved[len(prefix) :])
                return posixpath.join("src", suffix) if suffix else ""

        if repository_cwd is not None:
            for prefix in _KNOWN_CWD_PREFIXES:
                if resolved.startswith(prefix):
                    joined = posixpath.normpath(
                        posixpath.join(
                            repository_cwd or ".",
                            resolved[len(prefix) :],
                        )
                    )
                    return self._safe_relative_path(joined)

        checkout = os.path.abspath(str(checkout_dir))
        if os.path.isabs(resolved):
            absolute = os.path.abspath(resolved)
            try:
                relative = os.path.relpath(absolute, checkout)
            except ValueError:
                return ""
            return self._safe_relative_path(relative)
        if repository_cwd is not None:
            joined = posixpath.normpath(
                posixpath.join(repository_cwd or ".", resolved)
            )
            if joined == ".":
                return ""
            return self._safe_relative_path(joined)
        if resolved.startswith("./"):
            if not allow_bare:
                return ""
            return self._safe_relative_path(resolved[2:])
        if "$" in resolved or not allow_bare:
            return ""
        return self._safe_relative_path(resolved)

    def _repository_token_ambiguous(
        self,
        value: str,
        constants: Dict[str, str],
    ) -> bool:
        resolved = self._resolve_constants(value, constants)
        for prefix in (
            _KNOWN_REPOSITORY_PREFIXES
            + _KNOWN_SRCDIR_PARENT_PREFIXES
            + _KNOWN_SRCDIR_PREFIXES
        ):
            if resolved.startswith(prefix):
                resolved = resolved[len(prefix) :]
                break
        return any(
            marker in resolved
            for marker in ("$", "`", "*", "?", "[", "{")
        )

    def _resolve_constants(self, value: str, constants: Dict[str, str]) -> str:
        resolved = value
        for _index in range(_MAX_RESOLUTION_PASSES):
            updated = _resolve(resolved, constants)
            if updated == resolved:
                break
            resolved = updated
        return resolved

    def _artifact_relative_path(self, artifact: RepositoryArtifact) -> str:
        return self._safe_relative_path(str(artifact.relative_path or ""))

    def _safe_relative_path(self, value: str) -> str:
        raw = value or ""
        if "\\" in raw:
            return ""
        if not raw or raw.startswith("/") or "$" in raw or "`" in raw:
            return ""
        normalized = posixpath.normpath(raw)
        if normalized in {"", ".", ".."} or normalized.startswith("../"):
            return ""
        return normalized[2:] if normalized.startswith("./") else normalized

    def _normalize_installed_path(self, value: str) -> str:
        if "\x00" in value or "$" in value or "`" in value:
            return ""
        if ".." in PurePosixPath("/" + value.lstrip("/")).parts:
            return ""
        normalized = posixpath.normpath("/" + value.lstrip("/"))
        return normalized if normalized.startswith("/") else ""

    def _is_suid_mode(self, value: str) -> bool:
        normalized = (value or "").strip()
        if _SUID_NUMERIC_MODE.fullmatch(normalized):
            return True
        if _SUID_SYMBOLIC_MODE.fullmatch(normalized):
            return True
        for clause in normalized.split(","):
            parsed = re.fullmatch(
                r"(?P<who>[ugoa]*)(?P<operation>[+=-])(?P<permissions>[rwxXstugo]+)",
                clause,
                re.IGNORECASE,
            )
            if parsed is None or parsed.group("operation") == "-":
                continue
            who = parsed.group("who").lower()
            permissions = parsed.group("permissions").lower()
            if "s" in permissions and (not who or any(item in who for item in "uga")):
                return True
        return False

    def _presence_finding(
        self,
        artifact: RepositoryArtifact,
        checkout_dir: Path,
        pkg_name: str,
        pkg_ver: str,
    ) -> Finding:
        return Finding(
            rule_id="AUR-REPO-OPAQUE-ARTIFACT-001",
            package_name=pkg_name,
            package_version=pkg_ver,
            phase=Phase.pkgbuild_static,
            source=Source.deterministic_rule,
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            evidence_quality=EvidenceQuality.strong_heuristic,
            file_path=str(checkout_dir / self._artifact_relative_path(artifact)),
            explanation=(
                "An opaque executable or archive is present alongside the package checkout "
                "but is not represented by the parsed source declarations."
            ),
            recommendation=(
                "Review the artifact's provenance and expected role before building or installing."
            ),
            false_positive_notes=(
                "The artifact may be legitimate. Static presence does not prove it was committed, "
                "is malicious, or was executed."
            ),
            blocks_installation=False,
            requires_manual_review=True,
            evidence_snippet="opaque artifact is present alongside the package checkout",
            file_hash=artifact.sha256,
        )

    def _correlated_finding(
        self,
        artifact: RepositoryArtifact,
        correlation: _Correlation,
        pkg_name: str,
        pkg_ver: str,
    ) -> Finding:
        critical = correlation.rule_id == "AUR-REPO-OPAQUE-BINARY-EXEC-001"
        return Finding(
            rule_id=correlation.rule_id,
            package_name=pkg_name,
            package_version=pkg_ver,
            phase=correlation.phase,
            source=Source.deterministic_rule,
            severity=Severity.CRITICAL if critical else Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            evidence_quality=EvidenceQuality.confirmed_static_pattern,
            file_path=correlation.file_path,
            line_number=correlation.line_number,
            explanation=(
                "Package control text correlates an undeclared opaque checkout artifact with "
                + (
                    "execution or a set-user-ID/set-group-ID permission request."
                    if critical
                    else "copying or installation into the package payload."
                )
            ),
            recommendation=(
                "Do not build or install until the artifact provenance and the complete package "
                "control flow have been independently reviewed."
                if critical
                else "Review the artifact provenance and destination before accepting this package."
            ),
            false_positive_notes=(
                "Static correlation does not prove the artifact was committed, is malicious, "
                "the command ran, or execution succeeded."
            ),
            blocks_installation=critical,
            requires_manual_review=not critical,
            evidence_snippet=correlation.evidence,
            file_hash=artifact.sha256,
        )

    def _incomplete_finding(
        self,
        pkgbuild_path: str,
        pkg_name: str,
        pkg_ver: str,
        reason_code: str = "",
    ) -> Finding:
        allowed_reasons = {
            "analysis_limit",
            "artifact_limit",
            "candidate_limit",
            "command_parser_limit",
            "depth_limit",
            "directory_changed",
            "directory_unreadable",
            "elapsed_time_limit",
            "entry_limit",
            "entry_unreadable",
            "excluded_subtree_wrong_type",
            "file_changed",
            "file_oversized",
            "file_unreadable",
            "invalid_exclusion",
            "no_follow_unavailable",
            "path_too_long",
            "repository_unreadable",
            "required_path_limit",
            "required_path_ambiguous",
            "required_path_unsafe",
            "root_changed",
            "root_unavailable",
            "source_mapping_ambiguous",
            "special_entry",
            "symlink_entry",
            "total_size_limit",
            "unsafe_name",
            "unsafe_root",
        }
        safe_reason = reason_code if reason_code in allowed_reasons else ""
        evidence = "bounded package-checkout inspection did not complete"
        if safe_reason:
            evidence += ": " + safe_reason.replace("_", " ")
        return Finding(
            rule_id="AUR-REPO-INSPECTION-INCOMPLETE-001",
            package_name=pkg_name,
            package_version=pkg_ver,
            phase=Phase.pkgbuild_static,
            source=Source.deterministic_rule,
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            evidence_quality=EvidenceQuality.confirmed_static_pattern,
            file_path=pkgbuild_path,
            explanation=(
                "AuraScan could not complete bounded inspection of the package checkout and its "
                "opaque-artifact correlations."
            ),
            recommendation=(
                "Do not build or install until the complete package checkout can be captured and "
                "inspected within the configured safety bounds."
            ),
            false_positive_notes=(
                "Incomplete inspection is not evidence that the package or an artifact is malicious."
            ),
            blocks_installation=True,
            requires_manual_review=False,
            evidence_snippet=evidence,
        )
