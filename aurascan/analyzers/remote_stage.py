"""Static correlation for remote content that package logic later executes.

The analyzer deliberately models only a small, auditable shell subset.  It
never resolves paths on disk, downloads content, or evaluates shell syntax.
"""

import posixpath
import re
import shlex
import urllib.parse
from typing import Dict, List, NamedTuple, Optional, Sequence, Tuple

from aurascan.analyzers.aur_propagation import (
    _active_shell_text,
    _line_number,
    _line_starts,
    _logical_shell_views,
)


class RemoteStageSignal(NamedTuple):
    kind: str
    label: str
    line_number: int


class RemoteStageAnalysis(NamedTuple):
    """Bounded correlation result.

    ``complete`` is deliberately separate from ``signals`` so a caller never
    mistakes a parser or resource limit for a clear result.
    """

    signals: Tuple[RemoteStageSignal, ...]
    complete: bool


class CarrierExecutionAnalysis(NamedTuple):
    """Bounded correlation for local decoded or misleadingly named code."""

    signals: Tuple[RemoteStageSignal, ...]
    complete: bool


class _ShellCommand(NamedTuple):
    executable: str
    arguments: Tuple[str, ...]
    line_number: int
    pipeline_from_previous: bool = False
    assignments: Tuple[str, ...] = ()


class _Artifact(NamedTuple):
    path: str
    line_number: int
    directory: bool = False
    transformed: bool = False
    transformation_line: int = 0
    ambiguous: bool = False


_MAX_INPUT_CHARS = 5 * 1024 * 1024
_MAX_COMMANDS = 16384
_MAX_CONSTANTS = 4096
_MAX_WRAPPER_SPLIT_TOKENS = 256
_MAX_WRAPPER_SPLITS = 4
_ASSIGNMENT = re.compile(
    r"^[ \t]*(?:(?:export|local|readonly)[ \t]+)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>[^\n]+?)[ \t]*$"
)
_VARIABLE_REFERENCE = re.compile(
    r"\$(?:\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)\}|"
    r"(?P<plain>[A-Za-z_][A-Za-z0-9_]*))"
)
_SHELL_ASSIGNMENT_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=.*", re.S)
_NETWORK_URL = re.compile(r"(?:https?|ftp)://", re.IGNORECASE)
_INTERPRETERS = {
    "ash",
    "bash",
    "bun",
    "dash",
    "jsc",
    "lua",
    "luajit",
    "node",
    "nodejs",
    "perl",
    "php",
    "python",
    "python2",
    "python3",
    "qjs",
    "quickjs",
    "rscript",
    "ruby",
    "sh",
    "tclsh",
    "wish",
    "zsh",
}
_OPAQUE_CARRIER_SUFFIXES = {
    # Images and vector artwork.
    ".avif",
    ".bmp",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".png",
    ".svg",
    ".tif",
    ".tiff",
    ".webp",
    # Documents and otherwise inert text containers.
    ".doc",
    ".docx",
    ".csv",
    ".htm",
    ".html",
    ".json",
    ".md",
    ".odt",
    ".pdf",
    ".rtf",
    ".txt",
    ".xml",
    ".yaml",
    ".yml",
    # Fonts and common media containers.
    ".flac",
    ".m4a",
    ".mkv",
    ".mov",
    ".mp3",
    ".mp4",
    ".ogg",
    ".otf",
    ".ttf",
    ".wav",
    ".webm",
    ".woff",
    ".woff2",
}
_CONTROL_WORDS = {"!", "(", "{", "do", "elif", "else", "if", "then", "until", "while"}
_WRAPPERS = {"command", "exec", "time"}


def find_remote_stage_execution_signals(text: str) -> List[RemoteStageSignal]:
    """Compatibility wrapper returning only completed correlation signals."""

    return list(analyze_remote_stage_execution(text).signals)


def analyze_remote_stage_execution(text: str) -> RemoteStageAnalysis:
    """Return a bounded, artifact-aware remote-stage analysis."""

    if not text:
        return RemoteStageAnalysis((), True)
    if len(text) > _MAX_INPUT_CHARS:
        return RemoteStageAnalysis((), False)
    active = _active_shell_text(text)
    raw_view, command_view = _logical_shell_views(active)
    commands, commands_complete = _collect_commands(
        raw_view,
        command_view,
        _line_starts(text),
    )
    if not commands_complete:
        return RemoteStageAnalysis((), False)
    constants = _constant_values(active)
    artifacts: Dict[str, _Artifact] = {}
    pending_remote_stream: Optional[_Artifact] = None

    for command in commands:
        pipeline_origin = (
            pending_remote_stream if command.pipeline_from_previous else None
        )
        if not command.pipeline_from_previous:
            pending_remote_stream = None
        executable = _basename(command.executable).lower()
        if executable in {"cd", "pushd", "popd"}:
            # Relative paths are interpreted in a new directory after these
            # commands.  Keeping them would overstate artifact identity.
            artifacts = {
                path: artifact
                for path, artifact in artifacts.items()
                if path.startswith("/")
            }
            continue

        acquired = _acquired_artifact(command, constants)
        if acquired is not None:
            artifacts[acquired.path] = acquired
            continue

        remote_stream = _remote_stdout_stream(command, constants)
        if remote_stream is not None:
            pending_remote_stream = remote_stream
            continue

        if pipeline_origin is not None:
            executed_path, execution_complete = _executed_path_status(
                command,
                constants,
            )
            if executed_path:
                origin = _artifact_for_execution(executed_path, artifacts)
                if origin is not None:
                    return _remote_execution_result(
                        origin,
                        command,
                        execution_complete=execution_complete,
                    )
                # A separate script may consume the remote stream as data and
                # produce bytes for the next pipeline stage.  Its relationship
                # to those bytes is not statically provable, so retain only an
                # ambiguous stream identity.
                ambiguous = _ambiguous_stream(
                    pipeline_origin,
                    command.line_number,
                )
                output = _normalize_path(_redirect_output([
                    _resolve(value, constants) for value in command.arguments
                ]))
                _invalidate_mutated_artifacts(command, constants, artifacts)
                if output:
                    artifacts[output] = _Artifact(
                        output,
                        pipeline_origin.line_number,
                        transformed=True,
                        transformation_line=command.line_number,
                        ambiguous=True,
                    )
                    pending_remote_stream = None
                else:
                    pending_remote_stream = ambiguous
                continue
            if _interpreter_reads_pipeline_stdin(
                command,
                constants,
                execution_complete=execution_complete,
            ):
                # There is no concrete local artifact in a direct pipeline.
                # Fail closed as incomplete instead of claiming the artifact-
                # bound malware correlation succeeded.
                return RemoteStageAnalysis((), False)

            pipeline_artifacts, pending_remote_stream = _pipeline_effect(
                command,
                constants,
                pipeline_origin,
            )
            _invalidate_mutated_artifacts(command, constants, artifacts)
            for artifact in pipeline_artifacts:
                artifacts[artifact.path] = artifact
            continue

        transformed = _transformed_artifact(command, constants, artifacts)
        if transformed is not None:
            artifacts[transformed.path] = transformed
            if executable == "mv":
                source_path = _mutation_source_path(command, constants)
                if source_path:
                    artifacts.pop(source_path, None)
            continue

        _invalidate_mutated_artifacts(command, constants, artifacts)

        executed_path, execution_complete = _executed_path_status(command, constants)
        if not executed_path:
            if not execution_complete and _interpreter_arguments_reference_artifacts(
                command,
                constants,
                artifacts,
            ):
                return RemoteStageAnalysis((), False)
            continue
        origin = _artifact_for_execution(executed_path, artifacts)
        if origin is None:
            continue
        return _remote_execution_result(
            origin,
            command,
            execution_complete=execution_complete,
        )
    return RemoteStageAnalysis((), True)


def analyze_carrier_execution(text: str) -> CarrierExecutionAnalysis:
    """Find active local carrier-to-code execution chains.

    This deliberately does not inspect, decode, render, or infer the bytes in a
    named carrier.  It only correlates active shell commands in the same text:
    either a bounded decode-to-file followed by execution of that exact file,
    or direct execution of a path whose suffix normally denotes media,
    documentation, or a font.
    """

    parsed = _commands_and_constants(text)
    if parsed is None:
        return CarrierExecutionAnalysis((), False)
    commands, constants = parsed
    decoded: Dict[str, _Artifact] = {}

    for command in commands:
        executable = _basename(command.executable).lower()
        if executable in {"cd", "pushd", "popd"}:
            decoded = {
                path: artifact
                for path, artifact in decoded.items()
                if path.startswith("/")
            }
            continue

        derived = _local_decoded_artifact(command, constants)
        if derived is not None:
            decoded[derived.path] = derived
            continue

        transformed = _transformed_artifact(command, constants, decoded)
        if transformed is not None:
            decoded[transformed.path] = transformed
            if executable == "mv":
                source_path = _mutation_source_path(command, constants)
                if source_path:
                    decoded.pop(source_path, None)
            continue

        _invalidate_mutated_artifacts(command, constants, decoded)

        executed_path, execution_complete = _carrier_executed_path_status(
            command,
            constants,
        )
        if not execution_complete and _interpreter_arguments_reference_carrier(
            command,
            constants,
            decoded,
        ):
            return CarrierExecutionAnalysis((), False)
        if not executed_path:
            continue
        origin = _artifact_for_execution(executed_path, decoded)
        if origin is not None:
            if origin.ambiguous or not execution_complete:
                return CarrierExecutionAnalysis((), False)
            return CarrierExecutionAnalysis((
                RemoteStageSignal(
                    "carrier_decode",
                    "local content is decoded into a separate artifact",
                    origin.transformation_line or origin.line_number,
                ),
                RemoteStageSignal(
                    "carrier_execution",
                    "the decoded artifact is subsequently executed",
                    command.line_number,
                ),
            ), True)
        if _has_opaque_carrier_suffix(executed_path):
            if not execution_complete:
                return CarrierExecutionAnalysis((), False)
            return CarrierExecutionAnalysis((
                RemoteStageSignal(
                    "opaque_carrier",
                    "a media, document, or font-named artifact is supplied for execution",
                    command.line_number,
                ),
                RemoteStageSignal(
                    "carrier_execution",
                    "the carrier-named artifact is invoked as code",
                    command.line_number,
                ),
            ), True)

    return CarrierExecutionAnalysis((), True)


def _commands_and_constants(
    text: str,
) -> Optional[Tuple[List[_ShellCommand], Dict[str, str]]]:
    if not text:
        return ([], {})
    if len(text) > _MAX_INPUT_CHARS:
        return None
    active = _active_shell_text(text)
    raw_view, command_view = _logical_shell_views(active)
    commands, complete = _collect_commands(
        raw_view,
        command_view,
        _line_starts(text),
    )
    if not complete:
        return None
    return commands, _constant_values(active)


def _collect_commands(
    raw_view: str,
    command_view: str,
    line_starts: Sequence[int],
) -> Tuple[List[_ShellCommand], bool]:
    start = 0
    commands: List[_ShellCommand] = []
    segment_count = 0
    pipeline_from_previous = False

    def collect_segment(end: int) -> bool:
        nonlocal start, segment_count, pipeline_from_previous
        segment_count += 1
        if segment_count > _MAX_COMMANDS * 4:
            return False
        segment = raw_view[start:end]
        parsed, malformed = _parse_command(segment)
        if malformed:
            return False
        if parsed is not None:
            executable, arguments, relative_offset, assignments = parsed
            commands.append(_ShellCommand(
                executable,
                tuple(arguments),
                _line_number(line_starts, start + relative_offset),
                pipeline_from_previous,
                tuple(assignments),
            ))
            if len(commands) > _MAX_COMMANDS:
                return False
        return True

    for boundary in re.finditer(r"\$\(|\x1f|[;|&)]+", command_view):
        if not collect_segment(boundary.start()):
            return [], False
        pipeline_from_previous = boundary.group(0) in {"|", "|&"}
        start = boundary.end()
    if not collect_segment(len(raw_view)):
        return [], False
    return commands, True


def _parse_command(
    segment: str,
) -> Tuple[Optional[Tuple[str, List[str], int, List[str]]], bool]:
    try:
        tokens = shlex.split(segment, comments=False, posix=True)
    except ValueError:
        return None, bool(segment.strip())
    tokens = _split_attached_input_redirections(tokens)
    if not tokens:
        return None, False
    index = 0
    assignments: List[str] = []
    while index < len(tokens) and tokens[index] in _CONTROL_WORDS:
        index += 1
    while index < len(tokens) and _SHELL_ASSIGNMENT_TOKEN.fullmatch(tokens[index]):
        assignments.append(tokens[index])
        index += 1
    wrapper_splits = 0
    while index < len(tokens):
        token = _basename(tokens[index])
        if token == "exec":
            index += 1
            while index < len(tokens):
                value = tokens[index]
                if value == "--":
                    index += 1
                    break
                if value == "-a":
                    if index + 1 >= len(tokens):
                        return None, False
                    index += 2
                    continue
                if value in {"-c", "-l"} or (
                    value.startswith("-")
                    and value != "-"
                    and set(value[1:]) <= {"c", "l"}
                ):
                    index += 1
                    continue
                if value.startswith("-"):
                    # Unknown option arity cannot prove a wrapped executable.
                    return None, True
                break
            continue
        if token == "command":
            index += 1
            query_only = False
            while index < len(tokens):
                value = tokens[index]
                if value == "--":
                    index += 1
                    break
                if re.fullmatch(r"-[pVv]+", value):
                    query_only = query_only or "v" in value or "V" in value
                    index += 1
                    continue
                if value.startswith("-"):
                    # Unsupported builtin options cannot establish an
                    # executable operand.  Bash rejects them before running
                    # any following path, so this is a complete inert command.
                    return None, False
                break
            if query_only:
                # ``command -v`` and ``command -V`` query command lookup; the
                # following token is data, never an executed command.
                return None, False
            continue
        if token == "time":
            index += 1
            while index < len(tokens):
                value = tokens[index]
                if value == "--":
                    index += 1
                    break
                if value in {"-o", "--output", "-f", "--format"}:
                    if index + 1 >= len(tokens):
                        return None, False
                    index += 2
                    continue
                if value.startswith(("--output=", "--format=")) or (
                    value.startswith(("-o", "-f"))
                    and value not in {"-o", "-f"}
                ):
                    index += 1
                    continue
                if value in {
                    "-a", "--append", "-p", "--portability", "-q", "--quiet",
                    "-v", "--verbose", "-V", "--version", "--help",
                }:
                    index += 1
                    continue
                if value.startswith("-"):
                    return None, True
                break
            continue
        if token in _WRAPPERS:
            index += 1
            while index < len(tokens) and tokens[index].startswith("-"):
                index += 1
            continue
        if token == "env":
            index += 1
            while index < len(tokens):
                value = tokens[index]
                if _SHELL_ASSIGNMENT_TOKEN.fullmatch(value):
                    assignments.append(value)
                    index += 1
                    continue
                if value in {"-S", "--split-string"}:
                    if index + 1 >= len(tokens):
                        return None, True
                    split_tokens = _bounded_env_split_tokens(tokens[index + 1])
                    if split_tokens is None or wrapper_splits >= _MAX_WRAPPER_SPLITS:
                        return None, True
                    tokens[index : index + 2] = split_tokens
                    wrapper_splits += 1
                    continue
                if value.startswith("--split-string="):
                    split_tokens = _bounded_env_split_tokens(value.split("=", 1)[1])
                    if split_tokens is None or wrapper_splits >= _MAX_WRAPPER_SPLITS:
                        return None, True
                    tokens[index : index + 1] = split_tokens
                    wrapper_splits += 1
                    continue
                if value in {
                    "-C", "--chdir", "-u", "--unset", "-a", "--argv0",
                }:
                    if index + 1 >= len(tokens):
                        return None, True
                    index += 2
                    continue
                if value.startswith(("--chdir=", "--unset=", "--argv0=")):
                    index += 1
                    continue
                if value.startswith("-"):
                    index += 1
                    continue
                break
            continue
        break
    if index >= len(tokens):
        return None, False
    executable = tokens[index]
    relative = segment.find(executable)
    return (
        executable,
        tokens[index + 1 :],
        max(0, relative),
        assignments,
    ), False


def _bounded_env_split_tokens(value: str) -> Optional[List[str]]:
    """Parse one literal GNU ``env -S`` value without shell expansion."""

    if not value or len(value) > _MAX_INPUT_CHARS or "`" in value or "$(" in value:
        return None
    scrubbed = _VARIABLE_REFERENCE.sub(
        lambda match: "" if (match.group("braced") or match.group("plain")) in {
            "PWD", "pkgbuilddir", "pkgdir", "srcdir", "startdir",
        } else "$",
        value,
    )
    if "$" in scrubbed:
        return None
    try:
        split_tokens = shlex.split(value, comments=False, posix=True)
    except ValueError:
        return None
    if not split_tokens or len(split_tokens) > _MAX_WRAPPER_SPLIT_TOKENS:
        return None
    return split_tokens


def _split_attached_input_redirections(tokens: Sequence[str]) -> List[str]:
    """Split ordinary ``command<input`` spelling without evaluating shell."""

    result: List[str] = []
    for token in tokens:
        marker = token.find("<")
        if marker < 0 or token.startswith("<<", marker):
            result.append(token)
            continue
        head = token[:marker]
        tail = token[marker + 1:]
        if not tail:
            result.append(token)
            continue
        if head == "0":
            result.extend(("0<", tail))
        else:
            if head:
                result.append(head)
            result.extend(("<", tail))
    return result


def _constant_values(text: str) -> Dict[str, str]:
    counts: Dict[str, int] = {}
    values: Dict[str, str] = {}
    for line in text.splitlines():
        match = _ASSIGNMENT.match(line)
        if match is None:
            continue
        name = match.group("name")
        counts[name] = counts.get(name, 0) + 1
        if len(counts) > _MAX_CONSTANTS:
            return {}
        raw = match.group("value").strip()
        if any(marker in raw for marker in ("$(", "`", ";", "\n")):
            continue
        try:
            parsed = shlex.split(raw, comments=False, posix=True)
        except ValueError:
            continue
        if len(parsed) == 1 and len(parsed[0]) <= 4096:
            values[name] = parsed[0]
    return {name: value for name, value in values.items() if counts.get(name) == 1}


def _resolve(token: str, constants: Dict[str, str]) -> str:
    """Resolve bounded, simple constant references inside one shell token."""

    if not token or len(token) > 8192:
        return token
    output: List[str] = []
    cursor = 0
    size = 0
    for match in _VARIABLE_REFERENCE.finditer(token):
        literal = token[cursor:match.start()]
        name = match.group("braced") or match.group("plain") or ""
        replacement = constants.get(name, match.group(0))
        size += len(literal) + len(replacement)
        if size > 8192:
            return token
        output.extend((literal, replacement))
        cursor = match.end()
    suffix = token[cursor:]
    if size + len(suffix) > 8192:
        return token
    output.append(suffix)
    return "".join(output)


def _remote_stdout_stream(
    command: _ShellCommand,
    constants: Dict[str, str],
) -> Optional[_Artifact]:
    """Return the origin of a supported network command writing bytes to stdout."""

    executable = _basename(command.executable).lower()
    if executable not in {"curl", "wget"}:
        return None
    arguments = [_resolve(value, constants) for value in command.arguments]
    if not any(_NETWORK_URL.search(value) for value in arguments):
        return None
    output = _download_output(executable, arguments)
    if executable == "curl" and not output:
        return _Artifact("", command.line_number)
    if executable == "wget" and output == "-":
        return _Artifact("", command.line_number)
    return None


def _pipeline_output_artifacts(
    command: _ShellCommand,
    constants: Dict[str, str],
    origin: _Artifact,
) -> List[_Artifact]:
    """Bind supported remote pipeline writers to concrete local artifacts."""

    executable = _basename(command.executable).lower()
    arguments = [_resolve(value, constants) for value in command.arguments]
    if executable == "tee":
        artifacts: List[_Artifact] = []
        after_terminator = False
        for value in _arguments_without_redirections(arguments):
            if value == "--":
                after_terminator = True
                continue
            if not after_terminator and value.startswith("-"):
                continue
            path = _normalize_path(value)
            if path:
                artifacts.append(_Artifact(
                    path,
                    origin.line_number,
                    transformed=origin.transformed,
                    transformation_line=origin.transformation_line,
                    ambiguous=origin.ambiguous,
                ))
        return artifacts

    derived = _local_decoded_artifact(command, constants)
    if derived is not None:
        return [
            _Artifact(
                derived.path,
                origin.line_number,
                transformed=True,
                transformation_line=command.line_number,
                ambiguous=origin.ambiguous,
            )
        ]

    if executable == "cat":
        output = _normalize_path(_redirect_output(arguments))
        if output:
            return [_Artifact(
                output,
                origin.line_number,
                transformed=origin.transformed,
                transformation_line=origin.transformation_line,
                ambiguous=origin.ambiguous,
            )]
    return []


def _pipeline_effect(
    command: _ShellCommand,
    constants: Dict[str, str],
    origin: _Artifact,
) -> Tuple[List[_Artifact], Optional[_Artifact]]:
    """Carry bounded remote provenance through one pipeline command."""

    executable = _basename(command.executable).lower()
    arguments = [_resolve(value, constants) for value in command.arguments]
    artifacts = _pipeline_output_artifacts(command, constants, origin)
    redirected = bool(_normalize_path(_redirect_output(arguments)))

    if executable == "tee":
        outgoing = None if redirected else origin
        return artifacts, outgoing

    if executable == "cat":
        if not _cat_reads_stdin(arguments):
            return [], None
        outgoing = None if redirected else origin
        return artifacts, outgoing

    if executable == "tr":
        transformed = _derived_stream(origin, command.line_number)
        if redirected:
            output = _normalize_path(_redirect_output(arguments))
            return ([
                _Artifact(
                    output,
                    origin.line_number,
                    transformed=True,
                    transformation_line=command.line_number,
                    ambiguous=origin.ambiguous,
                )
            ] if output else []), None
        return [], transformed

    if _is_stream_decoder(executable, arguments):
        transformed = _derived_stream(origin, command.line_number)
        return artifacts, None if redirected else transformed

    # An unmodeled command can ignore, transform, or replace its stdin.  Keep
    # that uncertainty bound to its concrete output/next pipeline edge so a
    # later execution fails incomplete instead of false-clearing or becoming a
    # confirmed malware claim.
    ambiguous = _ambiguous_stream(origin, command.line_number)
    output = _normalize_path(_redirect_output(arguments))
    if output:
        return [
            _Artifact(
                output,
                origin.line_number,
                transformed=True,
                transformation_line=command.line_number,
                ambiguous=True,
            )
        ], None
    return [], ambiguous


def _cat_reads_stdin(arguments: Sequence[str]) -> bool:
    stdin_names = {"-", "/dev/fd/0", "/dev/stdin", "/proc/self/fd/0"}
    values = [
        value
        for value in _arguments_without_redirections(arguments)
        if not value.startswith("-")
    ]
    return not values or any(value in stdin_names for value in arguments)


def _arguments_without_redirections(arguments: Sequence[str]) -> List[str]:
    values: List[str] = []
    skip_next = False
    for value in arguments:
        if skip_next:
            skip_next = False
            continue
        if value in {">", "1>"}:
            skip_next = True
            continue
        if value.startswith((">", "1>")):
            continue
        values.append(value)
    return values


def _is_stream_decoder(executable: str, arguments: Sequence[str]) -> bool:
    if executable == "base64":
        return any(value in {"-d", "--decode"} for value in arguments)
    if executable == "xxd":
        return any(value == "-r" or value.startswith("-r") for value in arguments)
    return bool(
        executable == "openssl"
        and arguments
        and arguments[0] in {"enc", "base64"}
        and any(value in {"-d", "-decode"} for value in arguments[1:])
    )


def _derived_stream(origin: _Artifact, line_number: int) -> _Artifact:
    return _Artifact(
        "",
        origin.line_number,
        transformed=True,
        transformation_line=origin.transformation_line or line_number,
        ambiguous=origin.ambiguous,
    )


def _ambiguous_stream(origin: _Artifact, line_number: int) -> _Artifact:
    return _Artifact(
        "",
        origin.line_number,
        transformed=True,
        transformation_line=origin.transformation_line or line_number,
        ambiguous=True,
    )


def _remote_execution_result(
    origin: _Artifact,
    command: _ShellCommand,
    *,
    execution_complete: bool,
) -> RemoteStageAnalysis:
    if origin.ambiguous or not execution_complete:
        return RemoteStageAnalysis((), False)
    signals = [
        RemoteStageSignal(
            "remote_acquisition",
            "remote content is written to a local artifact",
            origin.line_number,
        )
    ]
    if origin.transformed:
        signals.append(
            RemoteStageSignal(
                "carrier_transform",
                "downloaded content is decoded or copied into another artifact",
                origin.transformation_line or command.line_number,
            )
        )
    signals.append(
        RemoteStageSignal(
            "artifact_execution",
            "the acquired artifact or its derived content is executed",
            command.line_number,
        )
    )
    return RemoteStageAnalysis(tuple(signals), True)


def _acquired_artifact(
    command: _ShellCommand,
    constants: Dict[str, str],
) -> Optional[_Artifact]:
    executable = _basename(command.executable).lower()
    arguments = [_resolve(value, constants) for value in command.arguments]
    if executable in {"curl", "wget"}:
        if not any(_NETWORK_URL.search(value) for value in arguments):
            return None
        output = _download_output(executable, arguments)
        normalized = _normalize_path(output)
        return _Artifact(normalized, command.line_number) if normalized else None
    if executable == "git":
        clone = _git_clone_destination(arguments)
        if clone:
            return _Artifact(clone, command.line_number, directory=True)
    return None


def _download_output(executable: str, arguments: Sequence[str]) -> str:
    option_names = {"-o", "--output"} if executable == "curl" else {"-O", "--output-document"}
    remote_name = False
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if token in option_names and index + 1 < len(arguments):
            return arguments[index + 1]
        for option in option_names:
            if token.startswith(option + "="):
                return token.split("=", 1)[1]
        if executable == "curl" and token.startswith("-o") and len(token) > 2:
            return token[2:]
        if executable == "wget" and token.startswith("-O") and len(token) > 2:
            return token[2:]
        if executable == "curl" and token in {"-O", "--remote-name"}:
            remote_name = True
        if token in {">", "1>"} and index + 1 < len(arguments):
            return arguments[index + 1]
        if token.startswith(">") and len(token) > 1:
            return token.lstrip(">")
        index += 1
    if executable == "wget" or remote_name:
        urls = [value for value in arguments if _NETWORK_URL.search(value)]
        if urls:
            return posixpath.basename(urllib.parse.urlsplit(urls[-1]).path)
    return ""


def _git_clone_destination(arguments: Sequence[str]) -> str:
    index = 0
    while index < len(arguments) and arguments[index].startswith("-"):
        option = arguments[index]
        if option in {"-C", "-c", "--git-dir", "--work-tree"}:
            index += 2
        else:
            index += 1
    if index >= len(arguments) or arguments[index].lower() != "clone":
        return ""
    values: List[str] = []
    index += 1
    options_with_value = {
        "-b", "-j", "-o", "-u", "--branch", "--depth", "--filter", "--jobs",
        "--origin", "--reference", "--reference-if-able", "--server-option",
        "--template", "--upload-pack",
    }
    while index < len(arguments):
        token = arguments[index]
        if token in options_with_value:
            index += 2
            continue
        if any(token.startswith(option + "=") for option in options_with_value if option.startswith("--")):
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        values.append(token)
        index += 1
    if not values or not _looks_like_remote(values[0]):
        return ""
    destination = values[1] if len(values) > 1 else posixpath.basename(
        urllib.parse.urlsplit(values[0].replace("git+", "", 1)).path.rstrip("/")
    )
    if destination.endswith(".git"):
        destination = destination[:-4]
    return _normalize_path(destination)


def _looks_like_remote(value: str) -> bool:
    return bool(
        re.match(r"(?:git\+)?https?://|ssh://|git://|[^/@\s]+@[^:\s]+:", value, re.I)
    )


def _transformed_artifact(
    command: _ShellCommand,
    constants: Dict[str, str],
    artifacts: Dict[str, _Artifact],
) -> Optional[_Artifact]:
    executable = _basename(command.executable).lower()
    arguments = [_resolve(value, constants) for value in command.arguments]
    source = ""
    output = ""
    if executable == "base64" and any(value in {"-d", "--decode"} for value in arguments):
        source = _first_positional(arguments, {"-d", "--decode", "-i", "--ignore-garbage", "-w", "--wrap"})
        output = _redirect_output(arguments)
    elif executable == "xxd" and any(value == "-r" or value.startswith("-r") for value in arguments):
        values = [value for value in arguments if not value.startswith("-")]
        if len(values) >= 2:
            source, output = values[-2], values[-1]
        elif values:
            source, output = values[-1], _redirect_output(arguments)
    elif executable == "openssl" and arguments and arguments[0] in {"enc", "base64"}:
        source = _option_value(arguments, "-in")
        output = _option_value(arguments, "-out") or _redirect_output(arguments)
    elif executable in {"cp", "mv"}:
        values = [value for value in arguments if not value.startswith("-")]
        if len(values) >= 2:
            source, output = values[-2], values[-1]
    source_path = _normalize_path(source)
    output_path = _normalize_path(output)
    origin = _artifact_for_execution(source_path, artifacts)
    if origin is None or not output_path:
        return None
    return _Artifact(
        output_path,
        origin.line_number,
        transformed=True,
        transformation_line=command.line_number,
        ambiguous=origin.ambiguous,
    )


def _local_decoded_artifact(
    command: _ShellCommand,
    constants: Dict[str, str],
) -> Optional[_Artifact]:
    """Return an exact output path for a supported active decode command."""

    executable = _basename(command.executable).lower()
    arguments = [_resolve(value, constants) for value in command.arguments]
    output = ""
    if executable == "base64" and any(
        value in {"-d", "--decode"} for value in arguments
    ):
        output = _redirect_output(arguments)
    elif executable == "xxd" and any(
        value == "-r" or value.startswith("-r") for value in arguments
    ):
        values = [
            value for value in arguments
            if not value.startswith("-") and value not in {"<", ">", "1>"}
        ]
        output = values[-1] if len(values) >= 2 else _redirect_output(arguments)
    elif (
        executable == "openssl"
        and arguments
        and arguments[0] in {"enc", "base64"}
        and any(value in {"-d", "-decode"} for value in arguments[1:])
    ):
        output = _option_value(arguments, "-out") or _redirect_output(arguments)
    output_path = _normalize_path(output)
    if not output_path:
        return None
    return _Artifact(
        output_path,
        command.line_number,
        transformed=True,
        transformation_line=command.line_number,
    )


def _mutation_source_path(
    command: _ShellCommand,
    constants: Dict[str, str],
) -> str:
    arguments = [_resolve(value, constants) for value in command.arguments]
    values = [value for value in arguments if not value.startswith("-")]
    return _normalize_path(values[-2]) if len(values) >= 2 else ""


def _invalidate_mutated_artifacts(
    command: _ShellCommand,
    constants: Dict[str, str],
    artifacts: Dict[str, _Artifact],
) -> None:
    """Forget tracked bytes when a command definitely replaces/removes them."""

    executable = _basename(command.executable).lower()
    arguments = [_resolve(value, constants) for value in command.arguments]
    mutated: List[Tuple[str, bool]] = []

    redirected = _redirect_output(arguments)
    if redirected:
        mutated.append((_normalize_path(redirected), False))

    values = [value for value in arguments if not value.startswith("-")]
    if executable in {"cp", "install"} and len(values) >= 2:
        mutated.append((_normalize_path(values[-1]), False))
    elif executable == "mv" and len(values) >= 2:
        mutated.append((_normalize_path(values[-1]), False))
        mutated.append((_normalize_path(values[-2]), False))
    elif executable in {"rm", "unlink", "rmdir"}:
        mutated.extend((_normalize_path(value), True) for value in values)
    elif executable in {"touch", "truncate"}:
        mutated.extend((_normalize_path(value), False) for value in values)
    elif executable == "tee":
        mutated.extend((_normalize_path(value), False) for value in values)
    elif executable == "dd":
        for value in arguments:
            if value.startswith("of="):
                mutated.append((_normalize_path(value.split("=", 1)[1]), False))
    elif executable in {"sed", "perl"} and any(
        value == "-i" or value.startswith("-i") for value in arguments
    ):
        mutated.extend((_normalize_path(value), False) for value in values)

    for path, recursive in mutated:
        if not path:
            continue
        artifacts.pop(path, None)
        if recursive:
            prefix = path.rstrip("/") + "/"
            for candidate in list(artifacts):
                if candidate.startswith(prefix):
                    artifacts.pop(candidate, None)


def _executed_path(command: _ShellCommand, constants: Dict[str, str]) -> str:
    return _executed_path_status(command, constants)[0]


def _executed_path_status(
    command: _ShellCommand,
    constants: Dict[str, str],
) -> Tuple[str, bool]:
    executable = _basename(command.executable).lower()
    arguments = [_resolve(value, constants) for value in command.arguments]
    if _is_script_interpreter(executable):
        return _interpreter_script_path(executable, arguments)
    if executable == "source" or command.executable == ".":
        return _normalize_path(_first_positional(arguments, set())), True
    resolved_executable = _resolve(command.executable, constants)
    if _looks_like_local_execution(resolved_executable):
        return _normalize_path(resolved_executable), True
    return "", True


def _interpreter_script_path(
    executable: str,
    arguments: Sequence[str],
) -> Tuple[str, bool]:
    if re.fullmatch(r"python(?:\d+(?:\.\d+)*)?", executable):
        return _python_script_path(arguments)
    if any(value in {"-c", "-e", "-m"} for value in arguments):
        return "", True
    positional = _normalize_path(
        _first_positional(arguments, {"-u", "--", "-B", "-E", "-s", "-S"})
    )
    return positional or _normalize_path(_redirect_input(arguments)), True


def _python_script_path(arguments: Sequence[str]) -> Tuple[str, bool]:
    """Resolve Python's code input while accounting for option operands."""

    complete = True
    index = 0
    no_value_options = {
        "-b", "-B", "-d", "-E", "-h", "--help", "-i", "-I", "-O", "-OO",
        "-P", "-q", "-s", "-S", "-u", "-v", "-V", "--version", "-x",
    }
    while index < len(arguments):
        value = arguments[index]
        if value in {"<", "0<"} or value.startswith(("<", "0<")):
            break
        if value in {">", "1>"} or value.startswith((">", "1>")):
            break
        if value == "--":
            index += 1
            if index >= len(arguments) or arguments[index] == "-":
                break
            return _normalize_path(arguments[index]), complete
        if value in {"-c", "-m"} or value.startswith(("-c", "-m")):
            return "", True
        if value in {"-W", "-X", "--check-hash-based-pycs"}:
            if index + 1 >= len(arguments):
                return "", False
            index += 2
            continue
        if value.startswith(("-W", "-X", "--check-hash-based-pycs=")):
            index += 1
            continue
        if value in no_value_options:
            index += 1
            continue
        if value == "-":
            break
        if value.startswith("-"):
            # Unknown option arity: keep parsing, but a later carrier match can
            # establish only incomplete inspection, never a confirmed chain.
            complete = False
            index += 1
            continue
        return _normalize_path(value), complete
    return _normalize_path(_redirect_input(arguments)), complete


def _interpreter_reads_pipeline_stdin(
    command: _ShellCommand,
    constants: Dict[str, str],
    *,
    execution_complete: bool,
) -> bool:
    executable = _basename(command.executable).lower()
    if not _is_script_interpreter(executable):
        return False
    arguments = [_resolve(value, constants) for value in command.arguments]
    if any(value in {"-h", "--help", "-v", "-V", "--version"} for value in arguments):
        return False
    if any(
        value in {"-c", "-e", "-m"}
        or value.startswith(("-c", "-e", "-m"))
        for value in arguments
    ):
        return False
    path, _complete = _interpreter_script_path(executable, arguments)
    if path:
        return False
    # A bare interpreter, ``-``/``-s`` form, or ambiguous option stream can
    # consume the inherited pipeline as program text.
    return execution_complete or bool(arguments)


def _carrier_executed_path(
    command: _ShellCommand,
    constants: Dict[str, str],
) -> str:
    return _carrier_executed_path_status(command, constants)[0]


def _carrier_executed_path_status(
    command: _ShellCommand,
    constants: Dict[str, str],
) -> Tuple[str, bool]:
    executed, complete = _executed_path_status(command, constants)
    if executed:
        return executed, complete
    resolved_executable = _resolve(command.executable, constants)
    if _has_opaque_carrier_suffix(resolved_executable):
        return _normalize_path(resolved_executable), complete
    return "", complete


def _interpreter_argument_paths(
    command: _ShellCommand,
    constants: Dict[str, str],
) -> List[str]:
    executable = _basename(command.executable).lower()
    if not _is_script_interpreter(executable):
        return []
    result: List[str] = []
    arguments = [_resolve(item, constants) for item in command.arguments]
    for value in arguments:
        if value in {"<", "0<", ">", "1>"} or value.startswith(("<", "0<", ">", "1>")):
            continue
        path = _normalize_path(value)
        if path:
            result.append(path)
    redirected = _normalize_path(_redirect_input(arguments))
    if redirected:
        result.append(redirected)
    return result


def _interpreter_arguments_reference_artifacts(
    command: _ShellCommand,
    constants: Dict[str, str],
    artifacts: Dict[str, _Artifact],
) -> bool:
    return any(
        _artifact_for_execution(path, artifacts) is not None
        for path in _interpreter_argument_paths(command, constants)
    )


def _interpreter_arguments_reference_carrier(
    command: _ShellCommand,
    constants: Dict[str, str],
    artifacts: Dict[str, _Artifact],
) -> bool:
    for path in _interpreter_argument_paths(command, constants):
        if _artifact_for_execution(path, artifacts) is not None:
            return True
        if _has_opaque_carrier_suffix(path):
            return True
    return False


def _has_opaque_carrier_suffix(path: str) -> bool:
    lowered = path.lower().rstrip("/")
    return any(lowered.endswith(suffix) for suffix in _OPAQUE_CARRIER_SUFFIXES)


def _artifact_for_execution(
    path: str,
    artifacts: Dict[str, _Artifact],
) -> Optional[_Artifact]:
    if not path:
        return None
    exact = artifacts.get(path)
    if exact is not None:
        return exact
    for artifact in artifacts.values():
        if artifact.directory and path.startswith(artifact.path.rstrip("/") + "/"):
            return artifact
    return None


def _first_positional(arguments: Sequence[str], flags_without_value: set) -> str:
    skip_next = False
    for value in arguments:
        if skip_next:
            skip_next = False
            continue
        if value in {"-w", "--wrap"}:
            skip_next = True
            continue
        if value == "--":
            continue
        if value in flags_without_value or value.startswith("-"):
            continue
        if value in {"<", "0<"} or value.startswith(("<", "0<")):
            break
        if value in {">", "1>"} or value.startswith(">"):
            break
        return value
    return ""


def _redirect_input(arguments: Sequence[str]) -> str:
    for index, value in enumerate(arguments):
        if value in {"<", "0<"} and index + 1 < len(arguments):
            return arguments[index + 1]
        if value.startswith("0<") and len(value) > 2 and not value.startswith("0<<"):
            return value[2:]
        if value.startswith("<") and len(value) > 1 and not value.startswith("<<"):
            return value[1:]
    return ""


def _redirect_output(arguments: Sequence[str]) -> str:
    for index, value in enumerate(arguments):
        if value in {">", "1>"} and index + 1 < len(arguments):
            return arguments[index + 1]
        if value.startswith(">") and len(value) > 1:
            return value.lstrip(">")
        if value.startswith("1>") and len(value) > 2:
            return value[2:]
        # ``shlex`` does not split punctuation by default, so retain support
        # for ordinary shell spelling such as ``input.b64>stage``.  Do not
        # mistake stderr redirection for the decoded stdout artifact.
        match = re.search(r">(?!>)([^>]+)\Z", value)
        if match is not None:
            descriptor = value[:match.start()]
            if descriptor.isdigit() and descriptor != "1":
                continue
            return match.group(1)
    return ""


def _option_value(arguments: Sequence[str], option: str) -> str:
    for index, value in enumerate(arguments):
        if value == option and index + 1 < len(arguments):
            return arguments[index + 1]
        if value.startswith(option + "="):
            return value.split("=", 1)[1]
    return ""


def _normalize_path(value: str) -> str:
    raw = (value or "").strip()
    if not raw or raw in {"-", "/", ".", ".."} or "$" in raw or "`" in raw:
        return ""
    normalized = posixpath.normpath(raw)
    if normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def _looks_like_local_execution(value: str) -> bool:
    return value.startswith(("./", "../", "/", "$"))


def _is_script_interpreter(executable: str) -> bool:
    if executable in _INTERPRETERS:
        return True
    return bool(
        re.fullmatch(
            r"(?:lua|php|python|ruby|tclsh|wish)(?:\d+(?:\.\d+)*)?",
            executable,
        )
    )


def _basename(value: str) -> str:
    return posixpath.basename(value or "")
