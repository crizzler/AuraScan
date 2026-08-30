"""Static correlation for package code that propagates into AUR repositories."""

import re
import shlex
from bisect import bisect_right
from typing import Dict, List, NamedTuple, Optional, Sequence, Set, Tuple

from aurascan.analyzers.remote_access import mask_shell_quoted_text, shell_command_pattern


class AurPropagationSignal(NamedTuple):
    kind: str
    label: str
    line_number: int


class _GitCommand(NamedTuple):
    subcommand: str
    arguments: Tuple[str, ...]
    context: Tuple[str, ...]
    line_number: int


_COMMAND_BOUNDARY = (
    r"(?:^|[;&|]|\$\(|\x1f)\s*"
    r"(?:(?:!|\{|\()\s*|(?:if|then|elif|while|until|do|else)\b\s+)*"
    r"(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*"
)
_ENV_WRAPPER = (
    r"(?:/(?:usr/)?bin/)?env"
    r"(?:\s+(?:(?:-u|--unset|-C|--chdir|-S|--split-string)\s+\S+|"
    r"--?[A-Za-z0-9][^\s]*|[A-Za-z_][A-Za-z0-9_]*=\S*))*\s+"
)
_COMMAND_WRAPPER = r"command(?:\s+(?:--|-p))*\s+"
_EXEC_WRAPPER = r"exec(?:\s+(?:(?:-a)\s+\S+|--|-c|-l))*\s+"
_TIME_WRAPPER = r"time(?:\s+(?:--|-p))*\s+"
_GIT_COMMAND = re.compile(
    _COMMAND_BOUNDARY
    + r"(?:"
    + _ENV_WRAPPER
    + r"|"
    + _COMMAND_WRAPPER
    + r"|"
    + _EXEC_WRAPPER
    + r"|"
    + _TIME_WRAPPER
    + r")*"
    + r"(?:/(?:usr/)?s?bin/)?git(?=\s|$)",
    re.IGNORECASE,
)
_FIND_COMMAND = shell_command_pattern("find", "fd", "fdfind")
_SSH_KEY_COMMAND = shell_command_pattern("ssh-add", "ssh-agent", "ssh-keygen")
_AUR_GIT_ENDPOINT = re.compile(
    r"(?:"
    r"ssh://aur@aur\.archlinux\.org(?::(?P<port>[0-9]{1,5}))?/[A-Za-z0-9@._+%-]+\.git"
    r"|https://aur\.archlinux\.org/[A-Za-z0-9@._+%-]+\.git"
    r"|aur@aur\.archlinux\.org:[A-Za-z0-9@._+%-]+\.git"
    r")\Z",
    re.IGNORECASE,
)
_CONSTANT_ASSIGNMENT = re.compile(
    r"^[ \t]*(?:(?:export|local|readonly)[ \t]+)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>[^\n]+?)[ \t]*$"
)
_ARRAY_ASSIGNMENT = re.compile(r"(?<![A-Za-z0-9_])(?:[A-Za-z_][A-Za-z0-9_]*)\+?=\(")
_VARIABLE_TOKEN = re.compile(
    r"\$(?:\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)\}|"
    r"(?P<plain>[A-Za-z_][A-Za-z0-9_]*))\Z"
)
_REMOTE_CONFIG_KEY = re.compile(r"remote\.(?P<name>.+)\.(?:url|pushurl)\Z", re.IGNORECASE)
_LOOP_START = re.compile(r"(?:^|[;{}])\s*(?:for|while|until|select)\b", re.IGNORECASE)
_SSH_REFERENCE = re.compile(
    r"(?:\bSSH_AUTH_SOCK\b|\bGIT_SSH(?:_COMMAND)?\b|"
    r"(?:^|[\s=])(?:~|\$\{?HOME\}?)/\.ssh(?:/|\b)|"
    r"\bid_(?:rsa|dsa|ecdsa|ed25519)\b)",
    re.IGNORECASE,
)

_MUTATION_SUBCOMMANDS = {
    "add",
    "am",
    "apply",
    "cherry-pick",
    "commit",
    "commit-tree",
    "merge",
    "mktree",
    "mv",
    "rebase",
    "replace",
    "rm",
    "update-index",
    "update-ref",
}
_GLOBAL_OPTIONS_WITH_VALUE = {
    "-C",
    "-c",
    "--config-env",
    "--git-dir",
    "--namespace",
    "--super-prefix",
    "--work-tree",
}
_GLOBAL_CONTEXT_OPTIONS = {"-C", "--git-dir", "--work-tree"}
_GLOBAL_OPTIONS_WITH_ATTACHED_VALUE = (
    "--config-env=",
    "--git-dir=",
    "--namespace=",
    "--super-prefix=",
    "--work-tree=",
)
_REMOTE_ADD_OPTIONS_WITH_VALUE = {"-m", "-t", "--master", "--track"}
_CLONE_OPTIONS_WITH_VALUE = {
    "-b",
    "-j",
    "-o",
    "-u",
    "--branch",
    "--bundle-uri",
    "--depth",
    "--filter",
    "--jobs",
    "--origin",
    "--reference",
    "--reference-if-able",
    "--separate-git-dir",
    "--server-option",
    "--shallow-exclude",
    "--shallow-since",
    "--template",
    "--upload-pack",
}
_PUSH_OPTIONS_WITH_VALUE = {
    "--exec",
    "--push-option",
    "--receive-pack",
    "-o",
}
_MAX_INPUT_CHARS = 5 * 1024 * 1024
_MAX_GIT_COMMANDS = 16384
_MAX_AUR_VARIABLES = 16384


def find_aur_repository_propagation_signals(
    text: str,
    *,
    dot_prefixed_hook: bool = False,
) -> List[AurPropagationSignal]:
    """Return fixed labels for a mutation and destination-bound AUR push chain."""

    if not text or len(text) > _MAX_INPUT_CHARS:
        return []

    active_text = _active_shell_text(text)
    raw_view, command_view = _logical_shell_views(active_text)
    line_starts = _line_starts(text)
    aur_variables = _constant_aur_variables(active_text)
    commands = _git_commands(raw_view, command_view, line_starts)
    if commands is None:
        return []

    mutations: Dict[Tuple[str, ...], AurPropagationSignal] = {}
    remote_bindings: Dict[Tuple[Tuple[str, ...], str], AurPropagationSignal] = {}
    targeted_pushes: List[Tuple[AurPropagationSignal, AurPropagationSignal, Tuple[str, ...]]] = []

    for command in commands:
        if command.subcommand in _MUTATION_SUBCOMMANDS and not _is_non_mutating_invocation(
            command.subcommand,
            command.arguments,
        ):
            _remember_context_signal(
                mutations,
                command.context,
                AurPropagationSignal(
                    "repository_mutation",
                    "repository content mutation",
                    command.line_number,
                ),
            )

        _update_remote_bindings(remote_bindings, command, aur_variables)

        if command.subcommand != "push" or _is_dry_run_push(command.arguments):
            continue
        anchor = _aur_push_anchor(remote_bindings, command, aur_variables)
        if anchor is not None:
            targeted_pushes.append(
                (
                    anchor,
                    AurPropagationSignal("git_push", "Git push", command.line_number),
                    command.context,
                )
            )

    chains = [
        (anchor, mutations[context], push)
        for anchor, push, context in targeted_pushes
        if context in mutations
    ]
    if not chains:
        return []

    anchor, mutation, push = min(
        chains,
        key=lambda item: (min(signal.line_number for signal in item), item[2].line_number),
    )
    required = [anchor, mutation, push]
    support = _supporting_signals(raw_view, command_view, line_starts)
    if dot_prefixed_hook:
        support.append(
            AurPropagationSignal(
                "dot_prefixed_hook",
                "dot-prefixed install hook",
                min(signal.line_number for signal in required),
            )
        )
    return required + _ordered_unique_support(support)


def _git_commands(
    raw_view: str,
    command_view: str,
    line_starts: Sequence[int],
) -> Optional[List[_GitCommand]]:
    commands: List[_GitCommand] = []
    for command_match in _GIT_COMMAND.finditer(command_view):
        if len(commands) >= _MAX_GIT_COMMANDS:
            return None
        segment_end = _shell_segment_end(command_view, command_match.end())
        tokens = _shell_tokens(raw_view[command_match.end():segment_end])
        parsed = _git_subcommand(tokens)
        if parsed is None:
            continue
        subcommand, arguments, context = parsed
        commands.append(
            _GitCommand(
                subcommand,
                tuple(arguments),
                context,
                _line_number(line_starts, command_match.end() - len("git")),
            )
        )
    return commands


def _update_remote_bindings(
    bindings: Dict[Tuple[Tuple[str, ...], str], AurPropagationSignal],
    command: _GitCommand,
    aur_variables: Dict[str, str],
) -> None:
    if command.subcommand == "remote":
        _update_remote_command_binding(bindings, command, aur_variables)
    elif command.subcommand == "config":
        _update_config_binding(bindings, command, aur_variables)
    elif command.subcommand == "clone":
        _update_clone_binding(bindings, command, aur_variables)


def _update_clone_binding(
    bindings: Dict[Tuple[Tuple[str, ...], str], AurPropagationSignal],
    command: _GitCommand,
    aur_variables: Dict[str, str],
) -> None:
    values = _option_free_positionals(command.arguments, _CLONE_OPTIONS_WITH_VALUE)
    if not values:
        return
    endpoint = _resolved_aur_endpoint(values[0], aur_variables)
    if endpoint is None:
        return
    destination = values[1] if len(values) >= 2 else _clone_default_directory(endpoint)
    if not destination:
        return
    origin = _clone_origin_name(command.arguments) or "origin"
    context = _clone_destination_context(command.context, destination)
    if context is None:
        return
    bindings[(context, origin)] = AurPropagationSignal(
        "aur_remote",
        "AUR Git remote",
        command.line_number,
    )


def _clone_origin_name(arguments: Sequence[str]) -> Optional[str]:
    for index, token in enumerate(arguments):
        if token in {"-o", "--origin"}:
            return arguments[index + 1] if index + 1 < len(arguments) else None
        if token.startswith("--origin="):
            return token.split("=", 1)[1]
        if token.startswith("-o") and len(token) > 2:
            return token[2:]
    return None


def _clone_default_directory(endpoint: str) -> Optional[str]:
    if not _is_aur_endpoint(endpoint):
        return None
    path = endpoint.rsplit("/", 1)[-1]
    if ":" in path:
        path = path.rsplit(":", 1)[-1]
    return path[:-4] if path.lower().endswith(".git") else None


def _clone_destination_context(
    clone_context: Tuple[str, ...],
    destination: str,
) -> Optional[Tuple[str, ...]]:
    if not clone_context:
        return ("repository=" + destination,)
    if len(clone_context) != 1 or not clone_context[0].startswith("repository="):
        return None
    base = clone_context[0].split("=", 1)[1].rstrip("/")
    if destination.startswith("/"):
        combined = destination
    elif base in {"", "."}:
        combined = destination
    else:
        combined = base + "/" + destination
    return ("repository=" + combined,)


def _update_remote_command_binding(
    bindings: Dict[Tuple[Tuple[str, ...], str], AurPropagationSignal],
    command: _GitCommand,
    aur_variables: Dict[str, str],
) -> None:
    if not command.arguments:
        return
    action = command.arguments[0].lower()
    remainder = list(command.arguments[1:])

    if action in {"remove", "rm"}:
        names = _option_free_positionals(remainder, set())
        if names:
            bindings.pop((command.context, names[0]), None)
        return
    if action == "rename":
        names = _option_free_positionals(remainder, set())
        if len(names) >= 2:
            previous = bindings.pop((command.context, names[0]), None)
            if previous is not None:
                bindings[(command.context, names[1])] = previous
        return
    if action not in {"add", "set-url"}:
        return

    options_with_value = _REMOTE_ADD_OPTIONS_WITH_VALUE if action == "add" else set()
    values = _option_free_positionals(remainder, options_with_value)
    if len(values) < 2:
        return
    name, target = values[0], values[1]
    key = (command.context, name)
    is_additional = action == "set-url" and "--add" in remainder
    is_delete = action == "set-url" and "--delete" in remainder
    if is_delete:
        if _token_is_aur_endpoint(target, aur_variables):
            bindings.pop(key, None)
        return
    if _token_is_aur_endpoint(target, aur_variables):
        bindings[key] = AurPropagationSignal(
            "aur_remote",
            "AUR Git remote",
            command.line_number,
        )
    elif not is_additional:
        bindings.pop(key, None)


def _update_config_binding(
    bindings: Dict[Tuple[Tuple[str, ...], str], AurPropagationSignal],
    command: _GitCommand,
    aur_variables: Dict[str, str],
) -> None:
    arguments = list(command.arguments)
    key_index = -1
    key_match = None
    for index, token in enumerate(arguments):
        match = _REMOTE_CONFIG_KEY.fullmatch(token)
        if match is not None:
            key_index = index
            key_match = match
            break
    if key_match is None:
        return
    binding_key = (command.context, key_match.group("name"))
    if "--unset" in arguments or "--unset-all" in arguments:
        bindings.pop(binding_key, None)
        return
    if key_index + 1 >= len(arguments):
        return
    target = arguments[key_index + 1]
    if _token_is_aur_endpoint(target, aur_variables):
        bindings[binding_key] = AurPropagationSignal(
            "aur_remote",
            "AUR Git remote",
            command.line_number,
        )
    elif "--add" not in arguments:
        bindings.pop(binding_key, None)


def _aur_push_anchor(
    bindings: Dict[Tuple[Tuple[str, ...], str], AurPropagationSignal],
    command: _GitCommand,
    aur_variables: Dict[str, str],
) -> Optional[AurPropagationSignal]:
    destination = _push_destination(command.arguments)
    if destination is None:
        return bindings.get((command.context, "origin"))
    if _token_is_aur_endpoint(destination, aur_variables):
        return AurPropagationSignal("aur_remote", "AUR Git remote", command.line_number)
    return bindings.get((command.context, destination))


def _push_destination(arguments: Sequence[str]) -> Optional[str]:
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if token == "--":
            return arguments[index + 1] if index + 1 < len(arguments) else None
        if token.startswith("--repo="):
            return token.split("=", 1)[1]
        if token == "--repo":
            return arguments[index + 1] if index + 1 < len(arguments) else None
        if token in _PUSH_OPTIONS_WITH_VALUE:
            index += 2
            continue
        if any(token.startswith(option + "=") for option in _PUSH_OPTIONS_WITH_VALUE if option.startswith("--")):
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        return token
    return None


def _option_free_positionals(arguments: Sequence[str], options_with_value: Set[str]) -> List[str]:
    values: List[str] = []
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if token == "--":
            values.extend(arguments[index + 1:])
            break
        if token in options_with_value:
            index += 2
            continue
        if any(
            token.startswith(option + "=")
            for option in options_with_value
            if option.startswith("--")
        ):
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        values.append(token)
        index += 1
    return values


def _constant_aur_variables(text: str) -> Dict[str, str]:
    assignment_counts: Dict[str, int] = {}
    aur_assignments: Dict[str, str] = {}
    for line in text.splitlines():
        match = _CONSTANT_ASSIGNMENT.match(line)
        if match is None:
            continue
        name = match.group("name")
        assignment_counts[name] = assignment_counts.get(name, 0) + 1
        if len(assignment_counts) > _MAX_AUR_VARIABLES:
            return {}
        raw_value = match.group("value").strip()
        if "$" in raw_value or "`" in raw_value or ";" in raw_value:
            continue
        values = _shell_tokens(raw_value)
        if len(values) == 1 and _is_aur_endpoint(values[0]):
            aur_assignments[name] = values[0]
    return {
        name: endpoint
        for name, endpoint in aur_assignments.items()
        if assignment_counts.get(name) == 1
    }


def _token_is_aur_endpoint(token: str, aur_variables: Dict[str, str]) -> bool:
    return _resolved_aur_endpoint(token, aur_variables) is not None


def _resolved_aur_endpoint(token: str, aur_variables: Dict[str, str]) -> Optional[str]:
    if _is_aur_endpoint(token):
        return token
    variable = _VARIABLE_TOKEN.fullmatch(token)
    if variable is None:
        return None
    name = variable.group("braced") or variable.group("plain")
    return aur_variables.get(name) if name else None


def _is_aur_endpoint(token: str) -> bool:
    match = _AUR_GIT_ENDPOINT.fullmatch(token)
    if match is None:
        return False
    port = match.group("port")
    return port is None or int(port) <= 65535


def _git_subcommand(
    tokens: Sequence[str],
) -> Optional[Tuple[str, List[str], Tuple[str, ...]]]:
    context: List[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            index += 1
            break
        if token in _GLOBAL_OPTIONS_WITH_VALUE:
            if index + 1 >= len(tokens):
                return None
            if token in _GLOBAL_CONTEXT_OPTIONS:
                context.append(_context_option(token, tokens[index + 1]))
            index += 2
            continue
        attached_context = _attached_context_option(token)
        if attached_context is not None:
            context.append(attached_context)
            index += 1
            continue
        if token.startswith(_GLOBAL_OPTIONS_WITH_ATTACHED_VALUE):
            index += 1
            continue
        if token.startswith("-c") and len(token) > 2:
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        return token.lower(), list(tokens[index + 1:]), tuple(context)
    if index < len(tokens):
        return tokens[index].lower(), list(tokens[index + 1:]), tuple(context)
    return None


def _attached_context_option(token: str) -> Optional[str]:
    if token.startswith("-C") and len(token) > 2:
        return _context_option("-C", token[2:])
    for option in ("--git-dir", "--work-tree"):
        prefix = option + "="
        if token.startswith(prefix):
            return _context_option(option, token[len(prefix):])
    return None


def _context_option(option: str, value: str) -> str:
    if option in {"-C", "--work-tree"}:
        return "repository=" + value
    return option + "=" + value


def _is_dry_run_push(arguments: Sequence[str]) -> bool:
    return any(_is_enabled_dry_run_option(token, allow_short=True) for token in arguments)


def _is_non_mutating_invocation(subcommand: str, arguments: Sequence[str]) -> bool:
    if subcommand in {"add", "commit", "rm"} and any(
        _is_enabled_dry_run_option(
            token,
            allow_short=subcommand in {"add", "rm"},
        )
        for token in arguments
    ):
        return True
    return subcommand == "apply" and "--check" in arguments


def _is_enabled_dry_run_option(token: str, *, allow_short: bool) -> bool:
    if token == "--dry-run" or (allow_short and token == "-n"):
        return True
    if not token.startswith("--dry-run="):
        return False
    value = token.split("=", 1)[1].strip().lower()
    return value not in {"0", "false", "no", "off"}


def _supporting_signals(
    raw_view: str,
    command_view: str,
    line_starts: Sequence[int],
) -> List[AurPropagationSignal]:
    signals: List[AurPropagationSignal] = []

    for match in _FIND_COMMAND.finditer(command_view):
        segment_end = _shell_segment_end(command_view, match.end())
        arguments = _shell_tokens(raw_view[match.end():segment_end])
        if any(_looks_like_repository_marker(token) for token in arguments):
            signals.append(
                AurPropagationSignal(
                    "repository_enumeration",
                    "repository enumeration",
                    _line_number(
                        line_starts,
                        _matched_executable_start(command_view, match, ("find", "fd", "fdfind")),
                    ),
                )
            )
            break

    loop_match = _LOOP_START.search(command_view)
    if loop_match is not None:
        signals.append(
            AurPropagationSignal(
                "repository_loop",
                "repository iteration loop",
                _line_number(line_starts, loop_match.start()),
            )
        )

    ssh_match = next(_SSH_KEY_COMMAND.finditer(command_view), None)
    ssh_reference = _SSH_REFERENCE.search(command_view)
    offsets = []
    if ssh_match is not None:
        offsets.append(
            _matched_executable_start(
                command_view,
                ssh_match,
                ("ssh-add", "ssh-agent", "ssh-keygen"),
            )
        )
    if ssh_reference is not None:
        offsets.append(ssh_reference.start())
    if offsets:
        signals.append(
            AurPropagationSignal(
                "ssh_credential_reference",
                "SSH agent or key reference",
                _line_number(line_starts, min(offsets)),
            )
        )
    return signals


def _looks_like_repository_marker(token: str) -> bool:
    lowered = token.lower().rstrip("/")
    return (
        lowered == ".git"
        or lowered.endswith("/.git")
        or lowered == "pkgbuild"
        or lowered.endswith("/pkgbuild")
    )


def _matched_executable_start(
    text: str,
    match: re.Match,
    names: Sequence[str],
) -> int:
    for name in sorted(names, key=len, reverse=True):
        start = match.end() - len(name)
        if start >= 0 and text[start:match.end()].lower() == name.lower():
            return match.end() - len(name)
    return match.start()


def _ordered_unique_support(signals: Sequence[AurPropagationSignal]) -> List[AurPropagationSignal]:
    order = (
        "repository_enumeration",
        "repository_loop",
        "ssh_credential_reference",
        "dot_prefixed_hook",
    )
    earliest: Dict[str, AurPropagationSignal] = {}
    for signal in signals:
        if signal.kind in order:
            previous = earliest.get(signal.kind)
            if previous is None or signal.line_number < previous.line_number:
                earliest[signal.kind] = signal
    return [earliest[kind] for kind in order if kind in earliest]


def _remember_context_signal(
    signals: Dict[Tuple[str, ...], AurPropagationSignal],
    context: Tuple[str, ...],
    signal: AurPropagationSignal,
) -> None:
    previous = signals.get(context)
    if previous is None or signal.line_number < previous.line_number:
        signals[context] = signal


def _active_shell_text(text: str) -> str:
    """Mask comments, inert heredocs, and inert array values without changing offsets."""

    without_comments = _mask_shell_comments(text)
    without_heredocs = _mask_heredoc_bodies(without_comments)
    return _mask_array_values(without_heredocs)


def _mask_shell_comments(text: str) -> str:
    output = list(text)
    quote = ""
    escaped = False
    substitution_disabled = False
    index = 0
    while index < len(text):
        char = text[index]
        if quote == "'":
            if char == "'":
                quote = ""
            index += 1
            continue
        if quote == '"':
            if escaped:
                escaped = False
                index += 1
                continue
            if char == "\\":
                escaped = True
                index += 1
                continue
            if char == '"':
                quote = ""
                substitution_disabled = False
                index += 1
                continue
            if not substitution_disabled and text.startswith("$(", index):
                end = _command_substitution_end(text, index + 2)
                if end is not None:
                    nested = _mask_shell_comments(text[index + 2:end])
                    output[index + 2:end] = nested
                    index = end + 1
                    continue
                substitution_disabled = True
            if not substitution_disabled and char == "`":
                end = _backtick_end(text, index + 1)
                if end is not None:
                    nested = _mask_shell_comments(text[index + 1:end])
                    output[index + 1:end] = nested
                    index = end + 1
                    continue
                substitution_disabled = True
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
            substitution_disabled = False
            index += 1
            continue
        if text.startswith("$(", index):
            end = _command_substitution_end(text, index + 2)
            if end is not None:
                nested = _mask_shell_comments(text[index + 2:end])
                output[index + 2:end] = nested
                index = end + 1
                continue
            break
        if char == "`":
            end = _backtick_end(text, index + 1)
            if end is not None:
                nested = _mask_shell_comments(text[index + 1:end])
                output[index + 1:end] = nested
                index = end + 1
                continue
            break
        if char == "#" and _comment_starts_word(text, index):
            end = text.find("\n", index)
            if end < 0:
                end = len(text)
            for position in range(index, end):
                output[position] = " "
            index = end
            continue
        index += 1
    return "".join(output)


def _comment_starts_word(text: str, index: int) -> bool:
    return index == 0 or text[index - 1].isspace() or text[index - 1] in ";|&(){}"


def _mask_heredoc_bodies(text: str) -> str:
    structural = mask_shell_quoted_text(text)
    inert_shift_offsets = _inert_shift_offsets(structural)
    lines = text.splitlines(keepends=True)
    line_offsets: List[int] = []
    offset = 0
    for line in lines:
        line_offsets.append(offset)
        offset += len(line)
    output: List[str] = []
    pending: List[Tuple[str, bool, bool]] = []
    line_index = 0
    while line_index < len(lines):
        line = lines[line_index]
        offset = line_offsets[line_index]
        if pending:
            delimiter, strip_tabs, quoted = pending[0]
            body_lines: List[str] = []
            while line_index < len(lines):
                body_line = lines[line_index]
                body = body_line.rstrip("\r\n")
                candidate = body.lstrip("\t") if strip_tabs else body
                if candidate == delimiter:
                    break
                body_lines.append(body_line)
                line_index += 1
            body_text = "".join(body_lines)
            if quoted:
                output.append(_spaces_preserving_newlines(body_text))
            else:
                output.append(_mask_except_substitutions(body_text, include_process=False))
            if line_index < len(lines):
                output.append(_spaces_preserving_newlines(lines[line_index]))
                line_index += 1
            pending.pop(0)
            continue

        output.append(line)
        structural_line = structural[offset:offset + len(line)]
        for operator in re.finditer(r"<<-?", structural_line):
            absolute = offset + operator.start()
            if inert_shift_offsets[absolute]:
                continue
            parsed = _parse_heredoc_delimiter(text, absolute)
            if parsed is not None:
                pending.append(parsed)
        line_index += 1
    return "".join(output)


def _inert_shift_offsets(text: str) -> bytearray:
    """Return ``<<`` offsets that are arithmetic or ``[[`` test operators."""

    offsets = bytearray(len(text))
    stack: List[Tuple[str, int]] = []
    index = 0
    while index < len(text):
        if stack:
            kind, depth = stack[-1]
            if text.startswith("<<", index):
                offsets[index] = 1
                index += 2
                continue
            if kind == "arithmetic_parentheses":
                if text[index] == "(":
                    stack[-1] = (kind, depth + 1)
                elif text[index] == ")":
                    depth -= 1
                    if depth == 0:
                        stack.pop()
                    else:
                        stack[-1] = (kind, depth)
                index += 1
                continue
            if kind == "arithmetic_bracket":
                if text[index] == "]":
                    stack.pop()
                index += 1
                continue
            if kind == "double_bracket":
                if text.startswith("]]", index):
                    stack.pop()
                    index += 2
                else:
                    index += 1
                continue

        if text.startswith("$((", index):
            stack.append(("arithmetic_parentheses", 2))
            index += 3
            continue
        if text.startswith("((", index):
            stack.append(("arithmetic_parentheses", 2))
            index += 2
            continue
        if text.startswith("$[", index):
            stack.append(("arithmetic_bracket", 1))
            index += 2
            continue
        if text.startswith("[[", index):
            stack.append(("double_bracket", 1))
            index += 2
            continue
        index += 1
    return offsets


def _parse_heredoc_delimiter(text: str, start: int) -> Optional[Tuple[str, bool, bool]]:
    if not text.startswith("<<", start) or text.startswith("<<<", start):
        return None
    index = start + 2
    strip_tabs = False
    if index < len(text) and text[index] == "-":
        strip_tabs = True
        index += 1
    while index < len(text) and text[index] in " \t":
        index += 1
    if index >= len(text) or text[index] in "\r\n;|&()<>":
        return None

    delimiter: List[str] = []
    quoted = False
    while index < len(text):
        char = text[index]
        if char.isspace() or char in ";|&()<>":
            break
        if char == "'":
            quoted = True
            end = text.find("'", index + 1)
            if end < 0:
                return None
            delimiter.append(text[index + 1:end])
            index = end + 1
            continue
        if char == '"':
            quoted = True
            index += 1
            while index < len(text) and text[index] != '"':
                if text[index] == "\\" and index + 1 < len(text):
                    index += 1
                delimiter.append(text[index])
                index += 1
            if index >= len(text):
                return None
            index += 1
            continue
        if char == "\\":
            quoted = True
            if index + 1 >= len(text):
                return None
            delimiter.append(text[index + 1])
            index += 2
            continue
        delimiter.append(char)
        index += 1
    value = "".join(delimiter)
    return (value, strip_tabs, quoted) if value else None


def _mask_array_values(text: str) -> str:
    structural = mask_shell_quoted_text(text)
    output = list(text)
    search_at = 0
    while search_at < len(structural):
        match = _ARRAY_ASSIGNMENT.search(structural, search_at)
        if match is None:
            break
        open_index = match.end() - 1
        close_index = _matching_parenthesis_end(text, open_index)
        if close_index is None:
            break
        masked = _mask_except_substitutions(
            text[open_index + 1:close_index],
            include_process=True,
        )
        output[open_index + 1:close_index] = masked
        search_at = close_index + 1
    return "".join(output)


def _mask_except_substitutions(text: str, *, include_process: bool) -> str:
    output = list(_spaces_preserving_newlines(text))
    index = 0
    while index < len(text):
        if text.startswith("$(", index):
            end = _command_substitution_end(text, index + 2)
            if end is not None:
                output[index:end + 1] = text[index:end + 1]
                index = end + 1
                continue
        if include_process and index + 1 < len(text) and text[index] in "<>" and text[index + 1] == "(":
            end = _matching_parenthesis_end(text, index + 1)
            if end is not None:
                output[index:end + 1] = text[index:end + 1]
                index = end + 1
                continue
        if text[index] == "`":
            end = _backtick_end(text, index + 1)
            if end is not None:
                output[index:end + 1] = text[index:end + 1]
                index = end + 1
                continue
        index += 1
    return "".join(output)


def _command_substitution_end(text: str, start: int) -> Optional[int]:
    depth = 1
    quote = ""
    escaped = False
    index = start
    while index < len(text):
        char = text[index]
        if quote == "'":
            if char == "'":
                quote = ""
            index += 1
            continue
        if quote == '"':
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quote = ""
            elif text.startswith("$(", index):
                nested = _command_substitution_end(text, index + 2)
                if nested is None:
                    return None
                index = nested
            elif char == "`":
                nested = _backtick_end(text, index + 1)
                if nested is None:
                    return None
                index = nested
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
        if char == "#" and _comment_starts_word(text, index):
            newline = text.find("\n", index)
            index = len(text) if newline < 0 else newline + 1
            continue
        if char == "`":
            nested = _backtick_end(text, index + 1)
            if nested is None:
                return None
            index = nested + 1
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def _matching_parenthesis_end(text: str, open_index: int) -> Optional[int]:
    return _command_substitution_end(text, open_index + 1)


def _backtick_end(text: str, start: int) -> Optional[int]:
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == "`":
            return index
    return None


def _spaces_preserving_newlines(text: str) -> str:
    return "".join(char if char in "\r\n" else " " for char in text)


def _logical_shell_views(text: str) -> Tuple[str, str]:
    raw = list(text)
    command = list(mask_shell_quoted_text(text))
    for index, char in enumerate(text):
        if char != "\n":
            continue
        backslashes = 0
        cursor = index - 1
        while cursor >= 0 and text[cursor] == "\\":
            backslashes += 1
            cursor -= 1
        if backslashes % 2 == 1:
            raw[index - 1] = " "
            command[index - 1] = " "
            raw[index] = " "
            command[index] = " "
        else:
            raw[index] = ";"
            command[index] = ";"
    return "".join(raw), "".join(command)


def _line_starts(text: str) -> List[int]:
    starts = [0]
    starts.extend(index + 1 for index, char in enumerate(text) if char == "\n")
    return starts


def _line_number(line_starts: Sequence[int], offset: int) -> int:
    return bisect_right(line_starts, offset)


def _shell_tokens(text: str) -> List[str]:
    try:
        return shlex.split(text, comments=False, posix=True)
    except ValueError:
        return []


def _shell_segment_end(masked_text: str, command_end: int) -> int:
    separator = re.search(r"[;|&)]", masked_text[command_end:])
    return len(masked_text) if separator is None else command_end + separator.start()
