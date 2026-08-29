"""Shared static signals for package-delivered remote-access backdoors."""

import re
from typing import List, NamedTuple, Optional, Tuple


class RemoteAccessSignal(NamedTuple):
    label: str
    line_number: int
    remote_anchor: bool


_COMMAND_SUBSTITUTION_BOUNDARY = "\x1f"
_COMMAND_PREFIX = (
    r"(?:^|[;&|]|\$\(|" + re.escape(_COMMAND_SUBSTITUTION_BOUNDARY) + r")\s*"
    r"(?:(?:!|\{|\()\s*|(?:if|then|elif|while|until|do|else)\b\s+)*"
    r"(?:(?:command|exec|env|time)\s+|[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*"
)


def shell_command_pattern(*executables: str) -> re.Pattern:
    """Compile a quote-mask-friendly shell command-position matcher."""

    names = "|".join(re.escape(name) for name in executables)
    return re.compile(
        _COMMAND_PREFIX
        + r"(?:/(?:usr/)?s?bin/)?(?:" + names + r")(?=\s|$)",
        re.IGNORECASE,
    )


def _balanced_parenthesis_end(text: str, start: int, depth: int = 0) -> Optional[int]:
    if depth >= 32:
        return None
    quote = ""
    index = start
    while index < len(text):
        char = text[index]
        if quote == "'":
            if char == "'":
                quote = ""
            index += 1
            continue
        if quote == '"':
            if char == "\\":
                index += 2
                continue
            if char == '"':
                quote = ""
                index += 1
                continue
            if text.startswith("$(", index):
                nested_end = _balanced_parenthesis_end(text, index + 2, depth + 1)
                if nested_end is None:
                    return None
                index = nested_end + 1
                continue
            index += 1
            continue
        if char == "\\":
            index += 2
            continue
        if char in {"'", '"'}:
            quote = char
            index += 1
            continue
        if char == "`":
            nested_end = _unescaped_backtick_end(text, index + 1)
            if nested_end is None:
                return None
            index = nested_end + 1
            continue
        if char == "(":
            nested_end = _balanced_parenthesis_end(text, index + 1, depth + 1)
            if nested_end is None:
                return None
            index = nested_end + 1
            continue
        if char == ")":
            return index
        index += 1
    return None


def _unescaped_backtick_end(text: str, start: int) -> Optional[int]:
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
        elif char == "`":
            return index
    return None


def mask_shell_quoted_text(text: str, _depth: int = 0) -> str:
    """Mask quoted shell text while preserving offsets and newline positions."""

    output: List[str] = []
    quote = ""
    escaped = False
    substitution_disabled = False
    index = 0
    while index < len(text):
        char = text[index]
        if quote:
            if (
                quote == '"'
                and not escaped
                and not substitution_disabled
                and _depth < 8
                and text.startswith("$(", index)
            ):
                end = _balanced_parenthesis_end(text, index + 2)
                if end is not None:
                    output.extend("$(")
                    output.extend(mask_shell_quoted_text(text[index + 2:end], _depth + 1))
                    output.append(")")
                    index = end + 1
                    continue
                substitution_disabled = True
            if quote == '"' and not escaped and not substitution_disabled and _depth < 8 and char == "`":
                end = _unescaped_backtick_end(text, index + 1)
                if end is not None:
                    output.append(_COMMAND_SUBSTITUTION_BOUNDARY)
                    output.extend(mask_shell_quoted_text(text[index + 1:end], _depth + 1))
                    output.append(" ")
                    index = end + 1
                    continue
                substitution_disabled = True
            output.append("\n" if char == "\n" else " ")
            if quote == "'":
                if char == "'":
                    quote = ""
            elif escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quote = ""
                substitution_disabled = False
            index += 1
        elif escaped:
            output.append(char)
            escaped = False
            index += 1
        elif char == "\\":
            output.append(char)
            escaped = True
            index += 1
        elif char in {"'", '"'}:
            output.append(" ")
            quote = char
            substitution_disabled = False
            index += 1
        elif char == "`" and _depth < 8:
            end = _unescaped_backtick_end(text, index + 1)
            if end is None:
                output.extend("\n" if value == "\n" else " " for value in text[index:])
                break
            output.append(_COMMAND_SUBSTITUTION_BOUNDARY)
            output.extend(mask_shell_quoted_text(text[index + 1:end], _depth + 1))
            output.append(" ")
            index = end + 1
        else:
            output.append(char)
            index += 1
    return "".join(output)


_TAILSCALE_COMMAND = shell_command_pattern("tailscale")
_SSHD_COMMAND = shell_command_pattern("sshd")
_JOURNALCTL_COMMAND = shell_command_pattern("journalctl")
_TRUNCATE_COMMAND = shell_command_pattern("truncate")
_SET_COMMAND = shell_command_pattern("set")
_CHMOD_COMMAND = shell_command_pattern("chmod")

_TAILSCALE_ENROLLMENT_ARGS = re.compile(
    r"\s+up\b"
    r"(?=[^\n]*--auth-?key(?:\s|=|$))"
    r"(?=[^\n]*--ssh(?:\s|$|=(?:true|1)\b))",
    re.IGNORECASE,
)
_HIDDEN_ROOT_SSHD_ARGS = re.compile(
    r"[^\n]*\s-f\s+['\"]?/etc/pacman\.d/[^\s'\"]+",
    re.IGNORECASE,
)
_JOURNAL_ERASURE_ARGS = re.compile(
    r"[^\n]*--vacuum-time\s*=\s*1s\b",
    re.IGNORECASE,
)
_HISTORY_ERASURE_ARGS = re.compile(
    r"[^\n]*\s['\"]?(?:/root|/home/[^/\s'\"]+)/\.bash_history['\"]?(?:\s|$)",
    re.IGNORECASE,
)
_DISABLE_HISTORY_ARGS = re.compile(r"\s+\+o\s+history\b", re.IGNORECASE)
_SUID_CHMOD_ARGS = re.compile(
    r"(?:^|\s)['\"]?(?:0?4[0-7]{3}|u\+s|\+s)['\"]?(?:\s|$)",
    re.IGNORECASE,
)

_PASSWORDLESS_SUDO_POLICY = re.compile(
    r"(?:^[ \t]*|['\"][ \t]*)(?:%?[A-Za-z_][A-Za-z0-9_.-]*|ALL)[ \t]+"
    r"[^=\s]+[ \t]*=[ \t]*(?:\([^\n)]*\)[ \t]*)?NOPASSWD[ \t]*:",
    re.IGNORECASE | re.MULTILINE,
)
_KNOWN_DISGUISED_PATHS = re.compile(
    r"/(?:etc|usr/lib)/systemd/system/(?:hyprland-fixes\.(?:service|timer)|"
    r"arch-mirrorlist-criteria\.service|arch-keyring-syncer\.service)\b",
    re.IGNORECASE,
)
_PACMAN_SSH_CONFIG_PATH = re.compile(r"/etc/pacman\.d/[^\s'\"]+", re.IGNORECASE)

_ALT_ROOT_SSH_EVENTS = re.compile(
    r"(?P<port>\bPort\s+(?:3333|4444)\b)|"
    r"(?P<root_login>\bPermitRootLogin\s+yes\b)",
    re.IGNORECASE,
)
_HOURLY_ROOT_SYSTEMD_EVENTS = re.compile(
    r"(?P<hourly>\bOnCalendar\s*=\s*hourly\b)|"
    r"(?P<root_user>\bUser\s*=\s*root\b)",
    re.IGNORECASE,
)


def _shell_segment_end(masked_line: str, command_end: int) -> int:
    separator = re.search(r"[;|&)]", masked_line[command_end:])
    return len(masked_line) if separator is None else command_end + separator.start()


def _find_command_behavior(
    text: str,
    command_pattern: re.Pattern,
    argument_pattern: re.Pattern,
) -> Optional[int]:
    for line_number, line in enumerate(text.splitlines(), 1):
        masked_line = mask_shell_quoted_text(line)
        for command_match in command_pattern.finditer(masked_line):
            segment_end = _shell_segment_end(masked_line, command_match.end())
            raw_arguments = line[command_match.end():segment_end]
            if argument_pattern.search(raw_arguments):
                return line_number
    return None


def _bounded_pair_start(
    text: str,
    pattern: re.Pattern,
    first: str,
    second: str,
    max_distance: int,
) -> Optional[int]:
    """Find a nearby pair with a single linear regex pass over untrusted text."""

    last_positions = {}
    for match in pattern.finditer(text):
        kind = match.lastgroup
        if kind is None:
            continue
        other = second if kind == first else first
        other_position = last_positions.get(other)
        if other_position is not None and match.start() - other_position <= max_distance:
            return other_position
        last_positions[kind] = match.start()
    return None


def _command_signals(text: str) -> List[RemoteAccessSignal]:
    checks: Tuple[Tuple[str, bool, re.Pattern, re.Pattern], ...] = (
        (
            "Tailscale auth-key enrollment with Tailscale SSH",
            True,
            _TAILSCALE_COMMAND,
            _TAILSCALE_ENROLLMENT_ARGS,
        ),
        (
            "root sshd launched with a config hidden under /etc/pacman.d",
            True,
            _SSHD_COMMAND,
            _HIDDEN_ROOT_SSHD_ARGS,
        ),
        ("journal erasure", False, _JOURNALCTL_COMMAND, _JOURNAL_ERASURE_ARGS),
        ("shell-history erasure", False, _TRUNCATE_COMMAND, _HISTORY_ERASURE_ARGS),
        ("shell-history disabling", False, _SET_COMMAND, _DISABLE_HISTORY_ARGS),
        ("set-user-ID permission request", False, _CHMOD_COMMAND, _SUID_CHMOD_ARGS),
    )
    signals: List[RemoteAccessSignal] = []
    for label, remote_anchor, command_pattern, argument_pattern in checks:
        line_number = _find_command_behavior(text, command_pattern, argument_pattern)
        if line_number is not None:
            signals.append(RemoteAccessSignal(label, line_number, remote_anchor))
    return signals


def _strip_shell_comments(text: str) -> str:
    active_lines: List[str] = []
    for line in text.splitlines():
        in_single = False
        in_double = False
        escaped = False
        comment_start = len(line)
        for index, char in enumerate(line):
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
            elif char == "'" and not in_double:
                in_single = not in_single
            elif char == '"' and not in_single:
                in_double = not in_double
            elif (
                char == "#"
                and not in_single
                and not in_double
                and (index == 0 or line[index - 1].isspace() or line[index - 1] in ";|&(){}")
            ):
                comment_start = index
                break
        active_lines.append(line[:comment_start])
    return "\n".join(active_lines)


def find_remote_access_backdoor_signals(text: str) -> List[RemoteAccessSignal]:
    """Return bounded, secret-free labels for independent backdoor behaviors."""

    text = _strip_shell_comments(text)
    signals = _command_signals(text)

    for label, remote_anchor, pattern in (
        ("passwordless sudo grant", False, _PASSWORDLESS_SUDO_POLICY),
        ("reported disguised systemd persistence paths", False, _KNOWN_DISGUISED_PATHS),
    ):
        match = pattern.search(text)
        if match:
            signals.append(RemoteAccessSignal(label, text[:match.start()].count("\n") + 1, remote_anchor))

    ssh_pair_start = _bounded_pair_start(
        text,
        _ALT_ROOT_SSH_EVENTS,
        "port",
        "root_login",
        512,
    )
    if ssh_pair_start is not None:
        context_start = max(0, ssh_pair_start - 512)
        context_end = min(len(text), ssh_pair_start + 1536)
        config_path = _PACMAN_SSH_CONFIG_PATH.search(text[context_start:context_end])
    else:
        config_path = None
    if ssh_pair_start is not None and config_path is not None:
        signals.append(RemoteAccessSignal(
            "alternate-port SSH configuration permits root login",
            text[:ssh_pair_start].count("\n") + 1,
            True,
        ))

    systemd_pair_start = _bounded_pair_start(
        text,
        _HOURLY_ROOT_SYSTEMD_EVENTS,
        "hourly",
        "root_user",
        1024,
    )
    if systemd_pair_start is not None:
        signals.append(RemoteAccessSignal(
            "hourly root systemd persistence",
            text[:systemd_pair_start].count("\n") + 1,
            False,
        ))
    return signals
