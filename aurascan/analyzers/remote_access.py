"""Shared static signals for package-delivered remote-access backdoors."""

import re
from typing import List, NamedTuple, Optional, Tuple


class RemoteAccessSignal(NamedTuple):
    label: str
    line_number: int
    remote_anchor: bool


class AccountBackdoorSignal(NamedTuple):
    """One independent behavior in a package-controlled account chain.

    ``kind`` drives correlation only; ``label`` is a fixed, secret-free string
    so no package-controlled password or user name reaches a report.
    """

    kind: str
    label: str
    line_number: int
    remote_anchor: bool


# Shared sudoers policy shapes. The per-line package rules and the correlated
# account detector import these strings so both surfaces agree on the exact
# policy text they treat as a privileged grant.
ADMIN_GROUP_SUDO_POLICY_PATTERN = (
    r"(?:^|['\"])[ \t]*%(?:wheel|sudo|admin)\b[ \t]+[^\s=]+[ \t]*="
    r"(?![^\n]*NOPASSWD[ \t]*:)[^\n]*"
)
SUDO_POLICY_GRANT_PATTERN = (
    r"(?:^|['\"])[ \t]*(?:%?[A-Za-z_][A-Za-z0-9_.-]*|ALL)[ \t]+[^\s=]+[ \t]*=[ \t]*"
    r"(?:\([^\n)]*\)[ \t]*)?(?:NOPASSWD[ \t]*:[ \t]*)?(?:ALL\b|/[^\s,]+)"
)
ROOT_ACCOUNT_CREDENTIAL_PATTERN = r"(?:^|[\s'\"=])root:[^\s:'\"$`]{1,128}"


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

_CREDENTIAL_COMMAND = shell_command_pattern(
    "chpasswd", "usermod", "useradd", "adduser", "passwd",
)
_GROUP_MEMBERSHIP_COMMAND = shell_command_pattern("useradd", "adduser", "usermod", "gpasswd")
_SYSTEMCTL_COMMAND = shell_command_pattern("systemctl")
_MESSAGE_COMMAND = shell_command_pattern("echo", "printf", "msg", "msg2", "warn", "warning")
# A literal account name and password pair, or an explicit password value.
# Variable references and command substitutions are excluded on purpose: only a
# credential the package itself carries counts as exposed.
_LITERAL_ACCOUNT_CREDENTIAL = re.compile(
    r"(?:^|[\s'\"=])(?:[A-Za-z_][A-Za-z0-9_.-]{0,31}):(?P<pair>[^\s:'\"$`]{1,128})"
    r"|(?:^|\s)-p[ \t]*['\"]?(?P<short>[^\s'\"]{1,128})"
    r"|(?:^|\s)--password(?:=|[ \t]+)['\"]?(?P<long>[^\s'\"]{1,128})",
    re.IGNORECASE,
)
_ROOT_ACCOUNT_CREDENTIAL = re.compile(ROOT_ACCOUNT_CREDENTIAL_PATTERN, re.IGNORECASE)
_HEREDOC_MARKER = re.compile(r"<<-?[ \t]*['\"]?(?P<marker>[A-Za-z_][A-Za-z0-9_]{0,31})")
_MAX_HEREDOC_LINES = 16
_ADMINISTRATIVE_GROUP = re.compile(r"\b(?:wheel|sudo|admin)\b", re.IGNORECASE)
_SSH_SERVICE_ARGUMENT = re.compile(
    r"\b(?:enable|reenable|start|restart)\b[^\n;|&]*"
    r"(?<![\w.-])(?:sshd|ssh)(?:\.service|\.socket)?\b",
    re.IGNORECASE,
)
_SSH_PASSWORD_AUTHENTICATION = re.compile(
    r"\bPasswordAuthentication\b[^\n]{0,64}?\byes\b",
    re.IGNORECASE,
)
_SSHD_CONFIG_WRITE = re.compile(
    r"\b(?:install|cp|mv|tee|chmod|chown|cat)\b[^\n]{0,200}?"
    r"(?:\$pkgdir|\$\{pkgdir\})?/etc/ssh/sshd_config(?:\.d(?:/[^\s'\"]*)?)?(?=[\s'\"]|$)"
    r"|>>?[ \t]*['\"]?(?:\$pkgdir|\$\{pkgdir\})?/etc/ssh/sshd_config(?:\.d(?:/[^\s'\"]*)?)?"
    r"|/etc/ssh/sshd_config(?:\.d(?:/[^\s'\"]*)?)?[^\n]{0,80}?<<",
    re.IGNORECASE,
)
_ADMIN_GROUP_SUDO_POLICY = re.compile(
    ADMIN_GROUP_SUDO_POLICY_PATTERN,
    re.IGNORECASE | re.MULTILINE,
)
_SUDO_POLICY_GRANT = re.compile(
    SUDO_POLICY_GRANT_PATTERN,
    re.IGNORECASE | re.MULTILINE,
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


def _first_matching_line(text: str, pattern: re.Pattern) -> Optional[int]:
    match = pattern.search(text)
    return None if match is None else text[:match.start()].count("\n") + 1


def _line_emits_message(lines: List[str], line_number: int) -> bool:
    """Report whether a line is documentation rather than active configuration."""

    if line_number < 1 or line_number > len(lines):
        return False
    return _MESSAGE_COMMAND.search(mask_shell_quoted_text(lines[line_number - 1])) is not None


def _first_config_line(text: str, pattern: re.Pattern) -> Optional[int]:
    """Find the first matching line that is not echoed or printed as a message."""

    lines = text.splitlines()
    for match in pattern.finditer(text):
        line_number = text[:match.start()].count("\n") + 1
        if not _line_emits_message(lines, line_number):
            return line_number
    return None


def _heredoc_body(lines: List[str], start: int, marker: str) -> str:
    """Return the bounded body lines of a heredoc, without executing anything."""

    body: List[str] = []
    for line in lines[start:start + _MAX_HEREDOC_LINES]:
        if line.strip() == marker:
            break
        body.append(line)
    return "\n".join(body)


def _literal_credential_event(text: str) -> Tuple[Optional[int], bool]:
    """Find package-controlled assignment of a literal account password.

    The command must appear in shell command position in the quote-masked view
    so documentation is never treated as an assignment, while the credential
    itself is read from the raw line. A ``chpasswd`` heredoc body counts as part
    of the same command. Returns the one-based line and whether the credential
    targets the ``root`` account.
    """

    lines = text.splitlines()
    for index, line in enumerate(lines):
        masked_line = mask_shell_quoted_text(line)
        if _CREDENTIAL_COMMAND.search(masked_line) is None:
            continue
        region = line
        if _LITERAL_ACCOUNT_CREDENTIAL.search(region) is None:
            marker = _HEREDOC_MARKER.search(line)
            if marker is None:
                continue
            region = _heredoc_body(lines, index + 1, marker.group("marker"))
            if _LITERAL_ACCOUNT_CREDENTIAL.search(region) is None:
                continue
        return index + 1, _ROOT_ACCOUNT_CREDENTIAL.search(region) is not None
    return None, False


def find_account_backdoor_signals(text: str) -> List[AccountBackdoorSignal]:
    """Return secret-free behaviors of a package-controlled privileged account.

    A package that creates a system account is ordinary. Creating an
    interactive account with a password the package itself carries, granting it
    privilege, and exposing SSH is a different semantic event, so the behaviors
    are reported separately and correlated by the caller. Command-shaped
    behaviors must appear in shell command position, and configuration values
    are ignored when the line only prints a message. Labels are fixed strings:
    no observed account name, password, or hash is ever included.
    """

    text = _strip_shell_comments(text)
    signals: List[AccountBackdoorSignal] = []

    credential_line, targets_root = _literal_credential_event(text)
    if credential_line is not None:
        signals.append(AccountBackdoorSignal(
            "privileged_credential" if targets_root else "account_credential",
            "package-controlled account password is set to a literal value",
            credential_line,
            False,
        ))

    group_line = _find_command_behavior(text, _GROUP_MEMBERSHIP_COMMAND, _ADMINISTRATIVE_GROUP)
    if group_line is not None:
        signals.append(AccountBackdoorSignal(
            "administrative_group",
            "package-controlled account gains administrative group membership",
            group_line,
            False,
        ))

    grant_line = _first_matching_line(text, _SUDO_POLICY_GRANT)
    if grant_line is not None:
        signals.append(AccountBackdoorSignal(
            "sudo_grant",
            "package logic contains a sudo policy grant",
            grant_line,
            False,
        ))

    service_line = _find_command_behavior(text, _SYSTEMCTL_COMMAND, _SSH_SERVICE_ARGUMENT)
    if service_line is not None:
        signals.append(AccountBackdoorSignal(
            "ssh_service",
            "package enables or starts the SSH service",
            service_line,
            True,
        ))

    password_line = _first_config_line(text, _SSH_PASSWORD_AUTHENTICATION)
    if password_line is not None:
        signals.append(AccountBackdoorSignal(
            "ssh_password_auth",
            "package enables SSH password authentication",
            password_line,
            True,
        ))

    config_line = _first_matching_line(text, _SSHD_CONFIG_WRITE)
    if config_line is not None:
        signals.append(AccountBackdoorSignal(
            "ssh_config_write",
            "package writes SSH daemon configuration",
            config_line,
            True,
        ))
    return signals


ACCOUNT_CREDENTIAL_KINDS = ("account_credential", "privileged_credential")
ACCOUNT_PRIVILEGE_KINDS = ("administrative_group", "sudo_grant", "privileged_credential")
ACCOUNT_SSH_EXPOSURE_KINDS = ("ssh_service", "ssh_password_auth", "ssh_config_write")
