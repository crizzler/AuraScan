import argparse
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from aurascan.core.ai_provider import (
    call_ai_provider,
    resolve_ai_config,
    safe_provider_error_detail,
)
from aurascan.core.hardware_health import (
    HARDWARE_HEALTH_PROBE_ID,
    question_requests_hardware_context,
)
from aurascan.core.followup import (
    EXIT_FOLLOWUP_ACTION_FAILED,
    EXIT_FOLLOWUP_PROVIDER_ERROR,
    EXIT_FOLLOWUP_UNAVAILABLE,
    FollowUpActionOutcome,
    FollowUpContext,
    FollowUpProbeResult,
    FollowUpRuntime,
    FollowUpTurn,
    build_default_runtime,
    classify_followup_failure,
    context_from_latest_saved_incident,
    context_from_saved_incident,
    current_user_uid,
    ensure_hardware_health_probe,
    followup_context_fingerprint,
    latest_followup_context,
    load_followup_context,
    persist_followup_context,
    redact_followup_structure,
    redact_followup_text,
    user_followup_root,
)
from aurascan.core.trusted_tools import (
    TrustedTool,
    TrustedToolError,
    capture_trusted_system_tool,
    revalidate_trusted_system_tool,
)
from aurascan.core.text_safety import (
    load_strict_json_object,
    validate_model_advisory_text,
)


AGENT_SCHEMA_VERSION = "1.0"
AGENT_REPORT_TYPE = "agent_session"
AGENT_ACCESS_ENV = "AURASCAN_AGENT_ACCESS"
AGENT_APPROVAL_ENV = "AURASCAN_AGENT_APPROVAL"
AGENT_OUTPUT_SHARING_ENV = "AURASCAN_AGENT_OUTPUT_SHARING"
AGENT_SESSION_TIMEOUT_ENV = "AURASCAN_AGENT_SESSION_TIMEOUT"
AGENT_ROOT_ALLOWED_ENV = "AURASCAN_AGENT_ROOT_ALLOWED"
AGENT_ROOT_MAX_APPROVAL_ENV = "AURASCAN_AGENT_ROOT_MAX_APPROVAL"
AGENT_ROOT_MAX_MINUTES_ENV = "AURASCAN_AGENT_ROOT_MAX_MINUTES"
AGENT_ROOT_POLICY_PATH = Path("/etc/aurascan/agent.conf")
AGENT_RUNTIME_ROOT = Path("/run/aurascan-agent")
AGENT_ROOT_AUDIT_ROOT = Path("/var/lib/aurascan/agent")
AGENT_RECOVERY_RUNTIME_MARKER = Path("/run/aurascan-recovery/environment")
AGENT_TRUSTED_SUDO_PATH = Path("/usr/bin/sudo")
AGENT_TRUSTED_HELPER_PATH = Path("/usr/bin/aurascan")
AGENT_PRIVILEGED_TOOLS_ERROR = (
    "privileged agent tools are unavailable, unsafe, or changed"
)
AGENT_COMMAND_POLICY_ERROR = (
    "agent command violates AuraScan's local-only execution policy"
)
AGENT_AI_RESPONSE_ERROR = "AI response rejected by guarded agent contract"
AGENT_OUTPUT_LIMIT_ERROR = "command output exceeded AuraScan's fixed capture limit"
AGENT_OUTPUT_CAPTURE_ERROR = "command output could not be captured safely"

AGENT_ACCESS_VALUES = ("guarded", "user-shell", "root-shell")
AGENT_APPROVAL_VALUES = ("each-command", "whole-plan", "session")
AGENT_OUTPUT_VALUES = ("redacted", "full")
AGENT_ACCESS_ORDER = {value: index for index, value in enumerate(AGENT_ACCESS_VALUES)}
AGENT_APPROVAL_ORDER = {value: index for index, value in enumerate(AGENT_APPROVAL_VALUES)}

AGENT_DEFAULT_SESSION_MINUTES = 30
AGENT_MAX_SESSION_MINUTES = 120
AGENT_DEFAULT_COMMAND_TIMEOUT = 120
AGENT_MAX_COMMAND_TIMEOUT = 1800
AGENT_MAX_COMMAND_CHARS = 8192
AGENT_MAX_COMMANDS_PER_PLAN = 10
AGENT_MAX_COMMANDS_PER_SESSION = 30
AGENT_MAX_PROVIDER_REQUESTS = 40
AGENT_MAX_QUESTIONS = 20
AGENT_MAX_PROMPT_CHARS = 12000
AGENT_MAX_AI_RESPONSE_CHARS = 32 * 1024
AGENT_MAX_AI_OUTPUT_PER_COMMAND = 32 * 1024
AGENT_MAX_AI_OUTPUT_PER_SESSION = 128 * 1024
AGENT_MAX_RETAINED_OUTPUT = 128 * 1024
AGENT_MAX_COMMAND_OUTPUT_BYTES = 128 * 1024
AGENT_OUTPUT_READ_CHUNK = 4096
AGENT_MAX_REQUEST_BYTES = 256 * 1024
AGENT_RETENTION_DAYS = 30
AGENT_MAX_AUDITS = 50
AGENT_ROOT_GRANT_PHRASE = "GRANT AI ROOT REPAIR COMMANDS"
AGENT_RAW_OUTPUT_PHRASE = "SHARE FULL TERMINAL OUTPUT"
AGENT_NO_SNAPSHOT_PHRASE = "CONTINUE WITHOUT ROLLBACK"

EXIT_AGENT_CONFIG_ERROR = 73
EXIT_AGENT_EXECUTION_FAILED = 74
EXIT_AGENT_ROOT_REFUSED = 75

SAFE_SESSION_ID_RE = re.compile(r"^agent-[a-f0-9]{32}$")
CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
ANSI_ESCAPE_RE = re.compile(
    r"\x1b(?:\][^\x07]*(?:\x07|\x1b\\)|\[[0-?]*[ -/]*[@-~])"
)
AGENT_REMOTE_REFERENCE_RE = re.compile(
    r"(?:\b[a-z][a-z0-9+.-]{1,20}://|\bwww\.|"
    r"(?:[a-z0-9_.-]+@)?(?:[a-z0-9-]+\.)+[a-z]{2,63}:|"
    r"\[[0-9a-f:]+\]:|/dev/(?:tcp|udp)/)",
    re.IGNORECASE,
)
AGENT_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
AGENT_ENCODED_ESCAPE_RE = re.compile(
    r"\\(?:x[0-9a-fA-F]{2}|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|[0-7]{2,3})"
)
AGENT_SENSITIVE_PATH_RE = re.compile(
    r"(?:^|/)(?:\.aws|\.azure|\.docker|\.gnupg|\.kube|\.ssh|keyrings?|secrets?)(?:/|$)|"
    r"^/etc/(?:gshadow|shadow|sudoers)(?:$|[./])|"
    r"^/etc/(?:ssh|sudoers\.d)/|"
    r"^/(?:proc/(?:kcore|(?:self|[0-9]+)/(?:environ|mem))|run/(?:credentials|secrets))(?:/|$)|"
    r"(?:^|/)(?:\.env|auth\.json|credentials(?:\.json)?|id_(?:dsa|ecdsa|ed25519|rsa))(?:$|\.)",
    re.IGNORECASE,
)
AGENT_FORBIDDEN_PROGRAMS = {
    # Network clients and remote shells/copies.
    "aria2c",
    "curl",
    "fetch",
    "ftp",
    "git",
    "gpg",
    "gpg2",
    "hg",
    "lftp",
    "nc",
    "ncat",
    "netcat",
    "rclone",
    "rsync",
    "scp",
    "sftp",
    "socat",
    "ssh",
    "svn",
    "bzr",
    "cvs",
    "fossil",
    "telnet",
    "wget",
    "wget2",
    # AUR helpers and package/source build front ends.
    "aura",
    "aurman",
    "bauerbill",
    "pakku",
    "pacaur",
    "pamac",
    "paru",
    "pikaur",
    "rua",
    "shelly",
    "trizen",
    "yay",
    "yaourt",
    "makepkg",
    "pkgctl",
    "archbuild",
    "mkarchroot",
    "cmake",
    "gmake",
    "make",
    "meson",
    "ninja",
    "scons",
    "bazel",
    "buck",
    "cargo",
    "rustc",
    "go",
    "gcc",
    "g++",
    "cc",
    "c++",
    "clang",
    "clang++",
    "ld",
    "as",
    "javac",
    "gradle",
    "mvn",
    "ant",
    "npm",
    "npx",
    "pnpm",
    "yarn",
    "bun",
    "pip",
    "pip3",
    "pipx",
    "uv",
    "gem",
    "composer",
    "luarocks",
    "cpan",
    "cpanm",
    "pear",
    "pecl",
    # Interpreters, loaders, command multiplexers, and persistence launchers.
    "bash",
    "dash",
    "fish",
    "ksh",
    "sh",
    "zsh",
    "python",
    "python2",
    "python3",
    "perl",
    "ruby",
    "php",
    "node",
    "deno",
    "lua",
    "luajit",
    "eval",
    "exec",
    "source",
    "xargs",
    "busybox",
    "toybox",
    "parallel",
    "run-parts",
    "chroot",
    "unshare",
    "nsenter",
    "proot",
    "bwrap",
    "systemd-run",
    "systemd-nspawn",
    "at",
    "batch",
    "crontab",
    # General package/network installers other than guarded /usr/bin/pacman.
    "apt",
    "apt-get",
    "dnf",
    "flatpak",
    "snap",
    "zypper",
    "systemd-sysupdate",
    # Dynamic decoders and interactive tools with shell escape surfaces.
    "base64",
    "basenc",
    "openssl",
    "uudecode",
    "unzip",
    "gunzip",
    "bunzip2",
    "unxz",
    "unzstd",
    "vi",
    "vim",
    "nvim",
    "emacs",
    "less",
    "more",
    "gdb",
    "lldb",
}
AGENT_SHELL_RESERVED_WORDS = {
    "alias",
    "builtin",
    "case",
    "coproc",
    "declare",
    "do",
    "done",
    "elif",
    "else",
    "enable",
    "esac",
    "export",
    "fi",
    "for",
    "function",
    "if",
    "in",
    "local",
    "readonly",
    "select",
    "then",
    "time",
    "trap",
    "typeset",
    "unalias",
    "until",
    "while",
}
AGENT_PACMAN_UNSAFE_LONG_OPTIONS = {
    "--arch",
    "--cachedir",
    "--config",
    "--dbpath",
    "--gpgdir",
    "--hookdir",
    "--logfile",
    "--root",
    "--sysroot",
    "--upgrade",
    "--assume-installed",
    "--database",
    "--ignore",
    "--ignoregroup",
    "--nodeps",
    "--overwrite",
}
AGENT_PACMAN_ALLOWED_LONG_OPTIONS = {
    "--asdeps",
    "--asexplicit",
    "--changelog",
    "--check",
    "--clean",
    "--color",
    "--confirm",
    "--debug",
    "--deps",
    "--deptest",
    "--disable-download-timeout",
    "--downloadonly",
    "--explicit",
    "--file",
    "--files",
    "--foreign",
    "--groups",
    "--help",
    "--info",
    "--list",
    "--machinereadable",
    "--native",
    "--needed",
    "--noconfirm",
    "--nosave",
    "--owns",
    "--print",
    "--query",
    "--quiet",
    "--recursive",
    "--refresh",
    "--regex",
    "--remove",
    "--search",
    "--sync",
    "--sysupgrade",
    "--unneeded",
    "--unrequired",
    "--upgrades",
    "--verbose",
    "--version",
}
AGENT_ALLOWED_SHELL_BUILTINS = {
    ":",
    "echo",
    "false",
    "printf",
    "pwd",
    "test",
    "true",
}
AGENT_ALLOWED_LOCAL_DIAGNOSTICS = {
    "b2sum",
    "basename",
    "blkid",
    "cat",
    "cut",
    "df",
    "dirname",
    "dmesg",
    "du",
    "file",
    "find",
    "findmnt",
    "free",
    "grep",
    "groups",
    "head",
    "hostname",
    "hostnamectl",
    "id",
    "ip",
    "journalctl",
    "loginctl",
    "lscpu",
    "ls",
    "lsblk",
    "lsof",
    "lsmod",
    "lspci",
    "lsusb",
    "md5sum",
    "modinfo",
    "mountpoint",
    "namei",
    "networkctl",
    "nproc",
    "pactree",
    "pgrep",
    "pidof",
    "printenv",
    "ps",
    "readlink",
    "realpath",
    "rg",
    "sensors",
    "sha1sum",
    "sha224sum",
    "sha256sum",
    "sha384sum",
    "sha512sum",
    "sort",
    "ss",
    "stat",
    "strings",
    "sysctl",
    "systemctl",
    "tail",
    "timedatectl",
    "tr",
    "uname",
    "uniq",
    "uptime",
    "users",
    "vercmp",
    "wc",
    "who",
    "whoami",
}


@dataclass
class AgentConfig:
    access: str = "guarded"
    approval: str = "each-command"
    output_sharing: str = "redacted"
    session_timeout_minutes: int = AGENT_DEFAULT_SESSION_MINUTES
    error: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "access": self.access,
            "approval": self.approval,
            "output_sharing": self.output_sharing,
            "session_timeout_minutes": self.session_timeout_minutes,
            "error": self.error,
        }


@dataclass(frozen=True)
class AgentPrivilegedTools:
    sudo: TrustedTool
    helper: TrustedTool


@dataclass
class AgentRootPolicy:
    allowed: bool = False
    max_approval: str = "each-command"
    max_minutes: int = AGENT_DEFAULT_SESSION_MINUTES
    error: str = ""
    path: Path = AGENT_ROOT_POLICY_PATH

    def to_dict(self) -> Dict[str, object]:
        return {
            "allowed": self.allowed,
            "max_approval": self.max_approval,
            "max_minutes": self.max_minutes,
            "error": self.error,
            "path": str(self.path),
        }


@dataclass
class AgentCommand:
    command: str
    reason: str
    expected_result: str = ""
    cwd: str = ""
    timeout_seconds: int = AGENT_DEFAULT_COMMAND_TIMEOUT
    requires_root: bool = False
    command_id: str = ""

    def __post_init__(self) -> None:
        if not self.command_id:
            material = json.dumps(
                [self.command, self.cwd, self.timeout_seconds, self.requires_root],
                separators=(",", ":"),
            )
            self.command_id = "agent-cmd-" + hashlib.sha256(
                material.encode("utf-8", "replace")
            ).hexdigest()[:16]

    def to_dict(self, *, include_command: bool = True) -> Dict[str, object]:
        data = {
            "command_id": self.command_id,
            "reason": self.reason,
            "expected_result": self.expected_result,
            "cwd": self.cwd,
            "timeout_seconds": self.timeout_seconds,
            "requires_root": self.requires_root,
        }
        if include_command:
            data["command"] = self.command
        return data


@dataclass
class AgentCommandResult:
    command_id: str
    status: str
    exit_code: int
    output: str
    duration_seconds: float
    timed_out: bool = False
    error: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "command_id": self.command_id,
            "status": self.status,
            "exit_code": self.exit_code,
            "output": self.output,
            "duration_seconds": round(self.duration_seconds, 3),
            "timed_out": self.timed_out,
            "error": self.error,
        }


@dataclass
class AgentAIResponse:
    answer: str
    requested_access: str = ""
    referenced_fact_ids: List[str] = field(default_factory=list)
    requested_probe_ids: List[str] = field(default_factory=list)
    requested_action_ids: List[str] = field(default_factory=list)
    commands: List[AgentCommand] = field(default_factory=list)
    status: str = "ok"
    error: str = ""


@dataclass
class AgentSession:
    session_id: str
    context_id: str
    context_fingerprint: str
    access: str
    approval: str
    output_sharing: str
    created_at: int
    expires_at: int
    command_count: int = 0
    provider_requests: int = 0
    questions: int = 0
    snapshot_id: str = ""
    snapshot_waived: bool = False
    root_capability: str = ""
    tty: str = ""
    active_plan_hash: str = ""
    stopped: bool = False
    audit_entries: List[Dict[str, object]] = field(default_factory=list)

    def to_public_dict(self) -> Dict[str, object]:
        return {
            "schema": f"{AGENT_REPORT_TYPE}/{AGENT_SCHEMA_VERSION}",
            "schema_version": AGENT_SCHEMA_VERSION,
            "report_type": AGENT_REPORT_TYPE,
            "session_id": self.session_id,
            "context_id": self.context_id,
            "context_fingerprint": self.context_fingerprint,
            "access": self.access,
            "approval": self.approval,
            "output_sharing": self.output_sharing,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "command_count": self.command_count,
            "provider_requests": self.provider_requests,
            "questions": self.questions,
            "snapshot_id": self.snapshot_id,
            "snapshot_waived": self.snapshot_waived,
            "stopped": self.stopped,
            "audit_entries": list(self.audit_entries),
        }


@dataclass
class AgentSessionResult:
    questions: int = 0
    provider_requests: int = 0
    commands_run: int = 0
    command_failed: bool = False
    provider_failed: bool = False
    stopped: bool = False
    setup_failed: bool = False
    action_outcome: FollowUpActionOutcome = field(default_factory=FollowUpActionOutcome)


def resolve_agent_config(env: Optional[Mapping[str, str]] = None) -> AgentConfig:
    source = os.environ if env is None else env
    access = str(source.get(AGENT_ACCESS_ENV, "guarded") or "guarded").strip().lower()
    approval = str(source.get(AGENT_APPROVAL_ENV, "each-command") or "each-command").strip().lower()
    output = str(source.get(AGENT_OUTPUT_SHARING_ENV, "redacted") or "redacted").strip().lower()
    raw_minutes = str(
        source.get(AGENT_SESSION_TIMEOUT_ENV, str(AGENT_DEFAULT_SESSION_MINUTES))
        or AGENT_DEFAULT_SESSION_MINUTES
    ).strip()
    errors = []
    if access not in AGENT_ACCESS_VALUES:
        errors.append(f"invalid {AGENT_ACCESS_ENV} value")
        access = "guarded"
    if approval not in AGENT_APPROVAL_VALUES:
        errors.append(f"invalid {AGENT_APPROVAL_ENV} value")
        approval = "each-command"
    if output not in AGENT_OUTPUT_VALUES:
        errors.append(f"invalid {AGENT_OUTPUT_SHARING_ENV} value")
        output = "redacted"
    try:
        minutes = int(raw_minutes)
    except ValueError:
        minutes = AGENT_DEFAULT_SESSION_MINUTES
        errors.append(f"invalid {AGENT_SESSION_TIMEOUT_ENV} value")
    if minutes < 1 or minutes > AGENT_MAX_SESSION_MINUTES:
        minutes = AGENT_DEFAULT_SESSION_MINUTES
        errors.append(f"{AGENT_SESSION_TIMEOUT_ENV} must be between 1 and {AGENT_MAX_SESSION_MINUTES}")
    return AgentConfig(access, approval, output, minutes, "; ".join(errors))


def effective_agent_approval(access: str, approval: str) -> str:
    """Return the command approval mode enforced by the current runtime.

    Older configuration files may still contain ``whole-plan`` or ``session``.
    Keep accepting those values so an upgrade does not make the configuration
    unreadable, but never let either value authorize model-authored shell text.
    """
    if access in {"user-shell", "root-shell"}:
        return "each-command"
    return approval


def read_agent_root_policy(
    path: Path = AGENT_ROOT_POLICY_PATH,
    *,
    required_uid: int = 0,
) -> AgentRootPolicy:
    if not path.exists():
        return AgentRootPolicy(path=path)
    try:
        if path.is_symlink() or not path.is_file():
            return AgentRootPolicy(error="agent root policy is not a regular file", path=path)
        metadata = path.stat()
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return AgentRootPolicy(error=f"agent root policy could not be read: {exc}", path=path)
    if metadata.st_uid != required_uid or metadata.st_mode & 0o022:
        return AgentRootPolicy(
            error="agent root policy ownership or permissions are unsafe",
            path=path,
        )
    values: Dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip("\"'")
    allowed_raw = values.get(AGENT_ROOT_ALLOWED_ENV, "0").strip().lower()
    if allowed_raw not in {"0", "1"}:
        return AgentRootPolicy(error=f"invalid {AGENT_ROOT_ALLOWED_ENV} value", path=path)
    approval = values.get(AGENT_ROOT_MAX_APPROVAL_ENV, "each-command").strip().lower()
    if approval not in AGENT_APPROVAL_VALUES:
        return AgentRootPolicy(error=f"invalid {AGENT_ROOT_MAX_APPROVAL_ENV} value", path=path)
    try:
        minutes = int(values.get(AGENT_ROOT_MAX_MINUTES_ENV, str(AGENT_DEFAULT_SESSION_MINUTES)))
    except ValueError:
        return AgentRootPolicy(error=f"invalid {AGENT_ROOT_MAX_MINUTES_ENV} value", path=path)
    if minutes < 1 or minutes > AGENT_MAX_SESSION_MINUTES:
        return AgentRootPolicy(
            error=f"{AGENT_ROOT_MAX_MINUTES_ENV} must be between 1 and {AGENT_MAX_SESSION_MINUTES}",
            path=path,
        )
    return AgentRootPolicy(allowed_raw == "1", approval, minutes, path=path)


def write_agent_root_policy(
    allowed: bool,
    max_approval: str,
    max_minutes: int,
    path: Path = AGENT_ROOT_POLICY_PATH,
    *,
    require_root: bool = True,
) -> Tuple[bool, str]:
    approval = str(max_approval or "").strip().lower()
    if approval not in AGENT_APPROVAL_VALUES:
        return False, f"Invalid agent root approval policy: {max_approval}"
    try:
        minutes = int(max_minutes)
    except (TypeError, ValueError):
        return False, "Agent root session duration must be an integer."
    if minutes < 1 or minutes > AGENT_MAX_SESSION_MINUTES:
        return False, f"Agent root session duration must be between 1 and {AGENT_MAX_SESSION_MINUTES} minutes."
    if require_root and (not hasattr(os, "geteuid") or os.geteuid() != 0):
        return False, "AuraScan agent root policy writes require root privileges."
    content = (
        f"{AGENT_ROOT_ALLOWED_ENV}={'1' if allowed else '0'}\n"
        f"{AGENT_ROOT_MAX_APPROVAL_ENV}={approval}\n"
        f"{AGENT_ROOT_MAX_MINUTES_ENV}={minutes}\n"
    )
    try:
        path.parent.mkdir(parents=True, mode=0o755, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=".agent.", dir=str(path.parent), text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(content)
            os.chmod(tmp_name, 0o644)
            os.replace(tmp_name, path)
            os.chmod(path, 0o644)
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
    except OSError as exc:
        return False, f"Could not write AuraScan agent root policy: {exc}"
    state = "allowed" if allowed else "disabled"
    return True, f"AuraScan policy-gated root repair access is {state}."


def configure_agent_root_policy(
    allowed: bool,
    max_approval: str,
    max_minutes: int,
    *,
    runner: Callable = subprocess.run,
    helper: Path = Path("/usr/bin/aurascan"),
    which: Callable[[str], Optional[str]] = shutil.which,
) -> Tuple[bool, str]:
    if max_approval not in AGENT_APPROVAL_VALUES:
        return False, f"Invalid agent root approval policy: {max_approval}"
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return write_agent_root_policy(allowed, max_approval, max_minutes)
    try:
        privileged_tools = _capture_agent_privileged_tools(helper, which=which)
    except TrustedToolError:
        return False, (
            "Agent root policy configuration requires trusted package-managed "
            "/usr/bin/sudo and /usr/bin/aurascan."
        )
    command = [
        privileged_tools.sudo.path,
        "--",
        privileged_tools.helper.path,
        "agent",
        "--set-root-policy",
        "1" if allowed else "0",
        "--root-max-approval",
        max_approval,
        "--root-max-minutes",
        str(max_minutes),
    ]
    try:
        _revalidate_agent_privileged_tools(privileged_tools)
        result = runner(command, capture_output=True, text=True, check=False)
    except TrustedToolError:
        return False, (
            "Agent root policy configuration refused because trusted privileged tools changed."
        )
    except OSError as exc:
        return False, f"Could not configure AuraScan agent root policy: {exc}"
    if int(getattr(result, "returncode", 1)) != 0:
        detail = redact_followup_text((getattr(result, "stderr", "") or "").strip())[:500]
        return False, detail or f"Agent root policy command failed with exit code {result.returncode}."
    state = "allowed" if allowed else "disabled"
    return True, f"AuraScan policy-gated root repair access is {state}."


def build_agent_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aurascan agent",
        description="Open AuraScan's foreground contextual repair agent.",
    )
    parser.add_argument("context_id", nargs="?", help="retained follow-up context or incident report ID")
    parser.add_argument("--latest", action="store_true", help="open the newest retained AuraScan context")
    parser.add_argument("--access", choices=AGENT_ACCESS_VALUES, help="requested access for this session")
    parser.add_argument("--approval", choices=AGENT_APPROVAL_VALUES, help="command approval mode")
    parser.add_argument("--output-sharing", choices=AGENT_OUTPUT_VALUES, help="AI command-output sharing mode")
    parser.add_argument("--session-timeout", type=int, metavar="MINUTES", help="session duration in minutes")
    parser.add_argument("--facts-only", action="store_true", help="omit evidence excerpts from AI requests")
    parser.add_argument("--set-root-policy", choices=("0", "1"), help=argparse.SUPPRESS)
    parser.add_argument("--root-max-approval", choices=AGENT_APPROVAL_VALUES, help=argparse.SUPPRESS)
    parser.add_argument("--root-max-minutes", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--issue-root-session", metavar="REQUEST", help=argparse.SUPPRESS)
    parser.add_argument("--execute-request", metavar="REQUEST", help=argparse.SUPPRESS)
    parser.add_argument("--revoke-root-session", metavar="REQUEST", help=argparse.SUPPRESS)
    return parser


def user_agent_root(env: Optional[Mapping[str, str]] = None) -> Path:
    source = os.environ if env is None else env
    state_home = str(source.get("XDG_STATE_HOME") or "").strip()
    base = Path(state_home) if state_home else Path.home() / ".local" / "state"
    return base / "aurascan" / "agent"


def _ensure_private_dir(path: Path, *, mode: int = 0o700) -> None:
    path.mkdir(parents=True, mode=mode, exist_ok=True)
    if path.is_symlink() or not path.is_dir():
        raise OSError(f"unsafe directory: {path}")
    os.chmod(path, mode)


def _atomic_private_json(path: Path, value: object, *, mode: int = 0o600) -> None:
    _ensure_private_dir(path.parent)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent), text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
        os.chmod(path, mode)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def _redact_agent_text(value: object, env: Optional[Mapping[str, str]] = None) -> str:
    text = redact_followup_text(value)
    source = os.environ if env is None else env
    for key, secret in source.items():
        if (
            len(str(secret)) >= 6
            and any(token in key.upper() for token in ("KEY", "TOKEN", "SECRET", "PASSWORD"))
        ):
            text = text.replace(str(secret), "<redacted>")
    return text


def scrub_agent_helper_environment() -> None:
    for key in list(os.environ):
        upper = key.upper()
        if (
            upper == "AURASCAN_AI_KEY"
            or upper.startswith("AURASCAN_") and any(
                marker in upper for marker in ("API_KEY", "TOKEN", "SECRET", "PASSWORD")
            )
        ):
            os.environ.pop(key, None)


def persist_agent_audit(
    session: AgentSession,
    *,
    root: Optional[Path] = None,
    env: Optional[Mapping[str, str]] = None,
) -> Path:
    audit_root = root or user_agent_root(env)
    _ensure_private_dir(audit_root)
    path = audit_root / f"{session.session_id}.json"
    _atomic_private_json(path, redact_followup_structure(session.to_public_dict()))
    prune_agent_audits(audit_root)
    return path


def prune_agent_audits(root: Path, *, now: Optional[float] = None) -> None:
    now = time.time() if now is None else now
    cutoff = now - AGENT_RETENTION_DAYS * 86400
    try:
        paths = sorted(root.glob("agent-*.json"), key=lambda item: item.stat().st_mtime, reverse=True)
    except OSError:
        return
    for index, path in enumerate(paths):
        try:
            remove = index >= AGENT_MAX_AUDITS or path.stat().st_mtime < cutoff
        except OSError:
            continue
        if remove:
            try:
                path.unlink()
            except OSError:
                pass


def _known_ids(raw: object, known: set, limit: int) -> List[str]:
    if not isinstance(raw, list):
        return []
    result = []
    for item in raw:
        value = str(item or "")
        if value in known and value not in result:
            result.append(value)
        if len(result) >= limit:
            break
    return result


def _contains_active_shell_expansion(command: str) -> bool:
    """Detect expansion syntax outside inert single-quoted shell text."""

    single_quoted = False
    double_quoted = False
    escaped = False
    previous = ""
    for char in command:
        if single_quoted:
            if char == "'":
                single_quoted = False
            previous = char
            continue
        if escaped:
            escaped = False
            previous = char
            continue
        if char == "\\":
            escaped = True
            previous = char
            continue
        if char == "'" and not double_quoted:
            single_quoted = True
            previous = char
            continue
        if char == '"':
            double_quoted = not double_quoted
            previous = char
            continue
        if char == "#" and not double_quoted and (
            not previous or previous.isspace() or previous in ";&|()"
        ):
            break
        if char in {"$", "`"}:
            return True
        previous = char
    return False


def _contains_active_path_expansion(command: str) -> bool:
    """Reject unquoted glob, brace, character-class, and tilde expansion."""

    single_quoted = False
    double_quoted = False
    escaped = False
    previous = ""
    for char in command:
        if single_quoted:
            if char == "'":
                single_quoted = False
            previous = char
            continue
        if escaped:
            escaped = False
            previous = char
            continue
        if char == "\\":
            escaped = True
            previous = char
            continue
        if char == "'" and not double_quoted:
            single_quoted = True
            previous = char
            continue
        if char == '"':
            double_quoted = not double_quoted
            previous = char
            continue
        if char == "#" and not double_quoted and (
            not previous or previous.isspace() or previous in ";&|()"
        ):
            break
        if not double_quoted and char in "*?[]{}~":
            return True
        previous = char
    return False


def _agent_sensitive_path(tokens: Sequence[str], cwd: str) -> bool:
    base = Path(cwd) if cwd else Path.cwd()
    for raw_token in tokens:
        if AGENT_SENSITIVE_PATH_RE.search(raw_token):
            return True
        if (
            not raw_token
            or all(char in ";&|<>()" for char in raw_token)
        ):
            continue
        token = raw_token
        if token.startswith("-"):
            if "=" in token:
                token = token.partition("=")[2]
            elif "/" in token:
                token = token[token.find("/") :]
            else:
                continue
        if not token:
            continue
        candidate = Path(token)
        if not candidate.is_absolute():
            candidate = base / candidate
        try:
            resolved = candidate.resolve(strict=False)
        except (OSError, RuntimeError):
            continue
        if AGENT_SENSITIVE_PATH_RE.search(str(resolved)):
            return True
        try:
            mode = resolved.stat().st_mode
        except OSError:
            continue
        if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
            return True
    try:
        resolved_base = base.resolve(strict=False)
    except (OSError, RuntimeError):
        return True
    return AGENT_SENSITIVE_PATH_RE.search(str(resolved_base)) is not None


def _lex_agent_command(command: str) -> List[str]:
    try:
        lexer = shlex.shlex(
            command,
            posix=True,
            punctuation_chars=";&|<>()",
        )
        lexer.whitespace_split = True
        lexer.commenters = "#"
        return list(lexer)
    except ValueError:
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)


def _agent_command_segments(tokens: Sequence[str]) -> List[List[str]]:
    segments: List[List[str]] = []
    current: List[str] = []
    for token in tokens:
        if token and all(char in ";&|<>()" for char in token):
            if any(char in "<>()" for char in token):
                raise ValueError(AGENT_COMMAND_POLICY_ERROR)
            if "&" in token and token != "&&":
                raise ValueError(AGENT_COMMAND_POLICY_ERROR)
            if not current:
                raise ValueError(AGENT_COMMAND_POLICY_ERROR)
            segments.append(current)
            current = []
            continue
        current.append(token)
    if current:
        segments.append(current)
    elif tokens:
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    return segments


def _agent_program_and_args(segment: Sequence[str]) -> Tuple[str, List[str]]:
    if not segment:
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if any(token in AGENT_SHELL_RESERVED_WORDS for token in segment):
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if AGENT_ASSIGNMENT_RE.match(segment[0]):
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    index = 0
    if segment[index] == "command":
        index += 1
        if index < len(segment) and segment[index] in {"-v", "-V"}:
            # A command-name lookup is local and does not invoke its operand.
            return "command-lookup", list(segment[index + 1 :])
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if index >= len(segment):
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    program = segment[index]
    args = list(segment[index + 1 :])
    if program == ".":
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if any(char in program for char in "*?[]{}"):
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if "/" in program:
        path = Path(program)
        if not path.is_absolute() or str(path.parent) not in {
            "/bin",
            "/sbin",
            "/usr/bin",
            "/usr/sbin",
        }:
            raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    return Path(program).name.lower(), args


def _validate_agent_pacman_command(program_token: str, args: Sequence[str]) -> None:
    if program_token != "/usr/bin/pacman":
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if not args:
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    operations: List[str] = []
    short_allowed = {
        "F": set("Fylxqvh"),
        "Q": set("Qcdegiklmnopqstuvh"),
        "R": set("Rnsuqvh"),
        "S": set("Sygwupcilsqvh"),
        "T": set("Tqvh"),
    }
    long_operations = {
        "--deptest": "T",
        "--files": "F",
        "--query": "Q",
        "--remove": "R",
        "--sync": "S",
    }
    for token in args:
        lowered = token.lower()
        option = lowered.partition("=")[0]
        if option in AGENT_PACMAN_UNSAFE_LONG_OPTIONS:
            raise ValueError(AGENT_COMMAND_POLICY_ERROR)
        if token.startswith("--"):
            if option not in AGENT_PACMAN_ALLOWED_LONG_OPTIONS:
                raise ValueError(AGENT_COMMAND_POLICY_ERROR)
            operation = long_operations.get(option)
            if operation:
                operations.append(operation)
            continue
        if token.startswith("-") and token != "-":
            if token == "-V":
                continue
            operation_letters = [char for char in token[1:] if char in short_allowed]
            selected = [char for char in operation_letters if char in {"F", "Q", "R", "S", "T"}]
            if len(selected) != 1:
                raise ValueError(AGENT_COMMAND_POLICY_ERROR)
            operation = selected[0]
            if any(char not in short_allowed[operation] for char in token[1:]):
                raise ValueError(AGENT_COMMAND_POLICY_ERROR)
            operations.append(operation)
    distinct_operations = set(operations)
    version_only = any(token in {"-V", "--version", "--help"} for token in args)
    if len(distinct_operations) > 1 or (not distinct_operations and not version_only):
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    operation = next(iter(distinct_operations), "")
    if operation in {"S", "R"}:
        target_re = re.compile(
            r"^(?!\.)[A-Za-z0-9@._+:-]+(?:/(?!\.)[A-Za-z0-9@._+:-]+)?$"
        )
        for token in args:
            if token == "--" or token.startswith("-"):
                continue
            if not target_re.fullmatch(token):
                raise ValueError(AGENT_COMMAND_POLICY_ERROR)
            if token.rpartition("/")[2].lower() == "aurascan":
                raise ValueError(AGENT_COMMAND_POLICY_ERROR)


def _first_agent_subcommand(args: Sequence[str]) -> str:
    for token in args:
        if token == "--":
            continue
        if not token.startswith("-"):
            return token
    return ""


def _validate_agent_read_only_diagnostic(program: str, args: Sequence[str]) -> None:
    if program == "cat" and (
        not args or any(token == "-" for token in args)
    ):
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if program == "blkid" and any(
        token in {"-g", "-w", "--garbage-collect", "--write-cache"}
        or token.startswith("--write-cache=")
        for token in args
    ):
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if program == "dmesg" and any(
        token in {
            "-c",
            "-C",
            "-D",
            "-E",
            "-n",
            "-w",
            "-W",
            "--clear",
            "--console-off",
            "--console-on",
            "--console-level",
            "--follow",
            "--follow-new",
        }
        or token.startswith("--console-level=")
        or (
            token.startswith("-")
            and not token.startswith("--")
            and any(flag in token[1:] for flag in "wW")
        )
        for token in args
    ):
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if program == "file" and any(
        token in {"-C", "--compile"} for token in args
    ):
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if program == "find" and any(
        token in {
            "-delete",
            "-exec",
            "-execdir",
            "-fls",
            "-fprint",
            "-fprint0",
            "-fprintf",
            "-ok",
            "-okdir",
        }
        for token in args
    ):
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if program == "hostname":
        allowed = {
            "-A",
            "-d",
            "-f",
            "-i",
            "-I",
            "-s",
            "--all-fqdns",
            "--all-ip-addresses",
            "--domain",
            "--fqdn",
            "--ip-address",
            "--short",
        }
        if any(token not in allowed for token in args):
            raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if program in {"hostnamectl", "loginctl", "systemctl", "timedatectl"} and any(
        token in {"-H", "-M", "--host", "--machine", "--root", "--image"}
        or (token.startswith(("-H", "-M")) and len(token) > 2)
        or token.startswith(("--host=", "--machine=", "--root=", "--image="))
        for token in args
    ):
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if program == "hostnamectl" and any(
        token.startswith("set-") for token in args
    ):
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if program == "hostnamectl" and any(
        not token.startswith("-") and token != "status" for token in args
    ):
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if program == "timedatectl" and any(
        token in {"set-time", "set-timezone", "set-local-rtc", "set-ntp"}
        for token in args
    ):
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if program == "timedatectl" and any(
        not token.startswith("-")
        and token not in {"status", "show", "show-timesync", "timesync-status"}
        for token in args
    ):
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if program == "loginctl" and any(
        token in {
            "activate",
            "attach",
            "enable-linger",
            "flush-devices",
            "kill-session",
            "kill-user",
            "lock-session",
            "lock-sessions",
            "terminate-seat",
            "terminate-session",
            "terminate-user",
            "unlock-session",
            "unlock-sessions",
            "disable-linger",
        }
        for token in args
    ):
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if program == "loginctl":
        safe_loginctl = {
            "list-seats",
            "list-sessions",
            "list-users",
            "seat-status",
            "session-status",
            "show-seat",
            "show-session",
            "show-user",
            "user-status",
        }
        if _first_agent_subcommand(args) not in safe_loginctl:
            raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if program == "networkctl" and any(
        token in {
            "delete",
            "down",
            "edit",
            "forcerenew",
            "label",
            "mask",
            "persist",
            "reconfigure",
            "reload",
            "renew",
            "unmask",
            "up",
        }
        for token in args
    ):
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if program == "networkctl" and _first_agent_subcommand(args) not in {
        "list",
        "lldp",
        "status",
    }:
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if program == "networkctl" and any(
        not token.startswith("-")
        and token not in {"list", "lldp", "status"}
        and not re.fullmatch(r"[A-Za-z0-9_.:@-]+", token)
        for token in args
    ):
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if program == "systemctl":
        safe_subcommands = {
            "cat",
            "get-default",
            "is-active",
            "is-enabled",
            "is-failed",
            "is-system-running",
            "list-dependencies",
            "list-jobs",
            "list-machines",
            "list-sockets",
            "list-timers",
            "list-unit-files",
            "list-units",
            "show",
            "status",
        }
        if _first_agent_subcommand(args) not in safe_subcommands:
            raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if program == "ip" and any(
        token in {
            "add",
            "append",
            "batch",
            "change",
            "delete",
            "del",
            "exec",
            "flush",
            "netns",
            "prepend",
            "replace",
            "restore",
            "set",
        }
        or token in {"-b", "-batch", "--batch"}
        or token.startswith(("-b", "--batch="))
        for token in args
    ):
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if program == "ip":
        non_options = [token for token in args if not token.startswith("-")]
        if non_options:
            object_name = non_options[0]
            if object_name == "monitor":
                raise ValueError(AGENT_COMMAND_POLICY_ERROR)
            safe_ip_actions = {
                "addr": {"", "list", "show"},
                "address": {"", "list", "show"},
                "link": {"", "list", "show"},
                "maddress": {"", "list", "show"},
                "mroute": {"", "list", "show"},
                "neigh": {"", "list", "show"},
                "neighbor": {"", "list", "show"},
                "netconf": {"", "list", "show"},
                "ntable": {"", "list", "show"},
                "route": {"", "get", "list", "show"},
                "rule": {"", "list", "show"},
                "tcp_metrics": {"", "list", "show"},
                "token": {"", "list", "show"},
                "tunnel": {"", "list", "show"},
                "tuntap": {"", "list", "show"},
            }
            action = non_options[1] if len(non_options) > 1 else ""
            if object_name not in safe_ip_actions or action not in safe_ip_actions[object_name]:
                raise ValueError(AGENT_COMMAND_POLICY_ERROR)
            if object_name == "route" and action == "get":
                if len(non_options) < 3:
                    raise ValueError(AGENT_COMMAND_POLICY_ERROR)
                try:
                    ipaddress.ip_address(non_options[2].split("%", 1)[0])
                except ValueError:
                    raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if program == "journalctl" and any(
        token in {
            "-f",
            "--flush",
            "--follow",
            "--relinquish-var",
            "--rotate",
            "--setup-keys",
            "--sync",
            "--update-catalog",
        }
        or token.startswith(
            (
                "--directory=",
                "--file=",
                "--image=",
                "--machine=",
                "--namespace=",
                "--root=",
                "--vacuum-files=",
                "--vacuum-size=",
                "--vacuum-time=",
            )
        )
        or token in {
            "-D",
            "-M",
            "--directory",
            "--file",
            "--image",
            "--machine",
            "--namespace",
            "--root",
            "--vacuum-files",
            "--vacuum-size",
            "--vacuum-time",
        }
        or (token.startswith(("-D", "-M")) and len(token) > 2)
        or token.startswith("--follow=")
        or (
            token.startswith("-")
            and not token.startswith("--")
            and "f" in token[1:]
        )
        for token in args
    ):
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if program == "findmnt" and any(
        token in {"-p", "--poll"} or token.startswith("--poll=")
        for token in args
    ):
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if program == "free" and any(
        token in {"-s", "--seconds"}
        or token.startswith(("-s", "--seconds="))
        for token in args
    ):
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if program == "rg" and any(
        token in {"--pre", "--search-zip", "-z"}
        or token.startswith("--pre=")
        for token in args
    ):
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if program == "lsof":
        if any(
            re.fullmatch(r"[+-]r(?:[0-9]+(?:\.[0-9]+)?)?", token)
            for token in args
        ):
            raise ValueError(AGENT_COMMAND_POLICY_ERROR)
        compact_flags = "".join(
            token[1:]
            for token in args
            if token.startswith("-") and not token.startswith("--")
        )
        if "n" not in compact_flags or "P" not in compact_flags:
            raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if program == "ps" and any(
        token == "e"
        or (
            not token.startswith("-")
            and "e" in token.lower()
            and any(char in token.lower() for char in "auxw")
            and re.fullmatch(r"[A-Za-z]+", token) is not None
        )
        or (
            token.startswith("-")
            and token not in {"-e", "-eF", "-ef"}
            and "e" in token[1:].lower()
            and any(char in token[1:].lower() for char in "auxw")
        )
        or "environ" in token.lower()
        for token in args
    ):
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if program == "sensors" and any(
        token in {"-s", "--set"} for token in args
    ):
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if program == "sort" and any(
        token in {"-o", "--output", "--compress-program"}
        or token.startswith(("--output=", "--compress-program="))
        or (token.startswith("-o") and token != "-o")
        for token in args
    ):
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if program == "ss" and any(
        token in {"-E", "-K", "--events", "--kill", "-r", "--resolve"}
        or token.startswith(("-E", "-K"))
        for token in args
    ):
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if program == "sysctl" and any(
        token in {"-p", "-w", "--load", "--system", "--write"}
        or token.startswith(("--load=", "--write="))
        or token.startswith("-w")
        or ("=" in token and not token.startswith("--pattern="))
        for token in args
    ):
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if program == "tail" and any(
        token in {"-f", "-F", "--follow", "--retry"}
        or token.startswith("--follow=")
        or (
            token.startswith("-")
            and not token.startswith("--")
            and any(flag in token[1:] for flag in "fF")
        )
        for token in args
    ):
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)


def _validate_agent_segment(segment: Sequence[str]) -> None:
    program, args = _agent_program_and_args(segment)
    if program == "command-lookup":
        return
    program_token = segment[0]
    if program == "pacman":
        _validate_agent_pacman_command(program_token, args)
        return
    if program in AGENT_FORBIDDEN_PROGRAMS or re.fullmatch(
        r"(?:python\d+(?:\.\d+)?|gcc-\d+|clang-\d+|ld-linux[^/]*|"
        r"(?:extra|core|multilib|staging)-[^/]*-build)",
        program,
    ):
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if program in AGENT_ALLOWED_SHELL_BUILTINS:
        if "/" in program_token:
            raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    elif program in AGENT_ALLOWED_LOCAL_DIAGNOSTICS:
        if program_token not in {f"/usr/bin/{program}", f"/usr/sbin/{program}"}:
            raise ValueError(AGENT_COMMAND_POLICY_ERROR)
        _validate_agent_read_only_diagnostic(program, args)
    else:
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if program in {"printf", "echo"} and any(
        AGENT_ENCODED_ESCAPE_RE.search(token) for token in args
    ):
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)


def _validate_agent_command_policy(command: str, *, cwd: str = "") -> None:
    if "\n" in command or "\r" in command:
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if any(unicodedata.category(char) == "Cf" for char in command):
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if _contains_active_shell_expansion(command):
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if _contains_active_path_expansion(command):
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    tokens = _lex_agent_command(command)
    if not tokens:
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if AGENT_REMOTE_REFERENCE_RE.search(" ".join(tokens)):
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    if _agent_sensitive_path(tokens, cwd):
        raise ValueError(AGENT_COMMAND_POLICY_ERROR)
    for segment in _agent_command_segments(tokens):
        _validate_agent_segment(segment)


def _validate_agent_id_list(
    value: object,
    *,
    limit: int,
) -> List[str]:
    if not isinstance(value, list) or len(value) > limit:
        raise ValueError("agent response identifier list is invalid")
    result: List[str] = []
    for item in value:
        if (
            not isinstance(item, str)
            or not item
            or len(item) > 256
            or CONTROL_RE.search(item)
        ):
            raise ValueError("agent response identifier list is invalid")
        if item in result:
            raise ValueError("agent response identifier list is invalid")
        result.append(item)
    return result


def validate_agent_command(
    data: Mapping[str, object],
    *,
    access: str,
    allow_command_id: bool = False,
) -> AgentCommand:
    if access not in {"user-shell", "root-shell"}:
        raise ValueError("shell command fields require an active shell grant")
    command_fields = {
        "command",
        "cwd",
        "timeout_seconds",
        "requires_root",
        "reason",
        "expected_result",
    }
    supplied_fields = frozenset(data)
    allowed_fields = {frozenset(command_fields)}
    if allow_command_id:
        allowed_fields.add(frozenset(command_fields | {"command_id"}))
    if supplied_fields not in allowed_fields:
        raise ValueError("agent command schema did not match")
    supplied_command_id = data.get("command_id")
    if supplied_command_id is not None and (
        not isinstance(supplied_command_id, str)
        or not re.fullmatch(r"agent-cmd-[a-f0-9]{16}", supplied_command_id)
    ):
        raise ValueError("agent command identifier is invalid")
    command = data.get("command")
    reason = data.get("reason")
    if not isinstance(command, str) or not command.strip():
        raise ValueError("agent command must be a non-empty string")
    if CONTROL_RE.search(command) or len(command) > AGENT_MAX_COMMAND_CHARS:
        raise ValueError("agent command is unsafe or too large")
    raw_cwd = data.get("cwd")
    if not isinstance(raw_cwd, str):
        raise ValueError("agent command working directory is invalid")
    cwd = raw_cwd
    if cwd:
        candidate = Path(cwd)
        if (
            CONTROL_RE.search(cwd)
            or any(value in cwd for value in ("\n", "\t"))
            or len(cwd) > 4096
            or not candidate.is_absolute()
            or not candidate.is_dir()
        ):
            raise ValueError("agent command working directory is invalid")
    _validate_agent_command_policy(command, cwd=cwd)
    clean_reason = validate_model_advisory_text(
        reason,
        max_chars=1000,
        allow_empty=False,
    )
    expected_result = validate_model_advisory_text(
        data.get("expected_result"),
        max_chars=1000,
    )
    raw_timeout = data.get("timeout_seconds")
    if isinstance(raw_timeout, bool) or not isinstance(raw_timeout, int):
        raise ValueError("agent command timeout is invalid")
    timeout = raw_timeout
    if timeout < 1 or timeout > AGENT_MAX_COMMAND_TIMEOUT:
        raise ValueError("agent command timeout exceeds the allowed range")
    requires_root = data.get("requires_root")
    if not isinstance(requires_root, bool):
        raise ValueError("agent command privilege flag is invalid")
    if access == "user-shell" and requires_root:
        raise ValueError("a user-shell session cannot accept a root command")
    if access == "root-shell" and not requires_root:
        requires_root = True
    validated = AgentCommand(
        command=command,
        reason=clean_reason,
        expected_result=expected_result,
        cwd=cwd,
        timeout_seconds=timeout,
        requires_root=requires_root,
    )
    if supplied_command_id is not None and not secrets.compare_digest(
        supplied_command_id,
        validated.command_id,
    ):
        raise ValueError("agent command identifier does not match its content")
    return validated


def validate_agent_ai_response(
    context: FollowUpContext,
    data: Mapping[str, object],
    *,
    access: str,
) -> AgentAIResponse:
    if set(data) != {
        "answer",
        "requested_access",
        "referenced_fact_ids",
        "requested_probe_ids",
        "requested_action_ids",
        "commands",
    }:
        raise ValueError("agent response schema did not match")
    answer = validate_model_advisory_text(
        data.get("answer"),
        max_chars=4000,
    )
    raw_requested_access = data.get("requested_access")
    if not isinstance(raw_requested_access, str) or len(raw_requested_access) > 32:
        raise ValueError("agent response requested_access is invalid")
    requested_access = raw_requested_access.strip().lower()
    if requested_access and requested_access not in AGENT_ACCESS_VALUES:
        raise ValueError("agent response requested_access is invalid")
    referenced_ids = _validate_agent_id_list(
        data.get("referenced_fact_ids"),
        limit=20,
    )
    probe_ids = _validate_agent_id_list(
        data.get("requested_probe_ids"),
        limit=6,
    )
    action_ids = _validate_agent_id_list(
        data.get("requested_action_ids"),
        limit=20,
    )
    raw_commands = data.get("commands", [])
    if not isinstance(raw_commands, list) or len(raw_commands) > AGENT_MAX_COMMANDS_PER_PLAN:
        raise ValueError("agent response contains too many commands")
    commands = []
    for raw in raw_commands:
        if not isinstance(raw, Mapping):
            raise ValueError("agent response contains a malformed command")
        commands.append(validate_agent_command(raw, access=access))
    known_facts = {item.fact_id for item in context.facts}
    known_probes = {item.probe_id for item in context.probes}
    known_actions = {item.action_id for item in context.actions if item.verified}
    return AgentAIResponse(
        answer=answer,
        requested_access=requested_access,
        referenced_fact_ids=_known_ids(referenced_ids, known_facts, 20),
        requested_probe_ids=_known_ids(probe_ids, known_probes, 6),
        requested_action_ids=_known_ids(action_ids, known_actions, 20),
        commands=commands,
    )


def build_agent_ai_prompt(
    context: FollowUpContext,
    question: str,
    turns: Sequence[FollowUpTurn],
    *,
    access: str,
    approval: str,
    facts_only: bool,
    command_results: Sequence[AgentCommandResult] = (),
    probe_results: Sequence[FollowUpProbeResult] = (),
) -> str:
    approval = effective_agent_approval(access, approval)
    shell_note = (
        "No shell grant is active. commands MUST be empty. You may request user-shell or root-shell access, "
        "but only the user can grant it."
        if access == "guarded"
        else (
            f"An explicit {access} grant is active. You may request exact commands only when they materially "
            "help answer or resolve the user's AuraScan context. Every exact command requires a fresh user "
            "confirmation. Commands remain local-only: do not request URLs, remote access or downloads, Git, "
            "AUR helpers, source builds, interpreters, decoding/evaluation, shell expansion, redirection, or "
            "arbitrary executable paths. Trusted repository package operations must name /usr/bin/pacman "
            "directly and cannot use -U or alternate config/root/key/hook paths. Never conceal command effects "
            "or claim success before reading a command result."
        )
    )
    instructions = (
        "You are AuraScan's foreground repair agent for an Arch-family Linux system.\n"
        "Use only the supplied bounded context and terminal results. Be calm and explicit about uncertainty.\n"
        f"{shell_note}\n"
        "Known probe and action IDs may be requested. Do not fabricate IDs.\n"
        "Every prose value must be one short line without URLs, commands, executable instructions, terminal "
        "labels or controls, credential-like assignments, or claims that a system is safe or compromised.\n"
        "Return strict JSON only with this shape:\n"
        "{\"answer\":\"plain-language response\",\"requested_access\":\"\","
        "\"referenced_fact_ids\":[],\"requested_probe_ids\":[],\"requested_action_ids\":[],"
        "\"commands\":[{\"command\":\"exact shell text\",\"cwd\":\"/absolute/path or empty\","
        "\"timeout_seconds\":120,\"requires_root\":false,\"reason\":\"why\","
        "\"expected_result\":\"what should happen\"}]}\n"
        "Return at most ten commands with exactly the shown fields. Commands are noninteractive and cannot "
        "receive passwords or model keystrokes.\n\n"
    )
    facts = [
        {
            "fact_id": item.fact_id,
            "kind": item.kind,
            "summary": redact_followup_text(item.summary)[:1000],
            "details": (
                ""
                if facts_only and item.kind == "evidence"
                else redact_followup_text(item.details)[:3000]
            ),
            "severity": item.severity,
        }
        for item in context.facts
    ]
    payload = {
        "session": {
            "access": access,
            "approval": approval,
            "command_limit": AGENT_MAX_COMMANDS_PER_SESSION,
            "context_id": context.context_id,
            "source_type": context.source_type,
            "phase": context.phase,
        },
        "facts": facts,
        "available_probes": [item.to_dict() for item in context.probes],
        "available_actions": [item.to_dict() for item in context.actions if item.verified],
        "probe_results": [item.to_dict() for item in probe_results],
        "command_results": [item.to_dict() for item in command_results],
        "conversation": [item.to_ai_dict() for item in turns],
        "question": redact_followup_text(question)[:2000],
        "input_truncated": False,
    }
    prompt = instructions + json.dumps(payload, sort_keys=True)
    while len(prompt) > AGENT_MAX_PROMPT_CHARS:
        payload["input_truncated"] = True
        if payload["conversation"]:
            payload["conversation"].pop(0)
        elif payload["facts"] and len(payload["facts"]) > 1:
            payload["facts"].pop()
        elif payload["command_results"]:
            payload["command_results"].pop(0)
        elif payload["probe_results"]:
            payload["probe_results"].pop()
        else:
            break
        prompt = instructions + json.dumps(payload, sort_keys=True)
    return prompt[:AGENT_MAX_PROMPT_CHARS]


def ask_agent_ai(
    context: FollowUpContext,
    question: str,
    turns: Sequence[FollowUpTurn],
    *,
    access: str,
    approval: str,
    facts_only: bool,
    command_results: Sequence[AgentCommandResult] = (),
    probe_results: Sequence[FollowUpProbeResult] = (),
    env: Optional[Mapping[str, str]] = None,
    urlopen: Optional[Callable] = None,
) -> AgentAIResponse:
    source = dict(os.environ if env is None else env)
    config = resolve_ai_config(source)
    if not config.ready:
        if config.error:
            error = "AI provider configuration is invalid"
            status = "config_error"
        elif not config.enabled:
            error = "AI provider is disabled"
            status = "not_configured"
        elif not config.authentication_ready:
            error = "AI provider authentication is not configured"
            status = "not_configured"
        else:
            error = "AI provider is not configured"
            status = "not_configured"
        return AgentAIResponse("", status=status, error=error)
    try:
        text = call_ai_provider(
            config,
            build_agent_ai_prompt(
                context,
                question,
                turns,
                access=access,
                approval=approval,
                facts_only=facts_only,
                command_results=command_results,
                probe_results=probe_results,
            ),
            timeout=60,
            urlopen=urlopen,
        )
    except Exception as exc:
        return AgentAIResponse(
            "",
            status=classify_followup_failure(exc),
            error=safe_provider_error_detail(exc),
        )
    try:
        data = load_strict_json_object(
            text,
            max_chars=AGENT_MAX_AI_RESPONSE_CHARS,
        )
        return validate_agent_ai_response(context, data, access=access)
    except Exception:
        return AgentAIResponse(
            "",
            status="invalid_response",
            error=AGENT_AI_RESPONSE_ERROR,
        )


def minimal_agent_environment(
    env: Optional[Mapping[str, str]] = None,
    *,
    root: bool = False,
) -> Dict[str, str]:
    source = os.environ if env is None else env
    result = {
        "PATH": "/usr/bin:/usr/sbin:/bin:/sbin",
        "LANG": str(source.get("LANG") or "C.UTF-8"),
        "LC_ALL": str(source.get("LC_ALL") or ""),
        "TERM": str(source.get("TERM") or "xterm-256color"),
        "HOME": "/root" if root else str(source.get("HOME") or str(Path.home())),
    }
    if not root:
        for key in ("USER", "LOGNAME", "SHELL"):
            if source.get(key):
                result[key] = str(source[key])
    return {key: value for key, value in result.items() if value}


def sanitize_terminal_output(value: object) -> str:
    return CONTROL_RE.sub("", ANSI_ESCAPE_RE.sub("", str(value or "")))


def stream_shell_command(
    command: AgentCommand,
    *,
    stdout=None,
    stderr=None,
    env: Optional[Mapping[str, str]] = None,
    root: bool = False,
    popen_factory: Callable = subprocess.Popen,
) -> AgentCommandResult:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    started = time.monotonic()
    captured = bytearray()
    capture_lock = threading.Lock()
    output_limit_reached = threading.Event()
    output_capture_failed = threading.Event()
    try:
        process = popen_factory(
            ["/bin/bash", "--noprofile", "--norc", "-lc", command.command],
            cwd=command.cwd or None,
            env=minimal_agent_environment(env, root=root),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=False,
            bufsize=0,
            start_new_session=True,
        )
    except OSError as exc:
        return AgentCommandResult(
            command.command_id,
            "failed",
            127,
            "",
            time.monotonic() - started,
            error=_redact_agent_text(str(exc), env)[:500],
        )

    def stop_for_unsafe_output() -> None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass

    def consume() -> None:
        stream = process.stdout
        if stream is None:
            output_capture_failed.set()
            stop_for_unsafe_output()
            return
        try:
            try:
                output_fd = stream.fileno()
            except (AttributeError, OSError, ValueError):
                output_fd = None
            while True:
                if output_fd is None:
                    chunk = stream.read(AGENT_OUTPUT_READ_CHUNK)
                else:
                    chunk = os.read(output_fd, AGENT_OUTPUT_READ_CHUNK)
                if not chunk:
                    return
                if isinstance(chunk, str):
                    chunk = chunk.encode("utf-8", "replace")
                else:
                    chunk = bytes(chunk)
                with capture_lock:
                    remaining = AGENT_MAX_COMMAND_OUTPUT_BYTES - len(captured)
                    if remaining > 0:
                        captured.extend(chunk[:remaining])
                    exceeded = len(chunk) > remaining
                if exceeded:
                    output_limit_reached.set()
                    stop_for_unsafe_output()
                    return
        except (OSError, ValueError):
            output_capture_failed.set()
            stop_for_unsafe_output()

    thread = threading.Thread(target=consume, daemon=True)
    thread.start()
    timed_out = False
    interrupted = False

    def terminate_process_group() -> None:
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=3)
        except (OSError, subprocess.TimeoutExpired):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass

    try:
        exit_code = process.wait(timeout=command.timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        terminate_process_group()
        exit_code = int(process.returncode if process.returncode is not None else 124)
        print(
            f"\n[AuraScan] Command exceeded {command.timeout_seconds}s and its process group was stopped.",
            file=stderr,
        )
    except KeyboardInterrupt:
        interrupted = True
        terminate_process_group()
        exit_code = int(process.returncode if process.returncode is not None else 130)
        print("\n[AuraScan] Command interrupted; its process group was stopped.", file=stderr)
    thread.join(timeout=2)
    if thread.is_alive():
        output_capture_failed.set()
        stop_for_unsafe_output()
        thread.join(timeout=1)
    with capture_lock:
        captured_bytes = bytes(captured)
    output = sanitize_terminal_output(
        captured_bytes.decode("utf-8", "replace")
    )[:AGENT_MAX_RETAINED_OUTPUT]
    if output:
        print(output, end="", file=stdout, flush=True)
    status = (
        "interrupted"
        if interrupted
        else (
            "timeout"
            if timed_out
            else (
                "output_limit"
                if output_limit_reached.is_set()
                else (
                    "failed"
                    if output_capture_failed.is_set()
                    else ("ok" if exit_code == 0 else "failed")
                )
            )
        )
    )
    error = ""
    if status == "output_limit":
        error = AGENT_OUTPUT_LIMIT_ERROR
        print(f"\n[AuraScan] {AGENT_OUTPUT_LIMIT_ERROR}.", file=stderr)
    elif output_capture_failed.is_set() and not timed_out and not interrupted:
        error = AGENT_OUTPUT_CAPTURE_ERROR
        print(f"\n[AuraScan] {AGENT_OUTPUT_CAPTURE_ERROR}.", file=stderr)
    return AgentCommandResult(
        command.command_id,
        status,
        int(exit_code),
        output,
        time.monotonic() - started,
        timed_out=timed_out,
        error=error,
    )


def _process_start_time(pid: int) -> str:
    try:
        fields = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8").split()
        return fields[21] if len(fields) > 21 else ""
    except OSError:
        return ""


def _process_uid(pid: int) -> Optional[int]:
    try:
        for line in Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines():
            if line.startswith("Uid:"):
                return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        return None
    return None


def _process_tty(pid: int) -> str:
    try:
        target = os.readlink(f"/proc/{pid}/fd/0")
    except OSError:
        return ""
    if target.startswith("/dev/"):
        return target
    return ""


def _tty_identity(stream=None) -> str:
    stream = stream or sys.stdin
    try:
        return os.ttyname(stream.fileno())
    except (AttributeError, OSError, ValueError):
        return ""


def validate_agent_request_file(path: Path) -> Tuple[bool, str]:
    fd = -1
    try:
        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(str(path), flags)
        metadata = os.fstat(fd)
    except OSError as exc:
        return False, _redact_agent_text(str(exc))[:500]
    try:
        if not stat.S_ISREG(metadata.st_mode):
            return False, "request is not a regular file"
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            return False, "request permissions must be exactly 0600"
        allowed = {0}
        sudo_uid = str(os.environ.get("SUDO_UID") or "")
        if os.geteuid() == 0 and sudo_uid.isdigit():
            allowed.add(int(sudo_uid))
        if metadata.st_uid not in allowed:
            return False, "request owner does not match the invoking user"
        if metadata.st_size <= 0 or metadata.st_size > AGENT_MAX_REQUEST_BYTES:
            return False, "request size is invalid"
        return True, ""
    finally:
        os.close(fd)


def _read_request(path: Path, expected_schema: str) -> Tuple[Optional[Dict[str, object]], str]:
    fd = -1
    try:
        flags = os.O_RDONLY
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(str(path), flags)
        metadata = os.fstat(fd)
        allowed = {0}
        sudo_uid = str(os.environ.get("SUDO_UID") or "")
        if os.geteuid() == 0 and sudo_uid.isdigit():
            allowed.add(int(sudo_uid))
        if not stat.S_ISREG(metadata.st_mode):
            return None, "request is not a regular file"
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            return None, "request permissions must be exactly 0600"
        if metadata.st_uid not in allowed:
            return None, "request owner does not match the invoking user"
        if metadata.st_size <= 0 or metadata.st_size > AGENT_MAX_REQUEST_BYTES:
            return None, "request size is invalid"
        chunks = []
        remaining = AGENT_MAX_REQUEST_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > AGENT_MAX_REQUEST_BYTES:
            return None, "request exceeds the bounded size"
        data = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, f"request JSON is invalid: {_redact_agent_text(str(exc))[:300]}"
    finally:
        if fd >= 0:
            os.close(fd)
    if not isinstance(data, dict) or data.get("schema") != expected_schema:
        return None, "request schema is invalid"
    return data, ""


def _root_session_path(session_id: str, uid: int, root: Path = AGENT_RUNTIME_ROOT) -> Path:
    if not SAFE_SESSION_ID_RE.fullmatch(session_id):
        raise ValueError("unsafe agent session ID")
    return root / str(uid) / f"{session_id}.json"


def _write_root_state(path: Path, data: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise OSError("unsafe agent runtime directory")
    os.chmod(path.parent, 0o700)
    _atomic_private_json(path, data)


def cleanup_expired_root_sessions(
    uid: int,
    *,
    runtime_root: Path = AGENT_RUNTIME_ROOT,
    now: Optional[int] = None,
) -> int:
    current = int(time.time()) if now is None else int(now)
    root = runtime_root / str(uid)
    if not root.is_dir() or root.is_symlink():
        return 0
    removed = 0
    for path in list(root.glob("agent-*.json"))[:100]:
        try:
            if path.is_symlink() or not path.is_file():
                continue
            data = json.loads(path.read_text(encoding="utf-8"))
            if int(data.get("expires_at") or 0) <= current:
                path.unlink()
                removed += 1
        except (OSError, ValueError, json.JSONDecodeError):
            continue
    return removed


def _snapshot_capability(
    *,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
) -> Tuple[bool, str]:
    if not which("findmnt") or not which("snapper"):
        return False, "Btrfs/Snapper rollback tooling is unavailable"
    try:
        result = runner(
            ["findmnt", "-n", "-o", "FSTYPE", "/"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, _redact_agent_text(str(exc))[:300]
    if result.returncode != 0 or result.stdout.strip().lower() != "btrfs":
        return False, "the root filesystem is not a detected Btrfs filesystem"
    return True, ""


def _create_agent_snapshot(
    session_id: str,
    *,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
    snapshot_root: Path = Path("/.snapshots"),
) -> Tuple[str, str]:
    capable, reason = _snapshot_capability(runner=runner, which=which)
    if not capable:
        return "", reason
    command = [
        "snapper",
        "-c",
        "root",
        "create",
        "--type",
        "single",
        "--description",
        f"AuraScan AI agent pre-session {session_id}",
        "--print-number",
    ]
    try:
        result = runner(
            command,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return "", _redact_agent_text(str(exc))[:300]
    snapshot_id = result.stdout.strip()
    if result.returncode != 0 or not snapshot_id.isdigit():
        detail = _redact_agent_text(result.stderr.strip())[:300]
        return "", detail or "Snapper did not return a valid snapshot ID"
    snapshot = snapshot_root / snapshot_id / "snapshot"
    try:
        if snapshot.is_symlink() or not snapshot.is_dir():
            return "", "Snapper returned an ID but the root snapshot could not be validated"
    except OSError as exc:
        return "", _redact_agent_text(str(exc))[:300]
    return snapshot_id, ""


def issue_root_session(
    request_path: Path,
    *,
    policy_path: Path = AGENT_ROOT_POLICY_PATH,
    runtime_root: Path = AGENT_RUNTIME_ROOT,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
    now: Optional[int] = None,
    policy_uid: int = 0,
) -> Dict[str, object]:
    request, error = _read_request(request_path, "agent_root_session_request/1.0")
    if request is None:
        return {"ok": False, "error": error}
    policy = read_agent_root_policy(policy_path, required_uid=policy_uid)
    if policy.error or not policy.allowed:
        return {"ok": False, "error": policy.error or "root repair agent policy is disabled"}
    try:
        uid = int(request.get("uid"))
        pid = int(request.get("origin_pid"))
        minutes = int(request.get("minutes"))
    except (TypeError, ValueError):
        return {"ok": False, "error": "root session identity is invalid"}
    sudo_uid = str(os.environ.get("SUDO_UID") or "")
    if sudo_uid.isdigit() and uid != int(sudo_uid):
        return {"ok": False, "error": "root session UID does not match sudo"}
    if _process_uid(pid) != uid:
        return {"ok": False, "error": "originating agent process is unavailable or belongs to another user"}
    start_time = str(request.get("origin_start_time") or "")
    if not start_time or _process_start_time(pid) != start_time:
        return {"ok": False, "error": "originating agent process identity changed"}
    tty = str(request.get("tty") or "")
    if not tty.startswith("/dev/") or _process_tty(pid) != tty:
        return {
            "ok": False,
            "error": "root session terminal does not match the originating process",
        }
    requested_approval = str(request.get("approval") or "")
    if requested_approval not in AGENT_APPROVAL_VALUES:
        return {"ok": False, "error": "root session approval mode is invalid"}
    approval = effective_agent_approval("root-shell", requested_approval)
    policy_approval = effective_agent_approval("root-shell", policy.max_approval)
    if AGENT_APPROVAL_ORDER[approval] > AGENT_APPROVAL_ORDER[policy_approval]:
        return {"ok": False, "error": "requested approval mode exceeds the root policy ceiling"}
    if minutes < 1 or minutes > min(policy.max_minutes, AGENT_MAX_SESSION_MINUTES):
        return {"ok": False, "error": "requested root session duration exceeds the policy ceiling"}
    session_id = str(request.get("session_id") or "")
    capability = str(request.get("capability") or "")
    fingerprint = str(request.get("context_fingerprint") or "")
    if (
        not SAFE_SESSION_ID_RE.fullmatch(session_id)
        or len(capability) < 32
        or not re.fullmatch(r"[a-f0-9]{64}", fingerprint)
    ):
        return {"ok": False, "error": "root session identifiers are invalid"}
    snapshot_requested = bool(request.get("snapshot_requested", False))
    snapshot_waived = bool(request.get("snapshot_waived", False))
    if snapshot_requested == snapshot_waived:
        return {"ok": False, "error": "root session requires either a snapshot or an explicit waiver"}
    snapshot_id = ""
    if snapshot_requested:
        snapshot_id, snapshot_error = _create_agent_snapshot(
            session_id,
            runner=runner,
            which=which,
        )
        if not snapshot_id:
            return {
                "ok": False,
                "error": f"snapshot_unavailable: {snapshot_error}",
                "snapshot_unavailable": True,
            }
    current = int(time.time()) if now is None else int(now)
    cleanup_expired_root_sessions(uid, runtime_root=runtime_root, now=current)
    state = {
        "schema": "agent_root_session/1.0",
        "session_id": session_id,
        "uid": uid,
        "origin_pid": pid,
        "origin_start_time": start_time,
        "tty": tty,
        "context_fingerprint": fingerprint,
        "approval": approval,
        "created_at": current,
        "expires_at": current + minutes * 60,
        "capability_hash": hashlib.sha256(capability.encode("utf-8")).hexdigest(),
        "snapshot_id": snapshot_id,
        "snapshot_waived": snapshot_waived,
        "command_count": 0,
        "active_plan_hash": "",
    }
    try:
        path = _root_session_path(session_id, uid, runtime_root)
        _write_root_state(path, state)
    except (OSError, ValueError) as exc:
        retained = f" Snapshot {snapshot_id} was retained." if snapshot_id else ""
        return {
            "ok": False,
            "error": _redact_agent_text(str(exc))[:500] + retained,
            "snapshot_id": snapshot_id,
        }
    return {
        "ok": True,
        "session_id": session_id,
        "expires_at": state["expires_at"],
        "snapshot_id": snapshot_id,
        "snapshot_waived": snapshot_waived,
    }


def _load_root_session(
    session_id: str,
    uid: int,
    capability: str,
    *,
    runtime_root: Path,
    now: Optional[int] = None,
) -> Tuple[Optional[Dict[str, object]], Optional[Path], str]:
    try:
        path = _root_session_path(session_id, uid, runtime_root)
    except ValueError as exc:
        return None, None, str(exc)
    try:
        if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) != 0o600:
            return None, path, "root session record is missing or unsafe"
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return None, path, _redact_agent_text(str(exc))[:500]
    if not isinstance(state, dict) or state.get("schema") != "agent_root_session/1.0":
        return None, path, "root session record schema is invalid"
    current = int(time.time()) if now is None else int(now)
    if int(state.get("expires_at") or 0) <= current:
        try:
            path.unlink()
        except OSError:
            pass
        return None, path, "root session expired"
    if int(state.get("uid") or -1) != uid:
        return None, path, "root session UID mismatch"
    pid = int(state.get("origin_pid") or 0)
    if _process_uid(pid) != uid or _process_start_time(pid) != str(state.get("origin_start_time") or ""):
        return None, path, "originating agent process is no longer valid"
    if _process_tty(pid) != str(state.get("tty") or ""):
        return None, path, "originating agent terminal is no longer valid"
    digest = hashlib.sha256(capability.encode("utf-8")).hexdigest()
    if not secrets.compare_digest(digest, str(state.get("capability_hash") or "")):
        return None, path, "root session capability is invalid"
    return state, path, ""


def _root_audit_path(session_id: str, root: Path = AGENT_ROOT_AUDIT_ROOT) -> Path:
    if not SAFE_SESSION_ID_RE.fullmatch(session_id):
        raise ValueError("unsafe agent session ID")
    return root / session_id / "manifest.json"


def _append_root_audit(
    session_id: str,
    entry: Mapping[str, object],
    *,
    root: Path = AGENT_ROOT_AUDIT_ROOT,
) -> None:
    _ensure_private_dir(root)
    path = _root_audit_path(session_id, root)
    existing: Dict[str, object] = {
        "schema": "agent_root_audit/1.0",
        "session_id": session_id,
        "commands": [],
    }
    if path.is_file() and not path.is_symlink():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict) and loaded.get("schema") == "agent_root_audit/1.0":
                existing = loaded
        except (OSError, json.JSONDecodeError):
            pass
    commands = existing.get("commands", [])
    if not isinstance(commands, list):
        commands = []
    commands.append(redact_followup_structure(dict(entry)))
    existing["commands"] = commands[-AGENT_MAX_COMMANDS_PER_SESSION:]
    _atomic_private_json(path, existing)


def execute_root_command_request(
    request_path: Path,
    *,
    runtime_root: Path = AGENT_RUNTIME_ROOT,
    audit_root: Path = AGENT_ROOT_AUDIT_ROOT,
    stdout=None,
    stderr=None,
    env: Optional[Mapping[str, str]] = None,
    popen_factory: Callable = subprocess.Popen,
    now: Optional[int] = None,
) -> Dict[str, object]:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    request, error = _read_request(request_path, "agent_command_request/1.0")
    if request is None:
        return {"ok": False, "error": error}
    try:
        uid = int(request.get("uid"))
    except (TypeError, ValueError):
        return {"ok": False, "error": "command request UID is invalid"}
    sudo_uid = str(os.environ.get("SUDO_UID") or "")
    if sudo_uid.isdigit() and uid != int(sudo_uid):
        return {"ok": False, "error": "command request UID does not match sudo"}
    state, state_path, error = _load_root_session(
        str(request.get("session_id") or ""),
        uid,
        str(request.get("capability") or ""),
        runtime_root=runtime_root,
        now=now,
    )
    if state is None or state_path is None:
        return {"ok": False, "error": error}
    if str(request.get("context_fingerprint") or "") != str(state.get("context_fingerprint") or ""):
        return {"ok": False, "error": "command context fingerprint does not match the root grant"}
    if str(request.get("tty") or "") != str(state.get("tty") or ""):
        return {"ok": False, "error": "command terminal does not match the root grant"}
    if int(state.get("command_count") or 0) >= AGENT_MAX_COMMANDS_PER_SESSION:
        return {"ok": False, "error": "root session command limit reached"}
    raw_command = request.get("command")
    if not isinstance(raw_command, Mapping):
        return {"ok": False, "error": "command request does not contain a command object"}
    try:
        command = validate_agent_command(
            raw_command,
            access="root-shell",
            allow_command_id=True,
        )
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    command_hash = str(request.get("plan_hash") or "")
    expected_hash = _plan_hash([command])
    if not re.fullmatch(r"[a-f0-9]{64}", command_hash) or not secrets.compare_digest(
        command_hash,
        expected_hash,
    ):
        return {"ok": False, "error": "approved command hash does not match the exact command"}
    # Legacy root-session records may name a broader approval mode. The broker
    # deliberately narrows them so a previous plan/session grant cannot carry
    # forward after an upgrade.
    state["approval"] = effective_agent_approval(
        "root-shell",
        str(state.get("approval") or "each-command"),
    )
    state["active_plan_hash"] = ""
    print(
        f"[AuraScan root agent] Running approved command {command.command_id}.",
        file=stderr,
        flush=True,
    )
    result = stream_shell_command(
        command,
        stdout=stderr,
        stderr=stderr,
        env=env,
        root=True,
        popen_factory=popen_factory,
    )
    state["command_count"] = int(state.get("command_count") or 0) + 1
    try:
        _write_root_state(state_path, state)
        _append_root_audit(
            str(state["session_id"]),
            {
                "command_id": command.command_id,
                "command_sha256": hashlib.sha256(command.command.encode("utf-8", "replace")).hexdigest(),
                "command": str(request.get("audit_command") or "<redacted-command>")[:AGENT_MAX_COMMAND_CHARS],
                "cwd": command.cwd,
                "timeout_seconds": command.timeout_seconds,
                "approval": state.get("approval"),
                "started_at": int(time.time()),
                "status": result.status,
                "exit_code": result.exit_code,
                "duration_seconds": round(result.duration_seconds, 3),
                "snapshot_id": state.get("snapshot_id", ""),
                "snapshot_waived": bool(state.get("snapshot_waived", False)),
                "output": redact_followup_text(result.output)[:AGENT_MAX_AI_OUTPUT_PER_COMMAND],
            },
            root=audit_root,
        )
    except (OSError, ValueError) as exc:
        return {"ok": False, "error": f"root audit/state write failed: {_redact_agent_text(str(exc))[:300]}"}
    return {"ok": True, "result": result.to_dict()}


def revoke_root_session(
    request_path: Path,
    *,
    runtime_root: Path = AGENT_RUNTIME_ROOT,
    now: Optional[int] = None,
) -> Dict[str, object]:
    request, error = _read_request(request_path, "agent_root_revoke_request/1.0")
    if request is None:
        return {"ok": False, "error": error}
    try:
        uid = int(request.get("uid"))
    except (TypeError, ValueError):
        return {"ok": False, "error": "revoke request UID is invalid"}
    state, path, error = _load_root_session(
        str(request.get("session_id") or ""),
        uid,
        str(request.get("capability") or ""),
        runtime_root=runtime_root,
        now=now,
    )
    if state is None or path is None:
        return {"ok": False, "error": error}
    try:
        path.unlink()
    except OSError as exc:
        return {"ok": False, "error": _redact_agent_text(str(exc))[:300]}
    return {"ok": True}


def _temporary_request(data: Mapping[str, object]) -> str:
    fd, name = tempfile.mkstemp(prefix="aurascan-agent-", suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(data, handle)
    os.chmod(name, 0o600)
    return name


def _capture_agent_privileged_tools(
    helper: Path,
    *,
    which: Callable[[str], Optional[str]] = shutil.which,
    search_path: Optional[str] = None,
) -> AgentPrivilegedTools:
    if helper != AGENT_TRUSTED_HELPER_PATH:
        raise TrustedToolError("privileged agent helper was not package-managed")
    resolver = which
    if search_path is not None and which is shutil.which:
        resolver = lambda name: shutil.which(name, path=search_path)
    sudo = capture_trusted_system_tool("sudo", which=resolver)
    package_helper = capture_trusted_system_tool("aurascan", which=resolver)
    if sudo is None or package_helper is None:
        raise TrustedToolError("privileged agent tool was unavailable")
    if sudo.path != str(AGENT_TRUSTED_SUDO_PATH) or package_helper.path != str(
        AGENT_TRUSTED_HELPER_PATH
    ):
        raise TrustedToolError("privileged agent tool path was unexpected")
    return AgentPrivilegedTools(sudo=sudo, helper=package_helper)


def _revalidate_agent_privileged_tools(tools: AgentPrivilegedTools) -> None:
    revalidate_trusted_system_tool(tools.sudo)
    revalidate_trusted_system_tool(tools.helper)


def _invoke_root_helper(
    args: Sequence[str],
    request: Mapping[str, object],
    *,
    privileged_tools: AgentPrivilegedTools,
    runner: Callable = subprocess.run,
) -> Dict[str, object]:
    name = _temporary_request(request)
    try:
        _revalidate_agent_privileged_tools(privileged_tools)
        command = [
            privileged_tools.sudo.path,
            "--",
            privileged_tools.helper.path,
            "agent",
            *args,
            name,
        ]
        if runner is subprocess.run:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=None,
                text=True,
            )
            captured_stdout, _unused = process.communicate()
            result = subprocess.CompletedProcess(
                command,
                int(process.returncode or 0),
                captured_stdout,
                "",
            )
        else:
            result = runner(command, capture_output=True, text=True, check=False)
        captured_stderr = str(getattr(result, "stderr", "") or "")
        if captured_stderr:
            print(captured_stderr, end="" if captured_stderr.endswith("\n") else "\n", file=sys.stderr)
        raw = (getattr(result, "stdout", "") or "").strip()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            detail = _redact_agent_text((getattr(result, "stderr", "") or raw).strip())[:500]
            return {"ok": False, "error": detail or "privileged agent helper returned invalid output"}
        if not isinstance(data, dict):
            return {"ok": False, "error": "privileged agent helper returned invalid output"}
        return data
    except TrustedToolError:
        return {"ok": False, "error": AGENT_PRIVILEGED_TOOLS_ERROR}
    except OSError as exc:
        return {"ok": False, "error": _redact_agent_text(str(exc))[:500]}
    finally:
        try:
            os.unlink(name)
        except OSError:
            pass


def _issue_root_grant(
    session: AgentSession,
    *,
    snapshot_requested: bool,
    snapshot_waived: bool,
    privileged_tools: AgentPrivilegedTools,
    runner: Callable,
    tty: str,
) -> Dict[str, object]:
    capability = secrets.token_urlsafe(32)
    request = {
        "schema": "agent_root_session_request/1.0",
        "session_id": session.session_id,
        "capability": capability,
        "uid": current_user_uid(),
        "origin_pid": os.getpid(),
        "origin_start_time": _process_start_time(os.getpid()),
        "tty": tty,
        "context_fingerprint": session.context_fingerprint,
        "approval": session.approval,
        "minutes": max(1, (session.expires_at - session.created_at) // 60),
        "snapshot_requested": snapshot_requested,
        "snapshot_waived": snapshot_waived,
    }
    response = _invoke_root_helper(
        ["--issue-root-session"],
        request,
        privileged_tools=privileged_tools,
        runner=runner,
    )
    if response.get("ok"):
        session.root_capability = capability
        session.snapshot_id = str(response.get("snapshot_id") or "")
        session.snapshot_waived = bool(response.get("snapshot_waived", False))
    return response


def _execute_via_root_helper(
    session: AgentSession,
    command: AgentCommand,
    plan_hash: str,
    *,
    privileged_tools: AgentPrivilegedTools,
    runner: Callable,
    env: Mapping[str, str],
) -> AgentCommandResult:
    request = {
        "schema": "agent_command_request/1.0",
        "session_id": session.session_id,
        "capability": session.root_capability,
        "uid": current_user_uid(),
        "tty": session.tty,
        "context_fingerprint": session.context_fingerprint,
        "plan_hash": plan_hash,
        "audit_command": _redact_agent_text(command.command, env),
        "command": command.to_dict(),
    }
    response = _invoke_root_helper(
        ["--execute-request"],
        request,
        privileged_tools=privileged_tools,
        runner=runner,
    )
    if not response.get("ok") or not isinstance(response.get("result"), Mapping):
        return AgentCommandResult(
            command.command_id,
            "failed",
            1,
            "",
            0.0,
            error=_redact_agent_text(response.get("error") or "root helper refused the command", env)[:500],
        )
    data = response["result"]
    return AgentCommandResult(
        command_id=str(data.get("command_id") or command.command_id),
        status=str(data.get("status") or "failed"),
        exit_code=int(data.get("exit_code") or 0),
        output=str(data.get("output") or "")[:AGENT_MAX_RETAINED_OUTPUT],
        duration_seconds=float(data.get("duration_seconds") or 0.0),
        timed_out=bool(data.get("timed_out", False)),
        error=str(data.get("error") or "")[:500],
    )


def _revoke_root_grant(
    session: AgentSession,
    *,
    privileged_tools: AgentPrivilegedTools,
    runner: Callable,
) -> None:
    if not session.root_capability:
        return
    request = {
        "schema": "agent_root_revoke_request/1.0",
        "session_id": session.session_id,
        "capability": session.root_capability,
        "uid": current_user_uid(),
    }
    _invoke_root_helper(
        ["--revoke-root-session"],
        request,
        privileged_tools=privileged_tools,
        runner=runner,
    )
    session.root_capability = ""


def _plan_hash(commands: Sequence[AgentCommand]) -> str:
    payload = [item.to_dict() for item in commands]
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8", "replace")
    ).hexdigest()


def _print_agent_banner(session: AgentSession, stdout) -> None:
    print("\n[AuraScan] Policy-Gated Repair Agent", file=stdout)
    print("=" * 54, file=stdout)
    if session.access == "root-shell":
        print("ACCESS: POLICY-GATED ROOT REPAIR", file=stdout)
    elif session.access == "user-shell":
        print("ACCESS: LOCAL DIAGNOSTIC COMMANDS", file=stdout)
    else:
        print("ACCESS: GUARDED AURASCAN TOOLS", file=stdout)
    print(
        f"Approval: {session.approval} | AI output: {session.output_sharing} | "
        f"Expires: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(session.expires_at))}",
        file=stdout,
    )
    if session.access == "root-shell":
        rollback = f"Snapper snapshot {session.snapshot_id}" if session.snapshot_id else "NO SNAPSHOT"
        print(f"Rollback preparation: {rollback}", file=stdout)
        print(
            "Warning: approved /usr/bin/pacman root repairs can still alter installed packages "
            "and system state; local diagnostic commands remain read-only.",
            file=stdout,
        )
    if session.access in {"user-shell", "root-shell"}:
        print(
            "Command gate: local-only allowlisted commands require fresh confirmation; remote "
            "acquisition, arbitrary executables, AUR/build tools, and dynamic code are refused.",
            file=stdout,
        )
    print("Commands: /status, /agent ACCESS, /stop", file=stdout)
    print("-" * 54, file=stdout)


def _print_agent_status(session: AgentSession, stdout) -> None:
    remaining = max(0, session.expires_at - int(time.time()))
    print(
        f"[AuraScan] Agent status: access={session.access}, approval={session.approval}, "
        f"output={session.output_sharing}, commands={session.command_count}/{AGENT_MAX_COMMANDS_PER_SESSION}, "
        f"provider requests={session.provider_requests}/{AGENT_MAX_PROVIDER_REQUESTS}, "
        f"remaining={remaining}s.",
        file=stdout,
    )


def _display_plan(commands: Sequence[AgentCommand], stdout) -> None:
    print("\n[AuraScan] AI-requested terminal plan", file=stdout)
    for index, item in enumerate(commands, 1):
        privilege = "root" if item.requires_root else "user"
        reason_lines = item.reason.splitlines() or [item.reason]
        print(f"{index}. [{privilege}] {reason_lines[0]}", file=stdout)
        for line in reason_lines[1:]:
            print(f"   {line}", file=stdout)
        print(f"   Working directory: {item.cwd or os.getcwd()}", file=stdout)
        print("   Exact command:", file=stdout)
        for line in item.command.splitlines() or [item.command]:
            print(f"     | {line}", file=stdout)
        if item.expected_result:
            expected_lines = item.expected_result.splitlines()
            print(f"   Expected: {expected_lines[0]}", file=stdout)
            for line in expected_lines[1:]:
                print(f"   {line}", file=stdout)


def _confirm_commands(
    commands: Sequence[AgentCommand],
    _approval: str,
    input_func: Callable[[str], str],
    stdout,
) -> List[AgentCommand]:
    # ``whole-plan`` and ``session`` remain accepted configuration spellings for
    # upgrade compatibility, but all model-authored shell text is confirmed one
    # exact command at a time.
    approved = []
    for command in commands:
        _display_plan([command], stdout)
        answer = input_func("Run this exact command? [y/N] ").strip().lower()
        if answer in {"y", "yes"}:
            approved.append(command)
        else:
            print("[AuraScan] Command declined. Remaining commands were not run.", file=stdout)
            break
    return approved


def _agent_result_for_ai(
    result: AgentCommandResult,
    session: AgentSession,
    env: Mapping[str, str],
    used: int,
) -> Tuple[AgentCommandResult, int]:
    remaining = max(0, AGENT_MAX_AI_OUTPUT_PER_SESSION - used)
    limit = min(AGENT_MAX_AI_OUTPUT_PER_COMMAND, remaining)
    output = result.output[:limit]
    if session.output_sharing != "full":
        output = _redact_agent_text(output, env)
    clone = AgentCommandResult(
        result.command_id,
        result.status,
        result.exit_code,
        output,
        result.duration_seconds,
        result.timed_out,
        _redact_agent_text(result.error, env),
    )
    return clone, used + len(output)


def _audit_command(
    session: AgentSession,
    command: AgentCommand,
    result: AgentCommandResult,
    *,
    env: Mapping[str, str],
) -> None:
    session.audit_entries.append({
        "command_id": command.command_id,
        "command_sha256": hashlib.sha256(command.command.encode("utf-8", "replace")).hexdigest(),
        "command": _redact_agent_text(command.command, env)[:AGENT_MAX_COMMAND_CHARS],
        "reason": _redact_agent_text(command.reason, env)[:1000],
        "cwd": command.cwd,
        "requires_root": command.requires_root,
        "approval": session.approval,
        "status": result.status,
        "exit_code": result.exit_code,
        "duration_seconds": round(result.duration_seconds, 3),
        "output": _redact_agent_text(result.output, env)[:AGENT_MAX_AI_OUTPUT_PER_COMMAND],
    })


def _handle_verified_requests(
    context: FollowUpContext,
    response: AgentAIResponse,
    runtime: FollowUpRuntime,
    input_func: Callable[[str], str],
    stdout,
    stderr,
) -> Tuple[FollowUpContext, Sequence[FollowUpProbeResult], FollowUpActionOutcome]:
    current = context
    probe_results: Sequence[FollowUpProbeResult] = ()
    outcome = FollowUpActionOutcome()
    if response.requested_probe_ids and runtime.run_probes:
        print(
            f"[AuraScan] Running {len(response.requested_probe_ids)} guarded local verification check(s)...",
            file=stdout,
            flush=True,
        )
        try:
            current, probe_results = runtime.run_probes(current, response.requested_probe_ids)
        except Exception as exc:
            probe_results = [
                FollowUpProbeResult(
                    response.requested_probe_ids[0],
                    "failed",
                    _redact_agent_text(str(exc))[:500],
                )
            ]
    if response.requested_action_ids and runtime.run_actions:
        print("[AuraScan] Refreshing and preparing AuraScan-owned repairs...", file=stdout, flush=True)
        outcome = runtime.run_actions(
            current,
            response.requested_action_ids,
            input_func,
            stdout,
            stderr,
        )
        if outcome.message:
            print(outcome.message, file=stderr if outcome.failed else stdout)
    return current, probe_results, outcome


def run_agent_session(
    context: FollowUpContext,
    *,
    access: str,
    approval: str,
    output_sharing: str,
    session_timeout_minutes: int,
    runtime: Optional[FollowUpRuntime] = None,
    input_func: Callable[[str], str] = input,
    stdout=None,
    stderr=None,
    env: Optional[Mapping[str, str]] = None,
    facts_only: bool = False,
    urlopen: Optional[Callable] = None,
    context_root: Optional[Path] = None,
    audit_root: Optional[Path] = None,
    helper: Path = Path("/usr/bin/aurascan"),
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
    popen_factory: Callable = subprocess.Popen,
    tty: Optional[str] = None,
    root_policy_path: Path = AGENT_ROOT_POLICY_PATH,
    root_policy_uid: int = 0,
) -> AgentSessionResult:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    source = dict(os.environ if env is None else env)
    runtime = runtime or FollowUpRuntime()
    now = int(time.time())
    effective_approval = effective_agent_approval(access, approval)
    session = AgentSession(
        session_id="agent-" + uuid.uuid4().hex,
        context_id=context.context_id,
        context_fingerprint=followup_context_fingerprint(context),
        access=access,
        approval=effective_approval,
        output_sharing=output_sharing,
        created_at=now,
        expires_at=now + session_timeout_minutes * 60,
        tty=tty if tty is not None else _tty_identity(),
    )
    result = AgentSessionResult()
    privileged_tools: Optional[AgentPrivilegedTools] = None
    persist_followup_context(context, context_root)

    if approval != effective_approval:
        print(
            f"[AuraScan] Configured approval mode '{approval}' is a legacy alias for shell sessions. "
            "Effective approval is each-command: every exact model-authored command requires a fresh confirmation.",
            file=stdout,
        )

    if access == "user-shell":
        answer = input_func(
            "Allow the AI to propose policy-validated local diagnostic commands for this session? "
            "Every exact command will still require confirmation. [y/N] "
        ).strip().lower()
        if answer not in {"y", "yes"}:
            print("[AuraScan] User-shell access was not enabled.", file=stdout)
            return result

    if output_sharing == "full":
        phrase = input_func(
            f"Type {AGENT_RAW_OUTPUT_PHRASE} to send bounded raw terminal output to AI: "
        ).strip()
        if phrase != AGENT_RAW_OUTPUT_PHRASE:
            session.output_sharing = "redacted"
            print("[AuraScan] Raw output sharing was not granted; using redacted output.", file=stdout)

    if access == "root-shell":
        policy = read_agent_root_policy(root_policy_path, required_uid=root_policy_uid)
        if policy.error or not policy.allowed:
            print(
                f"[AuraScan] Root-shell access is unavailable: {policy.error or 'root policy is disabled'}.",
                file=stderr,
            )
            result.setup_failed = True
            return result
        phrase = input_func(
            "ROOT REPAIR permits policy-validated /usr/bin/pacman workflows plus read-only diagnostics.\n"
            f"Type {AGENT_ROOT_GRANT_PHRASE} to continue: "
        ).strip()
        if phrase != AGENT_ROOT_GRANT_PHRASE:
            print("[AuraScan] Root repair access was not granted.", file=stdout)
            return result
        try:
            privileged_tools = _capture_agent_privileged_tools(
                helper,
                which=which,
                search_path=str(source["PATH"]) if "PATH" in source else None,
            )
        except TrustedToolError:
            print(
                "[AuraScan] Root-shell access requires trusted package-managed "
                "/usr/bin/sudo and /usr/bin/aurascan.",
                file=stderr,
            )
            result.setup_failed = True
            return result
        response = _issue_root_grant(
            session,
            snapshot_requested=True,
            snapshot_waived=False,
            privileged_tools=privileged_tools,
            runner=runner,
            tty=session.tty,
        )
        if response.get("snapshot_unavailable"):
            print(
                "[AuraScan] A validated Btrfs/Snapper snapshot could not be created. "
                "A snapshot would not protect other disks, firmware, credentials, or remote systems.",
                file=stdout,
            )
            waiver = input_func(f"Type {AGENT_NO_SNAPSHOT_PHRASE} to continue without it: ").strip()
            if waiver != AGENT_NO_SNAPSHOT_PHRASE:
                print(
                    "[AuraScan] Root-shell session stopped because rollback preparation was unavailable.",
                    file=stdout,
                )
                return result
            response = _issue_root_grant(
                session,
                snapshot_requested=False,
                snapshot_waived=True,
                privileged_tools=privileged_tools,
                runner=runner,
                tty=session.tty,
            )
        if not response.get("ok"):
            print(
                f"[AuraScan] Root session broker refused the grant: "
                f"{_redact_agent_text(response.get('error') or 'unknown error', source)}",
                file=stderr,
            )
            result.setup_failed = True
            return result

    _print_agent_banner(session, stdout)
    turns: List[FollowUpTurn] = []
    current = context
    ensure_hardware_health_probe(current)
    hardware_opened = bool(current.metadata.get("hardware_health"))
    ai_output_used = 0
    pending_results: List[AgentCommandResult] = []
    prompt = "Ask AuraScan what to investigate or fix, or press Enter to finish: "
    try:
        while (
            not session.stopped
            and session.questions < AGENT_MAX_QUESTIONS
            and session.provider_requests < AGENT_MAX_PROVIDER_REQUESTS
            and session.command_count < AGENT_MAX_COMMANDS_PER_SESSION
            and int(time.time()) < session.expires_at
        ):
            try:
                question = input_func(prompt).strip()
            except (EOFError, KeyboardInterrupt):
                print("", file=stdout)
                break
            if not question:
                break
            if question == "/stop":
                session.stopped = True
                result.stopped = True
                print("[AuraScan] Agent session stopped and its grant was revoked.", file=stdout)
                break
            if question == "/status":
                _print_agent_status(session, stdout)
                continue
            if question.startswith("/agent"):
                requested = question.partition(" ")[2].strip()
                if not requested:
                    _print_agent_status(session, stdout)
                elif requested != session.access:
                    print(
                        "[AuraScan] Access changes require a new agent session so consent and rollback checks "
                        "cannot be inherited.",
                        file=stdout,
                    )
                continue
            session.questions += 1
            initial_probe_results: Sequence[FollowUpProbeResult] = ()
            if (
                not hardware_opened
                and question_requests_hardware_context(question)
                and runtime.run_probes is not None
                and any(
                    item.probe_id == HARDWARE_HEALTH_PROBE_ID
                    for item in current.probes
                )
            ):
                hardware_opened = True
                print(
                    "[AuraScan] Checking CPU, GPU, memory, cooling, firmware, and driver context...",
                    file=stdout,
                    flush=True,
                )
                try:
                    current, initial_probe_results = runtime.run_probes(
                        current,
                        [HARDWARE_HEALTH_PROBE_ID],
                    )
                except Exception as exc:
                    initial_probe_results = [
                        FollowUpProbeResult(
                            HARDWARE_HEALTH_PROBE_ID,
                            "failed",
                            _redact_agent_text(str(exc), source)[:500],
                        )
                    ]
                persist_followup_context(current, context_root)
            print("[AuraScan] AI is reviewing the retained result and current request...", file=stdout, flush=True)
            response = ask_agent_ai(
                current,
                question,
                turns,
                access=session.access,
                approval=session.approval,
                facts_only=facts_only or current.privacy_mode == "facts-only",
                command_results=pending_results,
                probe_results=initial_probe_results,
                env=source,
                urlopen=urlopen,
            )
            session.provider_requests += 1
            pending_results = []
            if response.status != "ok":
                result.provider_failed = True
                print(
                    f"[AuraScan] Agent AI was unavailable ({response.status}). "
                    "No terminal command was inferred or run.",
                    file=stderr,
                )
                if response.error:
                    print(f"[AuraScan] Provider detail: {response.error}", file=stderr)
                break
            print("\n[AuraScan] Agent answer", file=stdout)
            print(response.answer or "AuraScan did not receive a usable answer.", file=stdout)
            if (
                response.requested_access
                and AGENT_ACCESS_ORDER[response.requested_access]
                > AGENT_ACCESS_ORDER[session.access]
            ):
                print(
                    f"[AuraScan] AI requested {response.requested_access}. Only you can grant it; "
                    f"start a new session with `aurascan agent --access {response.requested_access}`.",
                    file=stdout,
                )
            current, probe_results, action_outcome = _handle_verified_requests(
                current,
                response,
                runtime,
                input_func,
                stdout,
                stderr,
            )
            if action_outcome.attempted:
                result.action_outcome = action_outcome
                if action_outcome.applied or action_outcome.source_changed:
                    break
            if probe_results and session.provider_requests < AGENT_MAX_PROVIDER_REQUESTS:
                print("[AuraScan] AI is reviewing guarded local verification results...", file=stdout, flush=True)
                response = ask_agent_ai(
                    current,
                    question,
                    turns,
                    access=session.access,
                    approval=session.approval,
                    facts_only=facts_only or current.privacy_mode == "facts-only",
                    probe_results=probe_results,
                    env=source,
                    urlopen=urlopen,
                )
                session.provider_requests += 1
                if response.status != "ok":
                    result.provider_failed = True
                    print("[AuraScan] Final AI review failed; local verification remains available.", file=stderr)
                    break
                print("\n[AuraScan] Agent verification review", file=stdout)
                print(response.answer, file=stdout)

            tool_rounds = 0
            while (
                response.commands
                and tool_rounds < AGENT_MAX_COMMANDS_PER_SESSION
                and session.provider_requests < AGENT_MAX_PROVIDER_REQUESTS
                and session.command_count < AGENT_MAX_COMMANDS_PER_SESSION
            ):
                commands = response.commands[
                    : max(0, AGENT_MAX_COMMANDS_PER_SESSION - session.command_count)
                ]
                pending_results = []
                for command in commands:
                    if int(time.time()) >= session.expires_at:
                        print("[AuraScan] Agent grant expired before the next command.", file=stderr)
                        break
                    approved = _confirm_commands(
                        [command],
                        session.approval,
                        input_func,
                        stdout,
                    )
                    if not approved:
                        break
                    print(
                        f"\n[AuraScan] Running approved {'root' if command.requires_root else 'user'} command "
                        f"{command.command_id}...",
                        file=stdout,
                        flush=True,
                    )
                    if session.access == "root-shell":
                        command_result = _execute_via_root_helper(
                            session,
                            command,
                            _plan_hash([command]),
                            privileged_tools=privileged_tools,
                            runner=runner,
                            env=source,
                        )
                    else:
                        command_result = stream_shell_command(
                            command,
                            stdout=stdout,
                            stderr=stderr,
                            env=source,
                            popen_factory=popen_factory,
                        )
                    session.command_count += 1
                    result.commands_run += 1
                    _audit_command(session, command, command_result, env=source)
                    ai_result, ai_output_used = _agent_result_for_ai(
                        command_result,
                        session,
                        source,
                        ai_output_used,
                    )
                    pending_results.append(ai_result)
                    persist_agent_audit(session, root=audit_root, env=source)
                    if command_result.status != "ok":
                        result.command_failed = True
                        if command_result.status == "interrupted":
                            session.stopped = True
                            result.stopped = True
                        print(
                            f"[AuraScan] Command finished with {command_result.status} "
                            f"(exit {command_result.exit_code}); remaining commands were stopped.",
                            file=stderr,
                        )
                        break
                tool_rounds += 1
                if not pending_results or session.provider_requests >= AGENT_MAX_PROVIDER_REQUESTS:
                    break
                if result.command_failed:
                    break
                if pending_results:
                    print("[AuraScan] AI is reviewing bounded terminal results...", file=stdout, flush=True)
                    review = ask_agent_ai(
                        current,
                        question,
                        turns,
                        access=session.access,
                        approval=session.approval,
                        facts_only=facts_only or current.privacy_mode == "facts-only",
                        command_results=pending_results,
                        env=source,
                        urlopen=urlopen,
                    )
                    session.provider_requests += 1
                    if review.status == "ok":
                        print("\n[AuraScan] Agent result review", file=stdout)
                        print(review.answer, file=stdout)
                        response = review
                        current, _review_probes, review_outcome = _handle_verified_requests(
                            current,
                            response,
                            runtime,
                            input_func,
                            stdout,
                            stderr,
                        )
                        if review_outcome.attempted:
                            result.action_outcome = review_outcome
                            if review_outcome.applied or review_outcome.source_changed:
                                break
                    else:
                        result.provider_failed = True
                        print(
                            "[AuraScan] Terminal results are shown above, but the AI result review failed.",
                            file=stderr,
                        )
                        break
                    pending_results = []
            turns.append(FollowUpTurn(question, response.answer))
            prompt = "Ask another question, or press Enter to finish: "
    except KeyboardInterrupt:
        print("\n[AuraScan] Stopping the active agent session...", file=stderr)
        session.stopped = True
        result.stopped = True
    finally:
        if session.access == "root-shell" and privileged_tools is not None:
            _revoke_root_grant(
                session,
                privileged_tools=privileged_tools,
                runner=runner,
            )
        session.stopped = True
        result.questions = session.questions
        result.provider_requests = session.provider_requests
        try:
            persist_agent_audit(session, root=audit_root, env=source)
        except OSError as exc:
            print(f"[AuraScan] Warning: agent audit could not be saved: {_redact_agent_text(str(exc))}", file=stderr)
    if int(time.time()) >= session.expires_at:
        print("[AuraScan] Agent session time limit reached.", file=stdout)
    elif session.command_count >= AGENT_MAX_COMMANDS_PER_SESSION:
        print("[AuraScan] Agent command limit reached.", file=stdout)
    elif session.provider_requests >= AGENT_MAX_PROVIDER_REQUESTS:
        print("[AuraScan] Agent provider request limit reached.", file=stdout)
    return result


def _load_agent_context(
    context_id: str,
    *,
    latest: bool,
    env: Mapping[str, str],
    context_root: Path,
    incident_root: Optional[Path],
) -> Optional[FollowUpContext]:
    context = None
    if context_id and not latest:
        context = load_followup_context(context_id, context_root)
        if context is None:
            context = context_from_saved_incident(
                context_id,
                env=env,
                incident_root=incident_root,
            )
    else:
        context = latest_followup_context(context_root)
        if context is None:
            context = context_from_latest_saved_incident(
                env=env,
                incident_root=incident_root,
            )
    if context is not None:
        persist_followup_context(context, context_root)
    return context


def run_agent(
    argv: Optional[Sequence[str]] = None,
    *,
    input_func: Callable[[str], str] = input,
    stdout=None,
    stderr=None,
    env: Optional[Mapping[str, str]] = None,
    urlopen: Optional[Callable] = None,
    runner: Callable = subprocess.run,
    popen_factory: Callable = subprocess.Popen,
    which: Callable[[str], Optional[str]] = shutil.which,
    context_root: Optional[Path] = None,
    incident_root: Optional[Path] = None,
    system_root: Optional[Path] = None,
    audit_root: Optional[Path] = None,
    helper: Path = Path("/usr/bin/aurascan"),
    root_policy_path: Path = AGENT_ROOT_POLICY_PATH,
    root_policy_uid: int = 0,
    runtime_root: Path = AGENT_RUNTIME_ROOT,
    root_audit_root: Path = AGENT_ROOT_AUDIT_ROOT,
    force_interactive: Optional[bool] = None,
) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    args = build_agent_parser().parse_args(list(argv or []))
    hidden = bool(
        args.set_root_policy is not None
        or args.issue_root_session
        or args.execute_request
        or args.revoke_root_session
    )
    if hidden:
        scrub_agent_helper_environment()
    source = dict(os.environ if env is None else env)
    recovery_runtime = (
        source.get("AURASCAN_RECOVERY_RUNTIME", "").strip().lower()
        in {"1", "true", "yes", "on"}
        or AGENT_RECOVERY_RUNTIME_MARKER.exists()
    )
    if recovery_runtime:
        if hidden:
            print(json.dumps({"ok": False, "error": "agent helpers are disabled in recovery mode"}), file=stdout)
        else:
            print("[AuraScan] Policy-Gated Repair Agent is not available in recovery mode v1.", file=stderr)
        return EXIT_FOLLOWUP_UNAVAILABLE

    if args.set_root_policy is not None:
        if os.geteuid() != 0:
            print("[AuraScan] Agent root policy writes require root privileges.", file=stderr)
            return EXIT_AGENT_ROOT_REFUSED
        ok, message = write_agent_root_policy(
            args.set_root_policy == "1",
            args.root_max_approval or "each-command",
            args.root_max_minutes or AGENT_DEFAULT_SESSION_MINUTES,
            path=root_policy_path,
        )
        print(message, file=stdout if ok else stderr)
        return 0 if ok else EXIT_AGENT_ROOT_REFUSED
    if args.issue_root_session:
        if os.geteuid() != 0:
            print(json.dumps({"ok": False, "error": "root helper requires root"}), file=stdout)
            return EXIT_AGENT_ROOT_REFUSED
        response = issue_root_session(
            Path(args.issue_root_session),
            policy_path=root_policy_path,
            runtime_root=runtime_root,
            runner=runner,
            which=which,
            policy_uid=root_policy_uid,
        )
        print(json.dumps(response), file=stdout)
        return 0 if response.get("ok") else EXIT_AGENT_ROOT_REFUSED
    if args.execute_request:
        if os.geteuid() != 0:
            print(json.dumps({"ok": False, "error": "root helper requires root"}), file=stdout)
            return EXIT_AGENT_ROOT_REFUSED
        response = execute_root_command_request(
            Path(args.execute_request),
            runtime_root=runtime_root,
            audit_root=root_audit_root,
            stdout=stdout,
            stderr=stderr,
            env={},
            popen_factory=popen_factory,
        )
        print(json.dumps(response), file=stdout)
        return 0 if response.get("ok") else EXIT_AGENT_EXECUTION_FAILED
    if args.revoke_root_session:
        if os.geteuid() != 0:
            print(json.dumps({"ok": False, "error": "root helper requires root"}), file=stdout)
            return EXIT_AGENT_ROOT_REFUSED
        response = revoke_root_session(
            Path(args.revoke_root_session),
            runtime_root=runtime_root,
        )
        print(json.dumps(response), file=stdout)
        return 0 if response.get("ok") else EXIT_AGENT_ROOT_REFUSED

    if force_interactive is None and not (
        getattr(stdout, "isatty", lambda: False)()
        and getattr(sys.stdin, "isatty", lambda: False)()
    ):
        print("[AuraScan] Repair Agent requires an interactive foreground terminal.", file=stderr)
        return EXIT_FOLLOWUP_UNAVAILABLE
    ai_config = resolve_ai_config(source)
    if not ai_config.ready:
        print("[AuraScan] Repair Agent requires a configured foreground AI provider.", file=stderr)
        return EXIT_FOLLOWUP_UNAVAILABLE
    config = resolve_agent_config(source)
    if config.error:
        print(f"[AuraScan] Repair Agent configuration error: {config.error}.", file=stderr)
        return EXIT_AGENT_CONFIG_ERROR
    requested_access = args.access or config.access
    requested_approval = args.approval or config.approval
    effective_requested_approval = effective_agent_approval(
        requested_access,
        requested_approval,
    )
    requested_output = args.output_sharing or config.output_sharing
    requested_minutes = args.session_timeout or config.session_timeout_minutes
    if requested_minutes < 1 or requested_minutes > AGENT_MAX_SESSION_MINUTES:
        print(
            f"[AuraScan] Session timeout must be between 1 and {AGENT_MAX_SESSION_MINUTES} minutes.",
            file=stderr,
        )
        return EXIT_AGENT_CONFIG_ERROR
    if AGENT_ACCESS_ORDER[requested_access] > AGENT_ACCESS_ORDER[config.access]:
        print(
            f"[AuraScan] Requested {requested_access} exceeds configured access {config.access}. "
            "Change it through `aurascan init` first.",
            file=stderr,
        )
        return EXIT_AGENT_CONFIG_ERROR
    if requested_access == "root-shell":
        policy = read_agent_root_policy(root_policy_path, required_uid=root_policy_uid)
        if policy.error or not policy.allowed:
            print(
                f"[AuraScan] Root-shell policy is unavailable: {policy.error or 'disabled'}. "
                "Enable it explicitly through `aurascan init --allow-agent-root`.",
                file=stderr,
            )
            return EXIT_AGENT_ROOT_REFUSED
        effective_policy_approval = effective_agent_approval(
            "root-shell",
            policy.max_approval,
        )
        if AGENT_APPROVAL_ORDER[effective_requested_approval] > AGENT_APPROVAL_ORDER[effective_policy_approval]:
            print("[AuraScan] Requested approval mode exceeds the root policy ceiling.", file=stderr)
            return EXIT_AGENT_ROOT_REFUSED
        requested_minutes = min(requested_minutes, policy.max_minutes)
    root = context_root or user_followup_root(source)
    context = _load_agent_context(
        args.context_id or "",
        latest=bool(args.latest),
        env=source,
        context_root=root,
        incident_root=incident_root,
    )
    if context is None:
        print("[AuraScan] No retained AuraScan result is available for the agent.", file=stderr)
        return EXIT_FOLLOWUP_UNAVAILABLE
    runtime = build_default_runtime(
        context,
        env=source,
        runner=runner,
        which=which,
        urlopen=urlopen,
        context_root=root,
        incident_root=incident_root,
        system_root=system_root,
    )
    if requested_access == "guarded":
        from aurascan.core.followup import run_followup_session

        guarded = run_followup_session(
            context,
            runtime=runtime,
            input_func=input_func,
            stdout=stdout,
            stderr=stderr,
            env=source,
            facts_only=bool(args.facts_only),
            urlopen=urlopen,
            context_root=root,
        )
        if guarded.action_outcome.failed:
            return EXIT_FOLLOWUP_ACTION_FAILED
        return EXIT_FOLLOWUP_PROVIDER_ERROR if guarded.provider_failed else 0
    result = run_agent_session(
        context,
        access=requested_access,
        approval=requested_approval,
        output_sharing=requested_output,
        session_timeout_minutes=requested_minutes,
        runtime=runtime,
        input_func=input_func,
        stdout=stdout,
        stderr=stderr,
        env=source,
        facts_only=bool(args.facts_only),
        urlopen=urlopen,
        context_root=root,
        audit_root=audit_root,
        helper=helper,
        runner=runner,
        which=which,
        popen_factory=popen_factory,
        root_policy_path=root_policy_path,
        root_policy_uid=root_policy_uid,
    )
    if result.action_outcome.failed or result.command_failed:
        return EXIT_AGENT_EXECUTION_FAILED
    if result.setup_failed:
        return EXIT_AGENT_ROOT_REFUSED
    if result.provider_failed:
        return EXIT_FOLLOWUP_PROVIDER_ERROR
    return 0


def agent_doctor_status(
    env: Optional[Mapping[str, str]] = None,
    *,
    policy_path: Path = AGENT_ROOT_POLICY_PATH,
    policy_uid: int = 0,
    audit_root: Optional[Path] = None,
    runtime_root: Path = AGENT_RUNTIME_ROOT,
    which: Callable[[str], Optional[str]] = shutil.which,
    runner: Callable = subprocess.run,
) -> Dict[str, object]:
    source = dict(os.environ if env is None else env)
    config = resolve_agent_config(source)
    policy = read_agent_root_policy(policy_path, required_uid=policy_uid)
    root = audit_root or user_agent_root(source)
    storage_exists = root.exists()
    storage_safe = True
    storage_error = ""
    if storage_exists:
        try:
            metadata = root.stat()
            storage_safe = (
                root.is_dir()
                and not root.is_symlink()
                and metadata.st_uid == current_user_uid()
                and metadata.st_mode & 0o077 == 0
            )
        except OSError as exc:
            storage_safe = False
            storage_error = str(exc)
    stale_sessions = 0
    uid_dir = runtime_root / str(current_user_uid())
    stale_sessions_checked = not uid_dir.exists() or os.geteuid() == 0
    if os.geteuid() == 0 and uid_dir.is_dir() and not uid_dir.is_symlink():
        for path in uid_dir.glob("agent-*.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if int(data.get("expires_at") or 0) <= int(time.time()):
                    stale_sessions += 1
            except (OSError, json.JSONDecodeError):
                stale_sessions += 1
    snapshot_ready, snapshot_detail = _snapshot_capability(which=which, runner=runner)
    return {
        "config": config.to_dict(),
        "root_policy": policy.to_dict(),
        "bash": which("bash") or "",
        "sudo": which("sudo") or "",
        "findmnt": which("findmnt") or "",
        "snapper": which("snapper") or "",
        "snapshot_ready": snapshot_ready,
        "snapshot_detail": snapshot_detail,
        "audit_root": str(root),
        "audit_storage_exists": storage_exists,
        "audit_storage_safe": storage_safe,
        "audit_storage_error": storage_error,
        "stale_root_sessions": stale_sessions,
        "stale_root_sessions_checked": stale_sessions_checked,
        "foreground_only": True,
    }
