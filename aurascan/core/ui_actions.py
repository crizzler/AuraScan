"""Fixed action catalog for AuraScan desktop user interfaces.

The catalog is the only place a desktop action can be defined. A renderer never
supplies an executable, a flag, or a command string: it selects an action ID and
supplies the declared arguments, and the desktop shell runs the fixed argument
vector this module builds.

Mutating actions stay terminal-only in this phase. Any future action that the
renderer may request and that changes local state must also bind the exact
report the user saw, which the core revalidates with ``verify_report_binding``
before acting.
"""

import hashlib
import hmac
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Tuple

MAX_ARGUMENT_LENGTH = 4096
MAX_ACTIONS = 50
ACTION_KINDS = ("read_only", "terminal_only")
CONFIRMATIONS = ("none", "hash_bound", "terminal_only")
PLACEHOLDER = re.compile(r"^\{([a-z][a-z0-9_]{0,63})\}$")
UNSAFE_ARGUMENT_CHARS = re.compile(r"[\x00-\x1f\x7f]")


class UIActionError(RuntimeError):
    """Raised when an action request does not match the catalog."""


@dataclass(frozen=True)
class ActionArgument:
    name: str
    kind: str
    label: str

    def to_dict(self) -> Dict[str, object]:
        return {"name": self.name, "kind": self.kind, "label": self.label}


@dataclass(frozen=True)
class UIAction:
    action_id: str
    label: str
    summary: str
    kind: str
    confirmation: str
    argv: Tuple[str, ...]
    arguments: Tuple[ActionArgument, ...] = ()
    notes: str = ""

    def argument_names(self) -> Tuple[str, ...]:
        return tuple(argument.name for argument in self.arguments)

    def to_dict(self) -> Dict[str, object]:
        return {
            "id": self.action_id,
            "label": self.label,
            "summary": self.summary,
            "kind": self.kind,
            "confirmation": self.confirmation,
            "renderer_may_request": self.kind == "read_only",
            "arguments": [argument.to_dict() for argument in self.arguments],
            "argv_preview": list(self.argv),
            "notes": self.notes,
        }


ACTIONS: Tuple[UIAction, ...] = (
    UIAction(
        action_id="scan_package",
        label="Scan a package archive",
        summary=(
            "Audit one package archive with the default deterministic rules and "
            "return the bounded report projection."
        ),
        kind="read_only",
        confirmation="none",
        argv=("aurascan", "--pkg", "{package_path}", "--json"),
        arguments=(
            ActionArgument("package_path", "existing_file", "Package archive"),
        ),
        notes="Read-only. It inspects archive bytes and never installs anything.",
    ),
    UIAction(
        action_id="scan_pkgbuild",
        label="Scan a PKGBUILD",
        summary=(
            "Audit one PKGBUILD and its declared install hooks with the default "
            "deterministic rules."
        ),
        kind="read_only",
        confirmation="none",
        argv=("aurascan", "--pkgbuild", "{pkgbuild_path}", "--json"),
        arguments=(
            ActionArgument("pkgbuild_path", "existing_file", "PKGBUILD file"),
        ),
        notes="Read-only. The build script is parsed, never executed.",
    ),
    UIAction(
        action_id="project_report",
        label="Open a saved report",
        summary="Render a previously produced AuraScan JSON report.",
        kind="read_only",
        confirmation="none",
        argv=("aurascan", "ui", "--report", "{report_path}", "--json"),
        arguments=(
            ActionArgument("report_path", "existing_file", "Report file"),
        ),
        notes="Read-only. Raw package bytes and absolute paths stay out of the view.",
    ),
    UIAction(
        action_id="refresh_snapshot",
        label="Refresh the evidence snapshot",
        summary="Re-collect local check, detection-data and incident evidence.",
        kind="read_only",
        confirmation="none",
        argv=("aurascan", "ui", "--json"),
        notes="Read-only. It runs no package manager and contacts no model.",
    ),
    UIAction(
        action_id="repair_runtime_links",
        label="Repair missing shared libraries",
        summary=(
            "Scan recent package updates for missing shared libraries and offer "
            "the official provider packages."
        ),
        kind="terminal_only",
        confirmation="terminal_only",
        argv=("aurascan", "doctor", "--fix-runtime-links"),
        notes=(
            "Installs packages through sudo, so it stays in the terminal and is "
            "never requested by the renderer."
        ),
    ),
    UIAction(
        action_id="repair_hung_application",
        label="Repair a hung application",
        summary=(
            "Diagnose a wait-then-read pipe deadlock and offer a cached older "
            "package build."
        ),
        kind="terminal_only",
        confirmation="terminal_only",
        argv=("aurascan", "doctor", "--fix-hung-apps"),
        notes=(
            "Downgrades a package through sudo, so it stays in the terminal and "
            "is never requested by the renderer."
        ),
    ),
)


def action_catalog() -> List[Dict[str, object]]:
    return [action.to_dict() for action in ACTIONS]


def action_by_id(action_id: str) -> UIAction:
    for action in ACTIONS:
        if action.action_id == action_id:
            return action
    raise UIActionError("unknown action identifier")


def _validated_argument(name: str, value: object) -> str:
    if not isinstance(value, str) or not value:
        raise UIActionError("action argument {0} is missing".format(name))
    if len(value) > MAX_ARGUMENT_LENGTH:
        raise UIActionError("action argument {0} is too long".format(name))
    if UNSAFE_ARGUMENT_CHARS.search(value):
        raise UIActionError("action argument {0} contains control characters".format(name))
    if value.startswith("-"):
        raise UIActionError("action argument {0} looks like a flag".format(name))
    if not Path(value).is_absolute():
        raise UIActionError("action argument {0} must be an absolute path".format(name))
    return value


def build_action_argv(action_id: str, values: Optional[Mapping[str, str]] = None) -> List[str]:
    """Return the fixed argument vector for an action and its declared values."""

    action = action_by_id(action_id)
    supplied = dict(values or {})
    declared = set(action.argument_names())
    for name in supplied:
        if name not in declared:
            raise UIActionError("action has no argument named {0}".format(name))
    missing = declared - set(supplied)
    if missing:
        raise UIActionError("action is missing required arguments")
    argv: List[str] = []
    for part in action.argv:
        match = PLACEHOLDER.match(part)
        if match is None:
            argv.append(part)
            continue
        name = match.group(1)
        if name not in declared:
            raise UIActionError("action template references an undeclared argument")
        argv.append(_validated_argument(name, supplied.get(name)))
    return argv


def report_sha256(report_bytes: bytes) -> str:
    return hashlib.sha256(report_bytes).hexdigest()


def verify_report_binding(expected_sha256: str, report_bytes: bytes) -> None:
    """Fail closed unless the evidence still matches what the user confirmed."""

    if not isinstance(expected_sha256, str) or len(expected_sha256) != 64:
        raise UIActionError("report binding is malformed")
    actual = hashlib.sha256(report_bytes).hexdigest()
    if not hmac.compare_digest(actual, expected_sha256.lower()):
        raise UIActionError("report binding does not match the current evidence")
