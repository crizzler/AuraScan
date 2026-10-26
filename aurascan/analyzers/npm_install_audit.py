"""Bounded pre-install audit for a JavaScript project.

``npm install`` runs lifecycle scripts (``preinstall``, ``install``,
``postinstall``, ``prepare``) before the dependency tree is trusted, so a single
malicious project can read the environment, send it out, and evaluate whatever
comes back. This module inspects the project's own install-time code as inert
text. It never runs npm, node, a shell, or any captured file, and it does not
fetch package metadata.

Only the files a lifecycle command names are read, and only through the lexical
token subset in :mod:`aurascan.analyzers.npm_lifecycle`. Dependency lifecycle
scripts cannot be known without registry metadata, so that gap is reported as
unknown coverage instead of being guessed.
"""

import posixpath
import shlex
from typing import Dict, List, Mapping, Optional, Sequence

from aurascan.analyzers.npm_lifecycle import _Incomplete, _tokens
from aurascan.analyzers.npm_metadata import (
    MetadataIncomplete,
    strict_json_object,
)
from aurascan.core.models import (
    Confidence,
    EvidenceQuality,
    Finding,
    Phase,
    Severity,
    Source,
)

MAX_MANIFEST_CHARS = 1024 * 1024
MAX_SCRIPT_FILE_CHARS = 1024 * 1024

LIFECYCLE_HOOKS = ("preinstall", "install", "postinstall", "prepare")

RULE_ENV_EXFIL_EVAL = "SUPPLYCHAIN-NPM-INSTALL-ENV-EXFIL-EVAL-001"
RULE_REMOTE_SCRIPT = "SUPPLYCHAIN-NPM-INSTALL-REMOTE-SCRIPT-001"
RULE_INCOMPLETE = "NPM-LIFECYCLE-INSPECTION-INCOMPLETE-001"

_NETWORK_MODULES = frozenset({"http", "https", "net", "tls", "dns", "undici"})
_NETWORK_CALLS = frozenset({"fetch", "XMLHttpRequest", "WebSocket"})
_EVAL_CALLS = frozenset({"eval"})
_VM_CALLS = frozenset({"runInThisContext", "runInNewContext", "runInContext", "compileFunction"})


def _finding(rule_id: str, path: str, severity: Severity, explanation: str,
             labels: Sequence[str], *, line: Optional[int] = None,
             blocking: bool = False, coverage: bool = False,
             recommendation: str = "") -> Finding:
    return Finding(
        rule_id=rule_id,
        package_name="npm-project",
        package_version="unknown",
        phase=Phase.unpacked_source_scan,
        source=Source.deterministic_rule,
        severity=severity,
        confidence=Confidence.HIGH if not coverage else Confidence.MEDIUM,
        evidence_quality=EvidenceQuality.strong_heuristic,
        file_path=path,
        explanation=explanation,
        recommendation=recommendation or (
            "Do not run npm install in this project on a machine that holds credentials. "
            "Review the named install-time file first, or install with --ignore-scripts in a "
            "disposable, resource-limited environment."
        ),
        blocks_installation=blocking,
        requires_manual_review=not blocking,
        evidence_snippet="; ".join(labels),
        line_number=line,
        false_positive_notes=(
            "Only supported literal lifecycle commands and bounded lexical evidence from the "
            "same project are correlated. Static evidence does not prove the code ran, that "
            "data left the machine, or that an account was compromised."
        ),
    )


def _incomplete(path: str, reason: str) -> Finding:
    return _finding(
        RULE_INCOMPLETE,
        path,
        Severity.HIGH,
        "Install-time code could not be inspected completely within the supported bounds: "
        + reason,
        ("bounded install-time inspection incomplete",),
        coverage=True,
    )


def _pair(tokens: Sequence, index: int) -> Optional[str]:
    if index + 2 < len(tokens):
        if tokens[index + 1].value == "." and tokens[index + 2].kind == "id":
            return tokens[index + 2].value
    return None


def install_code_signals(text: str) -> Optional[Dict[str, int]]:
    """Return correlated install-time signals, or ``None`` when unsupported.

    The lexical subset is the same one the captured-package analyzer uses, so a
    call spelled inside a comment, string, or regular expression is not evidence.
    """

    if len(text) > MAX_SCRIPT_FILE_CHARS:
        return None
    try:
        tokens = _tokens(text)
    except _Incomplete:
        return None

    signals: Dict[str, int] = {}
    environment_line = None
    network_line = None
    eval_line = None

    for index, token in enumerate(tokens):
        if token.kind != "id":
            continue
        name = token.value
        if name == "process" and _pair(tokens, index) == "env":
            environment_line = environment_line or token.line
        if name in _NETWORK_CALLS:
            network_line = network_line or token.line
        if name == "require" or name == "import":
            following = next(
                (item for item in tokens[index + 1:index + 4] if item.kind == "string"),
                None,
            )
            if following is not None and following.value.split("/")[-1] in _NETWORK_MODULES:
                network_line = network_line or token.line
        if name == "http" or name == "https":
            # ``http.request(...)`` / ``https.get(...)`` after a require binding.
            if index + 1 < len(tokens) and tokens[index + 1].value == ".":
                if index + 2 < len(tokens) and tokens[index + 2].value in {
                    "request", "get", "createServer"
                }:
                    network_line = network_line or token.line
        if name in _EVAL_CALLS:
            if index + 1 < len(tokens) and tokens[index + 1].value == "(":
                eval_line = eval_line or token.line
        if name == "Function" and index > 0 and tokens[index - 1].value == "new":
            eval_line = eval_line or token.line
        if name == "vm" and _pair(tokens, index) in _VM_CALLS:
            eval_line = eval_line or token.line

    if environment_line is not None:
        signals["environment access"] = environment_line
    if network_line is not None:
        signals["outbound network call"] = network_line
    if eval_line is not None:
        signals["dynamic code evaluation"] = eval_line
    return signals


def _local_entry(command: Sequence[str]) -> Optional[str]:
    if not command:
        return None
    runner = posixpath.basename(command[0])
    if runner not in {"node", "bun"}:
        return None
    for argument in command[1:]:
        if argument.startswith("-"):
            continue
        return argument
    return None


def _remote_pipe(command: Sequence[str]) -> bool:
    if "|" not in command:
        return False
    joined = " ".join(command)
    fetches = any(word in joined for word in ("curl ", "wget ", "fetch "))
    executes = any(word in command for word in ("sh", "bash", "zsh", "node", "bun", "python3"))
    return fetches and executes


def audit_npm_install(
    manifest_path: str,
    manifest_text: str,
    lifecycle_files: Mapping[str, str],
) -> List[Finding]:
    """Inspect a project's install-time code from already captured text.

    ``lifecycle_files`` maps the absolute path of each file named by a lifecycle
    command to its bounded text. Missing entries are reported as incomplete
    coverage, never as clean.
    """

    if len(manifest_text) > MAX_MANIFEST_CHARS:
        return [_incomplete(manifest_path, "the package manifest exceeds the supported size")]
    try:
        manifest = strict_json_object(manifest_text)
    except (MetadataIncomplete, ValueError, RecursionError):
        return [_incomplete(manifest_path, "the package manifest is not a supported JSON object")]

    hooks = manifest.get("scripts", {})
    if hooks is None:
        hooks = {}
    if not isinstance(hooks, dict):
        return [_incomplete(manifest_path, "the scripts field is not an object")]

    project_dir = posixpath.dirname(manifest_path)
    findings: List[Finding] = []
    for hook in LIFECYCLE_HOOKS:
        command_text = hooks.get(hook)
        if command_text is None:
            continue
        if not isinstance(command_text, str):
            findings.append(_incomplete(manifest_path, "a lifecycle command is not a string"))
            continue
        try:
            command = shlex.split(command_text, comments=False, posix=True)
        except ValueError:
            findings.append(
                _incomplete(manifest_path, "a lifecycle command could not be parsed")
            )
            continue
        if not command:
            continue
        if _remote_pipe(command):
            findings.append(
                _finding(
                    RULE_REMOTE_SCRIPT,
                    manifest_path,
                    Severity.HIGH,
                    "An npm lifecycle command pipes a network download into a shell or "
                    "interpreter, so the project can execute code that is not in the repository.",
                    (f"{hook} pipes a remote download into an interpreter",),
                    blocking=True,
                    recommendation=(
                        "Do not run npm install here. Inspect the lifecycle command, and if you "
                        "still need the project, install with --ignore-scripts in a disposable "
                        "environment without credentials."
                    ),
                )
            )
            continue
        entry = _local_entry(command)
        if entry is None:
            continue
        target = posixpath.normpath(posixpath.join(project_dir, entry))
        if not target.startswith(project_dir + "/"):
            findings.append(
                _incomplete(
                    manifest_path,
                    f"the {hook} command runs a file outside the project directory",
                )
            )
            continue
        text = lifecycle_files.get(target)
        if not isinstance(text, str):
            findings.append(
                _incomplete(manifest_path, f"the {hook} entry file could not be captured")
            )
            continue
        signals = install_code_signals(text)
        if signals is None:
            findings.append(
                _incomplete(manifest_path, f"the {hook} entry file is not inspectable")
            )
            continue
        if (
            "environment access" in signals
            and "outbound network call" in signals
            and "dynamic code evaluation" in signals
        ):
            findings.append(
                _finding(
                    RULE_ENV_EXFIL_EVAL,
                    target,
                    Severity.CRITICAL,
                    "Install-time code reads environment variables, contacts a network "
                    "destination, and evaluates dynamic code in the same file. This is the "
                    "shape of an install-time backdoor; static evidence does not prove that "
                    "data left the machine.",
                    (
                        "environment access",
                        "outbound network call",
                        "dynamic code evaluation",
                    ),
                    line=min(signals.values()),
                    blocking=True,
                    recommendation=(
                        "Do not run npm install in this project on a machine with credentials. "
                        "Treat environment variables, tokens, and SSH or cloud credentials on "
                        "this host as exposed if the project was already installed."
                    ),
                )
            )
    return findings
