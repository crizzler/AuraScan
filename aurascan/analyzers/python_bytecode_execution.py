"""Bounded acquired-shell references to captured precompiled carrier paths.

The caller supplies only stable snapshots.  This module neither opens a path
nor evaluates shell/Python code.  Script location alone never establishes its
runtime working directory, and import names never establish a carrier match.
"""

import posixpath
import re
from pathlib import Path
from typing import List, NamedTuple, Sequence, Tuple

from aurascan.analyzers.aur_propagation import _active_shell_text, _logical_shell_views
from aurascan.analyzers.python_bytecode import PYTHON_PRECOMPILED_KINDS
from aurascan.analyzers.remote_stage import _commands_and_constants, _executed_path_status
from aurascan.core.models import Confidence, EvidenceQuality, Finding, Phase, Severity, Source


MAX_PRECOMPILED_CARRIERS = 5000
MAX_PRECOMPILED_SCRIPTS = 5000
MAX_PRECOMPILED_SCRIPT_CHARS = 5 * 1024 * 1024
MAX_PRECOMPILED_CORRELATION_WORK = 262144
MAX_PRECOMPILED_EXEC_FINDINGS = 128
_PYTHON_COMMAND = re.compile(r"python(?:\d+(?:\.\d+)*)?\Z")
_COMPOUND_SHELL = re.compile(r"[(){}]|\b(?:if|then|else|elif|fi|for|while|until|case|esac|do|done|function)\b")
_SHELL_SEPARATE_CONTEXT = re.compile(r"\||(?<!&)&(?!&)")
_DYNAMIC_PATH = re.compile(r"[$`*?\[\]{}\\\x00-\x1f\x7f]")
_PATH_MUTATORS = frozenset({
    "cp", "mv", "rm", "install", "dd", "tee", "truncate", "unlink",
    "alias", "unalias", "enable", "eval", "source", ".",
})


class PrecompiledExecutionAnalysis(NamedTuple):
    findings: Tuple[Finding, ...]
    complete: bool


def is_precompiled_control_script(path: str) -> bool:
    # Make recipes have separate shells and their own expansion rules.  Do not
    # feed them, Markdown, Python source, or arbitrary text into a shell parser.
    return str(path).lower().endswith((".sh", ".bash", ".zsh"))


def _literal_path(value: str) -> str:
    if not value or len(value) > 4096 or _DYNAMIC_PATH.search(value):
        return ""
    return posixpath.normpath(value)


def _python_operand(arguments: Sequence[str]) -> Tuple[str, bool]:
    """Keep a raw input path for coverage checks without expanding variables."""

    index = 0
    complete = True
    while index < len(arguments):
        value = arguments[index]
        if value == "--":
            return (arguments[index + 1] if index + 1 < len(arguments) else ""), complete
        if value in {
            "-h", "--help", "--help-env", "--help-xoptions", "--help-all",
            "-V", "--version", "-VV",
        } or value.startswith(("-c", "-m")):
            return "", True
        if value in {"-W", "-X", "--check-hash-based-pycs"}:
            if index + 1 >= len(arguments):
                return "", False
            index += 2
            continue
        if value.startswith(("-W", "-X", "--check-hash-based-pycs=")) or value in {
            "-b", "-B", "-d", "-E", "-i", "-I", "-O", "-OO",
            "-P", "-q", "-s", "-S", "-u", "-v", "-x",
        }:
            index += 1
            continue
        if value == "-" or value.startswith(("<", ">", "0<", "1>", "2>")):
            return "", True
        if value.startswith("-"):
            complete = False
            index += 1
            continue
        return value, complete
    return "", complete


def analyze_precompiled_execution(
    root: Path,
    carriers: Sequence[Tuple[str, str]],
    scripts: Sequence[Tuple[str, str]],
) -> PrecompiledExecutionAnalysis:
    """Correlate captured ``(absolute path, kind)`` and ``(path, shell text)``.

    Return incomplete coverage on resource/parser limits or a matching relative
    reference without a proven working directory.  Only a captured absolute
    path, or a relative path after a supported literal directory change in a
    simple shell stream, can produce a blocking execution-reference finding.
    """

    if len(carriers) > MAX_PRECOMPILED_CARRIERS or len(scripts) > MAX_PRECOMPILED_SCRIPTS:
        return PrecompiledExecutionAnalysis((), False)
    root_path = _literal_path(str(root))
    if not root_path or not posixpath.isabs(root_path):
        return PrecompiledExecutionAnalysis((), False)
    root_prefix = root_path.rstrip("/") + "/"
    paths = set()
    relative_paths = []
    for path, kind in carriers:
        normalized = _literal_path(str(path))
        if kind not in PYTHON_PRECOMPILED_KINDS:
            continue
        if not normalized or not normalized.startswith(root_prefix):
            return PrecompiledExecutionAnalysis((), False)
        paths.add(normalized)
        relative_paths.append(normalized[len(root_prefix):])
    if not paths:
        return PrecompiledExecutionAnalysis((), True)

    findings: List[Finding] = []
    complete = True
    total_chars = 0
    work = 0
    emitted = set()
    for script_path, text in scripts:
        if not is_precompiled_control_script(str(script_path)):
            continue
        normalized_script = _literal_path(str(script_path))
        if not normalized_script or not normalized_script.startswith(root_prefix):
            return PrecompiledExecutionAnalysis(tuple(findings), False)
        total_chars += len(text)
        if total_chars > MAX_PRECOMPILED_SCRIPT_CHARS:
            return PrecompiledExecutionAnalysis(tuple(findings), False)
        parsed = _commands_and_constants(text)
        if parsed is None:
            complete = False
            continue
        commands, _unused_constants = parsed
        # Constant assignments are intentionally not folded across shell
        # scopes.  Complex control flow also prevents carrying a guessed cwd
        # between commands, including function bodies and subshells.
        _raw_view, command_view = _logical_shell_views(_active_shell_text(text))
        simple_stream = not (
            _COMPOUND_SHELL.search(command_view)
            or _SHELL_SEPARATE_CONTEXT.search(command_view)
        )
        cwd = ""
        mutated = False
        for command in commands:
            work += 1
            if work > MAX_PRECOMPILED_CORRELATION_WORK:
                return PrecompiledExecutionAnalysis(tuple(findings), False)
            executable = posixpath.basename(command.executable)
            arguments = command.arguments
            if (
                executable in _PATH_MUTATORS
                or any(">" in token for token in arguments)
                or (
                    executable in {"sed", "perl"}
                    and any(value.startswith("-i") for value in arguments)
                )
            ):
                # A prior writer or command-definition change may invalidate
                # the captured operand.  Preserve coverage uncertainty instead
                # of claiming that the later reference still uses these bytes.
                mutated = True
            if executable in {"cd", "pushd", "popd"}:
                if executable == "cd" and simple_stream:
                    operands = list(arguments)
                    if operands and operands[0] == "--":
                        operands.pop(0)
                    target = _literal_path(operands[0]) if len(operands) == 1 else ""
                    if target and not target.startswith("-"):
                        cwd = target if target.startswith("/") else (
                            posixpath.normpath(posixpath.join(cwd, target)) if cwd else ""
                        )
                    else:
                        cwd = ""
                else:
                    cwd = ""
                continue
            python_command = bool(_PYTHON_COMMAND.fullmatch(executable))
            if not python_command and "/" not in command.executable:
                continue
            candidate, command_complete = (
                _python_operand(arguments) if python_command
                else _executed_path_status(command, {})
            )
            if not candidate:
                continue
            normalized = _literal_path(candidate)
            exact = ""
            if normalized:
                if normalized.startswith("/"):
                    exact = normalized if normalized in paths else ""
                elif cwd:
                    resolved = posixpath.normpath(posixpath.join(cwd, normalized))
                    exact = resolved if resolved in paths else ""
            if exact:
                if not command_complete or mutated or not simple_stream:
                    complete = False
                    continue
                key = (normalized_script, command.line_number, exact)
                if key not in emitted:
                    if len(findings) >= MAX_PRECOMPILED_EXEC_FINDINGS:
                        return PrecompiledExecutionAnalysis(tuple(findings), False)
                    emitted.add(key)
                    findings.append(_execution_finding(normalized_script, command.line_number))
                continue
            if normalized.startswith("/") or (normalized and cwd):
                continue
            # Unknown cwd or dynamic parent references cannot prove that a
            # similarly named captured path is the executed operand.  Require
            # a bounded exact suffix match before reporting that uncertainty.
            suffix = normalized if normalized else posixpath.basename(candidate)
            if not suffix or _DYNAMIC_PATH.search(suffix):
                continue
            suffix = suffix[2:] if suffix.startswith("./") else suffix
            for relative in relative_paths:
                work += 1
                if work > MAX_PRECOMPILED_CORRELATION_WORK:
                    return PrecompiledExecutionAnalysis(tuple(findings), False)
                if relative == suffix or relative.endswith("/" + suffix):
                    complete = False
                    break
    return PrecompiledExecutionAnalysis(tuple(findings), complete)


def _execution_finding(script_path: str, line_number: int) -> Finding:
    return Finding(
        rule_id="PYTHON-BYTECODE-EXEC-001",
        package_name="unknown",
        package_version="unknown",
        phase=Phase.unpacked_source_scan,
        source=Source.deterministic_rule,
        severity=Severity.CRITICAL,
        confidence=Confidence.CONFIRMED,
        evidence_quality=EvidenceQuality.confirmed_static_pattern,
        file_path=script_path,
        line_number=line_number,
        explanation=(
            "Acquired shell control text supplies the exact path of a captured "
            "precompiled Python carrier for execution. Nearby source does not "
            "establish the behavior of the precompiled bytes."
        ),
        recommendation=(
            "Do not build or install until the carrier provenance and its "
            "execution reference have been independently reviewed."
        ),
        false_positive_notes=(
            "The carrier may be legitimate. Static correlation does not prove "
            "a valid executable payload, malicious behavior, or that this command ran."
        ),
        blocks_installation=True,
        requires_manual_review=False,
        evidence_snippet="captured precompiled carrier path is supplied for execution in acquired shell text",
    )
