"""Bounded static review of captured Linux VS Code task configuration.

Only literal process arguments and single shell commands are interpreted.
Extension tasks, inline programs, compound shell syntax, unresolved variables,
and unknown interpreter options remain incomplete coverage. Referenced assets
are never opened, decoded, or executed; signals describe configured behavior.
"""

from dataclasses import dataclass
import json
import math
import posixpath
import re
import shlex
from typing import List, Tuple

from aurascan.core.models import Confidence, EvidenceQuality, Finding, Phase, Severity, Source


MAX_TASK_BYTES = 1024 * 1024
MAX_TASKS = 128
MAX_NODES = 8192
MAX_DEPTH = 32
MAX_STRING = 8192
MAX_ARGUMENTS = 128
MAX_DEPENDENCIES = 512
_WORKSPACE = "${workspaceFolder}"
_DEFAULTS = frozenset({"type", "command", "args", "options"})
_OVERRIDE_CONTROL = frozenset({"tasks", "label", "dependsOn", "dependsOrder", "runOptions"})
_KINDS = {
    "font": frozenset({".otf", ".ttf", ".woff", ".woff2"}),
    "media": frozenset({".avif", ".bmp", ".gif", ".ico", ".jpeg", ".jpg", ".png", ".svg",
                        ".tif", ".tiff", ".webp", ".flac", ".m4a", ".mkv", ".mov", ".mp3",
                        ".mp4", ".ogg", ".wav", ".webm"}),
    "document": frozenset({".doc", ".docx", ".htm", ".html", ".md", ".odt", ".pdf", ".rtf", ".txt"}),
    "data": frozenset({".bin", ".csv", ".dat", ".data", ".json", ".xml", ".yaml", ".yml"}),
}
_SHELLS = frozenset({"sh", "bash", "dash", "ash", "zsh"})
_INTERPRETERS = _SHELLS | frozenset({"node", "nodejs", "bun", "python", "perl", "php", "ruby", "lua", "luajit"})
_CODE_ENV = frozenset({
    "NODE_OPTIONS", "NODE_PATH", "BUN_OPTIONS", "BASH_ENV", "ENV", "ZDOTDIR", "SHELLOPTS", "BASHOPTS",
    "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PYTHONINSPECT", "PYTHONBREAKPOINT", "PYTHONWARNINGS",
    "PERL5LIB", "PERL5OPT", "RUBYOPT", "RUBYLIB", "LUA_PATH", "LUA_CPATH", "LUA_INIT",
    "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "DYLD_INSERT_LIBRARIES",
})


@dataclass(frozen=True)
class EditorTaskSignal:
    task_index: int
    interpreter: str
    carrier_kind: str


@dataclass(frozen=True)
class EditorTaskAnalysis:
    signals: Tuple[EditorTaskSignal, ...]
    incomplete: bool


class _Incomplete(ValueError):
    pass


def _require(condition):
    if not condition:
        raise _Incomplete()


def _jsonc(payload):
    _require(type(payload) is bytes and len(payload) <= MAX_TASK_BYTES)
    text = payload.decode("utf-8-sig")
    output, index, quoted, escaped = [], 0, False, False
    while index < len(text):
        char = text[index]
        if quoted:
            output.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
            output.append(char)
        elif text.startswith("//", index):
            end = text.find("\n", index + 2)
            index = len(text) if end < 0 else end
            output.append("\n")
            continue
        elif text.startswith("/*", index):
            end = text.find("*/", index + 2)
            _require(end >= 0)
            output.append(" ")
            index = end + 2
            continue
        else:
            output.append(char)
        index += 1
    _require(not quoted)
    text = "".join(output)
    output, quoted, escaped, depth, previous = [], False, False, 0, ""
    for index, char in enumerate(text):
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            _require(depth <= MAX_DEPTH)
        elif char in "]}":
            depth -= 1
            _require(depth >= 0)
        elif char == ",":
            following = index + 1
            while following < len(text) and text[following] in " \r\n\t":
                following += 1
            if following < len(text) and text[following] in "]}":
                _require(bool(previous) and previous not in "[{,:")
                char = " "
        output.append(char)
        if not quoted and not char.isspace():
            previous = char

    def unique(pairs):
        value = {}
        for key, entry in pairs:
            _require(key not in value)
            value[key] = entry
        return value

    def integer(value):
        _require(len(value) <= 32)
        return int(value)

    def decimal(value):
        _require(len(value) <= 64)
        result = float(value)
        _require(math.isfinite(result))
        return result

    def constant(_value):
        raise _Incomplete()

    value = json.loads("".join(output), object_pairs_hook=unique, parse_int=integer,
                       parse_float=decimal, parse_constant=constant)
    pending, count = [value], 0
    while pending:
        entry = pending.pop()
        count += 1
        _require(count <= MAX_NODES)
        if isinstance(entry, dict):
            pending.extend(entry.keys())
            pending.extend(entry.values())
        elif isinstance(entry, list):
            pending.extend(entry)
        elif isinstance(entry, str):
            _require(len(entry) <= MAX_STRING and not any(0xD800 <= ord(char) <= 0xDFFF for char in entry))
    _require(isinstance(value, dict))
    return value


def _linux(value):
    override = value.get("linux", {})
    _require(isinstance(override, dict) and not (_OVERRIDE_CONTROL & set(override)))
    return override


def _effective(document, task):
    result = {key: value for key, value in document.items() if key in _DEFAULTS}
    options = {}
    for layer in (document, _linux(document), task, _linux(task)):
        for key in _DEFAULTS:
            if key in layer:
                result[key] = layer[key]
        if "options" in layer:
            _require(isinstance(layer["options"], dict))
            for key, value in layer["options"].items():
                if key == "env":
                    _require(isinstance(value, dict))
                    options.setdefault("env", {}).update(value)
                else:
                    options[key] = value
    result.update({key: value for key, value in task.items() if key not in _DEFAULTS})
    result["options"] = options
    return result


def _literal(value):
    _require(isinstance(value, str) and len(value) <= MAX_STRING)
    _require(not any(ord(char) < 32 or ord(char) == 127 for char in value))
    if value == _WORKSPACE or value.startswith(_WORKSPACE + "/"):
        value = "workspace" + value[len(_WORKSPACE):]
    _require(not any(char in value for char in ("$", "`")))
    return value


def _shell_words(command):
    _require(isinstance(command, str) and len(command) <= MAX_STRING)
    # Preserve quoting before shlex removes it: punctuation inside a quoted
    # argument is data, while unquoted command composition is unsupported.
    command = command.replace(_WORKSPACE + "/", "workspace/")
    output, quote, index = [], "", 0
    while index < len(command):
        char = command[index]
        if char == "\\" and quote != "'":
            _require(index + 1 < len(command))
            output.extend(command[index:index + 2])
            index += 2
            continue
        if quote:
            if char == quote:
                quote = ""
            elif quote == '"':
                _require(char not in "`$")
        elif char in "\"'":
            quote = char
        elif char == "#" and (index == 0 or command[index - 1].isspace()):
            end = command.find("\n", index)
            if end < 0:
                break
            output.append("\n")
            index = end + 1
            continue
        else:
            _require(char not in ";&|<>(){}*?[]`$")
        output.append(char)
        index += 1
    _require(not quote)
    text = "".join(output).strip()
    _require("\n" not in text and "\r" not in text)
    return shlex.split(text, comments=False, posix=True)


def _script(argv):
    _require(bool(argv) and len(argv) <= MAX_ARGUMENTS + 1)
    command = _literal(argv[0])
    name = posixpath.basename(command)
    if re.fullmatch(r"python(?:[23](?:\.[0-9]{1,2})?)?", name):
        name = "python"
    if name not in _INTERPRETERS:
        _require(name not in {"env", "exec", "command", "eval", "source", ".", "if", "for", "while", "case"})
        return None
    args = [_literal(value) for value in argv[1:]]
    if name == "nodejs":
        name = "node"
    index, no_execution = 0, False
    if name == "bun" and args[:1] == ["run"]:
        index = 1
        _require(len(args) > index and args[index].startswith(("./", "/", "workspace/")))
    no_value = {
        "node": {"--no-warnings", "--trace-warnings", "--use-strict"},
        "bun": {"--silent"},
        "python": {"-b", "-B", "-d", "-E", "-I", "-O", "-OO", "-P", "-q", "-s", "-S", "-u", "-v"},
        "sh": {"-e", "-u", "-x", "-f"}, "bash": {"-e", "-u", "-x", "-f", "--noprofile", "--norc"},
        "dash": {"-e", "-u", "-x", "-f"}, "ash": {"-e", "-u", "-x", "-f"}, "zsh": {"-e", "-u", "-x", "-f"},
        "perl": {"-w", "-T"}, "php": {"-n"}, "ruby": {"-w"}, "lua": set(), "luajit": set(),
    }[name]
    while index < len(args):
        value = args[index]
        if value == "--":
            index += 1
            break
        if value in {"--help", "--version"} or (value in {"-h", "-V"} and name == "python"):
            no_execution = True
            index += 1
            continue
        if ((name in {"node", "bun"} and value == "-v")
                or (name == "node" and value in {"-c", "--check"})
                or (name in _SHELLS and value == "-n") or (name == "php" and value == "-l")
                or (name == "ruby" and value == "-c")):
            no_execution = True
            index += 1
            continue
        if name == "python" and value in {"-W", "-X", "--check-hash-based-pycs"}:
            _require(index + 1 < len(args) and bool(args[index + 1]))
            index += 2
            continue
        if name == "python" and (value.startswith(("-W", "-X")) and len(value) > 2
                                 or value.startswith("--check-hash-based-pycs=")):
            index += 1
            continue
        if value in no_value:
            index += 1
            continue
        _require(not value.startswith("-"))
        break
    if no_execution and index == len(args):
        return None
    _require(index < len(args) and args[index] not in {"", "-"})
    path = args[index]
    _require("\\" not in path)
    if no_execution:
        return None
    suffix = posixpath.splitext(path)[1].lower()
    kind = next((kind for kind, suffixes in _KINDS.items() if suffix in suffixes), None)
    return (name, kind) if kind else None


def _task_signal(task, index):
    options = task["options"]
    if "cwd" in options:
        _literal(options["cwd"])
    for name, value in options.get("env", {}).items():
        _require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", name) is not None)
        _literal(value)
        _require(not value or (name not in _CODE_ENV and not name.startswith("LUA_INIT_")))
    if "command" not in task:
        _require(bool(task.get("dependsOn")) and task.get("type") in {None, "shell", "process"})
        return None
    _require(task.get("type") in {"shell", "process"})
    args = task.get("args", [])
    _require(isinstance(args, list) and len(args) <= MAX_ARGUMENTS)
    args = [_literal(value) for value in args]
    command = task["command"]
    if task["type"] == "shell":
        _require("shell" not in options)
        _require(not any(any(char in value for char in ";&|<>(){}*?[]'\"\\") for value in args))
        argv = _shell_words(command) + args
    else:
        argv = [_literal(command)] + args
    result = _script(argv)
    return EditorTaskSignal(index + 1, *result) if result else None


def analyze_editor_tasks(payload: bytes) -> EditorTaskAnalysis:
    try:
        document = _jsonc(payload)
        _require(document.get("version", "2.0.0") == "2.0.0")
        _require("runOptions" not in document)
        _linux(document)
        raw_tasks = document.get("tasks", [])
        _require(isinstance(raw_tasks, list) and len(raw_tasks) <= MAX_TASKS)
        _require(all(isinstance(task, dict) for task in raw_tasks))
        tasks = [_effective(document, task) for task in raw_tasks]
        roots, labels = [], {}
        for index, task in enumerate(tasks):
            if isinstance(task.get("label"), str):
                labels.setdefault(task["label"], []).append(index)
            run = task.get("runOptions", {})
            _require(isinstance(run, dict) and run.get("runOn", "default") in {"default", "folderOpen"})
            if run.get("runOn") == "folderOpen":
                roots.append(index)
        colors, reachable, edges = {}, set(), [0]

        def visit(index, depth):
            _require(depth <= MAX_DEPTH and colors.get(index) != 1)
            if colors.get(index) == 2:
                return
            colors[index] = 1
            task = tasks[index]
            if "label" in task:
                label = task["label"]
                _require(isinstance(label, str) and bool(label) and len(labels.get(label, [])) == 1)
            _require(task.get("dependsOrder", "parallel") in {"parallel", "sequence"})
            dependencies = task.get("dependsOn", [])
            dependencies = [dependencies] if isinstance(dependencies, str) else dependencies
            _require(isinstance(dependencies, list) and len(dependencies) <= MAX_TASKS)
            for label in dependencies:
                edges[0] += 1
                _require(edges[0] <= MAX_DEPENDENCIES and isinstance(label, str)
                         and len(labels.get(label, [])) == 1)
                visit(labels[label][0], depth + 1)
            colors[index] = 2
            reachable.add(index)

        for index in roots:
            visit(index, 0)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return EditorTaskAnalysis((), True)
    signals, incomplete = [], False
    for index in sorted(reachable):
        try:
            signal = _task_signal(tasks[index], index)
            if signal:
                signals.append(signal)
        except (ValueError, TypeError, UnicodeError, RecursionError):
            incomplete = True
    return EditorTaskAnalysis(tuple(signals), incomplete)


def editor_task_findings(payload, file_path, pkgname="", pkgver="", phase="deterministic") -> List[Finding]:
    result = analyze_editor_tasks(payload)
    selected_phase = Phase.pkgbuild_static if phase == "deterministic" else Phase(phase)
    findings = []
    for signal in result.signals:
        findings.append(Finding(
            rule_id="EDITOR-TASK-AUTORUN-CARRIER-001", package_name=pkgname or "unknown",
            package_version=pkgver or "unknown", phase=selected_phase, source=Source.deterministic_rule,
            severity=Severity.CRITICAL, confidence=Confidence.HIGH,
            evidence_quality=EvidenceQuality.confirmed_static_pattern, file_path=file_path,
            explanation="A task reachable from a folder-open task configures an interpreter to execute a media, document, data, or font-named file.",
            recommendation="Review the captured task configuration and referenced artifact before building or opening the workspace with automatic tasks enabled.",
            blocks_installation=True, requires_manual_review=False,
            evidence_snippet="task ordinal: {}; interpreter: {}; carrier kind: {}".format(
                signal.task_index, signal.interpreter, signal.carrier_kind),
            false_positive_notes="Execution depends on workspace trust, automatic-task permission, and successful task prerequisites. Static configuration does not establish execution, artifact contents, or host compromise.",
        ))
    if result.incomplete:
        findings.append(Finding(
            rule_id="EDITOR-TASK-INSPECTION-INCOMPLETE-001", package_name=pkgname or "unknown",
            package_version=pkgver or "unknown", phase=selected_phase, source=Source.deterministic_rule,
            severity=Severity.HIGH, confidence=Confidence.HIGH,
            evidence_quality=EvidenceQuality.strong_heuristic, file_path=file_path,
            explanation="Captured editor task configuration exceeds supported structural or active command-resolution bounds.",
            recommendation="Complete independent review of the task configuration before building or enabling automatic workspace tasks.",
            blocks_installation=True, requires_manual_review=False,
            evidence_snippet="bounded editor task inspection incomplete",
            false_positive_notes="Unsupported or malformed configuration is missing coverage, not evidence of malware, execution, or compromise.",
        ))
    return findings
