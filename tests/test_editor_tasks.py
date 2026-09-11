"""Captured editor task strings are inert data; no workspace or command runs."""

import json
import socket
import subprocess

import pytest

from aurascan.analyzers import editor_tasks as editor
from aurascan.core.models import Confidence, Phase, Severity


@pytest.fixture(autouse=True)
def no_execution_or_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("task analysis must not execute commands or contact a network")
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)


def automatic(**changes):
    task = {"label": "inert-task", "type": "process", "command": "node",
            "args": ["${workspaceFolder}/assets/inert.woff2"],
            "runOptions": {"runOn": "folderOpen"}}
    task.update(changes)
    return task


def analyze(tasks, **global_fields):
    value = {"version": "2.0.0", "tasks": tasks}
    value.update(global_fields)
    return editor.analyze_editor_tasks(json.dumps(value).encode("utf-8"))


@pytest.mark.parametrize("command,arguments,interpreter,kind", [
    ("node", ["assets/inert.woff2"], "node", "font"),
    ("/usr/bin/node", ["${workspaceFolder}/assets/inert.ttf"], "node", "font"),
    ("nodejs", ["./assets/inert.png"], "node", "media"),
    ("python3.13", ["-B", "./assets/inert.dat"], "python", "data"),
    ("python3", ["-X", "utf8", "./assets/inert.pdf"], "python", "document"),
    ("python", ["-Wignore", "--", "./assets/inert.json"], "python", "data"),
    ("bun", ["./assets/inert.woff"], "bun", "font"),
    ("bun", ["run", "./assets/inert.woff"], "bun", "font"),
    ("sh", ["-e", "./assets/inert.txt"], "sh", "document"),
    ("bash", ["--noprofile", "./assets/inert.otf"], "bash", "font"),
    ("perl", ["-w", "./assets/inert.xml"], "perl", "data"),
    ("ruby", ["./assets/inert.csv"], "ruby", "data"),
    ("php", ["-n", "./assets/inert.png"], "php", "media"),
    ("lua", ["./assets/inert.jpg"], "lua", "media"),
])
def test_literal_automatic_interpreter_carrier(command, arguments, interpreter, kind):
    result = analyze([automatic(command=command, args=arguments)])
    assert result == editor.EditorTaskAnalysis((editor.EditorTaskSignal(1, interpreter, kind),), False)


@pytest.mark.parametrize("command,args", [
    ("node assets/inert.woff2", []),
    ('node "${workspaceFolder}/assets/inert font.woff2"', []),
    ("node", ["${workspaceFolder}/assets/inert.woff2"]),
    ("node './assets/inert.woff2' # inert comment", []),
])
def test_single_shell_command_preserves_literal_arguments(command, args):
    result = analyze([automatic(type="shell", command=command, args=args)])
    assert result.signals == (editor.EditorTaskSignal(1, "node", "font"),)
    assert result.incomplete is False


def test_jsonc_comments_trailing_commas_and_comment_like_strings():
    payload = b'''{
      // "runOptions": {"runOn": "default"},
      "version": "2.0.0",
      "tasks": [{
        "label": "https://example.invalid/comment/*data*/",
        "type": "process", /* harmless comment */
        "command": "node",
        "args": ["${workspaceFolder}/assets/inert.woff2",],
        "runOptions": {"runOn": "folderOpen",},
      },],
    }'''
    result = editor.analyze_editor_tasks(payload)
    assert result == editor.EditorTaskAnalysis((editor.EditorTaskSignal(1, "node", "font"),), False)


def test_jsonc_comments_do_not_create_an_automatic_task():
    payload = b'''{
      "version": "2.0.0", "tasks": [{
        "label": "inert", "type": "process", "command": "echo",
        "args": ["node assets/inert.woff2; runOn folderOpen"],
        // "runOptions": {"runOn": "folderOpen"},
      }],
      "description": "/* runOn folderOpen */ node assets/inert.woff2",
    }'''
    assert editor.analyze_editor_tasks(payload) == editor.EditorTaskAnalysis((), False)


@pytest.mark.parametrize("task", [
    automatic(runOptions={}), automatic(runOptions={"runOn": "default"}),
    automatic(command="node", args=["./build.js"]),
    automatic(command="node", args=["./build.js", "assets/inert.woff2"]),
    automatic(command="node assets/inert.woff2", args=[]),
    automatic(command="node", args=["assets/inert.woff2 --version"]),
    automatic(command="echo", args=["node", "assets/inert.woff2"]),
    automatic(type="shell", command="echo 'node assets/inert.woff2; harmless data'", args=[]),
    automatic(command="npm", args=["run", "build"]),
    automatic(command="make", args=["all"]),
    automatic(command="node", args=["--check", "assets/inert.woff2"]),
    automatic(command="node", args=["--version", "assets/inert.woff2"]),
    automatic(command="python3", args=["--version", "assets/inert.woff2"]),
    automatic(command="python3", args=["-W", "assets/inert.woff2", "build.py"]),
    automatic(command="bash", args=["-n", "assets/inert.woff2"]),
])
def test_manual_tasks_legitimate_builds_and_literal_data_are_negative(task):
    assert analyze([task]) == editor.EditorTaskAnalysis((), False)


def test_unrelated_manual_task_does_not_contribute_to_automatic_build():
    tasks = [automatic(label="build", command="make", args=["all"]),
             automatic(label="manual", runOptions={"runOn": "default"})]
    assert analyze(tasks) == editor.EditorTaskAnalysis((), False)


def test_reachable_dependency_is_bound_to_actual_task_ordinal():
    tasks = [automatic(label="entry", command="make", args=["all"], dependsOn="dependency"),
             automatic(label="unrelated", runOptions={}),
             automatic(label="dependency", runOptions={})]
    result = analyze(tasks)
    assert result == editor.EditorTaskAnalysis((editor.EditorTaskSignal(3, "node", "font"),), False)


def test_compound_task_can_reach_a_manual_dependency_chain():
    tasks = [{"label": "start", "runOptions": {"runOn": "folderOpen"}, "dependsOn": ["middle"]},
             {"label": "middle", "dependsOn": "last"},
             automatic(label="last", runOptions={})]
    assert analyze(tasks) == editor.EditorTaskAnalysis((editor.EditorTaskSignal(3, "node", "font"),), False)


@pytest.mark.parametrize("tasks", [
    [automatic(dependsOn="missing")],
    [automatic(dependsOn="inert-task")],
    [automatic(label="a", dependsOn="b"), automatic(label="b", dependsOn="a", runOptions={})],
    [automatic(dependsOn="duplicate"), automatic(label="duplicate", runOptions={}),
     automatic(label="duplicate", runOptions={})],
    [automatic(dependsOn={"type": "npm", "script": "build"})],
    [automatic(dependsOn=[{"type": "npm"}])],
    [automatic(dependsOrder="unsupported")],
])
def test_ambiguous_missing_cyclic_or_unsupported_dependencies_are_coverage(tasks):
    result = analyze(tasks)
    assert result == editor.EditorTaskAnalysis((), True)


def test_manual_dependency_cycles_do_not_poison_unrelated_automatic_build():
    tasks = [automatic(label="build", command="make", args=["all"]),
             automatic(label="a", dependsOn="b", runOptions={}),
             automatic(label="b", dependsOn="a", runOptions={})]
    assert analyze(tasks) == editor.EditorTaskAnalysis((), False)


def test_linux_task_override_controls_the_effective_command():
    task = automatic(command="echo", args=["harmless"],
                     linux={"command": "node", "args": ["assets/inert.woff2"]})
    assert analyze([task]).signals == (editor.EditorTaskSignal(1, "node", "font"),)
    task = automatic(linux={"command": "echo", "args": ["harmless"]})
    assert analyze([task]) == editor.EditorTaskAnalysis((), False)


def test_linux_global_defaults_and_task_precedence_are_preserved():
    task = {"label": "inert", "runOptions": {"runOn": "folderOpen"}}
    defaults = {"type": "process", "command": "echo", "args": ["harmless"],
                "linux": {"command": "node", "args": ["assets/inert.woff2"]}}
    assert analyze([task], **defaults).signals == (editor.EditorTaskSignal(1, "node", "font"),)
    task.update(command="make", args=["all"])
    assert analyze([task], **defaults) == editor.EditorTaskAnalysis((), False)


def test_other_platform_override_does_not_create_a_linux_signal():
    task = automatic(command="make", args=["all"], windows={"command": "node", "args": ["assets/inert.woff2"]},
                     osx={"command": "node", "args": ["assets/inert.woff2"]})
    assert analyze([task]) == editor.EditorTaskAnalysis((), False)


@pytest.mark.parametrize("changes", [
    {"command": "${config:interpreter}"}, {"args": ["${env:PRIVATE}/assets/inert.woff2"]},
    {"args": ["${workspaceFolder:another}/assets/inert.woff2"]},
    {"args": [{"value": "assets/inert.woff2", "quoting": "weak"}]},
    {"args": ["-e", "'assets/inert.woff2'"]}, {"args": ["--unknown", "assets/inert.woff2"]},
    {"command": "python3", "args": ["-m", "inert"]},
    {"command": "node", "args": ["--require", "assets/inert.woff2", "build.js"]},
    {"type": "npm", "command": "build"}, {"type": "process", "args": "assets/inert.woff2"},
    {"command": {}}, {"type": ["process"]}, {"options": {"cwd": "${input:directory}"}},
    {"type": "shell", "command": "echo inert; node assets/inert.woff2", "args": []},
    {"type": "shell", "command": "node $(inert)", "args": []},
    {"type": "shell", "command": "node *.woff2", "args": []},
    {"type": "shell", "command": "node", "options": {"shell": {"executable": "inert"}}},
    {"command": "env", "args": ["node", "assets/inert.woff2"]},
])
def test_unsupported_active_command_resolution_is_incomplete_without_a_signal(changes):
    assert analyze([automatic(**changes)]) == editor.EditorTaskAnalysis((), True)


@pytest.mark.parametrize("payload", [
    b'{"tasks":[],"tasks":[]}', b'{"tasks":[{"runOptions":{"runOn":"default","runOn":"folderOpen"}}]}',
    b'{"tasks":[}', b'{/* unterminated', b'{"tasks":NaN}', b'{"tasks":1}', b'[]',
    b'{"version":"0.1.0","tasks":[]}', b'{"tasks":[],"linux":[]}', b'"\\ud800"',
    b'{"tasks":[{"runOptions":{"runOn":[]}}]}', b'{"tasks":[{"linux":{"runOptions":{"runOn":"folderOpen"}}}]}',
    b'\xff', b'{"number":1e999}', b'{"tasks":[{"label":"inert","runOptions":false}]}',
    b'{,}', b'{"tasks":[,]}', b'{"tasks":,}', b'{"tasks":[{},,]}',
])
def test_malformed_jsonc_and_unsupported_structures_are_coverage(payload):
    assert editor.analyze_editor_tasks(payload) == editor.EditorTaskAnalysis((), True)


def test_resource_bounds_are_explicit(monkeypatch):
    monkeypatch.setattr(editor, "MAX_TASK_BYTES", 8)
    assert editor.analyze_editor_tasks(b'{"tasks":[]}').incomplete
    monkeypatch.setattr(editor, "MAX_TASK_BYTES", 1024 * 1024)
    monkeypatch.setattr(editor, "MAX_TASKS", 1)
    assert analyze([automatic(), automatic()]).incomplete
    monkeypatch.setattr(editor, "MAX_TASKS", 128)
    monkeypatch.setattr(editor, "MAX_DEPENDENCIES", 1)
    tasks = [automatic(dependsOn=["a", "b"]), automatic(label="a", runOptions={}), automatic(label="b", runOptions={})]
    assert analyze(tasks).incomplete
    monkeypatch.setattr(editor, "MAX_DEPTH", 4)
    assert editor.analyze_editor_tasks(b'{"nested":[[[[[]]]]],"tasks":[]}').incomplete


def test_repeated_dependency_is_analyzed_once():
    tasks = [automatic(label="a", command="make", args=[], dependsOn="last"),
             automatic(label="b", command="make", args=[], dependsOn="last"),
             automatic(label="last", runOptions={})]
    assert analyze(tasks) == editor.EditorTaskAnalysis((editor.EditorTaskSignal(3, "node", "font"),), False)


def test_findings_have_fixed_evidence_and_conditional_execution_claims():
    task = automatic(label="PRIVATE_LABEL_SHOULD_NOT_LEAK", args=["${workspaceFolder}/PRIVATE_PATH.woff2"],
                     detail="PRIVATE_DESCRIPTION_SHOULD_NOT_LEAK")
    payload = json.dumps({"version": "2.0.0", "tasks": [task]}).encode()
    result = editor.editor_task_findings(payload, "/captured/.vscode/tasks.json", "inert", "1-1")
    assert len(result) == 1
    finding = result[0]
    assert finding.rule_id == "EDITOR-TASK-AUTORUN-CARRIER-001"
    assert finding.severity == Severity.CRITICAL and finding.confidence == Confidence.HIGH
    assert finding.blocks_installation and finding.phase == Phase.pkgbuild_static
    assert finding.package_name == "inert" and finding.package_version == "1-1"
    assert "workspace trust" in finding.false_positive_notes
    assert "automatic-task permission" in finding.false_positive_notes
    assert "PRIVATE_" not in json.dumps(finding.to_dict())
    assert finding.line_number is None and finding.raw_output is None


def test_coverage_finding_uses_source_phase_and_contains_no_raw_error():
    result = editor.editor_task_findings(b'{PRIVATE_ERROR', "captured/tasks.json", phase=Phase.unpacked_source_scan)
    assert len(result) == 1
    finding = result[0]
    assert finding.rule_id == "EDITOR-TASK-INSPECTION-INCOMPLETE-001"
    assert finding.severity == Severity.HIGH and finding.blocks_installation
    assert finding.phase == Phase.unpacked_source_scan
    assert "PRIVATE_ERROR" not in json.dumps(finding.to_dict())


def test_independent_supported_signal_survives_incomplete_active_command():
    result = analyze([automatic(), automatic(label="unresolved", command="${config:interpreter}")])
    assert result.signals == (editor.EditorTaskSignal(1, "node", "font"),)
    assert result.incomplete


@pytest.mark.parametrize("argument", ["hello; node assets/inert.woff2", "inert&node", "inert|node",
                                      ">inert", "$(inert)", "`inert`", "*.woff2", '"inert"'])
def test_shell_arguments_with_unsupported_quoting_or_control_syntax_are_coverage(argument):
    result = analyze([automatic(type="shell", command="echo", args=[argument])])
    assert result == editor.EditorTaskAnalysis((), True)


def test_process_literal_metacharacters_cannot_form_a_shell_command():
    result = analyze([automatic(command="echo", args=["hello; node assets/inert.woff2"])])
    assert result == editor.EditorTaskAnalysis((), False)


@pytest.mark.parametrize("environment", [
    {"NODE_OPTIONS": "--require ./inert.js"}, {"BASH_ENV": "./inert.sh"},
    {"ENV": "./inert.sh"}, {"PYTHONPATH": "./inert"}, {"LD_PRELOAD": "./inert.so"},
    {"SAFE": "${command:inert}"}, {"SAFE": None}, {"SAFE": ["inert"]}, "inert", [],
])
def test_active_environment_authority_or_malformed_environment_is_coverage(environment):
    result = analyze([automatic(command="make", args=["all"], options={"env": environment})])
    assert result == editor.EditorTaskAnalysis((), True)


def test_global_environment_is_not_erased_by_unrelated_task_environment():
    task = automatic(command="make", args=["all"], options={"env": {"SAFE": "inert"}})
    result = analyze([task], options={"env": {"NODE_OPTIONS": "--require ./inert.js"}})
    assert result == editor.EditorTaskAnalysis((), True)


def test_literal_environment_and_explicit_empty_loader_value_are_not_a_finding():
    task = automatic(command="make", args=["all"], options={"env": {"SAFE": "inert", "NODE_OPTIONS": ""}})
    assert analyze([task]) == editor.EditorTaskAnalysis((), False)


@pytest.mark.parametrize("command,args", [
    ("node", ["--check", "--require", "./inert.js", "assets/inert.woff2"]),
    ("node", ["--version", "--unknown", "assets/inert.woff2"]),
    ("bash", ["-n", "-c", "inert command text"]),
    ("ruby", ["-c", "-r", "inert", "assets/inert.woff2"]),
])
def test_nonexecution_option_does_not_hide_other_unsupported_execution_options(command, args):
    result = analyze([automatic(command=command, args=args)])
    assert result == editor.EditorTaskAnalysis((), True)


@pytest.mark.parametrize("other_run_options", [{}, {"runOn": "folderOpen"}])
def test_duplicate_label_makes_automatic_task_identity_ambiguous(other_run_options):
    tasks = [automatic(), automatic(command="make", args=["all"], runOptions=other_run_options)]
    assert analyze(tasks) == editor.EditorTaskAnalysis((), True)


def test_unreachable_duplicate_labels_do_not_poison_independent_automatic_build():
    tasks = [automatic(label="automatic-build", command="make", args=["all"]),
             automatic(runOptions={}), automatic(runOptions={})]
    assert analyze(tasks) == editor.EditorTaskAnalysis((), False)
