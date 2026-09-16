"""Characterization tests for the shared incident infrastructure modules.

Stage 6 moved four symbols out of the incident workflow into lower-level owners:
the incident value vocabulary (`incident_models`), the privacy redactor
(`redaction`), the atomic state writer (`state_file`) and the bounded command
capture (`bounded_process`). These tests pin the behavior that moved, so the new
owners are verified directly instead of only through the subsystem suites that
consume them.

Nothing here executes candidate content: the runner and the filesystem are both
injected or temporary.
"""

import ast
import os
import stat
from pathlib import Path

import pytest

from aurascan.core.bounded_process import CommandOutput, run_bounded_command
from aurascan.core.incident_models import IncidentReport, RepairAction, RepairResult
from aurascan.core.redaction import correlation_token, redact_incident_text, redact_structure
from aurascan.core.state_file import atomic_write_json

ROOT = Path(__file__).resolve().parents[1]


class FakeRun:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode

    def to_dict(self):  # pragma: no cover - parity with subprocess.CompletedProcess
        return {"returncode": self.returncode}


def test_atomic_write_json_replaces_the_target_and_sets_the_mode(tmp_path):
    target = tmp_path / "nested" / "state.json"

    atomic_write_json(target, {"b": 1, "a": 2}, mode=0o600)
    first = target.read_text(encoding="utf-8")
    atomic_write_json(target, {"b": 3}, mode=0o600)

    assert first == '{\n  "a": 2,\n  "b": 1\n}\n'
    assert target.read_text(encoding="utf-8") == '{\n  "b": 3\n}\n'
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert [item.name for item in target.parent.iterdir()] == ["state.json"]


def test_atomic_write_json_leaves_no_partial_file_when_the_write_fails(tmp_path):
    target = tmp_path / "state.json"
    target.mkdir()

    with pytest.raises(OSError):
        atomic_write_json(target, {"a": 1}, mode=0o600)

    assert [item.name for item in tmp_path.iterdir()] == ["state.json"]


def test_run_bounded_command_preserves_argv_and_truncates_marked_output():
    seen = []

    def runner(command, **kwargs):
        seen.append((command, kwargs))
        return FakeRun(stdout="x" * 40, stderr="y" * 40, returncode=3)

    output = run_bounded_command(runner, ("/usr/bin/thing", "--flag"), max_chars=10, timeout=7)

    assert seen[0][0] == ["/usr/bin/thing", "--flag"]
    assert seen[0][1] == {"capture_output": True, "text": True, "check": False, "timeout": 7}
    assert output == CommandOutput(3, "x" * 10, "y" * 10, True)


def test_run_bounded_command_retries_without_timeout_and_reports_execution_errors():
    calls = []

    def no_timeout_runner(command, **kwargs):
        calls.append(kwargs)
        if "timeout" in kwargs:
            raise TypeError("unexpected keyword argument 'timeout'")
        return FakeRun(stdout="ok")

    assert run_bounded_command(no_timeout_runner, ["tool"], max_chars=5, timeout=1).stdout == "ok"
    assert calls[-1] == {"capture_output": True, "text": True, "check": False}

    def broken_runner(command, **kwargs):
        raise OSError("missing executable")

    failed = run_bounded_command(broken_runner, ["tool"], max_chars=5, timeout=1)

    assert failed.returncode == 127
    assert "missing executable" in failed.stderr
    assert failed.truncated is False


def test_redact_incident_text_masks_secrets_and_keeps_correlation_stable():
    text = (
        "password: hunter2\n"
        "https://alice:s3cret@example.invalid/path\n"
        "Authorization: Bearer abcdefghijklmnop\n"
        "host 10.4.5.6 mac aa:bb:cc:dd:ee:ff home /home/alice\n"
    )

    redacted = redact_incident_text(text)

    assert "hunter2" not in redacted
    assert "s3cret" not in redacted
    assert "abcdefghijklmnop" not in redacted
    assert "10.4.5.6" not in redacted
    assert "aa:bb:cc:dd:ee:ff" not in redacted
    assert "/home/alice" not in redacted
    assert redact_incident_text(text) == redacted
    assert redact_incident_text("nothing sensitive here") == "nothing sensitive here"


def test_redact_structure_redacts_nested_mappings_and_sequences():
    value = {
        "command": "/usr/bin/env COMMAND=secret-value",
        "items": ["10.0.0.1", 7, None],
        "token": "abcdefghijklmnop",
    }

    redacted = redact_structure(value)

    assert "secret-value" not in redacted["command"]
    # An unlabelled string is not treated as a credential: the redactor targets
    # assignments, URLs, private keys, addresses, hostnames and usernames.
    assert redacted["token"] == "abcdefghijklmnop"
    assert redacted["items"][1:] == [7, None]
    assert redacted["items"][0].startswith("<ip:")


def test_correlation_token_is_a_stable_short_digest():
    assert correlation_token("host", "builder") == correlation_token("host", "builder")
    assert correlation_token("host", "builder") != correlation_token("host", "other")
    assert correlation_token("host", "builder").startswith("<host:")
    assert len(correlation_token("host", "builder")) == len("<host:>") + 8


def test_incident_report_round_trip_keeps_the_persisted_schema():
    report = IncidentReport(
        incident_id="incident-1",
        target_boot="0",
        trigger="manual",
        created_at=1234,
        repair_actions=[RepairAction("a1", "restart_system_service", "t", "s", "HIGH")],
        repair_results=[RepairResult("a1", "restart_system_service", "applied", "done")],
    )

    payload = report.to_dict()
    restored = IncidentReport.from_dict(payload)

    assert payload["schema"] == "incident_report/1.3"
    assert payload["scanner_version"] == report.scanner_version
    assert restored.to_dict() == payload


def test_incident_repairs_does_not_depend_on_the_incident_workflow():
    """Stage 6 regression: the repair planner must not import the workflow."""

    source = (ROOT / "aurascan" / "core" / "incident_repairs.py").read_text(encoding="utf-8")
    tree = ast.parse(source)

    imported = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    imported |= {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }

    assert "aurascan.core.incidents" not in imported
    assert not any(name.startswith("aurascan.core.incidents.") for name in imported)
    # The document modules an operator may copy off the machine are the reason
    # the redactor and the state writer exist; they must not be reached through
    # the workflow either.
    assert "import aurascan.core.incidents" not in source
    assert "aurascan.core.incidents" not in {m for m in imported if m}


def test_moved_helpers_have_a_single_definition_site():
    """The new owners define each helper; the workflow only imports them."""

    workflow = (ROOT / "aurascan" / "core" / "incidents.py").read_text(encoding="utf-8")
    workflow_tree = ast.parse(workflow)
    defined = {
        node.name
        for node in workflow_tree.body
        if isinstance(node, (ast.FunctionDef, ast.ClassDef))
    }

    for name in ("atomic_write_json", "run_bounded_command", "redact_incident_text",
                 "redact_structure", "valid_boot_target", "IncidentReport",
                 "RepairAction", "RepairResult", "CommandOutput"):
        assert name not in defined, name

    owners = {
        "aurascan/core/state_file.py": ["atomic_write_json"],
        "aurascan/core/bounded_process.py": ["run_bounded_command", "CommandOutput"],
        "aurascan/core/redaction.py": ["redact_incident_text", "redact_structure", "correlation_token"],
        "aurascan/core/incident_models.py": ["valid_boot_target", "IncidentReport"],
    }
    for relative, names in owners.items():
        tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
        defined = {
            node.name
            for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.ClassDef))
        }
        for name in names:
            assert name in defined, (relative, name)


def test_atomic_write_json_is_imported_not_copied(tmp_path):
    """A second implementation of the same guarantee would be a real defect."""

    copies = []
    for path in (ROOT / "aurascan").rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        if "def atomic_write_json" in source and path.name != "state_file.py":
            copies.append(path.name)

    assert copies == []
