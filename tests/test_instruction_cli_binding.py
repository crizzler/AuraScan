"""Instruction Guard CLI evidence binding.

A desktop client may only act on the report it displayed. These tests pin the
CLI plumbing that forwards the expected report identity and candidate hash into
the Guard, and the fail-closed handling of malformed or misapplied binding.
"""

import io

import pytest

import aurascan.core.instruction_cli as instruction_cli
from aurascan.core.instruction_cli import EXIT_CLEAR, EXIT_ERROR, run_instruction_audit

DIGEST = "a" * 64
REPORT_ID = "igr-0000000000000000"


def _run(argv, tmp_path):
    stdout = io.StringIO()
    stderr = io.StringIO()
    code = run_instruction_audit(
        argv + ["--state-root", str(tmp_path)],
        stdout=stdout,
        stderr=stderr,
        input_func=lambda _prompt: "y",
        env={"HOME": str(tmp_path)},
    )
    return code, stdout.getvalue(), stderr.getvalue()


@pytest.fixture
def guard_calls(monkeypatch):
    calls = []

    def approve(file_id, **kwargs):
        calls.append(("approve", file_id, kwargs))
        return {"status": "approved", "file_id": file_id}

    def disable(file_id, **kwargs):
        calls.append(("disable", file_id, kwargs))
        return {"status": "disabled", "file_id": file_id}

    monkeypatch.setattr("aurascan.core.instruction_guard.approve_candidate", approve)
    monkeypatch.setattr("aurascan.core.instruction_guard.disable_candidate", disable)
    return calls


def _binding(calls):
    return [
        (name, file_id, {key: kwargs[key] for key in ("expected_report_id", "expected_sha256")})
        for name, file_id, kwargs in calls
    ]


def test_approve_forwards_the_expected_report_and_hash(guard_calls, tmp_path):
    code, stdout, _stderr = _run(
        [
            "--approve",
            "file-123",
            "--expect-report-id",
            REPORT_ID,
            "--expect-sha256",
            DIGEST,
            "--json",
        ],
        tmp_path,
    )

    assert code == EXIT_CLEAR
    assert _binding(guard_calls) == [
        (
            "approve",
            "file-123",
            {"expected_report_id": REPORT_ID, "expected_sha256": DIGEST},
        )
    ]
    assert '"approved"' in stdout


def test_disable_forwards_the_expected_report_and_hash(guard_calls, tmp_path):
    code, _stdout, _stderr = _run(
        [
            "--disable",
            "file-123",
            "--yes",
            "--expect-sha256",
            DIGEST.upper(),
        ],
        tmp_path,
    )

    assert code == EXIT_CLEAR
    assert _binding(guard_calls) == [
        ("disable", "file-123", {"expected_report_id": None, "expected_sha256": DIGEST})
    ]


def test_binding_without_an_action_is_refused(guard_calls, tmp_path):
    code, _stdout, stderr = _run(["--status", "--expect-sha256", DIGEST], tmp_path)

    assert code == EXIT_ERROR
    assert "--expect-sha256" in stderr
    assert guard_calls == []


@pytest.mark.parametrize("digest", ["abc", "z" * 64, "a" * 63, "a" * 65])
def test_a_malformed_expected_hash_is_refused(guard_calls, tmp_path, digest):
    code, _stdout, stderr = _run(
        ["--approve", "file-123", "--expect-sha256", digest], tmp_path
    )

    assert code == EXIT_ERROR
    assert "SHA-256" in stderr
    assert guard_calls == []


def test_approve_without_binding_still_works(guard_calls, tmp_path):
    code, _stdout, _stderr = _run(["--approve", "file-123"], tmp_path)

    assert code == EXIT_CLEAR
    assert _binding(guard_calls) == [
        ("approve", "file-123", {"expected_report_id": None, "expected_sha256": None})
    ]
