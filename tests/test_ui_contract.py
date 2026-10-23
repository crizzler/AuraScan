import io
import json
from pathlib import Path

import pytest

from aurascan import cli
from aurascan.core import ui_cli


def _check(name, status, message="message", details=None):
    entry = {"name": name, "status": status, "message": message}
    if details is not None:
        entry["details"] = details
    return entry


def _snapshot(**overrides):
    values = {
        "doctor_checks": [
            _check("distro_compatibility", "ok"),
            _check("recovery_image", "warn"),
        ],
        "intelligence": {
            "status": "bundled",
            "source": "bundled",
            "digest": "a" * 64,
            "identity": "b" * 64,
            "update_channel": "unconfigured",
        },
        "markers": [{"severity": "LOW"}, {"severity": "HIGH"}],
        "unseen_markers": [{"severity": "HIGH"}],
        "app_version": "0.0.0-test",
        "generated_at": 1000,
        "python_version": "3.8.0",
        "platform_name": "linux",
    }
    values.update(overrides)
    return ui_cli.build_ui_snapshot(**values)


def test_contract_identifier_is_stable():
    # Changing this string is a deliberate contract break: update the renderer
    # parser and this assertion together.
    assert ui_cli.UI_CONTRACT == "aurascan-ui/1"


def test_snapshot_has_only_the_documented_top_level_keys():
    assert set(_snapshot()) == {
        "app",
        "contract",
        "doctor",
        "generated_at",
        "incidents",
        "intelligence",
    }


def test_snapshot_carries_app_and_timestamp_identity():
    snapshot = _snapshot()

    assert snapshot["app"] == {
        "version": "0.0.0-test",
        "python": "3.8.0",
        "platform": "linux",
    }
    assert snapshot["contract"] == ui_cli.UI_CONTRACT
    assert snapshot["generated_at"] == 1000


def test_snapshot_computes_doctor_health_from_check_statuses():
    healthy = _snapshot(doctor_checks=[_check("a", "ok"), _check("b", "warn")])
    unhealthy = _snapshot(doctor_checks=[_check("a", "ok"), _check("b", "error")])

    assert healthy["doctor"]["ok"] is True
    assert unhealthy["doctor"]["ok"] is False


def test_snapshot_projects_incident_counts_and_highest_severity():
    incidents = _snapshot()["incidents"]

    assert incidents == {
        "available": True,
        "pending": 2,
        "unseen": 1,
        "highest_severity": "HIGH",
    }


def test_snapshot_reports_unavailable_incidents_instead_of_zero():
    incidents = _snapshot(incidents_available=False)["incidents"]

    assert incidents["available"] is False
    assert incidents["pending"] == 0
    assert incidents["highest_severity"] is None


def test_snapshot_keeps_intelligence_projection_allowlisted():
    intelligence = _snapshot(
        intelligence={
            "status": "bundled",
            "source": "bundled",
            "digest": "a" * 64,
            "identity": "b" * 64,
            "update_channel": "unconfigured",
            "local_state_path": "/home/example/private",
            "scan_root": "/home/example/src",
        }
    )["intelligence"]

    assert intelligence["status"] == "bundled"
    assert "local_state_path" not in intelligence
    assert "scan_root" not in intelligence


def test_snapshot_marks_missing_intelligence_unavailable():
    assert _snapshot(intelligence=None)["intelligence"] == {"status": "unavailable"}


def test_snapshot_rejects_an_unknown_check_status():
    with pytest.raises(ui_cli.UISnapshotError):
        _snapshot(doctor_checks=[_check("a", "clean")])


def test_snapshot_rejects_an_unbounded_check_list():
    checks = [_check("check-{0}".format(index), "ok") for index in range(ui_cli.MAX_CHECKS + 1)]

    with pytest.raises(ui_cli.UISnapshotError):
        _snapshot(doctor_checks=checks)


def test_snapshot_rejects_a_check_without_a_name():
    with pytest.raises(ui_cli.UISnapshotError):
        _snapshot(doctor_checks=[{"status": "ok", "message": "no name"}])


def test_run_ui_emits_contract_json_with_injected_evidence():
    calls = []

    def doctor_provider():
        calls.append("doctor")
        return [_check("distro_compatibility", "ok")]

    def intelligence_provider():
        calls.append("intelligence")
        return {"status": "bundled"}

    def incidents_provider():
        calls.append("incidents")
        return [], [], True

    stdout = io.StringIO()
    stderr = io.StringIO()
    code = ui_cli.run_ui(
        ["--json"],
        stdout=stdout,
        stderr=stderr,
        doctor_checks_provider=doctor_provider,
        intelligence_provider=intelligence_provider,
        incidents_provider=incidents_provider,
        now=lambda: 1234,
    )

    payload = json.loads(stdout.getvalue())
    assert code == 0
    assert stderr.getvalue() == ""
    assert payload["contract"] == ui_cli.UI_CONTRACT
    assert payload["generated_at"] == 1234
    assert payload["doctor"]["checks"][0]["name"] == "distro_compatibility"
    assert sorted(calls) == ["doctor", "incidents", "intelligence"]


def test_run_ui_fails_closed_on_malformed_evidence_without_leaking_details():
    stdout = io.StringIO()
    stderr = io.StringIO()
    code = ui_cli.run_ui(
        ["--json"],
        stdout=stdout,
        stderr=stderr,
        doctor_checks_provider=lambda: [{"name": "x", "status": "clean", "message": "m"}],
        intelligence_provider=lambda: {},
        incidents_provider=lambda: ([], [], True),
        now=lambda: 1234,
    )

    assert code == 1
    assert stdout.getvalue() == ""
    assert "Desktop snapshot unavailable" in stderr.getvalue()
    assert "unsupported status" in stderr.getvalue()


def test_run_ui_summary_is_evidence_only():
    stdout = io.StringIO()
    code = ui_cli.run_ui(
        [],
        stdout=stdout,
        stderr=io.StringIO(),
        doctor_checks_provider=lambda: [_check("distro_compatibility", "ok")],
        intelligence_provider=lambda: {"status": "bundled"},
        incidents_provider=lambda: ([], [], True),
        now=lambda: 1234,
    )

    text = stdout.getvalue().lower()
    assert code == 0
    assert "aurascan ui snapshot" in text
    assert "not a certification" in text
    for forbidden in ("is safe", "is clean", "is trusted", "approved", "no threats"):
        assert forbidden not in text


def test_cli_help_lists_the_ui_command():
    help_text = cli.build_parser().format_help()

    assert "aurascan ui" in help_text
    assert "read-only evidence snapshot" in help_text


def test_cli_dispatches_the_ui_command(monkeypatch):
    recorded = {}

    def fake_run_ui(argv):
        recorded["argv"] = list(argv)
        return 0

    monkeypatch.setattr(cli, "load_command_environment", lambda _argv: None)
    monkeypatch.setattr(ui_cli, "run_ui", fake_run_ui)

    with pytest.raises(SystemExit) as excinfo:
        cli.main(["ui", "--json"])

    assert excinfo.value.code == 0
    assert recorded["argv"] == ["--json"]


def test_ui_cli_module_is_a_user_facing_entry_point():
    # The desktop snapshot is a UI entry point: it must stay out of the core
    # dependency graph and must not carry rule identifiers.
    source = Path(ui_cli.__file__).read_text(encoding="utf-8")

    assert "-001" not in source
    assert "SYS-" not in source
    assert "AUR-" not in source


def test_desktop_sample_fixture_matches_the_python_contract():
    # The renderer's checked-in sample must stay a valid snapshot, so a contract
    # change cannot leave the prototype pointing at evidence Python would reject.
    fixture = (
        Path(__file__).resolve().parents[1]
        / "desktop"
        / "src"
        / "fixtures"
        / "snapshot.sample.json"
    )
    data = json.loads(fixture.read_text(encoding="utf-8"))
    incidents = data["incidents"]
    severity = incidents["highest_severity"]
    rebuilt = ui_cli.build_ui_snapshot(
        doctor_checks=data["doctor"]["checks"],
        intelligence=data["intelligence"],
        markers=[{"severity": severity} for _ in range(incidents["pending"])],
        unseen_markers=[{} for _ in range(incidents["unseen"])],
        app_version=data["app"]["version"],
        generated_at=data["generated_at"],
        python_version=data["app"]["python"],
        platform_name=data["app"]["platform"],
        incidents_available=incidents["available"],
    )

    assert rebuilt["contract"] == data["contract"] == ui_cli.UI_CONTRACT
    assert rebuilt["app"] == data["app"]
    assert rebuilt["doctor"] == data["doctor"]
    assert rebuilt["incidents"] == data["incidents"]
    assert rebuilt["intelligence"] == data["intelligence"]
