import io
import json
from pathlib import Path

import pytest

from aurascan.core import ui_actions, ui_cli


EXPECTED_ACTION_IDS = [
    "project_report",
    "refresh_snapshot",
    "repair_hung_application",
    "repair_runtime_links",
    "scan_package",
    "scan_pkgbuild",
]

STATE_CHANGING_ACTIONS = {"repair_runtime_links", "repair_hung_application"}


def test_action_ids_are_unique_and_stable():
    ids = [action.action_id for action in ui_actions.ACTIONS]

    assert len(ids) == len(set(ids))
    assert sorted(ids) == EXPECTED_ACTION_IDS
    assert len(ui_actions.ACTIONS) <= ui_actions.MAX_ACTIONS


def test_every_action_has_a_fixed_aurascan_argv():
    for action in ui_actions.ACTIONS:
        assert action.argv[0] == "aurascan"
        for part in action.argv[1:]:
            match = ui_actions.PLACEHOLDER.match(part)
            if match is not None:
                assert match.group(1) in action.argument_names()
                continue
            assert "{" not in part and "}" not in part
            for character in ";|&$`><":
                assert character not in part


def test_action_scopes_and_confirmations_are_consistent():
    for action in ui_actions.ACTIONS:
        payload = action.to_dict()
        assert action.kind in ui_actions.ACTION_KINDS
        assert action.confirmation in ui_actions.CONFIRMATIONS
        if action.kind == "read_only":
            assert action.confirmation == "none"
            assert payload["renderer_may_request"] is True
        else:
            assert action.confirmation == "terminal_only"
            assert payload["renderer_may_request"] is False


def test_state_changing_actions_stay_terminal_only():
    for action in ui_actions.ACTIONS:
        if action.action_id in STATE_CHANGING_ACTIONS:
            assert action.kind == "terminal_only"
            assert action.to_dict()["renderer_may_request"] is False


def test_build_action_argv_substitutes_declared_arguments():
    argv = ui_actions.build_action_argv(
        "scan_package",
        {"package_path": "/var/cache/pacman/pkg/example.pkg.tar.zst"},
    )

    assert argv == [
        "aurascan",
        "--pkg",
        "/var/cache/pacman/pkg/example.pkg.tar.zst",
        "--json",
    ]


def test_build_action_argv_rejects_unvalidated_values():
    for bad in (
        "relative/path.pkg.tar.zst",
        "--pkg=/etc/passwd",
        "/tmp/bad\x00name",
        "/tmp/line\nbreak",
        "/tmp/" + "a" * 5000,
        "",
        42,
    ):
        with pytest.raises(ui_actions.UIActionError):
            ui_actions.build_action_argv("scan_package", {"package_path": bad})


def test_build_action_argv_rejects_missing_and_extra_arguments():
    with pytest.raises(ui_actions.UIActionError):
        ui_actions.build_action_argv("scan_package", {})
    with pytest.raises(ui_actions.UIActionError):
        ui_actions.build_action_argv("refresh_snapshot", {"command": "rm -rf /"})
    with pytest.raises(ui_actions.UIActionError):
        ui_actions.build_action_argv("not_a_real_action", {})


def test_report_binding_matches_exact_bytes():
    payload = b'{"findings": []}'
    digest = ui_actions.report_sha256(payload)

    ui_actions.verify_report_binding(digest, payload)
    ui_actions.verify_report_binding(digest.upper(), payload)

    with pytest.raises(ui_actions.UIActionError):
        ui_actions.verify_report_binding(
            ui_actions.report_sha256(b'{"findings": [1]}'), payload
        )
    for malformed in ("", "z" * 64, "a" * 63):
        with pytest.raises(ui_actions.UIActionError):
            ui_actions.verify_report_binding(malformed, payload)


def test_run_ui_actions_mode_skips_live_evidence():
    def forbidden_provider():
        raise AssertionError("live evidence must not be collected in action mode")

    stdout = io.StringIO()
    stderr = io.StringIO()
    code = ui_cli.run_ui(
        ["--actions", "--json"],
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
    assert sorted(payload) == ["actions", "app", "contract", "generated_at"]
    assert sorted(action["id"] for action in payload["actions"]) == EXPECTED_ACTION_IDS


def test_run_ui_actions_summary_lists_scopes():
    stdout = io.StringIO()
    code = ui_cli.run_ui(["--actions"], stdout=stdout, stderr=io.StringIO(), now=lambda: 1)

    text = stdout.getvalue()
    assert code == 0
    assert "AuraScan actions (aurascan-ui/1)" in text
    assert "scan_package [read_only] renderer may request" in text
    assert "repair_runtime_links [terminal_only] terminal only" in text
    assert "never a command" in text


def test_report_and_actions_modes_are_exclusive():
    with pytest.raises(SystemExit):
        ui_cli.build_ui_parser().parse_args(["--report", "/tmp/report.json", "--actions"])


def test_desktop_fixture_actions_match_the_python_catalog():
    fixture = (
        Path(__file__).resolve().parents[1]
        / "desktop"
        / "src"
        / "fixtures"
        / "snapshot.sample.json"
    )
    fixture_actions = json.loads(fixture.read_text(encoding="utf-8"))["actions"]
    catalog = ui_actions.action_catalog()

    assert [action["id"] for action in fixture_actions] == [
        action["id"] for action in catalog
    ]
    assert set(fixture_actions[0]) == set(catalog[0])
    assert [action["argv_preview"] for action in fixture_actions] == [
        action["argv_preview"] for action in catalog
    ]
