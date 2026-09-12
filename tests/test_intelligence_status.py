"""Local tray status never grants service authority or invents update success."""

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from aurascan.core import intelligence_cli as cli
from aurascan.core.intelligence import (
    MANIFEST_FILENAME, PAYLOAD_FILENAME, SIGNATURE_FILENAME, build_manifest,
    bundled_snapshot, canonical_json, format_time,
)
from aurascan.core.intelligence_crypto import PinnedKey
from aurascan.core.intelligence_store import IntelligenceStore
from aurascan.core.trusted_tools import TrustedToolError


def forbidden(*_args, **_kwargs):
    raise AssertionError("unexpected authority, network or service operation")


def service_output(*, timer_enabled="disabled", timer_active="inactive", changes=None):
    """Representative systemd properties, independent of the status reducer."""
    units = {
        "aurascan-intelligence-update.timer": {
            "Id": "aurascan-intelligence-update.timer", "LoadState": "loaded",
            "ActiveState": timer_active, "UnitFileState": timer_enabled,
        },
    }
    for name in ("aurascan-intelligence-fetch.service", "aurascan-intelligence-activate.service",
                 "aurascan-intelligence-import.service", "aurascan-intelligence-auto-enable.service",
                 "aurascan-intelligence-auto-disable.service"):
        units[name] = {"Id": name, "LoadState": "loaded", "ActiveState": "inactive",
                       "UnitFileState": "static", "Result": "success"}
    for name, properties in (changes or {}).items():
        units[name].update(properties)
    return "\n\n".join("\n".join(key + "=" + value for key, value in unit.items())
                        for unit in units.values()) + "\n"


def capture_services(monkeypatch, output, *, returncode=0):
    calls = []
    tool = SimpleNamespace(path="/usr/bin/systemctl")
    monkeypatch.setattr(cli, "capture_trusted_system_tool", lambda *args, **kwargs: tool)
    monkeypatch.setattr(cli, "revalidate_trusted_system_tool", lambda captured: calls.append(captured))
    monkeypatch.setattr(cli, "run_bounded_trusted_tool", lambda args, **kwargs:
                        calls.append((args, kwargs)) or SimpleNamespace(
                            returncode=returncode, stdout=output, stderr="fake-private-error"))
    return calls, tool


def test_default_status_remains_service_free(monkeypatch, capsys):
    monkeypatch.setattr(cli, "load_intelligence_snapshot", bundled_snapshot)
    monkeypatch.setattr(cli, "_service_status", forbidden)
    monkeypatch.setattr(cli, "fetch_bundle", forbidden)
    monkeypatch.setattr(cli, "activate_bundle", forbidden)
    assert cli.run_intelligence(["status", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["activated_at"] == ""
    assert "automatic_updates" not in result
    assert "status_schema" not in result


def test_extended_status_uses_one_read_only_bounded_fixed_command(monkeypatch, capsys):
    calls, tool = capture_services(monkeypatch, service_output())
    monkeypatch.setattr(cli, "load_intelligence_snapshot", bundled_snapshot)
    monkeypatch.setattr(cli, "_systemctl", forbidden)
    monkeypatch.setattr(cli, "_require_root", forbidden)
    monkeypatch.setattr(cli, "fetch_bundle", forbidden)
    monkeypatch.setattr(cli, "activate_bundle", forbidden)
    monkeypatch.setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/tmp/fake-bus")
    monkeypatch.setenv("AURASCAN_AI_KEY", "fake-private-secret")
    assert cli.run_intelligence(["status", "--json", "--include-services"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status_schema"] == "intelligence-status/1.0"
    assert result["automatic_updates"] == "disabled"
    assert result["refresh_status"] == "idle"
    assert result["update_channel"] == "unconfigured"
    assert calls[0] is tool and calls[2] is tool
    args, options = calls[1]
    assert args[:4] == ["/usr/bin/systemctl", "--no-pager", "--no-ask-password", "show"]
    assert set(args[-6:]) == {
        "aurascan-intelligence-update.timer", "aurascan-intelligence-fetch.service",
        "aurascan-intelligence-activate.service", "aurascan-intelligence-import.service",
        "aurascan-intelligence-auto-enable.service", "aurascan-intelligence-auto-disable.service",
    }
    assert options["timeout"] <= 10 and options["cwd"] == "/"
    assert "shell" not in options
    assert "DBUS_SYSTEM_BUS_ADDRESS" not in options["env"]
    assert "AURASCAN_AI_KEY" not in options["env"]


@pytest.mark.parametrize("enabled,active,expected", [
    ("enabled", "active", "enabled"),
    ("disabled", "inactive", "disabled"),
    ("enabled", "inactive", "inconsistent"),
    ("disabled", "active", "inconsistent"),
    ("enabled-runtime", "active", "inconsistent"),
    ("masked", "inactive", "inconsistent"),
    ("enabled", "failed", "inconsistent"),
])
def test_timer_state_requires_both_persistence_and_running_state(monkeypatch, enabled, active, expected):
    capture_services(monkeypatch, service_output(timer_enabled=enabled, timer_active=active))
    assert cli._service_status()["automatic_updates"] == expected


@pytest.mark.parametrize("changes,expected", [
    ({cli.FETCH_SERVICE: {"ActiveState": "activating"}}, "running"),
    ({cli.ACTIVATION_SERVICE: {"ActiveState": "failed", "Result": "exit-code"}}, "failed"),
    ({cli.FETCH_SERVICE: {"ActiveState": "failed", "Result": "timeout"}}, "failed"),
    ({cli.IMPORT_SERVICE: {"ActiveState": "inactive", "Result": "signal"}}, "failed"),
    ({cli.FETCH_SERVICE: {"ActiveState": "activating"},
      cli.ACTIVATION_SERVICE: {"ActiveState": "failed", "Result": "exit-code"}}, "running"),
    ({cli.FETCH_SERVICE: {"LoadState": "not-found", "Result": ""}}, "unavailable"),
    ({cli.IMPORT_SERVICE: {"Result": ""}}, "unavailable"),
    ({cli.AUTO_ENABLE_SERVICE: {"ActiveState": "activating"}}, "running"),
    ({cli.AUTO_DISABLE_SERVICE: {"ActiveState": "failed", "Result": "timeout"}}, "failed"),
])
def test_refresh_health_distinguishes_in_progress_failure_and_missing_evidence(monkeypatch, changes, expected):
    capture_services(monkeypatch, service_output(changes=changes))
    assert cli._service_status()["refresh_status"] == expected


@pytest.mark.parametrize("transform", [
    lambda output: output.replace("LoadState=loaded", "LoadState=loaded\nLoadState=loaded", 1),
    lambda output: output.replace("LoadState=loaded", "LoadState=loaded\nSecret=fake-secret", 1),
    lambda output: output.replace("Id=aurascan-intelligence-fetch.service", "Id=unrelated.service"),
    lambda output: output.replace("Result=success", "Result=success\x1b[0m", 1),
    lambda output: output.split("\n\n", 1)[0],
    lambda output: output + "x" * 9000,
])
def test_malformed_service_response_cannot_become_disabled_or_healthy(monkeypatch, transform):
    capture_services(monkeypatch, transform(service_output()))
    assert cli._service_status() == {"automatic_updates": "unavailable", "refresh_status": "unavailable"}


def test_absent_units_and_failed_service_query_do_not_report_success(monkeypatch, capsys):
    capture_services(monkeypatch, service_output(changes={cli.UPDATE_TIMER: {"LoadState": "not-found"}}))
    assert cli._service_status()["automatic_updates"] == "unavailable"
    capture_services(monkeypatch, service_output(), returncode=1)
    monkeypatch.setattr(cli, "load_intelligence_snapshot", bundled_snapshot)
    assert cli.run_intelligence(["status", "--json", "--include-services"]) == 0
    rendered = capsys.readouterr()
    assert "fake-private-error" not in rendered.out + rendered.err
    assert json.loads(rendered.out)["refresh_status"] == "unavailable"


def test_unsafe_or_replaced_systemctl_never_establishes_service_status(monkeypatch):
    calls, _tool = capture_services(monkeypatch, service_output())
    def changed(_tool):
        raise TrustedToolError("fake-private-tool-path")
    monkeypatch.setattr(cli, "revalidate_trusted_system_tool", changed)
    assert cli._service_status()["automatic_updates"] == "unavailable"
    assert not calls
    monkeypatch.setattr(cli, "capture_trusted_system_tool", lambda *args, **kwargs: None)
    assert cli._service_status()["refresh_status"] == "unavailable"


def test_timeout_never_leaks_helper_output_or_establishes_service_status(monkeypatch, capsys):
    capture_services(monkeypatch, service_output())
    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("fixed-command", 10, output="fake-private-output")
    monkeypatch.setattr(cli, "run_bounded_trusted_tool", timeout)
    monkeypatch.setattr(cli, "load_intelligence_snapshot", bundled_snapshot)
    assert cli.run_intelligence(["status", "--json", "--include-services"]) == 0
    rendered = capsys.readouterr()
    assert "fake-private-output" not in rendered.out + rendered.err
    assert json.loads(rendered.out)["automatic_updates"] == "unavailable"


def test_activation_time_records_installation_and_survives_noop_reimport(tmp_path):
    now = [datetime(2026, 9, 12, 12, tzinfo=timezone.utc)]
    key = PinnedKey("A" * 40, b"inert-public-key")
    target = IntelligenceStore(tmp_path / "installed", expected_uid=os.getuid(), keys=(key,),
                               clock=lambda: now[0], verifier=lambda *_args: key.fingerprint)
    source = tmp_path / "input"
    source.mkdir()
    payload = canonical_json(json.loads((Path(__file__).parents[1]
                                        / "aurascan/assets/runtime-intelligence.json").read_bytes()))
    (source / PAYLOAD_FILENAME).write_bytes(payload)
    (source / SIGNATURE_FILENAME).write_bytes(b"inert-signature")
    (source / MANIFEST_FILENAME).write_bytes(canonical_json(build_manifest(payload, 1, now[0] - timedelta(hours=1))))
    assert target.load().metadata()["activated_at"] == ""
    first = target.activate(source)
    assert first["activated_at"] == format_time(now[0])
    now[0] += timedelta(hours=2)
    repeated = target.activate(source)
    assert repeated["activated_at"] == first["activated_at"]
    assert repeated["identity"] == first["identity"]
    assert repeated["activation"] == "unchanged"
    (source / MANIFEST_FILENAME).write_bytes(canonical_json(build_manifest(payload, 2, now[0])))
    second = target.activate(source)
    assert second["activated_at"] == format_time(now[0])
    assert second["activated_at"] != first["activated_at"]
    assert target.load().metadata()["activated_at"] == second["activated_at"]
    (target.root / "active.json").write_text("{}", encoding="utf-8")
    unavailable = target.load().metadata()
    assert unavailable["status"] == "unavailable" and unavailable["activated_at"] == ""
