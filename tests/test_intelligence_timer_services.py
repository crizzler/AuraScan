"""Fixed desktop-authorized timer operations retain the existing CLI boundary."""

import configparser
from pathlib import Path
import shlex

import pytest

from aurascan.core import intelligence_cli as cli
from aurascan.core.intelligence import IntelligenceError


ROOT = Path(__file__).resolve().parents[1]


def forbidden(*_args, **_kwargs):
    raise AssertionError("unexpected privileged, service or network operation")


@pytest.mark.parametrize("operation,state", [("_auto-enable", "enable"), ("_auto-disable", "disable")])
def test_timer_entry_points_share_public_authorization_and_configuration_checks(monkeypatch, operation, state):
    calls = []
    monkeypatch.setattr(cli, "run_intelligence", lambda args: calls.append(args) or 7)
    assert cli._service_main([operation]) == 7
    assert calls == [["auto-update", state]]


@pytest.mark.parametrize("operation", ["_auto-enable", "_auto-disable"])
def test_timer_private_entry_points_cannot_skip_root_requirement(monkeypatch, operation):
    monkeypatch.setattr(cli.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(cli, "_systemctl", forbidden)
    monkeypatch.setattr(cli, "assert_production_trust_configured", forbidden)
    assert cli._service_main([operation]) == 1


@pytest.mark.parametrize("missing", ["trust", "feed"])
def test_timer_enable_refuses_unconfigured_production_channel(monkeypatch, missing):
    def unconfigured():
        raise IntelligenceError("test channel is unconfigured")
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli, "_systemctl", forbidden)
    monkeypatch.setattr(cli, "assert_production_trust_configured", unconfigured if missing == "trust" else lambda: None)
    monkeypatch.setattr(cli, "assert_feed_configured", unconfigured if missing == "feed" else forbidden)
    assert cli._service_main(["_auto-enable"]) == 1


def test_timer_disable_remains_possible_with_missing_feed_and_trust(monkeypatch):
    calls = []
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli, "assert_production_trust_configured", forbidden)
    monkeypatch.setattr(cli, "assert_feed_configured", forbidden)
    monkeypatch.setattr(cli, "fetch_bundle", forbidden)
    monkeypatch.setattr(cli, "activate_bundle", forbidden)
    monkeypatch.setattr(cli, "_systemctl", lambda args: calls.append(args))
    assert cli._service_main(["_auto-disable"]) == 0
    assert calls == [["disable", "--now", "aurascan-intelligence-update.timer"]]


def test_configured_enable_selects_only_the_fixed_daily_timer(monkeypatch):
    calls = []
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli, "assert_production_trust_configured", lambda: None)
    monkeypatch.setattr(cli, "assert_feed_configured", lambda: None)
    monkeypatch.setattr(cli, "fetch_bundle", forbidden)
    monkeypatch.setattr(cli, "activate_bundle", forbidden)
    monkeypatch.setattr(cli, "_systemctl", lambda args: calls.append(args))
    assert cli._service_main(["_auto-enable"]) == 0
    assert calls == [["enable", "--now", "aurascan-intelligence-update.timer"]]


@pytest.mark.parametrize("arguments", [
    ["_auto-enable", "unrelated.timer"], ["_auto-disable", "--skip-verification"],
    ["_auto-enable", "--feed", "https://example.invalid"], ["_auto-restart"],
])
def test_private_timer_operations_cannot_select_arbitrary_parameters(monkeypatch, arguments):
    monkeypatch.setattr(cli, "run_intelligence", forbidden)
    assert cli._service_main(arguments) == 1


@pytest.mark.parametrize("state", ["enable", "disable"])
def test_timer_control_units_are_fixed_privileged_offline_oneshots(state):
    name = "aurascan-intelligence-auto-" + state + ".service"
    parser = configparser.ConfigParser(interpolation=None)
    parser.read(ROOT / "aurascan/assets" / name)
    service = parser["Service"]
    assert service["Type"] == "oneshot" and service["User"] == service["Group"] == "root"
    assert shlex.split(service["ExecStart"]) == [
        "/usr/bin/env", "-i", "PATH=/usr/bin:/usr/sbin", "LANG=C", "LC_ALL=C", "HOME=/",
        "/usr/bin/python", "-I", "-m", "aurascan.core.intelligence_cli", "_auto-" + state,
    ]
    assert service["WorkingDirectory"] == "/"
    assert service["PrivateNetwork"] == "yes" and service["IPAddressDeny"] == "any"
    assert service["RestrictAddressFamilies"] == "AF_UNIX"
    assert service["ProtectSystem"] == "strict" and service["ProtectHome"] == "yes"
    assert service["ReadWritePaths"] == "/etc/systemd/system"
    assert service["NoNewPrivileges"] == "yes"
    assert service["CapabilityBoundingSet"] == service["AmbientCapabilities"] == ""
    assert 240 < int(service["TimeoutStartSec"]) <= 250
    assert int(service["TimeoutStopSec"]) <= 5
    assert service["Restart"] == "no"
    assert "MemoryMax" in service and "TasksMax" in service and "LimitFSIZE" in service
    assert "Install" not in parser and "Requires" not in parser["Unit"]
    recipe = (ROOT / "packaging/arch/PKGBUILD").read_text(encoding="utf-8")
    assert 'install -Dm644 aurascan/assets/' + name + ' "$pkgdir/usr/lib/systemd/system/' + name + '"' in recipe
    assert name not in (ROOT / "packaging/arch/aurascan.install").read_text(encoding="utf-8")


def test_new_units_are_included_by_runtime_asset_packaging():
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib
    with (ROOT / "pyproject.toml").open("rb") as stream:
        project = tomllib.load(stream)
    assert "assets/*" in project["tool"]["setuptools"]["package-data"]["aurascan"]
    assert not list((ROOT / "aurascan/assets").glob("*.policy"))
