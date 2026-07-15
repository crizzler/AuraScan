import os
import subprocess
from pathlib import Path

from aurascan.core.recovery_network import (
    RecoveryNetworkState,
    connect_wifi,
    discover_saved_wifi_profiles,
    import_saved_wifi_profiles,
    normalize_wifi_security,
    scan_wifi_networks,
)


def test_saved_wifi_profile_requires_regular_owner_and_0600(tmp_path):
    root = tmp_path / "target"
    profile_root = root / "etc/NetworkManager/system-connections"
    profile_root.mkdir(parents=True)
    valid = profile_root / "home.nmconnection"
    valid.write_text("[connection]\ntype=wifi\n[wifi]\nssid=Home\n", encoding="utf-8")
    valid.chmod(0o600)
    loose = profile_root / "loose.nmconnection"
    loose.write_text("[connection]\ntype=wifi\n", encoding="utf-8")
    loose.chmod(0o644)

    profiles, notes = discover_saved_wifi_profiles(root, required_uid=os.getuid())

    assert profiles == [valid]
    assert any("0600" in item for item in notes)


def test_manual_wifi_secret_never_appears_in_argv():
    calls = []

    def runner(command, **kwargs):
        calls.append((command, kwargs.get("input")))
        return subprocess.CompletedProcess(command, 0, "connected", "")

    ok, _message = connect_wifi(
        "Home WiFi",
        password_func=lambda _prompt: "fixture-wifi-secret",
        runner=runner,
        which=lambda _name: "/usr/bin/nmcli",
    )

    assert ok is True
    assert all("fixture-wifi-secret" not in part for part in calls[0][0])
    assert calls[0][1] == "fixture-wifi-secret\n"


def test_wifi_scan_supports_open_wpa2_wpa3_and_rejects_enterprise():
    output = "Cafe:80:--\nHome:90:WPA2\nModern:70:WPA3 SAE\nOffice:60:WPA2 802.1X\n"

    networks = scan_wifi_networks(
        runner=lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, output, ""),
        which=lambda _name: "/usr/bin/nmcli",
    )

    by_name = {item.ssid: item for item in networks}
    assert by_name["Cafe"].security == "open"
    assert by_name["Home"].security == "wpa2"
    assert by_name["Modern"].security == "wpa3"
    assert by_name["Office"].supported is False
    assert normalize_wifi_security("EAP WPA2") == "enterprise"


def test_saved_profile_is_activated_without_passing_its_psk_in_argv(tmp_path):
    root = tmp_path / "target"
    profile_root = root / "etc/NetworkManager/system-connections"
    profile_root.mkdir(parents=True)
    profile = profile_root / "home.nmconnection"
    profile.write_text(
        "[connection]\nid=Home\nuuid=12345678-1234-1234-1234-123456789abc\ntype=wifi\n"
        "[wifi]\nssid=Home\n[wifi-security]\npsk=fixture-profile-secret\n",
        encoding="utf-8",
    )
    profile.chmod(0o600)
    calls = []

    def runner(command, **_kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "ok", "")

    imported, _notes = import_saved_wifi_profiles(
        root,
        runtime_root=tmp_path / "run",
        required_uid=os.getuid(),
        runner=runner,
        which=lambda _name: "/usr/bin/nmcli",
    )

    assert imported == 1
    assert any(command[-2:] == ["uuid", "12345678-1234-1234-1234-123456789abc"] for command in calls)
    assert all("fixture-profile-secret" not in part for command in calls for part in command)


def test_persisted_network_state_uses_a_correlation_token_not_the_connection_name():
    state = RecoveryNetworkState(
        available=True,
        connected=True,
        connectivity="full",
        connection_type="wifi",
        connection_name="Private Home SSID",
    )

    serialized = state.to_dict()

    assert serialized["connection_name"].startswith("network-")
    assert "Private Home SSID" not in str(serialized)
