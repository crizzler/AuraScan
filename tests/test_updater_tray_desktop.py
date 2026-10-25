"""The tray opens the optional desktop console instead of the CLI wizard.

These tests use temporary executables; nothing here starts a GUI process.
"""

import os
import stat

import aurascan.core.updater_tray as tray


def _executable(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def test_menu_routes_settings_and_console_to_the_desktop_app():
    entries = {label: command for group in tray.UPDATER_MENU_GROUPS for label, command in group}

    assert entries["AuraScan Settings"] is tray.DESKTOP_SETTINGS_ACTION
    assert entries["Open AuraScan Console"] is tray.DESKTOP_CONSOLE_ACTION
    assert tray.DESKTOP_CONSOLE_ACTION not in {
        command for label, command in entries.items() if label not in {"Open AuraScan Console"}
    }


def test_resolve_prefers_the_packaged_launcher(tmp_path, monkeypatch):
    system = _executable(tmp_path / "usr-bin-aurascan-desktop")
    user = _executable(tmp_path / "home" / ".local" / "bin" / "aurascan-desktop")
    monkeypatch.setattr(tray, "DESKTOP_CONSOLE_SYSTEM_PATH", str(system))

    assert tray.resolve_desktop_console(which=lambda name: None, home=tmp_path / "home") == str(system)
    system.unlink()
    assert tray.resolve_desktop_console(which=lambda name: None, home=tmp_path / "home") == str(user)


def test_resolve_uses_path_lookup_and_reports_absence(tmp_path, monkeypatch):
    monkeypatch.setattr(tray, "DESKTOP_CONSOLE_SYSTEM_PATH", str(tmp_path / "missing"))

    assert (
        tray.resolve_desktop_console(
            which=lambda name: "/opt/bin/aurascan-desktop", home=tmp_path / "home"
        )
        == "/opt/bin/aurascan-desktop"
    )
    assert (
        tray.resolve_desktop_console(which=lambda name: "aurascan-desktop", home=tmp_path / "home")
        == ""
    )
    assert tray.resolve_desktop_console(which=lambda name: None, home=tmp_path / "home") == ""


def test_launch_uses_a_fixed_argument_vector():
    calls = []

    def popen(argv, **kwargs):
        calls.append((argv, kwargs))

    assert tray.launch_desktop_console("/usr/bin/aurascan-desktop", "settings", popen=popen) is True
    assert calls[0][0] == ["/usr/bin/aurascan-desktop", "--view", "settings"]
    assert calls[0][1]["close_fds"] is True
    assert "shell" not in calls[0][1]

    assert tray.launch_desktop_console("/usr/bin/aurascan-desktop", "", popen=popen) is True
    assert calls[1][0] == ["/usr/bin/aurascan-desktop"]


def test_launch_refuses_a_relative_or_unsafe_program():
    started = []

    assert tray.launch_desktop_console("aurascan-desktop", "", popen=lambda *a, **k: started.append(a)) is False
    assert tray.launch_desktop_console("/tmp/a\u0000b", "", popen=lambda *a, **k: started.append(a)) is False
    assert started == []


def test_launch_reports_a_missing_launcher():
    def popen(*_args, **_kwargs):
        raise FileNotFoundError

    assert tray.launch_desktop_console("/usr/bin/aurascan-desktop", "", popen=popen) is False


def test_user_launcher_must_be_executable(tmp_path, monkeypatch):
    monkeypatch.setattr(tray, "DESKTOP_CONSOLE_SYSTEM_PATH", str(tmp_path / "missing"))
    user = tmp_path / "home" / ".local" / "bin" / "aurascan-desktop"
    user.parent.mkdir(parents=True)
    user.write_text("#!/bin/sh\n", encoding="utf-8")
    os.chmod(user, 0o644)

    assert tray.resolve_desktop_console(which=lambda name: None, home=tmp_path / "home") == ""
