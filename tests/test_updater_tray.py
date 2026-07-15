import io
import json
from pathlib import Path

from aurascan.core.updater_tray import (
    UPDATER_AUTOSTART_ENV,
    UPDATER_INCIDENT_REFRESH_MS,
    UPDATER_MENU_GROUPS,
    UPDATER_TERMINAL_ENV,
    UPDATER_TRAY_ENABLED_ENV,
    INCIDENT_REVIEW_COMMAND,
    build_terminal_invocation,
    build_incident_notification,
    build_updater_status,
    install_updater_autostart,
    remove_updater_autostart,
    render_desktop_entry,
    resolve_tray_incident_state,
    resolve_updater_config,
    run_updater,
    updater_desktop_paths,
)


def fake_which(found):
    def _which(name):
        return f"/usr/bin/{name}" if name in found else None

    return _which


def test_terminal_launcher_prefers_xdg_terminal_exec():
    invocation = build_terminal_invocation(
        ["aurascan", "upgrade"],
        which=fake_which({"xdg-terminal-exec", "konsole"}),
    )

    assert invocation.terminal == "xdg-terminal-exec"
    assert invocation.command[0] == "/usr/bin/xdg-terminal-exec"
    assert invocation.command[1:3] == ["sh", "-lc"]
    assert "aurascan upgrade" in invocation.command[3]


def test_terminal_launcher_uses_native_hold_flags_for_common_terminals():
    assert build_terminal_invocation(["aurascan", "upgrade"], which=fake_which({"konsole"})).command == [
        "/usr/bin/konsole",
        "--hold",
        "-e",
        "aurascan",
        "upgrade",
    ]
    assert build_terminal_invocation(["aurascan", "upgrade"], which=fake_which({"alacritty"})).command == [
        "/usr/bin/alacritty",
        "--hold",
        "-e",
        "aurascan",
        "upgrade",
    ]
    assert build_terminal_invocation(["aurascan", "upgrade"], which=fake_which({"kitty"})).command == [
        "/usr/bin/kitty",
        "--hold",
        "aurascan",
        "upgrade",
    ]
    assert build_terminal_invocation(["aurascan", "upgrade"], which=fake_which({"xterm"})).command == [
        "/usr/bin/xterm",
        "-hold",
        "-e",
        "aurascan",
        "upgrade",
    ]


def test_terminal_launcher_uses_shell_pause_for_gnome_terminal():
    invocation = build_terminal_invocation(["aurascan", "upgrade", "--dry-run"], which=fake_which({"gnome-terminal"}))

    assert invocation.terminal == "gnome-terminal"
    assert invocation.command[:4] == ["/usr/bin/gnome-terminal", "--", "sh", "-lc"]
    assert "aurascan upgrade --dry-run" in invocation.command[4]
    assert "Press Enter to close AuraScan Updater" in invocation.command[4]


def test_terminal_launcher_reports_missing_terminal():
    invocation = build_terminal_invocation(["aurascan", "doctor"], which=fake_which(set()))

    assert invocation.error
    assert invocation.command == []


def test_desktop_entry_rendering_and_autostart_lifecycle(tmp_path):
    paths = updater_desktop_paths(config_home=tmp_path / "config", data_home=tmp_path / "data")

    result = install_updater_autostart(paths=paths)

    assert result.ok is True
    assert paths.app_desktop.exists()
    assert paths.autostart_desktop.exists()
    assert paths.icon.exists()
    assert all(path.exists() for path in paths.state_icons.values())
    assert "Exec=aurascan updater" in paths.app_desktop.read_text(encoding="utf-8")
    assert "X-GNOME-Autostart-enabled=true" in paths.autostart_desktop.read_text(encoding="utf-8")
    assert "<svg" in paths.icon.read_text(encoding="utf-8")

    removed = remove_updater_autostart(paths=paths)

    assert removed.ok is True
    assert not paths.autostart_desktop.exists()
    assert paths.app_desktop.exists()


def test_desktop_entry_without_autostart_flag():
    text = render_desktop_entry(autostart=False)

    assert "Name=AuraScan Updater" in text
    assert "X-GNOME-Autostart-enabled" not in text


def test_updater_config_parsing_and_invalid_values():
    config = resolve_updater_config({
        UPDATER_TRAY_ENABLED_ENV: "1",
        UPDATER_AUTOSTART_ENV: "0",
        UPDATER_TERMINAL_ENV: "konsole",
    })

    assert config.tray_enabled is True
    assert config.autostart_enabled is False
    assert config.terminal == "konsole"
    assert not config.error
    assert resolve_updater_config({UPDATER_TERMINAL_ENV: "unknown"}).error
    assert resolve_updater_config({UPDATER_TRAY_ENABLED_ENV: "sometimes"}).error


def test_updater_status_reports_qt_terminal_and_paths(tmp_path):
    paths = updater_desktop_paths(config_home=tmp_path / "config", data_home=tmp_path / "data")
    install_updater_autostart(paths=paths)

    status = build_updater_status(
        env={UPDATER_TRAY_ENABLED_ENV: "1", UPDATER_AUTOSTART_ENV: "1"},
        paths=paths,
        which=fake_which({"konsole"}),
        qt_binding_finder=lambda: "PyQt6",
    )

    assert status.config.tray_enabled is True
    assert status.qt_binding == "PyQt6"
    assert status.terminal == "konsole"
    assert status.app_desktop_installed is True
    assert status.autostart_installed is True
    assert status.icon_installed is True


def test_updater_cli_install_remove_and_status(tmp_path):
    stdout = io.StringIO()
    env = {"XDG_CONFIG_HOME": str(tmp_path / "config"), "XDG_DATA_HOME": str(tmp_path / "data")}
    paths = updater_desktop_paths(env=env)
    env_path = tmp_path / "aurascan.env"

    assert run_updater(["--install-autostart"], stdout=stdout, env=env, env_path=env_path) == 0
    assert paths.autostart_desktop.exists()
    assert f"{UPDATER_TRAY_ENABLED_ENV}=1" in env_path.read_text(encoding="utf-8")
    assert "Installed AuraScan Updater autostart" in stdout.getvalue()

    stdout = io.StringIO()
    status = run_updater(
        ["--status"],
        stdout=stdout,
        env={**env, UPDATER_TRAY_ENABLED_ENV: "1", UPDATER_AUTOSTART_ENV: "1"},
        which=fake_which({"konsole"}),
        qt_binding_finder=lambda: "PySide6",
    )
    assert status == 0
    assert "AuraScan Updater status" in stdout.getvalue()
    assert "PySide6" in stdout.getvalue()

    stdout = io.StringIO()
    assert run_updater(["--remove-autostart"], stdout=stdout, env=env, env_path=env_path) == 0
    assert not paths.autostart_desktop.exists()
    assert f"{UPDATER_AUTOSTART_ENV}=0" in env_path.read_text(encoding="utf-8")


def test_updater_cli_no_tray_does_not_start_gui(tmp_path):
    stdout = io.StringIO()
    env = {"XDG_CONFIG_HOME": str(tmp_path / "config"), "XDG_DATA_HOME": str(tmp_path / "data")}

    status = run_updater(
        ["--no-tray"],
        stdout=stdout,
        env=env,
        which=fake_which(set()),
        qt_binding_finder=lambda: "",
    )

    assert status == 0
    assert "Qt binding: not found" in stdout.getvalue()
    assert "Terminal: not found" in stdout.getvalue()


def test_updater_menu_exposes_one_guided_incident_resolution_workflow():
    commands = {label: list(command) for group in UPDATER_MENU_GROUPS for label, command in group}

    assert commands["Resolve System Findings"] == ["aurascan", "incidents", "--resolve"]
    assert commands["Run System Maintenance Scan"] == ["aurascan", "incidents", "--run-maintenance"]
    assert not {
        "AuraScan Doctor",
        "Config Drift Assistant",
        "Diagnose System Problems",
        "Dry-run Preflight",
        "Review Last Crash",
        "Review System Findings",
        "Recent Incidents",
    } & commands.keys()
    assert list(INCIDENT_REVIEW_COMMAND) == ["aurascan", "incidents", "--resolve"]
    assert UPDATER_INCIDENT_REFRESH_MS == 5_000


def test_incident_notification_groups_markers_by_boot():
    title, message = build_incident_notification([
        {"boot_id": "a" * 32, "uid_scope": "global", "count": 2},
        {"boot_id": "a" * 32, "uid_scope": "1000", "count": 1},
    ])

    assert title == "AuraScan found crash evidence"
    assert "3 incident event(s)" in message


def test_tray_state_is_due_when_maintenance_is_incomplete(tmp_path):
    status_path = tmp_path / "status.json"
    status_path.write_text(json.dumps({"collection_status": "partial", "last_success_usec": 1}), encoding="utf-8")

    state = resolve_tray_incident_state(
        marker_root=tmp_path / "pending",
        notification_seen_path=tmp_path / "seen.json",
        reviewed_path=tmp_path / "reviewed.json",
        maintenance_status_path=status_path,
        uid=1000,
        now_usec=2,
    )

    assert state.state == "due"
    assert state.notification_markers == []


def test_tray_state_attention_and_notification_thresholds(tmp_path):
    marker_root = tmp_path / "pending"
    marker_root.mkdir()
    medium = {
        "marker_type": "maintenance",
        "scan_id": "scan-medium",
        "boot_id": "a" * 32,
        "uid_scope": "1000",
        "severity": "MEDIUM",
        "categories": ["application_crash"],
        "count": 1,
        "repeated": False,
    }
    (marker_root / "medium.json").write_text(json.dumps(medium), encoding="utf-8")

    state = resolve_tray_incident_state(
        marker_root=marker_root,
        notification_seen_path=tmp_path / "seen.json",
        reviewed_path=tmp_path / "reviewed.json",
        maintenance_status_path=tmp_path / "missing.json",
        uid=1000,
    )

    assert state.state == "attention"
    assert state.notification_markers == []

    repeated = dict(medium, scan_id="scan-repeated", count=3, repeated=True)
    (marker_root / "repeated.json").write_text(json.dumps(repeated), encoding="utf-8")
    repeated_state = resolve_tray_incident_state(
        marker_root=marker_root,
        notification_seen_path=tmp_path / "seen.json",
        reviewed_path=tmp_path / "reviewed.json",
        maintenance_status_path=tmp_path / "missing.json",
        uid=1000,
    )
    assert any(item["scan_id"] == "scan-repeated" for item in repeated_state.notification_markers)

    critical = dict(medium, scan_id="scan-critical", severity="HIGH")
    (marker_root / "critical.json").write_text(json.dumps(critical), encoding="utf-8")
    critical_state = resolve_tray_incident_state(
        marker_root=marker_root,
        notification_seen_path=tmp_path / "seen.json",
        reviewed_path=tmp_path / "reviewed.json",
        maintenance_status_path=tmp_path / "missing.json",
        uid=1000,
    )

    assert critical_state.state == "critical"
    assert {item["scan_id"] for item in critical_state.notification_markers} == {"scan-critical", "scan-repeated"}


def test_reviewed_marker_clears_attention_but_later_generation_returns(tmp_path):
    marker_root = tmp_path / "pending"
    marker_root.mkdir()
    marker = {
        "marker_type": "maintenance",
        "scan_id": "scan-one",
        "boot_id": "a" * 32,
        "uid_scope": "1000",
        "severity": "MEDIUM",
        "categories": ["application_crash"],
        "count": 3,
        "repeated": True,
    }
    (marker_root / "one.json").write_text(json.dumps(marker), encoding="utf-8")
    reviewed = tmp_path / "reviewed.json"
    reviewed.write_text(json.dumps(["maintenance:scan-one:1000"]), encoding="utf-8")

    state = resolve_tray_incident_state(
        marker_root=marker_root,
        notification_seen_path=tmp_path / "seen.json",
        reviewed_path=reviewed,
        maintenance_status_path=tmp_path / "missing.json",
        uid=1000,
    )
    assert state.state == "normal"

    marker["scan_id"] = "scan-two"
    (marker_root / "two.json").write_text(json.dumps(marker), encoding="utf-8")
    later = resolve_tray_incident_state(
        marker_root=marker_root,
        notification_seen_path=tmp_path / "seen.json",
        reviewed_path=reviewed,
        maintenance_status_path=tmp_path / "missing.json",
        uid=1000,
    )
    assert later.state == "attention"
