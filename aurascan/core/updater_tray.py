import argparse
import importlib.util
import json
import os
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Mapping, Optional, Sequence

from aurascan.core.ai_provider import parse_bool as parse_config_bool
from aurascan.core.config import read_env_file, user_env_path, write_user_env
from aurascan.core.incidents import (
    INCIDENT_MAINTENANCE_STATUS,
    INCIDENT_MONITOR_MARKER_ROOT,
    incident_reviewed_state_path,
    incident_seen_state_path,
    load_maintenance_status,
    mark_pending_markers_seen,
    pending_markers,
    unseen_pending_markers,
)


UPDATER_TRAY_ENABLED_ENV = "AURASCAN_UPDATER_TRAY_ENABLED"
UPDATER_AUTOSTART_ENV = "AURASCAN_UPDATER_AUTOSTART"
UPDATER_TERMINAL_ENV = "AURASCAN_UPDATER_TERMINAL"
UPDATER_TERMINALS = {"auto", "xdg-terminal-exec", "konsole", "alacritty", "kitty", "gnome-terminal", "xterm"}
UPDATER_APP_ID = "aurascan-updater"
UPDATER_DESKTOP_NAME = f"{UPDATER_APP_ID}.desktop"
UPDATER_ICON_NAME = UPDATER_APP_ID
UPDATER_TOOLTIP = "AuraScan Updater - guarded package upgrades"
UPDATER_INCIDENT_REFRESH_MS = 5_000
INCIDENT_REVIEW_COMMAND = ("aurascan", "incidents", "--resolve")
UPDATER_STATE_ICONS = {
    "normal": UPDATER_ICON_NAME,
    "due": f"{UPDATER_ICON_NAME}-maintenance",
    "attention": f"{UPDATER_ICON_NAME}-attention",
    "critical": f"{UPDATER_ICON_NAME}-critical",
}
UPDATER_TERMINAL_ORDER = ["xdg-terminal-exec", "konsole", "alacritty", "kitty", "gnome-terminal", "xterm"]
UPDATER_MENU_GROUPS = (
    (
        ("Run AuraScan Upgrade", ("aurascan", "upgrade")),
    ),
    (
        ("Resolve System Findings", INCIDENT_REVIEW_COMMAND),
        ("Run System Maintenance Scan", ("aurascan", "incidents", "--run-maintenance")),
    ),
    (
        ("AuraScan Settings", ("aurascan", "init")),
    ),
)
ASSET_DIR = Path(__file__).resolve().parents[1] / "assets"


@dataclass
class UpdaterConfig:
    tray_enabled: bool = False
    autostart_enabled: bool = False
    terminal: str = "auto"
    error: str = ""


@dataclass
class TerminalInvocation:
    terminal: str = ""
    command: List[str] = None
    error: str = ""

    def __post_init__(self) -> None:
        if self.command is None:
            self.command = []


@dataclass
class TrayIncidentState:
    state: str
    icon_name: str
    tooltip: str
    unreviewed_markers: List[Dict[str, object]]
    unseen_notification_markers: List[Dict[str, object]]
    notification_markers: List[Dict[str, object]]


@dataclass
class UpdaterDesktopPaths:
    app_desktop: Path
    autostart_desktop: Path
    icon: Path
    state_icons: Dict[str, Path]


@dataclass
class UpdaterInstallResult:
    ok: bool
    status: str
    message: str
    paths: UpdaterDesktopPaths


@dataclass
class UpdaterStatus:
    config: UpdaterConfig
    paths: UpdaterDesktopPaths
    qt_binding: str = ""
    terminal: str = ""
    terminal_path: str = ""
    app_desktop_installed: bool = False
    autostart_installed: bool = False
    icon_installed: bool = False
    state_icons_installed: bool = False

    def to_lines(self) -> List[str]:
        lines = [
            "AuraScan Updater status",
            f"Tray config: {'enabled' if self.config.tray_enabled else 'disabled'}",
            f"Autostart config: {'enabled' if self.config.autostart_enabled else 'disabled'}",
            f"Terminal preference: {self.config.terminal}",
            f"Qt binding: {self.qt_binding or 'not found'}",
            f"Terminal: {self.terminal or 'not found'}" + (f" ({self.terminal_path})" if self.terminal_path else ""),
            f"Application launcher: {'installed' if self.app_desktop_installed else 'missing'} ({self.paths.app_desktop})",
            f"Autostart entry: {'installed' if self.autostart_installed else 'missing'} ({self.paths.autostart_desktop})",
            f"Icon: {'installed' if self.icon_installed else 'missing'} ({self.paths.icon})",
            f"Attention icons: {'installed' if self.state_icons_installed else 'missing'}",
        ]
        if self.config.error:
            lines.append(f"Config error: {self.config.error}")
        return lines


def build_updater_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aurascan updater",
        description="Run and configure the AuraScan Updater system tray applet.",
    )
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--install-autostart", action="store_true", help="install per-user desktop and autostart entries")
    action.add_argument("--remove-autostart", action="store_true", help="remove the per-user autostart entry")
    action.add_argument("--status", action="store_true", help="show updater tray configuration and integration status")
    action.add_argument("--no-tray", action="store_true", help="show diagnostics without starting the tray applet")
    return parser


def resolve_updater_config(env: Optional[Mapping[str, str]] = None) -> UpdaterConfig:
    source = env if env is not None else os.environ
    enabled_raw = source.get(UPDATER_TRAY_ENABLED_ENV)
    tray_enabled = parse_config_bool(enabled_raw)
    if enabled_raw is not None and tray_enabled is None:
        return UpdaterConfig(error=f"invalid {UPDATER_TRAY_ENABLED_ENV} value")
    if tray_enabled is None:
        tray_enabled = False

    autostart_raw = source.get(UPDATER_AUTOSTART_ENV)
    autostart_enabled = parse_config_bool(autostart_raw)
    if autostart_raw is not None and autostart_enabled is None:
        return UpdaterConfig(error=f"invalid {UPDATER_AUTOSTART_ENV} value")
    if autostart_enabled is None:
        autostart_enabled = False

    terminal = source.get(UPDATER_TERMINAL_ENV, "auto").strip().lower() or "auto"
    if terminal not in UPDATER_TERMINALS:
        return UpdaterConfig(error=f"invalid {UPDATER_TERMINAL_ENV} value")

    return UpdaterConfig(tray_enabled=bool(tray_enabled), autostart_enabled=bool(autostart_enabled), terminal=terminal)


def run_updater(
    argv: Optional[Sequence[str]] = None,
    *,
    stdout=None,
    stderr=None,
    env: Optional[Mapping[str, str]] = None,
    config_home: Optional[Path] = None,
    data_home: Optional[Path] = None,
    env_path: Optional[Path] = None,
    which: Callable[[str], Optional[str]] = shutil.which,
    popen: Callable = subprocess.Popen,
    qt_binding_finder: Callable[[], str] = None,
) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    args = build_updater_parser().parse_args(list(argv or []))
    effective_env = env if env is not None else os.environ
    paths = updater_desktop_paths(env=effective_env, config_home=config_home, data_home=data_home)

    if args.install_autostart:
        existing = _safe_read_env(env_path or user_env_path())
        existing_config = resolve_updater_config(existing)
        terminal = existing_config.terminal if not existing_config.error else "auto"
        result = install_updater_autostart(paths=paths)
        if result.ok:
            write_user_env({
                UPDATER_TRAY_ENABLED_ENV: "1",
                UPDATER_AUTOSTART_ENV: "1",
                UPDATER_TERMINAL_ENV: terminal or "auto",
            }, path=env_path or user_env_path())
        print(result.message, file=stdout if result.ok else stderr)
        return 0 if result.ok else 1
    if args.remove_autostart:
        existing = _safe_read_env(env_path or user_env_path())
        existing_config = resolve_updater_config(existing)
        terminal = existing_config.terminal if not existing_config.error else "auto"
        result = remove_updater_autostart(paths=paths)
        if result.ok:
            write_user_env({
                UPDATER_TRAY_ENABLED_ENV: "0",
                UPDATER_AUTOSTART_ENV: "0",
                UPDATER_TERMINAL_ENV: terminal or "auto",
            }, path=env_path or user_env_path())
        print(result.message, file=stdout if result.ok else stderr)
        return 0 if result.ok else 1
    if args.status or args.no_tray:
        status = build_updater_status(env=effective_env, paths=paths, which=which, qt_binding_finder=qt_binding_finder)
        for line in status.to_lines():
            print(line, file=stdout)
        return 1 if status.config.error else 0

    return start_tray_app(env=effective_env, which=which, popen=popen, stderr=stderr)


def updater_desktop_paths(
    *,
    env: Optional[Mapping[str, str]] = None,
    config_home: Optional[Path] = None,
    data_home: Optional[Path] = None,
) -> UpdaterDesktopPaths:
    source = env if env is not None else os.environ
    cfg = config_home or Path(source.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    data = data_home or Path(source.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return UpdaterDesktopPaths(
        app_desktop=data / "applications" / UPDATER_DESKTOP_NAME,
        autostart_desktop=cfg / "autostart" / UPDATER_DESKTOP_NAME,
        icon=data / "icons" / "hicolor" / "scalable" / "apps" / f"{UPDATER_ICON_NAME}.svg",
        state_icons={
            state: data / "icons" / "hicolor" / "scalable" / "apps" / f"{name}.svg"
            for state, name in UPDATER_STATE_ICONS.items()
            if state != "normal"
        },
    )


def install_updater_autostart(*, paths: Optional[UpdaterDesktopPaths] = None) -> UpdaterInstallResult:
    paths = paths or updater_desktop_paths()
    try:
        paths.app_desktop.parent.mkdir(parents=True, exist_ok=True)
        paths.autostart_desktop.parent.mkdir(parents=True, exist_ok=True)
        paths.icon.parent.mkdir(parents=True, exist_ok=True)
        paths.app_desktop.write_text(render_desktop_entry(autostart=False), encoding="utf-8")
        paths.autostart_desktop.write_text(render_desktop_entry(autostart=True), encoding="utf-8")
        paths.icon.write_text(load_icon_svg(), encoding="utf-8")
        for state, path in paths.state_icons.items():
            path.write_text(load_icon_svg(UPDATER_STATE_ICONS[state]), encoding="utf-8")
    except OSError as exc:
        return UpdaterInstallResult(False, "error", f"Updater autostart install failed: {exc}", paths)
    return UpdaterInstallResult(True, "ok", f"Installed AuraScan Updater autostart at {paths.autostart_desktop}.", paths)


def remove_updater_autostart(*, paths: Optional[UpdaterDesktopPaths] = None) -> UpdaterInstallResult:
    paths = paths or updater_desktop_paths()
    try:
        paths.autostart_desktop.unlink(missing_ok=True)
    except OSError as exc:
        return UpdaterInstallResult(False, "error", f"Updater autostart removal failed: {exc}", paths)
    return UpdaterInstallResult(True, "ok", f"Removed AuraScan Updater autostart entry at {paths.autostart_desktop}.", paths)


def render_desktop_entry(*, autostart: bool) -> str:
    lines = [
        "[Desktop Entry]",
        "Type=Application",
        "Name=AuraScan Updater",
        "Comment=Guarded package upgrades with AuraScan",
        "Exec=aurascan updater",
        f"Icon={UPDATER_ICON_NAME}",
        "Terminal=false",
        "Categories=System;Utility;",
        "Keywords=aurascan;upgrade;updates;pacman;aur;cachyos;",
    ]
    if autostart:
        lines.append("X-GNOME-Autostart-enabled=true")
    return "\n".join(lines) + "\n"


def load_icon_svg(icon_name: str = UPDATER_ICON_NAME) -> str:
    icon_path = ASSET_DIR / f"{icon_name}.svg"
    try:
        return icon_path.read_text(encoding="utf-8")
    except OSError:
        return FALLBACK_ICON_SVG


def _safe_read_env(path: Path) -> Dict[str, str]:
    if not path.exists():
        return {}
    try:
        return read_env_file(path)
    except OSError:
        return {}


def find_qt_binding() -> str:
    for binding in ("PyQt6", "PySide6"):
        if importlib.util.find_spec(binding) is not None:
            return binding
    return ""


def build_updater_status(
    *,
    env: Optional[Mapping[str, str]] = None,
    paths: Optional[UpdaterDesktopPaths] = None,
    which: Callable[[str], Optional[str]] = shutil.which,
    qt_binding_finder: Optional[Callable[[], str]] = None,
) -> UpdaterStatus:
    source = env if env is not None else os.environ
    config = resolve_updater_config(source)
    paths = paths or updater_desktop_paths(env=source)
    terminal = build_terminal_invocation(["aurascan", "doctor"], terminal=config.terminal if not config.error else "auto", which=which)
    qt_binding = (qt_binding_finder or find_qt_binding)()
    terminal_path = terminal.command[0] if terminal.command else ""
    return UpdaterStatus(
        config=config,
        paths=paths,
        qt_binding=qt_binding,
        terminal=terminal.terminal,
        terminal_path=terminal_path,
        app_desktop_installed=paths.app_desktop.exists(),
        autostart_installed=paths.autostart_desktop.exists(),
        icon_installed=paths.icon.exists(),
        state_icons_installed=all(path.exists() for path in paths.state_icons.values()),
    )


def build_terminal_invocation(
    command: Sequence[str],
    *,
    terminal: str = "auto",
    which: Callable[[str], Optional[str]] = shutil.which,
) -> TerminalInvocation:
    selected = resolve_terminal(terminal, which=which)
    if not selected:
        return TerminalInvocation(error="No supported terminal emulator found.")
    terminal_name, terminal_path = selected
    cmd = list(command)
    if terminal_name == "xdg-terminal-exec":
        return TerminalInvocation(terminal_name, [terminal_path, "sh", "-lc", pause_shell_script(cmd)])
    if terminal_name == "konsole":
        return TerminalInvocation(terminal_name, [terminal_path, "--hold", "-e", *cmd])
    if terminal_name == "alacritty":
        return TerminalInvocation(terminal_name, [terminal_path, "--hold", "-e", *cmd])
    if terminal_name == "kitty":
        return TerminalInvocation(terminal_name, [terminal_path, "--hold", *cmd])
    if terminal_name == "gnome-terminal":
        return TerminalInvocation(terminal_name, [terminal_path, "--", "sh", "-lc", pause_shell_script(cmd)])
    if terminal_name == "xterm":
        return TerminalInvocation(terminal_name, [terminal_path, "-hold", "-e", *cmd])
    return TerminalInvocation(terminal_name, [terminal_path, "-e", "sh", "-lc", pause_shell_script(cmd)])


def resolve_terminal(terminal: str, *, which: Callable[[str], Optional[str]] = shutil.which) -> Optional[tuple]:
    if terminal != "auto":
        path = which(terminal)
        return (terminal, path) if path else None
    for candidate in UPDATER_TERMINAL_ORDER:
        path = which(candidate)
        if path:
            return candidate, path
    return None


def pause_shell_script(command: Sequence[str]) -> str:
    quoted = shlex.join(list(command))
    return f'{quoted}; status=$?; echo; printf "Press Enter to close AuraScan Updater..."; read -r _; exit "$status"'


def launch_terminal(
    command: Sequence[str],
    *,
    terminal: str = "auto",
    which: Callable[[str], Optional[str]] = shutil.which,
    popen: Callable = subprocess.Popen,
) -> TerminalInvocation:
    invocation = build_terminal_invocation(command, terminal=terminal, which=which)
    if invocation.error:
        return invocation
    popen(invocation.command)
    return invocation


def start_tray_app(
    *,
    env: Optional[Mapping[str, str]] = None,
    which: Callable[[str], Optional[str]] = shutil.which,
    popen: Callable = subprocess.Popen,
    stderr=None,
    incident_marker_root: Path = INCIDENT_MONITOR_MARKER_ROOT,
    incident_seen_path: Optional[Path] = None,
    incident_reviewed_path: Optional[Path] = None,
    maintenance_status_path: Path = INCIDENT_MAINTENANCE_STATUS,
) -> int:
    stderr = stderr or sys.stderr
    config = resolve_updater_config(env)
    if config.error:
        print(f"[AuraScan] Updater configuration error: {config.error}", file=stderr)
        return 1
    try:
        QtCore, QtWidgets, QtGui = load_qt_modules()
    except ImportError as exc:
        print(f"[AuraScan] AuraScan Updater requires PyQt6 or PySide6: {exc}", file=stderr)
        return 1

    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication(sys.argv[:1])
    if not QtWidgets.QSystemTrayIcon.isSystemTrayAvailable():
        print("[AuraScan] No system tray/status notifier area is available in this desktop session.", file=stderr)
        return 1
    app.setQuitOnLastWindowClosed(False)

    tray = QtWidgets.QSystemTrayIcon()
    tray.setIcon(load_state_icon(QtGui, "normal"))
    tray.setToolTip(UPDATER_TOOLTIP)

    menu = QtWidgets.QMenu()

    def add_action(label: str, command: Sequence[str]):
        action = menu.addAction(label)
        action.triggered.connect(lambda _checked=False, cmd=list(command): launch_terminal(cmd, terminal=config.terminal, which=which, popen=popen))
        return action

    for group_index, group in enumerate(UPDATER_MENU_GROUPS):
        if group_index:
            menu.addSeparator()
        for label, command in group:
            add_action(label, command)
    menu.addSeparator()
    quit_action = menu.addAction("Quit")
    quit_action.triggered.connect(app.quit)
    tray.setContextMenu(menu)
    tray.activated.connect(lambda reason: _handle_tray_activation(reason, tray, config.terminal, which, popen))
    tray.messageClicked.connect(
        lambda: launch_terminal(INCIDENT_REVIEW_COMMAND, terminal=config.terminal, which=which, popen=popen)
    )
    tray.show()
    seen_path = incident_seen_path or incident_seen_state_path(env)
    reviewed_path = incident_reviewed_path or incident_reviewed_state_path(env)

    def refresh_incident_state() -> None:
        state = resolve_tray_incident_state(
            marker_root=incident_marker_root,
            notification_seen_path=seen_path,
            reviewed_path=reviewed_path,
            maintenance_status_path=maintenance_status_path,
        )
        tray.setIcon(load_state_icon(QtGui, state.state))
        tray.setToolTip(state.tooltip)
        if state.notification_markers:
            title, message = build_incident_notification(state.notification_markers)
            tray.showMessage(title, message)
        mark_pending_markers_seen(state.unseen_notification_markers, seen_path=seen_path)

    refresh_incident_state()
    refresh_timer = QtCore.QTimer(tray)
    refresh_timer.timeout.connect(refresh_incident_state)
    refresh_timer.start(UPDATER_INCIDENT_REFRESH_MS)
    return int(app.exec())


def load_qt_modules():
    try:
        from PyQt6 import QtCore, QtGui, QtWidgets

        return QtCore, QtWidgets, QtGui
    except ImportError:
        from PySide6 import QtCore, QtGui, QtWidgets

        return QtCore, QtWidgets, QtGui


def load_state_icon(QtGui, state: str):
    state = state if state in UPDATER_STATE_ICONS else "normal"
    icon_name = UPDATER_STATE_ICONS[state]
    icon = QtGui.QIcon.fromTheme(icon_name)
    if icon.isNull():
        asset = ASSET_DIR / f"{icon_name}.svg"
        if asset.exists():
            icon = QtGui.QIcon(str(asset))
    if icon.isNull():
        fallback = {
            "normal": "system-software-update",
            "due": "view-refresh",
            "attention": "dialog-warning",
            "critical": "dialog-error",
        }[state]
        icon = QtGui.QIcon.fromTheme(fallback)
    return icon


def _handle_tray_activation(reason, tray, terminal: str, which: Callable, popen: Callable) -> None:
    activation = type(tray).ActivationReason
    if reason == activation.DoubleClick:
        launch_terminal(["aurascan", "upgrade"], terminal=terminal, which=which, popen=popen)


def resolve_tray_incident_state(
    *,
    marker_root: Path = INCIDENT_MONITOR_MARKER_ROOT,
    notification_seen_path: Optional[Path] = None,
    reviewed_path: Optional[Path] = None,
    maintenance_status_path: Path = INCIDENT_MAINTENANCE_STATUS,
    uid: Optional[int] = None,
    now_usec: Optional[int] = None,
) -> TrayIncidentState:
    notification_seen_path = notification_seen_path or incident_seen_state_path()
    reviewed_path = reviewed_path or incident_reviewed_state_path()
    all_markers = pending_markers(uid=uid, root=marker_root)
    reviewed_keys = read_marker_keys(reviewed_path)
    unreviewed = [marker for marker in all_markers if marker_identity(marker) not in reviewed_keys]
    unseen_notifications = unseen_pending_markers(
        uid=uid,
        marker_root=marker_root,
        seen_path=notification_seen_path,
    )
    notification_markers = [marker for marker in unseen_notifications if marker_needs_notification(marker)]
    severity_rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    highest = max((severity_rank.get(str(marker.get("severity") or "LOW").upper(), 0) for marker in unreviewed), default=0)
    repeated = any(bool(marker.get("repeated")) for marker in unreviewed)
    maintenance = load_maintenance_status(maintenance_status_path, now_usec=now_usec)
    if highest >= severity_rank["HIGH"]:
        state = "critical"
        tooltip = "AuraScan Updater - urgent system findings need resolution"
    elif highest >= severity_rank["MEDIUM"] or repeated:
        state = "attention"
        tooltip = "AuraScan Updater - system findings are ready to resolve"
    elif maintenance.get("overdue"):
        state = "due"
        tooltip = "AuraScan Updater - weekly system maintenance is due"
    else:
        state = "normal"
        tooltip = UPDATER_TOOLTIP
    return TrayIncidentState(
        state=state,
        icon_name=UPDATER_STATE_ICONS[state],
        tooltip=tooltip,
        unreviewed_markers=unreviewed,
        unseen_notification_markers=unseen_notifications,
        notification_markers=notification_markers,
    )


def read_marker_keys(path: Path) -> set:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    return {str(item) for item in data} if isinstance(data, list) else set()


def marker_identity(marker: Mapping[str, object]) -> str:
    marker_type = marker.get("marker_type") or "boot_incident"
    boot = marker.get("boot_id") or marker.get("target_boot") or marker.get("incident_id")
    scan = marker.get("scan_id") or ""
    scope = marker.get("uid_scope") or marker.get("scope")
    generation = scan if marker_type == "maintenance" and scan else boot
    return f"{marker_type}:{generation}:{scope}"


def marker_needs_notification(marker: Mapping[str, object]) -> bool:
    severity = str(marker.get("severity") or "LOW").upper()
    return severity in {"HIGH", "CRITICAL"} or bool(marker.get("repeated"))


def build_incident_notification(markers: Sequence[Mapping[str, object]]) -> tuple:
    boot_ids = {
        str(marker.get("boot_id") or marker.get("target_boot") or marker.get("incident_id") or "")
        for marker in markers
    }
    boot_ids.discard("")
    event_count = sum(max(1, int(marker.get("count") or 1)) for marker in markers)
    boot_count = len(boot_ids) or 1
    maintenance_only = bool(markers) and all(str(marker.get("marker_type") or "") == "maintenance" for marker in markers)
    title = "AuraScan maintenance found system issues" if maintenance_only else "AuraScan found crash evidence"
    if maintenance_only:
        message = f"AuraScan recorded {event_count} maintenance finding(s). Click to resolve or acknowledge them."
    elif boot_count == 1:
        message = f"AuraScan recorded {event_count} incident event(s). Click to resolve or acknowledge them."
    else:
        message = f"AuraScan recorded {event_count} incident event(s) across {boot_count} boots. Click to resolve them in one guided flow."
    return title, message


FALLBACK_ICON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">
  <circle cx="32" cy="32" r="28" fill="#2563eb"/>
  <path d="M32 10 52 20v13c0 13-8 22-20 27-12-5-20-14-20-27V20z" fill="#0f172a" opacity=".28"/>
  <path d="M32 13 49 22v10c0 11-6 19-17 24-11-5-17-13-17-24V22z" fill="#f8fafc"/>
  <path d="M23 34h18M32 25v18" stroke="#2563eb" stroke-width="5" stroke-linecap="round"/>
</svg>
"""
