import argparse
import importlib.util
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


UPDATER_TRAY_ENABLED_ENV = "AURASCAN_UPDATER_TRAY_ENABLED"
UPDATER_AUTOSTART_ENV = "AURASCAN_UPDATER_AUTOSTART"
UPDATER_TERMINAL_ENV = "AURASCAN_UPDATER_TERMINAL"
UPDATER_TERMINALS = {"auto", "xdg-terminal-exec", "konsole", "alacritty", "kitty", "gnome-terminal", "xterm"}
UPDATER_APP_ID = "aurascan-updater"
UPDATER_DESKTOP_NAME = f"{UPDATER_APP_ID}.desktop"
UPDATER_ICON_NAME = UPDATER_APP_ID
UPDATER_TOOLTIP = "AuraScan Updater - guarded package upgrades"
UPDATER_TERMINAL_ORDER = ["xdg-terminal-exec", "konsole", "alacritty", "kitty", "gnome-terminal", "xterm"]
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
class UpdaterDesktopPaths:
    app_desktop: Path
    autostart_desktop: Path
    icon: Path


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


def load_icon_svg() -> str:
    icon_path = ASSET_DIR / f"{UPDATER_ICON_NAME}.svg"
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
) -> int:
    stderr = stderr or sys.stderr
    config = resolve_updater_config(env)
    if config.error:
        print(f"[AuraScan] Updater configuration error: {config.error}", file=stderr)
        return 1
    try:
        QtWidgets, QtGui = load_qt_modules()
    except ImportError as exc:
        print(f"[AuraScan] AuraScan Updater requires PyQt6 or PySide6: {exc}", file=stderr)
        return 1

    app = QtWidgets.QApplication.instance() or QtWidgets.QApplication(sys.argv[:1])
    if not QtWidgets.QSystemTrayIcon.isSystemTrayAvailable():
        print("[AuraScan] No system tray/status notifier area is available in this desktop session.", file=stderr)
        return 1
    app.setQuitOnLastWindowClosed(False)

    tray = QtWidgets.QSystemTrayIcon()
    icon = QtGui.QIcon.fromTheme(UPDATER_ICON_NAME)
    if icon.isNull():
        icon = QtGui.QIcon.fromTheme("system-software-update")
    tray.setIcon(icon)
    tray.setToolTip(UPDATER_TOOLTIP)

    menu = QtWidgets.QMenu()

    def add_action(label: str, command: Sequence[str]):
        action = menu.addAction(label)
        action.triggered.connect(lambda _checked=False, cmd=list(command): launch_terminal(cmd, terminal=config.terminal, which=which, popen=popen))
        return action

    add_action("Run AuraScan Upgrade", ["aurascan", "upgrade"])
    add_action("Dry-run Preflight", ["aurascan", "upgrade", "--dry-run"])
    add_action("Config Drift Assistant", ["aurascan", "config-drift"])
    add_action("AuraScan Doctor", ["aurascan", "doctor"])
    add_action("AuraScan Settings", ["aurascan", "init"])
    menu.addSeparator()
    quit_action = menu.addAction("Quit")
    quit_action.triggered.connect(app.quit)
    tray.setContextMenu(menu)
    tray.activated.connect(lambda reason: _handle_tray_activation(reason, tray, config.terminal, which, popen))
    tray.show()
    return int(app.exec())


def load_qt_modules():
    try:
        from PyQt6 import QtGui, QtWidgets

        return QtWidgets, QtGui
    except ImportError:
        from PySide6 import QtGui, QtWidgets

        return QtWidgets, QtGui


def _handle_tray_activation(reason, tray, terminal: str, which: Callable, popen: Callable) -> None:
    activation = type(tray).ActivationReason
    if reason == activation.DoubleClick:
        launch_terminal(["aurascan", "upgrade"], terminal=terminal, which=which, popen=popen)


FALLBACK_ICON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64" viewBox="0 0 64 64">
  <circle cx="32" cy="32" r="28" fill="#2563eb"/>
  <path d="M32 10 52 20v13c0 13-8 22-20 27-12-5-20-14-20-27V20z" fill="#0f172a" opacity=".28"/>
  <path d="M32 13 49 22v10c0 11-6 19-17 24-11-5-17-13-17-24V22z" fill="#f8fafc"/>
  <path d="M23 34h18M32 25v18" stroke="#2563eb" stroke-width="5" stroke-linecap="round"/>
</svg>
"""
