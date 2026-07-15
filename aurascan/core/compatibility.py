import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Mapping, Optional


ARCH_FAMILY_TOOLS = ("pacman", "pacman-conf", "makepkg", "vercmp", "paru", "yay", "shelly")
SUPPORTED_DISTROS = {"arch", "endeavouros", "manjaro", "cachyos"}


@dataclass
class DistroInfo:
    distro_id: str = "unknown"
    name: str = "Unknown"
    id_like: List[str] = field(default_factory=list)
    family: str = "unknown"
    support_tier: str = "best_effort"
    caveat: str = ""

    @property
    def arch_family(self) -> bool:
        return self.family in {"arch", "arch_like"} or self.distro_id in SUPPORTED_DISTROS

    def to_dict(self) -> Dict[str, object]:
        return {
            "id": self.distro_id,
            "name": self.name,
            "id_like": list(self.id_like),
            "family": self.family,
            "support_tier": self.support_tier,
            "arch_family": self.arch_family,
            "caveat": self.caveat,
        }


@dataclass
class DesktopSessionInfo:
    session_type: str = ""
    current_desktop: str = ""
    desktop_session: str = ""
    primary_desktop: str = "unknown"
    tray_support: str = "unknown"
    caveat: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "session_type": self.session_type,
            "current_desktop": self.current_desktop,
            "desktop_session": self.desktop_session,
            "primary_desktop": self.primary_desktop,
            "tray_support": self.tray_support,
            "caveat": self.caveat,
        }


@dataclass
class PackageManagerCapabilities:
    tools: Dict[str, str] = field(default_factory=dict)

    def found(self, tool: str) -> bool:
        return bool(self.tools.get(tool))

    def to_dict(self) -> Dict[str, object]:
        return {
            "tools": dict(self.tools),
            "found": sorted(name for name, path in self.tools.items() if path),
            "missing": sorted(name for name, path in self.tools.items() if not path),
        }


def parse_os_release(text: str) -> Dict[str, str]:
    values: Dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key.strip()] = value
    return values


def distro_from_os_release(values: Mapping[str, str]) -> DistroInfo:
    distro_id = values.get("ID", "unknown").strip().lower() or "unknown"
    name = values.get("NAME", distro_id).strip() or distro_id
    id_like = [item.strip().lower() for item in values.get("ID_LIKE", "").split() if item.strip()]

    if distro_id == "arch":
        return DistroInfo(distro_id=distro_id, name=name, id_like=id_like, family="arch", support_tier="supported")
    if distro_id == "endeavouros":
        return DistroInfo(distro_id=distro_id, name=name, id_like=id_like, family="arch", support_tier="supported")
    if distro_id == "cachyos":
        return DistroInfo(distro_id=distro_id, name=name, id_like=id_like, family="arch", support_tier="supported")
    if distro_id == "manjaro":
        return DistroInfo(
            distro_id=distro_id,
            name=name,
            id_like=id_like,
            family="arch",
            support_tier="supported_with_caveats",
            caveat="Manjaro delays repository updates compared with Arch, so AUR compatibility and mirror timing can differ.",
        )
    if "arch" in id_like:
        return DistroInfo(
            distro_id=distro_id,
            name=name,
            id_like=id_like,
            family="arch_like",
            support_tier="best_effort",
            caveat="Unknown Arch-like distribution; AuraScan uses generic pacman behavior with conservative guidance.",
        )
    return DistroInfo(
        distro_id=distro_id,
        name=name,
        id_like=id_like,
        family="unknown",
        support_tier="unsupported",
        caveat="AuraScan is designed for Arch-family systems.",
    )


def detect_distro(os_release_path: Path = Path("/etc/os-release")) -> DistroInfo:
    try:
        return distro_from_os_release(parse_os_release(os_release_path.read_text(encoding="utf-8", errors="replace")))
    except OSError:
        return DistroInfo(caveat="Could not read /etc/os-release.")


def detect_package_manager_capabilities(which: Callable[[str], Optional[str]] = shutil.which) -> PackageManagerCapabilities:
    return PackageManagerCapabilities({tool: which(tool) or "" for tool in ARCH_FAMILY_TOOLS})


def detect_desktop_session(env: Optional[Mapping[str, str]] = None) -> DesktopSessionInfo:
    source = os.environ if env is None else env
    session_type = source.get("XDG_SESSION_TYPE", "").strip().lower()
    current = source.get("XDG_CURRENT_DESKTOP", "").strip()
    desktop_session = source.get("DESKTOP_SESSION", "").strip()
    lowered = ":".join([current, desktop_session]).lower()

    if "kde" in lowered or "plasma" in lowered:
        return DesktopSessionInfo(session_type, current, desktop_session, "kde", "best", "KDE Plasma X11/Wayland is the best-supported tray target.")
    if "gnome" in lowered:
        return DesktopSessionInfo(session_type, current, desktop_session, "gnome", "extension_required", "GNOME may require AppIndicator/status-notifier support for tray icon visibility.")
    if "xfce" in lowered:
        return DesktopSessionInfo(session_type, current, desktop_session, "xfce", "expected", "XFCE is expected to work when its panel tray/status-notifier plugin is enabled.")
    if "cinnamon" in lowered:
        return DesktopSessionInfo(session_type, current, desktop_session, "cinnamon", "expected", "Cinnamon is expected to work when tray/status-notifier support is enabled.")
    if "mate" in lowered:
        return DesktopSessionInfo(session_type, current, desktop_session, "mate", "expected", "MATE is expected to work when tray/status-notifier support is enabled.")
    if "lxqt" in lowered:
        return DesktopSessionInfo(session_type, current, desktop_session, "lxqt", "expected", "LXQt is expected to work when tray/status-notifier support is enabled.")
    if "budgie" in lowered:
        return DesktopSessionInfo(session_type, current, desktop_session, "budgie", "expected", "Budgie is expected to work when tray/status-notifier support is enabled.")
    if any(name in lowered for name in ("sway", "i3", "hyprland", "wayfire")):
        return DesktopSessionInfo(session_type, current, desktop_session, "tiling", "manual_tray_host", "Tiling sessions need a tray/status-notifier host such as waybar or another panel.")
    return DesktopSessionInfo(session_type, current, desktop_session, "unknown", "unknown", "Desktop tray support could not be identified; CLI workflows remain supported.")
