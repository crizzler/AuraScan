import configparser
import hashlib
import os
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Mapping, Optional, Sequence, Tuple


RECOVERY_NETWORK_RUNTIME = Path("/run/aurascan-recovery/network")
SUPPORTED_WIFI_SECURITY = {"open", "wpa2", "wpa3"}
UNSUPPORTED_WIFI_SECURITY = {"802.1x", "enterprise"}


def _network_token(value: str) -> str:
    if not value:
        return ""
    if re.fullmatch(r"network-[0-9a-f]{12}", value):
        return value
    digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]
    return f"network-{digest}"


@dataclass
class RecoveryNetworkState:
    available: bool = False
    connected: bool = False
    connectivity: str = "unknown"
    connection_type: str = ""
    connection_name: str = ""
    captive_portal: bool = False
    imported_profiles: int = 0
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "available": self.available,
            "connected": self.connected,
            "connectivity": self.connectivity,
            "connection_type": self.connection_type,
            "connection_name": _network_token(self.connection_name),
            "captive_portal": self.captive_portal,
            "imported_profiles": self.imported_profiles,
            "notes": list(self.notes),
        }


@dataclass
class WifiNetwork:
    ssid: str
    signal: int = 0
    security: str = "open"
    hidden: bool = False
    supported: bool = True

    def to_dict(self) -> Dict[str, object]:
        return {
            "ssid": "<hidden>" if self.hidden else _network_token(self.ssid),
            "signal": self.signal,
            "security": self.security,
            "hidden": self.hidden,
            "supported": self.supported,
        }


def _run(
    runner: Callable,
    command: Sequence[str],
    *,
    timeout: int = 30,
    input_text: Optional[str] = None,
):
    return runner(
        list(command),
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        input=input_text,
    )


def start_network_manager(
    *,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
) -> Tuple[bool, str]:
    if not which("nmcli"):
        return False, "NetworkManager command line tools are unavailable."
    systemctl = which("systemctl")
    if not systemctl:
        return False, "systemctl is unavailable; NetworkManager could not be started."
    result = _run(runner, [systemctl, "start", "NetworkManager.service"], timeout=45)
    if result.returncode != 0:
        return False, "NetworkManager did not start successfully."
    return True, "NetworkManager is ready."


def detect_network_state(
    *,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
) -> RecoveryNetworkState:
    state = RecoveryNetworkState(available=bool(which("nmcli")))
    if not state.available:
        state.notes.append("NetworkManager is unavailable; offline recovery remains available.")
        return state
    general = _run(runner, ["nmcli", "-t", "-f", "STATE,CONNECTIVITY", "general"], timeout=15)
    if general.returncode == 0:
        fields = general.stdout.strip().split(":", 1)
        nm_state = fields[0].strip().lower() if fields else ""
        state.connectivity = fields[1].strip().lower() if len(fields) > 1 else "unknown"
        state.connected = nm_state in {"connected", "connected (global)"} and state.connectivity in {"full", "limited"}
        state.captive_portal = state.connectivity in {"portal", "limited"}
    active = _run(runner, ["nmcli", "-t", "-f", "TYPE,NAME", "connection", "show", "--active"], timeout=15)
    if active.returncode == 0:
        for line in active.stdout.splitlines():
            kind, separator, name = line.partition(":")
            if separator and kind in {"ethernet", "wifi", "gsm", "bridge", "tun"}:
                state.connection_type = kind
                state.connection_name = name[:120]
                break
    if state.captive_portal:
        state.notes.append("A captive portal or limited connection was detected; AI access is not assumed.")
    elif state.connected:
        state.notes.append("A usable network connection was detected.")
    else:
        state.notes.append("No usable network connection is active; deterministic recovery remains available.")
    return state


def normalize_wifi_security(raw: str) -> str:
    lowered = raw.strip().lower()
    if not lowered or lowered == "--":
        return "open"
    if "802.1x" in lowered or "enterprise" in lowered or "eap" in lowered:
        return "enterprise"
    if "wpa3" in lowered or "sae" in lowered:
        return "wpa3"
    if "wpa" in lowered or "rsn" in lowered:
        return "wpa2"
    return "unsupported"


def scan_wifi_networks(
    *,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
) -> List[WifiNetwork]:
    if not which("nmcli"):
        return []
    result = _run(
        runner,
        ["nmcli", "--escape", "yes", "-t", "-f", "SSID,SIGNAL,SECURITY", "device", "wifi", "list", "--rescan", "yes"],
        timeout=30,
    )
    if result.returncode != 0:
        return []
    networks: Dict[str, WifiNetwork] = {}
    for raw_line in result.stdout.splitlines():
        parts = re.split(r"(?<!\\):", raw_line, maxsplit=2)
        if len(parts) != 3:
            continue
        ssid = parts[0].replace("\\:", ":").replace("\\\\", "\\")
        hidden = not bool(ssid)
        label = ssid or "<hidden>"
        try:
            signal = min(100, max(0, int(parts[1])))
        except ValueError:
            signal = 0
        security = normalize_wifi_security(parts[2])
        item = WifiNetwork(label[:128], signal, security, hidden, security in SUPPORTED_WIFI_SECURITY)
        previous = networks.get(label)
        if previous is None or item.signal > previous.signal:
            networks[label] = item
    return sorted(networks.values(), key=lambda item: (-item.signal, item.ssid.casefold()))


def validate_wifi_profile(
    path: Path,
    *,
    required_uid: int = 0,
) -> Tuple[bool, str]:
    try:
        metadata = path.lstat()
    except OSError as exc:
        return False, f"profile could not be inspected: {exc}"
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        return False, "profile is not a regular non-symlink file"
    if metadata.st_uid != required_uid:
        return False, "profile is not owned by root"
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        return False, "profile permissions are not 0600"
    try:
        if metadata.st_size <= 0 or metadata.st_size > 128 * 1024:
            return False, "profile size is outside the recovery bound"
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return False, f"profile could not be read: {exc}"
    if "[connection]" not in text or "type=wifi" not in text:
        return False, "profile is not a NetworkManager Wi-Fi connection"
    return True, "validated"


def discover_saved_wifi_profiles(
    target_root: Path,
    *,
    required_uid: int = 0,
) -> Tuple[List[Path], List[str]]:
    profile_root = target_root / "etc/NetworkManager/system-connections"
    profiles: List[Path] = []
    notes: List[str] = []
    try:
        root_metadata = profile_root.lstat()
        if profile_root.is_symlink() or not stat.S_ISDIR(root_metadata.st_mode):
            return [], ["Ignored saved Wi-Fi directory because it is not a regular target directory."]
        profile_root.resolve(strict=False).relative_to(target_root.resolve(strict=False))
        candidates = sorted(profile_root.iterdir())[:100]
    except (OSError, ValueError):
        return [], []
    for path in candidates:
        try:
            path.resolve(strict=False).relative_to(profile_root.resolve(strict=False))
        except (OSError, ValueError):
            notes.append("Ignored one saved Wi-Fi profile because it escaped the mounted target.")
            continue
        valid, reason = validate_wifi_profile(path, required_uid=required_uid)
        if valid:
            profiles.append(path)
        else:
            notes.append(f"Ignored one saved Wi-Fi profile: {reason}.")
    return profiles, notes


def import_saved_wifi_profiles(
    target_root: Path,
    *,
    runtime_root: Path = RECOVERY_NETWORK_RUNTIME,
    required_uid: int = 0,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
) -> Tuple[int, List[str]]:
    if not which("nmcli"):
        return 0, ["NetworkManager is unavailable; saved Wi-Fi profiles were not imported."]
    profiles, notes = discover_saved_wifi_profiles(target_root, required_uid=required_uid)
    try:
        if runtime_root.exists():
            metadata = runtime_root.lstat()
            if runtime_root.is_symlink() or not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid():
                return 0, notes + ["Volatile network profile directory failed owner or path validation."]
        else:
            runtime_root.mkdir(parents=True, mode=0o700)
        os.chmod(runtime_root, 0o700)
    except OSError:
        return 0, notes + ["Volatile network profile directory could not be prepared safely."]
    imported = 0
    for profile in profiles:
        destination = runtime_root / f"profile-{imported + 1}.nmconnection"
        fd, temporary = tempfile.mkstemp(prefix=".wifi.", dir=str(runtime_root))
        try:
            with os.fdopen(fd, "wb") as output, profile.open("rb") as source:
                shutil.copyfileobj(source, output, length=64 * 1024)
                output.flush()
                os.fsync(output.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, destination)
            result = _run(runner, ["nmcli", "connection", "load", str(destination)], timeout=20)
            if result.returncode == 0:
                imported += 1
                parser = configparser.ConfigParser(interpolation=None)
                try:
                    parser.read(destination, encoding="utf-8")
                    connection_uuid = parser.get("connection", "uuid", fallback="").strip()
                    connection_id = parser.get("connection", "id", fallback="").strip()
                except (configparser.Error, OSError):
                    connection_uuid = ""
                    connection_id = ""
                if re.fullmatch(r"[0-9A-Fa-f-]{32,36}", connection_uuid):
                    activation = _run(runner, ["nmcli", "--wait", "30", "connection", "up", "uuid", connection_uuid], timeout=45)
                elif connection_id and len(connection_id) <= 128 and "\n" not in connection_id and "\r" not in connection_id:
                    activation = _run(runner, ["nmcli", "--wait", "30", "connection", "up", "id", connection_id], timeout=45)
                else:
                    activation = None
                if activation is not None and activation.returncode != 0:
                    notes.append("A saved Wi-Fi profile was loaded but did not connect.")
            else:
                destination.unlink(missing_ok=True)
                notes.append("NetworkManager declined one saved Wi-Fi profile.")
        except OSError:
            notes.append("A saved Wi-Fi profile could not be staged in volatile memory.")
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    return imported, notes


def connect_wifi(
    ssid: str,
    *,
    hidden: bool = False,
    password_func: Optional[Callable[[str], str]] = None,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
) -> Tuple[bool, str]:
    if not which("nmcli"):
        return False, "NetworkManager is unavailable."
    clean_ssid = ssid.strip()
    if not clean_ssid or len(clean_ssid) > 128 or "\n" in clean_ssid or "\r" in clean_ssid:
        return False, "Wi-Fi network name is invalid."
    password = password_func("Wi-Fi password (input hidden): ") if password_func else ""
    command = ["nmcli", "--ask", "device", "wifi", "connect", clean_ssid]
    if hidden:
        command.extend(["hidden", "yes"])
    # nmcli acts as the NetworkManager SecretAgent. Secrets travel over stdin,
    # never argv, and are not returned in AuraScan output.
    result = _run(runner, command, timeout=60, input_text=(password + "\n") if password else None)
    password = ""
    if result.returncode != 0:
        return False, "NetworkManager could not connect to the selected network."
    return True, "Wi-Fi connection established."
