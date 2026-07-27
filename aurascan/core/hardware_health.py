import csv
import json
import os
import re
import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Mapping, Optional, Sequence, Tuple


HARDWARE_HEALTH_SCHEMA_VERSION = "1.0"
HARDWARE_HEALTH_REPORT_TYPE = "hardware_health"
HARDWARE_HEALTH_PROBE_ID = "fup-hardware-health"
HARDWARE_MAX_COMMAND_CHARS = 64 * 1024
HARDWARE_MAX_SENSORS = 64
HARDWARE_MAX_GPUS = 8
HARDWARE_MAX_ERROR_CATEGORIES = 12
INTEL_VMIN_GUIDANCE_URL = (
    "https://www.intel.com/content/www/us/en/support/articles/000102331/processors.html"
)
INTEL_VMIN_MINIMUM_MICROCODE = 0x12F

HARDWARE_QUESTION_RE = re.compile(
    r"(?i)\b(?:"
    r"hardware|cpu|processor|microcode|gpu|graphics|nvidia|radeon|amdgpu|"
    r"memory|ram|dimm|ddr[345]?|xmp|expo|timings?|motherboard|mainboard|"
    r"bios|uefi|firmware|temperature|thermal|overheat(?:ing)?|cooling|fans?|"
    r"voltage|power supply|psu|machine check|mce|edac|oom|out[ -]of[ -]memory"
    r")\b"
)
CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


@dataclass
class HardwareCommandOutput:
    returncode: int
    stdout: str = ""
    stderr: str = ""
    truncated: bool = False


@dataclass
class HardwareHealthReport:
    inventory: Dict[str, object] = field(default_factory=dict)
    memory: Dict[str, object] = field(default_factory=dict)
    gpus: List[Dict[str, object]] = field(default_factory=list)
    sensors: List[Dict[str, object]] = field(default_factory=list)
    memory_pressure: Dict[str, object] = field(default_factory=dict)
    hardware_error_counts: Dict[str, int] = field(default_factory=dict)
    package_updates: List[Dict[str, object]] = field(default_factory=list)
    firmware: Dict[str, object] = field(default_factory=dict)
    advisories: List[Dict[str, object]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    status: str = "ok"
    collected_at: int = field(default_factory=lambda: int(time.time()))

    @property
    def summary(self) -> str:
        cpu = str(self.inventory.get("cpu_model") or "unknown CPU")
        memory_mib = int(self.memory.get("total_mib") or 0)
        memory_text = f"{memory_mib / 1024:.1f} GiB RAM" if memory_mib else "RAM size unavailable"
        gpu_names = [
            str(item.get("name") or item.get("pci_id") or "unknown GPU")
            for item in self.gpus[:2]
        ]
        gpu_text = ", ".join(gpu_names) if gpu_names else "GPU model unavailable"
        bios = str(self.inventory.get("bios_version") or "unknown")
        sensor_alerts = sum(
            1 for item in self.sensors if item.get("status") in {"alarm", "critical", "fault"}
        )
        firmware_status = str(self.firmware.get("status") or "not checked")
        firmware_count = int(self.firmware.get("updates_available") or 0)
        system_firmware_count = int(
            self.firmware.get("system_firmware_updates") or 0
        )
        if firmware_status == "updates_available":
            firmware_text = (
                f"{firmware_count} firmware update(s), "
                f"{system_firmware_count} system-firmware update(s)"
            )
        else:
            firmware_text = firmware_status
        return (
            f"{cpu}; {memory_text}; {gpu_text}; BIOS {bios}; "
            f"{sensor_alerts} sensor alert(s); firmware {firmware_text}."
        )

    def to_dict(self) -> Dict[str, object]:
        return {
            "schema": f"{HARDWARE_HEALTH_REPORT_TYPE}/{HARDWARE_HEALTH_SCHEMA_VERSION}",
            "schema_version": HARDWARE_HEALTH_SCHEMA_VERSION,
            "report_type": HARDWARE_HEALTH_REPORT_TYPE,
            "status": self.status,
            "collected_at": self.collected_at,
            "summary": self.summary,
            "inventory": dict(self.inventory),
            "memory": dict(self.memory),
            "gpus": [dict(item) for item in self.gpus[:HARDWARE_MAX_GPUS]],
            "sensors": [dict(item) for item in self.sensors[:HARDWARE_MAX_SENSORS]],
            "memory_pressure": dict(self.memory_pressure),
            "hardware_error_counts": dict(
                list(self.hardware_error_counts.items())[:HARDWARE_MAX_ERROR_CATEGORIES]
            ),
            "package_updates": [dict(item) for item in self.package_updates[:16]],
            "firmware": dict(self.firmware),
            "advisories": [dict(item) for item in self.advisories[:8]],
            "notes": [str(item)[:500] for item in self.notes[:20]],
        }


def question_requests_hardware_context(question: object) -> bool:
    return bool(HARDWARE_QUESTION_RE.search(str(question or "")))


def _read_text(path: Path, limit: int = 8192) -> str:
    try:
        if not path.is_file():
            return ""
        return path.read_text(encoding="utf-8", errors="replace")[:limit].strip()
    except OSError:
        return ""


def _safe_text(value: object, limit: int = 500) -> str:
    return CONTROL_RE.sub("", str(value or "")).strip()[:limit]


def _run_bounded(
    runner: Callable,
    command: Sequence[str],
    *,
    timeout: int = 15,
    max_chars: int = HARDWARE_MAX_COMMAND_CHARS,
) -> HardwareCommandOutput:
    kwargs = {
        "capture_output": True,
        "text": True,
        "check": False,
        "timeout": timeout,
        "env": {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/bin:/usr/sbin:/bin:/sbin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C",
            "HOME": str(Path.home()),
        },
    }
    try:
        try:
            result = runner(list(command), **kwargs)
        except TypeError:
            kwargs.pop("env", None)
            try:
                result = runner(list(command), **kwargs)
            except TypeError:
                kwargs.pop("timeout", None)
                result = runner(list(command), **kwargs)
    except (OSError, subprocess.SubprocessError) as exc:
        return HardwareCommandOutput(127, "", _safe_text(exc), False)
    stdout = str(getattr(result, "stdout", "") or "")
    stderr = str(getattr(result, "stderr", "") or "")
    truncated = len(stdout) > max_chars or len(stderr) > max_chars
    return HardwareCommandOutput(
        int(getattr(result, "returncode", 0)),
        stdout[:max_chars],
        stderr[:max_chars],
        truncated,
    )


def _parse_cpu_info(path: Path) -> Dict[str, object]:
    text = _read_text(path, 512 * 1024)
    if not text:
        return {}
    records = [item for item in text.split("\n\n") if item.strip()]
    first: Dict[str, str] = {}
    for line in records[0].splitlines() if records else []:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        first[key.strip().lower()] = value.strip()
    return {
        "cpu_model": first.get("model name") or first.get("hardware") or first.get("processor", ""),
        "cpu_vendor": first.get("vendor_id", ""),
        "cpu_family": first.get("cpu family", ""),
        "cpu_model_number": first.get("model", ""),
        "cpu_stepping": first.get("stepping", ""),
        "active_microcode": first.get("microcode", ""),
        "logical_cpus": len(records),
    }


def _parse_meminfo(path: Path) -> Dict[str, object]:
    text = _read_text(path, 64 * 1024)
    values: Dict[str, int] = {}
    for line in text.splitlines():
        match = re.match(r"^([A-Za-z_()]+):\s+(\d+)\s+kB$", line)
        if match:
            values[match.group(1)] = int(match.group(2)) // 1024
    return {
        "total_mib": values.get("MemTotal", 0),
        "available_mib": values.get("MemAvailable", 0),
        "swap_total_mib": values.get("SwapTotal", 0),
        "swap_free_mib": values.get("SwapFree", 0),
    }


def _collect_dmi_inventory(dmi_root: Path) -> Dict[str, object]:
    fields = {
        "system_vendor": "sys_vendor",
        "system_model": "product_name",
        "system_version": "product_version",
        "board_vendor": "board_vendor",
        "board_model": "board_name",
        "board_version": "board_version",
        "bios_vendor": "bios_vendor",
        "bios_version": "bios_version",
        "bios_date": "bios_date",
    }
    return {
        output_key: _safe_text(_read_text(dmi_root / filename), 240)
        for output_key, filename in fields.items()
        if _read_text(dmi_root / filename)
    }


def _size_to_mib(value: str) -> int:
    match = re.search(r"(\d+)\s*(KB|MB|GB|TB)\b", value, re.IGNORECASE)
    if not match:
        return 0
    amount = int(match.group(1))
    unit = match.group(2).upper()
    return {
        "KB": max(1, amount // 1024),
        "MB": amount,
        "GB": amount * 1024,
        "TB": amount * 1024 * 1024,
    }[unit]


def _parse_dmidecode_memory(text: str) -> Dict[str, object]:
    devices = []
    for block in re.split(r"\n\s*\n", text):
        if "Memory Device" not in block:
            continue
        values: Dict[str, str] = {}
        for line in block.splitlines():
            match = re.match(r"^\s*([^:]+):\s*(.*)$", line)
            if match:
                values[match.group(1).strip()] = match.group(2).strip()
        size = values.get("Size", "")
        if not size or "No Module Installed" in size:
            continue
        devices.append({
            "size_mib": _size_to_mib(size),
            "type": _safe_text(values.get("Type", ""), 40),
            "speed": _safe_text(values.get("Speed", ""), 80),
            "configured_speed": _safe_text(
                values.get("Configured Memory Speed", values.get("Configured Clock Speed", "")),
                80,
            ),
        })
    types = sorted({str(item["type"]) for item in devices if item["type"]})
    speeds = sorted({str(item["speed"]) for item in devices if item["speed"]})
    configured = sorted(
        {str(item["configured_speed"]) for item in devices if item["configured_speed"]}
    )
    return {
        "populated_dimms": len(devices),
        "dimm_total_mib": sum(int(item["size_mib"]) for item in devices),
        "dimm_types": types[:8],
        "reported_speeds": speeds[:8],
        "configured_speeds": configured[:8],
        "detailed_timings_status": (
            "not_exposed_by_smbios"
            if devices
            else "unavailable"
        ),
    }


def _memory_quantity_to_mib(value: str) -> int:
    match = re.search(r"(\d+(?:\.\d+)?)\s*(KiB|MiB|GiB|TiB)\b", value, re.IGNORECASE)
    if not match:
        return _size_to_mib(value)
    amount = float(match.group(1))
    unit = match.group(2).lower()
    factor = {
        "kib": 1 / 1024,
        "mib": 1,
        "gib": 1024,
        "tib": 1024 * 1024,
    }[unit]
    return int(round(amount * factor))


def _parse_inxi_memory(text: str) -> Dict[str, object]:
    clean = CONTROL_RE.sub("", text)
    array_match = re.search(
        r"(?im)^\s*Array-\d+:.*?\bslots:\s*(\d+).*?\bmodules:\s*(\d+)",
        clean,
    )
    devices = []
    for line in clean.splitlines():
        if not re.match(r"^\s*Device-\d+:", line):
            continue
        type_match = re.search(r"\btype:\s*([A-Za-z0-9_-]+)", line)
        size_match = re.search(r"\bsize:\s*(\d+(?:\.\d+)?\s*[KMGT]i?B)", line)
        spec_match = re.search(r"\bspec:\s*(\d+(?:\.\d+)?\s*(?:MT/s|MHz))", line)
        actual_match = re.search(r"\bactual:\s*(\d+(?:\.\d+)?\s*(?:MT/s|MHz))", line)
        devices.append({
            "size_mib": _memory_quantity_to_mib(size_match.group(1)) if size_match else 0,
            "type": _safe_text(type_match.group(1), 40) if type_match else "",
            "speed": _safe_text(spec_match.group(1), 80) if spec_match else "",
            "configured_speed": _safe_text(actual_match.group(1), 80) if actual_match else "",
        })
    if not devices and not array_match:
        return {}
    populated = int(array_match.group(2)) if array_match else len(devices)
    return {
        "memory_slots": int(array_match.group(1)) if array_match else 0,
        "populated_dimms": populated,
        "dimm_total_mib": sum(int(item["size_mib"]) for item in devices),
        "dimm_types": sorted({str(item["type"]) for item in devices if item["type"]})[:8],
        "reported_speeds": sorted(
            {str(item["speed"]) for item in devices if item["speed"]}
        )[:8],
        "configured_speeds": sorted(
            {
                str(item["configured_speed"])
                for item in devices
                if item["configured_speed"]
            }
        )[:8],
        "detailed_timings_status": "not_exposed_by_inxi",
    }


def _collect_memory_devices(
    runner: Callable,
    which: Callable[[str], Optional[str]],
) -> Dict[str, object]:
    output = _run_bounded(
        runner,
        ["dmidecode", "--type", "17"],
        timeout=20,
        max_chars=128 * 1024,
    )
    source = "dmidecode"
    if output.returncode != 0 and which("inxi"):
        inxi = _run_bounded(
            runner,
            ["inxi", "--memory", "--filter", "--no-host", "--color", "0"],
            timeout=20,
            max_chars=64 * 1024,
        )
        parsed = _parse_inxi_memory(inxi.stdout) if inxi.returncode == 0 else {}
        if parsed:
            parsed["memory_device_source"] = "inxi"
            return parsed
    if output.returncode != 0 and which("sudo"):
        output = _run_bounded(
            runner,
            ["sudo", "-n", "dmidecode", "--type", "17"],
            timeout=20,
            max_chars=128 * 1024,
        )
        source = "sudo_cached_dmidecode"
    if output.returncode != 0:
        return {
            "detailed_timings_status": "unavailable_without_privileged_smbios_access",
            "memory_device_source": "unavailable",
        }
    parsed = _parse_dmidecode_memory(output.stdout)
    parsed["memory_device_source"] = source
    return parsed


def _lspci_gpu_names(
    runner: Callable,
    which: Callable[[str], Optional[str]],
) -> Dict[str, Dict[str, str]]:
    if not which("lspci"):
        return {}
    output = _run_bounded(runner, ["lspci", "-D", "-mm", "-nn"], timeout=15)
    if output.returncode != 0:
        return {}
    result: Dict[str, Dict[str, str]] = {}
    for raw in output.stdout.splitlines()[:512]:
        try:
            fields = shlex.split(raw)
        except ValueError:
            continue
        if len(fields) < 4 or not fields[1].startswith(
            ("VGA compatible controller", "3D controller", "Display controller")
        ):
            continue
        result[fields[0]] = {
            "name": _safe_text(f"{fields[2]} {fields[3]}", 300),
            "class": fields[1],
        }
    return result


def _collect_gpus(
    *,
    sys_root: Path,
    runner: Callable,
    which: Callable[[str], Optional[str]],
) -> List[Dict[str, object]]:
    names = _lspci_gpu_names(runner, which)
    devices_root = sys_root / "bus" / "pci" / "devices"
    gpus: List[Dict[str, object]] = []
    try:
        devices = sorted(devices_root.iterdir())[:1024]
    except OSError:
        devices = []
    for device in devices:
        class_id = _read_text(device / "class", 64).lower()
        if not class_id.startswith(("0x0300", "0x0302", "0x0380")):
            continue
        slot = device.name
        driver = ""
        try:
            driver = (device / "driver").resolve().name if (device / "driver").exists() else ""
        except OSError:
            driver = ""
        module_version = _read_text(sys_root / "module" / driver / "version", 120) if driver else ""
        named = names.get(slot, {})
        gpus.append({
            "pci_slot": slot,
            "pci_id": (
                _read_text(device / "vendor", 32)
                + ":"
                + _read_text(device / "device", 32)
            ).strip(":"),
            "name": named.get("name", ""),
            "class": named.get("class", ""),
            "driver": driver,
            "module_version": module_version,
        })
        if len(gpus) >= HARDWARE_MAX_GPUS:
            break
    for slot, named in names.items():
        if any(item.get("pci_slot") == slot for item in gpus):
            continue
        gpus.append({
            "pci_slot": slot,
            "name": named.get("name", ""),
            "class": named.get("class", ""),
            "driver": "",
            "module_version": "",
        })
        if len(gpus) >= HARDWARE_MAX_GPUS:
            break
    if which("nvidia-smi"):
        output = _run_bounded(
            runner,
            [
                "nvidia-smi",
                "--query-gpu=name,driver_version,memory.total,temperature.gpu,fan.speed",
                "--format=csv,noheader,nounits",
            ],
            timeout=15,
            max_chars=16 * 1024,
        )
        if output.returncode == 0:
            nvidia_rows = list(csv.reader(output.stdout.splitlines()))[:HARDWARE_MAX_GPUS]
            nvidia_gpus = [
                item for item in gpus
                if "nvidia" in str(item.get("name", "")).lower()
                or item.get("driver") in {"nvidia", "nouveau"}
            ]
            for index, row in enumerate(nvidia_rows):
                if len(row) < 5:
                    continue
                if index >= len(nvidia_gpus):
                    nvidia_gpus.append({
                        "pci_slot": "",
                        "name": _safe_text(row[0], 300),
                        "driver": "nvidia",
                    })
                    gpus.append(nvidia_gpus[-1])
                item = nvidia_gpus[index]
                item.update({
                    "name": _safe_text(row[0], 300),
                    "runtime_driver_version": _safe_text(row[1], 80),
                    "vram_total_mib": _safe_text(row[2], 40),
                    "temperature_c": _safe_text(row[3], 40),
                    "fan_percent": _safe_text(row[4], 40),
                })
    return gpus[:HARDWARE_MAX_GPUS]


def _number(path: Path) -> Optional[float]:
    raw = _read_text(path, 80)
    try:
        return float(raw)
    except ValueError:
        return None


def _bool_file(path: Path) -> bool:
    return _read_text(path, 20) == "1"


def _collect_hwmon(sys_root: Path) -> List[Dict[str, object]]:
    hwmon_root = sys_root / "class" / "hwmon"
    sensors: List[Dict[str, object]] = []
    try:
        devices = sorted(hwmon_root.glob("hwmon*"))[:64]
    except OSError:
        devices = []
    for device in devices:
        chip = _safe_text(_read_text(device / "name", 120), 120) or device.name
        for kind, unit, scale in (("temp", "C", 1000.0), ("fan", "RPM", 1.0)):
            try:
                inputs = sorted(device.glob(f"{kind}[0-9]*_input"))[:32]
            except OSError:
                inputs = []
            for input_path in inputs:
                match = re.match(rf"^{kind}(\d+)_input$", input_path.name)
                if not match:
                    continue
                index = match.group(1)
                raw_value = _number(input_path)
                if raw_value is None:
                    continue
                value = raw_value / scale
                if kind == "temp" and not -50 <= value <= 200:
                    continue
                if kind == "fan" and not 0 <= value <= 200000:
                    continue
                base = device / f"{kind}{index}"
                label = _safe_text(_read_text(Path(str(base) + "_label"), 120), 120)
                maximum = _number(Path(str(base) + "_max"))
                critical = _number(Path(str(base) + "_crit"))
                if maximum is not None:
                    maximum /= scale
                if critical is not None:
                    critical /= scale
                alarm = _bool_file(Path(str(base) + "_alarm"))
                fault = _bool_file(Path(str(base) + "_fault"))
                status = "fault" if fault else "alarm" if alarm else "normal"
                if status == "normal" and critical is not None and value >= critical:
                    status = "critical"
                if kind == "fan" and value == 0 and status == "normal":
                    status = "stopped_or_unreported"
                sensors.append({
                    "chip": chip,
                    "label": label or f"{kind}{index}",
                    "kind": "temperature" if kind == "temp" else "fan",
                    "value": round(value, 2),
                    "unit": unit,
                    "max": round(maximum, 2) if maximum is not None else None,
                    "critical": round(critical, 2) if critical is not None else None,
                    "alarm": alarm,
                    "fault": fault,
                    "status": status,
                })
                if len(sensors) >= HARDWARE_MAX_SENSORS:
                    return sensors
    return sensors


def _parse_pressure(path: Path) -> Dict[str, object]:
    result: Dict[str, object] = {}
    text = _read_text(path, 4096)
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        values: Dict[str, float] = {}
        for item in fields[1:]:
            if "=" not in item:
                continue
            key, value = item.split("=", 1)
            try:
                values[key] = float(value)
            except ValueError:
                continue
        result[fields[0]] = values
    return result


def _collect_hardware_error_counts(
    runner: Callable,
    which: Callable[[str], Optional[str]],
) -> Dict[str, int]:
    if not which("journalctl"):
        return {}
    output = _run_bounded(
        runner,
        ["journalctl", "-k", "-b", "--no-pager", "-o", "cat", "-n", "800"],
        timeout=20,
        max_chars=128 * 1024,
    )
    if output.returncode != 0:
        return {}
    patterns = {
        "machine_check": re.compile(r"(?i)\b(?:mce:|machine check|hardware error)\b"),
        "edac": re.compile(r"(?i)\bedac\b.*\b(?:error|corrected|uncorrected)\b"),
        "pcie_aer": re.compile(r"(?i)\b(?:aer:|pcie bus error)\b"),
        "thermal_throttling": re.compile(r"(?i)\b(?:thermal thrott|temperature above threshold)\b"),
        "nvidia_xid": re.compile(r"(?i)\bnvrm:.*\bxid\b"),
        "gpu_reset": re.compile(r"(?i)\bamdgpu\b.*\b(?:reset|ring timeout|gpu fault)\b"),
        "memory_failure": re.compile(r"(?i)\b(?:memory failure|uncorrectable memory|bad page)\b"),
    }
    counts = {name: 0 for name in patterns}
    for line in output.stdout.splitlines()[:800]:
        for name, pattern in patterns.items():
            if pattern.search(line):
                counts[name] += 1
    return {name: count for name, count in counts.items() if count}


def _parse_package_query(text: str) -> Tuple[str, str]:
    fields = text.strip().split()
    return (fields[0], fields[1]) if len(fields) >= 2 else ("", "")


def _sync_package_version(text: str) -> str:
    for line in text.splitlines():
        if line.lstrip().startswith("Version") and ":" in line:
            return line.split(":", 1)[1].strip()
    return ""


def _package_state(
    package: str,
    *,
    runner: Callable,
    which: Callable[[str], Optional[str]],
) -> Optional[Dict[str, object]]:
    if not which("pacman"):
        return None
    installed = _run_bounded(runner, ["pacman", "-Q", package], timeout=15, max_chars=4096)
    installed_name, installed_version = _parse_package_query(installed.stdout)
    if installed.returncode != 0 or installed_name != package:
        return None
    sync = _run_bounded(runner, ["pacman", "-Si", package], timeout=20, max_chars=16 * 1024)
    sync_version = _sync_package_version(sync.stdout) if sync.returncode == 0 else ""
    status = "sync_version_unavailable"
    if sync_version:
        if sync_version == installed_version:
            status = "repository_current"
        elif which("vercmp"):
            compared = _run_bounded(
                runner,
                ["vercmp", installed_version, sync_version],
                timeout=10,
                max_chars=128,
            )
            try:
                status = (
                    "update_available"
                    if int(compared.stdout.strip()) < 0
                    else "installed_newer"
                    if int(compared.stdout.strip()) > 0
                    else "repository_current"
                )
            except ValueError:
                status = "version_differs"
        else:
            status = "version_differs"
    return {
        "package": package,
        "installed_version": installed_version,
        "repository_version": sync_version,
        "status": status,
    }


def _sync_database_age_hours(sync_root: Path) -> Optional[float]:
    try:
        mtimes = [
            path.stat().st_mtime
            for path in list(sync_root.glob("*.db"))[:128]
            if path.is_file()
        ]
    except OSError:
        return None
    if not mtimes:
        return None
    return round(max(0.0, time.time() - max(mtimes)) / 3600.0, 1)


def _packages_for_hardware(
    inventory: Mapping[str, object],
    gpus: Sequence[Mapping[str, object]],
) -> List[str]:
    packages = []
    vendor = str(inventory.get("cpu_vendor") or "").lower()
    if "intel" in vendor:
        packages.append("intel-ucode")
    elif "amd" in vendor:
        packages.append("amd-ucode")
    drivers = {str(item.get("driver") or "").lower() for item in gpus}
    names = " ".join(str(item.get("name") or "").lower() for item in gpus)
    if "nvidia" in drivers or "nvidia" in names:
        packages.append("nvidia-utils")
    if "amdgpu" in drivers or "radeon" in names or "advanced micro devices" in names:
        packages.extend(["mesa", "vulkan-radeon"])
    if drivers & {"i915", "xe"} or "intel" in names:
        packages.extend(["mesa", "vulkan-intel", "intel-media-driver"])
    return list(dict.fromkeys(packages))[:12]


def _firmware_update_summary(
    runner: Callable,
    which: Callable[[str], Optional[str]],
    *,
    refresh_metadata: bool,
) -> Dict[str, object]:
    if not which("fwupdmgr"):
        return {
            "status": "unavailable",
            "reason": "fwupdmgr is not installed",
            "metadata_refreshed": False,
            "bios_status": "unverified",
        }
    refreshed = False
    refresh_error = ""
    if refresh_metadata:
        refresh = _run_bounded(
            runner,
            ["fwupdmgr", "refresh", "--force", "--json", "--no-unreported-check"],
            timeout=60,
            max_chars=32 * 1024,
        )
        refreshed = refresh.returncode == 0
        if not refreshed:
            refresh_error = _safe_text(refresh.stderr or refresh.stdout, 300)
    updates = _run_bounded(
        runner,
        ["fwupdmgr", "get-updates", "--json", "--no-unreported-check"],
        timeout=45,
        max_chars=128 * 1024,
    )
    if updates.returncode == 2:
        return {
            "status": "current",
            "updates_available": 0,
            "devices": [],
            "metadata_refreshed": refreshed,
            "refresh_error": refresh_error,
            "system_firmware_updates": 0,
            "secure_boot_database_updates": 0,
            "device_firmware_updates": 0,
            "bios_status": "no_update_reported_by_fwupd",
        }
    try:
        data = json.loads(updates.stdout)
    except json.JSONDecodeError:
        return {
            "status": "error" if updates.returncode else "unavailable",
            "reason": _safe_text(updates.stderr or updates.stdout or "invalid fwupd JSON", 300),
            "metadata_refreshed": refreshed,
            "refresh_error": refresh_error,
            "bios_status": "unverified",
        }
    devices: List[Dict[str, str]] = []

    def visit(value: object) -> None:
        if isinstance(value, Mapping):
            releases = value.get("Releases", value.get("releases"))
            if isinstance(releases, list) and releases:
                name = _safe_text(
                    value.get("Name")
                    or value.get("DeviceName")
                    or value.get("name")
                    or "Firmware device",
                    200,
                )
                plugin = _safe_text(
                    value.get("Plugin") or value.get("plugin"),
                    80,
                ).lower()
                lowered_name = name.lower()
                if plugin in {"uefi_db", "uefi_dbx"} or any(
                    term in lowered_name
                    for term in ("secure boot", "uefi db", "uefi ca")
                ):
                    category = "secure_boot_database"
                elif plugin in {"uefi_capsule", "flashrom", "bios"} or any(
                    term in lowered_name
                    for term in ("system firmware", "mainboard", "motherboard", "bios")
                ):
                    category = "system_firmware"
                else:
                    category = "device_firmware"
                versions = []
                for release in releases[:8]:
                    if isinstance(release, Mapping):
                        version = _safe_text(
                            release.get("Version") or release.get("version"),
                            80,
                        )
                        if version:
                            versions.append(version)
                devices.append({
                    "name": name,
                    "available_versions": ", ".join(versions[:4]),
                    "category": category,
                })
            for item in list(value.values())[:100]:
                visit(item)
        elif isinstance(value, list):
            for item in value[:100]:
                visit(item)

    visit(data)
    unique = []
    seen = set()
    for item in devices:
        key = (item["name"], item["available_versions"], item["category"])
        if key not in seen:
            seen.add(key)
            unique.append(item)
    system_updates = sum(item["category"] == "system_firmware" for item in unique)
    secure_boot_updates = sum(
        item["category"] == "secure_boot_database" for item in unique
    )
    device_updates = len(unique) - system_updates - secure_boot_updates
    return {
        "status": "updates_available" if unique else "current",
        "updates_available": len(unique),
        "devices": unique[:12],
        "metadata_refreshed": refreshed,
        "refresh_error": refresh_error,
        "system_firmware_updates": system_updates,
        "secure_boot_database_updates": secure_boot_updates,
        "device_firmware_updates": device_updates,
        "bios_status": (
            "update_available"
            if system_updates
            else "no_update_reported_by_fwupd"
        ),
    }


def _parse_microcode(value: object) -> Optional[int]:
    text = str(value or "").strip().lower()
    try:
        return int(text, 16) if text.startswith("0x") else int(text)
    except ValueError:
        return None


def _hardware_advisories(inventory: Mapping[str, object]) -> List[Dict[str, object]]:
    model = str(inventory.get("cpu_model") or "")
    if not re.search(r"(?i)\b(?:i[3579]-?)?(?:13|14)\d{3}[a-z]{0,2}\b", model):
        return []
    microcode = _parse_microcode(inventory.get("active_microcode"))
    status = (
        "active_microcode_meets_guidance"
        if microcode is not None and microcode >= INTEL_VMIN_MINIMUM_MICROCODE
        else "active_microcode_below_guidance"
        if microcode is not None
        else "active_microcode_unknown"
    )
    return [{
        "advisory": "Intel 13th/14th Gen desktop Vmin Shift instability",
        "status": status,
        "active_microcode": str(inventory.get("active_microcode") or ""),
        "minimum_guidance": f"0x{INTEL_VMIN_MINIMUM_MICROCODE:X}",
        "guidance": (
            "Intel recommends Intel Default Settings and the latest motherboard BIOS "
            "containing microcode 0x12F or later. Runtime microcode alone does not prove "
            "that the installed BIOS is current."
        ),
        "source": INTEL_VMIN_GUIDANCE_URL,
    }]


def collect_static_hardware_facts(
    *,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
    proc_root: Path = Path("/proc"),
    sys_root: Path = Path("/sys"),
    include_memory_devices: bool = True,
    allow_commands: bool = True,
) -> Dict[str, object]:
    inventory = _parse_cpu_info(proc_root / "cpuinfo")
    inventory.update(_collect_dmi_inventory(sys_root / "class" / "dmi" / "id"))
    memory = _parse_meminfo(proc_root / "meminfo")
    if include_memory_devices and allow_commands and which("dmidecode"):
        memory.update(_collect_memory_devices(runner, which))
    else:
        memory["detailed_timings_status"] = "not_collected"
    command_which = which if allow_commands else lambda _name: None
    gpus = _collect_gpus(sys_root=sys_root, runner=runner, which=command_which)
    return {
        "inventory": inventory,
        "memory": memory,
        "gpus": gpus,
        "advisories": _hardware_advisories(inventory),
    }


def collect_hardware_health(
    *,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
    proc_root: Path = Path("/proc"),
    sys_root: Path = Path("/sys"),
    pacman_sync_root: Path = Path("/var/lib/pacman/sync"),
    refresh_firmware_metadata: bool = True,
) -> HardwareHealthReport:
    static = collect_static_hardware_facts(
        runner=runner,
        which=which,
        proc_root=proc_root,
        sys_root=sys_root,
        include_memory_devices=True,
    )
    report = HardwareHealthReport(
        inventory=dict(static.get("inventory") or {}),
        memory=dict(static.get("memory") or {}),
        gpus=list(static.get("gpus") or []),
        advisories=list(static.get("advisories") or []),
    )
    report.sensors = _collect_hwmon(sys_root)
    report.memory_pressure = _parse_pressure(proc_root / "pressure" / "memory")
    report.hardware_error_counts = _collect_hardware_error_counts(runner, which)
    for package in _packages_for_hardware(report.inventory, report.gpus):
        item = _package_state(package, runner=runner, which=which)
        if item is not None:
            report.package_updates.append(item)
    sync_age = _sync_database_age_hours(pacman_sync_root)
    if sync_age is not None:
        report.inventory["pacman_sync_age_hours"] = sync_age
        if sync_age > 48:
            report.notes.append(
                "Driver and microcode package comparisons use package databases older than 48 hours."
            )
    report.firmware = _firmware_update_summary(
        runner,
        which,
        refresh_metadata=refresh_firmware_metadata,
    )
    if not report.inventory.get("cpu_model"):
        report.notes.append("CPU model was unavailable.")
    if not report.gpus:
        report.notes.append("GPU model was unavailable.")
    if not report.sensors:
        report.notes.append(
            "No supported hwmon temperature or fan readings were exposed by the current kernel drivers."
        )
    if report.memory.get("detailed_timings_status") != "available":
        report.notes.append(
            "Exact DIMM timings were not exposed by safe SMBIOS sources; AuraScan did not "
            "access raw SPD/I2C data."
        )
    if report.firmware.get("status") in {"unavailable", "error"}:
        report.notes.append(
            "Firmware freshness could not be proven through fwupd; vendor BIOS availability may require manual confirmation."
        )
    report.status = (
        "ok"
        if report.inventory.get("cpu_model") and report.memory.get("total_mib")
        else "partial"
    )
    return report


def hardware_health_doctor_status(
    *,
    which: Callable[[str], Optional[str]] = shutil.which,
    proc_root: Path = Path("/proc"),
    sys_root: Path = Path("/sys"),
) -> Dict[str, object]:
    return {
        "cpu_inventory": (proc_root / "cpuinfo").is_file(),
        "memory_inventory": (proc_root / "meminfo").is_file(),
        "dmi_inventory": (sys_root / "class" / "dmi" / "id").is_dir(),
        "hwmon": (sys_root / "class" / "hwmon").is_dir(),
        "lspci": which("lspci") or "",
        "dmidecode": which("dmidecode") or "",
        "inxi": which("inxi") or "",
        "cached_sudo_supported": bool(which("sudo")),
        "sensors": which("sensors") or "",
        "nvidia_smi": which("nvidia-smi") or "",
        "fwupdmgr": which("fwupdmgr") or "",
        "pacman": which("pacman") or "",
        "vercmp": which("vercmp") or "",
    }
