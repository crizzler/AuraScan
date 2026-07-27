import os
from pathlib import Path

from aurascan.core.hardware_health import (
    HARDWARE_HEALTH_PROBE_ID,
    collect_hardware_health,
    collect_static_hardware_facts,
    hardware_health_doctor_status,
    question_requests_hardware_context,
)


class Completed:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


class HardwareRunner:
    def __init__(self):
        self.calls = []

    def __call__(self, command, **_kwargs):
        command = list(command)
        self.calls.append(command)
        if command[:4] == ["lspci", "-D", "-mm", "-nn"]:
            return Completed(
                '0000:01:00.0 "VGA compatible controller [0300]" '
                '"NVIDIA Corporation [10de]" "Fixture GPU [1234]"\n'
            )
        if command and command[0] == "nvidia-smi":
            return Completed("Fixture GPU, 610.1, 16384, 55, 30\n")
        if command == ["dmidecode", "--type", "17"]:
            return Completed(
                "Memory Device\n"
                "\tSize: 16384 MB\n"
                "\tType: DDR5\n"
                "\tSpeed: 6000 MT/s\n"
                "\tConfigured Memory Speed: 5600 MT/s\n\n"
                "Memory Device\n"
                "\tSize: 16384 MB\n"
                "\tType: DDR5\n"
                "\tSpeed: 6000 MT/s\n"
                "\tConfigured Memory Speed: 5600 MT/s\n\n"
                "Memory Device\n"
                "\tSize: 16384 MB\n"
                "\tType: DDR5\n"
                "\tSpeed: 6000 MT/s\n"
                "\tConfigured Memory Speed: 5600 MT/s\n\n"
                "Memory Device\n"
                "\tSize: 16384 MB\n"
                "\tType: DDR5\n"
                "\tSpeed: 6000 MT/s\n"
                "\tConfigured Memory Speed: 5600 MT/s\n"
            )
        if command[:6] == ["journalctl", "-k", "-b", "--no-pager", "-o", "cat"]:
            return Completed(
                "mce: Machine check events logged\n"
                "NVRM: Xid (PCI:0000:01:00): 31, pid=10\n"
            )
        if command[:2] == ["pacman", "-Q"]:
            versions = {
                "intel-ucode": "20260701-1",
                "nvidia-utils": "610.1-1",
            }
            version = versions.get(command[2])
            return Completed(
                f"{command[2]} {version}\n" if version else "",
                returncode=0 if version else 1,
            )
        if command[:2] == ["pacman", "-Si"]:
            versions = {
                "intel-ucode": "20260701-1",
                "nvidia-utils": "610.2-1",
            }
            version = versions.get(command[2])
            return Completed(
                f"Repository      : fixture\nName            : {command[2]}\n"
                f"Version         : {version}\n"
                if version
                else "",
                returncode=0 if version else 1,
            )
        if command and command[0] == "vercmp":
            return Completed("-1\n" if command[1] < command[2] else "0\n")
        if command[:2] == ["fwupdmgr", "refresh"]:
            return Completed("{}\n")
        if command[:2] == ["fwupdmgr", "get-updates"]:
            return Completed(
                '{"Devices":[{"Name":"Fixture Mainboard UEFI",'
                '"Plugin":"uefi_capsule",'
                '"Releases":[{"Version":"2.0"}]}]}\n'
            )
        return Completed(returncode=1)


class CachedSudoHardwareRunner(HardwareRunner):
    def __call__(self, command, **kwargs):
        command = list(command)
        if command == ["dmidecode", "--type", "17"]:
            self.calls.append(command)
            return Completed(stderr="Permission denied", returncode=1)
        if command == ["sudo", "-n", "dmidecode", "--type", "17"]:
            self.calls.append(command)
            command = ["dmidecode", "--type", "17"]
        return super().__call__(command, **kwargs)


def fake_which(name):
    found = {
        "dmidecode",
        "fwupdmgr",
        "journalctl",
        "lspci",
        "nvidia-smi",
        "pacman",
        "sensors",
        "sudo",
        "vercmp",
    }
    return f"/usr/bin/{name}" if name in found else None


def write_fixture_hardware(tmp_path: Path):
    proc = tmp_path / "proc"
    sys = tmp_path / "sys"
    dmi = sys / "class" / "dmi" / "id"
    dmi.mkdir(parents=True)
    proc.mkdir()
    (proc / "pressure").mkdir()
    (proc / "cpuinfo").write_text(
        "processor : 0\n"
        "vendor_id : GenuineIntel\n"
        "cpu family : 6\n"
        "model : 183\n"
        "stepping : 1\n"
        "model name : Intel(R) Core(TM) i9-13900K\n"
        "microcode : 0x12e\n\n"
        "processor : 1\n"
        "vendor_id : GenuineIntel\n"
        "model name : Intel(R) Core(TM) i9-13900K\n",
        encoding="utf-8",
    )
    (proc / "meminfo").write_text(
        "MemTotal:       67108864 kB\n"
        "MemAvailable:   50331648 kB\n"
        "SwapTotal:      8388608 kB\n"
        "SwapFree:       7340032 kB\n",
        encoding="utf-8",
    )
    (proc / "pressure" / "memory").write_text(
        "some avg10=0.10 avg60=0.05 avg300=0.01 total=100\n"
        "full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
        encoding="utf-8",
    )
    dmi_values = {
        "sys_vendor": "Fixture Systems",
        "product_name": "Fixture Workstation",
        "board_vendor": "Fixture Board Vendor",
        "board_name": "Z790 Fixture",
        "board_version": "1.0",
        "bios_vendor": "Fixture BIOS",
        "bios_version": "1.2.3",
        "bios_date": "07/01/2026",
        "product_serial": "MUST-NOT-BE-READ",
        "product_uuid": "MUST-NOT-BE-READ-EITHER",
    }
    for name, value in dmi_values.items():
        (dmi / name).write_text(value + "\n", encoding="utf-8")

    pci = sys / "bus" / "pci" / "devices" / "0000:01:00.0"
    driver = sys / "bus" / "pci" / "drivers" / "nvidia"
    driver.mkdir(parents=True)
    pci.mkdir(parents=True)
    (pci / "class").write_text("0x030000\n", encoding="utf-8")
    (pci / "vendor").write_text("0x10de\n", encoding="utf-8")
    (pci / "device").write_text("0x1234\n", encoding="utf-8")
    (pci / "driver").symlink_to(driver, target_is_directory=True)
    module = sys / "module" / "nvidia"
    module.mkdir(parents=True)
    (module / "version").write_text("610.1\n", encoding="utf-8")

    coretemp = sys / "class" / "hwmon" / "hwmon0"
    coretemp.mkdir(parents=True)
    (coretemp / "name").write_text("coretemp\n", encoding="utf-8")
    (coretemp / "temp1_label").write_text("Package id 0\n", encoding="utf-8")
    (coretemp / "temp1_input").write_text("80000\n", encoding="utf-8")
    (coretemp / "temp1_crit").write_text("100000\n", encoding="utf-8")
    fans = sys / "class" / "hwmon" / "hwmon1"
    fans.mkdir()
    (fans / "name").write_text("nct6775\n", encoding="utf-8")
    (fans / "fan1_label").write_text("CPU Fan\n", encoding="utf-8")
    (fans / "fan1_input").write_text("0\n", encoding="utf-8")
    return proc, sys


def test_hardware_health_collects_bounded_inventory_sensors_updates_and_advisory(tmp_path):
    proc, sys = write_fixture_hardware(tmp_path)
    sync = tmp_path / "sync"
    sync.mkdir()
    (sync / "core.db").write_bytes(b"fixture")
    os.utime(sync / "core.db", None)
    runner = HardwareRunner()

    report = collect_hardware_health(
        runner=runner,
        which=fake_which,
        proc_root=proc,
        sys_root=sys,
        pacman_sync_root=sync,
        refresh_firmware_metadata=True,
    )
    payload = report.to_dict()

    assert report.status == "ok"
    assert report.inventory["cpu_model"].endswith("i9-13900K")
    assert report.inventory["board_model"] == "Z790 Fixture"
    assert report.inventory["bios_version"] == "1.2.3"
    assert report.memory["total_mib"] == 65536
    assert report.memory["populated_dimms"] == 4
    assert report.memory["dimm_types"] == ["DDR5"]
    assert report.memory["configured_speeds"] == ["5600 MT/s"]
    assert report.memory["detailed_timings_status"] == "not_exposed_by_smbios"
    assert report.gpus[0]["name"] == "Fixture GPU"
    assert report.gpus[0]["runtime_driver_version"] == "610.1"
    assert next(item for item in report.sensors if item["kind"] == "temperature")["value"] == 80
    assert next(item for item in report.sensors if item["kind"] == "fan")["status"] == "stopped_or_unreported"
    assert report.hardware_error_counts == {"machine_check": 1, "nvidia_xid": 1}
    assert next(
        item for item in report.package_updates if item["package"] == "nvidia-utils"
    )["status"] == "update_available"
    assert report.firmware["status"] == "updates_available"
    assert report.firmware["system_firmware_updates"] == 1
    assert report.firmware["bios_status"] == "update_available"
    assert report.firmware["devices"][0]["name"] == "Fixture Mainboard UEFI"
    assert report.advisories[0]["status"] == "active_microcode_below_guidance"
    assert "MUST-NOT-BE-READ" not in str(payload)
    assert len(report.sensors) <= 64
    assert ["fwupdmgr", "refresh", "--force", "--json", "--no-unreported-check"] in runner.calls


def test_secure_boot_database_update_is_not_presented_as_a_bios_update(tmp_path):
    proc, sys = write_fixture_hardware(tmp_path)

    class SecureBootRunner(HardwareRunner):
        def __call__(self, command, **kwargs):
            if list(command)[:2] == ["fwupdmgr", "get-updates"]:
                return Completed(
                    '{"Devices":[{"Name":"UEFI dbx","Plugin":"uefi_dbx",'
                    '"Releases":[{"Version":"20260701"}]}]}\n'
                )
            return super().__call__(command, **kwargs)

    report = collect_hardware_health(
        runner=SecureBootRunner(),
        which=fake_which,
        proc_root=proc,
        sys_root=sys,
        pacman_sync_root=tmp_path / "sync",
        refresh_firmware_metadata=False,
    )

    assert report.firmware["updates_available"] == 1
    assert report.firmware["secure_boot_database_updates"] == 1
    assert report.firmware["system_firmware_updates"] == 0
    assert report.firmware["bios_status"] == "no_update_reported_by_fwupd"
    assert "0 system-firmware update(s)" in report.summary


def test_static_background_inventory_runs_no_external_commands_or_network(tmp_path):
    proc, sys = write_fixture_hardware(tmp_path)

    facts = collect_static_hardware_facts(
        runner=lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("background inventory executed a command")
        ),
        which=lambda name: f"/usr/bin/{name}",
        proc_root=proc,
        sys_root=sys,
        include_memory_devices=False,
        allow_commands=False,
    )

    assert facts["inventory"]["cpu_model"].endswith("i9-13900K")
    assert facts["memory"]["total_mib"] == 65536
    assert facts["gpus"][0]["pci_id"] == "0x10de:0x1234"
    assert facts["gpus"][0]["name"] == ""


def test_memory_inventory_uses_only_an_existing_noninteractive_sudo_grant(tmp_path):
    proc, sys = write_fixture_hardware(tmp_path)
    runner = CachedSudoHardwareRunner()

    facts = collect_static_hardware_facts(
        runner=runner,
        which=fake_which,
        proc_root=proc,
        sys_root=sys,
    )

    assert ["sudo", "-n", "dmidecode", "--type", "17"] in runner.calls
    assert facts["memory"]["populated_dimms"] == 4
    assert facts["memory"]["memory_device_source"] == "sudo_cached_dmidecode"


def test_memory_inventory_uses_filtered_unprivileged_inxi_before_sudo(tmp_path):
    proc, sys = write_fixture_hardware(tmp_path)

    class InxiRunner(HardwareRunner):
        def __call__(self, command, **kwargs):
            command = list(command)
            if command == ["dmidecode", "--type", "17"]:
                self.calls.append(command)
                return Completed(stderr="Permission denied", returncode=1)
            if command and command[0] == "inxi":
                self.calls.append(command)
                return Completed(
                    "Memory:\n"
                    "  Array-1: capacity: 128 GiB slots: 4 modules: 4 EC: None\n"
                    "  Device-1: DDR5-A1 type: DDR5 size: 16 GiB speed: "
                    "spec: 4800 MT/s actual: 4400 MT/s\n"
                    "  Device-2: DDR5-A2 type: DDR5 size: 16 GiB speed: "
                    "spec: 4800 MT/s actual: 4400 MT/s\n"
                    "  Device-3: DDR5-B1 type: DDR5 size: 16 GiB speed: "
                    "spec: 4800 MT/s actual: 4400 MT/s\n"
                    "  Device-4: DDR5-B2 type: DDR5 size: 16 GiB speed: "
                    "spec: 4800 MT/s actual: 4400 MT/s\n"
                )
            return super().__call__(command, **kwargs)

    which = lambda name: f"/usr/bin/{name}" if name in {
        "dmidecode", "inxi", "sudo",
    } else None
    runner = InxiRunner()
    facts = collect_static_hardware_facts(
        runner=runner,
        which=which,
        proc_root=proc,
        sys_root=sys,
    )

    assert facts["memory"]["memory_slots"] == 4
    assert facts["memory"]["populated_dimms"] == 4
    assert facts["memory"]["dimm_total_mib"] == 65536
    assert facts["memory"]["dimm_types"] == ["DDR5"]
    assert facts["memory"]["configured_speeds"] == ["4400 MT/s"]
    assert facts["memory"]["memory_device_source"] == "inxi"
    assert not any(call[:2] == ["sudo", "-n"] for call in runner.calls)


def test_hardware_question_classifier_is_specific_enough_for_followup():
    assert question_requests_hardware_context(
        "Could my CPU, BIOS, four DIMMs, or cooling be related?"
    )
    assert question_requests_hardware_context("Was this an out-of-memory event?")
    assert not question_requests_hardware_context("Why was Chromium restarted?")
    assert HARDWARE_HEALTH_PROBE_ID.startswith("fup-")


def test_hardware_doctor_reports_optional_tool_coverage(tmp_path):
    proc, sys = write_fixture_hardware(tmp_path)

    status = hardware_health_doctor_status(
        which=fake_which,
        proc_root=proc,
        sys_root=sys,
    )

    assert status["cpu_inventory"] is True
    assert status["memory_inventory"] is True
    assert status["dmi_inventory"] is True
    assert status["hwmon"] is True
    assert status["fwupdmgr"] == "/usr/bin/fwupdmgr"
