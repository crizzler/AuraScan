import hashlib
import json
import os
import subprocess
from pathlib import Path

from aurascan.core.recovery_boot import (
    RECOVERY_LIMINE_BEGIN,
    RECOVERY_LIMINE_END,
    build_uki_command,
    BootloaderInfo,
    bootloader_reinstall_commands,
    choose_recovery_kernel,
    detect_bootloader,
    detect_secure_boot,
    inspect_usb_device,
    install_bootloader_entry,
    merge_marked_block,
    render_grub_recovery_script,
    render_limine_recovery_entry,
    sign_recovery_image,
    validate_recovery_image,
    verify_recovery_iso,
)


def test_limine_entry_uses_documented_efi_protocol_and_is_idempotent():
    block = render_limine_recovery_entry()
    once = merge_marked_block("timeout: 3\n", block, RECOVERY_LIMINE_BEGIN, RECOVERY_LIMINE_END)
    twice = merge_marked_block(once, block, RECOVERY_LIMINE_BEGIN, RECOVERY_LIMINE_END)

    assert "protocol: efi" in block
    assert "EFI/Linux/aurascan-recovery.efi" in block
    assert once == twice
    assert once.count(RECOVERY_LIMINE_BEGIN) == 1


def test_grub_entry_chainloads_the_uki_without_formatting_or_key_changes():
    script = render_grub_recovery_script()

    assert "chainloader" in script
    assert "EFI/Linux/aurascan-recovery.efi" in script
    assert "mkfs" not in script
    assert "enroll" not in script


def test_bootloader_reinstall_recipes_never_modify_firmware_variables():
    root = Path("/run/aurascan-recovery/target")
    esp = root / "boot"

    limine = bootloader_reinstall_commands(BootloaderInfo(kind="limine"), root=root, esp_path=esp)
    systemd_boot = bootloader_reinstall_commands(BootloaderInfo(kind="systemd-boot"), root=root, esp_path=esp)
    grub = bootloader_reinstall_commands(BootloaderInfo(kind="grub"), root=root, esp_path=esp)

    assert "--no-efi-register" in limine[0]
    assert "--no-variables" in systemd_boot[0]
    assert "--no-nvram" in grub[0]


def test_uki_command_rejects_untrusted_kernel_version(tmp_path):
    try:
        build_uki_command(tmp_path / "out.efi", "6.12; reboot")
    except ValueError as exc:
        assert "invalid kernel" in str(exc)
    else:
        raise AssertionError("unsafe kernel version was accepted")


def test_recovery_kernel_prefers_newest_valid_lts_image(tmp_path):
    older = tmp_path / "6.12.1-lts"
    newer = tmp_path / "6.18.1-lts"
    ordinary = tmp_path / "7.1.0-arch"
    for index, (directory, pkgbase) in enumerate(((older, "linux-lts"), (newer, "linux-lts"), (ordinary, "linux")), start=1):
        directory.mkdir()
        (directory / "pkgbase").write_text(pkgbase + "\n", encoding="utf-8")
        image = directory / "vmlinuz"
        image.write_bytes(b"kernel")
        os.utime(image, (index, index))

    version, pkgbase = choose_recovery_kernel(tmp_path)

    assert version == newer.name
    assert pkgbase == "linux-lts"


def test_uki_command_uses_supported_mkosi_initrd_profile_without_host_config_import(tmp_path):
    overlay = tmp_path / "overlay"
    command = build_uki_command(tmp_path / "recovery.efi", "6.12.1-arch1-1", mkosi="/usr/bin/mkosi", extra_tree=overlay)

    assert command[0] == "/usr/bin/mkosi"
    assert "--include=mkosi-initrd" in command
    assert "--directory=" in command
    assert not any(item.startswith("--kernel-version=") for item in command)
    assert f"--extra-tree={overlay}:/" in command


def test_image_validation_scans_entire_file_for_credentials(tmp_path):
    image = tmp_path / "recovery.efi"
    image.write_bytes(b"MZ" + b"x" * (5 * 1024 * 1024) + b"AURASCAN_AI_KEY=secret")

    valid, errors = validate_recovery_image(image, minimum_size=2, which=lambda _name: None)

    assert valid is False
    assert any("credential" in item for item in errors)


def test_image_validation_requires_selected_kernel_in_ukify_metadata(tmp_path):
    image = tmp_path / "recovery.efi"
    image.write_bytes(b"MZfixture")

    valid, errors = validate_recovery_image(
        image,
        minimum_size=2,
        expected_kernel_version="6.18.1-lts",
        which=lambda name: "/usr/bin/ukify" if name == "ukify" else None,
        runner=lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, "Kernel Version: 7.1.0-arch\n", ""),
    )

    assert valid is False
    assert any("selected recovery kernel" in item for item in errors)


def test_usb_inspection_accepts_only_removable_unmounted_whole_disk():
    payload = {
        "blockdevices": [
            {"path": "/dev/sda", "type": "disk", "rm": 0, "size": 100000000000, "model": "Root", "serial": "A", "mountpoints": [None], "pkname": None, "children": [{"path": "/dev/sda2", "type": "part", "rm": 0, "size": 90000000000, "model": None, "serial": None, "mountpoints": ["/"], "pkname": "sda"}]},
            {"path": "/dev/sdb", "type": "disk", "rm": 1, "size": 16000000000, "model": "USB", "serial": "B", "mountpoints": [None], "pkname": None},
        ]
    }

    def runner(command, **_kwargs):
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    usb = inspect_usb_device("/dev/sdb", runner=runner, root_source="/dev/sda2")
    root = inspect_usb_device("/dev/sda", runner=runner, root_source="/dev/sda2")

    assert usb.eligible is True
    assert usb.model == "USB"
    assert root.eligible is False
    assert "removable" in root.refusal or "root" in root.refusal


def test_usb_inspection_rejects_removable_disk_beneath_encrypted_running_root():
    payload = {
        "blockdevices": [{
            "path": "/dev/sda", "type": "disk", "rm": 1, "size": 64000000000, "model": "Boot USB", "serial": "ROOT", "mountpoints": [None], "pkname": None,
            "children": [{
                "path": "/dev/sda2", "type": "part", "rm": 1, "size": 63000000000, "mountpoints": [None], "pkname": "sda",
                "children": [{"path": "/dev/mapper/cryptroot", "type": "crypt", "rm": 0, "size": 62000000000, "mountpoints": ["/"], "pkname": "sda2"}],
            }],
        }]
    }

    root = inspect_usb_device(
        "/dev/sda",
        runner=lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, json.dumps(payload), ""),
        root_source="/dev/mapper/cryptroot",
    )

    assert root.eligible is False
    assert "root filesystem" in root.refusal


def test_usb_inspection_rejects_nested_mounted_descendant():
    payload = {
        "blockdevices": [{
            "path": "/dev/sdb", "type": "disk", "rm": 1, "size": 64000000000, "model": "USB", "serial": "NESTED", "mountpoints": [None], "pkname": None,
            "children": [{
                "path": "/dev/sdb1", "type": "part", "rm": 1, "size": 63000000000, "mountpoints": [None], "pkname": "sdb",
                "children": [{"path": "/dev/mapper/usbdata", "type": "crypt", "rm": 0, "size": 62000000000, "mountpoints": ["/mnt/data"], "pkname": "sdb1"}],
            }],
        }]
    }

    info = inspect_usb_device(
        "/dev/sdb",
        runner=lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, json.dumps(payload), ""),
    )

    assert info.eligible is False
    assert "mounted" in info.refusal


def test_secure_boot_signing_requires_explicit_enrolled_sbctl_key(tmp_path):
    image = tmp_path / "recovery.efi"
    image.write_bytes(b"MZfixture")
    commands = []

    def runner(command, **_kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, json.dumps({"installed": False}), "")

    result = sign_recovery_image(image, runner=runner, which=lambda _name: "/usr/bin/sbctl")

    assert result.ok is False
    assert result.status == "refused"
    assert len(commands) == 1


def test_secure_boot_detection_uses_efi_variable_when_bootctl_is_unavailable(tmp_path):
    efivars = tmp_path / "efivars"
    efivars.mkdir()
    variable = efivars / "SecureBoot-fixture"
    variable.write_bytes(b"\x07\x00\x00\x00\x01")

    enabled = detect_secure_boot(which=lambda _name: None, efivars_root=efivars)
    variable.write_bytes(b"\x07\x00\x00\x00\x00")
    disabled = detect_secure_boot(which=lambda _name: None, efivars_root=efivars)

    assert enabled == "enabled"
    assert disabled == "disabled"


def test_limine_entry_refuses_symlink_configuration(tmp_path):
    root = tmp_path / "root"
    esp = root / "boot"
    esp.mkdir(parents=True)
    outside = tmp_path / "outside.conf"
    outside.write_text("timeout: 3\n", encoding="utf-8")
    (esp / "limine.conf").symlink_to(outside)
    loader = BootloaderInfo("limine", "Limine", str(esp / "limine.conf"), True, True, True)

    result = install_bootloader_entry(loader, root=root, esp_path=esp, backup_root=tmp_path / "backup")

    assert result.ok is False
    assert result.status == "refused"
    assert outside.read_text(encoding="utf-8") == "timeout: 3\n"


def test_bootloader_detection_does_not_trust_stale_default_config_alone(tmp_path):
    root = tmp_path / "root"
    esp = root / "boot"
    (root / "etc/default").mkdir(parents=True)
    esp.mkdir(parents=True)
    (root / "etc/default/grub").write_text("GRUB_TIMEOUT=5\n", encoding="utf-8")

    detected = detect_bootloader(root, esp)

    assert detected.installed is False
    assert detected.kind == "unknown"


def test_bootloader_detection_refuses_equally_strong_ambiguous_installations(tmp_path):
    root = tmp_path / "root"
    esp = root / "boot"
    (esp / "EFI/systemd").mkdir(parents=True)
    (esp / "EFI/limine").mkdir(parents=True)
    (esp / "loader").mkdir(parents=True)
    (esp / "EFI/systemd/systemd-bootx64.efi").write_bytes(b"MZsystemd")
    (esp / "loader/loader.conf").write_text("default arch.conf\n", encoding="utf-8")
    (esp / "EFI/limine/limine_x64.efi").write_bytes(b"MZlimine")
    (esp / "limine.conf").write_text("timeout: 3\n", encoding="utf-8")

    detected = detect_bootloader(root, esp)

    assert detected.installed is False
    assert detected.kind == "unknown"
    assert any("Multiple equally strong" in item for item in detected.evidence)


def test_grub_entry_install_refuses_when_configuration_generator_is_missing(tmp_path):
    root = tmp_path / "root"
    esp = root / "boot"
    (root / "etc/default").mkdir(parents=True)
    (esp / "EFI/GRUB").mkdir(parents=True)
    (root / "etc/default/grub").write_text("GRUB_TIMEOUT=5\n", encoding="utf-8")
    (esp / "EFI/GRUB/grubx64.efi").write_bytes(b"MZfixture")
    loader = detect_bootloader(root, esp)

    result = install_bootloader_entry(
        loader,
        root=root,
        esp_path=esp,
        backup_root=tmp_path / "backup",
        which=lambda _name: None,
    )

    assert loader.kind == "grub"
    assert result.ok is False
    assert result.status == "unavailable"
    assert not (root / "etc/grub.d/41_aurascan_recovery").exists()


def test_grub_entry_refuses_output_symlink_before_changing_the_script(tmp_path):
    root = tmp_path / "root"
    esp = root / "boot"
    (root / "etc/default").mkdir(parents=True)
    (root / "usr/bin").mkdir(parents=True)
    (esp / "EFI/GRUB").mkdir(parents=True)
    (esp / "grub").mkdir(parents=True)
    (root / "etc/default/grub").write_text("GRUB_TIMEOUT=5\n", encoding="utf-8")
    (root / "usr/bin/grub-mkconfig").write_text("fixture\n", encoding="utf-8")
    (esp / "EFI/GRUB/grubx64.efi").write_bytes(b"MZfixture")
    outside = tmp_path / "outside-grub.cfg"
    outside.write_text("existing menu\n", encoding="utf-8")
    (esp / "grub/grub.cfg").symlink_to(outside)
    loader = detect_bootloader(root, esp)

    result = install_bootloader_entry(
        loader,
        root=root,
        esp_path=esp,
        backup_root=tmp_path / "backup",
        which=lambda name: f"/usr/bin/{name}" if name == "arch-chroot" else None,
    )

    assert result.ok is False
    assert result.status == "refused"
    assert not (root / "etc/grub.d/41_aurascan_recovery").exists()
    assert outside.read_text(encoding="utf-8") == "existing menu\n"


def test_iso_verification_accepts_matching_local_sidecar_and_rejects_change(tmp_path):
    image = tmp_path / "recovery.iso"
    image.write_bytes(b"fixture-iso")
    digest = hashlib.sha256(image.read_bytes()).hexdigest()
    Path(str(image) + ".sha256").write_text(f"{digest}  {image.name}\n", encoding="utf-8")

    unavailable, _message, _expected = verify_recovery_iso(image, {})
    valid, _message, expected = verify_recovery_iso(image, {}, allow_local_sidecar=True)
    image.write_bytes(b"changed")
    changed, _message, _expected = verify_recovery_iso(image, {}, allow_local_sidecar=True)

    assert unavailable is False
    assert valid is True
    assert expected == digest
    assert changed is False
