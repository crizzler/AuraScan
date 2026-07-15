import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def read_text(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def test_arch_package_installs_recovery_assets_without_enabling_a_boot_entry():
    pkgbuild = read_text("packaging/arch/PKGBUILD")
    install_script = read_text("packaging/arch/aurascan.install")

    for asset in (
        "aurascan-recovery.service",
        "aurascan-recovery-refresh.hook",
        "aurascan-recovery-mkosi.conf",
        "aurascan-recovery-iso.json",
        "aurascan-recovery-tmpfiles.conf",
    ):
        assert asset in pkgbuild
    assert "systemctl enable" not in install_script
    assert "bootctl install" not in install_script
    assert "grub-install" not in install_script
    assert "limine-install" not in install_script
    assert "aurascan recovery --install" in install_script


def test_recovery_service_cannot_start_on_the_installed_host_by_accident():
    service = read_text("aurascan/assets/aurascan-recovery.service")

    assert "ConditionPathExists=/etc/aurascan/recovery-environment" in service
    assert "ExecStart=/usr/bin/aurascan recovery --runtime" in service
    assert "UMask=0077" in service
    assert "WantedBy=multi-user.target" in service


def test_archiso_profile_is_hybrid_and_contains_no_credentials():
    profile = read_text("packaging/recovery/archiso/profiledef.sh")
    packages = read_text("packaging/recovery/archiso/packages.x86_64")
    manifest = json.loads(read_text("aurascan/assets/aurascan-recovery-iso.json"))
    material = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in (ROOT / "packaging/recovery").rglob("*")
        if path.is_file()
    )

    assert "bios.syslinux.mbr" in profile
    assert "uefi-x64.systemd-boot.esp" in profile
    assert "aurascan" in packages
    assert not re.search(r"AURASCAN_(?:AI|OPENAI|ANTHROPIC|DEEPSEEK|GEMINI|OPENROUTER)_KEY=", material)
    assert manifest["version"] == "0.6.0"
    assert manifest["sha256"] == "" or re.fullmatch(r"[0-9a-f]{64}", manifest["sha256"])
    assert "/home/arawn" not in material
    assert "fixture-secret" not in material


def test_recovery_mkosi_profile_uses_explicit_packages_and_no_host_identity():
    profile = read_text("aurascan/assets/aurascan-recovery-mkosi.conf")

    assert "Distribution=arch" in profile
    assert "NetworkManager" not in profile
    assert "networkmanager" in profile
    assert "AURASCAN_" not in profile
    assert "/home/" not in profile
    assert "[Build]\nIncremental=no" in profile


def test_qemu_smoke_harness_requires_a_verified_iso_for_bios_and_uefi():
    harness = read_text("packaging/recovery/qemu-smoke.sh")

    assert "sha256sum --check" in harness
    assert "bios|uefi" in harness
    assert "bios|uefi|secure-boot" not in harness
    assert "run_archiso -i" in harness
    assert "run_archiso -u -i" in harness
    assert "qemu-system-x86_64" in harness
    assert "secure-boot)" not in harness


def test_qemu_uki_smoke_harness_requires_digest_and_ovmf():
    harness = read_text("packaging/recovery/qemu-uki-smoke.sh")

    assert "sha256sum --check" in harness
    assert "BOOTX64.EFI" in harness
    assert "uefi|secure-boot" in harness
    assert "AURASCAN_OVMF_CODE" in harness
    assert "AURASCAN_OVMF_VARS_TEMPLATE" in harness


def test_iso_builder_layers_aurascan_onto_the_maintained_archiso_profile():
    builder = read_text("packaging/recovery/build-iso.sh")
    live_pacman = read_text("packaging/recovery/archiso/airootfs/etc/pacman.conf")

    assert "/usr/share/archiso/configs/releng" in builder
    assert 'cp -a "$archiso_base"/. "$profile"/' in builder
    assert 'cp -a "$profile_source"/airootfs/. "$profile"/airootfs/' in builder
    assert 'cat "$profile_source/profiledef.sh" >> "$profile/profiledef.sh"' in builder
    assert 'sort -u -o "$profile/packages.x86_64"' in builder
    assert "multi-user.target.wants/aurascan-recovery.service" in builder
    assert "git -C \"$repo_root\" archive" in builder
    assert "status --porcelain" in builder
    assert 'cd "$repo_root/packaging/arch"' not in builder
    assert "aurascan-recovery" not in live_pacman
    assert "file://" not in live_pacman
