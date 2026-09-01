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


def test_arch_package_installs_license_and_declares_icon_theme_dependency():
    pkgbuild = read_text("packaging/arch/PKGBUILD")
    srcinfo = read_text("packaging/arch/.SRCINFO")

    assert "'hicolor-icon-theme'" in pkgbuild
    assert "depends = hicolor-icon-theme" in srcinfo
    assert 'install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"' in pkgbuild


def test_recovery_service_cannot_start_on_the_installed_host_by_accident():
    service = read_text("aurascan/assets/aurascan-recovery.service")

    assert "ConditionPathExists=/etc/aurascan/recovery-environment" in service
    assert "ExecStart=/usr/bin/aurascan recovery --runtime" in service
    assert "Before=getty@tty1.service" in service
    assert "Conflicts=getty@tty1.service" in service
    assert "Type=simple" in service
    assert "UMask=0077" in service
    assert "WantedBy=multi-user.target" in service


def test_iso_and_local_uki_use_the_same_bounded_boot_readiness_marker():
    packaged = read_text("aurascan/assets/aurascan-recovery-smoke-marker.service")
    archiso = read_text(
        "packaging/recovery/archiso/airootfs/usr/lib/systemd/system/"
        "aurascan-recovery-smoke-marker.service"
    )

    assert packaged == archiso
    assert "After=aurascan-recovery.service" in packaged
    assert "Requires=aurascan-recovery.service" in packaged
    assert "ConditionVirtualization=vm" in packaged
    assert "ConditionVirtualization=qemu" not in packaged
    assert "ExecStart=/usr/bin/echo AURASCAN_RECOVERY_READY" in packaged
    assert "StandardOutput=journal+console" in packaged
    assert "StandardError=journal+console" in packaged
    assert "SyslogIdentifier=aurascan-recovery-marker" in packaged
    assert "DynamicUser=yes" in packaged
    assert "CapabilityBoundingSet=\n" in packaged
    assert "PrivateNetwork=yes" in packaged


def test_archiso_profile_is_hybrid_and_contains_no_credentials():
    profile = read_text("packaging/recovery/archiso/profiledef.sh")
    packages = read_text("packaging/recovery/archiso/packages.x86_64")
    manifest = json.loads(read_text("aurascan/assets/aurascan-recovery-iso.json"))
    material = "\n".join(
        path.read_text(encoding="utf-8", errors="replace")
        for path in (ROOT / "packaging/recovery").rglob("*")
        if path.is_file()
    )

    assert "bios.syslinux" in profile
    assert "uefi.systemd-boot" in profile
    assert "airootfs_image_tool_options=('-comp' 'xz' '-Xbcj' 'x86' '-b' '1M')" in profile
    assert "aurascan" in packages
    assert not re.search(r"AURASCAN_(?:AI|OPENAI|ANTHROPIC|DEEPSEEK|GEMINI|OPENROUTER)_KEY=", material)
    assert manifest["application_version"] == "0.10.3"
    assert manifest["release_disposition"] == "recovery-bearing"
    assert manifest["version"] == "0.10.3"
    assert manifest["status"] in {"build-required", "release-ready"}
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
    tool_validation = harness.split("for tool in", 1)[1].split("done", 1)[0]
    assert '"$python_bin"' in tool_validation

    assert "snapshot-release" in harness
    assert "--kind iso" in harness
    assert "verify-snapshot --kind iso" in harness
    assert "bios|uefi" in harness
    assert "bios|uefi|secure-boot" not in harness
    assert "AURASCAN_RECOVERY_READY" in harness
    assert 'ulimit -f "$((16 * 1024))"' in harness
    assert "-drive \"file=$iso,media=cdrom,readonly=on\"" in harness
    assert "qemu-system-x86_64" in harness
    assert "secure-boot)" not in harness
    assert 'validate_trusted_executable "$tool"' in harness
    assert 'source "$tool_guard"' in harness
    assert 'validate_trusted_executable "$script_dir/qemu-smoke.sh"' in harness
    assert 'validate_trusted_executable "$tool_guard"' in harness
    assert 'run_smoke_minimal "$python_bin" -I -S "$guard"' in harness
    assert "smoke_environment_is_minimal" in harness
    assert "exec /usr/bin/env -i" in harness
    assert "AURASCAN_RECOVERY_SMOKE_CLEAN_ENV=1" in harness
    for tool in (
        "/usr/bin/bash",
        "/usr/bin/chmod",
        "/usr/bin/cp",
        "/usr/bin/env",
        "/usr/bin/grep",
        "/usr/bin/install",
        "/usr/bin/kill",
        "/usr/bin/mktemp",
        "/usr/bin/qemu-system-x86_64",
        "/usr/bin/readlink",
        "/usr/bin/rm",
        "/usr/bin/setsid",
        "/usr/bin/sleep",
        "/usr/bin/stat",
        "/usr/bin/timeout",
    ):
        assert tool in tool_validation


def test_qemu_uki_smoke_harness_requires_digest_and_ovmf():
    harness = read_text("packaging/recovery/qemu-uki-smoke.sh")
    tool_validation = harness.split("for tool in", 1)[1].split("done", 1)[0]
    assert '"$python_bin"' in tool_validation

    assert "snapshot-release" in harness
    assert "--kind uki" in harness
    assert "verify-snapshot --kind uki" in harness
    assert "BOOTX64.EFI" in harness
    assert '"$mode" == "uefi"' in harness
    assert '"$mode" == "secure-boot"' in harness
    assert "AURASCAN_OVMF_CODE" in harness
    assert "AURASCAN_OVMF_VARS_TEMPLATE" in harness
    assert 'validate_trusted_executable "$tool"' in harness
    assert 'source "$tool_guard"' in harness
    assert 'validate_trusted_executable "$script_dir/qemu-uki-smoke.sh"' in harness
    assert 'validate_trusted_executable "$tool_guard"' in harness
    assert 'run_smoke_minimal "$python_bin" -I -S "$guard"' in harness
    assert "smoke_environment_is_minimal" in harness
    assert "exec /usr/bin/env -i" in harness
    assert "AURASCAN_RECOVERY_SMOKE_CLEAN_ENV=1" in harness
    assert "run_smoke_minimal /usr/bin/timeout" in harness
    assert "/usr/bin/sbverify --list" in harness
    assert '/usr/bin/sbattach "$@"' in harness
    assert "(( status == 124 ))" in harness
    assert "grep -Eq" in harness
    assert "aurascan-recovery-marker" in harness
    for tool in (
        "/usr/bin/bash",
        "/usr/bin/chmod",
        "/usr/bin/cp",
        "/usr/bin/env",
        "/usr/bin/grep",
        "/usr/bin/install",
        "/usr/bin/kill",
        "/usr/bin/mktemp",
        "/usr/bin/qemu-system-x86_64",
        "/usr/bin/readlink",
        "/usr/bin/rm",
        "/usr/bin/sbattach",
        "/usr/bin/sbverify",
        "/usr/bin/setsid",
        "/usr/bin/sleep",
        "/usr/bin/stat",
        "/usr/bin/timeout",
    ):
        assert tool in tool_validation


def test_smoke_tool_guard_validates_root_and_every_path_component():
    guard = read_text("packaging/recovery/smoke-tool-guard.sh")

    assert "validate_trusted_component / directory" in guard
    assert "validate_trusted_component /usr directory" in guard
    assert "validate_trusted_component /usr/bin directory" in guard
    assert "validate_trusted_component /usr/bin/stat executable" in guard
    assert 'validate_trusted_component "$current" directory' in guard
    assert 'validate_trusted_component "$current" executable' in guard
    assert 'component_owner" == "0"' in guard
    assert "8#$component_mode & 8#022" in guard
    assert '[[ ! -L "$component" ]]' in guard


def test_recovery_scenario_record_separates_fixtures_from_live_boot_evidence():
    guide = read_text("packaging/recovery/SCENARIO_VALIDATION.md")
    normalized = " ".join(guide.split())

    assert "Automated deterministic fixtures" in guide
    assert "Actual ISO and UKI boot gates" in guide
    assert "Booted recovery scenarios" in guide
    assert "A readiness marker proves service startup only" in normalized
    assert "currently has no committed generator or harness" in guide
    assert "LUKS2 plus Btrfs" in guide
    assert "ext4 plus LVM2" in guide
    assert "Unknown or ambiguous bootloader" in guide
    assert guide.count("NOT RUN") >= 10
    assert "cannot be converted into a passing release claim" in normalized


def test_iso_builder_layers_aurascan_onto_the_maintained_archiso_profile():
    builder = read_text("packaging/recovery/build-iso.sh")
    live_pacman = read_text("packaging/recovery/archiso/airootfs/etc/pacman.conf")
    build_pacman = read_text("packaging/recovery/archiso/pacman.conf")

    assert "/usr/share/archiso/configs/releng" in builder
    assert 'cp -a -- "$archiso_base"/. "$profile"/' in builder
    assert 'cp -a -- "$profile_source"/airootfs/. "$profile/airootfs"/' in builder
    assert '/usr/bin/cat "$profile_source/profiledef.sh" >> "$profile/profiledef.sh"' in builder
    assert "sed -i -e '/^linux$/d' -e '/^broadcom-wl$/d'" in builder
    assert '/usr/bin/rm -f -- "$profile/airootfs/etc/mkinitcpio.d/linux.preset"' in builder
    assert "vmlinuz-linux-lts" in builder
    assert "initramfs-linux-lts.img" in builder
    assert "still references the removed standard kernel" in builder
    assert '"$sort_bin" -u -o "$profile/packages.x86_64"' in builder
    assert "multi-user.target.wants/aurascan-recovery.service" in builder
    assert 'getty@tty1.service"' in builder
    assert "ln -sfn /dev/null" in builder
    assert '"$git_bin" -C "$repo_root" archive' in builder
    assert "status" in builder and "--porcelain=v1" in builder
    assert "AURASCAN_ARCHISO_ROOT_HELPER" not in builder
    assert "AURASCAN_ARCHISO_CACHE" not in builder
    assert "CacheDir = $package_cache" in builder
    assert "Archiso 89 has an unexpected modules.alias implementation" in builder
    assert 'mkarchiso_runner="$work/trusted-tools/mkarchiso-archiso89"' in builder
    assert '"$gzip_bin" -t "$modalias"' in builder
    assert '"$python_bin" -I -S "$audit_script"' in builder
    assert '--forbid "$repo_root"' in builder
    assert "sudo|doas|pkexec" not in builder
    assert 'if (( EUID != 0 ))' in builder
    assert "--net --fork --kill-child=KILL --forward-signals" in builder
    assert "--reuid=\"$isolated_build_uid\"" in builder
    assert "assert_root_tree_safe \"$package_repo\"" in builder
    assert "resolve().as_uri()" in builder
    assert '"$sha256sum_bin" "$expected_iso"' in builder
    assert 'pkglist.x86_64.txt' in builder
    assert '"aurascan $pkgver-$pkgrel" "$installed_packages"' in builder
    assert '"$sort_bin" -u -- "$installed_packages"' in builder
    assert 'cd "$repo_root/packaging/arch"' not in builder
    assert "aurascan-recovery" not in live_pacman
    assert "file://" not in live_pacman
    assert "https://geo.mirror.pkgbuild.com/$repo/os/$arch" in build_pacman
    assert "https://fastly.mirror.pkgbuild.com/$repo/os/$arch" in build_pacman
    assert "https://geo.mirror.pkgbuild.com/$repo/os/$arch" in live_pacman
    for pacman_config in (build_pacman, live_pacman):
        assert pacman_config.index("https://fastly.mirror.pkgbuild.com") < pacman_config.index(
            "https://geo.mirror.pkgbuild.com"
        )
