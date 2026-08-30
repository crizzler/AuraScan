import io
import json
import os
import stat
import subprocess
from pathlib import Path
from urllib.error import HTTPError

import pytest

from aurascan.core import ai_provider
from aurascan.core import upgrade_preflight
from aurascan.core.models import Severity
from aurascan.core.upgrade_preflight import (
    EXIT_PREFLIGHT_UNAVAILABLE,
    EXIT_PREFLIGHT_DISABLED,
    EXIT_UPGRADE_BLOCKED,
    EXIT_UPGRADE_COMMAND_FAILED_TO_START,
    EXIT_UPGRADE_VERIFICATION_FAILED,
    EXIT_USER_DECLINED,
    ForeignPackageInfo,
    PACMAN_PRINT_FORMAT,
    UpgradeFinding,
    UpgradeOptions,
    build_upgrade_parser,
    UpgradePackage,
    UpgradePlan,
    UpgradePreflightReport,
    SystemSnapshot,
    TrustedExecutable,
    UnsafeUpgradeExecutable,
    analyze_upgrade_risks,
    apply_repository_health_repairs,
    apply_ai_risk_raises,
    apply_ai_upgrade_review,
    build_repository_health_check,
    build_upgrade_ai_prompt,
    build_upgrade_plan,
    collect_foreign_package_info,
    diagnose_upgrade_failure,
    foreign_package_dependency_issues,
    helper_upgrade_command,
    parse_aur_updates,
    parse_pacman_preview,
    parse_pacman_qi,
    parse_pacman_repository_entries,
    parse_shelly_updates,
    options_from_args,
    resolve_aur_helper,
    run_upgrade,
    verify_upgrade_handoff,
)


SUDO_PATH = "/usr/bin/sudo"
PACMAN_PATH = "/usr/bin/pacman"
REAL_CAPTURE_TRUSTED_EXECUTABLE = upgrade_preflight.capture_trusted_executable
REAL_REVALIDATE_TRUSTED_EXECUTABLE = upgrade_preflight.revalidate_trusted_executable


def fake_trusted_executable(name, path):
    return TrustedExecutable(
        name=name,
        path=str(path),
        device=1,
        inode=abs(hash((name, str(path)))) or 1,
        owner=0,
        group=0,
        mode=stat.S_IFREG | 0o755,
    )


@pytest.fixture(autouse=True)
def trusted_upgrade_executables(monkeypatch):
    monkeypatch.setattr(
        upgrade_preflight,
        "capture_trusted_executable",
        lambda name, path: fake_trusted_executable(name, path),
    )
    monkeypatch.setattr(upgrade_preflight, "revalidate_trusted_executable", lambda _executable: None)


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


class FakeRunner:
    def __init__(self, responses=None, default=None):
        self.responses = {tuple(key): value for key, value in (responses or {}).items()}
        self.default = default or subprocess.CompletedProcess([], 0, "", "")
        self.calls = []

    def __call__(self, cmd, **_kwargs):
        cmd = list(cmd)
        self.calls.append(cmd)
        return self.responses.get(tuple(cmd), self.default)


def completed(stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def preview_cmd():
    return [SUDO_PATH, PACMAN_PATH, "-Syu", "--print", "--print-format", PACMAN_PRINT_FORMAT]


def installed_q_cmd(*names):
    return tuple([PACMAN_PATH, "-Q", *names])


def base_snapshot(**overrides):
    data = {
        "running_kernel": "7.1.3-1-cachyos",
        "installed_packages": ["linux-cachyos", "nvidia-dkms", "glibc"],
        "foreign_packages": [],
        "foreign_package_info": [],
        "ignored_packages": [],
        "ignored_groups": [],
        "root_free_mib": 100000,
        "boot_free_mib": 2048,
        "boot_paths": ["/boot"],
        "dkms_packages": [],
        "nvidia_packages": [],
        "zfs_packages": [],
        "virtualbox_packages": [],
        "pacnew_count": 0,
        "pacsave_count": 0,
    }
    data.update(overrides)
    return SystemSnapshot(**data)


def test_parse_pacman_preview_reads_metadata_lists():
    output = "linux-cachyos\t7.1.4-1\tcore\t12345\tglibc bash\tvirtualbox-host-modules\told-kernel\n"

    packages = parse_pacman_preview(output)

    assert packages[0].name == "linux-cachyos"
    assert packages[0].new_version == "7.1.4-1"
    assert packages[0].repo == "core"
    assert packages[0].depends == ["glibc", "bash"]
    assert packages[0].conflicts == ["virtualbox-host-modules"]
    assert packages[0].replaces == ["old-kernel"]


def test_parse_pacman_preview_ignores_sync_noise_without_tabs():
    output = "core.db\nhttps://mirror.example/core.db\nlinux\t7.1\tcore\t1\tglibc\t\t\n"

    packages = parse_pacman_preview(output)

    assert [pkg.name for pkg in packages] == ["linux"]


def test_parse_aur_updates_accepts_helper_formats():
    packages = parse_aur_updates("aur/foo 1.0-1 -> 1.1-1\nbar 2 -> 3\n")

    assert [(pkg.name, pkg.old_version, pkg.new_version) for pkg in packages] == [
        ("foo", "1.0-1", "1.1-1"),
        ("bar", "2", "3"),
    ]


def test_parse_shelly_updates_tolerates_noisy_json_and_reads_aur_array():
    output = "curl progress noise\n{\"Packages\":[],\"Aur\":[{\"Name\":\"demo-bin\",\"OldVersion\":\"1\",\"Version\":\"2\",\"DownloadSize\":\"0.1 MiB\"}]}\n"

    packages = parse_shelly_updates(output)

    assert [(pkg.name, pkg.old_version, pkg.new_version, pkg.package_type) for pkg in packages] == [
        ("demo-bin", "1", "2", "aur")
    ]


def test_parse_pacman_qi_and_collect_foreign_dependency_status():
    qi = """Installed From  : None
Name            : demo-bin
Version         : 1-1
Depends On      : glibc  missing-lib>=2
Provides        : demo
Conflicts With  : demo-git
Install Script  : Yes
"""
    item = parse_pacman_qi(qi)

    assert item.name == "demo-bin"
    assert item.depends == ["glibc", "missing-lib>=2"]
    assert item.conflicts == ["demo-git"]
    assert item.install_script is True

    runner = FakeRunner({
        (PACMAN_PATH, "-Qi", "demo-bin"): completed(qi),
        (PACMAN_PATH, "-T", "glibc", "missing-lib>=2"): completed("missing-lib>=2\n", returncode=127),
    })
    info = collect_foreign_package_info(["demo-bin"], runner=runner)

    assert info[0].missing_depends == ["missing-lib>=2"]


def test_resolve_aur_helper_prefers_paru_then_yay():
    assert resolve_aur_helper("auto", which=lambda name: f"/usr/bin/{name}" if name == "yay" else None) == ("yay", "")
    helper, error = resolve_aur_helper("paru", which=lambda _name: None)
    assert helper == "none"
    assert "paru" in error


def test_resolve_aur_helper_auto_detects_shelly_after_paru_yay():
    assert resolve_aur_helper("auto", which=lambda name: "/usr/bin/shelly" if name == "shelly" else None) == ("shelly", "")
    assert helper_upgrade_command("shelly") == [
        "/usr/bin/shelly",
        "upgrade",
        "all",
        "--no-flatpak",
        "--no-appimage",
    ]
    assert helper_upgrade_command("shelly", shelly_modern=False) == [
        "/usr/bin/shelly",
        "upgrade-all",
        "--no-flatpak",
        "--no-appimage",
    ]


def test_trusted_executable_capture_rejects_symlink_and_writable_binary(tmp_path):
    target = tmp_path / "helper-real"
    target.write_text("fixture\n", encoding="utf-8")
    target.chmod(0o755)
    link = tmp_path / "helper-link"
    link.symlink_to(target)

    with pytest.raises(UnsafeUpgradeExecutable, match="symlink"):
        REAL_CAPTURE_TRUSTED_EXECUTABLE("paru", str(link))

    target.chmod(0o777)
    with pytest.raises(UnsafeUpgradeExecutable, match="root-owned|writable"):
        REAL_CAPTURE_TRUSTED_EXECUTABLE("paru", str(target))


def test_helper_resolution_rejects_hostile_path_entry(monkeypatch):
    def capture(name, path):
        if name == "paru":
            raise UnsafeUpgradeExecutable("fixture helper is user-controlled")
        return fake_trusted_executable(name, path)

    monkeypatch.setattr(upgrade_preflight, "capture_trusted_executable", capture)

    helper, error = resolve_aur_helper("paru", which=lambda _name: "/home/example/bin/paru")

    assert helper == "none"
    assert "trust check" in error


def test_hostile_path_cannot_replace_fixed_sudo_or_pacman(monkeypatch):
    monkeypatch.setenv("PATH", "/home/example/bin")
    runner = FakeRunner({
        tuple(preview_cmd()): completed("glibc\t2.40-1\tcore\t1\t\t\t\n"),
    })

    plan = build_upgrade_plan(
        UpgradeOptions(aur_helper="none"),
        runner=runner,
        which=lambda name: f"/home/example/bin/{name}",
    )

    assert plan.available is True
    assert plan.preview_command[:2] == [SUDO_PATH, PACMAN_PATH]
    assert plan.final_command == [SUDO_PATH, PACMAN_PATH, "-Syu"]
    assert runner.calls == [preview_cmd()]


def test_trusted_executable_revalidation_rejects_inode_replacement(monkeypatch):
    executable = fake_trusted_executable("pacman", PACMAN_PATH)
    replacement = os.stat_result((
        executable.mode,
        executable.inode + 1,
        executable.device,
        1,
        executable.owner,
        executable.group,
        1,
        0,
        0,
        0,
    ))
    monkeypatch.setattr(
        upgrade_preflight,
        "_trusted_executable_stat",
        lambda _name, _path, required_owner=0: replacement,
    )

    with pytest.raises(UnsafeUpgradeExecutable, match="changed after preflight"):
        REAL_REVALIDATE_TRUSTED_EXECUTABLE(executable)


def test_upgrade_options_default_to_enabled_and_read_env():
    args = build_upgrade_parser().parse_args([])

    options = options_from_args(args, {
        "AURASCAN_UPGRADE_PREFLIGHT_ENABLED": "1",
        "AURASCAN_UPGRADE_AUR_HELPER": "yay",
        "AURASCAN_UPGRADE_PREFLIGHT_AI": "0",
        "AURASCAN_KERNEL_MODULE_AUTOPILOT_ENABLED": "1",
    })

    assert options.preflight_enabled is True
    assert options.aur_helper == "yay"
    assert options.no_ai is True
    assert options.config_drift_enabled is True
    assert options.kernel_module_autopilot_enabled is True


def test_upgrade_options_can_disable_kernel_module_autopilot():
    args = build_upgrade_parser().parse_args(["--no-kernel-module-autopilot"])

    options = options_from_args(args, {"AURASCAN_KERNEL_MODULE_AUTOPILOT_ENABLED": "1"})

    assert options.kernel_module_autopilot_enabled is False


def test_upgrade_options_cli_can_override_disabled_config():
    args = build_upgrade_parser().parse_args(["--enable-preflight", "--aur-helper", "none", "--no-config-drift"])

    options = options_from_args(args, {
        "AURASCAN_UPGRADE_PREFLIGHT_ENABLED": "0",
        "AURASCAN_UPGRADE_AUR_HELPER": "yay",
    })

    assert options.preflight_enabled is True
    assert options.aur_helper == "none"
    assert options.config_drift_enabled is False


def test_upgrade_options_read_config_drift_ai_diff_setting():
    args = build_upgrade_parser().parse_args(["--config-drift-ai-diffs"])

    options = options_from_args(args, {
        "AURASCAN_CONFIG_DRIFT_ENABLED": "1",
        "AURASCAN_CONFIG_DRIFT_AI_DIFFS": "never",
    })

    assert options.config_drift_enabled is True
    assert options.config_drift_ai_diffs is True


def test_upgrade_options_trusted_handoff_defaults_on_and_can_be_disabled():
    args = build_upgrade_parser().parse_args([])
    options = options_from_args(args, {"AURASCAN_UPGRADE_TRUSTED_HANDOFF": "1"})

    assert options.trusted_handoff_enabled is True

    disabled = options_from_args(build_upgrade_parser().parse_args(["--no-trusted-handoff"]))

    assert disabled.trusted_handoff_enabled is False


def test_build_upgrade_plan_uses_helper_and_parses_aur_updates():
    runner = FakeRunner({
        tuple(preview_cmd()): completed("glibc\t2.40-1\tcore\t1\t\t\t\n"),
        ("/usr/bin/paru", "-Qua"): completed("aur/demo 1 -> 2\n"),
    })

    plan = build_upgrade_plan(UpgradeOptions(aur_helper="auto"), runner=runner, which=lambda name: "/usr/bin/paru" if name == "paru" else None)

    assert plan.selected_helper == "paru"
    assert plan.final_command == ["/usr/bin/paru", "-Syu"]
    assert plan.repo_packages[0].name == "glibc"
    assert plan.aur_packages[0].name == "demo"


def test_build_upgrade_plan_uses_shelly_and_parses_json_aur_updates():
    runner = FakeRunner({
        tuple(preview_cmd()): completed("glibc\t2.40-1\tcore\t1\t\t\t\n"),
        ("/usr/bin/shelly", "--version"): completed("3.0.1\n"),
        ("/usr/bin/shelly", "list-updates", "aur", "--json"): completed('[{"Name":"demo-bin","OldVersion":"1","Version":"2"}]\n'),
    })

    plan = build_upgrade_plan(UpgradeOptions(aur_helper="shelly"), runner=runner, which=lambda name: "/usr/bin/shelly" if name == "shelly" else None)

    assert plan.selected_helper == "shelly"
    assert plan.final_command == [
        "/usr/bin/shelly",
        "upgrade",
        "all",
        "--no-flatpak",
        "--no-appimage",
    ]
    assert plan.aur_packages[0].name == "demo-bin"


def test_preview_and_helper_queries_revalidate_each_executable(monkeypatch):
    checked = []
    monkeypatch.setattr(
        upgrade_preflight,
        "revalidate_trusted_executable",
        lambda executable: checked.append(executable.name),
    )
    runner = FakeRunner({
        tuple(preview_cmd()): completed("glibc\t2.40-1\tcore\t1\t\t\t\n"),
        ("/usr/bin/shelly", "--version"): completed("3.0.1\n"),
        ("/usr/bin/shelly", "list-updates", "aur", "--json"): completed("[]\n"),
    })

    build_upgrade_plan(
        UpgradeOptions(aur_helper="shelly"),
        runner=runner,
        which=lambda name: "/usr/bin/shelly" if name == "shelly" else None,
    )

    assert checked == ["shelly", "sudo", "pacman", "shelly"]


def test_build_upgrade_plan_supports_legacy_shelly_cli():
    runner = FakeRunner({
        tuple(preview_cmd()): completed("glibc\t2.40-1\tcore\t1\t\t\t\n"),
        ("/usr/bin/shelly", "--version"): completed("2.4.0\n"),
        ("/usr/bin/shelly", "check-updates", "--aur", "--json"): completed(
            '{"Packages":[],"Aur":[{"Name":"demo-bin","OldVersion":"1","Version":"2"}]}\n'
        ),
    })

    plan = build_upgrade_plan(
        UpgradeOptions(aur_helper="shelly"),
        runner=runner,
        which=lambda name: "/usr/bin/shelly" if name == "shelly" else None,
    )

    assert plan.helper_error == ""
    assert plan.final_command == [
        "/usr/bin/shelly",
        "upgrade-all",
        "--no-flatpak",
        "--no-appimage",
    ]


def test_shelly_query_syntax_fallback_updates_final_handoff():
    runner = FakeRunner({
        tuple(preview_cmd()): completed("glibc\t2.40-1\tcore\t1\t\t\t\n"),
        ("/usr/bin/shelly", "--version"): completed("version unavailable\n"),
        ("/usr/bin/shelly", "list-updates", "aur", "--json"): completed(
            stderr="Unrecognized command 'list-updates'.",
            returncode=1,
        ),
        ("/usr/bin/shelly", "check-updates", "--aur", "--json"): completed(
            '{"Packages":[],"Aur":[{"Name":"demo-bin","OldVersion":"1","Version":"2"}]}\n'
        ),
    })

    plan = build_upgrade_plan(
        UpgradeOptions(aur_helper="shelly"),
        runner=runner,
        which=lambda name: "/usr/bin/shelly" if name == "shelly" else None,
    )

    assert plan.helper_error == ""
    assert plan.final_command == [
        "/usr/bin/shelly",
        "upgrade-all",
        "--no-flatpak",
        "--no-appimage",
    ]


def test_explicit_missing_helper_makes_preflight_unavailable():
    plan = build_upgrade_plan(UpgradeOptions(aur_helper="paru"), runner=FakeRunner(), which=lambda _name: None)

    assert plan.available is False
    assert "paru" in plan.preview_error


def test_preview_os_error_makes_preflight_unavailable():
    def broken_runner(_cmd, **_kwargs):
        raise OSError("sudo missing")

    plan = build_upgrade_plan(UpgradeOptions(aur_helper="none"), runner=broken_runner, which=lambda _name: None)

    assert plan.available is False
    assert "sudo missing" in plan.preview_error


def test_deterministic_rules_cover_system_breakage_risks():
    plan = UpgradePlan(
        repo_packages=[
            UpgradePackage("linux-cachyos", "7.1.4-1"),
            UpgradePackage("mkinitcpio", "40-1"),
            UpgradePackage("glibc", "2.40-1", conflicts=["old-lib"], replaces=["glibc-old"]),
        ],
        aur_packages=[],
        replacements=["glibc-old"],
        conflicts=["old-lib"],
        selected_helper="none",
        helper_error="no supported AUR helper found",
        final_command=[SUDO_PATH, PACMAN_PATH, "-Syu"],
    )
    snapshot = base_snapshot(
        boot_free_mib=128,
        root_free_mib=1024,
        installed_packages=["linux-cachyos", "nvidia-dkms", "glibc", "glibc-old"],
        dkms_packages=["nvidia-dkms"],
        nvidia_packages=["nvidia-utils"],
        ignored_packages=["linux-cachyos"],
        foreign_packages=["unityhub"],
        pacnew_count=2,
    )

    rule_ids = {finding.rule_id for finding in analyze_upgrade_risks(plan, snapshot)}

    assert {
        "UPG-AUR-HELPER-UNAVAILABLE",
        "UPG-BOOT-SPACE",
        "UPG-ROOT-SPACE",
        "UPG-KERNEL-REBOOT",
        "UPG-KERNEL-MODULES",
        "UPG-CACHYOS-KERNEL",
        "UPG-BOOTLOADER-INITRAMFS",
        "UPG-IGNORED-PACKAGES",
        "UPG-TRANSACTION-REPLACES",
        "UPG-TRANSACTION-CONFLICTS",
        "UPG-AUR-REBUILD-RISK",
        "UPG-AUR-NOT-CHECKED",
        "UPG-PACNEW-CONFIG",
    }.issubset(rule_ids)


def test_no_kernel_module_autopilot_keeps_legacy_module_warning():
    plan = UpgradePlan(repo_packages=[UpgradePackage("linux-cachyos", "7.1.4-1")])
    snap = base_snapshot(dkms_packages=["nvidia-dkms"], nvidia_packages=["nvidia-utils"])

    rule_ids = {finding.rule_id for finding in analyze_upgrade_risks(plan, snap, kernel_module_autopilot_enabled=False)}

    assert "UPG-KERNEL-MODULES" in rule_ids


def test_manjaro_snapshot_gets_low_severity_aur_timing_advisory():
    plan = UpgradePlan(repo_packages=[UpgradePackage("glibc", "2.40-1")])
    snap = base_snapshot(distro_info={"id": "manjaro", "support_tier": "supported_with_caveats"})

    findings = analyze_upgrade_risks(plan, snap)
    advisory = next(finding for finding in findings if finding.rule_id == "UPG-MANJARO-AUR-CAVEAT")

    assert advisory.severity == Severity.LOW
    assert "Manjaro" in advisory.title
    assert "delays repository updates" in advisory.why_it_matters


def test_replacement_metadata_only_does_not_create_high_risk_false_alarm():
    plan = UpgradePlan(
        repo_packages=[
            UpgradePackage("nvidia-utils", "610.43.03-1", replaces=["nvidia-libgl"]),
            UpgradePackage("linux-cachyos", "7.1.3-2", replaces=["linux-cachyos-lto"]),
        ],
        replacements=["nvidia-libgl", "linux-cachyos-lto"],
        final_command=[SUDO_PATH, PACMAN_PATH, "-Syu"],
    )
    report = UpgradePreflightReport(plan=plan, snapshot=base_snapshot(installed_packages=["linux-cachyos", "nvidia-utils"]))

    findings = analyze_upgrade_risks(plan, report.snapshot)
    report.findings = findings

    assert "UPG-TRANSACTION-REPLACES" not in {finding.rule_id for finding in findings}
    assert report.transaction_change_count() == 0
    assert "Removals/Replacements: 0" in report.render_terminal(use_color=False)


def test_installed_replacement_target_is_reported_without_always_forcing_high():
    plan = UpgradePlan(
        repo_packages=[UpgradePackage("demo-new", "2-1", replaces=["demo-old"])],
        replacements=["demo-old"],
        final_command=[SUDO_PATH, PACMAN_PATH, "-Syu"],
    )

    findings = analyze_upgrade_risks(plan, base_snapshot(installed_packages=["linux-cachyos", "demo-old"]))

    replacement = next(finding for finding in findings if finding.rule_id == "UPG-TRANSACTION-REPLACES")
    assert replacement.severity == Severity.MEDIUM
    assert "installed replacement targets=demo-old" in replacement.evidence


def test_repository_conflict_is_explained_as_package_metadata_not_aurascan_error():
    plan = UpgradePlan(
        repo_packages=[UpgradePackage(
            "gcc",
            "16.1-5",
            repo="cachyos-v3",
            conflicts=["gcc-multilib"],
            replaces=["gcc-multilib"],
        )],
        replacements=["gcc-multilib"],
        conflicts=["gcc-multilib"],
    )

    findings = analyze_upgrade_risks(plan, base_snapshot(installed_packages=["gcc"]))
    conflict = next(finding for finding in findings if finding.rule_id == "UPG-TRANSACTION-CONFLICTS")

    assert conflict.title == "Repository package transition metadata was detected."
    assert "not AuraScan" in conflict.summary
    assert "cachyos-v3/gcc replaces gcc-multilib; conflicts with gcc-multilib" in conflict.evidence


def test_ai_prompt_distinguishes_repository_transitions_from_aurascan_errors():
    plan = UpgradePlan(
        repo_packages=[UpgradePackage("gcc", "16.1-5", repo="cachyos-v3", conflicts=["gcc-multilib"])],
        conflicts=["gcc-multilib"],
    )
    report = UpgradePreflightReport(plan=plan, snapshot=base_snapshot())
    report.findings = analyze_upgrade_risks(plan, report.snapshot)

    prompt = build_upgrade_ai_prompt(report)

    assert '"declared_conflicts": ["gcc-multilib"]' in prompt
    assert '"package_transitions": ["cachyos-v3/gcc conflicts with gcc-multilib"]' in prompt
    assert "originate in repository package metadata, not AuraScan" in prompt
    assert "Do not claim manual conflict resolution is required" in prompt


def test_foreign_dependency_check_reports_concrete_missing_deps_and_conflicts():
    plan = UpgradePlan(repo_packages=[UpgradePackage("demo-git", "2")])
    snapshot = base_snapshot(
        foreign_packages=["demo-bin"],
        foreign_package_info=[
            parse_pacman_qi("""Name : demo-bin
Version : 1
Depends On : missing-lib
Conflicts With : demo-git
""")
        ],
    )
    snapshot.foreign_package_info[0].missing_depends = ["missing-lib"]

    issues = foreign_package_dependency_issues(snapshot, plan)
    rule_ids = {finding.rule_id for finding in analyze_upgrade_risks(plan, snapshot)}

    assert {"missing_dependency", "conflicts_with_upgrade"} == {issue["kind"] for issue in issues}
    assert "UPG-AUR-DEPENDENCY-MISSING" in rule_ids
    assert "UPG-AUR-CONFLICTS" in rule_ids


def test_preview_failure_returns_only_unavailable_finding():
    plan = UpgradePlan(preview_error="pacman failed")

    findings = analyze_upgrade_risks(plan, base_snapshot())

    assert [finding.rule_id for finding in findings] == ["UPG-PREVIEW-FAILED"]
    assert findings[0].severity == Severity.CRITICAL


def test_planned_aur_build_creates_non_overridable_blocking_finding():
    plan = UpgradePlan(
        aur_packages=[UpgradePackage("demo-bin", "2", "1", package_type="aur")],
        selected_helper="paru",
        final_command=["/usr/bin/paru", "-Syu"],
        command_source="paru",
    )
    report = UpgradePreflightReport(plan=plan, snapshot=base_snapshot())
    report.findings = analyze_upgrade_risks(plan, report.snapshot)

    finding = next(item for item in report.findings if item.rule_id == "UPG-AUR-BUILD-UNSCANNED")

    assert finding.severity == Severity.CRITICAL
    assert finding.blocking is True
    assert report.blocks_upgrade is True
    assert report.action == "block"
    assert report.to_dict()["risk_summary"]["blocks_upgrade"] is True
    assert "aurascan-makepkg" in finding.recommended_action


def test_repository_health_detects_empty_mirrorlist_with_backup(tmp_path):
    pacman_conf = tmp_path / "pacman.conf"
    mirrorlist = tmp_path / "mirrorlist"
    backup = tmp_path / "mirrorlist-backup"
    pacman_conf.write_text("[options]\nColor\n[core]\nInclude = mirrorlist\n[extra]\nInclude = mirrorlist\n", encoding="utf-8")
    mirrorlist.write_text("#Server = https://example.invalid/$repo/os/$arch\n", encoding="utf-8")
    backup.write_text("Server = https://mirror.example/$repo/os/$arch\n", encoding="utf-8")

    check = build_repository_health_check(pacman_conf)

    assert check.status == "repair_available"
    assert check.fixable_issues[0].repositories == ["core", "extra"]
    assert check.fixable_issues[0].include_path == str(mirrorlist)
    assert check.fixable_issues[0].backup_path == str(backup)


def test_parse_pacman_repository_entries_ignores_commented_repos(tmp_path):
    entries = parse_pacman_repository_entries(
        "#[testing]\n#Include = mirrorlist\n[core]\nInclude = mirrorlist\nServer = https://local/$repo/os/$arch\n",
        base_dir=tmp_path,
    )

    assert [entry.name for entry in entries] == ["core"]
    assert entries[0].server_count == 1
    assert entries[0].includes == [tmp_path / "mirrorlist"]


def test_apply_repository_health_repairs_restores_from_backup(tmp_path):
    pacman_conf = tmp_path / "pacman.conf"
    mirrorlist = tmp_path / "mirrorlist"
    backup = tmp_path / "mirrorlist-backup"
    pacman_conf.write_text("[core]\nInclude = mirrorlist\n", encoding="utf-8")
    mirrorlist.write_text("#Server = https://disabled.invalid/$repo/os/$arch\n", encoding="utf-8")
    backup.write_text("Server = https://mirror.example/$repo/os/$arch\n", encoding="utf-8")
    check = build_repository_health_check(pacman_conf)

    result = apply_repository_health_repairs(check, backup_root=tmp_path / "backups")

    assert result.success is True
    assert "Server = https://mirror.example" in mirrorlist.read_text(encoding="utf-8")
    assert (Path(result.backup_dir) / "mirrorlist").exists()
    assert (Path(result.backup_dir) / "manifest.json").exists()


def test_preview_no_servers_finding_points_to_aurascan_repair(tmp_path):
    pacman_conf = tmp_path / "pacman.conf"
    mirrorlist = tmp_path / "mirrorlist"
    backup = tmp_path / "mirrorlist-backup"
    pacman_conf.write_text("[core]\nInclude = mirrorlist\n", encoding="utf-8")
    mirrorlist.write_text("#Server = https://disabled.invalid/$repo/os/$arch\n", encoding="utf-8")
    backup.write_text("Server = https://mirror.example/$repo/os/$arch\n", encoding="utf-8")
    check = build_repository_health_check(pacman_conf)
    plan = UpgradePlan(preview_error="pacman upgrade preview failed: error: no servers configured for repository")

    findings = analyze_upgrade_risks(plan, base_snapshot(), repository_health=check)

    assert findings[0].rule_id == "UPG-PREVIEW-FAILED"
    assert "Let AuraScan restore active mirrorlist servers from backup" in findings[0].recommended_action
    assert str(mirrorlist) in findings[0].evidence


def test_ai_raise_only_escalates_known_rule_without_replacing_deterministic_action():
    report = UpgradePreflightReport(
        plan=UpgradePlan(),
        snapshot=base_snapshot(),
        findings=[
            UpgradeFinding(
                "UPG-ROOT-SPACE",
                Severity.LOW,
                "Root low",
                "summary",
                "why",
                "action",
            )
        ],
    )

    applied = apply_ai_risk_raises(report, {
        "summary": "The existing space finding warrants more attention.",
        "risk_raises": [
            {"target_rule_id": "UPG-ROOT-SPACE", "severity": "HIGH", "reason": "Multiple bounded space signals overlap."},
        ]
    })

    assert applied == 1
    assert report.findings[0].severity == Severity.HIGH
    assert report.findings[0].recommended_action == "action"
    assert len(report.findings) == 1
    assert report.highest_severity == Severity.HIGH


def test_terminal_renders_high_severity_findings_before_medium_notices():
    report = UpgradePreflightReport(
        plan=UpgradePlan(final_command=[SUDO_PATH, PACMAN_PATH, "-Syu"]),
        snapshot=base_snapshot(),
        findings=[
            UpgradeFinding("UPG-KERNEL-REBOOT", Severity.MEDIUM, "Medium notice", "summary", "why", "action"),
            UpgradeFinding("UPG-TRANSACTION-REPLACES", Severity.HIGH, "High risk", "summary", "why", "action"),
        ],
    )

    rendered = report.render_terminal(use_color=False)

    assert rendered.index("1. High risk [HIGH]") < rendered.index("2. Medium notice [MEDIUM]")


def test_ai_raise_without_a_known_deterministic_target_is_rejected():
    report = UpgradePreflightReport(
        plan=UpgradePlan(selected_helper="shelly", aur_packages=[]),
        snapshot=base_snapshot(
            foreign_packages=["demo-bin"],
            foreign_package_info=[ForeignPackageInfo("demo-bin", depends=["glibc"])],
        ),
        findings=[],
    )

    with pytest.raises(ValueError, match="known deterministic rule"):
        apply_ai_risk_raises(report, {
            "summary": "A foreign package count was observed.",
            "risk_raises": [{
                "target_rule_id": "UPG-INVENTED-RULE",
                "severity": "MEDIUM",
                "reason": "A foreign package was not shown in the upgrade list.",
            }],
        })

    assert report.findings == []


def test_ai_equal_severity_does_not_rewrite_existing_finding():
    report = UpgradePreflightReport(
        plan=UpgradePlan(selected_helper="shelly", aur_packages=[]),
        snapshot=base_snapshot(
            foreign_packages=["demo-bin"],
            foreign_package_info=[ForeignPackageInfo("demo-bin", depends=["glibc"])],
        ),
        findings=[
            UpgradeFinding(
                "UPG-AUR-REBUILD-RISK",
                Severity.MEDIUM,
                "Foreign/AUR packages may need rebuilds after this upgrade.",
                "summary",
                "why",
                "action",
            )
        ],
    )

    original_summary = report.findings[0].summary
    applied = apply_ai_risk_raises(report, {
        "summary": "The existing rebuild finding remains advisory.",
        "risk_raises": [
            {
                "target_rule_id": "UPG-AUR-REBUILD-RISK",
                "severity": "MEDIUM",
                "reason": "Foreign packages were not shown in the helper result.",
            }
        ]
    })

    assert applied == 0
    assert [finding.rule_id for finding in report.findings] == ["UPG-AUR-REBUILD-RISK"]
    assert report.findings[0].summary == original_summary


def test_ai_cannot_escalate_metadata_only_transition_or_demand_manual_resolution(monkeypatch):
    monkeypatch.setenv("AURASCAN_AI_ENABLED", "1")
    monkeypatch.setenv("AURASCAN_AI_PROVIDER", "openai")
    monkeypatch.setenv("AURASCAN_OPENAI_API_KEY", "fixture-only-value")
    plan = UpgradePlan(
        repo_packages=[UpgradePackage("gcc", "16.1-5", repo="cachyos-v3", conflicts=["gcc-multilib"])],
        conflicts=["gcc-multilib"],
    )
    report = UpgradePreflightReport(plan=plan, snapshot=base_snapshot())
    report.findings = analyze_upgrade_risks(plan, report.snapshot)

    response = {
        "summary": "Package conflicts need manual resolution.",
        "risk_raises": [{
            "target_rule_id": "UPG-TRANSACTION-CONFLICTS",
            "severity": "HIGH",
            "reason": "declared package conflict",
        }],
    }

    def fake_urlopen(_req, timeout):
        return FakeResponse({"choices": [{"message": {"content": json.dumps(response)}}]})

    apply_ai_upgrade_review(report, urlopen=fake_urlopen)

    conflict = next(finding for finding in report.findings if finding.rule_id == "UPG-TRANSACTION-CONFLICTS")
    assert conflict.severity == Severity.MEDIUM
    assert report.ai_review["raises_applied"] == 0
    assert "metadata alone does not require manual conflict resolution" in report.ai_review["summary"]
    assert "not AuraScan" in report.ai_review["summary"]


def test_ai_invalid_json_is_non_blocking_note(monkeypatch):
    monkeypatch.setenv("AURASCAN_AI_ENABLED", "1")
    monkeypatch.setenv("AURASCAN_AI_PROVIDER", "openai")
    monkeypatch.setenv("AURASCAN_OPENAI_API_KEY", "fixture-only-value")
    report = UpgradePreflightReport(plan=UpgradePlan(), snapshot=base_snapshot(), findings=[])

    def fake_urlopen(_req, timeout):
        return FakeResponse({"choices": [{"message": {"content": "not json"}}]})

    apply_ai_upgrade_review(report, urlopen=fake_urlopen)

    assert report.ai_review["status"] == "invalid_response"
    assert report.ai_review["error"] == "AI response rejected by guarded advisory contract"
    assert report.action == "continue"


@pytest.mark.parametrize(
    ("content", "forbidden_marker"),
    [
        (
            json.dumps({"summary": "\x1b[31m[OK] approved\x1b[0m", "risk_raises": []}),
            "approved",
        ),
        (
            json.dumps({
                "summary": "A bounded review was attempted.",
                "risk_raises": [{
                    "target_rule_id": "UPG-ROOT-SPACE",
                    "severity": "HIGH",
                    "reason": "See https://example.invalid/payload for details.",
                }],
            }),
            "example.invalid",
        ),
        (
            json.dumps({
                "summary": "A bounded review was attempted.",
                "risk_raises": [{
                    "target_rule_id": "UPG-ROOT-SPACE",
                    "severity": "HIGH",
                    "reason": "Run curl to inspect this issue.",
                }],
            }),
            "curl",
        ),
        (
            json.dumps({
                "summary": "A bounded review was attempted.",
                "risk_raises": [{
                    "target_rule_id": "UPG-ROOT-SPACE",
                    "severity": "HIGH",
                    "reason": "token=fixture-secret",
                }],
            }),
            "fixture-secret",
        ),
        (
            json.dumps({"summary": "The upgrade is safe.", "risk_raises": []}),
            "upgrade is safe",
        ),
        (
            json.dumps({"summary": "Bounded review.", "risk_raises": [], "extra": "do-not-persist"}),
            "do-not-persist",
        ),
        (
            json.dumps({
                "summary": "Bounded review.",
                "risk_raises": [{
                    "target_rule_id": "UPG-ROOT-SPACE",
                    "severity": "HIGH",
                    "reason": "Overlapping signals warrant attention.",
                    "recommended_action": "do-not-persist",
                }],
            }),
            "do-not-persist",
        ),
        (
            json.dumps({
                "summary": "Bounded review.",
                "risk_raises": [{
                    "target_rule_id": "UPG-INVENTED-RULE",
                    "severity": "HIGH",
                    "reason": "Invented target should not be accepted.",
                }],
            }),
            "UPG-INVENTED-RULE",
        ),
        (
            json.dumps({
                "summary": "Bounded review.",
                "risk_raises": [{
                    "target_rule_id": "UPG-ROOT-SPACE",
                    "severity": "CRITICAL",
                    "reason": "Out-of-contract severity.",
                }],
            }),
            "Out-of-contract",
        ),
        (
            json.dumps({
                "summary": "Bounded review.",
                "risk_raises": [
                    {
                        "target_rule_id": "UPG-ROOT-SPACE",
                        "severity": "HIGH",
                        "reason": "Too many entries.",
                    }
                    for _index in range(13)
                ],
            }),
            "Too many entries",
        ),
        (
            json.dumps({
                "summary": "Bounded review.",
                "risk_raises": [
                    {
                        "target_rule_id": "UPG-ROOT-SPACE",
                        "severity": "MEDIUM",
                        "reason": "First duplicate target.",
                    },
                    {
                        "target_rule_id": "UPG-ROOT-SPACE",
                        "severity": "HIGH",
                        "reason": "Second duplicate target.",
                    },
                ],
            }),
            "Second duplicate target",
        ),
        (
            '{"summary":"ordinary","summary":"token=fixture-secret","risk_raises":[]}',
            "fixture-secret",
        ),
        (
            '{"summary":"ordinary","risk_raises":[{"target_rule_id":"UPG-ROOT-SPACE",'
            '"target_rule_id":"UPG-INVENTED-RULE","severity":"HIGH","reason":"duplicate"}]}',
            "UPG-INVENTED-RULE",
        ),
        ('{"summary":NaN,"risk_raises":[]}', "NaN"),
        ('{"summary":"unterminated",', "unterminated"),
        (
            json.dumps({"summary": "oversized-marker-" + ("x" * (17 * 1024)), "risk_raises": []}),
            "oversized-marker",
        ),
    ],
    ids=[
        "ansi",
        "url",
        "command",
        "credential",
        "unsupported-safe-claim",
        "extra-top-level-key",
        "extra-risk-key",
        "unknown-rule-id",
        "invalid-severity",
        "too-many-risks",
        "duplicate-risk-target",
        "duplicate-top-level-key",
        "duplicate-nested-key",
        "nonfinite",
        "malformed",
        "oversized",
    ],
)
def test_upgrade_ai_rejects_hostile_or_out_of_contract_output_without_persisting_it(
    monkeypatch,
    content,
    forbidden_marker,
):
    monkeypatch.setenv("AURASCAN_AI_ENABLED", "1")
    monkeypatch.setenv("AURASCAN_AI_PROVIDER", "openai")
    monkeypatch.setenv("AURASCAN_OPENAI_API_KEY", "fixture-only-value")
    finding = UpgradeFinding(
        "UPG-ROOT-SPACE",
        Severity.LOW,
        "Root low",
        "deterministic summary",
        "deterministic reason",
        "deterministic action",
    )
    report = UpgradePreflightReport(
        plan=UpgradePlan(),
        snapshot=base_snapshot(),
        findings=[finding],
    )

    def fake_urlopen(_req, timeout):
        return FakeResponse({"choices": [{"message": {"content": content}}]})

    apply_ai_upgrade_review(report, urlopen=fake_urlopen)

    assert report.ai_review == {
        "enabled": True,
        "provider": "openai",
        "status": "invalid_response",
        "error": "AI response rejected by guarded advisory contract",
    }
    assert finding.severity == Severity.LOW
    assert finding.summary == "deterministic summary"
    persisted = report.to_json() + report.render_terminal(use_color=False, verbose=True)
    assert forbidden_marker not in persisted


def test_upgrade_ai_provider_error_does_not_persist_raw_exception(monkeypatch):
    monkeypatch.setenv("AURASCAN_AI_ENABLED", "1")
    monkeypatch.setenv("AURASCAN_AI_PROVIDER", "openai")
    monkeypatch.setenv("AURASCAN_OPENAI_API_KEY", "fixture-only-value")
    report = UpgradePreflightReport(plan=UpgradePlan(), snapshot=base_snapshot())

    def fake_urlopen(_req, timeout):
        raise AssertionError("token=fixture-secret https://example.invalid/provider")

    apply_ai_upgrade_review(report, urlopen=fake_urlopen)

    assert report.ai_review == {
        "enabled": True,
        "provider": "openai",
        "status": "error",
        "error": "AI provider request failed",
    }
    persisted = report.to_json() + report.render_terminal(use_color=False)
    assert "fixture-secret" not in persisted
    assert "example.invalid" not in persisted


def test_upgrade_ai_config_error_does_not_persist_raw_configuration(monkeypatch):
    monkeypatch.setenv("AURASCAN_AI_ENABLED", "1")
    monkeypatch.setenv("AURASCAN_AI_PROVIDER", "token=fixture-secret")
    report = UpgradePreflightReport(plan=UpgradePlan(), snapshot=base_snapshot())

    apply_ai_upgrade_review(report)

    assert report.ai_review == {
        "enabled": False,
        "status": "config_error",
        "error": "AI provider configuration is invalid",
    }
    assert "fixture-secret" not in report.to_json()


def test_keyless_local_ai_reaches_upgrade_review(monkeypatch):
    monkeypatch.setenv("AURASCAN_AI_ENABLED", "1")
    monkeypatch.setenv("AURASCAN_AI_PROVIDER", "llamacpp")
    monkeypatch.setenv("AURASCAN_AI_MODEL", "aurascan-local")
    monkeypatch.delenv("AURASCAN_LOCAL_AI_API_KEY", raising=False)
    report = UpgradePreflightReport(plan=UpgradePlan(), snapshot=base_snapshot(), findings=[])
    seen = {}

    def fake_urlopen(request, timeout):
        seen["url"] = request.full_url
        seen["headers"] = dict(request.header_items())
        return FakeResponse({
            "choices": [{"message": {"content": json.dumps({"summary": "Reviewed locally.", "risk_raises": []})}}]
        })

    apply_ai_upgrade_review(report, urlopen=fake_urlopen)

    assert report.ai_review["status"] == "ok"
    assert report.ai_review["summary"] == "Reviewed locally."
    assert seen["url"] == "http://127.0.0.1:8080/v1/chat/completions"
    assert "Authorization" not in seen["headers"]


def test_upgrade_dry_run_never_runs_final_command():
    runner = FakeRunner({tuple(preview_cmd()): completed("glibc\t2.40-1\tcore\t1\t\t\t\n")})
    stdout = io.StringIO()

    status = run_upgrade(
        ["--dry-run", "--no-ai", "--aur-helper", "none"],
        runner=runner,
        snapshot=base_snapshot(),
        stdout=stdout,
    )

    assert status == 0
    assert [SUDO_PATH, PACMAN_PATH, "-Syu"] not in runner.calls
    assert "Upgrade Preflight" in stdout.getvalue()


def test_upgrade_shows_progress_before_preflight_report():
    runner = FakeRunner({tuple(preview_cmd()): completed("glibc\t2.40-1\tcore\t1\t\t\t\n")})
    stdout = io.StringIO()

    status = run_upgrade(
        ["--dry-run", "--no-ai", "--aur-helper", "none"],
        runner=runner,
        snapshot=base_snapshot(),
        stdout=stdout,
    )
    output = stdout.getvalue()

    assert status == 0
    assert output.index("[AuraScan] Starting upgrade preflight.") < output.index("[AuraScan] Upgrade Preflight")
    assert "[AuraScan] Building pacman upgrade preview. This may sync package databases and can take a moment." in output
    assert "[AuraScan] Collecting local system facts." in output
    assert "[AuraScan] Checking kernel and external module compatibility." in output


def test_upgrade_dry_run_invokes_config_drift_when_root_is_explicit():
    runner = FakeRunner({tuple(preview_cmd()): completed("glibc\t2.40-1\tcore\t1\t\t\t\n")})
    calls = []

    def drift_runner(argv, **_kwargs):
        calls.append(argv)
        return 0

    status = run_upgrade(
        ["--dry-run", "--no-ai", "--aur-helper", "none"],
        runner=runner,
        snapshot=base_snapshot(),
        stdout=io.StringIO(),
        config_drift_root=Path("/tmp/etc"),
        config_drift_runner=drift_runner,
    )

    assert status == 0
    assert calls == [["--root", "/tmp/etc", "--no-ai", "--dry-run"]]


def test_upgrade_disabled_config_does_not_run_final_command(monkeypatch):
    monkeypatch.setenv("AURASCAN_UPGRADE_PREFLIGHT_ENABLED", "0")
    runner = FakeRunner({tuple(preview_cmd()): completed("glibc\t2.40-1\tcore\t1\t\t\t\n")})
    stdout = io.StringIO()

    status = run_upgrade(
        ["--no-ai", "--aur-helper", "none"],
        runner=runner,
        snapshot=base_snapshot(),
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert status == EXIT_PREFLIGHT_DISABLED
    assert [SUDO_PATH, PACMAN_PATH, "-Syu"] not in runner.calls
    assert "Upgrade preflight did not run" in stdout.getvalue()


def test_upgrade_high_risk_prompt_decline_skips_final_command():
    runner = FakeRunner({tuple(preview_cmd()): completed("glibc\t2.40-1\tcore\t1\t\t\t\n")})

    status = run_upgrade(
        ["--no-ai", "--aur-helper", "none"],
        runner=runner,
        snapshot=base_snapshot(ignored_packages=["glibc"]),
        input_func=lambda _prompt: "",
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )

    assert status == EXIT_USER_DECLINED
    assert [SUDO_PATH, PACMAN_PATH, "-Syu"] not in runner.calls


def test_upgrade_yes_runs_final_command():
    runner = FakeRunner({
        tuple(preview_cmd()): completed("glibc\t2.40-1\tcore\t1\t\t\t\n"),
        (SUDO_PATH, PACMAN_PATH, "-Syu"): completed(returncode=0),
        installed_q_cmd("glibc"): completed("glibc 2.40-1\n"),
    })

    status = run_upgrade(
        ["--yes", "--no-ai", "--aur-helper", "none"],
        runner=runner,
        snapshot=base_snapshot(ignored_packages=["glibc"]),
        stdout=io.StringIO(),
    )

    assert status == 0
    assert [SUDO_PATH, PACMAN_PATH, "-Syu"] in runner.calls


def test_final_handoff_revalidates_executable_and_refuses_replacement(monkeypatch):
    sudo_checks = 0

    def revalidate(executable):
        nonlocal sudo_checks
        if executable.name == "sudo":
            sudo_checks += 1
            if sudo_checks > 1:
                raise UnsafeUpgradeExecutable("trusted sudo executable changed after preflight")

    monkeypatch.setattr(upgrade_preflight, "revalidate_trusted_executable", revalidate)
    runner = FakeRunner({
        tuple(preview_cmd()): completed("glibc\t2.40-1\tcore\t1\t\t\t\n"),
        (SUDO_PATH, PACMAN_PATH, "-Syu"): completed(returncode=0),
    })
    stderr = io.StringIO()

    status = run_upgrade(
        ["--yes", "--no-ai", "--aur-helper", "none"],
        runner=runner,
        snapshot=base_snapshot(),
        stdout=io.StringIO(),
        stderr=stderr,
    )

    assert status == EXIT_UPGRADE_COMMAND_FAILED_TO_START
    assert [SUDO_PATH, PACMAN_PATH, "-Syu"] not in runner.calls
    assert "changed after preflight" in stderr.getvalue()


def test_ai_review_cannot_override_aur_build_blocker(monkeypatch):
    monkeypatch.setenv("AURASCAN_AI_ENABLED", "1")
    monkeypatch.setenv("AURASCAN_AI_PROVIDER", "openai")
    monkeypatch.setenv("AURASCAN_OPENAI_API_KEY", "fixture-only-value")
    runner = FakeRunner({
        tuple(preview_cmd()): completed("glibc\t2.40-1\tcore\t1\t\t\t\n"),
        ("/usr/bin/paru", "-Qua"): completed("aur/demo-bin 1 -> 2\n"),
        ("/usr/bin/paru", "-Syu"): completed(returncode=0),
    })
    provider_calls = []

    def fake_urlopen(_request, timeout):
        provider_calls.append(timeout)
        response = {
            "summary": "The deterministic source-build blocker remains authoritative.",
            "risk_raises": [{
                "target_rule_id": "UPG-AUR-BUILD-UNSCANNED",
                "severity": "HIGH",
                "reason": "The unscanned source-build path remains unresolved.",
            }],
        }
        return FakeResponse({"choices": [{"message": {"content": json.dumps(response)}}]})

    stdout = io.StringIO()
    status = run_upgrade(
        ["--yes", "--aur-helper", "paru"],
        runner=runner,
        which=lambda name: "/usr/bin/paru" if name == "paru" else None,
        snapshot=base_snapshot(),
        stdout=stdout,
        stderr=io.StringIO(),
        urlopen=fake_urlopen,
    )

    assert status == EXIT_UPGRADE_BLOCKED
    assert provider_calls == [20]
    assert ["/usr/bin/paru", "-Syu"] not in runner.calls
    assert "cannot clear AuraScan's deterministic AUR source-build blocker" in stdout.getvalue()


def test_helper_with_no_aur_updates_uses_repo_only_pacman_handoff():
    runner = FakeRunner({
        tuple(preview_cmd()): completed("glibc\t2.40-1\tcore\t1\t\t\t\n"),
        ("/usr/bin/shelly", "--version"): completed("3.0.1\n"),
        ("/usr/bin/shelly", "list-updates", "aur", "--json"): completed("[]\n"),
        (SUDO_PATH, PACMAN_PATH, "-Syu"): completed(returncode=0),
        installed_q_cmd("glibc"): completed("glibc 2.40-1\n"),
    })
    stdout = io.StringIO()

    status = run_upgrade(
        ["--no-ai", "--aur-helper", "shelly"],
        runner=runner,
        which=lambda name: "/usr/bin/shelly" if name == "shelly" else None,
        snapshot=base_snapshot(),
        stdout=stdout,
    )

    assert status == 0
    assert [SUDO_PATH, PACMAN_PATH, "-Syu"] in runner.calls
    assert not any(call and call[0] == "/usr/bin/shelly" and "upgrade" in call for call in runner.calls)
    assert f"Planned command: {SUDO_PATH} {PACMAN_PATH} -Syu" in stdout.getvalue()
    assert "Package-manager handoff" in stdout.getvalue()
    assert "configured repositories, not AuraScan" in stdout.getvalue()
    assert "Upgrade transaction verified" in stdout.getvalue()
    assert "mirror-specific NotFound/404 messages" in stdout.getvalue()


def test_shelly_planned_aur_build_is_blocked_even_with_yes():
    runner = FakeRunner({
        tuple(preview_cmd()): completed("glibc\t2.40-1\tcore\t1\t\t\t\n"),
        ("/usr/bin/shelly", "--version"): completed("3.0.1\n"),
        ("/usr/bin/shelly", "list-updates", "aur", "--json"): completed(
            '[{"Name":"demo-bin","OldVersion":"1","Version":"2"}]\n'
        ),
        ("/usr/bin/shelly", "upgrade", "all", "--no-flatpak", "--no-appimage"): completed(returncode=0),
    })
    stderr = io.StringIO()

    status = run_upgrade(
        ["--yes", "--no-ai", "--aur-helper", "shelly"],
        runner=runner,
        which=lambda name: "/usr/bin/shelly" if name == "shelly" else None,
        snapshot=base_snapshot(),
        stdout=io.StringIO(),
        stderr=stderr,
    )

    assert status == EXIT_UPGRADE_BLOCKED
    assert ["/usr/bin/shelly", "upgrade", "all", "--no-flatpak", "--no-appimage"] not in runner.calls
    assert "aurascan-makepkg" in stderr.getvalue()


def test_helper_repo_only_handoff_ignores_shelly_confirmation_mode():
    runner = FakeRunner({
        tuple(preview_cmd()): completed("glibc\t2.40-1\tcore\t1\t\t\t\n"),
        ("/usr/bin/shelly", "--version"): completed("3.0.1\n"),
        ("/usr/bin/shelly", "list-updates", "aur", "--json"): completed("[]\n"),
        (SUDO_PATH, PACMAN_PATH, "-Syu"): completed(returncode=0),
        installed_q_cmd("glibc"): completed("glibc 2.40-1\n"),
    })

    status = run_upgrade(
        ["--no-ai", "--aur-helper", "shelly", "--no-trusted-handoff"],
        runner=runner,
        which=lambda name: "/usr/bin/shelly" if name == "shelly" else None,
        snapshot=base_snapshot(),
        stdout=io.StringIO(),
    )

    assert status == 0
    assert [SUDO_PATH, PACMAN_PATH, "-Syu"] in runner.calls
    assert not any(call and call[0] == "/usr/bin/shelly" and "upgrade" in call for call in runner.calls)


def test_upgrade_yes_runs_config_drift_before_and_after_when_root_is_explicit():
    runner = FakeRunner({
        tuple(preview_cmd()): completed("glibc\t2.40-1\tcore\t1\t\t\t\n"),
        (SUDO_PATH, PACMAN_PATH, "-Syu"): completed(returncode=0),
        installed_q_cmd("glibc"): completed("glibc 2.40-1\n"),
    })
    calls = []

    def drift_runner(argv, **_kwargs):
        calls.append(argv)
        return 0

    status = run_upgrade(
        ["--yes", "--no-ai", "--aur-helper", "none"],
        runner=runner,
        snapshot=base_snapshot(),
        stdout=io.StringIO(),
        config_drift_root=Path("/tmp/etc"),
        config_drift_runner=drift_runner,
    )

    assert status == 0
    assert calls == [
        ["--root", "/tmp/etc", "--no-ai", "--yes"],
        ["--root", "/tmp/etc", "--no-ai", "--yes"],
    ]


def test_json_mode_does_not_run_without_yes():
    runner = FakeRunner({tuple(preview_cmd()): completed("glibc\t2.40-1\tcore\t1\t\t\t\n")})
    stdout = io.StringIO()

    status = run_upgrade(
        ["--json", "--no-ai", "--aur-helper", "none"],
        runner=runner,
        snapshot=base_snapshot(),
        stdout=stdout,
    )
    data = json.loads(stdout.getvalue())

    assert status == 0
    assert data["report_type"] == "upgrade_preflight"
    assert data["kernel_module_check"]["enabled"] is True
    assert [SUDO_PATH, PACMAN_PATH, "-Syu"] not in runner.calls
    assert "Starting upgrade preflight" not in stdout.getvalue()


def test_kernel_module_autopilot_accepts_fix_and_reruns_preflight():
    class SequenceRunner(FakeRunner):
        def __init__(self):
            super().__init__({
                (SUDO_PATH, PACMAN_PATH, "-S", "--needed", "linux-cachyos-nvidia-open"): completed(returncode=0),
                (SUDO_PATH, PACMAN_PATH, "-Syu"): completed(returncode=0),
                installed_q_cmd("linux-cachyos", "linux-cachyos-nvidia-open"): completed(
                    "linux-cachyos 7.1.4-1\n"
                    "linux-cachyos-nvidia-open 7.1.4-1\n"
                ),
            })
            self.preview_count = 0

        def __call__(self, cmd, **kwargs):
            if list(cmd) == preview_cmd():
                self.calls.append(list(cmd))
                self.preview_count += 1
                if self.preview_count == 1:
                    return completed("linux-cachyos\t7.1.4-1\tcore\t1\t\t\t\n")
                return completed(
                    "linux-cachyos\t7.1.4-1\tcore\t1\t\t\t\n"
                    "linux-cachyos-nvidia-open\t7.1.4-1\tcore\t1\tlinux-cachyos=7.1.4-1\t\t\n"
                )
            return super().__call__(cmd, **kwargs)

    runner = SequenceRunner()
    stdout = io.StringIO()

    status = run_upgrade(
        ["--yes", "--no-ai", "--aur-helper", "none"],
        runner=runner,
        snapshot=base_snapshot(
            installed_packages=["linux-cachyos", "linux-cachyos-nvidia-open", "nvidia-utils", "linux-cachyos-lts"],
            nvidia_packages=["linux-cachyos-nvidia-open", "nvidia-utils"],
        ),
        input_func=lambda _prompt: "",
        stdout=stdout,
    )

    assert status == 0
    assert [SUDO_PATH, PACMAN_PATH, "-S", "--needed", "linux-cachyos-nvidia-open"] in runner.calls
    assert runner.preview_count == 2
    assert "Kernel/module fix completed. Rerunning preflight." in stdout.getvalue()


def test_kernel_module_autopilot_declined_fix_keeps_high_risk_prompt():
    runner = FakeRunner({tuple(preview_cmd()): completed("linux-cachyos\t7.1.4-1\tcore\t1\t\t\t\n")})
    answers = iter(["n", "n"])

    status = run_upgrade(
        ["--no-ai", "--aur-helper", "none"],
        runner=runner,
        snapshot=base_snapshot(
            installed_packages=["linux-cachyos", "linux-cachyos-nvidia-open", "nvidia-utils"],
            nvidia_packages=["linux-cachyos-nvidia-open", "nvidia-utils"],
        ),
        input_func=lambda _prompt: next(answers),
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )

    assert status == EXIT_USER_DECLINED
    assert [SUDO_PATH, PACMAN_PATH, "-S", "--needed", "linux-cachyos-nvidia-open"] not in runner.calls
    assert [SUDO_PATH, PACMAN_PATH, "-Syu"] not in runner.calls


def test_upgrade_success_runs_kernel_module_aftercare():
    runner = FakeRunner({
        tuple(preview_cmd()): completed("glibc\t2.40-1\tcore\t1\t\t\t\n"),
        (SUDO_PATH, PACMAN_PATH, "-Syu"): completed(returncode=0),
        installed_q_cmd("glibc"): completed("glibc 2.40-1\n"),
    })
    stdout = io.StringIO()

    status = run_upgrade(
        ["--yes", "--no-ai", "--aur-helper", "none"],
        runner=runner,
        snapshot=base_snapshot(),
        stdout=stdout,
    )

    assert status == 0
    assert "Kernel/module aftercare" in stdout.getvalue()


def test_upgrade_reported_success_but_versions_not_updated_skips_aftercare():
    runner = FakeRunner({
        tuple(preview_cmd()): completed("clamav\t1.5.3-1\textra\t1\t\t\t\n"),
        (SUDO_PATH, PACMAN_PATH, "-Syu"): completed(returncode=0),
        installed_q_cmd("clamav"): completed("clamav 1.5.2-2\n"),
    })
    stdout = io.StringIO()
    stderr = io.StringIO()

    status = run_upgrade(
        ["--yes", "--no-ai", "--aur-helper", "none"],
        runner=runner,
        snapshot=base_snapshot(installed_packages=["clamav"]),
        stdout=stdout,
        stderr=stderr,
    )

    assert status == EXIT_UPGRADE_VERIFICATION_FAILED
    assert "Kernel/module aftercare" not in stdout.getvalue()
    assert "planned package versions were not installed" in stderr.getvalue()
    assert "clamav expected 1.5.3-1, found 1.5.2-2" in stderr.getvalue()
    assert "Upgrade transaction verified" not in stdout.getvalue()


def test_failed_upgrade_diagnoses_mirror_notfound():
    url = "https://mirror.example/extra/os/x86_64/luajit-2.1-1-x86_64.pkg.tar.zst"

    class UrlRunner(FakeRunner):
        def __call__(self, cmd, **kwargs):
            if list(cmd) == preview_cmd():
                self.calls.append(list(cmd))
                return completed("luajit\t2.1-1\textra\t1\t\t\t\n")
            if list(cmd) == [SUDO_PATH, PACMAN_PATH, "-Syu"]:
                self.calls.append(list(cmd))
                return completed(returncode=1)
            if len(cmd) >= 5 and list(cmd[:3]) == [PACMAN_PATH, "-Sp", "--cachedir"]:
                self.calls.append(list(cmd))
                return completed(url + "\n")
            return super().__call__(cmd, **kwargs)

    def fake_urlopen(req, timeout):
        raise HTTPError(req.full_url, 404, "Not Found", {}, None)

    runner = UrlRunner()
    stdout = io.StringIO()

    status = run_upgrade(
        ["--no-ai", "--aur-helper", "none"],
        runner=runner,
        snapshot=base_snapshot(),
        stdout=stdout,
        urlopen=fake_urlopen,
    )

    output = stdout.getvalue()
    assert status == 1
    assert "Package mirror looks temporarily out of sync" in output
    assert "usually a mirror sync race" in output
    assert url in output


def test_upgrade_failure_diagnosis_ignores_reachable_package_urls():
    plan = UpgradePlan(repo_packages=[UpgradePackage("luajit", "2.1-1")])

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    def runner(cmd, **_kwargs):
        if len(cmd) >= 5 and list(cmd[:3]) == [PACMAN_PATH, "-Sp", "--cachedir"]:
            return completed("https://mirror.example/luajit.pkg.tar.zst\n")
        return completed()

    assert diagnose_upgrade_failure(plan, runner=runner, urlopen=lambda _req, timeout: Response()) is None


def test_verify_upgrade_handoff_reports_uninstalled_or_old_packages():
    plan = UpgradePlan(repo_packages=[
        UpgradePackage("clamav", "1.5.3-1"),
        UpgradePackage("linux-cachyos", "7.1.3-2"),
    ])
    runner = FakeRunner({
        installed_q_cmd("clamav", "linux-cachyos"): completed("clamav 1.5.2-2\n"),
    })

    missing = verify_upgrade_handoff(plan, runner=runner)

    assert missing == [
        "clamav expected 1.5.3-1, found 1.5.2-2",
        "linux-cachyos expected 7.1.3-2, found (not installed)",
    ]


def test_upgrade_json_mode_does_not_emit_config_drift_output_even_with_yes():
    runner = FakeRunner({
        tuple(preview_cmd()): completed("glibc\t2.40-1\tcore\t1\t\t\t\n"),
        (SUDO_PATH, PACMAN_PATH, "-Syu"): completed(returncode=0),
        installed_q_cmd("glibc"): completed("glibc 2.40-1\n"),
    })
    stdout = io.StringIO()
    calls = []

    def drift_runner(argv, **_kwargs):
        calls.append(argv)
        return 0

    status = run_upgrade(
        ["--json", "--yes", "--no-ai", "--aur-helper", "none"],
        runner=runner,
        snapshot=base_snapshot(),
        stdout=stdout,
        config_drift_root=Path("/tmp/etc"),
        config_drift_runner=drift_runner,
    )
    data = json.loads(stdout.getvalue())

    assert status == 0
    assert data["report_type"] == "upgrade_preflight"
    assert calls == []


def test_unavailable_preflight_does_not_run_upgrade():
    runner = FakeRunner({tuple(preview_cmd()): completed(stderr="not root", returncode=1)})

    status = run_upgrade(
        ["--yes", "--no-ai", "--aur-helper", "none"],
        runner=runner,
        snapshot=base_snapshot(),
        stdout=io.StringIO(),
    )

    assert status == EXIT_PREFLIGHT_UNAVAILABLE
    assert [SUDO_PATH, PACMAN_PATH, "-Syu"] not in runner.calls


def test_upgrade_repairs_empty_mirrorlist_and_reruns_preflight(tmp_path):
    pacman_conf = tmp_path / "pacman.conf"
    mirrorlist = tmp_path / "mirrorlist"
    backup = tmp_path / "mirrorlist-backup"
    pacman_conf.write_text("[core]\nInclude = mirrorlist\n", encoding="utf-8")
    mirrorlist.write_text("#Server = https://disabled.invalid/$repo/os/$arch\n", encoding="utf-8")
    backup.write_text("Server = https://mirror.example/$repo/os/$arch\n", encoding="utf-8")

    class SequenceRunner(FakeRunner):
        def __init__(self):
            super().__init__({
                (SUDO_PATH, PACMAN_PATH, "-Syu"): completed(returncode=0),
                installed_q_cmd("glibc"): completed("glibc 2.40-1\n"),
            })
            self.preview_count = 0

        def __call__(self, cmd, **kwargs):
            if list(cmd) == preview_cmd():
                self.calls.append(list(cmd))
                self.preview_count += 1
                if self.preview_count == 1:
                    return completed(stderr="error: failed to synchronize all databases (no servers configured for repository)", returncode=1)
                return completed("glibc\t2.40-1\tcore\t1\t\t\t\n")
            return super().__call__(cmd, **kwargs)

    runner = SequenceRunner()
    stdout = io.StringIO()

    status = run_upgrade(
        ["--yes", "--no-ai", "--aur-helper", "none"],
        runner=runner,
        snapshot=base_snapshot(),
        stdout=stdout,
        pacman_conf_path=pacman_conf,
        repository_repair_backup_root=tmp_path / "repair-backups",
    )

    assert status == 0
    assert runner.preview_count == 2
    assert "Repository repair completed. Rerunning preflight." in stdout.getvalue()
    assert "Server = https://mirror.example" in mirrorlist.read_text(encoding="utf-8")
    assert [SUDO_PATH, PACMAN_PATH, "-Syu"] in runner.calls


def test_final_command_os_error_returns_command_failure():
    def runner(cmd, **kwargs):
        if kwargs.get("capture_output"):
            return completed("glibc\t2.40-1\tcore\t1\t\t\t\n")
        raise OSError("cannot exec")

    status = run_upgrade(
        ["--yes", "--no-ai", "--aur-helper", "none"],
        runner=runner,
        snapshot=base_snapshot(),
        stdout=io.StringIO(),
        stderr=io.StringIO(),
    )

    assert status == EXIT_UPGRADE_COMMAND_FAILED_TO_START
