import io
import json
import subprocess
from pathlib import Path

from aurascan.core import ai_provider
from aurascan.core.models import Severity
from aurascan.core.upgrade_preflight import (
    EXIT_PREFLIGHT_UNAVAILABLE,
    EXIT_PREFLIGHT_DISABLED,
    EXIT_UPGRADE_COMMAND_FAILED_TO_START,
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
    analyze_upgrade_risks,
    apply_ai_risk_raises,
    apply_ai_upgrade_review,
    build_upgrade_plan,
    collect_foreign_package_info,
    foreign_package_dependency_issues,
    helper_upgrade_command,
    parse_aur_updates,
    parse_pacman_preview,
    parse_pacman_qi,
    parse_shelly_updates,
    options_from_args,
    resolve_aur_helper,
    run_upgrade,
)


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
    return ["sudo", "pacman", "-Syu", "--print", "--print-format", PACMAN_PRINT_FORMAT]


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
        ("pacman", "-Qi", "demo-bin"): completed(qi),
        ("pacman", "-T", "glibc", "missing-lib>=2"): completed("missing-lib>=2\n", returncode=127),
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
    assert helper_upgrade_command("shelly") == ["shelly", "upgrade-all", "--no-flatpak", "--no-appimage"]


def test_upgrade_options_default_to_enabled_and_read_env():
    args = build_upgrade_parser().parse_args([])

    options = options_from_args(args, {
        "AURASCAN_UPGRADE_PREFLIGHT_ENABLED": "1",
        "AURASCAN_UPGRADE_AUR_HELPER": "yay",
        "AURASCAN_UPGRADE_PREFLIGHT_AI": "0",
    })

    assert options.preflight_enabled is True
    assert options.aur_helper == "yay"
    assert options.no_ai is True
    assert options.config_drift_enabled is True


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


def test_build_upgrade_plan_uses_helper_and_parses_aur_updates():
    runner = FakeRunner({
        tuple(preview_cmd()): completed("glibc\t2.40-1\tcore\t1\t\t\t\n"),
        ("paru", "-Qua"): completed("aur/demo 1 -> 2\n"),
    })

    plan = build_upgrade_plan(UpgradeOptions(aur_helper="auto"), runner=runner, which=lambda name: "/usr/bin/paru" if name == "paru" else None)

    assert plan.selected_helper == "paru"
    assert plan.final_command == ["paru", "-Syu"]
    assert plan.repo_packages[0].name == "glibc"
    assert plan.aur_packages[0].name == "demo"


def test_build_upgrade_plan_uses_shelly_and_parses_json_aur_updates():
    runner = FakeRunner({
        tuple(preview_cmd()): completed("glibc\t2.40-1\tcore\t1\t\t\t\n"),
        ("shelly", "check-updates", "--aur", "--json"): completed('{"Packages":[],"Aur":[{"Name":"demo-bin","OldVersion":"1","Version":"2"}]}\n'),
    })

    plan = build_upgrade_plan(UpgradeOptions(aur_helper="shelly"), runner=runner, which=lambda name: "/usr/bin/shelly" if name == "shelly" else None)

    assert plan.selected_helper == "shelly"
    assert plan.final_command == ["shelly", "upgrade-all", "--no-flatpak", "--no-appimage"]
    assert plan.aur_packages[0].name == "demo-bin"


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
        final_command=["sudo", "pacman", "-Syu"],
    )
    snapshot = base_snapshot(
        boot_free_mib=128,
        root_free_mib=1024,
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


def test_ai_raise_only_caps_critical_and_never_lowers():
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
        "risk_raises": [
            {"target_rule_id": "UPG-ROOT-SPACE", "severity": "CRITICAL", "reason": "combined risk"},
            {"target_rule_id": "UPG-ROOT-SPACE", "severity": "LOW", "reason": "lower it"},
            {"severity": "HIGH", "reason": "new correlation", "recommended_action": "review"},
        ]
    })

    assert applied == 2
    assert report.findings[0].severity == Severity.HIGH
    assert report.findings[1].rule_id == "UPG-AI-RISK"
    assert report.highest_severity == Severity.HIGH


def test_ai_vague_foreign_raise_is_ignored_when_local_helper_checks_pass():
    report = UpgradePreflightReport(
        plan=UpgradePlan(selected_helper="shelly", aur_packages=[]),
        snapshot=base_snapshot(
            foreign_packages=["demo-bin"],
            foreign_package_info=[ForeignPackageInfo("demo-bin", depends=["glibc"])],
        ),
        findings=[],
    )

    applied = apply_ai_risk_raises(report, {
        "risk_raises": [
            {"severity": "MEDIUM", "reason": "1 foreign package is installed but was not shown in the upgrade list"}
        ]
    })

    assert applied == 0
    assert report.findings == []


def test_ai_vague_foreign_raise_is_ignored_when_rebuild_risk_already_exists():
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

    applied = apply_ai_risk_raises(report, {
        "risk_raises": [
            {"severity": "MEDIUM", "reason": "foreign packages are installed but not shown in the upgrade list"}
        ]
    })

    assert applied == 0
    assert [finding.rule_id for finding in report.findings] == ["UPG-AUR-REBUILD-RISK"]


def test_ai_invalid_json_is_non_blocking_note(monkeypatch):
    monkeypatch.setenv("AURASCAN_AI_ENABLED", "1")
    monkeypatch.setenv("AURASCAN_AI_PROVIDER", "openai")
    monkeypatch.setenv("AURASCAN_OPENAI_API_KEY", "fixture-only-value")
    report = UpgradePreflightReport(plan=UpgradePlan(), snapshot=base_snapshot(), findings=[])

    def fake_urlopen(_req, timeout):
        return FakeResponse({"choices": [{"message": {"content": "not json"}}]})

    apply_ai_upgrade_review(report, urlopen=fake_urlopen)

    assert report.ai_review["status"] == "invalid_response"
    assert report.action == "continue"


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
    assert ["sudo", "pacman", "-Syu"] not in runner.calls
    assert "Upgrade Preflight" in stdout.getvalue()


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
    assert ["sudo", "pacman", "-Syu"] not in runner.calls
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
    assert ["sudo", "pacman", "-Syu"] not in runner.calls


def test_upgrade_yes_runs_final_command():
    runner = FakeRunner({
        tuple(preview_cmd()): completed("glibc\t2.40-1\tcore\t1\t\t\t\n"),
        ("sudo", "pacman", "-Syu"): completed(returncode=0),
    })

    status = run_upgrade(
        ["--yes", "--no-ai", "--aur-helper", "none"],
        runner=runner,
        snapshot=base_snapshot(ignored_packages=["glibc"]),
        stdout=io.StringIO(),
    )

    assert status == 0
    assert ["sudo", "pacman", "-Syu"] in runner.calls


def test_upgrade_yes_runs_config_drift_before_and_after_when_root_is_explicit():
    runner = FakeRunner({
        tuple(preview_cmd()): completed("glibc\t2.40-1\tcore\t1\t\t\t\n"),
        ("sudo", "pacman", "-Syu"): completed(returncode=0),
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
    assert ["sudo", "pacman", "-Syu"] not in runner.calls


def test_upgrade_json_mode_does_not_emit_config_drift_output_even_with_yes():
    runner = FakeRunner({
        tuple(preview_cmd()): completed("glibc\t2.40-1\tcore\t1\t\t\t\n"),
        ("sudo", "pacman", "-Syu"): completed(returncode=0),
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
    assert ["sudo", "pacman", "-Syu"] not in runner.calls


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
