import subprocess
from pathlib import Path

from aurascan.core.kernel_module_autopilot import (
    build_kernel_module_check,
    expected_running_kernel_package,
    is_kernel_base_package,
    kernel_module_fix_command,
)
from aurascan.core.models import Severity
from aurascan.core.upgrade_preflight import UpgradePackage, UpgradePlan, SystemSnapshot, analyze_upgrade_risks


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


def snapshot(**overrides):
    data = {
        "running_kernel": "7.1.3-1-cachyos",
        "installed_packages": ["linux-cachyos", "linux-cachyos-nvidia-open", "nvidia-utils", "linux-cachyos-lts"],
        "foreign_packages": [],
        "foreign_package_info": [],
        "ignored_packages": [],
        "ignored_groups": [],
        "root_free_mib": 100000,
        "boot_free_mib": 2048,
        "boot_paths": ["/boot"],
        "dkms_packages": [],
        "nvidia_packages": ["linux-cachyos-nvidia-open", "nvidia-utils"],
        "zfs_packages": [],
        "virtualbox_packages": [],
        "pacnew_count": 0,
        "pacsave_count": 0,
    }
    data.update(overrides)
    return SystemSnapshot(**data)


def write_module(root: Path, release: str, pkgbase: str) -> None:
    path = root / release
    path.mkdir(parents=True)
    (path / "pkgbase").write_text(pkgbase, encoding="utf-8")


def test_kernel_family_detection_from_uname_modules_and_package_names(tmp_path):
    write_module(tmp_path, "7.1.3-1-cachyos", "linux-cachyos")

    assert is_kernel_base_package("linux-cachyos")
    assert is_kernel_base_package("linux-cachyos-lts")
    assert not is_kernel_base_package("linux-cachyos-headers")
    assert not is_kernel_base_package("linux-cachyos-nvidia-open")
    assert expected_running_kernel_package("7.1.3-1-cachyos", module_dirs={"7.1.3-1-cachyos": "linux-cachyos"}) == "linux-cachyos"


def test_cachyos_nvidia_pairing_passes_when_module_package_matches(tmp_path):
    write_module(tmp_path, "7.1.3-1-cachyos", "linux-cachyos")
    write_module(tmp_path, "6.18.38-1-cachyos-lts", "linux-cachyos-lts")
    plan = UpgradePlan(repo_packages=[
        UpgradePackage("linux-cachyos", "7.1.4-1"),
        UpgradePackage("linux-cachyos-nvidia-open", "7.1.4-1", depends=["linux-cachyos=7.1.4-1"]),
    ])

    check = build_kernel_module_check(plan, snapshot(), modules_root=tmp_path, runner=FakeRunner())

    assert check.status == "ok"
    assert check.prebuilt_module_status[0]["ok"] is True
    assert check.fallback_kernel["available"] is True
    assert "verified nvidia module coverage" in check.summary


def test_cachyos_lts_nvidia_does_not_match_plain_cachyos_kernel(tmp_path):
    write_module(tmp_path, "7.1.3-1-cachyos", "linux-cachyos")
    write_module(tmp_path, "6.18.38-1-cachyos-lts", "linux-cachyos-lts")
    plan = UpgradePlan(repo_packages=[
        UpgradePackage("linux-cachyos", "7.1.4-1"),
        UpgradePackage("linux-cachyos-nvidia-open", "7.1.4-1", depends=["linux-cachyos=7.1.4-1"]),
        UpgradePackage("linux-cachyos-lts-nvidia-open", "6.18.38-1", depends=["linux-cachyos-lts=6.18.38-1"]),
    ])

    check = build_kernel_module_check(
        plan,
        snapshot(installed_packages=[
            "linux-cachyos",
            "linux-cachyos-nvidia-open",
            "linux-cachyos-lts",
            "linux-cachyos-lts-nvidia-open",
            "nvidia-utils",
        ]),
        modules_root=tmp_path,
        runner=FakeRunner(),
    )

    assert [item["module_package"] for item in check.prebuilt_module_status] == ["linux-cachyos-nvidia-open"]
    assert check.unfixable_issues == []
    assert check.status == "ok"


def test_missing_cachyos_nvidia_pair_produces_fixable_issue(tmp_path):
    write_module(tmp_path, "7.1.3-1-cachyos", "linux-cachyos")
    plan = UpgradePlan(repo_packages=[UpgradePackage("linux-cachyos", "7.1.4-1")])

    check = build_kernel_module_check(plan, snapshot(installed_packages=["linux-cachyos", "linux-cachyos-nvidia-open", "nvidia-utils"]), modules_root=tmp_path, runner=FakeRunner())
    findings = analyze_upgrade_risks(plan, snapshot(installed_packages=["linux-cachyos", "linux-cachyos-nvidia-open", "nvidia-utils"]), kernel_module_check=check, kernel_module_autopilot_enabled=True)

    assert check.fix_packages() == ["linux-cachyos-nvidia-open"]
    assert kernel_module_fix_command(check) == ["sudo", "pacman", "-S", "--needed", "linux-cachyos-nvidia-open"]
    assert any(finding.rule_id == "UPG-KERNEL-MODULE-FIXABLE" and finding.severity == Severity.HIGH for finding in findings)


def test_dkms_headers_present_and_clean_status_passes(tmp_path):
    write_module(tmp_path, "7.1.3-1-cachyos", "linux-cachyos")
    runner = FakeRunner({("dkms", "status"): completed("nvidia/610.43.02, 7.1.3-1-cachyos, x86_64: installed\n")})
    plan = UpgradePlan(repo_packages=[UpgradePackage("linux-cachyos", "7.1.4-1"), UpgradePackage("linux-cachyos-headers", "7.1.4-1")])

    check = build_kernel_module_check(
        plan,
        snapshot(installed_packages=["linux-cachyos", "linux-cachyos-headers", "nvidia-dkms", "linux-cachyos-lts"], dkms_packages=["nvidia-dkms"], nvidia_packages=["nvidia-dkms"]),
        modules_root=tmp_path,
        runner=runner,
    )

    assert check.status == "ok"
    assert check.headers_status[0]["ok"] is True
    assert check.dkms_status["available"] is True


def test_dkms_missing_headers_is_fixable_and_failed_status_is_not(tmp_path):
    write_module(tmp_path, "7.1.3-1-cachyos", "linux-cachyos")
    plan = UpgradePlan(repo_packages=[UpgradePackage("linux-cachyos", "7.1.4-1")])
    base = snapshot(installed_packages=["linux-cachyos", "nvidia-dkms"], dkms_packages=["nvidia-dkms"], nvidia_packages=["nvidia-dkms"])

    check = build_kernel_module_check(plan, base, modules_root=tmp_path, runner=FakeRunner({("dkms", "status"): completed("nvidia/610: installed\n")}))
    failed = build_kernel_module_check(plan, base, modules_root=tmp_path, runner=FakeRunner({("dkms", "status"): completed("nvidia/610: build failed\n")}))

    assert check.fix_packages() == ["linux-cachyos-headers"]
    assert any(issue.kind == "dkms_failed" for issue in failed.unfixable_issues)


def test_fallback_kernel_detection_records_present_and_missing(tmp_path):
    plan = UpgradePlan(repo_packages=[UpgradePackage("linux-cachyos", "7.1.4-1")])
    both_kernels_upgrading = UpgradePlan(repo_packages=[
        UpgradePackage("linux-cachyos", "7.1.4-1"),
        UpgradePackage("linux-cachyos-lts", "6.18.39-1"),
    ])
    with_fallback = build_kernel_module_check(plan, snapshot(installed_packages=["linux-cachyos", "linux-cachyos-lts"]), modules_root=tmp_path, runner=FakeRunner())
    upgraded_fallback = build_kernel_module_check(both_kernels_upgrading, snapshot(installed_packages=["linux-cachyos", "linux-cachyos-lts"]), modules_root=tmp_path, runner=FakeRunner())
    without_fallback = build_kernel_module_check(plan, snapshot(installed_packages=["linux-cachyos"]), modules_root=tmp_path, runner=FakeRunner())

    assert with_fallback.fallback_kernel["available"] is True
    assert with_fallback.fallback_kernel["fallback_kernel_packages"] == ["linux-cachyos-lts"]
    assert upgraded_fallback.fallback_kernel["available"] is True
    assert upgraded_fallback.fallback_kernel["upgraded_fallback_kernel_packages"] == ["linux-cachyos-lts"]
    assert not any(issue.kind == "fallback_kernel_missing" for issue in upgraded_fallback.unfixable_issues)
    assert without_fallback.fallback_kernel["available"] is False
    assert any(issue.kind == "fallback_kernel_missing" for issue in without_fallback.unfixable_issues)
