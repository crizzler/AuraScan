import shutil
import subprocess
from pathlib import Path

import pytest

from aurascan.core import upgrade_preflight
from aurascan.setup_wizard import build_doctor_parser
from aurascan.core.runtime_links import (
    RuntimeLinkIssue,
    collect_runtime_link_issues,
    linker_cache_sonames,
    missing_provider_candidates,
    read_elf_needed,
)
from aurascan.core.trusted_executable import TrustedExecutable, UnsafeUpgradeExecutable
from aurascan.core.upgrade_models import UpgradePlan


def _host_elf() -> Path:
    for candidate in ("/bin/ls", "/usr/bin/ls", "/bin/sh"):
        path = Path(candidate)
        if path.is_file():
            return path
    raise AssertionError("no host ELF binary is available for the fixture")


def test_read_elf_needed_extracts_real_binary_dependencies():
    needed = read_elf_needed(_host_elf())

    assert needed
    assert all(".so" in soname for soname in needed)


def test_linker_cache_sonames_parses_ldconfig_output():
    output = (
        "5273 libs found in cache `/etc/ld.so.cache'\n"
        "        libzvbi.so.0 (libc6,x86-64) => /usr/lib/libzvbi.so.0\n"
        "        libc.so.6 (libc6,x86-64) => /usr/lib/libc.so.6\n"
    )

    assert linker_cache_sonames(output) == {"libzvbi.so.0", "libc.so.6"}


def test_collect_runtime_link_issues_finds_unknown_soname(tmp_path):
    root = tmp_path / "root"
    binary = root / "usr" / "bin" / "demo"
    binary.parent.mkdir(parents=True)
    shutil.copy2(_host_elf(), binary)
    runner = lambda command, **_kwargs: subprocess.CompletedProcess(
        command, 0, "demo /usr/bin/demo\n", ""
    )

    scan = collect_runtime_link_issues(
        ["demo"],
        query_runner=runner,
        linker_cache=set(),
        providers={"libc.so.6": frozenset({"glibc"})},
        root=root,
    )

    assert scan.notes == []
    assert any(issue.soname == "libc.so.6" for issue in scan.issues)
    issue = next(issue for issue in scan.issues if issue.soname == "libc.so.6")
    assert issue.providers == ("glibc",)


def test_collect_runtime_link_issues_accepts_provided_or_bundled_library(tmp_path):
    root = tmp_path / "root"
    binary = root / "usr" / "bin" / "demo"
    binary.parent.mkdir(parents=True)
    shutil.copy2(_host_elf(), binary)
    runner = lambda command, **_kwargs: subprocess.CompletedProcess(
        command, 0, "demo /usr/bin/demo\n", ""
    )

    scan = collect_runtime_link_issues(
        ["demo"],
        query_runner=runner,
        linker_cache={"libc.so.6"},
        providers={},
        root=root,
    )

    assert not any(issue.soname == "libc.so.6" for issue in scan.issues)


def test_missing_provider_candidates_skips_installed_packages():
    issues = [
        RuntimeLinkIssue("demo", "/usr/bin/demo", "libsimdutf.so.36", ("simdutf",)),
        RuntimeLinkIssue("demo", "/usr/bin/demo", "libfoo.so.1", ("foo",)),
    ]

    assert missing_provider_candidates(issues, {"simdutf": "9.2.1-2"}) == ["foo"]


def _trusted(name, path):
    return TrustedExecutable(name=name, path=path, device=1, inode=2, owner=0, group=0, mode=0o755)


def test_run_trusted_package_install_uses_sudo_and_pacman(monkeypatch):
    observed = {}

    def fake_run(command, executables, **kwargs):
        observed["command"] = command
        observed["executables"] = [item.name for item in executables]
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(upgrade_preflight, "run_trusted_command", fake_run)
    plan = UpgradePlan(
        trusted_executables={
            "sudo": _trusted("sudo", "/usr/bin/sudo"),
            "pacman": _trusted("pacman", "/usr/bin/pacman"),
        }
    )

    upgrade_preflight.run_trusted_package_install(plan, ["simdutf"], runner=lambda *_a, **_k: None)

    assert observed["command"] == [
        "/usr/bin/sudo",
        "/usr/bin/pacman",
        "-S",
        "--needed",
        "--noconfirm",
        "simdutf",
    ]
    assert observed["executables"] == ["sudo", "pacman"]


def test_run_trusted_package_install_rejects_unsafe_provider_name():
    plan = UpgradePlan(
        trusted_executables={
            "pacman": _trusted("pacman", "/usr/bin/pacman"),
        }
    )

    with pytest.raises(UnsafeUpgradeExecutable):
        upgrade_preflight.run_trusted_package_install(
            plan, ["simdutf; rm -rf /"], runner=lambda *_a, **_k: None
        )


def test_doctor_parser_accepts_runtime_link_repair_flags():
    args = build_doctor_parser().parse_args(
        ["--fix-runtime-links", "--runtime-link-package", "ungoogled-chromium-bin"]
    )

    assert args.fix_runtime_links is True
    assert args.runtime_link_package == ["ungoogled-chromium-bin"]
