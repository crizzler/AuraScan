import hashlib
import os
import subprocess
from pathlib import Path

import pytest

from aurascan.core.build_sandbox import (
    AUR_SANDBOX_ENV,
    AUR_SANDBOX_WORK_ROOT_ENV,
    SandboxBuildError,
    SandboxConfig,
    SandboxUnavailable,
    build_in_sandbox,
    cleanup_sandbox_build,
    resolve_sandbox_config,
    sandbox_makepkg_arguments,
    sandbox_status,
)
from aurascan.core.trusted_tools import TrustedTool


def _tool(name: str) -> TrustedTool:
    return TrustedTool(
        name=name,
        path=f"/usr/bin/{name}",
        device=1,
        inode=2,
        owner=0,
        group=0,
        mode=0o100755,
    )


def _tools(names=("arch-nspawn", "mkarchroot", "systemd-nspawn", "sudo", "cp", "rm")):
    table = {name: _tool(name) for name in names}

    def capture(name):
        return table.get(name)

    return capture


def _base_ready(_path):
    return True, ""


def _checkout(tmp_path: Path) -> Path:
    checkout = tmp_path / "aur-checkout"
    checkout.mkdir()
    (checkout / "PKGBUILD").write_text("pkgname=example\npkgver=1\n", encoding="utf-8")
    (checkout / "payload.txt").write_text("inert\n", encoding="utf-8")
    return checkout


class _Runner:
    def __init__(self, *, returncode=0, artifacts=1, sleep=None, timeout=False):
        self.returncode = returncode
        self.artifacts = artifacts
        self.sleep = sleep
        self.timeout = timeout
        self.calls = []

    def __call__(self, command, **kwargs):
        self.calls.append((list(command), dict(kwargs)))
        if self.timeout:
            raise subprocess.TimeoutExpired(list(command), kwargs.get("timeout"))
        if "/bin/bash" not in command:
            return subprocess.CompletedProcess(list(command), self.returncode)
        cwd = Path(kwargs["cwd"])
        for index in range(self.artifacts):
            artifact = cwd / f"example-1-1-x86_64.pkg.tar.zst"
            if index:
                artifact = cwd / f"example-{index + 1}-1-x86_64.pkg.tar.zst"
            artifact.write_bytes(b"package-bytes-" + str(index).encode())
        return subprocess.CompletedProcess(list(command), self.returncode)


def test_config_defaults_to_off(tmp_path):
    config = resolve_sandbox_config({})
    assert config.backend == "off"
    assert config.enabled is False
    assert config.error == ""


def test_config_accepts_devtools_and_boolean_aliases(tmp_path):
    assert resolve_sandbox_config({AUR_SANDBOX_ENV: "devtools"}).backend == "devtools"
    assert resolve_sandbox_config({AUR_SANDBOX_ENV: "yes"}).backend == "devtools"
    assert resolve_sandbox_config({AUR_SANDBOX_ENV: "off"}).backend == "off"
    config = resolve_sandbox_config(
        {AUR_SANDBOX_ENV: "devtools", AUR_SANDBOX_WORK_ROOT_ENV: str(tmp_path)}
    )
    assert config.work_root == tmp_path


def test_config_rejects_unknown_backend():
    config = resolve_sandbox_config({AUR_SANDBOX_ENV: "qemu"})
    assert config.error
    assert sandbox_status(config).available is False


def test_status_reports_disabled_without_touching_tools():
    status = sandbox_status(resolve_sandbox_config({}), tool_capture=lambda _name: None)
    assert status.enabled is False
    assert status.available is True
    assert status.backend == "off"


def test_status_requires_each_fixed_tool(tmp_path):
    config = SandboxConfig(backend="devtools", work_root=tmp_path)
    status = sandbox_status(
        config,
        base_root=tmp_path / "archbuild",
        tool_capture=_tools(("arch-nspawn", "mkarchroot", "systemd-nspawn", "sudo", "cp")),
        base_probe=_base_ready,
    )
    assert status.available is False
    assert "rm" in status.reason


def test_status_requires_base_chroot_setup(tmp_path):
    config = SandboxConfig(backend="devtools", work_root=tmp_path)
    status = sandbox_status(
        config,
        base_root=tmp_path / "archbuild",
        tool_capture=_tools(),
    )
    assert status.available is False
    assert "mkarchroot" in status.reason


def test_status_rejects_linked_base(tmp_path):
    base = tmp_path / "archbuild"
    base.mkdir()
    (base / "extra-x86_64").symlink_to(tmp_path)
    config = SandboxConfig(backend="devtools", work_root=tmp_path)
    status = sandbox_status(config, base_root=base, tool_capture=_tools())
    assert status.available is False
    assert "regular directory" in status.reason


def test_makepkg_arguments_strip_install_and_require_syncdeps():
    args = sandbox_makepkg_arguments(["--syncdeps", "--install", "--nocheck"])
    assert "--install" not in args
    assert "--syncdeps" in args
    assert "--noconfirm" in args
    assert "--nocheck" in args


def test_makepkg_arguments_reject_unknown_flags():
    with pytest.raises(SandboxBuildError):
        sandbox_makepkg_arguments(["--config", "/tmp/makepkg.conf"])


def test_build_copies_checkout_and_binds_artifact_hash(tmp_path):
    checkout = _checkout(tmp_path)
    runner = _Runner()
    result = build_in_sandbox(
        checkout,
        config=SandboxConfig(backend="devtools", work_root=tmp_path / "work"),
        runner=runner,
        environ={"TERM": "dumb"},
        base_root=tmp_path / "archbuild",
        tool_capture=_tools(),
        tool_revalidate=lambda _tool: None,
        base_probe=_base_ready,
    )
    try:
        assert len(result.artifacts) == 1
        artifact = result.artifacts[0]
        assert artifact.name == "example-1-1-x86_64.pkg.tar.zst"
        assert artifact.sha256 == hashlib.sha256(b"package-bytes-0").hexdigest()
        assert Path(artifact.path).is_file()
        build_call = next(call for call in runner.calls if "/bin/bash" in call[0])
        command, kwargs = build_call
        assert command[0] == "/usr/bin/sudo"
        assert "/usr/bin/arch-nspawn" in command
        assert "--syncdeps" in command
        assert "--noconfirm" in command
        assert "--skipinteg" not in command
        assert any(argument.startswith("--bind=") for argument in command)
        assert "-c" in command
        assert kwargs["env"]["PATH"] == "/usr/bin:/bin"
        assert kwargs["env"]["HOME"].startswith(str(result.build_root))
        assert (Path(result.build_root) / "build" / "PKGBUILD").is_file()
    finally:
        assert cleanup_sandbox_build(result) == ""
    assert not Path(result.build_root).exists()


def test_build_prunes_vcs_and_generated_trees(tmp_path):
    checkout = _checkout(tmp_path)
    (checkout / ".git").mkdir()
    (checkout / ".git" / "config").write_text("inert\n", encoding="utf-8")
    (checkout / "src").mkdir()
    (checkout / "src" / "stale").write_text("inert\n", encoding="utf-8")
    result = build_in_sandbox(
        checkout,
        config=SandboxConfig(backend="devtools", work_root=tmp_path / "work"),
        runner=_Runner(),
        base_root=tmp_path / "archbuild",
        tool_capture=_tools(),
        tool_revalidate=lambda _tool: None,
        base_probe=_base_ready,
    )
    try:
        copied = Path(result.build_root) / "build"
        assert not (copied / ".git").exists()
        assert not (copied / "src").exists()
        assert (copied / "PKGBUILD").is_file()
    finally:
        cleanup_sandbox_build(result)


def test_build_rejects_escaping_symlink(tmp_path):
    checkout = _checkout(tmp_path)
    (checkout / "escape").symlink_to("/etc/passwd")
    with pytest.raises(SandboxBuildError, match="escaping link"):
        build_in_sandbox(
            checkout,
            config=SandboxConfig(backend="devtools", work_root=tmp_path / "work"),
            runner=_Runner(),
            base_root=tmp_path / "archbuild",
            tool_capture=_tools(),
            tool_revalidate=lambda _tool: None,
            base_probe=_base_ready,
        )


def test_build_rejects_linked_directory(tmp_path):
    checkout = _checkout(tmp_path)
    (checkout / "linked").symlink_to(tmp_path)
    with pytest.raises(SandboxBuildError, match="linked directory"):
        build_in_sandbox(
            checkout,
            config=SandboxConfig(backend="devtools", work_root=tmp_path / "work"),
            runner=_Runner(),
            base_root=tmp_path / "archbuild",
            tool_capture=_tools(),
            tool_revalidate=lambda _tool: None,
            base_probe=_base_ready,
        )


def test_build_rejects_special_file(tmp_path):
    checkout = _checkout(tmp_path)
    os.mkfifo(str(checkout / "pipe"))
    with pytest.raises(SandboxBuildError, match="unsupported file"):
        build_in_sandbox(
            checkout,
            config=SandboxConfig(backend="devtools", work_root=tmp_path / "work"),
            runner=_Runner(),
            base_root=tmp_path / "archbuild",
            tool_capture=_tools(),
            tool_revalidate=lambda _tool: None,
            base_probe=_base_ready,
        )


def test_build_failure_removes_private_tree(tmp_path):
    checkout = _checkout(tmp_path)
    work = tmp_path / "work"
    with pytest.raises(SandboxBuildError, match="exit status 7"):
        build_in_sandbox(
            checkout,
            config=SandboxConfig(backend="devtools", work_root=work),
            runner=_Runner(returncode=7),
            base_root=tmp_path / "archbuild",
            tool_capture=_tools(),
            tool_revalidate=lambda _tool: None,
            base_probe=_base_ready,
        )
    assert list(work.iterdir()) == []


def test_build_timeout_is_bounded(tmp_path):
    checkout = _checkout(tmp_path)
    with pytest.raises(SandboxBuildError, match="time bound"):
        build_in_sandbox(
            checkout,
            config=SandboxConfig(backend="devtools", work_root=tmp_path / "work", timeout_seconds=1),
            runner=_Runner(timeout=True),
            base_root=tmp_path / "archbuild",
            tool_capture=_tools(),
            tool_revalidate=lambda _tool: None,
            base_probe=_base_ready,
        )


def test_build_requires_a_fresh_artifact(tmp_path):
    checkout = _checkout(tmp_path)
    with pytest.raises(SandboxBuildError, match="no fresh package archive"):
        build_in_sandbox(
            checkout,
            config=SandboxConfig(backend="devtools", work_root=tmp_path / "work"),
            runner=_Runner(artifacts=0),
            base_root=tmp_path / "archbuild",
            tool_capture=_tools(),
            tool_revalidate=lambda _tool: None,
            base_probe=_base_ready,
        )


def test_build_requires_enabled_backend(tmp_path):
    checkout = _checkout(tmp_path)
    with pytest.raises(SandboxUnavailable):
        build_in_sandbox(
            checkout,
            config=SandboxConfig(backend="off", work_root=tmp_path),
            runner=_Runner(),
            base_root=tmp_path / "archbuild",
            tool_capture=_tools(),
        )
