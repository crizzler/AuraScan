import hashlib
import os
import shutil
import subprocess
from pathlib import Path

import pytest

import aurascan.core.build_sandbox as build_sandbox
from aurascan.core.build_sandbox import (
    AUR_SANDBOX_ENV,
    AUR_SANDBOX_WORK_ROOT_ENV,
    SandboxBuildError,
    SandboxBuildResult,
    SandboxConfig,
    SandboxUnavailable,
    build_in_sandbox,
    cleanup_sandbox_build,
    resolve_sandbox_config,
    sandbox_makepkg_arguments,
    sandbox_status,
)
from aurascan.core.trusted_tools import TrustedTool, TrustedToolError


@pytest.fixture(autouse=True)
def allow_fixture_devtools_config(monkeypatch):
    monkeypatch.setattr(
        "aurascan.core.build_sandbox._probe_config_paths",
        lambda: (True, ""),
    )


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


def _cleanup_result(
    tmp_path,
    *,
    sudo_tool=None,
    rm_tool=None,
    sudo_path="/usr/bin/sudo",
    rm_path="/usr/bin/rm",
):
    root = tmp_path / "aurascan-devbuild-r10"
    root.mkdir()
    return SandboxBuildResult(
        backend="devtools",
        build_root=root,
        artifacts=(),
        duration_seconds=0.0,
        sudo_path=sudo_path,
        rm_path=rm_path,
        sudo_tool=sudo_tool,
        rm_tool=rm_tool,
    )


def _refuse_tree_delete(_path):
    raise OSError("root-owned tree requires the privileged removal path")


def _cleanup_tools():
    return _tool("sudo"), _tool("rm")


def test_cleanup_trace_revalidates_the_captured_objects_before_the_command(tmp_path, monkeypatch):
    sudo_tool, rm_tool = _cleanup_tools()
    result = _cleanup_result(tmp_path, sudo_tool=sudo_tool, rm_tool=rm_tool)
    root = result.build_root
    events = []
    calls = []
    monkeypatch.setattr(build_sandbox.shutil, "rmtree", _refuse_tree_delete)

    def recapture_forbidden(*_args, **_kwargs):
        raise AssertionError("cleanup must not recapture privileged tools")

    monkeypatch.setattr(build_sandbox, "capture_trusted_system_tool", recapture_forbidden)

    def revalidate(tool):
        events.append(("revalidate", tool.name, tool))

    def runner(command, **kwargs):
        events.append(("runner", tuple(command)))
        calls.append((list(command), dict(kwargs)))
        root.rmdir()
        return subprocess.CompletedProcess(list(command), 0)

    warning = cleanup_sandbox_build(result, runner=runner, tool_revalidate=revalidate)

    assert warning == ""
    assert [event[0] for event in events] == ["revalidate", "revalidate", "runner"]
    assert events[0][1] == "sudo"
    assert events[0][2] is sudo_tool
    assert events[1][1] == "rm"
    assert events[1][2] is rm_tool
    assert events[2][1] == (
        "/usr/bin/sudo",
        "/usr/bin/rm",
        "-rf",
        "--one-file-system",
        str(root),
    )
    assert calls == [
        (
            ["/usr/bin/sudo", "/usr/bin/rm", "-rf", "--one-file-system", str(root)],
            {"check": False, "timeout": 300.0},
        )
    ]
    assert result.sudo_tool is sudo_tool
    assert result.rm_tool is rm_tool
    assert not root.exists()


def test_cleanup_refuses_an_unexpected_tree_name_without_claiming_partial_removal(
    tmp_path
):
    root = tmp_path / "not-a-build-tree"
    root.mkdir()
    result = SandboxBuildResult(
        backend="devtools",
        build_root=root,
        artifacts=(),
        duration_seconds=0.0,
        sudo_path="/usr/bin/sudo",
        rm_path="/usr/bin/rm",
        sudo_tool=_tool("sudo"),
        rm_tool=_tool("rm"),
    )
    calls = []

    warning = cleanup_sandbox_build(
        result,
        runner=lambda command, **_kwargs: calls.append(command),
        tool_revalidate=lambda _tool: None,
    )

    assert warning == (
        "The isolated build tree did not match the private cleanup path policy "
        "and was not removed; inspect it manually."
    )
    assert calls == []
    assert root.exists()


@pytest.mark.parametrize("missing", ["sudo", "rm", "both"])
def test_cleanup_retains_tree_and_reports_when_a_captured_object_is_missing(
    tmp_path, monkeypatch, missing
):
    sudo_tool = None if missing in {"sudo", "both"} else _tool("sudo")
    rm_tool = None if missing in {"rm", "both"} else _tool("rm")
    result = _cleanup_result(tmp_path, sudo_tool=sudo_tool, rm_tool=rm_tool)
    calls = []
    monkeypatch.setattr(build_sandbox.shutil, "rmtree", _refuse_tree_delete)

    warning = cleanup_sandbox_build(
        result, runner=lambda command, **_kwargs: calls.append(command)
    )

    assert warning.startswith("The isolated build tree could not be removed")
    assert "build tree may be partially removed" in warning
    assert calls == []
    assert result.build_root.exists()
    # Display strings stay populated but the missing object is never replaced.
    assert result.sudo_path and result.rm_path


@pytest.mark.parametrize("tool_name", ["sudo", "rm"])
@pytest.mark.parametrize(
    "error",
    [
        TrustedToolError("changed after capture"),
        OSError("identity unavailable"),
        TypeError("bad identity"),
    ],
    ids=["trusted-tool-error", "oserror", "typeerror"],
)
def test_cleanup_refuses_when_each_privileged_identity_validation_raises(
    tmp_path, monkeypatch, tool_name, error
):
    sudo_tool, rm_tool = _cleanup_tools()
    result = _cleanup_result(tmp_path, sudo_tool=sudo_tool, rm_tool=rm_tool)
    calls = []
    events = []
    monkeypatch.setattr(build_sandbox.shutil, "rmtree", _refuse_tree_delete)

    def revalidate(tool):
        events.append(tool.name)
        if tool.name == tool_name:
            raise error

    warning = cleanup_sandbox_build(
        result,
        runner=lambda command, **_kwargs: calls.append(command),
        tool_revalidate=revalidate,
    )

    assert "could not be removed" in warning
    assert "identity could not be revalidated" in warning
    assert "build tree may be partially removed" in warning
    assert calls == []
    assert result.build_root.exists()
    assert events == (["sudo"] if tool_name == "sudo" else ["sudo", "rm"])


def test_cleanup_reports_a_timed_out_privileged_command(tmp_path, monkeypatch):
    sudo_tool, rm_tool = _cleanup_tools()
    result = _cleanup_result(tmp_path, sudo_tool=sudo_tool, rm_tool=rm_tool)
    monkeypatch.setattr(build_sandbox.shutil, "rmtree", _refuse_tree_delete)

    def runner(command, **kwargs):
        raise subprocess.TimeoutExpired(list(command), kwargs["timeout"])

    warning = cleanup_sandbox_build(
        result, runner=runner, tool_revalidate=lambda _tool: None
    )

    assert warning == (
        "The privileged cleanup command timed out; the build tree may be "
        "partially removed. Remove any remaining files manually."
    )
    assert result.build_root.exists()


@pytest.mark.parametrize(
    "error",
    [OSError("spawn failed"), TypeError("bad runner")],
    ids=["oserror", "typeerror"],
)
def test_cleanup_reports_a_privileged_command_that_cannot_start(
    tmp_path, monkeypatch, error
):
    sudo_tool, rm_tool = _cleanup_tools()
    result = _cleanup_result(tmp_path, sudo_tool=sudo_tool, rm_tool=rm_tool)
    monkeypatch.setattr(build_sandbox.shutil, "rmtree", _refuse_tree_delete)

    def runner(_command, **_kwargs):
        raise error

    warning = cleanup_sandbox_build(
        result, runner=runner, tool_revalidate=lambda _tool: None
    )

    assert warning == (
        "The privileged cleanup command could not be started; the build tree "
        "may be partially removed. Remove any remaining files manually."
    )
    assert result.build_root.exists()


def test_cleanup_does_not_verify_a_nonzero_command_with_a_retained_tree(
    tmp_path, monkeypatch
):
    sudo_tool, rm_tool = _cleanup_tools()
    result = _cleanup_result(tmp_path, sudo_tool=sudo_tool, rm_tool=rm_tool)
    monkeypatch.setattr(build_sandbox.shutil, "rmtree", _refuse_tree_delete)

    def runner(command, **_kwargs):
        return subprocess.CompletedProcess(list(command), 1)

    warning = cleanup_sandbox_build(
        result, runner=runner, tool_revalidate=lambda _tool: None
    )

    assert warning == (
        "The privileged cleanup command failed with exit status 1; the build "
        "tree may be partially removed. Remove any remaining files manually."
    )
    assert result.build_root.exists()


def test_cleanup_reports_a_nonzero_command_even_when_the_tree_is_absent(
    tmp_path, monkeypatch
):
    sudo_tool, rm_tool = _cleanup_tools()
    result = _cleanup_result(tmp_path, sudo_tool=sudo_tool, rm_tool=rm_tool)
    root = result.build_root
    monkeypatch.setattr(build_sandbox.shutil, "rmtree", _refuse_tree_delete)

    def runner(command, **_kwargs):
        root.rmdir()
        return subprocess.CompletedProcess(list(command), 1)

    warning = cleanup_sandbox_build(
        result, runner=runner, tool_revalidate=lambda _tool: None
    )

    assert warning == (
        "The privileged cleanup command failed with exit status 1, but the "
        "build tree is no longer present; removal may have been partial."
    )
    assert not root.exists()


def test_cleanup_reports_a_zero_status_that_left_the_tree_in_place(tmp_path, monkeypatch):
    sudo_tool, rm_tool = _cleanup_tools()
    result = _cleanup_result(tmp_path, sudo_tool=sudo_tool, rm_tool=rm_tool)
    monkeypatch.setattr(build_sandbox.shutil, "rmtree", _refuse_tree_delete)

    def runner(command, **_kwargs):
        return subprocess.CompletedProcess(list(command), 0)

    warning = cleanup_sandbox_build(
        result, runner=runner, tool_revalidate=lambda _tool: None
    )

    assert warning == (
        "The privileged cleanup command reported success, but the build tree "
        "is still present; remove it manually."
    )
    assert result.build_root.exists()


class _Completion:
    """Minimal completion double for deliberately malformed status values."""

    def __init__(self, returncode):
        self.returncode = returncode


@pytest.mark.parametrize(
    "completed",
    [
        None,
        object(),
        _Completion(None),
        _Completion(True),
        _Completion("0"),
    ],
    ids=["none", "no-returncode", "none-status", "bool-status", "text-status"],
)
def test_cleanup_fails_closed_on_missing_or_malformed_completion_evidence(
    tmp_path, monkeypatch, completed
):
    sudo_tool, rm_tool = _cleanup_tools()
    result = _cleanup_result(tmp_path, sudo_tool=sudo_tool, rm_tool=rm_tool)
    monkeypatch.setattr(build_sandbox.shutil, "rmtree", _refuse_tree_delete)

    warning = cleanup_sandbox_build(
        result,
        runner=lambda _command, **_kwargs: completed,
        tool_revalidate=lambda _tool: None,
    )

    assert warning == (
        "The privileged cleanup command did not report a usable exit status; "
        "the build tree may be partially removed. Remove any remaining files "
        "manually."
    )
    assert result.build_root.exists()


def test_cleanup_fails_closed_on_malformed_evidence_but_does_not_demand_absence_work(
    tmp_path, monkeypatch
):
    sudo_tool, rm_tool = _cleanup_tools()
    result = _cleanup_result(tmp_path, sudo_tool=sudo_tool, rm_tool=rm_tool)
    root = result.build_root
    monkeypatch.setattr(build_sandbox.shutil, "rmtree", _refuse_tree_delete)

    def runner(_command, **_kwargs):
        root.rmdir()
        return None

    warning = cleanup_sandbox_build(
        result, runner=runner, tool_revalidate=lambda _tool: None
    )

    assert warning == (
        "The privileged cleanup command did not report a usable exit status, "
        "but the build tree is no longer present; removal may have been partial."
    )
    assert not root.exists()


def test_failed_build_cleanup_keeps_the_original_error_and_reports_the_retained_tree(
    tmp_path, monkeypatch
):
    checkout = _checkout(tmp_path)
    work = tmp_path / "work"
    real_rmtree = shutil.rmtree
    table = {
        name: _tool(name)
        for name in (
            build_sandbox.AUR_SANDBOX_REQUIRED_TOOLS
            + build_sandbox.AUR_SANDBOX_ROOT_COMMANDS
        )
    }
    capture_calls = []
    revalidated = []
    cleanup_calls = []

    def capture(name):
        capture_calls.append(name)
        return table.get(name)

    def revalidate(tool):
        revalidated.append(tool)

    def runner(command, **kwargs):
        command = list(command)
        if "/bin/bash" in command:
            return subprocess.CompletedProcess(command, 1)
        if command[1:2] == ["/usr/bin/cp"]:
            return subprocess.CompletedProcess(command, 0)
        cleanup_calls.append((command, dict(kwargs)))
        return subprocess.CompletedProcess(command, 1)

    monkeypatch.setattr(build_sandbox.shutil, "rmtree", _refuse_tree_delete)

    with pytest.raises(SandboxBuildError) as caught:
        build_in_sandbox(
            checkout,
            config=SandboxConfig(backend="devtools", work_root=work),
            runner=runner,
            base_root=tmp_path / "archbuild",
            tool_capture=capture,
            tool_revalidate=revalidate,
            base_probe=_base_ready,
        )

    exc = caught.value
    assert type(exc) is SandboxBuildError
    assert str(exc) == "the isolated build failed with exit status 1"
    assert exc.cleanup_warning == (
        "The privileged cleanup command failed with exit status 1; the build "
        "tree may be partially removed. Remove any remaining files manually."
    )
    retained = list(work.glob("aurascan-devbuild-*"))
    assert len(retained) == 1
    assert retained[0].is_dir()
    assert len(cleanup_calls) == 1
    assert cleanup_calls[0][0][1] == "/usr/bin/rm"
    assert cleanup_calls[0][1] == {"check": False, "timeout": 300.0}
    # The cleanup revalidated the captured objects themselves, only after the
    # build-time capture pass, and never recaptured a tool.
    assert len(capture_calls) == len(table) * 2
    assert revalidated.count(table["sudo"]) == 2
    assert revalidated.count(table["rm"]) == 2
    assert revalidated[-2] is table["sudo"]
    assert revalidated[-1] is table["rm"]
    real_rmtree(retained[0])


def test_successful_build_carries_the_original_captured_tool_objects(tmp_path):
    checkout = _checkout(tmp_path)
    table = {
        name: _tool(name)
        for name in (
            build_sandbox.AUR_SANDBOX_REQUIRED_TOOLS
            + build_sandbox.AUR_SANDBOX_ROOT_COMMANDS
        )
    }
    capture_calls = []

    def capture(name):
        capture_calls.append(name)
        return table.get(name)

    result = build_in_sandbox(
        checkout,
        config=SandboxConfig(backend="devtools", work_root=tmp_path / "work"),
        runner=_Runner(),
        base_root=tmp_path / "archbuild",
        tool_capture=capture,
        tool_revalidate=lambda _tool: None,
        base_probe=_base_ready,
    )
    try:
        assert result.sudo_tool is table["sudo"]
        assert result.rm_tool is table["rm"]
        assert result.sudo_path == table["sudo"].path
        assert result.rm_path == table["rm"].path
        assert len(capture_calls) == len(table) * 2
    finally:
        assert cleanup_sandbox_build(result) == ""
