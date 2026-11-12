"""Fixed-path trusted-tool capture and immediate revalidation (recovery R7)."""

import os
from pathlib import Path

import pytest

from aurascan.core import trusted_tools
from aurascan.core.trusted_tools import (
    HOST_TOOL_FIRST_USE_MESSAGE,
    TrustedTool,
    TrustedToolError,
    _trusted_tool_stat,
    capture_trusted_system_tool,
    require_trusted_system_tool,
)


def test_host_tool_first_use_message_is_fixed_and_secret_free():
    assert HOST_TOOL_FIRST_USE_MESSAGE == (
        "A required recovery host tool could not be validated as a trusted system executable; "
        "no command was executed."
    )


def test_require_trusted_system_tool_captures_the_fixed_path():
    tool = require_trusted_system_tool("true")

    assert tool == TrustedTool(
        name="true",
        path="/usr/bin/true",
        device=tool.device,
        inode=tool.inode,
        owner=tool.owner,
        group=tool.group,
        mode=tool.mode,
    )
    assert tool.path == "/usr/bin/true"
    assert tool.owner == 0
    assert tool.mode & 0o111


def test_require_trusted_system_tool_never_consults_path(tmp_path, monkeypatch):
    hostile = tmp_path / "hostile-bin"
    hostile.mkdir()
    wrapper = hostile / "true"
    wrapper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    wrapper.chmod(0o755)
    monkeypatch.setenv("PATH", str(hostile))

    def forbidden_which(_name):
        raise AssertionError("the fixed-path seam must not consult PATH")

    monkeypatch.setattr(trusted_tools.shutil, "which", forbidden_which)

    tool = require_trusted_system_tool("true")

    assert tool.path == "/usr/bin/true"
    assert wrapper.read_text(encoding="utf-8") == "#!/bin/sh\nexit 0\n"


def test_require_trusted_system_tool_refuses_an_absent_fixed_path():
    with pytest.raises(TrustedToolError):
        require_trusted_system_tool("aurascan-fixture-tool-that-does-not-exist")


def test_require_trusted_system_tool_refuses_a_traversing_name():
    with pytest.raises(TrustedToolError):
        require_trusted_system_tool("../bin/sh")
    with pytest.raises(TrustedToolError):
        require_trusted_system_tool("sh/../../bin/sh")


def test_require_trusted_system_tool_revalidates_immediately(monkeypatch):
    def changed_after_capture(_tool):
        raise TrustedToolError("trusted system tool changed after capture")

    monkeypatch.setattr(trusted_tools, "revalidate_trusted_system_tool", changed_after_capture)

    with pytest.raises(TrustedToolError, match="changed after capture"):
        require_trusted_system_tool("true")


def test_capture_trusted_system_tool_refuses_a_resolver_mismatch():
    with pytest.raises(TrustedToolError, match="PATH did not resolve"):
        capture_trusted_system_tool("true", which=lambda _name: "/usr/local/bin/true")


def test_trusted_tool_stat_refuses_relative_traversing_and_unowned_paths(tmp_path):
    with pytest.raises(TrustedToolError):
        _trusted_tool_stat("true", "usr/bin/env")
    with pytest.raises(TrustedToolError):
        _trusted_tool_stat("true", "/usr/bin/../bin/env")
    with pytest.raises(TrustedToolError):
        _trusted_tool_stat("true", str(tmp_path / "bin" / "true"))


def test_require_trusted_system_tool_does_not_hold_a_cached_identity(monkeypatch):
    calls = []
    real_capture = trusted_tools.capture_trusted_system_tool

    def recording_capture(name, *, which=None):
        calls.append(name)
        return real_capture(name, which=which)

    monkeypatch.setattr(trusted_tools, "capture_trusted_system_tool", recording_capture)
    first = require_trusted_system_tool("true")
    second = require_trusted_system_tool("true")

    assert calls == ["true", "true"]
    assert first == second
    assert os.stat("/usr/bin/true").st_ino == first.inode
    assert Path(first.path) == Path("/usr/bin/true")
