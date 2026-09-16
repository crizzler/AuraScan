"""Bounded subprocess capture for already-authorized commands.

This adapter owns the *bounding* half of command execution: it runs a command
through the caller's injected runner with a timeout, captures stdout/stderr, and
truncates each stream to a caller-supplied character budget. It never resolves
an executable path, never validates a tool identity and never chooses the
command — the caller has already authorized both.

Trusted tool identity is a separate boundary: see
:mod:`aurascan.core.trusted_tools`, which captures and revalidates a fixed
system executable before running it on hostile input.
"""

import subprocess
from dataclasses import dataclass
from typing import Callable, Sequence


@dataclass
class CommandOutput:
    returncode: int
    stdout: str = ""
    stderr: str = ""
    truncated: bool = False


def run_bounded_command(
    runner: Callable,
    command: Sequence[str],
    *,
    max_chars: int,
    timeout: int,
) -> CommandOutput:
    kwargs = {"capture_output": True, "text": True, "check": False, "timeout": timeout}
    try:
        try:
            result = runner(list(command), **kwargs)
        except TypeError:
            kwargs.pop("timeout", None)
            result = runner(list(command), **kwargs)
    except (OSError, subprocess.SubprocessError) as exc:
        return CommandOutput(127, "", str(exc), False)
    stdout = str(getattr(result, "stdout", "") or "")
    stderr = str(getattr(result, "stderr", "") or "")
    truncated = len(stdout) > max_chars or len(stderr) > max_chars
    return CommandOutput(int(getattr(result, "returncode", 0)), stdout[:max_chars], stderr[:max_chars], truncated)
