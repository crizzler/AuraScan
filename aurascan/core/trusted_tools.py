"""Small trust boundary for fixed system executables used on hostile input."""

import os
import selectors
import shutil
import signal
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Optional


MAX_TRUSTED_TOOL_OUTPUT_BYTES = 256 * 1024


class TrustedToolError(RuntimeError):
    """A required executable was missing, unsafe, or changed after capture."""


@dataclass(frozen=True)
class TrustedTool:
    name: str
    path: str
    device: int
    inode: int
    owner: int
    group: int
    mode: int


def _trusted_tool_stat(name: str, path: str) -> os.stat_result:
    candidate = Path(path)
    if not candidate.is_absolute() or ".." in candidate.parts:
        raise TrustedToolError("trusted tool path was not absolute and normalized")

    current = Path(candidate.anchor)
    for component in [current] + [
        current.joinpath(*candidate.parts[1:index])
        for index in range(2, len(candidate.parts))
    ]:
        try:
            metadata = os.lstat(str(component))
        except OSError as exc:
            raise TrustedToolError("trusted tool path component was unavailable") from exc
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise TrustedToolError("trusted tool path component was unsafe")
        if metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise TrustedToolError("trusted tool path component permissions were unsafe")
        if os.geteuid() != 0 and os.access(str(component), os.W_OK):
            raise TrustedToolError("trusted tool path component was writable by the caller")

    try:
        metadata = os.lstat(str(candidate))
    except OSError as exc:
        raise TrustedToolError("trusted tool was unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise TrustedToolError("trusted tool was not a regular non-link file")
    if metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise TrustedToolError("trusted tool ownership or permissions were unsafe")
    if os.geteuid() != 0 and os.access(str(candidate), os.W_OK):
        raise TrustedToolError("trusted tool was writable by the caller")
    if not metadata.st_mode & 0o111:
        raise TrustedToolError("trusted tool was not executable")
    return metadata


def capture_trusted_system_tool(
    name: str,
    *,
    which: Optional[Callable[[str], Optional[str]]] = None,
) -> Optional[TrustedTool]:
    """Capture `/usr/bin/<name>` only when PATH resolves to that exact file."""

    expected = str(Path("/usr/bin") / name)
    resolver = which or shutil.which
    resolved = resolver(name)
    if resolved is None:
        return None
    if os.path.normpath(str(resolved)) != expected:
        raise TrustedToolError("PATH did not resolve the trusted system tool")
    metadata = _trusted_tool_stat(name, expected)
    return TrustedTool(
        name=name,
        path=expected,
        device=int(metadata.st_dev),
        inode=int(metadata.st_ino),
        owner=int(metadata.st_uid),
        group=int(metadata.st_gid),
        mode=int(metadata.st_mode),
    )


def revalidate_trusted_system_tool(tool: TrustedTool) -> None:
    metadata = _trusted_tool_stat(tool.name, tool.path)
    observed = (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_uid),
        int(metadata.st_gid),
        int(metadata.st_mode),
    )
    expected = (
        tool.device,
        tool.inode,
        tool.owner,
        tool.group,
        tool.mode,
    )
    if observed != expected:
        raise TrustedToolError("trusted system tool changed after capture")


def run_bounded_trusted_tool(
    args,
    *,
    capture_output: bool = False,
    text: bool = False,
    timeout: Optional[float] = None,
    check: bool = False,
    env: Optional[Dict[str, str]] = None,
    cwd: Optional[str] = None,
):
    """Run an already-captured native helper without unbounded pipe reads."""

    if not capture_output:
        raise ValueError("bounded trusted-tool runner requires captured output")
    process = subprocess.Popen(
        list(args),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        env=env,
        cwd=cwd,
    )
    selector = selectors.DefaultSelector()
    stdout = bytearray()
    stderr = bytearray()
    streams = []
    if process.stdout is not None:
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        streams.append(process.stdout)
    if process.stderr is not None:
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        streams.append(process.stderr)
    deadline = time.monotonic() + max(0.001, float(timeout or 30.0))
    failure = ""
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = "timeout"
                break
            for key, _events in selector.select(min(0.1, remaining)):
                try:
                    chunk = os.read(key.fd, 65536)
                except OSError:
                    chunk = b""
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                target = stdout if key.data == "stdout" else stderr
                target.extend(chunk)
                if len(stdout) + len(stderr) > MAX_TRUSTED_TOOL_OUTPUT_BYTES:
                    failure = "oversized"
                    break
            if failure:
                break
        if failure:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                try:
                    process.kill()
                except OSError:
                    pass
        try:
            returncode = process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
            except OSError:
                pass
            returncode = process.wait()
            failure = "timeout"
    finally:
        selector.close()
        for stream in streams:
            stream.close()

    bounded_stdout = bytes(stdout[:MAX_TRUSTED_TOOL_OUTPUT_BYTES])
    remaining = MAX_TRUSTED_TOOL_OUTPUT_BYTES - len(bounded_stdout)
    bounded_stderr = bytes(stderr[:max(0, remaining)])
    if text:
        rendered_stdout = bounded_stdout.decode("utf-8", errors="replace")
        rendered_stderr = bounded_stderr.decode("utf-8", errors="replace")
    else:
        rendered_stdout = bounded_stdout
        rendered_stderr = bounded_stderr
    if failure == "timeout":
        raise subprocess.TimeoutExpired(
            list(args),
            timeout,
            output=rendered_stdout,
            stderr=rendered_stderr,
        )
    if failure == "oversized":
        raise subprocess.SubprocessError("trusted native-tool output exceeded the safety bound")
    completed = subprocess.CompletedProcess(
        list(args),
        int(returncode),
        rendered_stdout,
        rendered_stderr,
    )
    if check and completed.returncode != 0:
        raise subprocess.CalledProcessError(
            completed.returncode,
            completed.args,
            output=completed.stdout,
            stderr=completed.stderr,
        )
    return completed
