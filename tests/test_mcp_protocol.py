"""Framing, lifecycle, malformed input, oversize lines, timeout, cancellation and protocol rows."""

import json
import os
import signal
import time
from pathlib import Path

import pytest

from helpers import mcp_client
from helpers.mcp_client import Loop, honour_line, spawn


def _root(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    return root


# -- framing and lifecycle ------------------------------------------------ #


def test_01_initialize_echoes_id_and_ships_the_honesty_line(tmp_path):
    with spawn(_root(tmp_path)) as client:
        message = client.initialize()

    assert message["id"] == 1
    assert message["result"]["serverInfo"]["name"] == "aurascan"
    assert honour_line() in message["result"]["instructions"]
    assert message["result"]["protocolVersion"] == "2025-06-18"


def test_02_initialized_notification_writes_nothing(tmp_path):
    with spawn(_root(tmp_path)) as client:
        client.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        assert client.read_none(0.8)
        client.send({"jsonrpc": "2.0", "method": "ping", "id": 2})
        assert client.read()["id"] == 2


SURFACE = Path(__file__).resolve().parent / "fixtures" / "mcp" / "tool_surface.json"

# Append-only rule: a tool added later must be pinned here before it can ship, and none of these
# triples may flip without an annotation review.
PINNED_ANNOTATIONS = {
    "scan_content": (True, False, False),
    "scan_path": (True, False, False),
    "audit_agent_config": (True, False, False),
    "security_audit": (True, False, False),
}


def _triple(tool):
    annotations = tool["annotations"]
    return (
        annotations["readOnlyHint"],
        annotations["destructiveHint"],
        annotations["openWorldHint"],
    )


def test_03_tools_list_is_the_pinned_surface(tmp_path):
    with spawn(_root(tmp_path)) as client:
        client.send({"jsonrpc": "2.0", "method": "tools/list", "id": 1})
        tools = client.read()["result"]["tools"]

    surface = json.loads(SURFACE.read_text(encoding="utf-8"))
    assert [tool["name"] for tool in tools][: len(surface)] == [
        entry["name"] for entry in surface
    ]
    # Every pinned field, in order: name, description, inputSchema and annotations.
    for tool, expected in zip(tools, surface):
        assert tool == expected

    for tool in tools:
        assert tool["inputSchema"]["type"] == "object"
        assert _triple(tool) == PINNED_ANNOTATIONS[tool["name"]], tool["name"]
        assert tool["annotations"]["title"]

    by_name = {tool["name"]: tool["description"] for tool in tools}
    for name in ("scan_content", "scan_path", "audit_agent_config"):
        assert honour_line() in by_name[name]
    assert honour_line() not in by_name["security_audit"]
    assert "read-only process" in by_name["security_audit"]

    # The registration block a human applies must name the same four tools, slice for slice.
    names = sorted(by_name)
    for source in (
        Path(__file__).resolve().parents[1] / "README.md",
        Path(__file__).resolve().parent / "fixtures" / "mcp" / "registration.yaml",
    ):
        text = source.read_text(encoding="utf-8")
        assert "verify_evidence" not in text
        assert "tools.include" in text or "include:" in text
        for name in names:
            assert name in text, (source, name)


def test_04_shutdown_then_exit_is_status_zero(tmp_path):
    with spawn(_root(tmp_path)) as client:
        client.send({"jsonrpc": "2.0", "method": "shutdown", "id": 1})
        assert client.read()["result"] is None
        client.send({"jsonrpc": "2.0", "method": "exit"})
        assert client.wait(10) == 0
        assert client.read_none(1.0)


def test_05_eof_without_shutdown_is_status_zero(tmp_path):
    client = spawn(_root(tmp_path))
    client.initialize()
    # A trailing partial line (no final newline) is dispatched before the loop exits.
    client.send_raw(b'{"jsonrpc":"2.0","method":"ping","id":2}')
    client.proc.stdin.close()
    assert client.read()["id"] == 2
    assert client.wait(10) == 0
    client.close()


def test_06_sigterm_while_idle_is_status_zero(tmp_path):
    client = spawn(_root(tmp_path))
    client.initialize()
    client.proc.send_signal(signal.SIGTERM)
    assert client.wait(10) == 0
    client.close()


def test_07_stdout_stays_pure_protocol(tmp_path):
    with spawn(_root(tmp_path)) as client:
        client.initialize()
        client.send({"jsonrpc": "2.0", "method": "tools/list", "id": 2})
        client.send({"jsonrpc": "2.0", "method": "ping", "id": 3})
        for _ in range(2):
            json.loads(client.read_raw().decode("utf-8"))
        stderr = client.stderr_text()

    assert stderr.startswith("[aurascan-mcp] ")


# -- malformed input ------------------------------------------------------ #


def test_08_non_json_then_valid_request(tmp_path):
    with spawn(_root(tmp_path)) as client:
        client.send_raw(b"not json\n")
        assert client.read()["error"]["code"] == -32700
        client.send({"jsonrpc": "2.0", "method": "ping", "id": 2})
        assert client.read()["id"] == 2


def test_09_scalar_and_array_documents_are_invalid_requests(tmp_path):
    with spawn(_root(tmp_path)) as client:
        client.send_raw(b"5\n")
        assert client.read()["error"]["code"] == -32600
        client.send_raw(b"[{}]\n")
        assert client.read()["error"]["data"] == "batch not supported"


def test_10_wrong_protocol_version(tmp_path):
    with spawn(_root(tmp_path)) as client:
        client.send({"jsonrpc": "1.0", "method": "ping", "id": 1})
        message = client.read()

    assert message["error"]["code"] == -32600
    assert message["id"] == 1


def test_11_unknown_methods(tmp_path):
    with spawn(_root(tmp_path)) as client:
        client.send({"jsonrpc": "2.0", "method": "nope", "id": 7})
        assert client.read()["error"]["code"] == -32601
        client.send({"jsonrpc": "2.0", "method": "nope-notification"})
        assert client.read_none(0.8)


def test_13_non_utf8_line(tmp_path):
    with spawn(_root(tmp_path)) as client:
        client.send_raw(b"\xff\xfe\n")
        assert client.read()["error"]["code"] == -32700


def test_14_raising_handler_is_internal_error(tmp_path):
    from aurascan.mcp import results

    loop = Loop([str(_root(tmp_path))])

    def boom(ctx, arguments):
        raise RuntimeError("exploded")

    loop.server.tools["boom"] = type("T", (), {
        "name": "boom",
        "budget": 5,
        "schema": {"type": "object", "properties": {}, "additionalProperties": False},
        "handler": staticmethod(boom),
    })()

    loop.feed({"jsonrpc": "2.0", "method": "tools/call",
               "params": {"name": "boom", "arguments": {}}, "id": 1})
    assert loop.only()["error"]["code"] == -32603
    loop.feed({"jsonrpc": "2.0", "method": "ping", "id": 2})
    assert loop.lines()[-1]["result"] == {}
    assert results is not None


def test_15_oversize_line_resynchronises(tmp_path):
    with spawn(_root(tmp_path), args=["--max-line-bytes", "64"]) as client:
        client.send_raw(b"x" * 65 + b"\n")
        message = client.read()
        assert message["error"]["code"] == -32700
        assert message["error"]["data"] == "line exceeds 64 bytes"
        client.send({"jsonrpc": "2.0", "method": "ping", "id": 2})
        assert client.read()["id"] == 2


# -- timeout and cancellation -------------------------------------------- #


def test_50_timeout_is_a_tool_error_and_the_session_survives(tmp_path):
    import time

    loop = Loop([str(_root(tmp_path))], budgets={"slow": 1})

    def slow(ctx, arguments):
        time.sleep(5)
        return {"content": [{"type": "text", "text": "{}"}], "isError": False}

    loop.server.tools["slow"] = type("T", (), {
        "name": "slow",
        "budget": 30,
        "schema": {"type": "object", "properties": {}, "additionalProperties": False},
        "handler": staticmethod(slow),
    })()

    loop.feed({"jsonrpc": "2.0", "method": "tools/call",
               "params": {"name": "slow", "arguments": {}}, "id": 1})
    message = loop.only()
    assert message["result"]["isError"] is True
    assert json.loads(message["result"]["content"][0]["text"])["error"]["code"] == "timeout"
    loop.feed({"jsonrpc": "2.0", "method": "ping", "id": 2})
    assert loop.lines()[-1]["id"] == 2


def _shim_dir(tmp_path, script):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    pacman = bin_dir / "pacman"
    pacman.write_text(script, encoding="utf-8")
    pacman.chmod(0o755)
    return bin_dir


def test_51_cancelled_running_call_returns_cancelled(tmp_path):
    root = _root(tmp_path)
    bin_dir = _shim_dir(tmp_path, "#!/bin/sh\nsleep 3\n")
    env = {"PATH": "%s:%s" % (bin_dir, os.environ.get("PATH", ""))}
    with spawn(root, args=["--budget", "security_audit=30"], env=env) as client:
        client.call("security_audit", {}, request_id=42)
        time.sleep(0.3)
        client.send({"jsonrpc": "2.0", "method": "notifications/cancelled",
                     "params": {"requestId": 42}})
        error = client.read_error(30)

    assert error["code"] == "cancelled"


def test_52_sigalrm_handler_and_interval_are_restored(tmp_path):
    import time

    sentinel = lambda signum, frame: None  # noqa: E731
    previous = signal.signal(signal.SIGALRM, sentinel)
    try:
        loop = Loop([str(_root(tmp_path))], budgets={"slow": 1})

        def slow(ctx, arguments):
            time.sleep(5)
            return {"content": [{"type": "text", "text": "{}"}], "isError": False}

        loop.server.tools["slow"] = type("T", (), {
            "name": "slow", "budget": 30,
            "schema": {"type": "object", "properties": {}, "additionalProperties": False},
            "handler": staticmethod(slow),
        })()

        loop.feed({"jsonrpc": "2.0", "method": "tools/call",
                   "params": {"name": "slow", "arguments": {}}, "id": 1})
        loop.feed({"jsonrpc": "2.0", "method": "ping", "id": 2})
        assert signal.getsignal(signal.SIGALRM) is sentinel
        assert signal.getitimer(signal.ITIMER_REAL)[0] == 0
    finally:
        signal.signal(signal.SIGALRM, previous)


def test_53_no_pacman_survives_a_timeout(tmp_path):
    root = _root(tmp_path)
    bin_dir = _shim_dir(tmp_path, "#!/bin/sh\nsleep 30\n")
    env = {"PATH": "%s:%s" % (bin_dir, os.environ.get("PATH", ""))}
    with spawn(root, args=["--budget", "security_audit=2"], env=env) as client:
        client.call("security_audit", {}, request_id=5)
        error = client.read_error(30)

    assert error["code"] == "timeout"
    marker = str(bin_dir).encode("utf-8")
    survivors = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        try:
            cmdline = open("/proc/%s/cmdline" % (entry,), "rb").read()
        except OSError:
            continue
        if marker in cmdline:
            survivors.append((entry, cmdline))
    assert survivors == []


# -- protocol rows -------------------------------------------------------- #


def test_54_duplicate_request_keys_are_last_wins(tmp_path):
    with spawn(_root(tmp_path)) as client:
        client.send_raw(
            b'{"jsonrpc":"2.0","method":"ping","method":"tools/list","id":1}\n'
        )
        assert "tools" in client.read()["result"]


def test_55_params_null_is_absent_except_for_tools_call(tmp_path):
    with spawn(_root(tmp_path)) as client:
        client.send({"jsonrpc": "2.0", "method": "ping", "params": None, "id": 1})
        assert client.read()["result"] == {}
        client.send({"jsonrpc": "2.0", "method": "tools/call", "params": None, "id": 2})
        assert client.read()["error"]["code"] == -32602


def test_56_non_scalar_id_is_invalid_request(tmp_path):
    with spawn(_root(tmp_path)) as client:
        client.send({"jsonrpc": "2.0", "method": "ping", "id": {}})
        message = client.read()
        assert message["error"]["code"] == -32600
        assert message["id"] is None
        client.send({"jsonrpc": "2.0", "method": "ping", "id": []})
        assert client.read()["id"] is None


def test_57_request_after_shutdown_is_served(tmp_path):
    with spawn(_root(tmp_path)) as client:
        client.send({"jsonrpc": "2.0", "method": "shutdown", "id": 1})
        client.read()
        client.send({"jsonrpc": "2.0", "method": "ping", "id": 2})
        assert client.read()["result"] == {}
        client.send({"jsonrpc": "2.0", "method": "exit"})
        assert client.wait(10) == 0
        assert client.read_none(1.0)


def test_61_cancel_queued_behind_the_call_still_yields_one_response(tmp_path):
    loop = Loop([str(_root(tmp_path))])
    loop.enqueue({"jsonrpc": "2.0", "method": "tools/call",
                  "params": {"name": "scan_content", "arguments": {"content": "hello"}}, "id": 1})
    loop.enqueue({"jsonrpc": "2.0", "method": "notifications/cancelled",
                  "params": {"requestId": 1}})
    loop.enqueue({"jsonrpc": "2.0", "method": "ping", "id": 2})
    loop.protocol.queue.put(("eof", None))
    loop.protocol.run_queue()

    lines = loop.lines()
    assert [line["id"] for line in lines] == [1, 2]
    assert lines[0]["result"]["isError"] is False


def test_63_budget_parsing(tmp_path):
    root = tmp_path / "build"
    root.mkdir()
    for bad in ("0", "scan_content=0", "scan_content=-1", "scan_content=x", "notatool=5"):
        client = spawn(root, args=["--budget", bad])
        code = client.wait(10)
        text = client.stderr_text()
        client.close()
        assert code == 2, (bad, code, text)
        assert "--budget" in text

    with spawn(root, args=["--budget", "scan_content=1"]) as client:
        assert client.initialize()["result"]["serverInfo"]["name"] == "aurascan"
