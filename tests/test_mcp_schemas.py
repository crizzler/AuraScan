"""Envelope and argument-validation behaviour: params shape, caps and numeric bounds."""

from helpers.mcp_client import spawn


def _root(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    return root


def test_12_params_shape_and_unknown_tool_are_invalid_params(tmp_path):
    with spawn(_root(tmp_path)) as client:
        client.send({"jsonrpc": "2.0", "method": "tools/call", "params": [], "id": 1})
        assert client.read()["error"]["code"] == -32602
        client.send({"jsonrpc": "2.0", "method": "tools/call",
                     "params": {"name": "nope", "arguments": {}}, "id": 2})
        message = client.read()
        assert message["error"]["code"] == -32602
        assert message["error"]["data"] == "unknown tool: nope"


def test_16_caps_and_numeric_bounds_are_stable_codes(tmp_path):
    with spawn(_root(tmp_path)) as client:
        client.call("scan_content", {"content": "x" * 262145}, request_id=1)
        assert client.read_error()["code"] == "content_too_large"
        for bound in (0, 33):
            client.call("scan_content", {"content": "hello", "max_findings": bound}, request_id=2)
            error = client.read_error()
            assert error["code"] == "invalid_arguments"
            assert "max_findings" in error["detail"]
        client.call("security_audit", {"max_findings": 501}, request_id=3)
        assert client.read_error()["code"] == "invalid_arguments"
        client.send({"jsonrpc": "2.0", "method": "ping", "id": 4})
        assert client.read()["id"] == 4


def test_17_over_cap_file_is_refused_before_the_read(tmp_path):
    root = _root(tmp_path)
    oversized = root / "big.md"
    oversized.write_bytes(b"a" * 262145)
    # Unreadable, so only a stat-before-open decision can report the cap rather than EACCES.
    oversized.chmod(0o000)
    with spawn(root) as client:
        client.call("scan_path", {"path": "big.md"})
        assert client.read_error()["code"] == "path_too_large"


def test_39_empty_arguments_are_schema_errors_not_crashes(tmp_path):
    with spawn(_root(tmp_path)) as client:
        for index, tool in enumerate((
            "scan_content",
            "scan_path",
            "audit_agent_config",
        )):
            client.call(tool, {}, request_id=index + 1)
            message = client.read()
            assert message["result"]["isError"] is True, (tool, message)
            assert "is required" in message["result"]["content"][0]["text"]
        # ``security_audit`` requires nothing, so ``{}`` is a valid call and must still answer.
        client.call("security_audit", {"max_findings": 1}, request_id=9)
        message = client.read()
        assert message["result"]["isError"] is False
        client.send({"jsonrpc": "2.0", "method": "ping", "id": 10})
        assert client.read()["id"] == 10
