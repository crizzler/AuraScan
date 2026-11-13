import json
import os
import shutil
import subprocess
import sys
from io import StringIO
from pathlib import Path

import pytest

import aurascan.core.agent_runtime_audit as runtime
from aurascan.core.agent import AGENT_FORBIDDEN_PROGRAMS
from aurascan.core.agent_audit_cli import run_agent_audit
from aurascan.core.agent_runtime_audit import (
    AGENT_AUDIT_REQUIRED_PROGRAMS,
    AgentAuditSchemaError,
    vocabulary_parity_errors,
)


def write(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def run(root: Path, surface: str = "mcp", *extra):
    out = StringIO()
    err = StringIO()
    code = run_agent_audit(
        ["--root", str(root), "--surface", surface, "--json", *extra],
        stdout=out,
        stderr=err,
    )
    return code, json.loads(out.getvalue()), out.getvalue(), err.getvalue()


def test_codex_builtin_shell_and_project_env(tmp_path: Path):
    write(tmp_path / ".codex" / "config.toml", 'approval_policy = "never"\n')
    write(tmp_path / ".env", "SENTINEL_DO_NOT_PRINT=weak-secret\n")

    code, data, raw, _err = run(tmp_path, "codex")

    assert code == 1
    assert data["facts"]["execution_authority"]["observed"] is True
    assert data["facts"]["execution_authority"]["channels"][0]["kind"] == "shell-tool"
    assert data["facts"]["execution_authority"]["approval_mode"]["normalized"] == "never"
    assert data["facts"]["secret_classes_readable"] == [
        {"class": "project-env", "scope": "project", "count": 1, "evidence": "observed"}
    ]
    assert data["aggregate"]["status"] == "cannot-rule-out"
    assert "This is not a model-safety verdict." in data["banner"]
    assert "SENTINEL_DO_NOT_PRINT" not in raw


def test_mcp_remote_only_is_clean(tmp_path: Path):
    write(
        tmp_path / ".mcp.json",
        '{"mcpServers":{"remote":{"url":"https://example.invalid/mcp"}}}',
    )

    code, data, _raw, _err = run(tmp_path, "mcp")

    assert code == 0
    assert data["facts"]["execution_authority"]["observed"] is False
    assert data["coverage"]["coverage_complete"] is True
    assert data["aggregate"]["status"] == "not-observed"


def test_mcp_stdio_command_is_execution_authority(tmp_path: Path):
    write(
        tmp_path / ".mcp.json",
        '{"mcpServers":{"local":{"command":"npx","args":["-y","server"]}}}',
    )

    code, data, _raw, _err = run(tmp_path, "mcp")

    assert code == 1
    assert data["facts"]["execution_authority"]["observed"] is True
    assert data["facts"]["execution_authority"]["channels"][0]["kind"] == "mcp-stdio-command"


def test_unknown_mcp_server_key_is_not_clean(tmp_path: Path):
    write(tmp_path / ".mcp.json", '{"mcpServers":{"local":{"shell":"bash"}}}')

    code, data, _raw, _err = run(tmp_path, "mcp")

    assert code == 3
    assert data["coverage"]["coverage_complete"] is False
    assert "mcp-unknown-execution-key" in data["coverage"]["reasons"]
    assert any(
        item["rule_id"] == "AGENT-RUNTIME-CONFIG-INCOMPLETE-001"
        for item in data["findings"]
    )


def test_claude_hook_is_authority_without_echoing_command(tmp_path: Path):
    write(
        tmp_path / ".claude" / "settings.json",
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {"hooks": [{"type": "command", "command": "curl http://sentinel.invalid"}]}
                    ]
                }
            }
        ),
    )
    write(tmp_path / ".claude" / "settings.local.json", "{}")

    code, data, raw, _err = run(tmp_path, "claude")

    assert code == 1
    kinds = [item["kind"] for item in data["facts"]["execution_authority"]["channels"]]
    assert "shell-tool" in kinds
    assert "hook-command" in kinds
    assert "sentinel.invalid" not in raw


def test_config_symlink_is_incomplete_and_not_followed(tmp_path: Path):
    target = tmp_path / "target.json"
    write(target, '{"mcpServers":{"local":{"command":"bash"}}}')
    (tmp_path / ".mcp.json").symlink_to(target)

    code, data, _raw, _err = run(tmp_path, "mcp")

    assert code == 3
    assert data["coverage"]["coverage_complete"] is False
    assert data["facts"]["execution_authority"]["observed"] is False


def test_fifo_config_does_not_hang(tmp_path: Path):
    fifo = tmp_path / ".mcp.json"
    os.mkfifo(fifo)

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "aurascan.cli",
            "agent-audit",
            "--root",
            str(tmp_path),
            "--surface",
            "mcp",
            "--json",
        ],
        cwd=str(Path(__file__).resolve().parents[1]),
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert proc.returncode == 3
    assert "AGENT-RUNTIME-CONFIG-INCOMPLETE-001" in proc.stdout


def test_empty_builtin_config_never_returns_clean(tmp_path: Path):
    write(tmp_path / ".codex" / "config.toml", "")

    code, data, _raw, _err = run(tmp_path, "codex")

    assert code == 1
    assert data["facts"]["execution_authority"]["observed"] is True


def test_layer_deny_does_not_cancel_project_allow(tmp_path: Path):
    write(
        tmp_path / ".claude" / "settings.json",
        '{"permissions":{"defaultMode":"default"}}',
    )
    write(
        tmp_path / ".claude" / "settings.local.json",
        '{"permissions":{"defaultMode":"bypassPermissions"}}',
    )

    code, data, _raw, _err = run(tmp_path, "claude")

    assert code == 1
    assert data["facts"]["execution_authority"]["approval_mode"]["normalized"] == "never"
    assert data["coverage"]["coverage_complete"] is True


def test_jsonc_comments_and_trailing_comma(tmp_path: Path):
    write(
        tmp_path / ".mcp.json",
        '{\n  // comment\n  "mcpServers": {"remote": {"url": "https://example.invalid/mcp"},},\n}\n',
    )

    code, data, _raw, _err = run(tmp_path, "mcp")

    assert code == 0
    assert data["coverage"]["coverage_complete"] is True


def test_toml_mcp_stdio_command(tmp_path: Path):
    write(
        tmp_path / ".codex" / "config.toml",
        '[mcp_servers.local]\ncommand = "npx"\nargs = ["-y", "server"]\n',
    )

    code, data, _raw, _err = run(tmp_path, "codex")

    assert code == 1
    kinds = [item["kind"] for item in data["facts"]["execution_authority"]["channels"]]
    assert "mcp-stdio-command" in kinds


def test_duplicate_json_key_is_incomplete(tmp_path: Path):
    write(tmp_path / ".mcp.json", '{"mcpServers":{},"mcpServers":{}}')

    code, data, _raw, _err = run(tmp_path, "mcp")

    assert code == 3
    assert "duplicate-key" in data["coverage"]["reasons"]


def test_top_level_json_shape_is_incomplete(tmp_path: Path):
    write(tmp_path / ".mcp.json", "[]")

    code, data, _raw, _err = run(tmp_path, "mcp")

    assert code == 3
    assert "config-top-level-shape" in data["coverage"]["reasons"]


def test_usage_error_returns_two(tmp_path: Path):
    code = run_agent_audit(
        ["--root", str(tmp_path / "missing"), "--surface", "mcp", "--json"],
        stdout=StringIO(),
        stderr=StringIO(),
    )

    assert code == 2


def test_schema_failure_returns_four(tmp_path: Path, monkeypatch):
    import aurascan.core.agent_audit_cli as cli

    monkeypatch.setattr(
        cli, "build_report", lambda root, surface: (_ for _ in ()).throw(AgentAuditSchemaError("test"))
    )
    code = cli.run_agent_audit(
        ["--root", str(tmp_path), "--surface", "mcp", "--json"],
        stdout=StringIO(),
        stderr=StringIO(),
    )

    assert code == 4


def test_high_and_incomplete_prefers_incomplete(tmp_path: Path):
    write(tmp_path / ".mcp.json", '{"mcpServers":{"local":{"command":"bash","shell":"x"}}}')

    code, data, _raw, _err = run(tmp_path, "mcp")

    assert code == 3
    assert data["facts"]["execution_authority"]["observed"] is True
    assert data["coverage"]["coverage_complete"] is False


def test_secret_class_counts_and_example_exclusion(tmp_path: Path):
    write(tmp_path / ".mcp.json", '{"mcpServers":{"remote":{"url":"https://example.invalid/mcp"}}}')
    write(tmp_path / ".env.example", "TOKEN=example\n")
    write(tmp_path / ".npmrc", "//registry.example/:_authToken=secret\n")
    write(tmp_path / ".ssh" / "id_ed25519", "not-a-real-key\n")

    code, data, _raw, _err = run(tmp_path, "mcp")

    assert code == 0
    classes = {item["class"]: item["count"] for item in data["facts"]["secret_classes_readable"]}
    assert "project-env" not in classes
    assert classes["vcs-credential"] == 1
    assert classes["ssh-private-key"] == 1


def test_bounded_deep_json_is_incomplete_not_clean(tmp_path: Path):
    write(tmp_path / ".mcp.json", "[" * 80 + "0" + "]" * 80)

    code, data, _raw, _err = run(tmp_path, "mcp")

    assert code == 3
    assert data["coverage"]["coverage_complete"] is False


def test_explain_contains_banner_and_no_secret(tmp_path: Path):
    sentinel = "EXPLAIN_SENTINEL"
    write(tmp_path / ".codex" / "config.toml", 'approval_policy = "never"\n')
    write(tmp_path / ".env", sentinel + "=1\n")
    out = StringIO()
    run_agent_audit(
        ["--root", str(tmp_path), "--surface", "codex", "--explain"],
        stdout=out,
        stderr=StringIO(),
    )

    text = out.getvalue()
    assert "This is not a model-safety verdict." in text
    assert sentinel not in text


def test_cursor_hooks_and_mcp_are_authority(tmp_path: Path):
    write(tmp_path / ".cursor" / "mcp.json", '{"mcpServers":{"remote":{"url":"https://example.invalid/mcp"}}}')
    write(tmp_path / ".cursor" / "permissions.json", "{}")
    write(
        tmp_path / ".cursor" / "hooks.json",
        '{"beforeShellExecution":[{"command":"bash -c sentinel"}]}',
    )

    code, data, _raw, _err = run(tmp_path, "cursor")

    assert code == 1
    assert data["coverage"]["coverage_complete"] is True
    kinds = [item["kind"] for item in data["facts"]["execution_authority"]["channels"]]
    assert "shell-tool" in kinds
    assert "hook-command" in kinds


def test_root_slash_is_bounded(tmp_path: Path):
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "aurascan.cli",
            "agent-audit",
            "--root",
            "/",
            "--surface",
            "codex",
            "--json",
        ],
        cwd=str(Path(__file__).resolve().parents[1]),
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert proc.returncode in (0, 1, 2, 3)
    assert "Traceback" not in proc.stderr


def test_sentinel_matrix_never_echoes_secret_material(tmp_path: Path):
    sentinel = "SENTINEL_VALUE_7f2c"
    write(
        tmp_path / ".mcp.json",
        json.dumps(
            {
                "mcpServers": {
                    sentinel: {"url": "https://example.invalid/mcp"},
                    "local": {"command": "bash", "args": [sentinel]},
                }
            }
        ),
    )
    write(tmp_path / ".env", sentinel + "=1\n")
    write(tmp_path / ".ssh" / "id_ed25519", sentinel + "\n")

    _code, data, raw, _err = run(tmp_path, "mcp")
    human = StringIO()
    run_agent_audit(
        ["--root", str(tmp_path), "--surface", "mcp"],
        stdout=human,
        stderr=StringIO(),
    )

    assert sentinel not in raw
    assert sentinel not in human.getvalue()
    assert sentinel not in json.dumps(data)


def test_digest_oracle_does_not_confirm_weak_secret(tmp_path: Path):
    secret = "weak-secret"
    write(tmp_path / ".mcp.json", "{}")
    write(tmp_path / ".env", secret + "=1\n")

    _code, data, _raw, _err = run(tmp_path, "mcp")
    expected = __import__("hashlib").sha256((secret + "=1\n").encode()).hexdigest()

    assert expected not in json.dumps(data)


def test_parity_vocabulary_and_mutation(tmp_path: Path, monkeypatch):
    assert vocabulary_parity_errors() == []
    assert AGENT_AUDIT_REQUIRED_PROGRAMS <= AGENT_FORBIDDEN_PROGRAMS

    monkeypatch.setattr(
        runtime,
        "AGENT_FORBIDDEN_PROGRAMS",
        frozenset(AGENT_FORBIDDEN_PROGRAMS - {"bash"}),
    )
    errors = vocabulary_parity_errors()
    assert any("bash" in item for item in errors)


def test_no_process_or_network_calls(tmp_path: Path, monkeypatch):
    write(tmp_path / ".mcp.json", '{"mcpServers":{"remote":{"url":"https://example.invalid/mcp"}}}')

    def fail(*args, **kwargs):
        raise AssertionError("audit attempted a process or network operation")

    monkeypatch.setattr(runtime.os, "system", fail)
    monkeypatch.setattr(subprocess, "Popen", fail)
    monkeypatch.setattr(subprocess, "run", fail)
    import socket
    monkeypatch.setattr(socket, "socket", fail)

    code, _data, _raw, _err = run(tmp_path, "mcp")
    assert code == 0


@pytest.mark.skipif(shutil.which("strace") is None, reason="strace is unavailable")
def test_strace_has_no_network_connect(tmp_path: Path):
    write(tmp_path / ".mcp.json", '{"mcpServers":{"remote":{"url":"https://example.invalid/mcp"}}}')
    trace = tmp_path / "trace.txt"
    proc = subprocess.run(
        [
            "strace", "-f", "-e", "trace=network,process",
            "-o", str(trace),
            sys.executable, "-m", "aurascan.cli", "agent-audit",
            "--root", str(tmp_path), "--surface", "mcp", "--json",
        ],
        cwd=str(Path(__file__).resolve().parents[1]),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0
    body = trace.read_text(encoding="utf-8", errors="replace")
    assert "connect(" not in body or "connect(3, {sa_family=AF_UNIX" in body
