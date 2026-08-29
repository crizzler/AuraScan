import io
import json
import os
import stat
import subprocess
import time
from pathlib import Path

import pytest

import aurascan.core.agent as agent
from aurascan.core.agent import (
    AGENT_NO_SNAPSHOT_PHRASE,
    AGENT_RAW_OUTPUT_PHRASE,
    AGENT_ROOT_GRANT_PHRASE,
    AgentCommand,
    ask_agent_ai,
    AgentConfig,
    build_agent_ai_prompt,
    execute_root_command_request,
    issue_root_session,
    read_agent_root_policy,
    resolve_agent_config,
    revoke_root_session,
    run_agent,
    run_agent_session,
    stream_shell_command,
    validate_agent_ai_response,
    validate_agent_request_file,
    write_agent_root_policy,
)
from aurascan.core.followup import (
    FollowUpAction,
    FollowUpContext,
    FollowUpFact,
    FollowUpProbe,
    FollowUpRuntime,
    persist_followup_context,
)
from aurascan.core.hardware_health import HARDWARE_HEALTH_PROBE_ID


class FakeResponse:
    def __init__(self, data):
        self.data = data

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps({
            "choices": [{"message": {"content": json.dumps(self.data)}}],
        }).encode("utf-8")


def ai_env(tmp_path: Path, **updates):
    env = {
        "AURASCAN_AI_ENABLED": "1",
        "AURASCAN_AI_PROVIDER": "openai",
        "AURASCAN_OPENAI_API_KEY": "fixture-api-key",
        "AURASCAN_AGENT_ACCESS": "user-shell",
        "AURASCAN_AGENT_APPROVAL": "each-command",
        "AURASCAN_AGENT_OUTPUT_SHARING": "redacted",
        "AURASCAN_AGENT_SESSION_TIMEOUT": "30",
        "XDG_STATE_HOME": str(tmp_path / "state"),
        "HOME": str(tmp_path / "home"),
    }
    env.update(updates)
    return env


def context():
    return FollowUpContext(
        "followup-agent-fixture",
        "incident",
        "incident-fixture",
        "incident",
        "Fixture incident",
        facts=[
            FollowUpFact(
                "fact-one",
                "finding",
                "A fixture service failed.",
                "password=hunter2 /home/arawn/private",
                "MEDIUM",
            )
        ],
        probes=[FollowUpProbe("probe-one", "Check service", "Run a guarded check.")],
        actions=[
            FollowUpAction(
                "action-one",
                "Restart verified fixture service",
                "AuraScan already verified this fixture action.",
                "LOW",
                True,
                True,
            )
        ],
    )


def command_response(command="", *, root=False, answer="I prepared one exact check."):
    commands = []
    if command:
        commands.append({
            "command": command,
            "cwd": "",
            "timeout_seconds": 10,
            "requires_root": root,
            "reason": "Verify the fixture state.",
            "expected_result": "The fixture text is printed.",
        })
    return {
        "answer": answer,
        "requested_access": "",
        "referenced_fact_ids": ["fact-one"],
        "requested_probe_ids": [],
        "requested_action_ids": [],
        "commands": commands,
    }


def test_keyless_local_ai_reaches_repair_agent_provider(tmp_path):
    env = ai_env(
        tmp_path,
        AURASCAN_AI_PROVIDER="llamacpp",
        AURASCAN_AI_MODEL="aurascan-local",
        AURASCAN_AI_BASE_URL="http://127.0.0.1:8080/v1",
        AURASCAN_OPENAI_API_KEY="",
    )
    seen = {}

    def urlopen(request, timeout):
        seen["url"] = request.full_url
        seen["headers"] = dict(request.header_items())
        return FakeResponse(command_response(answer="The local provider is ready."))

    response = ask_agent_ai(
        context(),
        "Summarize the verified facts.",
        [],
        access="guarded",
        approval="each-command",
        facts_only=False,
        env=env,
        urlopen=urlopen,
    )

    assert response.status == "ok"
    assert response.answer == "The local provider is ready."
    assert seen["url"] == "http://127.0.0.1:8080/v1/chat/completions"
    assert "Authorization" not in seen["headers"]


def write_private_request(path: Path, data):
    path.write_text(json.dumps(data), encoding="utf-8")
    path.chmod(0o600)


def test_agent_config_defaults_and_rejects_invalid_values():
    assert resolve_agent_config({}) == AgentConfig()

    config = resolve_agent_config({
        "AURASCAN_AGENT_ACCESS": "anything",
        "AURASCAN_AGENT_APPROVAL": "never",
        "AURASCAN_AGENT_OUTPUT_SHARING": "rawish",
        "AURASCAN_AGENT_SESSION_TIMEOUT": "500",
    })

    assert config.access == "guarded"
    assert config.approval == "each-command"
    assert config.output_sharing == "redacted"
    assert config.session_timeout_minutes == 30
    assert "invalid AURASCAN_AGENT_ACCESS" in config.error
    assert "must be between" in config.error


def test_root_helper_environment_scrubs_provider_credentials(monkeypatch):
    monkeypatch.setenv("AURASCAN_OPENAI_API_KEY", "secret")
    monkeypatch.setenv("AURASCAN_AI_KEY", "legacy-secret")
    monkeypatch.setenv("AURASCAN_AGENT_ACCESS", "root-shell")

    agent.scrub_agent_helper_environment()

    assert "AURASCAN_OPENAI_API_KEY" not in os.environ
    assert "AURASCAN_AI_KEY" not in os.environ
    assert os.environ["AURASCAN_AGENT_ACCESS"] == "root-shell"


def test_root_policy_defaults_off_and_requires_safe_ownership(tmp_path):
    path = tmp_path / "agent.conf"
    assert read_agent_root_policy(path, required_uid=os.getuid()).allowed is False

    ok, _message = write_agent_root_policy(
        True,
        "whole-plan",
        45,
        path,
        require_root=False,
    )

    assert ok is True
    assert stat.S_IMODE(path.stat().st_mode) == 0o644
    policy = read_agent_root_policy(path, required_uid=os.getuid())
    assert policy.allowed is True
    assert policy.max_approval == "whole-plan"
    assert policy.max_minutes == 45

    path.chmod(0o666)
    assert read_agent_root_policy(path, required_uid=os.getuid()).error


def test_snapshot_preparation_requires_btrfs_and_valid_snapper_id(tmp_path):
    calls = []
    snapshot_root = tmp_path / ".snapshots"

    def runner(command, **_kwargs):
        calls.append(command)
        if command[0] == "findmnt":
            return subprocess.CompletedProcess(command, 0, "btrfs\n", "")
        (snapshot_root / "42" / "snapshot").mkdir(parents=True)
        return subprocess.CompletedProcess(command, 0, "42\n", "")

    snapshot_id, error = agent._create_agent_snapshot(
        "agent-" + ("a" * 32),
        runner=runner,
        which=lambda name: f"/usr/bin/{name}" if name in {"findmnt", "snapper"} else None,
        snapshot_root=snapshot_root,
    )

    assert snapshot_id == "42"
    assert error == ""
    assert calls[0] == ["findmnt", "-n", "-o", "FSTYPE", "/"]
    assert calls[1][:5] == ["snapper", "-c", "root", "create", "--type"]


def test_agent_response_rejects_commands_without_shell_grant_and_validates_shell_fields():
    with pytest.raises(ValueError, match="active shell grant"):
        validate_agent_ai_response(
            context(),
            command_response("id"),
            access="guarded",
        )

    response = validate_agent_ai_response(
        context(),
        {
            **command_response("printf ok"),
            "requested_access": "root-shell",
            "referenced_fact_ids": ["fact-one", "invented"],
            "requested_probe_ids": ["probe-one", "invented"],
            "requested_action_ids": ["action-one", "invented"],
            "commands": [{
                "command": "printf ok",
                "cwd": "/",
                "timeout_seconds": 5,
                "requires_root": False,
                "reason": "Print a fixture.",
                "expected_result": "ok",
            }],
            "script": "hidden",
        },
        access="user-shell",
    )

    assert response.requested_access == "root-shell"
    assert response.referenced_fact_ids == ["fact-one"]
    assert response.requested_probe_ids == ["probe-one"]
    assert response.requested_action_ids == ["action-one"]
    assert response.commands[0].command == "printf ok"
    assert response.commands[0].requires_root is False

    unsafe = command_response("printf '\\033]0;forged\\007'")
    unsafe["commands"][0]["command"] = "printf ok\x1b]0;forged\x07"
    with pytest.raises(ValueError, match="unsafe"):
        validate_agent_ai_response(context(), unsafe, access="user-shell")


def test_agent_prompt_redacts_context_and_bounds_terminal_results(tmp_path):
    result = agent.AgentCommandResult(
        "agent-cmd-one",
        "ok",
        0,
        "token=secret-value /home/arawn/private " + ("x" * 30000),
        0.1,
    )

    prompt = build_agent_ai_prompt(
        context(),
        "Can you inspect password=hunter2?",
        [],
        access="user-shell",
        approval="each-command",
        facts_only=False,
        command_results=[result],
    )

    assert len(prompt) <= 12000
    assert "hunter2" not in prompt
    assert "secret-value" not in prompt
    assert "/home/arawn/private" not in prompt
    assert "<redacted>" in prompt


def test_user_shell_uses_minimal_environment_and_streams_output(tmp_path):
    stdout = io.StringIO()
    result = stream_shell_command(
        AgentCommand(
            "printf 'value=%s' \"${AURASCAN_OPENAI_API_KEY-unset}\"",
            "Check environment isolation.",
            timeout_seconds=5,
        ),
        stdout=stdout,
        stderr=stdout,
        env={
            "HOME": str(tmp_path),
            "AURASCAN_OPENAI_API_KEY": "fixture-secret",
        },
    )

    assert result.status == "ok"
    assert result.output == "value=unset"
    assert stdout.getvalue() == "value=unset"
    assert "fixture-secret" not in result.output


def test_user_shell_timeout_stops_process_group():
    stderr = io.StringIO()
    result = stream_shell_command(
        AgentCommand("sleep 2", "Exercise timeout handling.", timeout_seconds=1),
        stdout=io.StringIO(),
        stderr=stderr,
        env={},
    )

    assert result.status == "timeout"
    assert result.timed_out is True
    assert result.exit_code != 0
    assert "process group was stopped" in stderr.getvalue()


def test_terminal_output_removes_escape_sequences():
    stdout = io.StringIO()
    result = stream_shell_command(
        AgentCommand(
            "printf '\\033[31mred\\033[0m\\n'",
            "Exercise terminal sanitization.",
            timeout_seconds=5,
        ),
        stdout=stdout,
        stderr=stdout,
        env={},
    )

    assert result.status == "ok"
    assert result.output == "red\n"
    assert "\x1b" not in stdout.getvalue()


def test_keyboard_interrupt_stops_command_process_group(monkeypatch):
    signals = []

    class Process:
        pid = 4242
        returncode = None
        stdout = io.StringIO("")

        def __init__(self):
            self.waits = 0

        def wait(self, timeout):
            self.waits += 1
            if self.waits == 1:
                raise KeyboardInterrupt
            self.returncode = -15
            return self.returncode

    process = Process()
    monkeypatch.setattr(os, "killpg", lambda pid, sig: signals.append((pid, sig)))
    result = stream_shell_command(
        AgentCommand("sleep 30", "Exercise interrupt handling.", timeout_seconds=30),
        stdout=io.StringIO(),
        stderr=io.StringIO(),
        env={},
        popen_factory=lambda *_args, **_kwargs: process,
    )

    assert result.status == "interrupted"
    assert result.exit_code == -15
    assert signals == [(4242, agent.signal.SIGTERM)]


def test_user_shell_session_runs_only_after_command_approval_and_audits_privately(tmp_path):
    responses = iter([
        command_response("printf agent-ok"),
        command_response(answer="The approved local command printed agent-ok."),
    ])
    prompts = iter([
        "yes",
        "Please verify it.",
        "yes",
        "",
    ])
    stdout = io.StringIO()

    result = run_agent_session(
        context(),
        access="user-shell",
        approval="each-command",
        output_sharing="redacted",
        session_timeout_minutes=5,
        input_func=lambda _prompt: next(prompts),
        stdout=stdout,
        stderr=stdout,
        env=ai_env(tmp_path),
        urlopen=lambda _request, timeout: FakeResponse(next(responses)),
        context_root=tmp_path / "contexts",
        audit_root=tmp_path / "audits",
    )

    assert result.commands_run == 1
    assert result.provider_requests == 2
    assert result.command_failed is False
    assert "agent-ok" in stdout.getvalue()
    audits = list((tmp_path / "audits").glob("agent-*.json"))
    assert len(audits) == 1
    assert stat.S_IMODE(audits[0].stat().st_mode) == 0o600
    audit_text = audits[0].read_text(encoding="utf-8")
    assert "printf agent-ok" in audit_text
    assert "fixture-api-key" not in audit_text


def test_guarded_agent_collects_hardware_context_before_first_ai_request(tmp_path):
    item = context()
    probe_calls = []
    provider_prompts = []

    def run_probes(current, probe_ids):
        probe_calls.append(list(probe_ids))
        current.facts.append(
            FollowUpFact(
                "hardware-memory",
                "hardware_memory",
                "Memory: 64.0 GiB total; 4 populated DIMMs.",
                "Type: DDR5; configured speed: 5600 MT/s.",
            )
        )
        return current, []

    def urlopen(request, timeout):
        provider_prompts.append(request.data.decode("utf-8", "replace"))
        return FakeResponse(command_response(
            answer="The local RAM topology is now available for this diagnosis."
        ))

    prompts = iter([
        "Could all four RAM banks be involved?",
        "",
    ])
    result = run_agent_session(
        item,
        access="guarded",
        approval="each-command",
        output_sharing="redacted",
        session_timeout_minutes=5,
        runtime=FollowUpRuntime(run_probes=run_probes),
        input_func=lambda _prompt: next(prompts),
        stdout=io.StringIO(),
        stderr=io.StringIO(),
        env=ai_env(tmp_path),
        urlopen=urlopen,
        context_root=tmp_path / "contexts",
        audit_root=tmp_path / "audits",
    )

    assert result.provider_requests == 1
    assert probe_calls == [[HARDWARE_HEALTH_PROBE_ID]]
    assert "64.0 GiB" in provider_prompts[0]


def test_user_shell_decline_runs_no_command_or_second_provider_request(tmp_path):
    prompts = iter(["yes", "Please fix it.", "no", ""])
    result = run_agent_session(
        context(),
        access="user-shell",
        approval="each-command",
        output_sharing="redacted",
        session_timeout_minutes=5,
        input_func=lambda _prompt: next(prompts),
        stdout=io.StringIO(),
        stderr=io.StringIO(),
        env=ai_env(tmp_path),
        urlopen=lambda _request, timeout: FakeResponse(command_response("printf should-not-run")),
        context_root=tmp_path / "contexts",
        audit_root=tmp_path / "audits",
    )

    assert result.commands_run == 0
    assert result.provider_requests == 1


def test_full_output_requires_separate_typed_phrase(tmp_path):
    prompts = iter(["yes", "wrong phrase", ""])
    stdout = io.StringIO()
    run_agent_session(
        context(),
        access="user-shell",
        approval="each-command",
        output_sharing="full",
        session_timeout_minutes=5,
        input_func=lambda _prompt: next(prompts),
        stdout=stdout,
        stderr=stdout,
        env=ai_env(tmp_path),
        context_root=tmp_path / "contexts",
        audit_root=tmp_path / "audits",
    )

    assert "using redacted output" in stdout.getvalue()


def test_session_approval_requires_exact_user_shell_phrase(tmp_path):
    result = run_agent_session(
        context(),
        access="user-shell",
        approval="session",
        output_sharing="redacted",
        session_timeout_minutes=5,
        input_func=lambda _prompt: "yes",
        stdout=io.StringIO(),
        stderr=io.StringIO(),
        env=ai_env(tmp_path),
        context_root=tmp_path / "contexts",
        audit_root=tmp_path / "audits",
    )

    assert result.commands_run == 0
    assert result.provider_requests == 0


def test_private_request_validation_rejects_group_readable_and_symlink(tmp_path):
    request = tmp_path / "request.json"
    write_private_request(request, {"schema": "fixture"})
    assert validate_agent_request_file(request)[0] is (os.getuid() == 0)

    request.chmod(0o640)
    assert validate_agent_request_file(request)[0] is False
    request.chmod(0o600)
    link = tmp_path / "link.json"
    link.symlink_to(request)
    assert validate_agent_request_file(link)[0] is False


def test_root_broker_binds_capability_process_tty_and_plan(monkeypatch, tmp_path):
    uid = os.getuid()
    policy_path = tmp_path / "agent.conf"
    runtime_root = tmp_path / "run"
    audit_root = tmp_path / "audit"
    assert write_agent_root_policy(
        True,
        "whole-plan",
        30,
        policy_path,
        require_root=False,
    )[0]
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", str(uid))
    monkeypatch.setattr(agent, "_process_tty", lambda _pid: "/dev/pts/fixture")
    session_id = "agent-" + ("a" * 32)
    capability = "capability-" + ("x" * 40)
    issue_path = tmp_path / "issue.json"
    write_private_request(issue_path, {
        "schema": "agent_root_session_request/1.0",
        "session_id": session_id,
        "capability": capability,
        "uid": uid,
        "origin_pid": os.getpid(),
        "origin_start_time": agent._process_start_time(os.getpid()),
        "tty": "/dev/pts/fixture",
        "context_fingerprint": "b" * 64,
        "approval": "whole-plan",
        "minutes": 10,
        "snapshot_requested": False,
        "snapshot_waived": True,
    })

    issued = issue_root_session(
        issue_path,
        policy_path=policy_path,
        policy_uid=uid,
        runtime_root=runtime_root,
    )

    assert issued["ok"] is True
    state_path = runtime_root / str(uid) / f"{session_id}.json"
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert capability not in state_path.read_text(encoding="utf-8")
    assert state["tty"] == "/dev/pts/fixture"
    assert state["snapshot_waived"] is True

    execute_path = tmp_path / "execute.json"
    command = AgentCommand("printf root-broker-ok", "Print fixture.", requires_root=True)
    write_private_request(execute_path, {
        "schema": "agent_command_request/1.0",
        "session_id": session_id,
        "capability": capability,
        "uid": uid,
        "tty": "/dev/pts/fixture",
        "context_fingerprint": "b" * 64,
        "plan_hash": "c" * 64,
        "approve_plan": True,
        "audit_command": command.command,
        "command": command.to_dict(),
    })
    stderr = io.StringIO()

    monkeypatch.setattr(agent, "_process_tty", lambda _pid: "/dev/pts/other")
    wrong_tty = execute_root_command_request(
        execute_path,
        runtime_root=runtime_root,
        audit_root=audit_root,
    )
    assert wrong_tty["ok"] is False
    assert "terminal" in wrong_tty["error"]

    monkeypatch.setattr(agent, "_process_tty", lambda _pid: "/dev/pts/fixture")
    executed = execute_root_command_request(
        execute_path,
        runtime_root=runtime_root,
        audit_root=audit_root,
        stderr=stderr,
    )

    assert executed["ok"] is True
    assert executed["result"]["output"] == "root-broker-ok"
    assert "root-broker-ok" in stderr.getvalue()
    manifest = audit_root / session_id / "manifest.json"
    assert stat.S_IMODE(manifest.stat().st_mode) == 0o600

    changed = json.loads(execute_path.read_text(encoding="utf-8"))
    changed["plan_hash"] = "d" * 64
    changed["approve_plan"] = False
    write_private_request(execute_path, changed)
    refused = execute_root_command_request(
        execute_path,
        runtime_root=runtime_root,
        audit_root=audit_root,
    )
    assert refused["ok"] is False
    assert "plan changed" in refused["error"]

    changed["approve_plan"] = True
    write_private_request(execute_path, changed)
    renewed = execute_root_command_request(
        execute_path,
        runtime_root=runtime_root,
        audit_root=audit_root,
    )
    assert renewed["ok"] is True

    revoke_path = tmp_path / "revoke.json"
    write_private_request(revoke_path, {
        "schema": "agent_root_revoke_request/1.0",
        "session_id": session_id,
        "capability": capability,
        "uid": uid,
    })
    assert revoke_root_session(revoke_path, runtime_root=runtime_root)["ok"] is True
    assert not state_path.exists()


def test_root_broker_refuses_wrong_capability_and_expired_session(monkeypatch, tmp_path):
    uid = os.getuid()
    policy_path = tmp_path / "agent.conf"
    assert write_agent_root_policy(
        True,
        "session",
        30,
        policy_path,
        require_root=False,
    )[0]
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", str(uid))
    monkeypatch.setattr(agent, "_process_tty", lambda _pid: "/dev/pts/fixture")
    session_id = "agent-" + ("e" * 32)
    issue_path = tmp_path / "issue.json"
    write_private_request(issue_path, {
        "schema": "agent_root_session_request/1.0",
        "session_id": session_id,
        "capability": "correct-" + ("x" * 40),
        "uid": uid,
        "origin_pid": os.getpid(),
        "origin_start_time": agent._process_start_time(os.getpid()),
        "tty": "/dev/pts/fixture",
        "context_fingerprint": "f" * 64,
        "approval": "session",
        "minutes": 1,
        "snapshot_requested": False,
        "snapshot_waived": True,
    })
    assert issue_root_session(
        issue_path,
        policy_path=policy_path,
        policy_uid=uid,
        runtime_root=tmp_path / "run",
        now=100,
    )["ok"]
    execute_path = tmp_path / "execute.json"
    command = AgentCommand("true", "Fixture.", requires_root=True)
    write_private_request(execute_path, {
        "schema": "agent_command_request/1.0",
        "session_id": session_id,
        "capability": "wrong-" + ("z" * 40),
        "uid": uid,
        "tty": "/dev/pts/fixture",
        "context_fingerprint": "f" * 64,
        "plan_hash": "a" * 64,
        "approve_plan": True,
        "command": command.to_dict(),
    })

    wrong = execute_root_command_request(
        execute_path,
        runtime_root=tmp_path / "run",
        audit_root=tmp_path / "audit",
        now=101,
    )
    assert wrong["ok"] is False
    assert "capability" in wrong["error"]

    request = json.loads(execute_path.read_text(encoding="utf-8"))
    request["capability"] = "correct-" + ("x" * 40)
    write_private_request(execute_path, request)
    expired = execute_root_command_request(
        execute_path,
        runtime_root=tmp_path / "run",
        audit_root=tmp_path / "audit",
        now=161,
    )
    assert expired["ok"] is False
    assert "expired" in expired["error"]


def test_root_session_requires_exact_grant_and_snapshot_waiver(monkeypatch, tmp_path):
    policy = tmp_path / "agent.conf"
    helper = tmp_path / "aurascan"
    helper.write_text("#!/bin/sh\n", encoding="utf-8")
    assert write_agent_root_policy(
        True,
        "each-command",
        30,
        policy,
        require_root=False,
    )[0]
    calls = []

    def runner(command, **_kwargs):
        calls.append(command)
        request = json.loads(Path(command[-1]).read_text(encoding="utf-8"))
        if "--issue-root-session" in command:
            if request["snapshot_requested"]:
                payload = {
                    "ok": False,
                    "snapshot_unavailable": True,
                    "error": "snapshot_unavailable: fixture",
                }
                return subprocess.CompletedProcess(command, 75, json.dumps(payload), "")
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps({
                    "ok": True,
                    "session_id": request["session_id"],
                    "expires_at": int(time.time()) + 300,
                    "snapshot_id": "",
                    "snapshot_waived": True,
                }),
                "",
            )
        if "--execute-request" in command:
            item = request["command"]
            return subprocess.CompletedProcess(
                command,
                0,
                json.dumps({
                    "ok": True,
                    "result": {
                        "command_id": item["command_id"],
                        "status": "ok",
                        "exit_code": 0,
                        "output": "root-session-ok",
                        "duration_seconds": 0.1,
                        "timed_out": False,
                        "error": "",
                    },
                }),
                "",
            )
        return subprocess.CompletedProcess(command, 0, json.dumps({"ok": True}), "")

    responses = iter([
        command_response("printf root-session-ok", root=True),
        command_response(answer="The root fixture command succeeded."),
    ])
    prompts = iter([
        AGENT_ROOT_GRANT_PHRASE,
        AGENT_NO_SNAPSHOT_PHRASE,
        "Check the root fixture.",
        "yes",
        "",
    ])
    result = run_agent_session(
        context(),
        access="root-shell",
        approval="each-command",
        output_sharing="redacted",
        session_timeout_minutes=5,
        input_func=lambda _prompt: next(prompts),
        stdout=io.StringIO(),
        stderr=io.StringIO(),
        env=ai_env(tmp_path, AURASCAN_AGENT_ACCESS="root-shell"),
        urlopen=lambda _request, timeout: FakeResponse(next(responses)),
        context_root=tmp_path / "contexts",
        audit_root=tmp_path / "audits",
        helper=helper,
        runner=runner,
        tty="/dev/pts/fixture",
        root_policy_path=policy,
        root_policy_uid=os.getuid(),
    )

    assert result.commands_run == 1
    assert sum("--issue-root-session" in call for call in calls) == 2
    assert any("--execute-request" in call for call in calls)
    assert any("--revoke-root-session" in call for call in calls)


def test_wrong_root_phrase_makes_no_privileged_or_provider_call(tmp_path):
    policy = tmp_path / "agent.conf"
    assert write_agent_root_policy(
        True,
        "each-command",
        30,
        policy,
        require_root=False,
    )[0]
    called = []

    result = run_agent_session(
        context(),
        access="root-shell",
        approval="each-command",
        output_sharing="redacted",
        session_timeout_minutes=5,
        input_func=lambda _prompt: "yes",
        stdout=io.StringIO(),
        stderr=io.StringIO(),
        env=ai_env(tmp_path, AURASCAN_AGENT_ACCESS="root-shell"),
        urlopen=lambda *_args, **_kwargs: called.append("provider"),
        context_root=tmp_path / "contexts",
        audit_root=tmp_path / "audits",
        root_policy_path=policy,
        root_policy_uid=os.getuid(),
    )

    assert result.provider_requests == 0
    assert called == []


def test_run_agent_enforces_configured_access_ceiling_and_tty(tmp_path):
    root = tmp_path / "contexts"
    persist_followup_context(context(), root)
    stderr = io.StringIO()

    non_tty = run_agent(
        ["--latest"],
        stdout=io.StringIO(),
        stderr=stderr,
        env=ai_env(tmp_path),
        context_root=root,
    )
    assert non_tty == agent.EXIT_FOLLOWUP_UNAVAILABLE
    assert "interactive foreground terminal" in stderr.getvalue()

    stderr = io.StringIO()
    too_high = run_agent(
        ["--latest", "--access", "root-shell"],
        stdout=io.StringIO(),
        stderr=stderr,
        env=ai_env(tmp_path, AURASCAN_AGENT_ACCESS="user-shell"),
        context_root=root,
        force_interactive=True,
    )
    assert too_high == agent.EXIT_AGENT_CONFIG_ERROR
    assert "exceeds configured access" in stderr.getvalue()


def test_run_agent_reports_root_broker_setup_failure(tmp_path):
    root = tmp_path / "contexts"
    policy = tmp_path / "agent.conf"
    persist_followup_context(context(), root)
    assert write_agent_root_policy(
        True,
        "each-command",
        30,
        policy,
        require_root=False,
    )[0]
    stderr = io.StringIO()
    provider_calls = []

    status = run_agent(
        ["--latest", "--access", "root-shell"],
        input_func=lambda _prompt: AGENT_ROOT_GRANT_PHRASE,
        stdout=io.StringIO(),
        stderr=stderr,
        env=ai_env(tmp_path, AURASCAN_AGENT_ACCESS="root-shell"),
        urlopen=lambda *_args, **_kwargs: provider_calls.append("provider"),
        context_root=root,
        helper=tmp_path / "missing-aurascan",
        root_policy_path=policy,
        root_policy_uid=os.getuid(),
        force_interactive=True,
    )

    assert status == agent.EXIT_AGENT_ROOT_REFUSED
    assert "package-managed /usr/bin/aurascan" in stderr.getvalue()
    assert provider_calls == []


def test_run_agent_is_disabled_in_recovery_runtime(tmp_path):
    stderr = io.StringIO()
    status = run_agent(
        [],
        stdout=io.StringIO(),
        stderr=stderr,
        env=ai_env(tmp_path, AURASCAN_RECOVERY_RUNTIME="1"),
        force_interactive=True,
    )
    assert status == agent.EXIT_FOLLOWUP_UNAVAILABLE
    assert "recovery mode" in stderr.getvalue()


def test_followup_agent_command_cannot_exceed_configured_access(monkeypatch, tmp_path):
    from aurascan.core.followup import run_followup_session

    called = []
    monkeypatch.setattr(
        agent,
        "run_agent_session",
        lambda *_args, **_kwargs: called.append(True) or agent.AgentSessionResult(),
    )
    prompts = iter(["/agent root-shell", ""])
    stdout = io.StringIO()

    run_followup_session(
        context(),
        runtime=FollowUpRuntime(),
        input_func=lambda _prompt: next(prompts),
        stdout=stdout,
        stderr=stdout,
        env=ai_env(tmp_path, AURASCAN_AGENT_ACCESS="user-shell"),
        context_root=tmp_path / "contexts",
    )

    assert called == []
    assert "exceeds the configured access ceiling" in stdout.getvalue()


def test_agent_audit_retention_removes_old_and_excess_records(tmp_path):
    root = tmp_path / "audits"
    root.mkdir(mode=0o700)
    for index in range(55):
        path = root / f"agent-{index:032x}.json"
        path.write_text("{}", encoding="utf-8")
        path.chmod(0o600)
    old = root / f"agent-{'f' * 32}.json"
    old.write_text("{}", encoding="utf-8")
    old.chmod(0o600)
    stale = time.time() - 31 * 86400
    os.utime(old, (stale, stale))

    agent.prune_agent_audits(root)

    assert len(list(root.glob("agent-*.json"))) <= 50
    assert not old.exists()


def test_new_root_session_cleanup_removes_only_expired_records(tmp_path):
    root = tmp_path / "run"
    uid_root = root / str(os.getuid())
    uid_root.mkdir(parents=True)
    expired = uid_root / f"agent-{'1' * 32}.json"
    active = uid_root / f"agent-{'2' * 32}.json"
    expired.write_text(json.dumps({"expires_at": 99}), encoding="utf-8")
    active.write_text(json.dumps({"expires_at": 101}), encoding="utf-8")

    removed = agent.cleanup_expired_root_sessions(
        os.getuid(),
        runtime_root=root,
        now=100,
    )

    assert removed == 1
    assert not expired.exists()
    assert active.exists()
