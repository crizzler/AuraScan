import io
import subprocess
import sys
import types

import pytest

import aurascan.cli as cli
import aurascan.core as core_package
import aurascan.core.instruction_cli as instruction_cli
from aurascan.core.instruction_cli import (
    EXIT_CLEAR,
    EXIT_ERROR,
    EXIT_REVIEW,
    INSTRUCTION_AI_ENABLED_ENV,
    INSTRUCTION_ASSISTANT_SERVICE,
    INSTRUCTION_ASSISTANT_TIMER,
    INSTRUCTION_MONITOR_ENABLED_ENV,
    INSTRUCTION_MONITOR_SERVICE,
    INSTRUCTION_MONITOR_TIMER,
    INSTRUCTION_SCAN_MODE_ENV,
    read_instruction_guard_preferences,
    resolve_instruction_guard_preferences,
    run_instruction_audit,
    set_instruction_ai_enabled,
    set_instruction_monitor_enabled,
)


class FakeReport:
    def __init__(self, *, review_required=False, new_alert_count=0):
        self.review_required = review_required
        self.new_alert_count = new_alert_count

    def to_dict(self):
        return {
            "schema": "instruction_guard_report/1.0",
            "report_id": "fixture-report",
            "review_required": self.review_required,
        }


def install_fake_guard(
    monkeypatch,
    tmp_path,
    *,
    scan=None,
    review=None,
    status=None,
    pending_alerts=None,
    acknowledge=None,
):
    module = types.ModuleType("aurascan.core.instruction_guard")
    module.default_instruction_guard_state_root = lambda _env=None: tmp_path / "state"
    module.scan_instruction_files = scan or (lambda *_args, **_kwargs: FakeReport())
    module.review_report = review or (lambda *_args, **_kwargs: FakeReport())
    module.render_instruction_report = lambda report: "fixture instruction report"
    selected_status = status if status is not None else {
        "schema": "instruction_guard_status/1.0",
        "state": "clear",
    }
    module.instruction_guard_status = lambda **_kwargs: dict(selected_status)
    module.pending_instruction_guard_alerts = (
        (lambda **_kwargs: list(pending_alerts))
        if pending_alerts is not None
        else (lambda **_kwargs: [])
    )
    module.acknowledge_alert = acknowledge or (lambda *_args, **_kwargs: None)
    module.approve_candidate = lambda *_args, **_kwargs: {"status": "approved"}
    module.disable_candidate = lambda *_args, **_kwargs: {"status": "disabled"}
    module.restore_disabled = lambda *_args, **_kwargs: {"status": "restored"}
    module.process_one_ai_job = lambda **_kwargs: None
    monkeypatch.setitem(sys.modules, module.__name__, module)
    monkeypatch.setattr(core_package, "instruction_guard", module, raising=False)
    return module


def completed(command, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(command, returncode, stdout, stderr)


def test_instruction_preferences_parse_explicit_values_and_report_invalid_input():
    preferences = resolve_instruction_guard_preferences({
        INSTRUCTION_MONITOR_ENABLED_ENV: "yes",
        INSTRUCTION_AI_ENABLED_ENV: "0",
        INSTRUCTION_SCAN_MODE_ENV: "ALL-MARKDOWN",
    })

    assert preferences.monitor_enabled is True
    assert preferences.ai_enabled is False
    assert preferences.scan_mode == "all-markdown"
    assert preferences.error == ""

    invalid = resolve_instruction_guard_preferences({
        INSTRUCTION_MONITOR_ENABLED_ENV: "sometimes",
        INSTRUCTION_AI_ENABLED_ENV: "perhaps",
        INSTRUCTION_SCAN_MODE_ENV: "everything",
    })

    assert invalid.monitor_enabled is False
    assert invalid.ai_enabled is False
    assert invalid.scan_mode == "agent-surfaces"
    assert INSTRUCTION_MONITOR_ENABLED_ENV in invalid.error
    assert INSTRUCTION_AI_ENABLED_ENV in invalid.error
    assert INSTRUCTION_SCAN_MODE_ENV in invalid.error


def test_preference_reader_skips_secrets_and_bounds_untrusted_config(tmp_path):
    config = tmp_path / "aurascan.env"
    secret = "fixture-provider-secret-must-not-survive"
    config.write_text(
        f"AURASCAN_OPENAI_API_KEY={secret}\n"
        f"AURASCAN_LOCAL_AI_API_KEY={secret}\n"
        f"{INSTRUCTION_MONITOR_ENABLED_ENV}=1\n"
        f"{INSTRUCTION_AI_ENABLED_ENV}=0\n"
        f"{INSTRUCTION_SCAN_MODE_ENV}=all-markdown\n",
        encoding="utf-8",
    )
    config.chmod(0o600)

    preferences = read_instruction_guard_preferences(config)

    assert preferences.monitor_enabled is True
    assert preferences.ai_enabled is False
    assert preferences.scan_mode == "all-markdown"
    assert secret not in repr(preferences)
    assert set(preferences.__dict__) == {"monitor_enabled", "ai_enabled", "scan_mode", "error"}

    invalid_utf8 = tmp_path / "invalid.env"
    invalid_utf8.write_bytes(b"\xff\xfe")
    invalid_utf8.chmod(0o600)
    assert "UTF-8" in read_instruction_guard_preferences(invalid_utf8).error

    oversized = tmp_path / "oversized.env"
    oversized.write_bytes(b"x" * 33)
    oversized.chmod(0o600)
    assert "bounded read limit" in read_instruction_guard_preferences(oversized, max_bytes=32).error

    real_config = tmp_path / "real.env"
    real_config.write_text(f"{INSTRUCTION_MONITOR_ENABLED_ENV}=1\n", encoding="utf-8")
    real_config.chmod(0o600)
    linked_config = tmp_path / "linked.env"
    linked_config.symlink_to(real_config)
    assert "no-follow" in read_instruction_guard_preferences(linked_config).error


def test_monitor_and_assistant_user_units_enable_disable_without_real_systemd(tmp_path, monkeypatch):
    calls = []

    def runner(command, **_kwargs):
        command = list(command)
        calls.append(command)
        if "is-enabled" in command:
            return completed(command, 1, stdout="disabled\n")
        if "is-active" in command:
            return completed(command, 3, stdout="inactive\n")
        return completed(command)

    monitor_env = tmp_path / "monitor.env"
    ok, _message = set_instruction_monitor_enabled(True, runner=runner, env_path=monitor_env)

    assert ok is True
    assert calls == [
        ["systemctl", "--user", "is-enabled", INSTRUCTION_MONITOR_TIMER],
        ["systemctl", "--user", "is-active", INSTRUCTION_MONITOR_TIMER],
        ["systemctl", "--user", "is-active", INSTRUCTION_MONITOR_SERVICE],
        ["systemctl", "--user", "enable", "--now", INSTRUCTION_MONITOR_TIMER],
        ["systemctl", "--user", "start", "--no-block", INSTRUCTION_MONITOR_SERVICE],
    ]
    assert f"{INSTRUCTION_MONITOR_ENABLED_ENV}=1" in monitor_env.read_text(encoding="utf-8")

    calls.clear()
    assistant_env = tmp_path / "assistant.env"
    ok, _message = set_instruction_ai_enabled(False, runner=runner, env_path=assistant_env)

    assert ok is True
    assert calls == [
        ["systemctl", "--user", "is-enabled", INSTRUCTION_ASSISTANT_TIMER],
        ["systemctl", "--user", "is-active", INSTRUCTION_ASSISTANT_TIMER],
        ["systemctl", "--user", "is-active", INSTRUCTION_ASSISTANT_SERVICE],
        ["systemctl", "--user", "disable", "--now", INSTRUCTION_ASSISTANT_TIMER],
    ]
    assert f"{INSTRUCTION_AI_ENABLED_ENV}=0" in assistant_env.read_text(encoding="utf-8")

    calls.clear()
    monkeypatch.setattr(
        instruction_cli,
        "resolve_ai_config",
        lambda _env=None: types.SimpleNamespace(ready=True),
    )
    ok, _message = set_instruction_ai_enabled(
        True,
        runner=runner,
        env_path=assistant_env,
        env={"UNRELATED_SECRET": "not-forwarded-to-systemctl"},
    )

    assert ok is True
    assert calls == [
        ["systemctl", "--user", "is-enabled", INSTRUCTION_ASSISTANT_TIMER],
        ["systemctl", "--user", "is-active", INSTRUCTION_ASSISTANT_TIMER],
        ["systemctl", "--user", "is-active", INSTRUCTION_ASSISTANT_SERVICE],
        ["systemctl", "--user", "enable", "--now", INSTRUCTION_ASSISTANT_TIMER],
        ["systemctl", "--user", "start", "--no-block", INSTRUCTION_ASSISTANT_SERVICE],
    ]


def test_monitor_unit_rolls_back_when_private_config_write_fails(monkeypatch, tmp_path):
    calls = []

    def runner(command, **_kwargs):
        command = list(command)
        calls.append(command)
        if command == ["systemctl", "--user", "is-enabled", INSTRUCTION_MONITOR_TIMER]:
            return completed(command, stdout="enabled\n")
        if command == ["systemctl", "--user", "is-active", INSTRUCTION_MONITOR_TIMER]:
            return completed(command, stdout="active\n")
        if command == ["systemctl", "--user", "is-active", INSTRUCTION_MONITOR_SERVICE]:
            return completed(command, 3, stdout="inactive\n")
        return completed(command)

    monkeypatch.setattr(
        instruction_cli,
        "write_user_env",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("fixture write failure")),
    )

    ok, message = set_instruction_monitor_enabled(
        True,
        runner=runner,
        env_path=tmp_path / "unwritten.env",
    )

    assert ok is False
    assert "fixture write failure" in message
    assert calls == [
        ["systemctl", "--user", "is-enabled", INSTRUCTION_MONITOR_TIMER],
        ["systemctl", "--user", "is-active", INSTRUCTION_MONITOR_TIMER],
        ["systemctl", "--user", "is-active", INSTRUCTION_MONITOR_SERVICE],
        ["systemctl", "--user", "enable", "--now", INSTRUCTION_MONITOR_TIMER],
        ["systemctl", "--user", "start", "--no-block", INSTRUCTION_MONITOR_SERVICE],
        ["systemctl", "--user", "enable", "--now", INSTRUCTION_MONITOR_TIMER],
        ["systemctl", "--user", "stop", INSTRUCTION_MONITOR_SERVICE],
    ]


def test_ai_unit_rollback_restores_disabled_timer_and_running_service(monkeypatch, tmp_path):
    calls = []

    def runner(command, **_kwargs):
        command = list(command)
        calls.append(command)
        if command == ["systemctl", "--user", "is-enabled", INSTRUCTION_ASSISTANT_TIMER]:
            return completed(command, 1, stdout="disabled\n")
        if command == ["systemctl", "--user", "is-active", INSTRUCTION_ASSISTANT_TIMER]:
            return completed(command, 3, stdout="inactive\n")
        if command == ["systemctl", "--user", "is-active", INSTRUCTION_ASSISTANT_SERVICE]:
            return completed(command, stdout="active\n")
        return completed(command)

    monkeypatch.setattr(
        instruction_cli,
        "write_user_env",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("fixture AI write failure")),
    )

    ok, message = set_instruction_ai_enabled(
        False,
        runner=runner,
        env_path=tmp_path / "unwritten.env",
    )

    assert ok is False
    assert "fixture AI write failure" in message
    assert calls == [
        ["systemctl", "--user", "is-enabled", INSTRUCTION_ASSISTANT_TIMER],
        ["systemctl", "--user", "is-active", INSTRUCTION_ASSISTANT_TIMER],
        ["systemctl", "--user", "is-active", INSTRUCTION_ASSISTANT_SERVICE],
        ["systemctl", "--user", "disable", "--now", INSTRUCTION_ASSISTANT_TIMER],
        ["systemctl", "--user", "disable", "--now", INSTRUCTION_ASSISTANT_TIMER],
        ["systemctl", "--user", "start", "--no-block", INSTRUCTION_ASSISTANT_SERVICE],
    ]


def test_command_environment_keeps_background_capture_offline_and_assistant_user_only(monkeypatch, tmp_path):
    calls = []
    user_path = tmp_path / "user.env"
    monkeypatch.setattr(cli, "load_env", lambda *args, **kwargs: calls.append((args, kwargs)))
    monkeypatch.setattr(cli, "user_env_path", lambda: user_path)

    cli.load_command_environment(["instruction-audit", "--background-capture"])
    assert calls == []

    cli.load_command_environment(["instruction-audit", "--background-assist"])
    assert calls == [((), {"paths": [user_path]})]

    calls.clear()
    cli.load_command_environment(["instruction-audit", "--status"])
    assert calls == [((), {})]


@pytest.mark.parametrize(
    ("review_required", "raises", "expected"),
    [
        (False, False, EXIT_CLEAR),
        (True, False, EXIT_REVIEW),
        (False, True, EXIT_ERROR),
    ],
)
def test_instruction_audit_exit_codes(monkeypatch, tmp_path, review_required, raises, expected):
    def scan(*_args, **_kwargs):
        if raises:
            raise ValueError("fixture scan failure")
        return FakeReport(review_required=review_required)

    install_fake_guard(monkeypatch, tmp_path, scan=scan)
    stdout = io.StringIO()
    stderr = io.StringIO()

    status = run_instruction_audit(
        ["--root", str(tmp_path / "home")],
        stdout=stdout,
        stderr=stderr,
        env={"HOME": str(tmp_path / "home"), "XDG_STATE_HOME": str(tmp_path / "state-home")},
        env_path=tmp_path / "missing.env",
    )

    assert status == expected
    if raises:
        assert "scan failed" in stderr.getvalue().lower()
    else:
        assert "fixture instruction report" in stdout.getvalue()


@pytest.mark.parametrize(
    ("guard_state", "expected"),
    [
        ("clear", EXIT_CLEAR),
        ("review_required", EXIT_REVIEW),
        ("unavailable", EXIT_ERROR),
    ],
)
def test_instruction_audit_status_exit_code_reflects_persistent_review_state(
    monkeypatch,
    tmp_path,
    guard_state,
    expected,
):
    install_fake_guard(
        monkeypatch,
        tmp_path,
        status={
            "schema": "instruction_guard_status/1.0",
            "state": guard_state,
            "review_candidate_count": 1 if guard_state == "review_required" else 0,
        },
    )

    def runner(command, **_kwargs):
        command = list(command)
        if "is-enabled" in command:
            return completed(command, 1, stdout="disabled\n")
        return completed(command, 3, stdout="inactive\n")

    status = run_instruction_audit(
        ["--status", "--json", "--state-root", str(tmp_path / "state")],
        stdout=io.StringIO(),
        stderr=io.StringIO(),
        env={"HOME": str(tmp_path / "home")},
        env_path=tmp_path / "missing.env",
        runner=runner,
    )

    assert status == expected


def test_background_capture_returns_clear_and_notification_is_generic(monkeypatch, tmp_path):
    scan_calls = []

    def scan(root, **kwargs):
        scan_calls.append((root, kwargs))
        return FakeReport(review_required=True, new_alert_count=2)

    acknowledged = []
    install_fake_guard(
        monkeypatch,
        tmp_path,
        scan=scan,
        pending_alerts=[
            {"alert_id": "alert-one", "severity": "HIGH"},
            {"alert_id": "alert-two", "severity": "CRITICAL"},
        ],
        acknowledge=lambda alert_id, **_kwargs: acknowledged.append(alert_id),
    )
    secret = "fixture-secret-not-for-scanner"
    config = tmp_path / "user.env"
    config.write_text(
        f"AURASCAN_OPENAI_API_KEY={secret}\n"
        f"{INSTRUCTION_MONITOR_ENABLED_ENV}=1\n"
        f"{INSTRUCTION_AI_ENABLED_ENV}=1\n"
        f"{INSTRUCTION_SCAN_MODE_ENV}=all-markdown\n",
        encoding="utf-8",
    )
    config.chmod(0o600)
    commands = []

    status = run_instruction_audit(
        ["--background-capture", "--root", str(tmp_path / "home")],
        env={"HOME": str(tmp_path / "home"), "XDG_STATE_HOME": str(tmp_path / "state-home")},
        env_path=config,
        runner=lambda command, **_kwargs: commands.append(list(command)) or completed(command),
        which=lambda name: "/usr/bin/notify-send" if name == "notify-send" else None,
    )

    assert status == EXIT_CLEAR
    assert len(scan_calls) == 1
    assert scan_calls[0][1]["background"] is True
    assert scan_calls[0][1]["all_markdown"] is True
    assert scan_calls[0][1]["ai_reviewer"] is None
    assert secret not in repr(scan_calls)
    assert commands == [[
        "/usr/bin/notify-send",
        "AuraScan Agent Instruction Guard",
        "Agent file findings need review in AuraScan.",
    ]]
    assert str(tmp_path) not in repr(commands)
    assert secret not in repr(commands)
    assert acknowledged == ["alert-one", "alert-two"]


def test_background_capture_leaves_alert_pending_when_notification_fails(monkeypatch, tmp_path):
    acknowledged = []
    install_fake_guard(
        monkeypatch,
        tmp_path,
        scan=lambda *_args, **_kwargs: FakeReport(review_required=True, new_alert_count=1),
        pending_alerts=[{"alert_id": "alert-for-tray", "severity": "HIGH"}],
        acknowledge=lambda alert_id, **_kwargs: acknowledged.append(alert_id),
    )
    config = tmp_path / "user.env"
    config.write_text(f"{INSTRUCTION_MONITOR_ENABLED_ENV}=1\n", encoding="utf-8")
    config.chmod(0o600)

    status = run_instruction_audit(
        ["--background-capture", "--root", str(tmp_path / "home")],
        env={"HOME": str(tmp_path / "home")},
        env_path=config,
        runner=lambda command, **_kwargs: completed(command, 1),
        which=lambda name: "/usr/bin/notify-send" if name == "notify-send" else None,
    )

    assert status == EXIT_CLEAR
    assert acknowledged == []


def test_explicit_one_shot_ai_can_use_a_configured_disabled_local_provider(monkeypatch):
    seen = {}

    def call_provider(config, prompt, **_kwargs):
        seen["enabled"] = config.enabled
        seen["provider"] = config.provider
        seen["prompt"] = prompt
        return "fixture response"

    monkeypatch.setattr(instruction_cli, "call_ai_provider", call_provider)
    reviewer = instruction_cli._provider_reviewer(
        {
            "AURASCAN_AI_ENABLED": "0",
            "AURASCAN_AI_PROVIDER": "llamacpp",
            "AURASCAN_AI_MODEL": "fixture-model",
            "AURASCAN_AI_BASE_URL": "http://127.0.0.1:8080/v1",
        },
        urlopen=None,
        explicit_one_shot=True,
    )

    assert reviewer("bounded fixture prompt") == "fixture response"
    assert seen == {
        "enabled": True,
        "provider": "llamacpp",
        "prompt": "bounded fixture prompt",
    }
