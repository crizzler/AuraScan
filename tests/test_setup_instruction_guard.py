import io
import subprocess
import sys
import types
from pathlib import Path

import aurascan.core as core_package
import aurascan.core.instruction_cli as instruction_cli
from aurascan.core.ai_provider import (
    AI_BASE_URL_ENV,
    AI_ENABLED_ENV,
    AI_MODEL_ENV,
    AI_PROVIDER_ENV,
)
from aurascan.core.instruction_cli import (
    INSTRUCTION_AI_ENABLED_ENV,
    INSTRUCTION_ASSISTANT_SERVICE,
    INSTRUCTION_ASSISTANT_TIMER,
    INSTRUCTION_MONITOR_ENABLED_ENV,
    INSTRUCTION_MONITOR_SERVICE,
    INSTRUCTION_MONITOR_TIMER,
    INSTRUCTION_SCAN_MODE_ENV,
)
from aurascan.setup_wizard import build_doctor_checks, run_init


def completed(command, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(command, returncode, stdout, stderr)


def install_fake_guard_status(monkeypatch, state):
    module = types.ModuleType("aurascan.core.instruction_guard")
    module.default_instruction_guard_state_root = lambda env=None: (
        Path((env or {}).get("XDG_STATE_HOME", "."))
        / "aurascan"
        / "instruction-guard"
    )
    module.instruction_guard_status = lambda **_kwargs: dict(state)
    monkeypatch.setitem(sys.modules, module.__name__, module)
    monkeypatch.setattr(core_package, "instruction_guard", module, raising=False)


def write_instruction_units(root):
    root.mkdir(parents=True)
    for name in (
        INSTRUCTION_MONITOR_SERVICE,
        INSTRUCTION_MONITOR_TIMER,
        INSTRUCTION_ASSISTANT_SERVICE,
        INSTRUCTION_ASSISTANT_TIMER,
    ):
        (root / name).write_text("[Unit]\nDescription=fixture\n", encoding="utf-8")


def doctor_checks(tmp_path, *, env_path, unit_root, state_root, which, runner):
    return build_doctor_checks(
        env_path=env_path,
        env={
            "HOME": str(tmp_path / "home"),
            "XDG_STATE_HOME": str(tmp_path / "state-home"),
            "XDG_CONFIG_HOME": str(tmp_path / "config-home"),
            "XDG_DATA_HOME": str(tmp_path / "data-home"),
        },
        executable_path=tmp_path / "usr/bin/aurascan",
        local_hook_path=tmp_path / "local.hook",
        packaged_hook_path=tmp_path / "packaged.hook",
        updater_config_home=tmp_path / "updater-config",
        updater_data_home=tmp_path / "updater-data",
        which=which,
        qt_binding_finder=lambda: "",
        runner=runner,
        os_release_path=tmp_path / "os-release",
        incident_service_path=tmp_path / "incident-monitor.service",
        incident_maintenance_service_path=tmp_path / "incident-maintenance.service",
        incident_maintenance_timer_path=tmp_path / "incident-maintenance.timer",
        incident_system_root=tmp_path / "incident-state",
        incident_background_unit_root=tmp_path / "incident-user-units",
        instruction_unit_root=unit_root,
        instruction_state_root=state_root,
        incident_safe_service_path=tmp_path / "incident-safe.service",
        incident_auto_repair_policy_path=tmp_path / "incident-policy.conf",
        incident_user_root=tmp_path / "incident-user-state",
        journal_root=tmp_path / "journal",
        pstore_root=tmp_path / "pstore",
        recovery_root=tmp_path / "recovery-root",
        followup_root=tmp_path / "followup",
        agent_root_policy_path=tmp_path / "agent-policy.conf",
        agent_audit_root=tmp_path / "agent-audit",
        agent_runtime_root=tmp_path / "agent-runtime",
    )


def test_init_explicitly_configures_instruction_monitor_ai_and_scan_mode(monkeypatch, tmp_path):
    env_path = tmp_path / "aurascan.env"
    calls = []
    monkeypatch.setattr(
        instruction_cli,
        "resolve_ai_config",
        lambda _env=None: types.SimpleNamespace(ready=True),
    )

    def runner(command, **_kwargs):
        command = list(command)
        calls.append(command)
        if "is-enabled" in command:
            return completed(command, 1, stdout="disabled\n")
        if "is-active" in command:
            return completed(command, 3, stdout="inactive\n")
        return completed(command)

    status = run_init(
        [
            "--provider", "lmstudio",
            "--model", "fixture-local-model",
            "--base-url", "http://127.0.0.1:1234/v1",
            "--enable-ai",
            "--enable-instruction-monitor",
            "--enable-instruction-ai",
            "--instruction-scan-mode", "all-markdown",
            "--no-install-hook",
        ],
        input_func=lambda prompt: (_ for _ in ()).throw(AssertionError(f"unexpected prompt: {prompt}")),
        getpass_func=lambda prompt: (_ for _ in ()).throw(AssertionError(f"unexpected secret prompt: {prompt}")),
        stdout=io.StringIO(),
        stderr=io.StringIO(),
        env_path=env_path,
        runner=runner,
    )

    text = env_path.read_text(encoding="utf-8")
    assert status == 0
    assert f"{INSTRUCTION_MONITOR_ENABLED_ENV}=1" in text
    assert f"{INSTRUCTION_AI_ENABLED_ENV}=1" in text
    assert f"{INSTRUCTION_SCAN_MODE_ENV}=all-markdown" in text
    assert ["systemctl", "--user", "enable", "--now", INSTRUCTION_MONITOR_TIMER] in calls
    assert ["systemctl", "--user", "start", "--no-block", INSTRUCTION_MONITOR_SERVICE] in calls
    assert ["systemctl", "--user", "enable", "--now", INSTRUCTION_ASSISTANT_TIMER] in calls
    assert ["systemctl", "--user", "start", "--no-block", INSTRUCTION_ASSISTANT_SERVICE] in calls


def test_init_explicit_disable_repairs_running_units_when_consent_is_already_disabled(tmp_path):
    env_path = tmp_path / "aurascan.env"
    env_path.write_text(
        f"{INSTRUCTION_MONITOR_ENABLED_ENV}=0\n"
        f"{INSTRUCTION_AI_ENABLED_ENV}=0\n"
        f"{INSTRUCTION_SCAN_MODE_ENV}=agent-surfaces\n",
        encoding="utf-8",
    )
    env_path.chmod(0o600)
    calls = []

    def runner(command, **_kwargs):
        command = list(command)
        calls.append(command)
        if "is-enabled" in command:
            return completed(command, stdout="enabled\n")
        if "is-active" in command:
            return completed(command, stdout="active\n")
        return completed(command)

    status = run_init(
        [
            "--disable-ai",
            "--disable-instruction-monitor",
            "--disable-instruction-ai",
            "--no-install-hook",
        ],
        stdout=io.StringIO(),
        stderr=io.StringIO(),
        env_path=env_path,
        runner=runner,
    )

    assert status == 0
    assert ["systemctl", "--user", "disable", "--now", INSTRUCTION_MONITOR_TIMER] in calls
    assert ["systemctl", "--user", "disable", "--now", INSTRUCTION_ASSISTANT_TIMER] in calls


def test_init_explicit_enable_repairs_stopped_units_when_consent_is_already_enabled(tmp_path):
    env_path = tmp_path / "aurascan.env"
    env_path.write_text(
        f"{AI_ENABLED_ENV}=1\n"
        f"{AI_PROVIDER_ENV}=lmstudio\n"
        f"{AI_MODEL_ENV}=fixture-local-model\n"
        f"{AI_BASE_URL_ENV}=http://127.0.0.1:1234/v1\n"
        f"{INSTRUCTION_MONITOR_ENABLED_ENV}=1\n"
        f"{INSTRUCTION_AI_ENABLED_ENV}=1\n"
        f"{INSTRUCTION_SCAN_MODE_ENV}=agent-surfaces\n",
        encoding="utf-8",
    )
    env_path.chmod(0o600)
    calls = []

    def runner(command, **_kwargs):
        command = list(command)
        calls.append(command)
        if "is-enabled" in command:
            return completed(command, 1, stdout="disabled\n")
        if "is-active" in command:
            return completed(command, 3, stdout="inactive\n")
        return completed(command)

    status = run_init(
        [
            "--provider", "lmstudio",
            "--model", "fixture-local-model",
            "--base-url", "http://127.0.0.1:1234/v1",
            "--enable-ai",
            "--enable-instruction-monitor",
            "--enable-instruction-ai",
            "--no-install-hook",
        ],
        stdout=io.StringIO(),
        stderr=io.StringIO(),
        env_path=env_path,
        runner=runner,
    )

    assert status == 0
    assert ["systemctl", "--user", "enable", "--now", INSTRUCTION_MONITOR_TIMER] in calls
    assert ["systemctl", "--user", "start", "--no-block", INSTRUCTION_MONITOR_SERVICE] in calls
    assert ["systemctl", "--user", "enable", "--now", INSTRUCTION_ASSISTANT_TIMER] in calls
    assert ["systemctl", "--user", "start", "--no-block", INSTRUCTION_ASSISTANT_SERVICE] in calls


def test_init_restores_actual_unit_state_when_second_explicit_repair_fails(tmp_path):
    env_path = tmp_path / "aurascan.env"
    env_path.write_text(
        f"{INSTRUCTION_MONITOR_ENABLED_ENV}=0\n"
        f"{INSTRUCTION_AI_ENABLED_ENV}=0\n"
        f"{INSTRUCTION_SCAN_MODE_ENV}=agent-surfaces\n",
        encoding="utf-8",
    )
    env_path.chmod(0o600)
    calls = []

    def runner(command, **_kwargs):
        command = list(command)
        calls.append(command)
        if command == ["systemctl", "--user", "disable", "--now", INSTRUCTION_ASSISTANT_TIMER]:
            return completed(command, 1, stderr="fixture assistant failure")
        if "is-enabled" in command:
            return completed(command, stdout="enabled\n")
        if "is-active" in command and command[-1].endswith(".timer"):
            return completed(command, stdout="active\n")
        if "is-active" in command:
            return completed(command, 3, stdout="inactive\n")
        return completed(command)

    status = run_init(
        [
            "--disable-ai",
            "--disable-instruction-monitor",
            "--disable-instruction-ai",
            "--no-install-hook",
        ],
        stdout=io.StringIO(),
        stderr=io.StringIO(),
        env_path=env_path,
        runner=runner,
    )

    text = env_path.read_text(encoding="utf-8")
    assert status == 1
    assert f"{INSTRUCTION_MONITOR_ENABLED_ENV}=0" in text
    assert f"{INSTRUCTION_AI_ENABLED_ENV}=0" in text
    assert ["systemctl", "--user", "disable", "--now", INSTRUCTION_MONITOR_TIMER] in calls
    assert ["systemctl", "--user", "disable", "--now", INSTRUCTION_ASSISTANT_TIMER] in calls
    assert ["systemctl", "--user", "enable", "--now", INSTRUCTION_ASSISTANT_TIMER] in calls
    assert ["systemctl", "--user", "enable", "--now", INSTRUCTION_MONITOR_TIMER] in calls
    assert ["systemctl", "--user", "stop", INSTRUCTION_ASSISTANT_SERVICE] in calls
    assert ["systemctl", "--user", "stop", INSTRUCTION_MONITOR_SERVICE] in calls


def test_init_rolls_back_monitor_and_ai_consent_when_assistant_timer_fails(monkeypatch, tmp_path):
    env_path = tmp_path / "aurascan.env"
    env_path.write_text(
        f"{INSTRUCTION_MONITOR_ENABLED_ENV}=0\n"
        f"{INSTRUCTION_AI_ENABLED_ENV}=0\n"
        f"{INSTRUCTION_SCAN_MODE_ENV}=agent-surfaces\n",
        encoding="utf-8",
    )
    env_path.chmod(0o600)
    calls = []
    monkeypatch.setattr(
        instruction_cli,
        "resolve_ai_config",
        lambda _env=None: types.SimpleNamespace(ready=True),
    )

    def runner(command, **_kwargs):
        command = list(command)
        calls.append(command)
        if "is-enabled" in command:
            return completed(command, 1, stdout="disabled\n")
        if "is-active" in command:
            return completed(command, 3, stdout="inactive\n")
        if command == ["systemctl", "--user", "enable", "--now", INSTRUCTION_ASSISTANT_TIMER]:
            return completed(command, 1, stderr="fixture assistant failure")
        return completed(command)

    status = run_init(
        [
            "--provider", "lmstudio",
            "--model", "fixture-local-model",
            "--enable-ai",
            "--enable-instruction-monitor",
            "--enable-instruction-ai",
            "--instruction-scan-mode", "all-markdown",
            "--no-install-hook",
        ],
        stdout=io.StringIO(),
        stderr=io.StringIO(),
        env_path=env_path,
        runner=runner,
    )

    text = env_path.read_text(encoding="utf-8")
    assert status == 1
    assert f"{INSTRUCTION_MONITOR_ENABLED_ENV}=0" in text
    assert f"{INSTRUCTION_AI_ENABLED_ENV}=0" in text
    assert ["systemctl", "--user", "enable", "--now", INSTRUCTION_MONITOR_TIMER] in calls
    assert ["systemctl", "--user", "enable", "--now", INSTRUCTION_ASSISTANT_TIMER] in calls
    assert ["systemctl", "--user", "disable", "--now", INSTRUCTION_MONITOR_TIMER] in calls


def test_init_restores_all_instruction_preferences_when_monitor_enable_fails(monkeypatch, tmp_path):
    env_path = tmp_path / "aurascan.env"
    env_path.write_text(
        f"{INSTRUCTION_MONITOR_ENABLED_ENV}=0\n"
        f"{INSTRUCTION_AI_ENABLED_ENV}=0\n"
        f"{INSTRUCTION_SCAN_MODE_ENV}=agent-surfaces\n",
        encoding="utf-8",
    )
    env_path.chmod(0o600)
    monkeypatch.setattr(
        instruction_cli,
        "resolve_ai_config",
        lambda _env=None: types.SimpleNamespace(ready=True),
    )

    def runner(command, **_kwargs):
        command = list(command)
        if "is-enabled" in command:
            return completed(command, 1, stdout="disabled\n")
        if "is-active" in command:
            return completed(command, 3, stdout="inactive\n")
        if command == ["systemctl", "--user", "enable", "--now", INSTRUCTION_MONITOR_TIMER]:
            return completed(command, 1, stderr="fixture monitor failure")
        return completed(command)

    status = run_init(
        [
            "--provider", "lmstudio",
            "--model", "fixture-local-model",
            "--enable-ai",
            "--enable-instruction-monitor",
            "--enable-instruction-ai",
            "--instruction-scan-mode", "all-markdown",
            "--no-install-hook",
        ],
        stdout=io.StringIO(),
        stderr=io.StringIO(),
        env_path=env_path,
        runner=runner,
    )

    text = env_path.read_text(encoding="utf-8")
    assert status == 1
    assert f"{INSTRUCTION_MONITOR_ENABLED_ENV}=0" in text
    assert f"{INSTRUCTION_AI_ENABLED_ENV}=0" in text
    assert f"{INSTRUCTION_SCAN_MODE_ENV}=agent-surfaces" in text


def test_doctor_reports_healthy_units_private_state_notifier_and_ai_consent(monkeypatch, tmp_path):
    env_path = tmp_path / "aurascan.env"
    env_path.write_text(
        f"{AI_ENABLED_ENV}=1\n"
        f"{AI_PROVIDER_ENV}=lmstudio\n"
        f"{AI_MODEL_ENV}=fixture-local-model\n"
        f"{AI_BASE_URL_ENV}=http://127.0.0.1:1234/v1\n"
        f"{INSTRUCTION_MONITOR_ENABLED_ENV}=1\n"
        f"{INSTRUCTION_AI_ENABLED_ENV}=1\n"
        f"{INSTRUCTION_SCAN_MODE_ENV}=agent-surfaces\n",
        encoding="utf-8",
    )
    env_path.chmod(0o600)
    unit_root = tmp_path / "units"
    write_instruction_units(unit_root)
    state_root = tmp_path / "instruction-state"
    state_root.mkdir(mode=0o700)
    install_fake_guard_status(monkeypatch, {
        "schema": "instruction_guard_status/1.0",
        "state": "clear",
        "highest_severity": "LOW",
        "pending_alert_count": 0,
        "review_candidate_count": 0,
    })

    def runner(command, **_kwargs):
        command = list(command)
        if "is-enabled" in command:
            return completed(command, stdout="enabled\n")
        if "is-active" in command:
            return completed(command, stdout="active\n")
        return completed(command, 1)

    checks = doctor_checks(
        tmp_path,
        env_path=env_path,
        unit_root=unit_root,
        state_root=state_root,
        which=lambda name: "/usr/bin/notify-send" if name == "notify-send" else None,
        runner=runner,
    )
    by_name = {check.name: check for check in checks}

    assert by_name["instruction_guard_config"].status == "ok"
    assert by_name["instruction_guard_monitor"].status == "ok"
    assert by_name["instruction_guard_ai"].status == "ok"
    assert by_name["instruction_guard_ai"].details["consent_enabled"] is True
    assert by_name["instruction_guard_ai"].details["provider_ready"] is True
    assert by_name["instruction_guard_state"].status == "ok"
    assert by_name["instruction_guard_notifications"].status == "ok"
    assert by_name["instruction_guard_notifications"].details == {"notify_send": True}
    assert str(tmp_path) not in by_name["instruction_guard_notifications"].message
    assert "snippet" in by_name["instruction_guard_notifications"].message


def test_doctor_fails_closed_for_unhealthy_units_state_and_provider_consent(monkeypatch, tmp_path):
    env_path = tmp_path / "aurascan.env"
    env_path.write_text(
        f"{AI_ENABLED_ENV}=0\n"
        f"{INSTRUCTION_MONITOR_ENABLED_ENV}=1\n"
        f"{INSTRUCTION_AI_ENABLED_ENV}=1\n"
        f"{INSTRUCTION_SCAN_MODE_ENV}=agent-surfaces\n",
        encoding="utf-8",
    )
    env_path.chmod(0o600)
    unit_root = tmp_path / "units"
    write_instruction_units(unit_root)
    state_root = tmp_path / "instruction-state"
    state_root.mkdir(mode=0o700)
    install_fake_guard_status(monkeypatch, {
        "schema": "instruction_guard_status/1.0",
        "state": "unavailable",
        "error": "unsafe private state",
    })

    def runner(command, **_kwargs):
        command = list(command)
        if "is-enabled" in command:
            return completed(command, 1, stdout="disabled\n")
        if "is-active" in command:
            return completed(command, 3, stdout="inactive\n")
        return completed(command, 1)

    checks = doctor_checks(
        tmp_path,
        env_path=env_path,
        unit_root=unit_root,
        state_root=state_root,
        which=lambda _name: None,
        runner=runner,
    )
    by_name = {check.name: check for check in checks}

    assert by_name["instruction_guard_config"].status == "ok"
    assert by_name["instruction_guard_monitor"].status == "error"
    assert by_name["instruction_guard_ai"].status == "error"
    assert by_name["instruction_guard_ai"].details["consent_enabled"] is True
    assert by_name["instruction_guard_ai"].details["provider_ready"] is False
    assert by_name["instruction_guard_state"].status == "error"
    assert by_name["instruction_guard_notifications"].status == "warn"
    assert "tray and CLI" in by_name["instruction_guard_notifications"].message


def test_doctor_reports_running_timers_that_conflict_with_disabled_consent(monkeypatch, tmp_path):
    env_path = tmp_path / "aurascan.env"
    env_path.write_text(
        f"{AI_ENABLED_ENV}=0\n"
        f"{INSTRUCTION_MONITOR_ENABLED_ENV}=0\n"
        f"{INSTRUCTION_AI_ENABLED_ENV}=0\n"
        f"{INSTRUCTION_SCAN_MODE_ENV}=agent-surfaces\n",
        encoding="utf-8",
    )
    env_path.chmod(0o600)
    unit_root = tmp_path / "units"
    write_instruction_units(unit_root)
    state_root = tmp_path / "instruction-state"
    state_root.mkdir(mode=0o700)
    install_fake_guard_status(monkeypatch, {
        "schema": "instruction_guard_status/1.0",
        "state": "clear",
        "highest_severity": "LOW",
        "pending_alert_count": 0,
        "review_candidate_count": 0,
    })

    def runner(command, **_kwargs):
        command = list(command)
        if "is-enabled" in command:
            return completed(command, stdout="enabled\n")
        if "is-active" in command:
            return completed(command, stdout="active\n")
        return completed(command, 1)

    checks = doctor_checks(
        tmp_path,
        env_path=env_path,
        unit_root=unit_root,
        state_root=state_root,
        which=lambda _name: None,
        runner=runner,
    )
    by_name = {check.name: check for check in checks}

    assert by_name["instruction_guard_monitor"].status == "error"
    assert "disabled in config" in by_name["instruction_guard_monitor"].message
    assert by_name["instruction_guard_ai"].status == "error"
    assert "consent is disabled" in by_name["instruction_guard_ai"].message
    assert by_name["instruction_guard_ai"].details["assistant_timer_enabled"] == "enabled"
    assert by_name["instruction_guard_ai"].details["assistant_timer_active"] == "active"


def test_doctor_accepts_disabled_consent_with_disabled_inactive_timers(monkeypatch, tmp_path):
    env_path = tmp_path / "aurascan.env"
    env_path.write_text(
        f"{INSTRUCTION_MONITOR_ENABLED_ENV}=0\n"
        f"{INSTRUCTION_AI_ENABLED_ENV}=0\n"
        f"{INSTRUCTION_SCAN_MODE_ENV}=agent-surfaces\n",
        encoding="utf-8",
    )
    env_path.chmod(0o600)
    unit_root = tmp_path / "units"
    write_instruction_units(unit_root)
    state_root = tmp_path / "instruction-state"
    state_root.mkdir(mode=0o700)
    install_fake_guard_status(monkeypatch, {
        "schema": "instruction_guard_status/1.0",
        "state": "clear",
        "highest_severity": "LOW",
        "pending_alert_count": 0,
        "review_candidate_count": 0,
    })

    def runner(command, **_kwargs):
        command = list(command)
        if "is-enabled" in command:
            return completed(command, 1, stdout="disabled\n")
        if "is-active" in command:
            return completed(command, 3, stdout="inactive\n")
        return completed(command, 1)

    checks = doctor_checks(
        tmp_path,
        env_path=env_path,
        unit_root=unit_root,
        state_root=state_root,
        which=lambda _name: None,
        runner=runner,
    )
    by_name = {check.name: check for check in checks}

    assert by_name["instruction_guard_monitor"].status == "ok"
    assert by_name["instruction_guard_ai"].status == "ok"
