"""Exercise tray authority and observed-state invariants without host services."""

import json
import os
from types import SimpleNamespace

import pytest

from aurascan.core import intelligence_tray as ui
from aurascan.core.intelligence import bundled_snapshot
from aurascan.core.intelligence_store import IntelligenceStore
from aurascan.core.trusted_tools import TrustedToolError
from aurascan.core.updater_tray import bind_tray_mutation_guard
from tests.test_updater_tray import (
    FakeAction, FakeMenu, FakeProcess, FakeTimer, FakeTray, fake_instruction_menu,
    instruction_control_payload,
)


def status(**updates):
    payload = bundled_snapshot().metadata()
    payload.update(status_schema="intelligence-status/1.0", update_channel="configured",
                   automatic_updates="disabled", refresh_status="idle")
    payload.update(updates)
    return payload


def installed(**updates):
    payload = status(source="installed", sequence=17, status="current",
                     activated_at="2026-09-12T00:00:00Z", expires_at="2026-10-01T00:00:00Z")
    payload.update(updates)
    return payload


def menu_controller():
    menu, tray, processes, timers, commands, dialogs = FakeMenu(), FakeTray(), [], [], [], []

    def command(operation):
        commands.append(operation)
        return ["/injected/aurascan", operation]

    def factory():
        process = FakeProcess()
        processes.append(process)
        return process

    def schedule(process, milliseconds, callback):
        timer = FakeTimer(callback)
        timer.milliseconds = milliseconds
        timers.append(timer)
        return timer

    controller = ui.IntelligenceMenuController(menu, process_factory=factory,
        schedule_timeout=schedule, command_builder=command, notify=tray.showMessage,
        show_status=lambda *args: dialogs.append(args))
    return SimpleNamespace(controller=controller, menu=menu, tray=tray, processes=processes,
                           timers=timers, commands=commands, dialogs=dialogs)


def ready(**updates):
    app = menu_controller()
    app.controller.refresh()
    app.processes[-1].complete(0, status(**updates))
    return app


def test_start_and_status_click_only_read_local_status_and_surface_unconfigured_feed():
    app = menu_controller()
    assert app.commands == []
    assert not app.controller.update_action.enabled
    app.controller.status_action.triggered.emit()
    assert app.commands == ["status"]
    app.processes[-1].complete(0, status(update_channel="unconfigured"))
    assert not app.controller.update_action.enabled
    assert not app.controller.auto_action.enabled
    assert "Not yet configured" in app.dialogs[-1][1]
    assert "No signed update installed" in app.dialogs[-1][1]
    assert app.tray.messages == []
    assert not app.controller.mutate("update")
    assert not app.controller.mutate("enable")
    assert app.commands == ["status"]


def test_toggle_requires_successful_observed_state_and_serializes_children():
    app = ready()
    control = app.controller
    control.auto_action.trigger(True)
    assert app.commands == ["status", "enable"]
    assert control.auto_action.checked is False
    assert control.mutation_active
    assert not control.mutate("update")
    assert not control.refresh()
    app.processes[-1].complete(0)
    assert app.commands[-1] == "status"
    assert control.mutation_active
    assert not control.auto_action.checked
    assert app.tray.messages == []
    app.processes[-1].complete(0, status(automatic_updates="enabled"))
    assert control.auto_action.checked
    assert not control.mutation_active
    assert "now enabled" in app.tray.messages[-1][1]
    assert all(process.deleted for process in app.processes)
    assert all(timer.stopped and timer.deleted for timer in app.timers)


@pytest.mark.parametrize("automatic", ["unavailable", "inconsistent"])
def test_unknown_or_inconsistent_timer_is_not_permission_to_enable(automatic):
    app = ready(automatic_updates=automatic)
    assert not app.controller.auto_action.enabled
    assert not app.controller.mutate("enable")
    assert not app.controller.mutate("disable")
    assert app.commands == ["status"]


def test_disabling_enabled_timer_remains_possible_without_feed_configuration():
    app = ready(update_channel="unconfigured", automatic_updates="enabled")
    assert app.controller.auto_action.enabled
    assert app.controller.auto_action.checked
    app.controller.auto_action.trigger(False, include_checked=False)
    assert app.commands[-1] == "disable"
    assert app.controller.auto_action.checked  # Retain the observed enabled state.
    app.processes[-1].complete(0)
    app.processes[-1].complete(0, status(update_channel="unconfigured"))
    assert not app.controller.auto_action.checked
    assert "now disabled" in app.tray.messages[-1][1]


@pytest.mark.parametrize("code,word", [(126, "canceled"), (127, "authorization"), (1, "failed")])
def test_failed_authorization_or_update_never_claims_success_or_leaks_child_output(code, word):
    app = ready()
    app.controller.mutate("update")
    app.processes[-1].emit_stderr(b"fake-secret https://example.invalid/private")
    app.processes[-1].complete(code, b"fake-private-stdout")
    assert word in app.tray.messages[-1][1]
    assert app.commands == ["status", "update", "status"]
    app.processes[-1].complete(0, status())
    assert not app.controller.mutation_active
    assert not app.controller.auto_action.checked
    assert "fake-" not in repr(app.tray.messages)
    assert "https:" not in repr(app.tray.messages)


@pytest.mark.parametrize("payload", [status(), installed(status="unavailable"), installed(status="stale")])
def test_zero_exit_is_insufficient_for_update_success(payload):
    app = ready()
    app.controller.mutate("update")
    app.processes[-1].complete(0)
    app.processes[-1].complete(0, payload)
    assert "could not be confirmed" in app.tray.messages[-1][1]


def test_update_reports_captured_identity_and_status_click_during_work_is_not_lost():
    app = ready()
    app.controller.mutate("update")
    app.controller.status_action.triggered.emit()
    assert app.dialogs == []
    app.processes[-1].complete(0)
    app.processes[-1].complete(0, installed())
    assert "sequence 17" in app.tray.messages[-1][1]
    assert "2026-09-12T00:00:00Z" in app.dialogs[-1][1]
    assert "ClamAV" in app.dialogs[-1][1]
    assert len(app.commands) == 3


def test_running_service_prevents_another_refresh():
    app = ready(refresh_status="running")
    assert not app.controller.update_action.enabled
    assert not app.controller.mutate("update")


@pytest.mark.parametrize("problem", ["timeout", "stderr-limit", "combined-limit", "error"])
def test_mutating_child_retained_until_exit_then_state_reread(problem):
    app = ready()
    app.controller.mutate("update")
    process = app.processes[-1]
    old_timer = app.timers[-1]
    assert old_timer.milliseconds == ui.MUTATION_TIMEOUT_MS
    if problem == "timeout":
        old_timer.fire()
    elif problem == "stderr-limit":
        process.emit_stderr(b"x" * (ui.OUTPUT_LIMIT + 1))
    elif problem == "combined-limit":
        process.emit_stdout(b"x" * (ui.OUTPUT_LIMIT // 2))
        process.emit_stderr(b"y" * (ui.OUTPUT_LIMIT // 2 + 1))
    else:
        process.errorOccurred.emit(1)
    assert process.killed
    assert not process.deleted
    assert app.controller.mutation_active
    assert not app.controller.refresh()
    assert len(app.processes) == 2
    process.complete(-9, exit_status=1)
    assert process.deleted and old_timer.deleted and old_timer.stopped
    assert app.commands[-1] == "status"
    old_timer.fire()  # A late callback may not cancel the new child.
    assert not app.processes[-1].killed
    app.processes[-1].complete(0, status())
    assert not app.controller.mutation_active


def test_output_limit_during_finished_signal_is_bounded_and_does_not_recurse():
    app = menu_controller()
    app.controller.refresh(show=True)
    app.processes[-1].complete(0, b"x" * (ui.OUTPUT_LIMIT + 1))
    assert app.processes[-1].deleted
    assert app.controller.current_process is None
    assert app.controller.data is None
    assert "unavailable" in app.dialogs[-1][1]


@pytest.mark.parametrize("raw", [b"[]", b"[" * 2000, b"\xff", b"{}",
    json.dumps(status(sequence=True)).encode(),
    json.dumps(status(status_schema="intelligence-status/99")).encode(),
    json.dumps(status(reviewed_at="fake-secret")).encode(),
    json.dumps(status(status=["current"])).encode(),
    json.dumps(status(coverage_error="capture failed")).encode(),
    json.dumps(installed(activated_at="")).encode(),
    json.dumps(status()).replace('"sequence": 0', '"sequence": 0, "sequence": 1').encode()])
def test_malformed_status_fails_closed_and_is_never_displayed(raw):
    app = menu_controller()
    app.controller.refresh(show=True)
    app.processes[-1].complete(0, raw)
    assert app.controller.data is None
    assert not app.controller.update_action.enabled
    assert not app.controller.auto_action.enabled
    assert app.dialogs[-1][1] == ui.UNAVAILABLE


def test_optional_untrusted_fields_are_not_rendered():
    payload = status(status="unavailable", coverage_error="fake-secret", arbitrary="https://example.invalid/private")
    message = ui.status_text(ui.parse_status(json.dumps(payload).encode()))
    assert "fake-secret" not in message and "https:" not in message


def test_corrupt_store_status_preserves_coverage_warning_and_timer_disable(tmp_path, monkeypatch, capsys):
    from aurascan.core import intelligence_cli as cli

    root = tmp_path / "protected-intelligence"
    root.mkdir(mode=0o755)
    (root / "active.json").write_text("{}", encoding="utf-8")
    store = IntelligenceStore(root=root, expected_uid=os.geteuid())
    monkeypatch.setattr(cli, "load_intelligence_snapshot", store.load)
    monkeypatch.setattr(cli, "_service_status", lambda: {
        "automatic_updates": "enabled", "refresh_status": "idle",
    })

    def forbidden(*_args, **_kwargs):
        raise AssertionError("status must not mutate services or fetch intelligence")

    monkeypatch.setattr(cli, "_systemctl", forbidden)
    monkeypatch.setattr(cli, "fetch_bundle", forbidden)
    monkeypatch.setattr(cli, "activate_bundle", forbidden)
    assert cli.run_intelligence(["status", "--json", "--include-services"]) == 0
    raw = capsys.readouterr().out.encode()

    app = menu_controller()
    app.controller.refresh(show=True)
    app.processes[-1].complete(0, raw)
    assert app.controller.data["source"] == "bundled-fallback"
    assert app.controller.data["status"] == "unavailable"
    assert "Coverage failure: active storage cannot be trusted" in app.dialogs[-1][1]
    assert "Last successful activation (UTC): Unavailable" in app.dialogs[-1][1]
    assert app.controller.auto_action.checked and app.controller.auto_action.enabled
    app.controller.auto_action.trigger(False)
    assert app.commands == ["status", "disable"]


@pytest.mark.parametrize("updates", [
    {"status": "bundled"}, {"coverage_error": ""}, {"sequence": 1},
    {"activated_at": "2026-09-12T00:00:00Z"},
    {"expires_at": "2026-10-01T00:00:00Z"}, {"manifest_digest": "a" * 64},
])
def test_fallback_cannot_claim_successful_activation_or_current_coverage(updates):
    payload = status(source="bundled-fallback", status="unavailable", coverage_error="capture failed")
    payload.update(updates)
    with pytest.raises(ValueError):
        ui.parse_status(json.dumps(payload).encode())


def test_crash_exit_and_unavailable_command_do_not_enable_controls():
    app = menu_controller()
    app.controller.refresh()
    app.processes[-1].complete(0, status(), exit_status=1)
    assert app.controller.data is None

    def unavailable(_operation):
        raise TrustedToolError("fake-secret")
    app.controller.command_builder = unavailable
    app.controller.refresh(show=True)
    assert not app.controller.update_action.enabled
    assert "fake-secret" not in repr(app.dialogs)


def test_shared_quit_guard_does_not_release_other_controller_mutation():
    app = ready()
    menu, _, guard_processes, _, guard = fake_instruction_menu()
    quit_action = FakeAction("Quit")
    guard.bind_quit_action(quit_action)
    bind_tray_mutation_guard(quit_action, guard, app.controller)
    guard.apply_status(instruction_control_payload())
    app.controller.mutate("update")
    menu.actions[0].trigger(True)
    assert not quit_action.enabled
    guard_processes[-1].complete(0)
    assert not quit_action.enabled
    app.processes[-1].complete(0)
    assert not quit_action.enabled
    app.processes[-1].complete(0, installed())
    assert quit_action.enabled
    guard_processes[-1].complete(0, instruction_control_payload())
    menu.actions[0].trigger(True)
    assert not quit_action.enabled
    app.controller.refresh()
    app.processes[-1].complete(0, installed())
    assert not quit_action.enabled


@pytest.mark.parametrize("operation,suffix", [
    ("status", ["status", "--json", "--include-services"]),
    ("update", ["aurascan-intelligence-activate.service"]),
    ("enable", ["aurascan-intelligence-auto-enable.service"]),
    ("disable", ["aurascan-intelligence-auto-disable.service"]),
])
def test_command_boundary_is_fixed_revalidated_and_uses_no_shell(monkeypatch, operation, suffix):
    captured, revalidated = [], []
    def capture(name, which):
        assert which(name) == "/usr/bin/" + name
        captured.append(name)
        return SimpleNamespace(name=name, path="/usr/bin/" + name)
    monkeypatch.setattr(ui, "capture_trusted_system_tool", capture)
    monkeypatch.setattr(ui, "revalidate_trusted_system_tool", lambda tool: revalidated.append(tool.name))
    command = ui.trusted_command(operation)
    expected = ["/usr/bin/aurascan", "intelligence"] + suffix
    if operation != "status":
        expected = ["/usr/bin/setsid", "--wait", "/usr/bin/systemctl", "--no-pager", "start"] + suffix
    assert command == expected
    assert captured == revalidated
    with pytest.raises(ValueError):
        ui.trusted_command("import /tmp/hostile")


def test_replaced_or_missing_executable_prevents_launch(monkeypatch):
    monkeypatch.setattr(ui, "capture_trusted_system_tool", lambda *a, **k: None)
    with pytest.raises(TrustedToolError):
        ui.trusted_command("status")
    monkeypatch.setattr(ui, "capture_trusted_system_tool", lambda *a, **k: object())
    def replaced(_tool):
        raise TrustedToolError("changed")
    monkeypatch.setattr(ui, "revalidate_trusted_system_tool", replaced)
    with pytest.raises(TrustedToolError):
        ui.trusted_command("update")


def test_qt_adapter_clears_environment_closes_stdin_and_clears_old_notification_routes(monkeypatch):
    processes, routes, timers = [], [], []
    class Process(FakeProcess):
        def __init__(self, _parent):
            super().__init__()
            processes.append(self)
        def setProcessEnvironment(self, environment): self.environment = environment
        def setWorkingDirectory(self, cwd): self.cwd = cwd
        def setStandardInputFile(self, path): self.stdin = path
    class Environment(dict):
        def insert(self, key, value): self[key] = value
    class Timer(FakeTimer):
        def __init__(self, _parent):
            from tests.test_updater_tray import FakeSignal
            self.timeout = FakeSignal()
            super().__init__(self.timeout.emit)
            timers.append(self)
        def setSingleShot(self, value): self.single = value
        def start(self, milliseconds): self.milliseconds = milliseconds
    core = SimpleNamespace(QProcess=Process, QProcessEnvironment=Environment, QTimer=Timer)
    monkeypatch.setenv("PYTHONPATH", "/fake/project")
    monkeypatch.setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/fake/socket")
    monkeypatch.setenv("AURASCAN_AI_KEY", "fake-secret")
    tray = FakeTray()
    control = ui.build_intelligence_menu(FakeMenu(), tray, core, None,
        clear_notification=lambda: routes.append("cleared"), busy_changed=lambda: None)
    control.command_builder = lambda operation: ["/injected/tool", operation]
    control.refresh()
    process = processes[-1]
    assert process.environment == ui.CHILD_ENVIRONMENT
    assert "PYTHONPATH" not in process.environment
    assert "DBUS_SYSTEM_BUS_ADDRESS" not in process.environment
    assert "AURASCAN_AI_KEY" not in process.environment
    assert process.cwd == "/" and process.stdin == "/dev/null"
    assert timers[-1].single and timers[-1].milliseconds == ui.STATUS_TIMEOUT_MS
    process.complete(0, status())
    control.mutate("update")
    processes[-1].complete(126)
    assert routes == ["cleared"]
    assert "canceled" in tray.messages[-1][1]
