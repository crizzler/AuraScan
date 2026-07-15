import io
import json
import subprocess
from pathlib import Path

import aurascan.setup_wizard as setup_wizard
from aurascan.setup_wizard import (
    build_doctor_checks,
    install_pacman_hook,
    is_release_safe_hook_template,
    resolve_hook_template_path,
    run_doctor,
    run_init,
)
from aurascan.core.kernel_module_autopilot import KERNEL_MODULE_AUTOPILOT_ENV
from aurascan.core.incidents import (
    INCIDENT_AI_ENABLED_ENV,
    INCIDENT_AI_EVIDENCE_ENV,
    INCIDENT_BACKGROUND_AI_ENV,
    INCIDENT_MAINTENANCE_SERVICE,
    INCIDENT_MAINTENANCE_TIMER,
    INCIDENT_MONITOR_ENABLED_ENV,
    INCIDENT_MONITOR_SERVICE,
)
from aurascan.core.incident_automation import (
    INCIDENT_AUTO_REPAIR_ENV,
    INCIDENT_BACKGROUND_SERVICE,
    INCIDENT_BACKGROUND_TIMER,
    INCIDENT_SAFE_AUTOPILOT_SERVICE,
    background_result_path,
    background_state_path,
    safe_automation_paths,
)
from aurascan.core.updater_tray import UPDATER_AUTOSTART_ENV, UPDATER_TERMINAL_ENV, UPDATER_TRAY_ENABLED_ENV
from aurascan.core.recovery import RECOVERY_AI_ENABLED_ENV, RECOVERY_AUTO_REFRESH_ENV, RECOVERY_WIFI_PROFILES_ENV


class FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return b'{"choices":[{"message":{"content":"BENIGN: connectivity check passed"}}]}'


def test_init_writes_hidden_key_without_printing_secret(tmp_path):
    env_path = tmp_path / ".config" / "aurascan" / ".env"
    stdout = io.StringIO()
    answers = iter([""])

    status = run_init(
        ["--provider", "openai", "--enable-ai", "--no-install-hook"],
        input_func=lambda _prompt: next(answers),
        getpass_func=lambda _prompt: "fixture-only-value",
        stdout=stdout,
        env_path=env_path,
    )

    output = stdout.getvalue()
    text = env_path.read_text(encoding="utf-8")
    assert status == 0
    assert "fixture-only-value" not in output
    assert "AURASCAN_AI_PROVIDER=openai" in text
    assert "AURASCAN_AI_ENABLED=1" in text
    assert "AURASCAN_OPENAI_API_KEY=fixture-only-value" in text
    assert oct(env_path.stat().st_mode & 0o777) == "0o600"


def test_init_can_write_disabled_local_only_config(tmp_path):
    env_path = tmp_path / ".config" / "aurascan" / ".env"
    stdout = io.StringIO()

    status = run_init(
        ["--disable-ai", "--no-install-hook"],
        stdout=stdout,
        env_path=env_path,
    )

    assert status == 0
    assert "AURASCAN_AI_ENABLED=0" in env_path.read_text(encoding="utf-8")
    assert "local-only" not in stdout.getvalue().lower()


def test_init_can_write_upgrade_preflight_defaults(tmp_path):
    env_path = tmp_path / ".config" / "aurascan" / ".env"
    stdout = io.StringIO()

    status = run_init(
        [
            "--disable-ai",
            "--enable-upgrade-preflight",
            "--upgrade-aur-helper",
            "yay",
            "--disable-upgrade-ai",
            "--disable-kernel-module-autopilot",
            "--enable-config-drift",
            "--config-drift-ai-diffs",
            "never",
            "--no-install-hook",
        ],
        stdout=stdout,
        env_path=env_path,
    )
    text = env_path.read_text(encoding="utf-8")

    assert status == 0
    assert "AURASCAN_UPGRADE_PREFLIGHT_ENABLED=1" in text
    assert "AURASCAN_UPGRADE_AUR_HELPER=yay" in text
    assert "AURASCAN_UPGRADE_PREFLIGHT_AI=0" in text
    assert f"{KERNEL_MODULE_AUTOPILOT_ENV}=0" in text
    assert "AURASCAN_CONFIG_DRIFT_ENABLED=1" in text
    assert "AURASCAN_CONFIG_DRIFT_AI_DIFFS=never" in text
    assert "Configured upgrade preflight defaults." in stdout.getvalue()
    assert "Configured config drift assistant defaults." in stdout.getvalue()


def test_init_can_enable_kernel_module_autopilot(tmp_path):
    env_path = tmp_path / ".config" / "aurascan" / ".env"

    status = run_init(
        ["--disable-ai", "--enable-kernel-module-autopilot", "--no-install-hook"],
        stdout=io.StringIO(),
        env_path=env_path,
    )

    assert status == 0
    text = env_path.read_text(encoding="utf-8")
    assert "AURASCAN_UPGRADE_PREFLIGHT_ENABLED=1" in text
    assert f"{KERNEL_MODULE_AUTOPILOT_ENV}=1" in text


def test_init_can_explicitly_install_recovery_with_separate_consent(tmp_path):
    env_path = tmp_path / ".env"
    executable = tmp_path / "usr/bin/aurascan"
    calls = []

    def runner(command, **_kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "Recovery installed\n", "")

    status = run_init(
        [
            "--disable-ai",
            "--install-recovery",
            "--enable-recovery-ai",
            "--enable-recovery-auto-refresh",
            "--recovery-wifi-profiles", "ask",
            "--no-install-hook",
        ],
        stdout=io.StringIO(),
        env_path=env_path,
        executable_path=executable,
        recovery_root=tmp_path / "fixture-root",
        runner=runner,
    )

    text = env_path.read_text(encoding="utf-8")
    assert status == 0
    assert f"{RECOVERY_AI_ENABLED_ENV}=1" in text
    assert f"{RECOVERY_AUTO_REFRESH_ENV}=1" in text
    assert f"{RECOVERY_WIFI_PROFILES_ENV}=ask" in text
    install = next(command for command in calls if "recovery" in command and "--install" in command)
    assert install[:4] == ["sudo", str(executable), "recovery", "--install"]
    assert "--opted-uid" in install
    assert "--refresh-policy" in install


def test_doctor_reports_optional_recovery_state(tmp_path):
    checks = build_doctor_checks(
        env_path=tmp_path / "missing.env",
        env={},
        executable_path=tmp_path / "usr/bin/aurascan",
        local_hook_path=tmp_path / "local.hook",
        packaged_hook_path=tmp_path / "packaged.hook",
        recovery_root=tmp_path / "target",
        which=lambda _name: None,
        runner=lambda command, **_kwargs: subprocess.CompletedProcess(command, 1, "", ""),
    )
    by_name = {item.name: item for item in checks}

    assert by_name["recovery_config"].status == "warn"
    assert by_name["recovery_image"].status == "ok"
    assert by_name["recovery_esp"].status == "warn"
    assert by_name["recovery_build_tools"].status == "warn"
    assert by_name["recovery_ai"].status == "warn"
    assert by_name["recovery_iso"].status == "warn"
    assert by_name["recovery_last_result"].status == "ok"


def test_init_can_disable_config_drift_assistant(tmp_path):
    env_path = tmp_path / ".config" / "aurascan" / ".env"
    stdout = io.StringIO()

    status = run_init(
        ["--disable-ai", "--disable-config-drift", "--no-install-hook"],
        stdout=stdout,
        env_path=env_path,
    )

    assert status == 0
    assert "AURASCAN_CONFIG_DRIFT_ENABLED=0" in env_path.read_text(encoding="utf-8")
    assert "Config drift assistant will be disabled" in stdout.getvalue()


def test_init_can_install_updater_autostart(tmp_path):
    env_path = tmp_path / ".config" / "aurascan" / ".env"
    stdout = io.StringIO()

    status = run_init(
        ["--disable-ai", "--enable-updater-tray", "--install-updater-autostart", "--no-install-hook"],
        stdout=stdout,
        env_path=env_path,
        updater_config_home=tmp_path / "config",
        updater_data_home=tmp_path / "data",
    )
    text = env_path.read_text(encoding="utf-8")

    assert status == 0
    assert f"{UPDATER_TRAY_ENABLED_ENV}=1" in text
    assert f"{UPDATER_AUTOSTART_ENV}=1" in text
    assert f"{UPDATER_TERMINAL_ENV}=auto" in text
    assert (tmp_path / "config" / "autostart" / "aurascan-updater.desktop").exists()
    assert (tmp_path / "data" / "applications" / "aurascan-updater.desktop").exists()
    assert "Configured AuraScan Updater tray defaults." in stdout.getvalue()
    assert "Installed AuraScan Updater autostart" in stdout.getvalue()


def test_init_can_remove_updater_autostart(tmp_path):
    env_path = tmp_path / ".config" / "aurascan" / ".env"
    config_home = tmp_path / "config"
    autostart = config_home / "autostart" / "aurascan-updater.desktop"
    autostart.parent.mkdir(parents=True)
    autostart.write_text("fixture", encoding="utf-8")

    status = run_init(
        ["--disable-ai", "--remove-updater-autostart", "--no-install-hook"],
        stdout=io.StringIO(),
        env_path=env_path,
        updater_config_home=config_home,
        updater_data_home=tmp_path / "data",
    )

    assert status == 0
    assert not autostart.exists()
    assert f"{UPDATER_AUTOSTART_ENV}=0" in env_path.read_text(encoding="utf-8")


def test_init_can_enable_incident_monitor_and_ai(tmp_path):
    env_path = tmp_path / ".config" / "aurascan" / ".env"
    calls = []

    def runner(command, **_kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    status = run_init(
        [
            "--disable-ai",
            "--enable-incident-monitor",
            "--enable-incident-ai",
            "--incident-ai-evidence",
            "redacted",
            "--no-install-hook",
        ],
        stdout=io.StringIO(),
        env_path=env_path,
        runner=runner,
    )

    text = env_path.read_text(encoding="utf-8")
    assert status == 0
    assert f"{INCIDENT_MONITOR_ENABLED_ENV}=1" in text
    assert f"{INCIDENT_AI_ENABLED_ENV}=1" in text
    assert f"{INCIDENT_AI_EVIDENCE_ENV}=redacted" in text
    assert ["sudo", "systemctl", "enable", "--now", INCIDENT_MONITOR_SERVICE, INCIDENT_MAINTENANCE_TIMER] in calls
    assert ["sudo", "systemctl", "start", INCIDENT_MAINTENANCE_SERVICE] in calls


def test_init_explicitly_enables_background_ai_and_safe_autopilot(monkeypatch, tmp_path):
    env_path = tmp_path / ".env"
    calls = []
    policy = []
    monkeypatch.setattr(setup_wizard, "read_auto_repair_policy", lambda: type("Policy", (), {"policy": "off", "error": ""})())
    monkeypatch.setattr(
        setup_wizard,
        "configure_auto_repair_policy",
        lambda value, runner=None: policy.append(value) or (True, f"policy {value}"),
    )

    status = run_init(
        [
            "--disable-ai",
            "--enable-incident-background-ai",
            "--incident-auto-repair",
            "safe",
            "--no-install-hook",
        ],
        stdout=io.StringIO(),
        env_path=env_path,
        runner=lambda command, **_kwargs: calls.append(command) or subprocess.CompletedProcess(command, 0, "", ""),
    )

    assert status == 0
    assert f"{INCIDENT_BACKGROUND_AI_ENV}=1" in env_path.read_text(encoding="utf-8")
    assert ["systemctl", "--user", "enable", "--now", INCIDENT_BACKGROUND_TIMER] in calls
    assert ["systemctl", "--user", "start", "--no-block", INCIDENT_BACKGROUND_SERVICE] in calls
    assert policy == ["safe"]


def test_init_restores_monitor_config_when_systemd_enable_fails(tmp_path):
    env_path = tmp_path / ".env"

    status = run_init(
        ["--disable-ai", "--enable-incident-monitor", "--no-install-hook"],
        stdout=io.StringIO(),
        stderr=io.StringIO(),
        env_path=env_path,
        runner=lambda command, **_kwargs: subprocess.CompletedProcess(command, 1, "", "failure"),
    )

    assert status == 1
    assert f"{INCIDENT_MONITOR_ENABLED_ENV}=0" in env_path.read_text(encoding="utf-8")


def test_init_restores_safe_policy_when_monitor_enable_fails(monkeypatch, tmp_path):
    env_path = tmp_path / ".env"
    policies = []
    monkeypatch.setattr(setup_wizard, "read_auto_repair_policy", lambda: type("Policy", (), {"policy": "off", "error": ""})())
    monkeypatch.setattr(
        setup_wizard,
        "configure_auto_repair_policy",
        lambda value, runner=None: policies.append(value) or (True, f"policy {value}"),
    )

    status = run_init(
        [
            "--disable-ai",
            "--enable-incident-monitor",
            "--incident-auto-repair",
            "safe",
            "--no-install-hook",
        ],
        stdout=io.StringIO(),
        stderr=io.StringIO(),
        env_path=env_path,
        runner=lambda command, **_kwargs: subprocess.CompletedProcess(command, 1, "", "failure"),
    )

    assert status == 1
    assert policies == ["safe", "off"]


def test_doctor_json_reports_missing_key_without_leaking_values(tmp_path):
    env_path = tmp_path / ".config" / "aurascan" / ".env"
    env_path.parent.mkdir(parents=True)
    env_path.write_text(
        "AURASCAN_AI_ENABLED=1\nAURASCAN_AI_PROVIDER=openai\nAURASCAN_OPENAI_API_KEY=\n",
        encoding="utf-8",
    )
    env_path.chmod(0o600)
    stdout = io.StringIO()

    status = run_doctor(
        ["--json"],
        stdout=stdout,
        env_path=env_path,
        env={},
        executable_path=tmp_path / "usr" / "bin" / "aurascan",
        local_hook_path=tmp_path / "etc" / "pacman.d" / "hooks" / "aurascan.hook",
        packaged_hook_path=tmp_path / "usr" / "share" / "libalpm" / "hooks" / "aurascan.hook",
    )
    data = json.loads(stdout.getvalue())

    assert status == 1
    assert data["ok"] is False
    assert "fixture-only-value" not in stdout.getvalue()
    assert any(check["name"] == "ai_key" and check["status"] == "error" for check in data["checks"])


def test_doctor_reports_missing_config_as_warning(tmp_path):
    checks = build_doctor_checks(
        env_path=tmp_path / "missing.env",
        env={},
        executable_path=tmp_path / "usr" / "bin" / "aurascan",
        local_hook_path=tmp_path / "local.hook",
        packaged_hook_path=tmp_path / "packaged.hook",
    )

    by_name = {check.name: check for check in checks}
    assert by_name["config_file"].status == "warn"
    assert by_name["ai_enabled"].status == "warn"
    assert by_name["upgrade_preflight"].status == "ok"
    assert by_name["config_drift"].status == "ok"


def test_doctor_reports_distro_tools_and_desktop_session(tmp_path):
    os_release = tmp_path / "os-release"
    os_release.write_text('ID=manjaro\nID_LIKE=arch\nNAME="Manjaro Linux"\n', encoding="utf-8")

    checks = build_doctor_checks(
        env_path=tmp_path / "missing.env",
        env={"XDG_SESSION_TYPE": "wayland", "XDG_CURRENT_DESKTOP": "GNOME"},
        executable_path=tmp_path / "usr" / "bin" / "aurascan",
        local_hook_path=tmp_path / "local.hook",
        packaged_hook_path=tmp_path / "packaged.hook",
        os_release_path=os_release,
        which=lambda name: f"/usr/bin/{name}" if name in {"pacman", "yay", "konsole"} else None,
    )

    by_name = {check.name: check for check in checks}
    assert by_name["distro_compatibility"].status == "ok"
    assert by_name["distro_compatibility"].details["id"] == "manjaro"
    assert by_name["distro_compatibility"].details["support_tier"] == "supported_with_caveats"
    assert by_name["package_manager_capabilities"].details["tools"]["pacman"] == "/usr/bin/pacman"
    assert "yay" in by_name["package_manager_capabilities"].details["found"]
    assert by_name["desktop_session"].status == "warn"
    assert by_name["desktop_session"].details["primary_desktop"] == "gnome"
    assert by_name["desktop_session"].details["tray_support"] == "extension_required"


def test_doctor_reports_upgrade_preflight_config(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text(
        "AURASCAN_UPGRADE_PREFLIGHT_ENABLED=0\nAURASCAN_UPGRADE_AUR_HELPER=yay\n",
        encoding="utf-8",
    )
    env_path.chmod(0o600)

    checks = build_doctor_checks(
        env_path=env_path,
        env={},
        executable_path=tmp_path / "usr" / "bin" / "aurascan",
        local_hook_path=tmp_path / "local.hook",
        packaged_hook_path=tmp_path / "packaged.hook",
    )

    by_name = {check.name: check for check in checks}
    assert by_name["upgrade_preflight"].status == "warn"
    assert "disabled" in by_name["upgrade_preflight"].message


def test_doctor_reports_kernel_module_autopilot(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text(
        f"AURASCAN_UPGRADE_PREFLIGHT_ENABLED=1\n{KERNEL_MODULE_AUTOPILOT_ENV}=1\n",
        encoding="utf-8",
    )
    env_path.chmod(0o600)

    def fake_runner(cmd, **_kwargs):
        if cmd == ["pacman", "-Qq"]:
            return subprocess.CompletedProcess(cmd, 0, "linux-cachyos\nlinux-cachyos-nvidia-open\nnvidia-utils\n", "")
        return subprocess.CompletedProcess(cmd, 0, "", "")

    checks = build_doctor_checks(
        env_path=env_path,
        env={},
        executable_path=tmp_path / "usr" / "bin" / "aurascan",
        local_hook_path=tmp_path / "local.hook",
        packaged_hook_path=tmp_path / "packaged.hook",
        which=lambda name: f"/usr/bin/{name}" if name in {"pacman", "konsole"} else None,
        runner=fake_runner,
    )

    by_name = {check.name: check for check in checks}
    assert by_name["kernel_module_autopilot"].status == "ok"
    assert by_name["kernel_module_autopilot"].details["module_families"] == ["nvidia"]


def test_doctor_reports_config_drift_config(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text(
        "AURASCAN_CONFIG_DRIFT_ENABLED=0\nAURASCAN_CONFIG_DRIFT_AI_DIFFS=never\n",
        encoding="utf-8",
    )
    env_path.chmod(0o600)

    checks = build_doctor_checks(
        env_path=env_path,
        env={},
        executable_path=tmp_path / "usr" / "bin" / "aurascan",
        local_hook_path=tmp_path / "local.hook",
        packaged_hook_path=tmp_path / "packaged.hook",
    )

    by_name = {check.name: check for check in checks}
    assert by_name["config_drift"].status == "warn"
    assert "disabled" in by_name["config_drift"].message


def test_doctor_reports_updater_status(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text(
        f"{UPDATER_TRAY_ENABLED_ENV}=1\n{UPDATER_AUTOSTART_ENV}=1\n{UPDATER_TERMINAL_ENV}=konsole\n",
        encoding="utf-8",
    )
    env_path.chmod(0o600)
    config_home = tmp_path / "config"
    data_home = tmp_path / "data"
    autostart = config_home / "autostart" / "aurascan-updater.desktop"
    autostart.parent.mkdir(parents=True)
    autostart.write_text("fixture", encoding="utf-8")

    checks = build_doctor_checks(
        env_path=env_path,
        env={},
        executable_path=tmp_path / "usr" / "bin" / "aurascan",
        local_hook_path=tmp_path / "local.hook",
        packaged_hook_path=tmp_path / "packaged.hook",
        updater_config_home=config_home,
        updater_data_home=data_home,
        which=lambda name: "/usr/bin/konsole" if name == "konsole" else None,
        qt_binding_finder=lambda: "PyQt6",
    )

    by_name = {check.name: check for check in checks}
    assert by_name["updater_tray"].status == "ok"
    assert by_name["updater_qt_binding"].status == "ok"
    assert by_name["updater_terminal"].status == "ok"
    assert by_name["updater_autostart"].status == "ok"


def test_doctor_reports_incident_monitor_sources_and_tray_readiness(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text(
        f"{INCIDENT_MONITOR_ENABLED_ENV}=1\n"
        f"{INCIDENT_AI_ENABLED_ENV}=1\n"
        f"{INCIDENT_AI_EVIDENCE_ENV}=redacted\n"
        f"{UPDATER_TRAY_ENABLED_ENV}=0\n",
        encoding="utf-8",
    )
    env_path.chmod(0o600)
    service = tmp_path / "systemd" / INCIDENT_MONITOR_SERVICE
    service.parent.mkdir(parents=True)
    service.write_text("[Service]\n", encoding="utf-8")
    maintenance_service = service.parent / INCIDENT_MAINTENANCE_SERVICE
    maintenance_timer = service.parent / INCIDENT_MAINTENANCE_TIMER
    maintenance_service.write_text("[Service]\n", encoding="utf-8")
    maintenance_timer.write_text("[Timer]\n", encoding="utf-8")
    journal = tmp_path / "journal"
    journal.mkdir()
    pstore = tmp_path / "pstore"
    pstore.mkdir()
    state = tmp_path / "state"
    state.mkdir()
    (state / "maintenance").mkdir()
    (state / "maintenance" / "status.json").write_text(
        json.dumps({"collection_status": "complete", "last_success_usec": 9_999_999_999_999_999}),
        encoding="utf-8",
    )

    def runner(command, **_kwargs):
        if command[:2] == ["systemctl", "is-enabled"]:
            return subprocess.CompletedProcess(command, 0, "enabled\n", "")
        if command[:2] == ["systemctl", "is-active"]:
            return subprocess.CompletedProcess(command, 3, "inactive\n", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    checks = build_doctor_checks(
        env_path=env_path,
        env={},
        executable_path=tmp_path / "usr" / "bin" / "aurascan",
        local_hook_path=tmp_path / "local.hook",
        packaged_hook_path=tmp_path / "packaged.hook",
        incident_service_path=service,
        incident_maintenance_service_path=maintenance_service,
        incident_maintenance_timer_path=maintenance_timer,
        incident_system_root=state,
        journal_root=journal,
        pstore_root=pstore,
        which=lambda name: f"/usr/bin/{name}" if name in {"journalctl", "coredumpctl", "systemctl", "pacman"} else None,
        runner=runner,
    )

    by_name = {check.name: check for check in checks}
    assert by_name["incident_assistant"].status == "ok"
    assert by_name["incident_monitor"].status == "ok"
    assert by_name["incident_maintenance_timer"].status == "ok"
    assert by_name["incident_maintenance_health"].status == "ok"
    assert by_name["incident_journal"].status == "ok"
    assert by_name["incident_journal"].details["readable"] is True
    assert by_name["incident_coredumps"].status == "ok"
    assert by_name["incident_coredumps"].details["readable"] is True
    assert by_name["incident_storage"].status == "ok"
    assert by_name["incident_tray_notification"].status == "warn"


def test_doctor_reports_background_ai_and_safe_autopilot_readiness(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text(
        "AURASCAN_AI_ENABLED=1\n"
        "AURASCAN_AI_PROVIDER=openai\n"
        "AURASCAN_OPENAI_API_KEY=fixture-secret\n"
        f"{INCIDENT_AI_ENABLED_ENV}=1\n"
        f"{INCIDENT_BACKGROUND_AI_ENV}=1\n",
        encoding="utf-8",
    )
    env_path.chmod(0o600)
    user_units = tmp_path / "user-units"
    user_units.mkdir()
    (user_units / INCIDENT_BACKGROUND_SERVICE).write_text("[Service]\n", encoding="utf-8")
    (user_units / INCIDENT_BACKGROUND_TIMER).write_text("[Timer]\n", encoding="utf-8")
    safe_service = tmp_path / INCIDENT_SAFE_AUTOPILOT_SERVICE
    safe_service.write_text("[Service]\n", encoding="utf-8")
    policy = tmp_path / "incident-autopilot.conf"
    policy.write_text(f"{INCIDENT_AUTO_REPAIR_ENV}=safe\n", encoding="utf-8")
    policy.chmod(0o644)
    user_root = tmp_path / "user-state"
    state_path = background_state_path(user_root)
    state_path.parent.mkdir(parents=True)
    state_path.write_text(json.dumps({"last_status": "ok", "last_success_usec": 42}), encoding="utf-8")
    background_result_path(user_root).write_text(json.dumps({
        "prepared_repair_count": 2,
        "analysis_fingerprint": "analysis",
        "repair_plan_fingerprint": "plan",
        "planner_status": "ok",
        "provider_requests": 2,
        "completed_probe_count": 3,
    }), encoding="utf-8")
    system_root = tmp_path / "system-state"
    _safe_state, safe_status, _safe_lock = safe_automation_paths(system_root)
    safe_status.parent.mkdir(parents=True)
    safe_status.write_text(json.dumps({"state": "applied", "last_success_usec": 43, "action_count": 1}), encoding="utf-8")

    def runner(command, **_kwargs):
        if command[:3] == ["systemctl", "--user", "is-enabled"]:
            return subprocess.CompletedProcess(command, 0, "enabled\n", "")
        if command[:3] == ["systemctl", "--user", "is-active"]:
            state = "active\n" if command[-1] == INCIDENT_BACKGROUND_TIMER else "inactive\n"
            return subprocess.CompletedProcess(command, 0, state, "")
        return subprocess.CompletedProcess(command, 0, "", "")

    checks = build_doctor_checks(
        env_path=env_path,
        env={},
        executable_path=tmp_path / "aurascan",
        local_hook_path=tmp_path / "local.hook",
        packaged_hook_path=tmp_path / "packaged.hook",
        incident_system_root=system_root,
        incident_background_unit_root=user_units,
        incident_safe_service_path=safe_service,
        incident_auto_repair_policy_path=policy,
        incident_auto_repair_policy_uid=policy.stat().st_uid,
        incident_user_root=user_root,
        runner=runner,
    )

    by_name = {check.name: check for check in checks}
    assert by_name["incident_background_ai"].status == "ok"
    assert by_name["incident_background_ai"].details["last_status"] == "ok"
    assert by_name["incident_background_ai"].details["last_prepared_repair_count"] == 2
    assert by_name["incident_background_ai"].details["last_provider_requests"] == 2
    assert by_name["incident_background_ai"].details["last_completed_probe_count"] == 3
    assert by_name["incident_ai_repair_planner"].details["maximum_provider_requests"] == 2
    assert by_name["incident_safe_autopilot"].status == "ok"
    assert by_name["incident_safe_autopilot"].details["policy"] == "safe"
    assert by_name["incident_safe_autopilot"].details["last_action_count"] == 1


def test_doctor_accepts_packaged_hook_without_local_override(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text("AURASCAN_AI_ENABLED=0\n", encoding="utf-8")
    env_path.chmod(0o600)
    packaged_hook = tmp_path / "usr" / "share" / "libalpm" / "hooks" / "aurascan.hook"
    packaged_hook.parent.mkdir(parents=True)
    packaged_hook.write_text("Exec = /usr/bin/aurascan\nNeedsTargets\n", encoding="utf-8")

    checks = build_doctor_checks(
        env_path=env_path,
        env={},
        executable_path=tmp_path / "usr" / "bin" / "aurascan",
        local_hook_path=tmp_path / "etc" / "pacman.d" / "hooks" / "aurascan.hook",
        packaged_hook_path=packaged_hook,
    )

    by_name = {check.name: check for check in checks}
    assert by_name["local_pacman_hook"].status == "ok"
    assert by_name["packaged_pacman_hook"].status == "ok"


def test_doctor_accepts_local_hook_without_packaged_hook(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text("AURASCAN_AI_ENABLED=0\n", encoding="utf-8")
    env_path.chmod(0o600)
    local_hook = tmp_path / "etc" / "pacman.d" / "hooks" / "aurascan.hook"
    local_hook.parent.mkdir(parents=True)
    local_hook.write_text("Exec = /usr/bin/aurascan\nNeedsTargets\n", encoding="utf-8")

    checks = build_doctor_checks(
        env_path=env_path,
        env={},
        executable_path=tmp_path / "usr" / "bin" / "aurascan",
        local_hook_path=local_hook,
        packaged_hook_path=tmp_path / "usr" / "share" / "libalpm" / "hooks" / "aurascan.hook",
    )

    by_name = {check.name: check for check in checks}
    assert by_name["local_pacman_hook"].status == "ok"
    assert by_name["packaged_pacman_hook"].status == "ok"


def test_doctor_reports_bad_permissions_and_unsupported_provider(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text(
        "AURASCAN_AI_ENABLED=1\nAURASCAN_AI_PROVIDER=unknown-provider\n",
        encoding="utf-8",
    )
    env_path.chmod(0o644)

    checks = build_doctor_checks(
        env_path=env_path,
        env={},
        executable_path=tmp_path / "usr" / "bin" / "aurascan",
        local_hook_path=tmp_path / "local.hook",
        packaged_hook_path=tmp_path / "packaged.hook",
    )

    by_name = {check.name: check for check in checks}
    assert by_name["config_permissions"].status == "warn"
    assert by_name["ai_provider"].status == "error"


def test_doctor_check_ai_uses_mocked_provider(tmp_path):
    env_path = tmp_path / ".config" / "aurascan" / ".env"
    env_path.parent.mkdir(parents=True)
    env_path.write_text(
        "AURASCAN_AI_ENABLED=1\n"
        "AURASCAN_AI_PROVIDER=openai\n"
        "AURASCAN_OPENAI_API_KEY=fixture-only-value\n",
        encoding="utf-8",
    )
    env_path.chmod(0o600)
    stdout = io.StringIO()
    seen = {}

    def fake_urlopen(req, timeout):
        seen["url"] = req.full_url
        return FakeResponse()

    status = run_doctor(
        ["--json", "--check-ai"],
        stdout=stdout,
        env_path=env_path,
        env={},
        urlopen=fake_urlopen,
        executable_path=tmp_path / "usr" / "bin" / "aurascan",
        local_hook_path=tmp_path / "etc" / "pacman.d" / "hooks" / "aurascan.hook",
        packaged_hook_path=tmp_path / "usr" / "share" / "libalpm" / "hooks" / "aurascan.hook",
    )
    data = json.loads(stdout.getvalue())

    assert status == 0
    assert seen["url"] == "https://api.openai.com/v1/chat/completions"
    assert any(check["name"] == "ai_connectivity" and check["status"] == "ok" for check in data["checks"])
    assert "fixture-only-value" not in stdout.getvalue()


def test_hook_install_refuses_missing_installed_executable(tmp_path):
    template = tmp_path / "aurascan.hook"
    template.write_text("Exec = /usr/bin/aurascan\nNeedsTargets\n", encoding="utf-8")

    result = install_pacman_hook(
        template_path=template,
        executable_path=tmp_path / "missing-aurascan",
        hook_path=tmp_path / "hook",
        runner=lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0),
    )

    assert result.ok is False
    assert "does not exist" in result.message


def test_installed_wizard_resolves_hook_template_to_packaged_hook(tmp_path):
    module_path = tmp_path / "site-packages" / "aurascan" / "setup_wizard.py"
    module_path.parent.mkdir(parents=True)
    module_path.write_text("# fixture\n", encoding="utf-8")
    packaged_hook = tmp_path / "usr" / "share" / "libalpm" / "hooks" / "aurascan.hook"

    assert resolve_hook_template_path(module_path, packaged_hook) == packaged_hook

    source_hook = module_path.resolve().parents[1] / "packaging" / "arch" / "aurascan.hook"
    source_hook.parent.mkdir(parents=True)
    source_hook.write_text("Exec = /usr/bin/aurascan\nNeedsTargets\n", encoding="utf-8")

    assert resolve_hook_template_path(module_path, packaged_hook) == source_hook


def test_init_recognizes_active_packaged_hook_without_prompting_for_local_override(tmp_path):
    env_path = tmp_path / ".env"
    packaged_hook = tmp_path / "usr" / "share" / "libalpm" / "hooks" / "aurascan.hook"
    packaged_hook.parent.mkdir(parents=True)
    packaged_hook.write_text("Exec = /usr/bin/aurascan\nNeedsTargets\n", encoding="utf-8")
    stdout = io.StringIO()
    calls = []

    status = run_init(
        ["--disable-ai"],
        input_func=lambda prompt: (_ for _ in ()).throw(AssertionError(f"unexpected prompt: {prompt}")),
        stdout=stdout,
        env_path=env_path,
        hook_path=tmp_path / "etc" / "pacman.d" / "hooks" / "aurascan.hook",
        template_path=tmp_path / "missing-template.hook",
        packaged_hook_path=packaged_hook,
        runner=lambda command, **_kwargs: calls.append(command),
    )

    assert status == 0
    assert calls == []
    assert f"already active at {packaged_hook}" in stdout.getvalue()
    assert "no local override is needed" in stdout.getvalue()


def test_hook_install_uses_sudo_install_for_release_safe_template(tmp_path):
    template = tmp_path / "aurascan.hook"
    executable = tmp_path / "aurascan"
    hook = tmp_path / "etc" / "pacman.d" / "hooks" / "aurascan.hook"
    template.write_text("Exec = /usr/bin/aurascan\nNeedsTargets\n", encoding="utf-8")
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    calls = []

    def runner(cmd, check):
        calls.append((cmd, check))
        return subprocess.CompletedProcess(cmd, 0)

    result = install_pacman_hook(
        template_path=template,
        executable_path=executable,
        hook_path=hook,
        runner=runner,
    )

    assert result.ok is True
    assert calls == [(["sudo", "install", "-Dm644", str(template), str(hook)], False)]


def test_hook_template_safety_rejects_development_paths(tmp_path):
    template = tmp_path / "aurascan.hook"
    template.write_text("Exec = /home/developer/project/.venv/bin/python -m aurascan --deep-static\n", encoding="utf-8")

    assert is_release_safe_hook_template(template) is False
