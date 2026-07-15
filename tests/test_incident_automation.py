import io
import json
import os
import subprocess
from pathlib import Path

import aurascan.core.incident_automation as automation
import aurascan.core.incident_repairs as repairs
from aurascan.core.incident_automation import (
    AutoRepairPolicy,
    background_result_path,
    background_state_path,
    read_auto_repair_policy,
    run_background_assistant,
    run_safe_autopilot,
    safe_automation_paths,
    set_background_ai_enabled,
    write_auto_repair_policy,
)
from aurascan.core.incident_repairs import is_background_safe_action, make_action, safe_background_repository_file
from aurascan.core.incidents import (
    INCIDENT_AI_ENABLED_ENV,
    INCIDENT_AI_EVIDENCE_ENV,
    INCIDENT_BACKGROUND_AI_ENV,
    IncidentEvidence,
    IncidentFinding,
    IncidentReport,
    RepairResult,
    load_incident_report,
    pending_markers,
    persist_system_incident_report,
    run_incidents,
    write_pending_markers,
)
from aurascan.core.models import Confidence, Severity


class Completed:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def report_with_finding(*, incident_id="incident-automation", trigger="weekly_maintenance", status="complete", severity=Severity.MEDIUM):
    return IncidentReport(
        incident_id=incident_id,
        target_boot="0",
        trigger=trigger,
        boot_id="a" * 32,
        collection_status=status,
        truncated=status != "complete",
        evidence=[IncidentEvidence("iev-one", "journal", "repository failed", severity=severity)],
        findings=[IncidentFinding(
            "INC-REPOSITORY",
            severity,
            Confidence.CONFIRMED,
            "Repository issue",
            "A repository include has no active server.",
            "Updates cannot be downloaded.",
            "AuraScan can use a verified backup.",
            "repository",
            ["iev-one"],
        )],
    )


def enabled_ai_env(**updates):
    env = {
        "AURASCAN_AI_ENABLED": "1",
        "AURASCAN_AI_PROVIDER": "openai",
        "AURASCAN_OPENAI_API_KEY": "fixture-secret",
        INCIDENT_AI_ENABLED_ENV: "1",
        INCIDENT_AI_EVIDENCE_ENV: "redacted",
        INCIDENT_BACKGROUND_AI_ENV: "1",
    }
    env.update(updates)
    return env


def write_user_marker(system_root: Path, *, uid=None):
    uid = os.getuid() if uid is None else uid
    root = system_root / "pending"
    root.mkdir(parents=True, exist_ok=True)
    marker = {
        "schema": "incident_marker/2.0",
        "marker_type": "maintenance",
        "scan_id": "scan-one",
        "boot_id": "a" * 32,
        "uid_scope": str(uid),
        "severity": "MEDIUM",
        "categories": ["application_crash"],
        "category_severities": {"application_crash": "MEDIUM"},
        "resolved_categories": [],
        "auto_repair_state": "not_run",
        "count": 3,
        "repeated": True,
    }
    (root / f"scan-one-{uid}.json").write_text(json.dumps(marker), encoding="utf-8")


def test_auto_repair_policy_defaults_off_and_rejects_unsafe_file(tmp_path):
    policy_path = tmp_path / "incident-autopilot.conf"

    assert read_auto_repair_policy(policy_path, required_uid=os.getuid()).policy == "off"
    ok, _message = write_auto_repair_policy("safe", policy_path, require_root=False)
    assert ok is True
    assert policy_path.stat().st_mode & 0o777 == 0o644
    assert read_auto_repair_policy(policy_path, required_uid=os.getuid()).policy == "safe"

    policy_path.chmod(0o666)
    assert read_auto_repair_policy(policy_path, required_uid=os.getuid()).error
    assert write_auto_repair_policy("anything", policy_path, require_root=False)[0] is False


def test_auto_repair_policy_write_requires_root(monkeypatch, tmp_path):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)

    ok, message = write_auto_repair_policy("safe", tmp_path / "policy.conf")

    assert ok is False
    assert "root privileges" in message


def test_background_cli_can_repair_an_invalid_existing_toggle(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text(f"{INCIDENT_BACKGROUND_AI_ENV}=sometimes\n", encoding="utf-8")
    calls = []

    status = run_incidents(
        ["--enable-background-ai"],
        env_path=env_path,
        env={},
        runner=lambda command, **_kwargs: calls.append(command) or Completed(),
        stdout=io.StringIO(),
    )

    assert status == 0
    assert f"{INCIDENT_BACKGROUND_AI_ENV}=1" in env_path.read_text(encoding="utf-8")
    assert ["systemctl", "--user", "enable", "--now", automation.INCIDENT_BACKGROUND_TIMER] in calls


def test_auto_repair_cli_delegates_only_to_root_validated_policy_writer(monkeypatch):
    calls = []
    monkeypatch.setattr(
        automation,
        "configure_auto_repair_policy",
        lambda value, runner=None: calls.append(value) or (True, "configured"),
    )

    status = run_incidents(["--auto-repair", "safe"], env={}, stdout=io.StringIO())

    assert status == 0
    assert calls == ["safe"]


def test_background_ai_disabled_never_collects_or_calls_ai(monkeypatch, tmp_path):
    monkeypatch.setattr(
        automation,
        "build_incident_report",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("disabled assistant collected evidence")),
    )

    status = run_background_assistant(
        env={INCIDENT_BACKGROUND_AI_ENV: "0"},
        system_root=tmp_path / "system",
        user_root=tmp_path / "user",
    )

    assert status == 0
    state = json.loads(background_state_path(tmp_path / "user").read_text(encoding="utf-8"))
    assert state["last_status"] == "disabled"


def test_background_ai_processes_one_marker_once_without_repair_authority(monkeypatch, tmp_path):
    system_root = tmp_path / "system"
    user_root = tmp_path / "user"
    write_user_marker(system_root)
    calls = []

    def build_report(*_args, **_kwargs):
        calls.append("collect")
        return report_with_finding(trigger="background_ai")

    def apply_ai(report, **kwargs):
        calls.append(("ai", kwargs["facts_only"]))
        report.ai_review = {
            "enabled": True,
            "provider": "openai",
            "status": "ok",
            "summary": "A bounded background explanation.",
            "likely_causes": [],
            "recommended_action_ids": [],
        }

    monkeypatch.setattr(automation, "build_incident_report", build_report)
    monkeypatch.setattr(automation, "apply_ai_incident_review", apply_ai)
    monkeypatch.setattr(repairs, "plan_repair_actions", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        repairs,
        "apply_repair_plan",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("background AI executed repairs")),
    )

    first = run_background_assistant(
        env=enabled_ai_env(**{INCIDENT_AI_EVIDENCE_ENV: "facts-only"}),
        system_root=system_root,
        user_root=user_root,
        now_usec=1_000_000,
    )
    second = run_background_assistant(
        env=enabled_ai_env(**{INCIDENT_AI_EVIDENCE_ENV: "facts-only"}),
        system_root=system_root,
        user_root=user_root,
        now_usec=2_000_000,
    )

    assert first == second == 0
    assert calls == ["collect", ("ai", True)]
    result = json.loads(background_result_path(user_root).read_text(encoding="utf-8"))
    assert result["summary"] == "A bounded background explanation."
    assert result["safe_repair_state"] == "not_run"
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in (background_result_path(user_root), background_state_path(user_root)))


def test_background_ai_timeout_obeys_retry_window(monkeypatch, tmp_path):
    system_root = tmp_path / "system"
    user_root = tmp_path / "user"
    write_user_marker(system_root)
    attempts = []
    monkeypatch.setattr(automation, "build_incident_report", lambda *_args, **_kwargs: attempts.append(True) or report_with_finding(trigger="background_ai"))
    monkeypatch.setattr(repairs, "plan_repair_actions", lambda *_args, **_kwargs: [])

    def fail_ai(report, **_kwargs):
        report.ai_review = {"enabled": True, "status": "timeout", "error": "The read operation timed out"}

    monkeypatch.setattr(automation, "apply_ai_incident_review", fail_ai)

    run_background_assistant(env=enabled_ai_env(), system_root=system_root, user_root=user_root, now_usec=1_000_000)
    run_background_assistant(env=enabled_ai_env(), system_root=system_root, user_root=user_root, now_usec=2_000_000)

    assert len(attempts) == 1
    state = json.loads(background_state_path(user_root).read_text(encoding="utf-8"))
    marker_state = next(iter(state["markers"].values()))
    assert marker_state["status"] == "retry"
    assert marker_state["next_retry_usec"] == 1_000_000 + 15 * 60 * 1_000_000


def test_background_ai_ignores_another_users_marker(monkeypatch, tmp_path):
    system_root = tmp_path / "system"
    write_user_marker(system_root, uid=os.getuid() + 100)
    monkeypatch.setattr(
        automation,
        "build_incident_report",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("cross-UID evidence was collected")),
    )

    assert run_background_assistant(
        env=enabled_ai_env(),
        system_root=system_root,
        user_root=tmp_path / "user",
    ) == 0


def test_background_timer_enable_writes_config_only_after_systemd_success(tmp_path):
    env_path = tmp_path / ".env"

    ok, _message = set_background_ai_enabled(
        True,
        env_path=env_path,
        runner=lambda command, **_kwargs: Completed(returncode=1),
    )

    assert ok is False
    assert not env_path.exists()

    calls = []
    ok, _message = set_background_ai_enabled(
        True,
        env_path=env_path,
        runner=lambda command, **_kwargs: calls.append(command) or Completed(),
    )
    assert ok is True
    assert f"{INCIDENT_BACKGROUND_AI_ENV}=1" in env_path.read_text(encoding="utf-8")
    assert ["systemctl", "--user", "enable", "--now", automation.INCIDENT_BACKGROUND_TIMER] in calls


def test_background_timer_disable_is_idempotent_when_unit_is_already_absent(tmp_path):
    def runner(command, **_kwargs):
        if command[:4] == ["systemctl", "--user", "disable", "--now"]:
            return Completed(returncode=1)
        if command[:3] == ["systemctl", "--user", "is-enabled"]:
            return Completed("not-found\n", returncode=1)
        if command[:3] == ["systemctl", "--user", "is-active"]:
            return Completed("inactive\n", returncode=3)
        return Completed(returncode=1)

    ok, message = set_background_ai_enabled(False, env_path=tmp_path / ".env", runner=runner)

    assert ok is True
    assert "disabled" in message
    assert f"{INCIDENT_BACKGROUND_AI_ENV}=0" in (tmp_path / ".env").read_text(encoding="utf-8")


def test_safe_allowlist_rejects_every_other_recipe():
    stale = make_action(
        "stale_pacman_lock",
        "Move stale lock",
        "verified",
        Severity.LOW,
        {"lock_path": "/var/lib/pacman/db.lck", "minimum_age": 600, "category": "package_manager"},
        [["mv", "/var/lib/pacman/db.lck", "backup"]],
        reversible=True,
    )
    arbitrary = make_action(
        "restart_system_service",
        "Restart service",
        "verified",
        Severity.LOW,
        {"unit": "demo.service", "category": "failed_service"},
        [["systemctl", "restart", "demo.service"]],
        reversible=True,
    )

    assert is_background_safe_action(stale) is True
    assert is_background_safe_action(arbitrary) is False


def test_safe_repository_file_rejects_symlinks_and_outside_paths(tmp_path):
    root = tmp_path / "pacman.d"
    root.mkdir()
    mirror = root / "mirrorlist"
    mirror.write_text("Server = https://example.invalid\n", encoding="utf-8")
    link = root / "mirrorlink"
    link.symlink_to(mirror)
    outside = tmp_path / "outside"
    outside.write_text("Server = https://example.invalid\n", encoding="utf-8")

    assert safe_background_repository_file(mirror, root, required_uid=os.getuid()) is True
    assert safe_background_repository_file(link, root, required_uid=os.getuid()) is False
    assert safe_background_repository_file(outside, root, required_uid=os.getuid()) is False


def test_safe_autopilot_refuses_truncated_or_high_risk_reports(monkeypatch, tmp_path):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(automation, "read_auto_repair_policy", lambda *_args, **_kwargs: AutoRepairPolicy("safe"))
    report = report_with_finding(status="partial")
    persist_system_incident_report(report, root=tmp_path / "system" / "reports")
    write_pending_markers(report, root=tmp_path / "system" / "pending")
    monkeypatch.setattr(
        repairs,
        "plan_repair_actions",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("unsafe report reached planning")),
    )

    assert run_safe_autopilot(system_root=tmp_path / "system", now_usec=10_000_000) == 0
    stored = load_incident_report(report.incident_id, tmp_path / "system" / "reports")
    assert stored.automation["safe_autopilot"]["status"] == "refused"
    assert pending_markers(uid=os.getuid(), root=tmp_path / "system" / "pending")


def test_safe_autopilot_applies_at_most_two_and_resolves_only_verified_categories(monkeypatch, tmp_path):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(automation, "read_auto_repair_policy", lambda *_args, **_kwargs: AutoRepairPolicy("safe"))
    report = report_with_finding()
    persist_system_incident_report(report, root=tmp_path / "system" / "reports")
    write_pending_markers(report, root=tmp_path / "system" / "pending")
    actions = [
        make_action(
            "repository_restore",
            f"Restore {index}",
            "verified",
            Severity.MEDIUM,
            {"pacman_conf_path": "/etc/pacman.conf", "targets": [f"/etc/pacman.d/mirror-{index}"], "category": "repository"},
            [["install", "backup", "target"]],
            reversible=True,
        )
        for index in range(3)
    ]
    captured = []
    monkeypatch.setattr(repairs, "plan_repair_actions", lambda *_args, **_kwargs: actions)
    monkeypatch.setattr(repairs, "is_background_safe_action", lambda _action: True)

    def execute(selected, **_kwargs):
        captured.extend(selected)
        return [
            RepairResult(action.action_id, action.recipe_id, "applied", "verified", True)
            for action in selected
        ], True

    monkeypatch.setattr(repairs, "execute_background_safe_actions", execute)

    assert run_safe_autopilot(system_root=tmp_path / "system", now_usec=20_000_000) == 0
    assert len(captured) == 2
    assert pending_markers(uid=os.getuid(), root=tmp_path / "system" / "pending") == []
    _state_path, status_path, _lock_path = safe_automation_paths(tmp_path / "system")
    status = json.loads(status_path.read_text(encoding="utf-8"))
    assert status["state"] == "applied"
    assert status["action_count"] == 2
    assert status_path.stat().st_mode & 0o777 == 0o644


def test_safe_autopilot_failure_keeps_alert_active_and_records_cooldown(monkeypatch, tmp_path):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(automation, "read_auto_repair_policy", lambda *_args, **_kwargs: AutoRepairPolicy("safe"))
    report = report_with_finding()
    persist_system_incident_report(report, root=tmp_path / "system" / "reports")
    write_pending_markers(report, root=tmp_path / "system" / "pending")
    action = make_action(
        "repository_restore",
        "Restore mirrors",
        "verified",
        Severity.MEDIUM,
        {"pacman_conf_path": "/etc/pacman.conf", "targets": ["/etc/pacman.d/mirrorlist"], "category": "repository"},
        [["install", "backup", "target"]],
        reversible=True,
    )
    monkeypatch.setattr(repairs, "plan_repair_actions", lambda *_args, **_kwargs: [action])
    monkeypatch.setattr(repairs, "is_background_safe_action", lambda _action: True)
    monkeypatch.setattr(
        repairs,
        "execute_background_safe_actions",
        lambda *_args, **_kwargs: ([RepairResult(action.action_id, action.recipe_id, "failed", "rollback complete")], False),
    )

    assert run_safe_autopilot(system_root=tmp_path / "system", now_usec=30_000_000) != 0
    marker = pending_markers(uid=os.getuid(), root=tmp_path / "system" / "pending")[0]
    assert marker["auto_repair_state"] == "failed"
    state_path, _status_path, _lock_path = safe_automation_paths(tmp_path / "system")
    state = json.loads(state_path.read_text(encoding="utf-8"))
    assert state["action_cooldowns"][action.action_id] == 30_000_000

    later_report = report_with_finding(incident_id="incident-automation-later")
    persist_system_incident_report(later_report, root=tmp_path / "system" / "reports")
    write_pending_markers(later_report, root=tmp_path / "system" / "pending")
    monkeypatch.setattr(
        repairs,
        "execute_background_safe_actions",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("24-hour cooldown was bypassed")),
    )

    assert run_safe_autopilot(system_root=tmp_path / "system", now_usec=3_630_000_000) == 0
    later_stored = load_incident_report(later_report.incident_id, tmp_path / "system" / "reports")
    assert later_stored.automation["safe_autopilot"]["status"] == "no_action"
