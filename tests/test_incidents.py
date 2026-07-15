import io
import json
import os
import subprocess
import time
import urllib.error
from pathlib import Path

from aurascan.core.incidents import (
    INCIDENT_AI_ENABLED_ENV,
    INCIDENT_AI_EVIDENCE_ENV,
    INCIDENT_AI_TIMEOUT_SECONDS,
    INCIDENT_BACKGROUND_AI_ENV,
    INCIDENT_MAINTENANCE_SERVICE,
    INCIDENT_MAINTENANCE_TIMER,
    INCIDENT_MONITOR_ENABLED_ENV,
    CoredumpGroup,
    DiagnosticProbe,
    DiagnosticProbeResult,
    IncidentEvidence,
    IncidentFinding,
    IncidentReport,
    MaintenanceCheckpoint,
    RepairAction,
    RepairResult,
    analyze_journal_records,
    apply_ai_incident_review,
    build_incident_ai_prompt,
    build_incident_report,
    capture_incident_maintenance,
    collect_maintenance_coredumps,
    collect_maintenance_journal_records,
    collect_coredumps,
    collect_incident_system_facts,
    collect_pacman_history,
    collect_pstore_evidence,
    current_boot_id,
    current_user_uid,
    list_incident_reports,
    load_maintenance_checkpoint,
    load_maintenance_status,
    mark_pending_markers_seen,
    pending_markers,
    persist_incident_report,
    redact_incident_text,
    resolve_incident_config,
    run_incidents,
    set_incident_monitor_enabled,
    unseen_pending_markers,
    validate_incident_ai_response,
    write_pending_markers,
)
from aurascan.core.models import Confidence, Severity


class Completed:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


class FakeRunner:
    def __init__(self, responses=None):
        self.responses = responses or {}
        self.calls = []

    def __call__(self, command, **_kwargs):
        command = list(command)
        self.calls.append(command)
        response = self.responses.get(tuple(command))
        if callable(response):
            return response(command)
        return response or Completed()


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


def fake_which(found):
    return lambda name: f"/usr/bin/{name}" if name in found else None


def journal_record(message, *, boot="a" * 32, unit="kernel.service", timestamp="1", priority="3"):
    return {
        "MESSAGE": message,
        "_BOOT_ID": boot,
        "_SYSTEMD_UNIT": unit,
        "__REALTIME_TIMESTAMP": timestamp,
        "PRIORITY": priority,
    }


def test_current_boot_id_falls_back_to_journal_when_proc_is_hidden(tmp_path):
    boot_id = "32e34c1727574ae9bd41ffe2fdd219fb"
    command = ("/usr/bin/journalctl", "--list-boots", "--no-pager", "--output=json")
    runner = FakeRunner({
        command: Completed(json.dumps([
            {"index": -1, "boot_id": "a" * 32},
            {"index": 0, "boot_id": boot_id},
        ])),
    })

    result = current_boot_id(
        tmp_path / "hidden-proc" / "boot_id",
        runner=runner,
        which=fake_which({"journalctl"}),
    )

    assert result == boot_id
    assert runner.calls == [list(command)]


def test_current_user_uid_ignores_sudo_uid_when_not_root(monkeypatch):
    monkeypatch.setattr(os, "getuid", lambda: 1000)
    monkeypatch.setenv("SUDO_UID", "0")

    assert current_user_uid() == 1000


def minimal_report(**updates):
    values = {
        "incident_id": "incident-fixture",
        "target_boot": "-1",
        "trigger": "manual",
        "boot_id": "a" * 32,
    }
    values.update(updates)
    return IncidentReport(**values)


def test_incident_config_defaults_and_invalid_values():
    config = resolve_incident_config({})
    assert config.monitor_enabled is False
    assert config.ai_enabled is True
    assert config.ai_evidence == "redacted"
    assert config.background_ai_enabled is False

    configured = resolve_incident_config({
        INCIDENT_MONITOR_ENABLED_ENV: "1",
        INCIDENT_AI_ENABLED_ENV: "0",
        INCIDENT_AI_EVIDENCE_ENV: "facts-only",
        INCIDENT_BACKGROUND_AI_ENV: "1",
    })
    assert configured.monitor_enabled is True
    assert configured.ai_enabled is False
    assert configured.ai_evidence == "facts-only"
    assert configured.background_ai_enabled is True
    assert resolve_incident_config({INCIDENT_AI_EVIDENCE_ENV: "raw"}).error
    assert resolve_incident_config({INCIDENT_MONITOR_ENABLED_ENV: "sometimes"}).error
    assert resolve_incident_config({INCIDENT_BACKGROUND_AI_ENV: "sometimes"}).error


def test_monitor_disable_is_idempotent_when_systemd_reports_already_disabled():
    runner = FakeRunner({
        ("sudo", "systemctl", "disable", "--now", "aurascan-incident-monitor.service", INCIDENT_MAINTENANCE_TIMER): Completed(returncode=1),
        ("systemctl", "is-enabled", "aurascan-incident-monitor.service"): Completed("not-found\n", returncode=1),
        ("systemctl", "is-active", "aurascan-incident-monitor.service"): Completed("inactive\n", returncode=3),
        ("systemctl", "is-enabled", INCIDENT_MAINTENANCE_TIMER): Completed("not-found\n", returncode=1),
        ("systemctl", "is-active", INCIDENT_MAINTENANCE_TIMER): Completed("inactive\n", returncode=3),
    })

    ok, message = set_incident_monitor_enabled(False, runner=runner)

    assert ok is True
    assert "already disabled" in message


def test_journal_rules_detect_kernel_oom_gpu_storage_and_unclean_boot():
    records = [
        journal_record("Kernel panic - not syncing: fatal exception", timestamp="1"),
        journal_record("Out of memory: Killed process 99 (demo)", timestamp="2"),
        journal_record("NVRM: Xid (PCI:0000:01:00): 79, GPU has fallen off the bus", timestamp="3"),
        journal_record("nvme0: I/O error, dev nvme0n1", timestamp="4"),
    ]

    evidence, findings = analyze_journal_records(records, target_boot="-1")

    rules = {finding.rule_id for finding in findings}
    assert {"INC-KERNEL-PANIC", "INC-OOM", "INC-GPU-RESET", "INC-STORAGE-IO", "INC-BOOT-UNCLEAN"} <= rules
    assert all(item.message for item in evidence)


def test_nvidia_allocation_failure_is_not_mislabeled_as_system_oom():
    records = [journal_record(
        "NVRM: nvAssertOkFailedNoLog: Assertion failed: Out of memory "
        "[NV_ERR_NO_MEMORY] returned from mapping callback",
        timestamp="2",
    )]

    _evidence, findings = analyze_journal_records(records, target_boot="0")

    by_rule = {finding.rule_id: finding for finding in findings}
    assert "INC-OOM" not in by_rule
    assert by_rule["INC-NVIDIA-ALLOCATION"].severity == Severity.MEDIUM
    assert "does not prove" in by_rule["INC-NVIDIA-ALLOCATION"].why_it_matters


def test_clean_shutdown_marker_avoids_unclean_boot_finding():
    records = [journal_record("Reached target System Reboot", timestamp="99")]

    _evidence, findings = analyze_journal_records(records, target_boot="-1")

    assert all(finding.rule_id != "INC-BOOT-UNCLEAN" for finding in findings)


def test_coredumps_are_grouped_and_other_users_are_filtered(monkeypatch):
    monkeypatch.setattr(os, "getuid", lambda: 1000)
    command = ("coredumpctl", "--json=short", "--no-pager", "--reverse", "-n", "200", "list", "_BOOT_ID=" + "a" * 32)
    rows = [
        {"BOOT_ID": "a" * 32, "UID": "1000", "EXE": "/usr/bin/demo", "SIGNAL": "SIGSEGV", "TIME": "1"},
        {"BOOT_ID": "a" * 32, "UID": "1000", "EXE": "/usr/bin/demo", "SIGNAL": "SIGSEGV", "TIME": "2"},
        {"BOOT_ID": "a" * 32, "UID": "1001", "EXE": "/usr/bin/private-app", "SIGNAL": "SIGABRT", "TIME": "3"},
    ]
    runner = FakeRunner({command: Completed(json.dumps(rows))})

    groups, evidence, findings, errors, truncated = collect_coredumps(
        "-1",
        boot_id="a" * 32,
        runner=runner,
        which=fake_which({"coredumpctl"}),
    )

    assert errors == []
    assert truncated is False
    assert len(groups) == 1
    assert groups[0].executable == "demo"
    assert groups[0].count == 2
    assert len(evidence) == 2
    assert findings[0].rule_id == "INC-APPLICATION-COREDUMP"


def test_monitor_coredumps_with_same_signature_remain_separate_per_uid(monkeypatch):
    monkeypatch.setattr(os, "getuid", lambda: 0)
    command = ("coredumpctl", "--json=short", "--no-pager", "--reverse", "-n", "200", "list", "_BOOT_ID=" + "a" * 32)
    rows = [
        {"BOOT_ID": "a" * 32, "UID": "1000", "EXE": "/usr/bin/demo", "SIGNAL": "SIGSEGV", "TIME": "1"},
        {"BOOT_ID": "a" * 32, "UID": "1001", "EXE": "/usr/bin/demo", "SIGNAL": "SIGSEGV", "TIME": "2"},
    ]

    groups, _evidence, _findings, _errors, _truncated = collect_coredumps(
        "-1",
        boot_id="a" * 32,
        runner=FakeRunner({command: Completed("\n".join(json.dumps(row) for row in rows))}),
        which=fake_which({"coredumpctl"}),
        include_all_users=True,
    )

    assert len(groups) == 2
    assert {group.uid for group in groups} == {1000, 1001}


def test_coredumpctl_real_json_shape_is_enriched_without_command_lines(monkeypatch):
    monkeypatch.setattr(os, "getuid", lambda: 1000)
    boot = "a" * 32
    list_command = ("coredumpctl", "--json=short", "--no-pager", "--reverse", "-n", "200", "list", f"_BOOT_ID={boot}")
    detail_command = (
        "journalctl", "--boot=-1", "--output=json", "--no-pager", "--reverse", "--lines=200",
        "--output-fields=COREDUMP_EXE,COREDUMP_UID,COREDUMP_SIGNAL_NAME,COREDUMP_PACKAGE_NAME,COREDUMP_STACKTRACE,MESSAGE,_BOOT_ID,__REALTIME_TIMESTAMP",
        "MESSAGE_ID=fc2e22bc6ee647b6b90729ab34a250b1",
    )
    listing = [{"time": 123, "uid": 1000, "sig": 11, "exe": "/usr/bin/demo"}]
    detail = {
        "__REALTIME_TIMESTAMP": "123",
        "_BOOT_ID": boot,
        "COREDUMP_UID": "1000",
        "COREDUMP_EXE": "/usr/bin/demo",
        "COREDUMP_SIGNAL_NAME": "SIGSEGV",
        "COREDUMP_PACKAGE_NAME": "demo",
        "MESSAGE": "Process demo dumped core.\n#0  0x1234 crash_here (demo + 0x2)",
    }
    runner = FakeRunner({
        list_command: Completed(json.dumps(listing)),
        detail_command: Completed(json.dumps(detail)),
    })

    groups, _evidence, _findings, errors, _truncated = collect_coredumps(
        "-1",
        boot_id=boot,
        runner=runner,
        which=fake_which({"coredumpctl", "journalctl"}),
    )

    assert errors == []
    assert groups[0].package == "demo"
    assert groups[0].signal == "SIGSEGV"
    assert groups[0].top_frame.startswith("#0  <address>")
    assert all("CommandLine" not in json.dumps(call) for call in runner.calls)


def test_redaction_covers_secrets_paths_hosts_and_network_identifiers(monkeypatch):
    monkeypatch.setenv("USER", "alice")
    monkeypatch.setattr("aurascan.core.incidents.socket.gethostname", lambda: "private-host")
    text = (
        "password=hunter2 token:abcd https://bob:secret@example.test/x "
        "/home/alice/private 192.168.1.9 aa:bb:cc:dd:ee:ff private-host "
        "Authorization: Bearer bearer-secret\n"
        "-----BEGIN PRIVATE KEY-----\nprivate-key-body\n-----END PRIVATE KEY-----\n"
        "COMMAND=/usr/bin/demo --unsafe complete-command"
    )

    redacted = redact_incident_text(text)

    for secret in (
        "hunter2", "abcd", "bob:secret", "/home/alice", "192.168.1.9",
        "aa:bb:cc:dd:ee:ff", "private-host", "bearer-secret", "private-key-body",
        "complete-command",
    ):
        assert secret not in redacted
    assert "<redacted>" in redacted
    assert "<user:" in redacted
    assert "<ip:" in redacted
    assert "<mac:" in redacted
    assert "<redacted-private-key>" in redacted
    assert "<command-omitted>" in redacted


def test_ai_response_cannot_invent_evidence_actions_or_commands(monkeypatch):
    monkeypatch.setenv("AURASCAN_AI_ENABLED", "1")
    monkeypatch.setenv("AURASCAN_AI_PROVIDER", "openai")
    monkeypatch.setenv("AURASCAN_OPENAI_API_KEY", "fixture-only")
    evidence = IncidentEvidence("iev-known", "journal", "redacted message")
    action = RepairAction("ira-known", "stale_pacman_lock", "Fix lock", "summary", Severity.LOW, eligible=True, verified=True)
    report = minimal_report(evidence=[evidence], repair_actions=[action])
    ai_data = {
        "summary": "Likely interrupted transaction",
        "likely_causes": [
            {"title": "valid", "confidence": "high", "evidence_ids": ["iev-known"], "explanation": "matches"},
            {"title": "invented", "confidence": "high", "evidence_ids": ["iev-fake"], "explanation": "ignore"},
        ],
        "recommended_action_ids": ["ira-known", "ira-fake"],
        "command": "rm -rf /",
    }

    validated = validate_incident_ai_response(report, ai_data)

    assert validated["recommended_action_ids"] == ["ira-known"]
    assert [item["title"] for item in validated["likely_causes"]] == ["valid"]
    assert "command" not in validated


def test_ai_triage_rejects_fabricated_probe_ids_and_never_accepts_targets():
    evidence = IncidentEvidence("iev-known", "journal", "redacted message")
    probe = DiagnosticProbe(
        "idp-known",
        "package_integrity",
        "Inspect demo",
        "summary",
        target={"package": "trusted-local-package"},
        evidence_ids=[evidence.evidence_id],
    )
    report = minimal_report(evidence=[evidence])
    response = {
        "summary": "Check the implicated package",
        "likely_causes": [
            {"title": "cause", "confidence": "medium", "evidence_ids": ["iev-known"], "explanation": "matched"},
        ],
        "requested_probe_ids": ["idp-known", "idp-fabricated"],
        "recommended_action_ids": [],
        "target": {"package": "ai-invented-package"},
        "command": "pacman -S ai-invented-package",
    }

    validated = validate_incident_ai_response(report, response, phase="triage", probes=[probe])
    prompt = build_incident_ai_prompt(report, phase="triage", probes=[probe])

    assert validated["requested_probe_ids"] == ["idp-known"]
    assert "target" not in validated
    assert "command" not in validated
    assert '"target":' not in prompt
    assert "trusted-local-package" not in prompt


def test_final_ai_prompt_contains_only_normalized_probe_results():
    report = minimal_report(evidence=[IncidentEvidence("iev-one", "journal", "message")])
    result = DiagnosticProbeResult(
        "idp-one",
        "package_integrity",
        "no_action",
        "No missing immutable files were found.",
        evidence_ids=["iev-one"],
    )

    prompt = build_incident_ai_prompt(report, phase="final", probe_results=[result])

    assert "No missing immutable files were found." in prompt
    assert '"available_probes": []' in prompt
    assert "Do not request more probes" in prompt


def test_ai_invalid_json_is_nonblocking(monkeypatch):
    monkeypatch.setenv("AURASCAN_AI_ENABLED", "1")
    monkeypatch.setenv("AURASCAN_AI_PROVIDER", "openai")
    monkeypatch.setenv("AURASCAN_OPENAI_API_KEY", "fixture-only")
    report = minimal_report()

    apply_ai_incident_review(
        report,
        urlopen=lambda _request, timeout: FakeResponse({"choices": [{"message": {"content": "not-json"}}]}),
    )

    assert report.ai_review["status"] == "invalid_response"


def test_ai_timeout_is_classified_and_explained_without_blocking(monkeypatch):
    monkeypatch.setenv("AURASCAN_AI_ENABLED", "1")
    monkeypatch.setenv("AURASCAN_AI_PROVIDER", "deepseek")
    monkeypatch.setenv("AURASCAN_DEEPSEEK_API_KEY", "fixture-only")
    report = minimal_report()
    timeouts = []

    def timeout_response(_request, timeout):
        timeouts.append(timeout)
        raise TimeoutError("The read operation timed out")

    apply_ai_incident_review(report, urlopen=timeout_response)
    rendered = report.render_terminal()

    assert timeouts == [INCIDENT_AI_TIMEOUT_SECONDS]
    assert report.ai_review["status"] == "timeout"
    assert "AI review: timed out (deepseek)" in rendered
    assert "Deterministic diagnostics and verified repair checks still completed" in rendered
    assert "invalid_response" not in rendered


def test_ai_transport_failure_is_not_mislabeled_as_invalid_json(monkeypatch):
    monkeypatch.setenv("AURASCAN_AI_ENABLED", "1")
    monkeypatch.setenv("AURASCAN_AI_PROVIDER", "openai")
    monkeypatch.setenv("AURASCAN_OPENAI_API_KEY", "fixture-only")
    report = minimal_report()

    def unavailable(_request, timeout):
        assert timeout == INCIDENT_AI_TIMEOUT_SECONDS
        raise urllib.error.URLError("temporary network failure")

    apply_ai_incident_review(report, urlopen=unavailable)

    assert report.ai_review["status"] == "provider_error"
    assert "AI review: provider unavailable (openai)" in report.render_terminal()


def test_final_ai_failure_keeps_valid_triage_and_verified_plan(monkeypatch):
    monkeypatch.setenv("AURASCAN_AI_ENABLED", "1")
    monkeypatch.setenv("AURASCAN_AI_PROVIDER", "openai")
    monkeypatch.setenv("AURASCAN_OPENAI_API_KEY", "fixture-only")
    action = RepairAction("ira-known", "fixture", "Repair", "summary", Severity.LOW, eligible=True, verified=True)
    report = minimal_report(repair_actions=[action])
    report.ai_review = {
        "enabled": True,
        "provider": "openai",
        "status": "ok",
        "summary": "triage summary",
        "likely_causes": [],
        "recommended_action_ids": [],
        "requested_probe_ids": [],
        "triage": {
            "status": "ok",
            "summary": "triage summary",
            "likely_causes": [],
            "recommended_action_ids": [],
            "requested_probe_ids": [],
        },
    }

    apply_ai_incident_review(
        report,
        phase="final",
        urlopen=lambda _request, timeout: FakeResponse({"choices": [{"message": {"content": "not-json"}}]}),
    )

    assert report.ai_review["status"] == "triage_only"
    assert report.ai_review["summary"] == "triage summary"
    assert report.eligible_actions == [action]


def test_final_ai_timeout_keeps_valid_triage_and_explains_fallback(monkeypatch):
    monkeypatch.setenv("AURASCAN_AI_ENABLED", "1")
    monkeypatch.setenv("AURASCAN_AI_PROVIDER", "deepseek")
    monkeypatch.setenv("AURASCAN_DEEPSEEK_API_KEY", "fixture-only")
    action = RepairAction("ira-known", "fixture", "Repair", "summary", Severity.LOW, eligible=True, verified=True)
    report = minimal_report(repair_actions=[action])
    report.ai_review = {
        "enabled": True,
        "provider": "deepseek",
        "status": "ok",
        "summary": "triage summary",
        "likely_causes": [],
        "recommended_action_ids": [],
        "requested_probe_ids": [],
        "triage": {
            "status": "ok",
            "summary": "triage summary",
            "likely_causes": [],
            "recommended_action_ids": [],
            "requested_probe_ids": [],
        },
    }

    def timeout_response(_request, timeout):
        assert timeout == INCIDENT_AI_TIMEOUT_SECONDS
        raise TimeoutError("The read operation timed out")

    apply_ai_incident_review(report, phase="final", urlopen=timeout_response)
    rendered = report.render_terminal()

    assert report.ai_review["status"] == "triage_only"
    assert report.ai_review["final"]["status"] == "timeout"
    assert report.ai_review["summary"] == "triage summary"
    assert report.eligible_actions == [action]
    assert "final AI explanation timed out" in rendered


def test_ai_response_requires_strict_top_level_types():
    report = minimal_report()

    try:
        validate_incident_ai_response(report, {"summary": "x", "likely_causes": {}, "recommended_action_ids": []})
    except ValueError as exc:
        assert "likely_causes" in str(exc)
    else:
        raise AssertionError("malformed AI response should be rejected")


def test_facts_only_prompt_omits_evidence_messages():
    report = minimal_report(evidence=[IncidentEvidence("iev-one", "journal", "sensitive-ish message")])

    prompt = build_incident_ai_prompt(report, facts_only=True)

    assert "sensitive-ish message" not in prompt
    assert '"evidence": []' in prompt


def test_ai_prompt_is_redacted_and_bounded_to_total_character_limit():
    evidence = [
        IncidentEvidence(f"iev-{index}", "journal", f"password=secret-{index} " + "x" * 1800, uid=1000)
        for index in range(100)
    ]
    findings = [
        IncidentFinding("INC-OOM", Severity.HIGH, Confidence.HIGH, "OOM", "s" * 800, "w" * 800, "a" * 800, "out_of_memory")
        for _index in range(40)
    ]
    report = minimal_report(evidence=evidence, findings=findings)

    prompt = build_incident_ai_prompt(report)

    assert len(prompt) <= 12000
    assert "secret-0" not in prompt
    assert '"input_truncated": true' in prompt


def test_pacman_history_is_boot_bounded_and_omits_complete_commands(tmp_path):
    log = tmp_path / "pacman.log"
    log.write_text(
        "[1970-01-01T00:00:01+00:00] [PACMAN] Running 'pacman -S secret-package'\n"
        "[1970-01-01T00:00:01+00:00] [ALPM] transaction started\n"
        "[1970-01-01T00:00:02+00:00] [ALPM] error: failed to commit transaction\n"
        "[2026-01-01T00:00:00+00:00] [ALPM] error: unrelated old failure\n",
        encoding="utf-8",
    )
    records = [journal_record("boot start", timestamp="1000000"), journal_record("boot end", timestamp="3000000")]

    evidence, findings, errors = collect_pacman_history(records, path=log)

    assert errors == []
    assert len(evidence) == 2
    assert all("secret-package" not in item.message for item in evidence)
    assert [item.rule_id for item in findings] == ["INC-PACKAGE-INTERRUPTED"]


def test_repository_health_is_collected_as_structured_incident_fact(tmp_path):
    conf = tmp_path / "pacman.conf"
    mirrorlist = tmp_path / "mirrorlist"
    backup = tmp_path / "mirrorlist-backup"
    conf.write_text(f"[core]\nInclude = {mirrorlist}\n", encoding="utf-8")
    mirrorlist.write_text("# Server = disabled\n", encoding="utf-8")
    backup.write_text("Server = https://mirror.invalid/$repo/os/$arch\n", encoding="utf-8")

    facts, _evidence, findings, errors = collect_incident_system_facts(
        runner=FakeRunner(),
        which=fake_which(set()),
        pacman_conf_path=conf,
        etc_root=tmp_path,
        modules_root=tmp_path / "modules",
    )

    assert errors == []
    assert facts["repository_health"]["status"] == "repair_available"
    assert any(item.rule_id == "INC-REPOSITORY" for item in findings)


def test_report_persistence_permissions_history_and_marker_privacy(tmp_path):
    report = minimal_report(
        findings=[IncidentFinding("INC-OOM", Severity.HIGH, Confidence.CONFIRMED, "OOM", "summary", "why", "action", "out_of_memory")],
        coredumps=[CoredumpGroup("sig", "private-app", "private-package", "SIGSEGV", "frame", uid=1000)],
    )
    user_root = tmp_path / "user"
    marker_root = tmp_path / "markers"

    path = persist_incident_report(report, user_root)
    markers = write_pending_markers(report, root=marker_root)

    assert oct(path.stat().st_mode & 0o777) == "0o600"
    assert list_incident_reports(user_root)[0]["incident_id"] == report.incident_id
    marker_text = "\n".join(path.read_text(encoding="utf-8") for path in markers)
    assert "private-app" not in marker_text
    assert "private-package" not in marker_text
    marker_payloads = pending_markers(uid=1000, root=marker_root)
    assert {item["uid_scope"] for item in marker_payloads} == {"global", "1000"}
    expected_keys = {
        "schema",
        "marker_type",
        "scan_id",
        "boot_id",
        "uid_scope",
        "severity",
        "categories",
        "category_severities",
        "resolved_categories",
        "auto_repair_state",
        "count",
        "repeated",
        "active_categories",
    }
    assert all(set(item) == expected_keys for item in marker_payloads)


def test_pending_notification_seen_state_is_per_user(tmp_path):
    report = minimal_report(coredumps=[CoredumpGroup("sig", "demo", "", "SIGSEGV", "", uid=1000)])
    marker_root = tmp_path / "markers"
    seen_path = tmp_path / "seen.json"
    write_pending_markers(report, root=marker_root)

    unseen = unseen_pending_markers(uid=1000, marker_root=marker_root, seen_path=seen_path)
    mark_pending_markers_seen(unseen, seen_path=seen_path)

    assert unseen
    assert unseen_pending_markers(uid=1000, marker_root=marker_root, seen_path=seen_path) == []
    assert unseen_pending_markers(uid=1001, marker_root=marker_root, seen_path=tmp_path / "other.json") == []


def test_pending_markers_deduplicate_by_boot_and_treat_system_uid_as_global(tmp_path):
    marker_root = tmp_path / "markers"
    first = minimal_report(incident_id="incident-one", coredumps=[CoredumpGroup("sig", "svc", "", "SIGSEGV", "", uid=0)])
    second = minimal_report(incident_id="incident-two", coredumps=[CoredumpGroup("sig", "svc", "", "SIGSEGV", "", uid=0)])

    write_pending_markers(first, root=marker_root)
    write_pending_markers(second, root=marker_root)

    markers = pending_markers(uid=1000, root=marker_root)
    assert len(markers) == 1
    assert markers[0]["uid_scope"] == "global"
    assert len(list(marker_root.glob("*.json"))) == 1


def test_default_target_opens_unreviewed_boot_then_acknowledges_it_per_user(monkeypatch, tmp_path):
    monkeypatch.setattr(os, "getuid", lambda: 1000)
    system_root = tmp_path / "system"
    report = minimal_report(coredumps=[CoredumpGroup("sig", "demo", "", "SIGSEGV", "", uid=1000)])
    write_pending_markers(report, root=system_root / "pending")
    targets = []

    def fake_build(target, **_kwargs):
        targets.append(target)
        return report

    monkeypatch.setattr("aurascan.core.incidents.build_incident_report", fake_build)
    monkeypatch.setattr("aurascan.core.incident_repairs.plan_repair_actions", lambda *_args, **_kwargs: [])
    user_root = tmp_path / "user" / "incidents"

    first = run_incidents(["--dry-run", "--no-ai"], stdout=io.StringIO(), user_root=user_root, system_root=system_root, env={})
    second = run_incidents(["--dry-run", "--no-ai"], stdout=io.StringIO(), user_root=user_root, system_root=system_root, env={})

    assert first == second == 0
    assert targets == ["a" * 32, "0"]
    assert (user_root.parent / "incident_reviewed.json").exists()


def test_resolve_flow_acknowledges_all_pending_alerts_without_unsafe_repair(monkeypatch, tmp_path):
    monkeypatch.setattr(os, "getuid", lambda: 1000)
    system_root = tmp_path / "system"
    pending_report = minimal_report(
        incident_id="maintenance-pending",
        trigger="weekly_maintenance",
        findings=[IncidentFinding(
            "INC-NVIDIA-ALLOCATION",
            Severity.MEDIUM,
            Confidence.HIGH,
            "NVIDIA allocation",
            "summary",
            "why",
            "action",
            "gpu",
        )],
        coredumps=[CoredumpGroup("sig", "demo", "", "SIGSEGV", "", uid=1000, count=3)],
    )
    write_pending_markers(pending_report, root=system_root / "pending")
    monkeypatch.setattr("aurascan.core.incidents.build_incident_report", lambda *_args, **_kwargs: pending_report)
    monkeypatch.setattr("aurascan.core.incident_repairs.plan_repair_actions", lambda *_args, **_kwargs: [])
    user_root = tmp_path / "user" / "incidents"
    stdout = io.StringIO()

    status = run_incidents(
        ["--resolve", "--no-ai"],
        stdout=stdout,
        user_root=user_root,
        system_root=system_root,
        env={},
    )

    reviewed_path = user_root.parent / "incident_reviewed.json"
    assert status == 0
    assert unseen_pending_markers(uid=1000, marker_root=system_root / "pending", seen_path=reviewed_path) == []
    assert "Review complete - no automatic repair applied" in stdout.getvalue()
    assert "No verified automatic repair was safe or required" in stdout.getvalue()
    assert "tray icon will return to normal" in stdout.getvalue()
    assert "normal icon means the findings were handled or reviewed" in stdout.getvalue()


def test_resolve_dry_run_does_not_acknowledge_pending_alert(monkeypatch, tmp_path):
    monkeypatch.setattr(os, "getuid", lambda: 1000)
    system_root = tmp_path / "system"
    pending_report = minimal_report(
        incident_id="maintenance-pending",
        trigger="weekly_maintenance",
        findings=[IncidentFinding("INC-OOM", Severity.HIGH, Confidence.CONFIRMED, "OOM", "s", "w", "a", "out_of_memory")],
    )
    write_pending_markers(pending_report, root=system_root / "pending")
    monkeypatch.setattr("aurascan.core.incidents.build_incident_report", lambda *_args, **_kwargs: pending_report)
    monkeypatch.setattr("aurascan.core.incident_repairs.plan_repair_actions", lambda *_args, **_kwargs: [])
    user_root = tmp_path / "user" / "incidents"

    status = run_incidents(
        ["--resolve", "--dry-run", "--no-ai"],
        stdout=io.StringIO(),
        user_root=user_root,
        system_root=system_root,
        env={},
    )

    assert status == 0
    assert unseen_pending_markers(
        uid=1000,
        marker_root=system_root / "pending",
        seen_path=user_root.parent / "incident_reviewed.json",
    )


def test_build_report_bounds_journal_and_records_pstore_fixture(tmp_path):
    panic = json.dumps(journal_record("Kernel panic - not syncing", timestamp="1"))
    clean = json.dumps(journal_record("Reached target System Reboot", timestamp="2"))
    journal_commands = {
        ("journalctl", "--boot=-1", "--output=json", "--no-pager", "--priority=0..4", "--lines=2000"): Completed(panic),
        ("journalctl", "--boot=-1", "--dmesg", "--output=json", "--no-pager", "--lines=1000"): Completed(panic),
        ("journalctl", "--boot=-1", "--output=json", "--no-pager", "--lines=200"): Completed(clean),
        ("coredumpctl", "--json=short", "--no-pager", "--reverse", "-n", "200", "list", "_BOOT_ID=" + "a" * 32): Completed(""),
    }
    pstore = tmp_path / "pstore"
    pstore.mkdir()
    (pstore / "dmesg-erst-1").write_text("Kernel panic retained", encoding="utf-8")

    progress = []
    report = build_incident_report(
        "-1",
        runner=FakeRunner(journal_commands),
        which=fake_which({"journalctl", "coredumpctl"}),
        pstore_root=pstore,
        progress_callback=lambda step, label: progress.append((step, label)),
    )

    assert report.boot_id == "a" * 32
    assert {finding.rule_id for finding in report.findings} >= {"INC-KERNEL-PANIC", "INC-PSTORE-CRASH"}
    assert report.collection_status == "complete"
    assert [step for step, _label in progress] == list(range(1, 8))
    assert progress[0][1] == "Reading bounded system journal records"
    assert progress[-1][1] == "Finalizing and bounding diagnostic evidence"


def test_unprivileged_pstore_denial_is_optional_but_root_denial_is_reported(monkeypatch, tmp_path):
    pstore = tmp_path / "pstore"
    pstore.mkdir()
    original_iterdir = Path.iterdir

    def denied(path):
        if path == pstore:
            raise PermissionError(13, "Permission denied", str(path))
        return original_iterdir(path)

    monkeypatch.setattr(Path, "iterdir", denied)
    monkeypatch.setattr("aurascan.core.incidents.os.geteuid", lambda: 1000)
    evidence, findings, errors = collect_pstore_evidence(pstore)

    assert evidence == findings == errors == []

    monkeypatch.setattr("aurascan.core.incidents.os.geteuid", lambda: 0)
    _evidence, _findings, root_errors = collect_pstore_evidence(pstore)

    assert len(root_errors) == 1
    assert "pstore could not be read" in root_errors[0]


def test_cli_dry_run_never_invokes_repair(monkeypatch, tmp_path):
    report = minimal_report(
        repair_actions=[RepairAction("ira-one", "fixture", "Repair", "summary", Severity.LOW, eligible=True, verified=True)]
    )
    monkeypatch.setattr("aurascan.core.incidents.build_incident_report", lambda *_args, **_kwargs: report)
    monkeypatch.setattr("aurascan.core.incident_repairs.plan_repair_actions", lambda *_args, **_kwargs: report.repair_actions)
    called = []
    monkeypatch.setattr("aurascan.core.incident_repairs.apply_repair_plan", lambda *_args, **_kwargs: called.append(True))
    stdout = io.StringIO()

    status = run_incidents(
        ["--current-boot", "--dry-run", "--no-ai"],
        stdout=stdout,
        user_root=tmp_path / "reports",
        system_root=tmp_path / "system",
        env={},
    )

    assert status == 0
    assert called == []
    assert "Incident Recovery Assistant" in stdout.getvalue()
    assert "Verifying safe repair recipes" in stdout.getvalue()
    assert "Incident analysis ready" in stdout.getvalue()


def test_json_mode_is_report_only_without_yes(monkeypatch, tmp_path):
    report = minimal_report(
        repair_actions=[RepairAction("ira-one", "fixture", "Repair", "summary", Severity.LOW, eligible=True, verified=True)]
    )
    monkeypatch.setattr("aurascan.core.incidents.build_incident_report", lambda *_args, **_kwargs: report)
    monkeypatch.setattr("aurascan.core.incident_repairs.plan_repair_actions", lambda *_args, **_kwargs: report.repair_actions)
    called = []
    monkeypatch.setattr("aurascan.core.incident_repairs.apply_repair_plan", lambda *_args, **_kwargs: called.append(True))
    stdout = io.StringIO()

    status = run_incidents(
        ["--current-boot", "--json", "--no-ai"],
        stdout=stdout,
        user_root=tmp_path / "reports",
        system_root=tmp_path / "system",
        env={},
    )

    assert status == 0
    assert json.loads(stdout.getvalue())["report_type"] == "incident_report"
    assert called == []


def test_json_yes_emits_post_repair_report_once(monkeypatch, tmp_path):
    action = RepairAction("ira-one", "fixture", "Repair", "summary", Severity.LOW, eligible=True, verified=True)
    report = minimal_report(evidence=[IncidentEvidence("iev-one", "journal", "failure")], repair_actions=[action])
    fresh = minimal_report(trigger="post_repair")
    reports = iter([report, fresh])
    monkeypatch.setattr("aurascan.core.incidents.build_incident_report", lambda *_args, **_kwargs: next(reports))
    monkeypatch.setattr("aurascan.core.incident_repairs.plan_repair_actions", lambda *_args, **_kwargs: [action])
    monkeypatch.setattr(
        "aurascan.core.incident_repairs.apply_repair_plan",
        lambda *_args, **_kwargs: ([RepairResult("ira-one", "fixture", "applied", "done", True)], True),
    )
    stdout = io.StringIO()

    status = run_incidents(
        ["--current-boot", "--json", "--yes", "--no-ai"],
        stdout=stdout,
        user_root=tmp_path / "reports",
        system_root=tmp_path / "system",
        env={},
    )

    payload = json.loads(stdout.getvalue())
    assert status == 0
    assert payload["schema"] == "incident_report/1.3"
    assert payload["repair_results"][0]["status"] == "applied"
    assert payload["post_repair"]["collection_status"] == "complete"


def test_privileged_repair_helper_refuses_non_root_invocation(monkeypatch, tmp_path):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    stderr = io.StringIO()

    status = run_incidents(["--apply-request", str(tmp_path / "request.json")], stderr=stderr, env={})

    assert status != 0
    assert "non-root" in stderr.getvalue()


def test_monitor_capture_persists_markers_without_ai_or_repairs(monkeypatch, tmp_path):
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    report = minimal_report(
        trigger="boot_monitor",
        coredumps=[CoredumpGroup("sig", "demo", "demo", "SIGSEGV", "frame", uid=1000)],
    )
    monkeypatch.setattr("aurascan.core.incidents.build_incident_report", lambda *_args, **_kwargs: report)
    monkeypatch.setattr(
        "aurascan.core.incidents.apply_ai_incident_review",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("monitor must not call AI")),
    )
    monkeypatch.setattr(
        "aurascan.core.incident_repairs.plan_repair_actions",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("monitor must not plan repairs")),
    )
    system_root = tmp_path / "system"

    status = run_incidents(
        ["--last-boot", "--capture-monitor"],
        stdout=io.StringIO(),
        system_root=system_root,
        env={},
    )

    assert status == 0
    assert list((system_root / "reports").glob("*.json"))
    assert pending_markers(uid=1000, root=system_root / "pending")


def test_default_yes_is_disabled_for_truncated_or_unresolved_high_risk_reports():
    action = RepairAction(
        "ira-one",
        "fixture",
        "Repair",
        "summary",
        Severity.LOW,
        parameters={"category": "package_manager"},
        eligible=True,
        verified=True,
    )
    safe = minimal_report(repair_actions=[action])
    truncated = minimal_report(repair_actions=[action], truncated=True)
    unresolved = minimal_report(
        repair_actions=[action],
        findings=[IncidentFinding("INC-STORAGE-IO", Severity.CRITICAL, Confidence.HIGH, "Storage", "s", "w", "a", "storage")],
    )

    assert safe.apply_prompt_default_yes is True
    assert truncated.apply_prompt_default_yes is False
    assert unresolved.apply_prompt_default_yes is False

    header_only = RepairAction(
        "ira-headers",
        "kernel_headers_install",
        "Install headers",
        "summary",
        Severity.MEDIUM,
        parameters={"category": "kernel_module"},
        eligible=True,
        verified=True,
    )
    unavailable_dkms = minimal_report(
        repair_actions=[header_only],
        findings=[IncidentFinding(
            "INC-DKMS",
            Severity.HIGH,
            Confidence.CONFIRMED,
            "Current kernel module state needs attention",
            "DKMS command is unavailable.",
            "why",
            "Install DKMS before rebuilding modules.",
            "kernel_module",
        )],
    )
    assert unavailable_dkms.apply_prompt_default_yes is False


def test_incident_report_1_0_and_1_1_remain_loadable_after_schema_upgrade():
    for version in ("1.0", "1.1"):
        payload = minimal_report().to_dict()
        payload["schema"] = f"incident_report/{version}"
        payload["schema_version"] = version
        payload.pop("automation", None)
        if version == "1.0":
            payload.pop("scan_window", None)

        loaded = IncidentReport.from_dict(payload)

        assert loaded.schema_version == version
        assert loaded.automation == {}
        if version == "1.0":
            assert loaded.scan_window == {}


def test_incremental_journal_uses_cursor_fixed_window_and_detects_backlog():
    calls = []

    def runner(command, **_kwargs):
        calls.append(list(command))
        if len(calls) == 1:
            rows = [
                {"MESSAGE": f"failure {index}", "__CURSOR": f"cursor-{index}", "__REALTIME_TIMESTAMP": str(1_000_000 + index)}
                for index in range(2001)
            ]
        else:
            rows = [{"MESSAGE": "bounded", "__CURSOR": "cursor-final", "__REALTIME_TIMESTAMP": "1500000"}]
        return Completed("\n".join(json.dumps(row) for row in rows))

    records, errors, truncated, progress = collect_maintenance_journal_records(
        "a" * 32,
        after_cursor="cursor-old",
        since_usec=1_000_000,
        requested_end_usec=9_000_000,
        runner=runner,
        which=fake_which({"journalctl"}),
    )

    assert errors == []
    assert truncated is True
    assert records[-1]["__CURSOR"] == "cursor-final"
    assert progress["journal_cursor"] == "cursor-final"
    assert progress["journal_processed_end_usec"] < 9_000_000
    assert any("--after-cursor=cursor-old" in call for call in calls)
    assert all("--lines=2001" in call for call in calls)


def test_incremental_journal_recovers_from_missing_cursor_with_timestamp():
    calls = []

    def runner(command, **_kwargs):
        calls.append(list(command))
        if any(item.startswith("--after-cursor=") for item in command):
            return Completed(stderr="Failed to seek to cursor", returncode=1)
        return Completed(json.dumps({"MESSAGE": "OOM", "__CURSOR": "new", "__REALTIME_TIMESTAMP": "2000000"}))

    records, errors, truncated, progress = collect_maintenance_journal_records(
        "a" * 32,
        after_cursor="missing",
        since_usec=1_000_000,
        requested_end_usec=3_000_000,
        runner=runner,
        which=fake_which({"journalctl"}),
    )

    assert errors == []
    assert truncated is False
    assert records
    assert progress["journal_cursor_recovered"] is True
    assert any("--since=@1.000000" in call for call in calls)


def test_incremental_coredumps_filter_seen_records_and_update_checkpoint(monkeypatch):
    monkeypatch.setattr(os, "getuid", lambda: 0)
    boot = "a" * 32
    rows = [
        {"BOOT_ID": boot, "UID": "1000", "EXE": "/usr/bin/demo", "SIGNAL": "SIGSEGV", "TIME": "2"},
        {"BOOT_ID": boot, "UID": "1000", "EXE": "/usr/bin/demo", "SIGNAL": "SIGSEGV", "TIME": "3"},
    ]

    def runner(command, **_kwargs):
        return Completed("\n".join(json.dumps(row) for row in rows))

    groups, evidence, _findings, errors, truncated, progress = collect_maintenance_coredumps(
        "0",
        boot_id=boot,
        since_usec=1_000_000,
        requested_end_usec=4_000_000,
        seen_record_ids=[],
        runner=runner,
        which=fake_which({"coredumpctl"}),
    )

    assert errors == []
    assert truncated is False
    assert groups[0].count == 2
    assert len(evidence) == 2
    assert progress["coredump_since_usec"] == 4_000_000
    assert progress["coredump_seen_ids"]

    repeated = collect_maintenance_coredumps(
        "0",
        boot_id=boot,
        since_usec=1_000_000,
        requested_end_usec=4_000_000,
        seen_record_ids=progress["coredump_seen_ids"],
        runner=runner,
        which=fake_which({"coredumpctl"}),
    )
    assert repeated[0] == []
    assert repeated[1] == []


def test_weekly_capture_is_read_only_private_and_silent_when_clean(monkeypatch, tmp_path):
    monkeypatch.setattr("aurascan.core.incidents.current_boot_id", lambda: "a" * 32)
    monkeypatch.setattr("aurascan.core.incidents.current_boot_start_usec", lambda **_kwargs: 1_000_000)
    report = minimal_report(trigger="weekly_maintenance", target_boot="0", findings=[], coredumps=[])

    def fake_build(_target, **kwargs):
        context = kwargs["maintenance_context"]
        context.update({
            "journal_cursor": "cursor-new",
            "journal_since_usec": 2_000_000,
            "coredump_since_usec": 2_000_000,
            "coredump_seen_ids": [],
            "journal_processed_end_usec": 2_000_000,
            "coredump_processed_end_usec": 2_000_000,
        })
        return report

    monkeypatch.setattr("aurascan.core.incidents.build_incident_report", fake_build)
    monkeypatch.setattr(
        "aurascan.core.incidents.apply_ai_incident_review",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("maintenance must not call AI")),
    )
    monkeypatch.setattr(
        "aurascan.core.incident_repairs.plan_repair_actions",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("maintenance must not plan repairs")),
    )
    system_root = tmp_path / "system"
    stdout = io.StringIO()

    status = capture_incident_maintenance(system_root=system_root, stdout=stdout, now_usec=2_000_000)

    state_path = system_root / "maintenance" / "state.json"
    public_path = system_root / "maintenance" / "status.json"
    assert status == 0
    assert stdout.getvalue() == ""
    assert oct(state_path.stat().st_mode & 0o777) == "0o600"
    assert oct(public_path.stat().st_mode & 0o777) == "0o644"
    assert oct(public_path.parent.stat().st_mode & 0o777) == "0o755"
    assert set(json.loads(public_path.read_text(encoding="utf-8"))) == {
        "schema", "last_attempt_usec", "last_success_usec", "next_due_usec", "collection_status"
    }
    assert not list((system_root / "pending").glob("*.json")) if (system_root / "pending").exists() else True
    assert load_maintenance_checkpoint(state_path).journal_cursor == "cursor-new"
    assert load_maintenance_status(public_path, now_usec=2_000_000)["collection_status"] == "complete"


def test_maintenance_markers_have_unique_scan_generation(tmp_path):
    root = tmp_path / "pending"
    finding = IncidentFinding("INC-OOM", Severity.HIGH, Confidence.CONFIRMED, "OOM", "s", "w", "a", "out_of_memory")
    first = minimal_report(incident_id="maintenance-one", trigger="weekly_maintenance", findings=[finding])
    second = minimal_report(incident_id="maintenance-two", trigger="weekly_maintenance", findings=[finding])

    write_pending_markers(first, root=root)
    write_pending_markers(second, root=root)
    markers = pending_markers(uid=1000, root=root)

    assert len(markers) == 2
    assert {item["scan_id"] for item in markers} == {"maintenance-one", "maintenance-two"}
    assert all(item["marker_type"] == "maintenance" for item in markers)


def test_monitor_enablement_couples_timer_and_runs_baseline():
    runner = FakeRunner()

    ok, message = set_incident_monitor_enabled(True, runner=runner)

    assert ok is True
    assert "weekly timer enabled" in message
    assert runner.calls[0] == ["sudo", "systemctl", "enable", "--now", "aurascan-incident-monitor.service", INCIDENT_MAINTENANCE_TIMER]
    assert runner.calls[1] == ["sudo", "systemctl", "start", INCIDENT_MAINTENANCE_SERVICE]


def test_monitor_enablement_rolls_back_when_coupled_enable_fails():
    enable = ("sudo", "systemctl", "enable", "--now", "aurascan-incident-monitor.service", INCIDENT_MAINTENANCE_TIMER)
    runner = FakeRunner({enable: Completed(returncode=1)})

    ok, _message = set_incident_monitor_enabled(True, runner=runner)

    assert ok is False
    assert ["sudo", "systemctl", "disable", "--now", "aurascan-incident-monitor.service", INCIDENT_MAINTENANCE_TIMER] in runner.calls


def test_partial_maintenance_advances_only_processed_checkpoint_and_stays_due(monkeypatch, tmp_path):
    monkeypatch.setattr("aurascan.core.incidents.current_boot_id", lambda: "a" * 32)
    monkeypatch.setattr("aurascan.core.incidents.current_boot_start_usec", lambda **_kwargs: 1_000_000)
    report = minimal_report(trigger="weekly_maintenance", target_boot="0", collection_status="partial", truncated=True)

    def fake_build(_target, **kwargs):
        kwargs["maintenance_context"].update({
            "journal_cursor": "bounded-cursor",
            "journal_since_usec": 1_500_000,
            "coredump_since_usec": 1_500_000,
            "coredump_seen_ids": ["hash-one"],
            "journal_processed_end_usec": 1_500_000,
            "coredump_processed_end_usec": 1_500_000,
        })
        return report

    monkeypatch.setattr("aurascan.core.incidents.build_incident_report", fake_build)
    system_root = tmp_path / "system"

    assert capture_incident_maintenance(system_root=system_root, now_usec=2_000_000) == 0

    state = load_maintenance_checkpoint(system_root / "maintenance" / "state.json")
    status = load_maintenance_status(system_root / "maintenance" / "status.json", now_usec=2_000_000)
    assert state.journal_cursor == "bounded-cursor"
    assert state.last_window_end_usec == 1_500_000
    assert state.last_success_usec == 0
    assert status["collection_status"] == "partial"
    assert status["overdue"] is True


def test_unavailable_maintenance_does_not_advance_existing_checkpoint(monkeypatch, tmp_path):
    monkeypatch.setattr("aurascan.core.incidents.current_boot_id", lambda: "a" * 32)
    state_path = tmp_path / "system" / "maintenance" / "state.json"
    state_path.parent.mkdir(parents=True)
    existing = MaintenanceCheckpoint(
        boot_id="a" * 32,
        journal_cursor="keep-me",
        journal_since_usec=1_000_000,
        coredump_since_usec=1_000_000,
        last_window_end_usec=1_000_000,
        last_success_usec=900_000,
    )
    state_path.write_text(json.dumps(existing.to_dict()), encoding="utf-8")
    unavailable = minimal_report(trigger="weekly_maintenance", target_boot="0", collection_status="unavailable")
    monkeypatch.setattr("aurascan.core.incidents.build_incident_report", lambda *_args, **_kwargs: unavailable)

    result = capture_incident_maintenance(system_root=tmp_path / "system", now_usec=2_000_000, stderr=io.StringIO())

    after = load_maintenance_checkpoint(state_path)
    assert result != 0
    assert after.journal_cursor == "keep-me"
    assert after.last_window_end_usec == 1_000_000


def test_new_boot_resets_old_cursor_before_baseline(monkeypatch, tmp_path):
    state_path = tmp_path / "system" / "maintenance" / "state.json"
    state_path.parent.mkdir(parents=True)
    state_path.write_text(json.dumps(MaintenanceCheckpoint(
        boot_id="b" * 32,
        journal_cursor="old-boot-cursor",
        journal_since_usec=10,
        coredump_since_usec=10,
        last_window_end_usec=10,
    ).to_dict()), encoding="utf-8")
    monkeypatch.setattr("aurascan.core.incidents.current_boot_id", lambda: "a" * 32)
    monkeypatch.setattr("aurascan.core.incidents.current_boot_start_usec", lambda **_kwargs: 1_000_000)
    observed = {}

    def fake_build(_target, **kwargs):
        observed.update(kwargs["maintenance_context"])
        kwargs["maintenance_context"].update({
            "journal_processed_end_usec": 2_000_000,
            "coredump_processed_end_usec": 2_000_000,
            "journal_since_usec": 2_000_000,
            "coredump_since_usec": 2_000_000,
        })
        return minimal_report(trigger="weekly_maintenance", target_boot="0")

    monkeypatch.setattr("aurascan.core.incidents.build_incident_report", fake_build)

    assert capture_incident_maintenance(system_root=tmp_path / "system", now_usec=2_000_000) == 0
    assert observed["journal_cursor"] == ""
    assert observed["requested_start_usec"] == 1_000_000
