import json
import os
from pathlib import Path

import aurascan.core.incident_diagnostics as diagnostics
from aurascan.core.incident_automation import load_reusable_background_plan
from aurascan.core.incident_diagnostics import (
    diagnostic_probe_id,
    discover_diagnostic_probes,
    execute_diagnostic_probes,
    incident_analysis_fingerprint,
    make_probe,
    prepare_ai_guided_repair_plan,
    select_probe_ids,
)
from aurascan.core.incident_repairs import make_action
from aurascan.core.incidents import (
    CoredumpGroup,
    DiagnosticProbeResult,
    IncidentEvidence,
    IncidentFinding,
    IncidentReport,
    atomic_write_json,
    marker_key,
    persist_incident_report,
)
from aurascan.core.models import Confidence, Severity


class Completed:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def minimal_report(**updates):
    values = {
        "incident_id": "incident-probe-test",
        "target_boot": "0",
        "trigger": "manual",
        "boot_id": "a" * 32,
        "collection_status": "complete",
    }
    values.update(updates)
    return IncidentReport(**values)


def test_probe_discovery_is_opaque_bounded_and_round_trips_schema_13():
    finding = IncidentFinding(
        "INC-REPOSITORY",
        Severity.MEDIUM,
        Confidence.CONFIRMED,
        "Repository issue",
        "summary",
        "why",
        "action",
        "repository",
        ["iev-repo"],
    )
    groups = [
        CoredumpGroup(f"sig-{index}", f"app-{index}", f"package-{index}", "SIGSEGV", "frame", count=3)
        for index in range(30)
    ]
    report = minimal_report(findings=[finding], coredumps=groups)

    probes = discover_diagnostic_probes(report)
    report.diagnostic_probes = probes
    restored = IncidentReport.from_dict(report.to_dict())

    assert report.to_dict()["schema"] == "incident_report/1.3"
    assert len(probes) <= 24
    assert len({item.probe_id for item in probes}) == len(probes)
    assert all(item.probe_id.startswith("idp-") and "package" not in item.probe_id for item in probes)
    assert any(item.required and item.probe_type == "repository_health" for item in probes)
    assert restored.diagnostic_probes[0].to_dict() == probes[0].to_dict()


def test_schema_12_report_loads_without_probe_fields():
    payload = minimal_report().to_dict()
    payload["schema"] = "incident_report/1.2"
    payload["schema_version"] = "1.2"
    payload.pop("diagnostic_probes")
    payload.pop("probe_results")

    restored = IncidentReport.from_dict(payload)

    assert restored.schema_version == "1.2"
    assert restored.diagnostic_probes == []
    assert restored.probe_results == []


def test_probe_selection_rejects_unknown_ids_and_enforces_caps():
    probes = [
        make_probe(
            "package_integrity",
            f"Probe {index}",
            "summary",
            {"package": f"demo-{index}", "executable": ""},
            required=index < 8,
        )
        for index in range(24)
    ]
    requested = ["idp-fabricated"] + [item.probe_id for item in probes[8:20]]

    selected = select_probe_ids(probes, requested)

    assert len(selected) == 12
    assert "idp-fabricated" not in selected
    assert selected[:8] == [item.probe_id for item in probes[:8]]
    assert len(set(selected) & {item.probe_id for item in probes[8:]}) == 4


def test_selected_probe_can_add_only_an_aurascan_owned_verified_action(monkeypatch):
    probe = make_probe(
        "package_integrity",
        "Inspect demo",
        "summary",
        {"package": "demo", "executable": "demo"},
        evidence_ids=["iev-one"],
    )
    action = make_action(
        "exact_package_reinstall",
        "Reinstall demo",
        "verified locally",
        Severity.MEDIUM,
        {"package": "demo", "version": "1", "archive": "/var/cache/pacman/pkg/demo.pkg.tar.zst", "category": "application_crash"},
        [["pacman", "-U", "demo"]],
    )
    monkeypatch.setattr(diagnostics, "plan_exact_package_reinstall", lambda *_args, **_kwargs: action)

    results, actions = execute_diagnostic_probes(
        minimal_report(),
        [probe],
        [probe.probe_id, "idp-fabricated"],
        ai_requested_ids=[probe.probe_id, "idp-fabricated"],
        runner=lambda *_args, **_kwargs: Completed(),
        which=lambda name: f"/usr/bin/{name}" if name == "pacman" else None,
    )

    assert [item.status for item in results] == ["action_ready"]
    assert results[0].action_ids == [action.action_id]
    assert actions == [action]


def test_probe_deadline_marks_remaining_checks_incomplete(monkeypatch):
    probes = [
        make_probe("repository_health", "Repo", "summary", {"index": index}, required=True)
        for index in range(2)
    ]
    monkeypatch.setattr(diagnostics, "_execute_probe", lambda *_args, **_kwargs: ("no_action", "clean", []))
    values = iter([0.0, 0.0, 2.0, 2.0])

    results, actions = execute_diagnostic_probes(
        minimal_report(),
        probes,
        [item.probe_id for item in probes],
        deadline_seconds=1,
        clock=lambda: next(values),
    )

    assert [item.status for item in results] == ["no_action", "timeout"]
    assert results[1].affects_plan is True
    assert actions == []


def test_two_pass_planner_runs_ai_selected_probe_then_reviews_verified_actions(monkeypatch):
    probe = make_probe("package_integrity", "Inspect demo", "summary", {"package": "demo", "executable": "demo"})
    action = make_action(
        "exact_package_reinstall",
        "Reinstall demo",
        "verified",
        Severity.MEDIUM,
        {"package": "demo", "version": "1", "category": "application_crash"},
        [["pacman", "-U", "demo"]],
    )
    monkeypatch.setattr(diagnostics, "discover_diagnostic_probes", lambda _report: [probe])
    monkeypatch.setattr(
        diagnostics,
        "execute_diagnostic_probes",
        lambda *_args, **_kwargs: ([DiagnosticProbeResult(
            probe.probe_id,
            probe.probe_type,
            "action_ready",
            "verified",
            action_ids=[action.action_id],
        )], [action]),
    )
    calls = []

    def ai_reviewer(report, **kwargs):
        phase = kwargs.get("phase", "final")
        calls.append(phase)
        phase_data = {
            "enabled": True,
            "provider": "fixture",
            "status": "ok",
            "summary": f"{phase} summary",
            "likely_causes": [],
            "recommended_action_ids": [action.action_id] if phase == "final" else [],
            "requested_probe_ids": [probe.probe_id] if phase == "triage" else [],
        }
        report.ai_review[phase] = phase_data
        report.ai_review.update(phase_data)

    report = minimal_report()
    prepare_ai_guided_repair_plan(
        report,
        disabled=False,
        facts_only=False,
        ai_reviewer=ai_reviewer,
    )

    assert calls == ["triage", "final"]
    assert report.eligible_actions == [action]
    assert report.ai_review["recommended_action_ids"] == [action.action_id]
    assert report.automation["ai_guided_repair"]["provider_requests"] == 2


def test_fabricated_probe_id_never_triggers_second_ai_pass(monkeypatch):
    probe = make_probe("package_integrity", "Inspect demo", "summary", {"package": "demo", "executable": "demo"})
    monkeypatch.setattr(diagnostics, "discover_diagnostic_probes", lambda _report: [probe])
    monkeypatch.setattr(
        diagnostics,
        "execute_diagnostic_probes",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("fabricated probe executed")),
    )
    calls = []

    def ai_reviewer(report, **kwargs):
        calls.append(kwargs.get("phase"))
        report.ai_review = {
            "enabled": True,
            "provider": "fixture",
            "status": "ok",
            "summary": "triage",
            "likely_causes": [],
            "recommended_action_ids": [],
            "requested_probe_ids": ["idp-fabricated"],
            "triage": {
                "status": "ok",
                "summary": "triage",
                "likely_causes": [],
                "recommended_action_ids": [],
                "requested_probe_ids": ["idp-fabricated"],
            },
        }

    report = minimal_report()
    prepare_ai_guided_repair_plan(report, disabled=False, facts_only=False, ai_reviewer=ai_reviewer)

    assert calls == ["triage"]
    assert report.probe_results == []


def test_matching_private_background_plan_is_reusable_for_six_hours(tmp_path):
    report_root = tmp_path / "reports"
    automation_root = report_root / "automation"
    automation_root.mkdir(parents=True, mode=0o700)
    report = minimal_report(incident_id="incident-background-cache")
    report.ai_review = {
        "status": "ok",
        "triage": {"status": "ok", "requested_probe_ids": []},
        "final": {"status": "ok"},
    }
    persist_incident_report(report, report_root)
    marker = {
        "marker_type": "maintenance",
        "scan_id": "scan-one",
        "uid_scope": str(os.getuid()),
        "boot_id": report.boot_id,
    }
    now = 10_000_000_000
    result_path = automation_root / "background-ai-result.json"
    atomic_write_json(
        result_path,
        {
            "result_id": "result-one",
            "marker_key": marker_key(marker),
            "completed_at_usec": now - 60_000_000,
            "report_id": report.incident_id,
            "analysis_fingerprint": incident_analysis_fingerprint(report),
        },
        mode=0o600,
    )

    assert load_reusable_background_plan(report, marker, report_root, now_usec=now) is not None
    assert load_reusable_background_plan(
        report,
        marker,
        report_root,
        now_usec=now + 6 * 60 * 60 * 1_000_000 + 1,
    ) is None


def test_cached_guidance_refreshes_probe_without_another_provider_request(monkeypatch):
    probe = make_probe(
        "package_integrity",
        "Inspect demo",
        "summary",
        {"package": "demo", "executable": "demo"},
        required=True,
    )
    action = make_action(
        "exact_package_reinstall",
        "Reinstall demo",
        "verified",
        Severity.MEDIUM,
        {"package": "demo", "version": "1", "category": "application_crash"},
        [["pacman", "-U", "demo"]],
    )
    result = DiagnosticProbeResult(
        probe.probe_id,
        probe.probe_type,
        "action_ready",
        "verified",
        requested_by="deterministic+ai",
        action_ids=[action.action_id],
    )
    cached = minimal_report(incident_id="incident-cached", repair_actions=[action])
    cached.diagnostic_probes = [probe]
    cached.probe_results = [result]
    cached.ai_review = {
        "enabled": True,
        "provider": "fixture",
        "status": "ok",
        "summary": "cached final",
        "likely_causes": [],
        "recommended_action_ids": [action.action_id],
        "requested_probe_ids": [probe.probe_id],
        "triage": {"status": "ok", "requested_probe_ids": [probe.probe_id]},
        "final": {"status": "ok", "recommended_action_ids": [action.action_id]},
    }
    fresh = minimal_report()
    monkeypatch.setattr(diagnostics, "discover_diagnostic_probes", lambda _report: [probe])
    monkeypatch.setattr(
        diagnostics,
        "execute_diagnostic_probes",
        lambda *_args, **_kwargs: ([result], [action]),
    )

    prepare_ai_guided_repair_plan(
        fresh,
        disabled=False,
        facts_only=False,
        cached_report=cached,
        ai_reviewer=lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("provider was called")),
    )

    assert fresh.probe_results == [result]
    assert fresh.eligible_actions == [action]
    assert fresh.ai_review["summary"] == "cached final"
    assert fresh.automation["ai_guided_repair"]["cache_used"] is True
    assert fresh.automation["ai_guided_repair"]["provider_requests"] == 0


def test_probe_failure_disables_default_yes_for_a_repair_plan():
    action = make_action("fixture", "Repair", "summary", Severity.LOW, {}, [["fixture"]])
    report = minimal_report(
        repair_actions=[action],
        probe_results=[DiagnosticProbeResult("idp-one", "fixture", "timeout", "timed out", affects_plan=True)],
    )

    assert report.apply_prompt_default_yes is False


def test_probe_id_depends_only_on_local_type_and_target():
    assert diagnostic_probe_id("package_integrity", {"package": "demo"}) == diagnostic_probe_id(
        "package_integrity", {"package": "demo"}
    )
    assert diagnostic_probe_id("package_integrity", {"package": "demo"}) != diagnostic_probe_id(
        "package_integrity", {"package": "other"}
    )
