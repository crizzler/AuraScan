import io
import json
import os
import stat
import subprocess
import time
from pathlib import Path

from aurascan.core.config_drift import (
    build_config_drift_report,
    config_drift_action_id,
    run_config_drift,
)
from aurascan.core.followup import (
    EXIT_FOLLOWUP_PROVIDER_ERROR,
    EXIT_FOLLOWUP_UNAVAILABLE,
    FOLLOWUP_MAX_PROMPT_CHARS,
    FollowUpAction,
    FollowUpContext,
    FollowUpFact,
    FollowUpProbe,
    FollowUpProbeResult,
    FollowUpRuntime,
    build_followup_ai_prompt,
    context_from_config_drift,
    context_from_maintenance,
    followup_available,
    latest_followup_context,
    load_followup_context,
    persist_followup_context,
    prune_followup_contexts,
    run_ask,
    run_followup_session,
    validate_followup_ai_response,
)
from aurascan.core.hardware_health import HARDWARE_HEALTH_PROBE_ID
from aurascan.core.incidents import (
    IncidentEvidence,
    IncidentReport,
    persist_incident_report,
    run_incidents,
)
from aurascan.core.models import Severity
from aurascan.core.upgrade_preflight import (
    PACMAN_PRINT_FORMAT,
    SystemSnapshot,
    run_upgrade,
)


def ai_env(tmp_path: Path):
    return {
        "AURASCAN_AI_ENABLED": "1",
        "AURASCAN_AI_PROVIDER": "openai",
        "AURASCAN_OPENAI_API_KEY": "fixture-key",
        "XDG_STATE_HOME": str(tmp_path / "state"),
    }


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


def provider_response(data):
    return FakeResponse({
        "choices": [
            {"message": {"content": json.dumps(data)}},
        ]
    })


def context(context_id="followup-test"):
    item = FollowUpContext(
        context_id,
        "upgrade",
        "upgrade-one",
        "preflight",
        "Upgrade",
        facts=[FollowUpFact("fact-one", "summary", "One package is pending.")],
        probes=[FollowUpProbe("probe-one", "Check locally", "Run a bounded check.")],
        actions=[
            FollowUpAction(
                "action-one",
                "Apply verified repair",
                "AuraScan already verified this fixture repair.",
                "LOW",
                True,
                True,
            )
        ],
    )
    return item


def test_context_persistence_is_private_and_latest_is_selected(tmp_path):
    root = tmp_path / "follow-up"
    first = context("followup-first")
    second = context("followup-second")

    first_path = persist_followup_context(first, root)
    time.sleep(0.01)
    second_path = persist_followup_context(second, root)

    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE(first_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(second_path.stat().st_mode) == 0o600
    assert load_followup_context("followup-first", root).source_type == "upgrade"
    assert latest_followup_context(root).context_id == "followup-second"


def test_context_loader_rejects_unsafe_permissions_and_malformed_data(tmp_path):
    root = tmp_path / "follow-up"
    path = persist_followup_context(context(), root)
    path.chmod(0o644)

    assert load_followup_context("followup-test", root) is None

    path.chmod(0o600)
    path.write_text("{not json", encoding="utf-8")
    assert load_followup_context("followup-test", root) is None
    assert load_followup_context("../escape", root) is None


def test_context_loader_rejects_tampering_and_unsafe_directory(tmp_path):
    root = tmp_path / "follow-up"
    path = persist_followup_context(context(), root)
    data = json.loads(path.read_text(encoding="utf-8"))
    data["facts"][0]["summary"] = "A tampered package result."
    path.write_text(json.dumps(data), encoding="utf-8")
    path.chmod(0o600)

    assert load_followup_context("followup-test", root) is None

    persist_followup_context(context(), root)
    root.chmod(0o755)
    assert load_followup_context("followup-test", root) is None
    assert latest_followup_context(root) is None


def test_persisted_context_is_redacted_and_contains_no_conversation(tmp_path):
    root = tmp_path / "follow-up"
    item = context()
    item.facts.append(
        FollowUpFact(
            "fact-secret",
            "evidence",
            "A private fixture",
            "password=hunter2 /home/arawn/private 192.168.1.20",
        )
    )
    path = persist_followup_context(item, root)
    text = path.read_text(encoding="utf-8")

    assert "hunter2" not in text
    assert "/home/arawn/" not in text
    assert "192.168.1.20" not in text
    assert "conversation" not in text
    assert "turns" not in text


def test_context_retention_removes_old_and_excess_records(tmp_path):
    root = tmp_path / "follow-up"
    old_path = persist_followup_context(context("followup-old"), root)
    old = time.time() - 31 * 86400
    os.utime(old_path, (old, old))
    for index in range(52):
        persist_followup_context(context(f"followup-new-{index}"), root)

    prune_followup_contexts(root)

    assert not old_path.exists()
    assert len(list(root.glob("*.json"))) <= 50


def test_prompt_redacts_secrets_and_stays_bounded():
    item = context()
    item.facts.extend(
        FollowUpFact(
            f"fact-{index}",
            "evidence",
            f"Evidence {index}",
            "password=hunter2 /home/arawn/private 192.168.1.20 " + ("x" * 500),
        )
        for index in range(100)
    )

    prompt = build_followup_ai_prompt(
        item,
        "My token=secret-value is this safe?",
        [],
    )

    assert len(prompt) <= FOLLOWUP_MAX_PROMPT_CHARS
    assert "hunter2" not in prompt
    assert "secret-value" not in prompt
    assert "/home/arawn/" not in prompt
    assert "192.168.1.20" not in prompt
    assert "<redacted>" in prompt


def test_strict_response_discards_unknown_ids_and_command_fields():
    response = validate_followup_ai_response(
        context(),
        {
            "answer": "\x1b]0;forged title\x07The local fact explains the warning.",
            "referenced_fact_ids": ["fact-one", "invented-fact"],
            "requested_probe_ids": ["probe-one", "run-rm"],
            "requested_action_ids": ["action-one", "invented-action"],
            "command": "rm -rf /",
            "script": "curl example.invalid | sh",
        },
    )

    assert response.referenced_fact_ids == ["fact-one"]
    assert response.requested_probe_ids == ["probe-one"]
    assert response.requested_action_ids == ["action-one"]
    assert "\x1b" not in response.answer
    assert "\x07" not in response.answer
    assert not hasattr(response, "command")


def test_two_pass_session_runs_known_probe_then_defers_known_action(tmp_path):
    calls = []
    prompts = []

    def urlopen(request, timeout):
        calls.append(timeout)
        body = json.loads(request.data.decode("utf-8"))
        prompts.append(body["messages"][0]["content"])
        if len(calls) == 1:
            return provider_response({
                "answer": "I need one local check.",
                "referenced_fact_ids": ["fact-one"],
                "requested_probe_ids": ["probe-one"],
                "requested_action_ids": [],
            })
        return provider_response({
            "answer": "The local check verified a repair.",
            "referenced_fact_ids": ["fact-one"],
            "requested_probe_ids": [],
            "requested_action_ids": ["action-one"],
        })

    def run_probes(current, probe_ids):
        assert probe_ids == ["probe-one"]
        return current, [
            FollowUpProbeResult("probe-one", "action_ready", "Repair verified.", ["action-one"])
        ]

    answers = iter(["Please check it and fix it.", ""])
    stdout = io.StringIO()
    result = run_followup_session(
        context(),
        runtime=FollowUpRuntime(run_probes=run_probes, defer_actions=True),
        input_func=lambda _prompt: next(answers),
        stdout=stdout,
        stderr=stdout,
        env=ai_env(tmp_path),
        urlopen=urlopen,
        context_root=tmp_path / "contexts",
    )

    assert result.questions == 1
    assert result.provider_requests == 2
    assert result.actions_prepared == ["action-one"]
    assert calls == [60, 60]
    assert "Running 1 bounded local verification check" in stdout.getvalue()
    assert "Local verification result" in stdout.getvalue()
    assert "Repair verified." in stdout.getvalue()
    assert '"available_probes": []' in prompts[1]
    assert "final review after the local probe_results" in prompts[1]
    assert "workflow confirmation that follows" in stdout.getvalue()


def test_final_probe_review_rejects_a_repeated_probe_request(tmp_path):
    calls = []

    def urlopen(_request, timeout):
        calls.append(timeout)
        if len(calls) == 1:
            return provider_response({
                "answer": "I need one local check.",
                "referenced_fact_ids": ["fact-one"],
                "requested_probe_ids": ["probe-one"],
                "requested_action_ids": [],
            })
        return provider_response({
            "answer": "I will request the local check now.",
            "referenced_fact_ids": ["fact-one"],
            "requested_probe_ids": ["probe-one"],
            "requested_action_ids": [],
        })

    def run_probes(current, probe_ids):
        assert probe_ids == ["probe-one"]
        return current, [
            FollowUpProbeResult("probe-one", "ok", "The local check already completed.")
        ]

    answers = iter(["Investigate this.", ""])
    stdout = io.StringIO()
    result = run_followup_session(
        context(),
        runtime=FollowUpRuntime(run_probes=run_probes),
        input_func=lambda _prompt: next(answers),
        stdout=stdout,
        stderr=stdout,
        env=ai_env(tmp_path),
        urlopen=urlopen,
        context_root=tmp_path / "contexts",
    )

    output = stdout.getvalue()
    assert result.provider_requests == 2
    assert result.provider_failed is True
    assert "The local check already completed." in output
    assert "AI review did not complete, but AuraScan's local verification did." in output
    assert "I will request the local check now." not in output


def test_hardware_question_collects_local_context_before_first_ai_request(tmp_path):
    item = context()
    probe_calls = []
    provider_prompts = []

    def run_probes(current, probe_ids):
        probe_calls.append(list(probe_ids))
        current.facts.append(
            FollowUpFact(
                "hardware-cpu-platform",
                "hardware_cpu",
                "CPU: Intel Core i9-13900K; active microcode: 0x12f.",
                "Board: Z790 fixture; BIOS: 2.0.",
            )
        )
        return current, [
            FollowUpProbeResult(
                HARDWARE_HEALTH_PROBE_ID,
                "ok",
                "Hardware context collected.",
            )
        ]

    def urlopen(request, timeout):
        provider_prompts.append(request.data.decode("utf-8", "replace"))
        return provider_response({
            "answer": "The CPU and BIOS facts are now part of this assessment.",
            "referenced_fact_ids": ["hardware-cpu-platform"],
            "requested_probe_ids": [],
            "requested_action_ids": [],
        })

    answers = iter([
        "Could my i9-13900K, BIOS, or four RAM modules be related?",
        "",
    ])
    stdout = io.StringIO()
    result = run_followup_session(
        item,
        runtime=FollowUpRuntime(run_probes=run_probes),
        input_func=lambda _prompt: next(answers),
        stdout=stdout,
        stderr=stdout,
        env=ai_env(tmp_path),
        urlopen=urlopen,
        context_root=tmp_path / "contexts",
    )

    assert result.provider_requests == 1
    assert probe_calls == [[HARDWARE_HEALTH_PROBE_ID]]
    assert "Intel Core i9-13900K" in provider_prompts[0]
    assert "Hardware context collected" in provider_prompts[0]
    assert "Checking CPU, GPU, memory, cooling, firmware, and driver context" in stdout.getvalue()


def test_session_enforces_eight_question_limit(tmp_path):
    calls = []

    def urlopen(_request, timeout):
        calls.append(True)
        return provider_response({
            "answer": "Bounded answer.",
            "referenced_fact_ids": ["fact-one"],
            "requested_probe_ids": [],
            "requested_action_ids": [],
        })

    stdout = io.StringIO()
    result = run_followup_session(
        context(),
        input_func=lambda _prompt: "another question",
        stdout=stdout,
        stderr=stdout,
        env=ai_env(tmp_path),
        urlopen=urlopen,
        context_root=tmp_path / "contexts",
    )

    assert result.questions == 8
    assert result.provider_requests == 8
    assert len(calls) == 8
    assert "question limit reached" in stdout.getvalue()


def test_run_ask_defaults_to_latest_context(tmp_path):
    root = tmp_path / "contexts"
    persist_followup_context(context(), root)
    answers = iter(["What does this mean?", ""])
    stdout = io.StringIO()

    status = run_ask(
        [],
        input_func=lambda _prompt: next(answers),
        stdout=stdout,
        stderr=stdout,
        env=ai_env(tmp_path),
        context_root=root,
        force_interactive=True,
        urlopen=lambda _request, timeout: provider_response({
            "answer": "It describes the pending package.",
            "referenced_fact_ids": ["fact-one"],
            "requested_probe_ids": [],
            "requested_action_ids": [],
        }),
    )

    assert status == 0
    assert "pending package" in stdout.getvalue()


def test_run_ask_reports_missing_context(tmp_path):
    stderr = io.StringIO()

    status = run_ask(
        ["--latest"],
        stderr=stderr,
        stdout=io.StringIO(),
        env=ai_env(tmp_path),
        context_root=tmp_path / "missing",
        force_interactive=True,
    )

    assert status == EXIT_FOLLOWUP_UNAVAILABLE
    assert "No retained AuraScan result" in stderr.getvalue()


def test_run_ask_resolves_a_private_incident_id_directly(tmp_path):
    report_root = tmp_path / "incidents"
    report = IncidentReport(
        "incident-direct",
        "0",
        "manual",
        boot_id="a" * 32,
        evidence=[
            IncidentEvidence(
                "iev-direct",
                "journal",
                "A bounded fixture failure.",
                severity=Severity.MEDIUM,
            )
        ],
    )
    persist_incident_report(report, report_root)
    answers = iter(["What was recorded?", ""])
    stdout = io.StringIO()

    status = run_ask(
        ["incident-direct"],
        input_func=lambda _prompt: next(answers),
        stdout=stdout,
        stderr=stdout,
        env=ai_env(tmp_path),
        context_root=tmp_path / "contexts",
        incident_root=report_root,
        system_root=tmp_path / "system",
        force_interactive=True,
        urlopen=lambda _request, timeout: provider_response({
            "answer": "One bounded journal failure was recorded.",
            "referenced_fact_ids": ["iev-direct"],
            "requested_probe_ids": [],
            "requested_action_ids": [],
        }),
    )

    assert status == 0
    assert "bounded journal failure" in stdout.getvalue()
    assert latest_followup_context(tmp_path / "contexts").source_id == "incident-direct"


def test_run_ask_falls_back_to_latest_private_incident(tmp_path):
    report_root = tmp_path / "incidents"
    persist_incident_report(
        IncidentReport(
            "incident-latest",
            "0",
            "manual",
            boot_id="b" * 32,
            evidence=[
                IncidentEvidence(
                    "iev-latest",
                    "journal",
                    "A recent bounded incident.",
                    severity=Severity.LOW,
                )
            ],
        ),
        report_root,
    )
    answers = iter(["What is the latest result?", ""])
    stdout = io.StringIO()

    status = run_ask(
        [],
        input_func=lambda _prompt: next(answers),
        stdout=stdout,
        stderr=stdout,
        env=ai_env(tmp_path),
        context_root=tmp_path / "contexts",
        incident_root=report_root,
        system_root=tmp_path / "system",
        force_interactive=True,
        urlopen=lambda _request, timeout: provider_response({
            "answer": "The latest retained result is one bounded incident.",
            "referenced_fact_ids": ["iev-latest"],
            "requested_probe_ids": [],
            "requested_action_ids": [],
        }),
    )

    assert status == 0
    assert "latest retained result" in stdout.getvalue()
    assert latest_followup_context(tmp_path / "contexts").source_id == "incident-latest"


def test_run_ask_refuses_recovery_runtime(tmp_path):
    stderr = io.StringIO()

    status = run_ask(
        ["--latest"],
        stderr=stderr,
        stdout=io.StringIO(),
        env={**ai_env(tmp_path), "AURASCAN_RECOVERY_RUNTIME": "1"},
        context_root=tmp_path / "contexts",
        force_interactive=True,
    )

    assert status == EXIT_FOLLOWUP_UNAVAILABLE
    assert "not available inside AuraScan Recovery" in stderr.getvalue()


def test_standalone_provider_failure_has_its_own_exit_code(tmp_path):
    root = tmp_path / "contexts"
    persist_followup_context(context(), root)
    answers = iter(["Can you explain this?", ""])

    status = run_ask(
        [],
        input_func=lambda _prompt: next(answers),
        stderr=io.StringIO(),
        stdout=io.StringIO(),
        env=ai_env(tmp_path),
        context_root=root,
        force_interactive=True,
        urlopen=lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError("offline")),
    )

    assert status == EXIT_FOLLOWUP_PROVIDER_ERROR


def test_followup_availability_requires_ai_and_interactive_terminal(tmp_path):
    assert not followup_available(env={}, force_interactive=True)
    assert not followup_available(env=ai_env(tmp_path), force_interactive=False)
    assert followup_available(env=ai_env(tmp_path), force_interactive=True)


def test_config_context_never_persists_candidate_text_or_diff(tmp_path):
    root = tmp_path / "etc"
    root.mkdir()
    (root / "mirrorlist").write_text("old mirror\n", encoding="utf-8")
    (root / "mirrorlist.pacnew").write_text("new mirror\n", encoding="utf-8")
    report = build_config_drift_report(root)

    item = context_from_config_drift(report, ai_diffs_allowed=False)
    payload = json.dumps(item.to_dict())

    assert "old mirror" not in payload
    assert "new mirror" not in payload
    assert item.privacy_mode == "facts-only"
    assert item.actions[0].action_id == config_drift_action_id(report.apply_actions[0])


def test_config_context_includes_only_redacted_diff_after_explicit_consent(tmp_path):
    root = tmp_path / "etc"
    root.mkdir()
    (root / "mirrorlist").write_text(
        "Server = https://old.example.invalid/\npassword=hunter2\n",
        encoding="utf-8",
    )
    (root / "mirrorlist.pacnew").write_text(
        "Server = https://new.example.invalid/\npassword=new-secret\n",
        encoding="utf-8",
    )
    report = build_config_drift_report(root)

    item = context_from_config_drift(report, ai_diffs_allowed=True)
    payload = json.dumps(item.to_dict())

    assert "new.example.invalid" in payload
    assert "hunter2" not in payload
    assert "new-secret" not in payload
    assert "<redacted>" in payload
    assert item.privacy_mode == "redacted"


def test_selected_config_action_is_refused_after_contents_change(tmp_path):
    root = tmp_path / "etc"
    root.mkdir()
    target = root / "mirrorlist"
    drift = root / "mirrorlist.pacnew"
    target.write_text("old\n", encoding="utf-8")
    drift.write_text("new\n", encoding="utf-8")
    report = build_config_drift_report(root)
    action_id = config_drift_action_id(report.apply_actions[0])
    drift.write_text("different\n", encoding="utf-8")
    stdout = io.StringIO()

    status = run_config_drift(
        ["--root", str(root), "--no-ai", "--yes", "--action-id", action_id],
        stdout=stdout,
        backup_root=tmp_path / "backups",
    )

    assert status != 0
    assert target.read_text(encoding="utf-8") == "old\n"
    assert "changed or are no longer available" in stdout.getvalue()


def test_maintenance_context_exposes_lazy_incident_and_hardware_probes():
    item = context_from_maintenance(
        {"collection_status": "complete", "last_success_usec": 10},
        {
            "scan_id": "scan-one",
            "boot_id": "a" * 32,
            "severity": "HIGH",
            "categories": ["gpu"],
        },
    )

    assert item.source_type == "maintenance"
    assert [probe.probe_type for probe in item.probes] == [
        "hardware_health",
        "maintenance_incident",
    ]
    assert item.actions == []


def test_first_maintenance_question_opens_incident_analysis_before_ai(tmp_path):
    item = context_from_maintenance(
        {"collection_status": "complete", "last_success_usec": 10},
        {
            "scan_id": "scan-one",
            "boot_id": "a" * 32,
            "severity": "HIGH",
            "categories": ["gpu"],
        },
    )
    opened = []

    def run_probes(_current, probe_ids):
        opened.append(list(probe_ids))
        refreshed = FollowUpContext(
            item.context_id,
            "incident",
            "incident-one",
            "maintenance_followup",
            "Incident",
            facts=[FollowUpFact("incident-fact", "finding", "A GPU reset was recorded.")],
        )
        return refreshed, [
            FollowUpProbeResult(
                "fup-maintenance-incident",
                "ok",
                "Matching incident analysis opened.",
            )
        ]

    prompts = []

    def urlopen(request, timeout):
        body = json.loads(request.data.decode("utf-8"))
        prompt = body["messages"][0]["content"]
        prompts.append(prompt)
        return provider_response({
            "answer": "The matching incident contains one GPU reset.",
            "referenced_fact_ids": ["incident-fact"],
            "requested_probe_ids": [],
            "requested_action_ids": [],
        })

    answers = iter(["What did maintenance find?", ""])
    stdout = io.StringIO()
    result = run_followup_session(
        item,
        runtime=FollowUpRuntime(run_probes=run_probes),
        input_func=lambda _prompt: next(answers),
        stdout=stdout,
        stderr=stdout,
        env=ai_env(tmp_path),
        urlopen=urlopen,
        context_root=tmp_path / "contexts",
    )

    assert opened == [["fup-maintenance-incident"]]
    assert result.provider_requests == 1
    assert '"source_type": "incident"' in prompts[0]
    assert "Matching incident analysis opened" in prompts[0]
    assert "Opening the matching user-scoped incident analysis" in stdout.getvalue()


def test_config_drift_dry_run_offers_fact_only_followup_without_applying(monkeypatch, tmp_path):
    for key, value in ai_env(tmp_path).items():
        monkeypatch.setenv(key, value)
    root = tmp_path / "etc"
    root.mkdir()
    target = root / "mirrorlist"
    drift = root / "mirrorlist.pacnew"
    target.write_text("old\n", encoding="utf-8")
    drift.write_text("new\n", encoding="utf-8")
    answers = iter(["Why is this listed?", ""])
    stdout = io.StringIO()

    status = run_config_drift(
        ["--dry-run", "--root", str(root)],
        input_func=lambda _prompt: next(answers),
        stdout=stdout,
        stderr=stdout,
        followup_context_root=tmp_path / "contexts",
        followup_interactive=True,
        urlopen=lambda _request, timeout: provider_response({
            "answer": "The packaged mirror list differs from the active one.",
            "referenced_fact_ids": ["config-drift-summary"],
            "requested_probe_ids": [],
            "requested_action_ids": [],
        }),
    )

    assert status == 0
    assert target.read_text(encoding="utf-8") == "old\n"
    assert drift.exists()
    assert "Follow-up answer" in stdout.getvalue()


def test_upgrade_dry_run_offers_followup_after_preflight(monkeypatch, tmp_path):
    for key, value in ai_env(tmp_path).items():
        monkeypatch.setenv(key, value)
    calls = []

    def runner(command, **_kwargs):
        calls.append(list(command))
        if list(command) == [
            "sudo",
            "pacman",
            "-Syu",
            "--print",
            "--print-format",
            PACMAN_PRINT_FORMAT,
        ]:
            return subprocess.CompletedProcess(command, 0, "glibc\t2.40-1\tcore\t1\t\t\t\n", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    provider_calls = []

    def urlopen(request, timeout):
        provider_calls.append(timeout)
        body = json.loads(request.data.decode("utf-8"))
        prompt = body["messages"][0]["content"]
        if "risk_raises" in prompt:
            return provider_response({"summary": "Routine package update.", "risk_raises": []})
        return provider_response({
            "answer": "The dry run found one repository package update.",
            "referenced_fact_ids": ["upgrade-summary"],
            "requested_probe_ids": [],
            "requested_action_ids": [],
        })

    answers = iter(["What will change?", ""])
    stdout = io.StringIO()
    status = run_upgrade(
        ["--dry-run", "--aur-helper", "none", "--no-config-drift"],
        runner=runner,
        snapshot=SystemSnapshot(distro_info={"id": "arch"}, installed_packages=["glibc"]),
        input_func=lambda _prompt: next(answers),
        stdout=stdout,
        stderr=stdout,
        urlopen=urlopen,
        followup_context_root=tmp_path / "contexts",
        followup_interactive=True,
    )

    assert status == 0
    assert provider_calls == [20, 60]
    assert ["sudo", "pacman", "-Syu"] not in calls
    assert "Follow-up answer" in stdout.getvalue()


def test_upgrade_followup_provider_failure_does_not_replace_parent_status(monkeypatch, tmp_path):
    for key, value in ai_env(tmp_path).items():
        monkeypatch.setenv(key, value)

    def runner(command, **_kwargs):
        if list(command) == [
            "sudo",
            "pacman",
            "-Syu",
            "--print",
            "--print-format",
            PACMAN_PRINT_FORMAT,
        ]:
            return subprocess.CompletedProcess(command, 0, "glibc\t2.40-1\tcore\t1\t\t\t\n", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    provider_calls = []

    def urlopen(request, timeout):
        provider_calls.append(timeout)
        if timeout == 20:
            return provider_response({"summary": "Routine package update.", "risk_raises": []})
        raise OSError("provider unavailable")

    stdout = io.StringIO()
    status = run_upgrade(
        ["--dry-run", "--aur-helper", "none", "--no-config-drift"],
        runner=runner,
        snapshot=SystemSnapshot(distro_info={"id": "arch"}, installed_packages=["glibc"]),
        input_func=lambda _prompt: "What changed?",
        stdout=stdout,
        stderr=stdout,
        urlopen=urlopen,
        followup_context_root=tmp_path / "contexts",
        followup_interactive=True,
    )

    assert status == 0
    assert provider_calls == [20, 60]
    assert "original AuraScan result remains valid" in stdout.getvalue()


def test_incident_foreground_flow_offers_followup_but_service_capture_does_not(
    monkeypatch,
    tmp_path,
):
    env = ai_env(tmp_path)
    report = IncidentReport(
        "incident-fixture",
        "0",
        "manual",
        boot_id="a" * 32,
        evidence=[
            IncidentEvidence(
                "iev-one",
                "journal",
                "A bounded fixture service failed.",
                severity=Severity.MEDIUM,
            )
        ],
    )
    monkeypatch.setattr(
        "aurascan.core.incidents.build_incident_report",
        lambda *_args, **_kwargs: report,
    )
    monkeypatch.setattr(
        "aurascan.core.incident_repairs.plan_repair_actions",
        lambda *_args, **_kwargs: [],
    )

    def guided(item, **_kwargs):
        item.ai_review = {"enabled": True, "status": "ok", "summary": "Fixture review."}

    monkeypatch.setattr(
        "aurascan.core.incident_diagnostics.prepare_ai_guided_repair_plan",
        guided,
    )
    answers = iter(["What failed?", ""])
    stdout = io.StringIO()
    status = run_incidents(
        ["--current-boot"],
        input_func=lambda _prompt: next(answers),
        stdout=stdout,
        stderr=stdout,
        env=env,
        user_root=tmp_path / "incidents",
        system_root=tmp_path / "system",
        urlopen=lambda _request, timeout: provider_response({
            "answer": "The bounded report contains one service failure.",
            "referenced_fact_ids": ["iev-one"],
            "requested_probe_ids": [],
            "requested_action_ids": [],
        }),
        followup_context_root=tmp_path / "contexts",
        followup_interactive=True,
    )

    assert status == 0
    assert "Follow-up answer" in stdout.getvalue()

    monkeypatch.setattr(os, "geteuid", lambda: 0)
    service_stdout = io.StringIO()
    status = run_incidents(
        ["--capture-monitor"],
        input_func=lambda _prompt: (_ for _ in ()).throw(AssertionError("service prompted")),
        stdout=service_stdout,
        stderr=service_stdout,
        env=env,
        system_root=tmp_path / "system-service",
        urlopen=lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("service called AI")),
        followup_interactive=True,
    )

    assert status == 0


def test_manual_maintenance_offers_one_followup_prompt(monkeypatch, tmp_path):
    env = ai_env(tmp_path)
    monkeypatch.setattr("aurascan.core.incidents.run_maintenance_now", lambda **_kwargs: 0)
    monkeypatch.setattr(
        "aurascan.core.incidents.load_maintenance_status",
        lambda _path: {"collection_status": "complete", "last_success_usec": 10},
    )
    prompts = []

    status = run_incidents(
        ["--run-maintenance"],
        input_func=lambda prompt: prompts.append(prompt) or "",
        stdout=io.StringIO(),
        stderr=io.StringIO(),
        env=env,
        user_root=tmp_path / "incidents",
        system_root=tmp_path / "system",
        followup_context_root=tmp_path / "contexts",
        followup_interactive=True,
    )

    assert status == 0
    assert prompts == ["Ask AuraScan about this result, or press Enter to finish: "]
