import hashlib
import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from aurascan.core.incident_repairs import (
    RECIPE_ORDER,
    SAFE_NAME_RE,
    SAFE_UNIT_RE,
    parse_package_owner,
    plan_dkms_autoinstall,
    plan_exact_package_reinstall,
    plan_initramfs_rebuild,
    plan_kernel_headers,
    plan_package_cache_cleanup,
    plan_repository_restore,
    plan_service_restart,
    plan_stale_lock,
)
from aurascan.core.incidents import (
    DiagnosticProbe,
    DiagnosticProbeResult,
    IncidentReport,
    RepairAction,
    bounded_ai_system_facts,
    redact_incident_text,
    run_bounded_command,
)


INCIDENT_MAX_PROBE_CANDIDATES = 24
INCIDENT_MAX_AI_REQUESTED_PROBES = 6
INCIDENT_MAX_EXECUTED_PROBES = 12
INCIDENT_PROBE_DEADLINE_SECONDS = 180
INCIDENT_BACKGROUND_PLAN_MAX_AGE_SECONDS = 6 * 60 * 60

PROBE_PRIORITY = {
    "repository_health": 10,
    "stale_pacman_lock": 20,
    "package_cache": 30,
    "kernel_module": 40,
    "initramfs": 50,
    "failed_service": 60,
    "package_integrity": 70,
    "service_package_integrity": 80,
    "evidence_package_integrity": 90,
}


def diagnostic_probe_id(probe_type: str, target: Mapping[str, object]) -> str:
    material = json.dumps({"probe_type": probe_type, "target": dict(target)}, sort_keys=True)
    return "idp-" + hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()[:16]


def make_probe(
    probe_type: str,
    title: str,
    summary: str,
    target: Mapping[str, object],
    *,
    evidence_ids: Sequence[str] = (),
    required: bool = False,
) -> DiagnosticProbe:
    bounded_target = dict(target)
    return DiagnosticProbe(
        probe_id=diagnostic_probe_id(probe_type, bounded_target),
        probe_type=probe_type,
        title=redact_incident_text(title)[:240],
        summary=redact_incident_text(summary)[:500],
        target=bounded_target,
        evidence_ids=[str(item) for item in evidence_ids[:12]],
        priority=PROBE_PRIORITY.get(probe_type, 100),
        required=required,
        affects_plan=True,
    )


def discover_diagnostic_probes(report: IncidentReport) -> List[DiagnosticProbe]:
    categories = {finding.category for finding in report.findings}
    category_evidence: Dict[str, List[str]] = {}
    for finding in report.findings:
        category_evidence.setdefault(finding.category, []).extend(finding.evidence_ids)
    probes: List[DiagnosticProbe] = []

    def add(probe: DiagnosticProbe) -> None:
        if probe.probe_id not in {item.probe_id for item in probes}:
            probes.append(probe)

    if "repository" in categories:
        add(make_probe(
            "repository_health",
            "Recheck repository recovery",
            "Verify current repository includes and packaged backup mirrorlists.",
            {"pacman_conf_path": "/etc/pacman.conf"},
            evidence_ids=category_evidence.get("repository", []),
            required=True,
        ))
    if "package_manager" in categories:
        add(make_probe(
            "stale_pacman_lock",
            "Recheck package-manager lock state",
            "Verify that the pacman lock still exists, is old enough, and no package manager is active.",
            {"lock_path": "/var/lib/pacman/db.lck"},
            evidence_ids=category_evidence.get("package_manager", []),
            required=True,
        ))
    if "disk_space" in categories:
        add(make_probe(
            "package_cache",
            "Measure safe package-cache cleanup",
            "Use paccache's read-only preview to measure reclaimable space while retaining two versions.",
            {"cache_root": "/var/cache/pacman/pkg", "target_boot": report.target_boot},
            evidence_ids=category_evidence.get("disk_space", []),
            required=True,
        ))
    if "kernel_module" in categories or "gpu" in categories:
        evidence = category_evidence.get("kernel_module", []) + category_evidence.get("gpu", [])
        add(make_probe(
            "kernel_module",
            "Recheck kernel, headers, and DKMS",
            "Verify installed kernel families, matching headers, and current DKMS status.",
            {},
            evidence_ids=evidence,
            required="kernel_module" in categories,
        ))
    if "initramfs" in categories:
        add(make_probe(
            "initramfs",
            "Check guarded initramfs recovery",
            "Verify the installed generator and whether a backed-up rebuild recipe can be prepared.",
            {"target_boot": report.target_boot},
            evidence_ids=category_evidence.get("initramfs", []),
            required=True,
        ))

    failed_units: Dict[Tuple[str, bool], List[str]] = {}
    for item in report.evidence:
        if item.source not in {"systemctl", "systemctl-user"} or not SAFE_UNIT_RE.fullmatch(item.unit):
            continue
        key = (item.unit, item.source == "systemctl-user")
        failed_units.setdefault(key, []).append(item.evidence_id)
    for (unit, user_service), evidence_ids in list(sorted(failed_units.items()))[:4]:
        target = {"unit": unit, "user_service": user_service}
        add(make_probe(
            "failed_service",
            f"Recheck failed {'user ' if user_service else ''}service {unit}",
            "Confirm that this noncritical unit is still failed before preparing a restart.",
            target,
            evidence_ids=evidence_ids,
            required=True,
        ))
        add(make_probe(
            "service_package_integrity",
            f"Inspect package files for {unit}",
            "Resolve the unit file to its owning official package and check immutable files and signed cache recovery.",
            target,
            evidence_ids=evidence_ids,
        ))

    for group in report.coredumps[:12]:
        package = group.package.strip()
        executable = group.executable.strip()
        if package and not SAFE_NAME_RE.fullmatch(package):
            package = ""
        if executable and ("/" in executable or len(executable) > 200):
            executable = ""
        if not package and not executable:
            continue
        add(make_probe(
            "package_integrity",
            f"Inspect package integrity for {package or executable}",
            "Check package ownership, official-package status, immutable files, and an exact signed cached archive.",
            {"package": package, "executable": executable},
            evidence_ids=group.evidence_ids,
            required=group.desktop_component or group.count >= 3,
        ))

    coredump_evidence = {item for group in report.coredumps for item in group.evidence_ids}
    for item in report.evidence:
        if item.evidence_id in coredump_evidence:
            continue
        package = item.package.strip()
        executable = item.executable.strip()
        if package and not SAFE_NAME_RE.fullmatch(package):
            package = ""
        if executable and ("/" in executable or len(executable) > 200):
            executable = ""
        if not package and not executable:
            continue
        add(make_probe(
            "evidence_package_integrity",
            f"Inspect implicated package for {package or executable}",
            "Resolve this locally observed executable to an official package and verify immutable files before considering reinstall.",
            {"package": package, "executable": executable},
            evidence_ids=[item.evidence_id],
        ))
        if len(probes) >= INCIDENT_MAX_PROBE_CANDIDATES:
            break

    probes.sort(key=lambda item: (not item.required, item.priority, item.probe_id))
    return probes[:INCIDENT_MAX_PROBE_CANDIDATES]


def select_probe_ids(probes: Sequence[DiagnosticProbe], ai_requested_ids: Sequence[str]) -> List[str]:
    known = {item.probe_id for item in probes}
    requested: List[str] = []
    for raw in ai_requested_ids:
        probe_id = str(raw)
        if probe_id in known and probe_id not in requested:
            requested.append(probe_id)
        if len(requested) >= INCIDENT_MAX_AI_REQUESTED_PROBES:
            break
    selected = [item.probe_id for item in probes if item.required]
    for probe_id in requested:
        if probe_id not in selected:
            selected.append(probe_id)
    return selected[:INCIDENT_MAX_EXECUTED_PROBES]


def execute_diagnostic_probes(
    report: IncidentReport,
    probes: Sequence[DiagnosticProbe],
    probe_ids: Sequence[str],
    *,
    ai_requested_ids: Sequence[str] = (),
    deterministic_probe_ids: Sequence[str] = (),
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
    deadline_seconds: int = INCIDENT_PROBE_DEADLINE_SECONDS,
    clock: Callable[[], float] = time.monotonic,
) -> Tuple[List[DiagnosticProbeResult], List[RepairAction]]:
    candidates = {item.probe_id: item for item in probes}
    ai_requested = set(str(item) for item in ai_requested_ids)
    deterministic = {item.probe_id for item in probes if item.required} | {str(item) for item in deterministic_probe_ids}
    deadline = clock() + max(1, int(deadline_seconds))
    results: List[DiagnosticProbeResult] = []
    actions: List[RepairAction] = []
    seen = set()
    for raw_id in probe_ids[:INCIDENT_MAX_EXECUTED_PROBES]:
        probe_id = str(raw_id)
        probe = candidates.get(probe_id)
        if probe is None or probe_id in seen:
            continue
        seen.add(probe_id)
        requested_by = (
            "deterministic+ai" if probe_id in deterministic and probe_id in ai_requested
            else "deterministic" if probe_id in deterministic
            else "ai"
        )
        started = clock()
        if started >= deadline:
            results.append(DiagnosticProbeResult(
                probe_id,
                probe.probe_type,
                "timeout",
                "The bounded diagnostic-probe deadline was reached before this check could run.",
                requested_by=requested_by,
                evidence_ids=probe.evidence_ids,
                affects_plan=probe.affects_plan,
            ))
            continue
        try:
            status, summary, prepared = _execute_probe(report, probe, runner=runner, which=which)
        except Exception as exc:
            status, summary, prepared = "failed", redact_incident_text(str(exc))[:500], []
        elapsed_ms = max(0, int((clock() - started) * 1000))
        actions.extend(prepared)
        results.append(DiagnosticProbeResult(
            probe_id,
            probe.probe_type,
            status,
            redact_incident_text(summary)[:500],
            requested_by=requested_by,
            evidence_ids=probe.evidence_ids,
            action_ids=[item.action_id for item in prepared],
            affects_plan=probe.affects_plan,
            duration_ms=elapsed_ms,
        ))
    return results, merge_repair_actions([], actions)


def _execute_probe(
    report: IncidentReport,
    probe: DiagnosticProbe,
    *,
    runner: Callable,
    which: Callable[[str], Optional[str]],
) -> Tuple[str, str, List[RepairAction]]:
    target = probe.target
    prepared: List[RepairAction] = []
    if probe.probe_type == "repository_health":
        action = plan_repository_restore(Path("/etc/pacman.conf"))
        if action:
            prepared.append(action)
    elif probe.probe_type == "stale_pacman_lock":
        lock = Path("/var/lib/pacman/db.lck")
        if lock.exists():
            action = plan_stale_lock(lock)
            if action:
                prepared.append(action)
    elif probe.probe_type == "package_cache":
        if not which("paccache"):
            return "unavailable", "paccache is unavailable, so AuraScan could not preview bounded cache cleanup.", []
        action = plan_package_cache_cleanup(
            runner=runner,
            cache_root=Path("/var/cache/pacman/pkg"),
            target_boot=report.target_boot,
        )
        if action:
            prepared.append(action)
    elif probe.probe_type == "kernel_module":
        if not which("pacman"):
            return "unavailable", "pacman is unavailable, so installed kernel and header packages could not be verified.", []
        installed_output = run_bounded_command(runner, ["pacman", "-Qq"], max_chars=256000, timeout=60)
        if installed_output.returncode != 0 or installed_output.truncated:
            return "failed", "AuraScan could not read the installed package set for kernel/module verification.", []
        installed = [line.strip() for line in installed_output.stdout.splitlines() if line.strip()]
        if not installed:
            return "failed", "AuraScan received an empty installed package set during kernel/module verification.", []
        for action in (
            plan_kernel_headers(installed, runner=runner),
            plan_dkms_autoinstall(installed, runner=runner, which=which),
        ):
            if action:
                prepared.append(action)
    elif probe.probe_type == "initramfs":
        if not which("mkinitcpio") and not which("dracut"):
            return "unavailable", "No supported initramfs generator is installed.", []
        action = plan_initramfs_rebuild(which=which, target_boot=report.target_boot)
        if action:
            prepared.append(action)
    elif probe.probe_type == "failed_service":
        unit = str(target.get("unit") or "")
        user_service = bool(target.get("user_service", False))
        if not SAFE_UNIT_RE.fullmatch(unit) or not which("systemctl"):
            return "unavailable", "The service target or systemctl is unavailable for a bounded state check.", []
        prefix = ["systemctl", "--user"] if user_service else ["systemctl"]
        state = run_bounded_command(runner, prefix + ["is-failed", unit], max_chars=4000, timeout=15)
        if state.returncode not in {0, 1}:
            return "failed", f"systemctl could not verify the current failed state of {unit}.", []
        if state.stdout.strip() != "failed":
            return "no_action", f"{unit} is no longer in a failed state.", []
        action = plan_service_restart(unit, user_service=user_service)
        if action:
            prepared.append(action)
    elif probe.probe_type == "service_package_integrity":
        unit = str(target.get("unit") or "")
        user_service = bool(target.get("user_service", False))
        if not SAFE_UNIT_RE.fullmatch(unit) or not which("systemctl") or not which("pacman"):
            return "unavailable", "The service package could not be resolved with the installed local tools.", []
        prefix = ["systemctl", "--user"] if user_service else ["systemctl"]
        fragment = run_bounded_command(
            runner,
            prefix + ["show", unit, "--property=FragmentPath", "--value"],
            max_chars=4096,
            timeout=15,
        )
        path = fragment.stdout.strip()
        if fragment.returncode != 0 or not path.startswith("/") or "\n" in path:
            return "no_action", "AuraScan could not resolve this unit to a regular package-owned fragment.", []
        owner = run_bounded_command(runner, ["pacman", "-Qo", path], max_chars=4096, timeout=15)
        package = parse_package_owner(owner.stdout) if owner.returncode == 0 else ""
        if not SAFE_NAME_RE.fullmatch(package):
            return "no_action", "The unit fragment is not owned by a supported official package target.", []
        action = plan_exact_package_reinstall("", package, runner=runner, which=which, cache_root=Path("/var/cache/pacman/pkg"))
        if action:
            prepared.append(action)
    elif probe.probe_type in {"package_integrity", "evidence_package_integrity"}:
        package = str(target.get("package") or "")
        executable = str(target.get("executable") or "")
        if package and not SAFE_NAME_RE.fullmatch(package):
            return "failed", "The locally generated package target no longer passes validation.", []
        if not package and (not executable or "/" in executable or len(executable) > 200):
            return "failed", "The locally generated executable target no longer passes validation.", []
        if not which("pacman"):
            return "unavailable", "pacman is unavailable for package ownership and integrity checks.", []
        action = plan_exact_package_reinstall(
            executable,
            package,
            runner=runner,
            which=which,
            cache_root=Path("/var/cache/pacman/pkg"),
        )
        if action:
            prepared.append(action)
    else:
        return "failed", "AuraScan rejected an unknown diagnostic probe type.", []

    if prepared:
        titles = "; ".join(item.title for item in prepared)
        return "action_ready", f"Local verification prepared: {titles}", prepared
    return "no_action", "The local check completed and did not prove that a repair is currently required.", []


def merge_repair_actions(existing: Sequence[RepairAction], additional: Sequence[RepairAction]) -> List[RepairAction]:
    merged: Dict[str, RepairAction] = {}
    for action in list(existing) + list(additional):
        if action.action_id and action.eligible and action.verified:
            merged[action.action_id] = action
    return sorted(merged.values(), key=lambda item: (RECIPE_ORDER.get(item.recipe_id, 999), item.action_id))


def incident_analysis_fingerprint(report: IncidentReport) -> str:
    payload = {
        "boot_id": report.boot_id,
        "target_boot": report.target_boot,
        "collection_status": report.collection_status,
        "truncated": report.truncated,
        "findings": [
            {
                "rule_id": item.rule_id,
                "severity": item.severity.value,
                "category": item.category,
                "evidence_ids": list(item.evidence_ids),
            }
            for item in report.findings
        ],
        "coredumps": [
            {"signature": item.signature, "count": item.count, "evidence_ids": list(item.evidence_ids)}
            for item in report.coredumps
        ],
        "system_facts": bounded_ai_system_facts(report.system_facts),
    }
    material = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()


def repair_plan_fingerprint(report: IncidentReport) -> str:
    payload = {
        "actions": [item.action_id for item in report.eligible_actions],
        "probes": [
            {
                "probe_id": item.probe_id,
                "status": item.status,
                "action_ids": list(item.action_ids),
            }
            for item in report.probe_results
        ],
    }
    material = json.dumps(payload, sort_keys=True)
    return hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()


def prepare_ai_guided_repair_plan(
    report: IncidentReport,
    *,
    disabled: bool,
    facts_only: bool,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
    urlopen: Optional[Callable] = None,
    env: Optional[Mapping[str, str]] = None,
    cached_report: Optional[IncidentReport] = None,
    progress_callback: Optional[Callable[[str], None]] = None,
    ai_reviewer: Optional[Callable] = None,
) -> None:
    if ai_reviewer is None:
        from aurascan.core.incidents import apply_ai_incident_review

        ai_reviewer = apply_ai_incident_review

    report.diagnostic_probes = discover_diagnostic_probes(report)
    analysis_fingerprint = incident_analysis_fingerprint(report)
    automation = {
        "analysis_fingerprint": analysis_fingerprint,
        "candidate_probe_count": len(report.diagnostic_probes),
        "provider_requests": 0,
        "cache_used": False,
    }
    report.automation["ai_guided_repair"] = automation
    if disabled:
        ai_reviewer(report, disabled=True)
        automation["status"] = "disabled"
        return

    cached_usable = bool(
        cached_report is not None
        and incident_analysis_fingerprint(cached_report) == analysis_fingerprint
        and isinstance(cached_report.ai_review.get("triage"), Mapping)
        and cached_report.ai_review.get("triage", {}).get("status") == "ok"
    )
    if cached_usable and cached_report is not None:
        report.ai_review = dict(cached_report.ai_review)
        automation["cache_used"] = True
        automation["cached_report_id"] = cached_report.incident_id
    else:
        if progress_callback:
            progress_callback("Asking AI which local diagnostic checks are useful")
        ai_reviewer(
            report,
            facts_only=facts_only,
            phase="triage",
            probes=report.diagnostic_probes,
            urlopen=urlopen,
            env=env,
        )
        automation["provider_requests"] = 1

    triage = report.ai_review.get("triage", {}) if isinstance(report.ai_review, Mapping) else {}
    triage_ok = isinstance(triage, Mapping) and triage.get("status") == "ok"
    requested_ids = list(triage.get("requested_probe_ids", [])) if triage_ok else []
    fallback_ids = []
    if not triage_ok:
        fallback_ids = [item.probe_id for item in report.diagnostic_probes if not item.required][:INCIDENT_MAX_AI_REQUESTED_PROBES]
    selected_ids = select_probe_ids(report.diagnostic_probes, requested_ids + fallback_ids)
    automation["requested_probe_count"] = len([item for item in requested_ids if item in {probe.probe_id for probe in report.diagnostic_probes}])
    automation["selected_probe_count"] = len(selected_ids)
    if selected_ids:
        if progress_callback:
            progress_callback(f"Running {len(selected_ids)} bounded local verification check(s)")
        results, additional_actions = execute_diagnostic_probes(
            report,
            report.diagnostic_probes,
            selected_ids,
            ai_requested_ids=requested_ids,
            deterministic_probe_ids=fallback_ids,
            runner=runner,
            which=which,
        )
        report.probe_results = results
        report.repair_actions = merge_repair_actions(report.repair_actions, additional_actions)

    automation["completed_probe_count"] = len(report.probe_results)
    automation["repair_plan_fingerprint"] = repair_plan_fingerprint(report)
    if not report.probe_results or not triage_ok:
        automation["status"] = "triage_only" if triage_ok else str(report.ai_review.get("status") or "unavailable")
        return

    cached_final_usable = bool(
        cached_usable
        and cached_report is not None
        and repair_plan_fingerprint(cached_report) == automation["repair_plan_fingerprint"]
        and isinstance(cached_report.ai_review.get("final"), Mapping)
        and cached_report.ai_review.get("final", {}).get("status") == "ok"
    )
    if cached_final_usable and cached_report is not None:
        report.ai_review = dict(cached_report.ai_review)
        automation["status"] = "ok"
        return

    if progress_callback:
        progress_callback("Asking AI to explain and prioritize the verified repair plan")
    ai_reviewer(
        report,
        facts_only=facts_only,
        phase="final",
        probes=report.diagnostic_probes,
        probe_results=report.probe_results,
        urlopen=urlopen,
        env=env,
    )
    automation["provider_requests"] = int(automation["provider_requests"]) + 1
    automation["status"] = str(report.ai_review.get("status") or "unknown")
