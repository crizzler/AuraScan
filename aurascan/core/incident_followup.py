"""Incident-family follow-up adapters.

The follow-up framework (:mod:`aurascan.core.followup`) owns contexts, sessions,
prompts, persistence and advisory text for every lifecycle. The *incident*
lifecycle's adapters - loading a retained incident result, and building the
runtime that refreshes incident state, runs diagnostic probes and applies
verified repairs - live here instead, so the generic framework never imports the
incident workflow, its diagnostics planner or its repair planner.

Everything in this module is incident authority: report collection, marker
acknowledgement, repair planning/execution and post-repair summarisation. The
framework calls these adapters through the providers its callers supply, and
fails closed when no provider is available rather than acting on stale state.
"""

import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from aurascan.core.followup import (
    FOLLOWUP_PROBE_MAINTENANCE_INCIDENT,
    FollowUpAction,
    FollowUpActionOutcome,
    FollowUpContext,
    FollowUpProbeResult,
    FollowUpRuntime,
    _confirm_action_plan,
    _print_action_plan,
    context_from_incident,
    current_user_uid,
    with_hardware_health_runtime,
)


def context_from_saved_incident(
    incident_id: str,
    *,
    env: Optional[Mapping[str, str]] = None,
    incident_root: Optional[Path] = None,
) -> Optional[FollowUpContext]:
    from aurascan.core.incidents import load_incident_report, resolve_incident_config, user_incident_root

    root = incident_root or user_incident_root(env)
    report = load_incident_report(incident_id, root)
    if report is None:
        return None
    config = resolve_incident_config(env)
    privacy_mode = "facts-only" if not config.error and config.ai_evidence == "facts-only" else "redacted"
    return context_from_incident(report, privacy_mode=privacy_mode)


def context_from_latest_saved_incident(
    *,
    env: Optional[Mapping[str, str]] = None,
    incident_root: Optional[Path] = None,
) -> Optional[FollowUpContext]:
    from aurascan.core.incidents import list_incident_reports, user_incident_root

    root = incident_root or user_incident_root(env)
    history = list_incident_reports(root)
    for item in history:
        incident_id = str(item.get("incident_id") or "")
        if not incident_id:
            continue
        context = context_from_saved_incident(
            incident_id,
            env=env,
            incident_root=root,
        )
        if context is not None:
            return context
    return None


def build_incident_runtime(
    initial_context: FollowUpContext,
    *,
    env: Optional[Mapping[str, str]],
    runner: Callable,
    which: Callable,
    context_root: Optional[Path],
    incident_root: Optional[Path],
    system_root: Optional[Path],
    report_override=None,
    defer_actions: bool = False,
) -> FollowUpRuntime:
    from aurascan.core.incident_diagnostics import (
        discover_diagnostic_probes,
        execute_diagnostic_probes,
        merge_repair_actions,
    )
    from aurascan.core.incident_repairs import apply_repair_plan, plan_repair_actions
    from aurascan.core.incident_models import (
        INCIDENT_REPAIR_ROOT,
        INCIDENT_SYSTEM_ROOT,
    )
    from aurascan.core.incidents import (
        build_incident_report,
        current_user_uid,
        incident_reviewed_state_path,
        load_incident_report,
        mark_pending_markers_seen,
        persist_incident_report,
        resolve_incident_config,
        summarize_post_repair,
        unseen_pending_markers,
        user_incident_root,
    )

    source = dict(os.environ if env is None else env)
    reports = incident_root or user_incident_root(source)
    incident_system_root = system_root or INCIDENT_SYSTEM_ROOT
    repairs = incident_system_root / "repairs"
    state = {"report": report_override}

    def load_report():
        report = state.get("report")
        if report is not None:
            return report
        report = load_incident_report(initial_context.source_id, reports)
        if report is None:
            target = str(initial_context.metadata.get("target_boot") or initial_context.metadata.get("boot_id") or "0")
            report = build_incident_report(target, trigger="followup", runner=runner, which=which)
            report.repair_actions = plan_repair_actions(
                report,
                runner=runner,
                which=which,
                include_package_integrity=True,
            )
            report.diagnostic_probes = discover_diagnostic_probes(report)
            persist_incident_report(report, reports)
        state["report"] = report
        return report

    def probes_callback(
        current: FollowUpContext,
        probe_ids: Sequence[str],
    ) -> Tuple[FollowUpContext, Sequence[FollowUpProbeResult]]:
        report = load_report()
        candidates = discover_diagnostic_probes(report)
        known = {item.probe_id for item in candidates}
        selected = [item for item in probe_ids if item in known][:6]
        results, actions = execute_diagnostic_probes(
            report,
            candidates,
            selected,
            ai_requested_ids=selected,
            runner=runner,
            which=which,
        )
        report.diagnostic_probes = candidates
        existing_results = {item.probe_id: item for item in report.probe_results}
        for item in results:
            existing_results[item.probe_id] = item
        report.probe_results = list(existing_results.values())[:12]
        report.repair_actions = merge_repair_actions(report.repair_actions, actions)
        persist_incident_report(report, reports)
        config = resolve_incident_config(source)
        privacy = "facts-only" if not config.error and config.ai_evidence == "facts-only" else current.privacy_mode
        refreshed = context_from_incident(
            report,
            context_id=current.context_id,
            metadata={
                key: value
                for key, value in current.metadata.items()
                if key not in {"action_probe_map"}
            },
            privacy_mode=privacy,
        )
        state["report"] = report
        return refreshed, [
            FollowUpProbeResult(item.probe_id, item.status, item.summary, list(item.action_ids))
            for item in results
        ]

    def actions_callback(
        current: FollowUpContext,
        action_ids: Sequence[str],
        input_func: Callable[[str], str],
        stdout,
        stderr,
    ) -> FollowUpActionOutcome:
        report = load_report()
        fresh = build_incident_report(
            str(current.metadata.get("target_boot") or report.target_boot or "0"),
            trigger="followup_revalidation",
            runner=runner,
            which=which,
        )
        fresh.repair_actions = plan_repair_actions(
            fresh,
            runner=runner,
            which=which,
            include_package_integrity=True,
        )
        fresh.diagnostic_probes = discover_diagnostic_probes(fresh)
        action_probe_map = current.metadata.get("action_probe_map", {})
        needed_probes = []
        if isinstance(action_probe_map, Mapping):
            for action_id in action_ids:
                raw = action_probe_map.get(action_id, [])
                if isinstance(raw, list):
                    needed_probes.extend(str(item) for item in raw)
        if needed_probes:
            probe_results, probe_actions = execute_diagnostic_probes(
                fresh,
                fresh.diagnostic_probes,
                list(dict.fromkeys(needed_probes))[:12],
                ai_requested_ids=needed_probes,
                runner=runner,
                which=which,
            )
            fresh.probe_results = probe_results
            fresh.repair_actions = merge_repair_actions(fresh.repair_actions, probe_actions)
        by_id = {item.action_id: item for item in fresh.eligible_actions}
        selected = [by_id[item] for item in action_ids if item in by_id]
        if not selected:
            return FollowUpActionOutcome(
                attempted=True,
                source_changed=True,
                message="AuraScan refreshed the incident state; the requested repair is no longer verified or required.",
            )
        _print_action_plan(
            [
                FollowUpAction(
                    item.action_id,
                    item.title,
                    item.summary,
                    item.risk.value,
                    item.eligible and item.verified,
                    item.reversible,
                )
                for item in selected
            ],
            stdout,
        )
        default_yes = bool(
            fresh.collection_status == "complete"
            and not fresh.truncated
            and not any(item.severity.value in {"HIGH", "CRITICAL"} for item in fresh.findings)
            and all(item.risk.value in {"LOW", "MEDIUM"} for item in selected)
            and all(item.reversible for item in selected)
        )
        if not _confirm_action_plan(input_func, default_yes):
            return FollowUpActionOutcome(attempted=True, message="[AuraScan] Follow-up repair was not applied.")
        results, ok = apply_repair_plan(
            selected,
            runner=runner,
            which=which,
            stdout=stdout,
            stderr=stderr,
            repair_root=repairs if system_root is not None else INCIDENT_REPAIR_ROOT,
        )
        fresh.repair_results.extend(results)
        after = build_incident_report(
            fresh.target_boot,
            trigger="post_repair",
            runner=runner,
            which=which,
        )
        fresh.post_repair = summarize_post_repair(fresh, after)
        persist_incident_report(fresh, reports)
        state["report"] = fresh
        acknowledged = 0
        if ok and results and (
            bool(current.metadata.get("resolve_pending"))
            or bool(current.metadata.get("maintenance_source_id"))
        ):
            reviewed_path = incident_reviewed_state_path(source, report_root=reports)
            markers = unseen_pending_markers(
                uid=current_user_uid(),
                marker_root=incident_system_root / "pending",
                seen_path=reviewed_path,
                include_resolved=True,
            )
            boot_id = str(fresh.boot_id or current.metadata.get("boot_id") or "").replace("-", "")
            scan_id = str(current.metadata.get("maintenance_source_id") or "")
            matching = [
                item
                for item in markers
                if (
                    boot_id
                    and str(item.get("boot_id") or "").replace("-", "") == boot_id
                )
                or (
                    scan_id
                    and str(item.get("scan_id") or "") == scan_id
                )
            ]
            mark_pending_markers_seen(matching, seen_path=reviewed_path)
            acknowledged = len(matching)
        return FollowUpActionOutcome(
            attempted=True,
            applied=ok and bool(results),
            failed=not ok,
            source_changed=True,
            message=(
                (
                    f"[AuraScan] Applied and checked {len(results)} follow-up repair(s). "
                    f"Acknowledged {acknowledged} matching tray alert(s)."
                    if acknowledged
                    else f"[AuraScan] Applied and checked {len(results)} follow-up repair(s)."
                )
                if ok
                else "[AuraScan] Follow-up repair stopped after fresh validation or execution failed."
            ),
        )

    return with_hardware_health_runtime(
        initial_context,
        FollowUpRuntime(
            run_probes=probes_callback,
            run_actions=actions_callback,
            defer_actions=defer_actions,
        ),
        runner=runner,
        which=which,
    )


def build_maintenance_runtime(
    initial_context: FollowUpContext,
    *,
    env: Optional[Mapping[str, str]],
    runner: Callable,
    which: Callable,
    context_root: Optional[Path],
    incident_root: Optional[Path],
    system_root: Optional[Path],
) -> FollowUpRuntime:
    state: Dict[str, object] = {"incident_runtime": None, "incident_context": None}

    def probes_callback(
        current: FollowUpContext,
        probe_ids: Sequence[str],
    ) -> Tuple[FollowUpContext, Sequence[FollowUpProbeResult]]:
        if FOLLOWUP_PROBE_MAINTENANCE_INCIDENT not in probe_ids:
            runtime = state.get("incident_runtime")
            incident_context = state.get("incident_context")
            if (
                isinstance(runtime, FollowUpRuntime)
                and isinstance(incident_context, FollowUpContext)
                and runtime.run_probes is not None
            ):
                refreshed, results = runtime.run_probes(incident_context, probe_ids)
                state["incident_context"] = refreshed
                return refreshed, results
            return current, []
        from aurascan.core.incident_diagnostics import discover_diagnostic_probes
        from aurascan.core.incident_repairs import plan_repair_actions
        from aurascan.core.incidents import build_incident_report, persist_incident_report, resolve_incident_config, user_incident_root

        target = str(current.metadata.get("boot_id") or "0")
        report = build_incident_report(target, trigger="maintenance_followup", runner=runner, which=which)
        report.repair_actions = plan_repair_actions(
            report,
            runner=runner,
            which=which,
            include_package_integrity=True,
        )
        report.diagnostic_probes = discover_diagnostic_probes(report)
        reports = incident_root or user_incident_root(env)
        marker = current.metadata.get("marker")
        if isinstance(marker, Mapping):
            from aurascan.core.incident_automation import load_reusable_background_plan
            from aurascan.core.incident_diagnostics import merge_repair_actions

            cached = load_reusable_background_plan(report, marker, reports)
            if cached is not None:
                report.ai_review = dict(cached.ai_review)
                report.probe_results = list(cached.probe_results)[:12]
                report.repair_actions = merge_repair_actions(
                    report.repair_actions,
                    cached.repair_actions,
                )
                report.automation["followup_background_plan"] = {
                    "status": "reused",
                    "source_report_id": cached.incident_id,
                }
        persist_incident_report(report, reports)
        config = resolve_incident_config(env)
        privacy = "facts-only" if not config.error and config.ai_evidence == "facts-only" else "redacted"
        refreshed = context_from_incident(
            report,
            context_id=current.context_id,
            metadata={
                "maintenance_source_id": current.source_id,
                "resolve_pending": True,
            },
            privacy_mode=privacy,
        )
        runtime = build_incident_runtime(
            refreshed,
            env=env,
            runner=runner,
            which=which,
            context_root=context_root,
            incident_root=reports,
            system_root=system_root,
            report_override=report,
        )
        state["incident_runtime"] = runtime
        state["incident_context"] = refreshed
        return refreshed, [
            FollowUpProbeResult(
                FOLLOWUP_PROBE_MAINTENANCE_INCIDENT,
                "ok" if report.collection_status != "unavailable" else "failed",
                f"User-scoped incident analysis completed with {len(report.findings)} finding(s) and {sum(item.count for item in report.coredumps)} crash record(s).",
                [item.action_id for item in refreshed.actions],
            )
        ]

    def actions_callback(
        current: FollowUpContext,
        action_ids: Sequence[str],
        input_func: Callable[[str], str],
        stdout,
        stderr,
    ) -> FollowUpActionOutcome:
        runtime = state.get("incident_runtime")
        incident_context = state.get("incident_context")
        if not isinstance(runtime, FollowUpRuntime) or not isinstance(incident_context, FollowUpContext):
            return FollowUpActionOutcome(
                attempted=True,
                message="AuraScan needs the detailed incident probe before it can prepare a repair. No command was run.",
            )
        if runtime.run_actions is None:
            return FollowUpActionOutcome(attempted=True, message="No verified incident action is available.")
        return runtime.run_actions(incident_context, action_ids, input_func, stdout, stderr)

    return with_hardware_health_runtime(
        initial_context,
        FollowUpRuntime(run_probes=probes_callback, run_actions=actions_callback),
        runner=runner,
        which=which,
    )

def build_incident_followup_runtime(
    context: FollowUpContext,
    *,
    env: Optional[Mapping[str, str]] = None,
    runner: Callable,
    which: Callable,
    context_root: Optional[Path],
    incident_root: Optional[Path],
    system_root: Optional[Path],
    report_override=None,
    defer_actions: bool = False,
) -> FollowUpRuntime:
    """Build the incident or maintenance follow-up runtime for a context.

    The generic framework receives this function from its caller instead of
    importing the incident workflow, and calls it for both incident and
    maintenance contexts.
    """
    if context.source_type == "maintenance":
        return build_maintenance_runtime(
            context,
            env=env,
            runner=runner,
            which=which,
            context_root=context_root,
            incident_root=incident_root,
            system_root=system_root,
        )
    return build_incident_runtime(
        context,
        env=env,
        runner=runner,
        which=which,
        context_root=context_root,
        incident_root=incident_root,
        system_root=system_root,
        report_override=report_override,
        defer_actions=defer_actions,
    )


def load_incident_followup_context(
    context_id: str = "",
    *,
    latest: bool = False,
    env: Optional[Mapping[str, str]] = None,
    incident_root: Optional[Path] = None,
) -> Optional[FollowUpContext]:
    """Load a retained incident result as a follow-up context, or ``None``."""
    if latest or not context_id:
        return context_from_latest_saved_incident(env=env, incident_root=incident_root)
    return context_from_saved_incident(context_id, env=env, incident_root=incident_root)
