"""Upgrade follow-up adapter: the upgrade lifecycle's own session runtime.

The generic follow-up framework coordinates a session; this module owns what an
upgrade session *does*. It builds the retained upgrade context, refreshes it
through the preflight that owns it, and applies the verified repository, kernel
module and config-drift fixes with the adapters that own those operations.

The framework never imports this module. Callers that hold an upgrade context
supply :func:`build_upgrade_runtime` as the upgrade runtime provider, the same
way the incident and config-drift lifecycles supply theirs.
"""

import json
import time
from pathlib import Path
from typing import Callable, List, Mapping, Optional, Sequence, Tuple

from aurascan.core.followup import (
    FollowUpAction,
    FollowUpActionOutcome,
    FollowUpContext,
    FollowUpFact,
    FollowUpProbe,
    FollowUpProbeResult,
    FollowUpRuntime,
    _confirm_action_plan,
    _print_action_plan,
    ensure_hardware_health_probe,
    followup_context_fingerprint,
    make_context_id,
    persist_followup_context,
    redact_followup_structure,
    redact_followup_text,
    stable_followup_id,
    with_hardware_health_runtime,
)
from aurascan.core.kernel_module_autopilot import kernel_module_fix_command
from aurascan.core.repository_repair import apply_repository_health_repairs


FOLLOWUP_ACTION_REPOSITORY = "fua-upgrade-repository-restore"
FOLLOWUP_ACTION_KERNEL = "fua-upgrade-kernel-support"
FOLLOWUP_ACTION_CONFIG_DRIFT = "fua-upgrade-config-drift"
FOLLOWUP_PROBE_UPGRADE_REFRESH = "fup-upgrade-refresh"


def context_from_upgrade(
    report,
    *,
    phase: str,
    outcome: Optional[Mapping[str, object]] = None,
    context_id: str = "",
    metadata: Optional[Mapping[str, object]] = None,
) -> FollowUpContext:
    plan = report.plan
    facts = [
        FollowUpFact(
            "upgrade-summary",
            "summary",
            f"{len(plan.repo_packages)} repository package(s) and {len(plan.aur_packages)} AUR package(s) are planned.",
            f"Highest risk: {report.highest_severity.value}; action: {report.action}; helper: {plan.selected_helper}.",
            report.highest_severity.value,
        ),
    ]
    for index, package in enumerate((plan.repo_packages + plan.aur_packages)[:120]):
        facts.append(FollowUpFact(
            stable_followup_id("fuf-upkg-", index, package.name, package.new_version),
            "package",
            f"{package.name}: {package.old_version or 'not installed'} -> {package.new_version or 'unknown'}",
            f"Repository/type: {package.repo or package.package_type}; conflicts: {', '.join(package.conflicts[:8]) or 'none'}; replaces: {', '.join(package.replaces[:8]) or 'none'}.",
        ))
    for index, finding in enumerate(report.terminal_findings()[:30]):
        facts.append(FollowUpFact(
            stable_followup_id("fuf-ufind-", index, finding.rule_id, finding.evidence),
            "finding",
            f"{finding.title} [{finding.severity.value}]",
            f"{finding.summary} Why it matters: {finding.why_it_matters} AuraScan response: {finding.recommended_action}",
            finding.severity.value,
        ))
    if report.kernel_module_check is not None:
        check = report.kernel_module_check
        facts.append(FollowUpFact(
            "upgrade-kernel-module",
            "kernel_module",
            check.summary,
            json.dumps(redact_followup_structure(check.to_dict()), sort_keys=True)[:3000],
        ))
    if report.repository_health is not None:
        facts.append(FollowUpFact(
            "upgrade-repository-health",
            "repository",
            report.repository_health.summary,
            f"Status: {report.repository_health.status}; enabled repositories: {', '.join(report.repository_health.enabled_repositories[:20])}.",
        ))
    ai_summary = str(report.ai_review.get("summary") or "") if isinstance(report.ai_review, Mapping) else ""
    if ai_summary:
        facts.append(FollowUpFact("upgrade-ai-summary", "ai_summary", "Earlier AI review", ai_summary))
    if outcome:
        status = str(outcome.get("status") or "unknown")
        facts.append(FollowUpFact(
            "upgrade-outcome",
            "outcome",
            f"Upgrade outcome: {status}",
            redact_followup_text(str(outcome.get("summary") or ""))[:2000],
            str(outcome.get("severity") or ""),
        ))

    probes = [
        FollowUpProbe(
            FOLLOWUP_PROBE_UPGRADE_REFRESH,
            "Refresh upgrade preflight",
            "Rerun the deterministic package, repository, and kernel/module checks without starting the upgrade.",
            "upgrade_refresh",
        )
    ]
    actions: List[FollowUpAction] = []
    if report.repository_health is not None and report.repository_health.fixable_issues:
        actions.append(FollowUpAction(
            FOLLOWUP_ACTION_REPOSITORY,
            "Restore verified repository mirror configuration",
            report.repository_health.summary,
            "MEDIUM",
            True,
            True,
        ))
    if report.kernel_module_check is not None and report.kernel_module_check.fix_packages():
        packages = ", ".join(report.kernel_module_check.fix_packages())
        actions.append(FollowUpAction(
            FOLLOWUP_ACTION_KERNEL,
            "Install verified kernel support packages",
            f"Install the currently verified missing support packages: {packages}.",
            "MEDIUM",
            True,
            False,
        ))
    if report.snapshot.pacnew_count or report.snapshot.pacsave_count:
        actions.append(FollowUpAction(
            FOLLOWUP_ACTION_CONFIG_DRIFT,
            "Run Config Drift Assistant",
            f"Handle {report.snapshot.pacnew_count} .pacnew and {report.snapshot.pacsave_count} .pacsave file(s) through the existing guarded assistant.",
            "MEDIUM",
            True,
            True,
        ))
    context = FollowUpContext(
        context_id=context_id or make_context_id("upgrade", phase),
        source_type="upgrade",
        source_id=f"upgrade-{int(time.time())}",
        phase=phase,
        title="AuraScan Upgrade",
        facts=facts,
        probes=probes,
        actions=actions,
        metadata={
            "selected_helper": plan.selected_helper,
            "phase": phase,
            **dict(metadata or {}),
        },
        privacy_mode="redacted",
    )
    ensure_hardware_health_probe(context)
    context.source_fingerprint = followup_context_fingerprint(context)
    return context


def build_upgrade_runtime(
    initial_context: FollowUpContext,
    *,
    runner: Callable,
    which: Callable,
    urlopen: Optional[Callable],
    context_root: Optional[Path],
    defer_actions: bool = False,
    refresh_report: Optional[Callable] = None,
    config_drift_remediation_provider: Optional[Callable] = None,
) -> FollowUpRuntime:

    def refreshed_report():
        """Return fresh upgrade state, supplied by the upgrade lifecycle.

        The framework does not import the upgrade workflow: the caller that owns
        the preflight passes ``refresh_report`` and this runtime calls it with the
        session's own hooks. Without it the refresh probe and the support actions
        fail closed instead of acting on stale state.
        """
        if refresh_report is None:
            return None
        return refresh_report(
            initial_context,
            runner=runner,
            which=which,
            urlopen=urlopen,
        )

    def probes_callback(
        current: FollowUpContext,
        probe_ids: Sequence[str],
    ) -> Tuple[FollowUpContext, Sequence[FollowUpProbeResult]]:
        if FOLLOWUP_PROBE_UPGRADE_REFRESH not in probe_ids:
            return current, []
        report = refreshed_report()
        if report is None:
            return current, [
                FollowUpProbeResult(
                    FOLLOWUP_PROBE_UPGRADE_REFRESH,
                    "failed",
                    "The upgrade preflight cannot be refreshed in this session; rerun the upgrade preflight.",
                    [],
                )
            ]
        refreshed = context_from_upgrade(
            report,
            phase="refreshed_preflight",
            context_id=current.context_id,
            metadata=current.metadata,
        )
        return refreshed, [
            FollowUpProbeResult(
                FOLLOWUP_PROBE_UPGRADE_REFRESH,
                "ok" if report.plan.available else "failed",
                (
                    "The deterministic upgrade preflight was refreshed successfully."
                    if report.plan.available
                    else f"The refreshed preflight remains unavailable: {report.plan.preview_error}"
                ),
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
        report = refreshed_report()
        if report is None:
            return FollowUpActionOutcome(
                attempted=True,
                failed=True,
                source_changed=True,
                message="[AuraScan] The upgrade preflight cannot be refreshed in this session; no support action was applied.",
            )
        refreshed = context_from_upgrade(
            report,
            phase="action_revalidation",
            context_id=current.context_id,
            metadata=current.metadata,
        )
        available = {item.action_id: item for item in refreshed.actions}
        selected_ids = [item for item in action_ids if item in available]
        persist_followup_context(refreshed, context_root)
        if not selected_ids:
            return FollowUpActionOutcome(
                attempted=True,
                source_changed=True,
                message="AuraScan refreshed the preflight; the requested operation is no longer verified or required.",
            )
        selected = [available[item] for item in selected_ids]
        config_remediation = None
        config_safe = True
        if FOLLOWUP_ACTION_CONFIG_DRIFT in selected_ids:
            # The config-drift lifecycle re-derives its own fixes and tells the
            # framework whether they are safe to offer. A missing provider fails
            # closed: the requested drift action is dropped, never applied from
            # stale state.
            if config_drift_remediation_provider is None:
                selected_ids = [
                    item for item in selected_ids
                    if item != FOLLOWUP_ACTION_CONFIG_DRIFT
                ]
                selected = [
                    item for item in selected
                    if item.action_id != FOLLOWUP_ACTION_CONFIG_DRIFT
                ]
                if not selected:
                    return FollowUpActionOutcome(
                        attempted=True,
                        source_changed=True,
                        message=(
                            "[AuraScan] The requested config-drift fix could not be re-prepared in this session; "
                            "no support action was applied."
                        ),
                    )
            else:
                config_remediation = config_drift_remediation_provider(
                    Path("/etc"),
                    stdout=stdout,
                )
                config_safe = bool(getattr(config_remediation, "safe", False))
                if not getattr(config_remediation, "action_ids", []):
                    selected_ids = [
                        item for item in selected_ids
                        if item != FOLLOWUP_ACTION_CONFIG_DRIFT
                    ]
                    selected = [
                        item for item in selected
                        if item.action_id != FOLLOWUP_ACTION_CONFIG_DRIFT
                    ]
        if not selected:
            return FollowUpActionOutcome(
                attempted=True,
                source_changed=True,
                message="AuraScan refreshed the state; none of the requested support actions remain necessary.",
            )
        _print_action_plan(selected, stdout)
        default_yes = (
            config_safe
            and report.highest_severity.value not in {"HIGH", "CRITICAL"}
            and all(item.verified and item.risk in {"LOW", "MEDIUM"} for item in selected)
            and all(item.reversible for item in selected)
        )
        if not _confirm_action_plan(input_func, default_yes):
            return FollowUpActionOutcome(attempted=True, message="[AuraScan] Follow-up upgrade support action was not applied.")
        for action_id in (
            FOLLOWUP_ACTION_REPOSITORY,
            FOLLOWUP_ACTION_KERNEL,
            FOLLOWUP_ACTION_CONFIG_DRIFT,
        ):
            if action_id not in selected_ids:
                continue
            if action_id == FOLLOWUP_ACTION_REPOSITORY:
                check = report.repository_health
                if check is None or not check.fixable_issues:
                    return FollowUpActionOutcome(attempted=True, failed=True, source_changed=True, message="[AuraScan] Repository repair no longer passes validation.")
                repair = apply_repository_health_repairs(check, runner=runner)
                if not repair.success:
                    return FollowUpActionOutcome(attempted=True, failed=True, source_changed=True, message="[AuraScan] Repository repair failed and retained its backup manifest.")
            elif action_id == FOLLOWUP_ACTION_KERNEL:
                check = report.kernel_module_check
                command = kernel_module_fix_command(check) if check is not None else []
                if not command:
                    return FollowUpActionOutcome(attempted=True, failed=True, source_changed=True, message="[AuraScan] Kernel support fix no longer passes validation.")
                try:
                    result = runner(command, check=False)
                except OSError as exc:
                    return FollowUpActionOutcome(attempted=True, failed=True, source_changed=True, message=f"[AuraScan] Kernel support fix could not start: {redact_followup_text(str(exc))}.")
                if int(getattr(result, "returncode", 0)) != 0:
                    return FollowUpActionOutcome(attempted=True, failed=True, source_changed=True, message="[AuraScan] Kernel support package command failed.")
            elif action_id == FOLLOWUP_ACTION_CONFIG_DRIFT:
                status = config_remediation.apply(
                    input_func=input_func,
                    stdout=stdout,
                    stderr=stderr,
                    runner=runner,
                )
                if status != 0:
                    return FollowUpActionOutcome(attempted=True, failed=True, source_changed=True, message="[AuraScan] Config Drift Assistant failed or refused the refreshed plan.")
        return FollowUpActionOutcome(
            attempted=True,
            applied=True,
            source_changed=True,
            message="[AuraScan] The selected upgrade support action completed. Run a fresh preflight before upgrading.",
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
