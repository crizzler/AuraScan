"""Terminal presentation for the incident report.

Rendering lives in the presentation layer so ``IncidentReport`` stays data and
semantics. This module formats incident findings, crash groups, verified repair
actions and AI advisory text that were already decided and recorded on the
report. It performs no collection, no probing and no repair.
"""

from typing import TYPE_CHECKING, List, Mapping

from aurascan.core.models import Severity
from aurascan.core.text_safety import advisory_text_or_fallback

if TYPE_CHECKING:  # pragma: no cover - annotations only, never executed
    from aurascan.core.incident_models import IncidentReport

# Severity ordering for display sorting. This mirrors the ordering used by the
# other severity-aware modules (presenter.py and risk.py each keep a private
# copy for the same reason).
SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]

# Presentation copy of the advisory wording and the provider timeout used in the
# rendered explanation. ``tests/test_presentation_renderers.py`` asserts the
# timeout still matches the value the incident engine actually passes to the
# provider.
INCIDENT_AI_FALLBACK = (
    "AI explanation was omitted because the provider response did not meet AuraScan's guarded advisory contract."
)
INCIDENT_AI_TIMEOUT_SECONDS = 60


def render_incident(report: "IncidentReport", *, verbose: bool = False) -> str:
    """Render an incident report as terminal text."""
    lines: List[str] = [
        "\n[AuraScan] Incident Recovery Assistant",
        "=" * 54,
        f"Incident: {report.incident_id} | Boot: {report.boot_id or report.target_boot}",
        f"Findings: {len(report.findings)} | Application crashes: {sum(group.count for group in report.coredumps)} | Risk: {report.highest_severity.value}",
        f"Collection: {report.collection_status}" + (" (truncated)" if report.truncated else ""),
        "-" * 54,
    ]
    if not report.findings and not report.coredumps:
        lines.append("[OK] AuraScan did not find a recognized crash or system-failure pattern.")
    ordered = sorted(
        enumerate(report.findings),
        key=lambda item: (-SEVERITY_ORDER.index(item[1].severity), item[0]),
    )
    visible = ordered if verbose else ordered[:5]
    if visible:
        lines.append("Likely causes and incidents:")
        for index, (_original, finding) in enumerate(visible, start=1):
            lines.append(f"{index}. {finding.title} [{finding.severity.value}, {finding.confidence.value.lower()} confidence]")
            lines.append(finding.summary)
            if finding.why_it_matters:
                lines.append(f"Why: {finding.why_it_matters}")
            if finding.recommended_action:
                lines.append(f"AuraScan response: {finding.recommended_action}")
            if verbose and finding.evidence_ids:
                lines.append("Evidence: " + ", ".join(finding.evidence_ids[:8]))
            lines.append("")
        if lines[-1] == "":
            lines.pop()
    hidden = len(ordered) - len(visible)
    if hidden:
        lines.append(f"{hidden} additional incident findings hidden. Use --verbose to show all.")
    if report.coredumps:
        lines.append("\nApplication crash groups:")
        groups = report.coredumps if verbose else report.coredumps[:8]
        for group in groups:
            label = group.executable or "unknown application"
            package = f" ({group.package})" if group.package else ""
            lines.append(f"- {label}{package}: signal {group.signal or 'unknown'}, count {group.count}")
        if len(report.coredumps) > len(groups):
            lines.append(f"- {len(report.coredumps) - len(groups)} additional groups hidden")
    if report.probe_results:
        completed = sum(item.status not in {"failed", "timeout"} for item in report.probe_results)
        ready = sum(item.status == "action_ready" for item in report.probe_results)
        failed = len(report.probe_results) - completed
        lines.append(
            f"\nAI-guided local checks: {completed}/{len(report.probe_results)} completed; "
            f"{ready} produced verified repair options"
            + (f"; {failed} incomplete" if failed else "")
            + "."
        )
        if verbose:
            for item in report.probe_results:
                lines.append(f"- {item.probe_type}: {item.status} - {item.summary}")
    if report.eligible_actions:
        eligible_actions = report.eligible_actions
        recommended_ids = report.ai_review.get("recommended_action_ids", []) if isinstance(report.ai_review, Mapping) else []
        recommended = {str(item) for item in recommended_ids} if isinstance(recommended_ids, list) else set()
        original_order = {item.action_id: index for index, item in enumerate(eligible_actions)}
        display_actions = sorted(
            eligible_actions,
            key=lambda item: (item.action_id not in recommended, original_order[item.action_id]),
        )
        lines.append("\nPrepared repairs:")
        for index, action in enumerate(display_actions, start=1):
            recommendation = " | AI recommended" if action.action_id in recommended else ""
            lines.append(f"{index}. {action.title} [{action.risk.value}{recommendation}]")
            lines.append(action.summary)
            if verbose and action.command_preview:
                for command in action.command_preview:
                    lines.append("   Command: " + " ".join(command))
            if action.backup_description:
                lines.append("   Backup: " + action.backup_description)
    if report.collection_errors:
        lines.append("\nCollection notes:")
        lines.extend(f"- {item}" for item in report.collection_errors[:8])
    if report.ai_review:
        status = str(report.ai_review.get("status") or "unknown")
        provider = str(report.ai_review.get("provider") or "")
        summary = advisory_text_or_fallback(
            report.ai_review.get("summary"),
            max_chars=1000,
            fallback=INCIDENT_AI_FALLBACK,
        )
        final_phase = report.ai_review.get("final", {})
        phase_label = "two-pass" if isinstance(final_phase, Mapping) and final_phase.get("status") == "ok" else "triage"
        status_label = {
            "timeout": "timed out",
            "provider_error": "provider unavailable",
            "invalid_response": "response could not be validated",
        }.get(status, status)
        lines.append("\nAI review: " + status_label + (f", {phase_label}" if status in {"ok", "triage_only"} else "") + (f" ({provider})" if provider else ""))
        if summary:
            lines.append(summary)
        if status == "timeout":
            lines.append(
                f"The AI provider did not answer within {INCIDENT_AI_TIMEOUT_SECONDS} seconds. "
                "Deterministic diagnostics and verified repair checks still completed; AuraScan accepted no AI-generated command."
            )
        elif status == "provider_error":
            lines.append(
                "The AI provider could not complete this review. Deterministic diagnostics and verified repair checks remain available."
            )
        elif status == "invalid_response":
            lines.append(
                "The AI response did not match AuraScan's guarded JSON contract and was ignored. Deterministic diagnostics remain authoritative."
            )
        elif status == "triage_only" and isinstance(final_phase, Mapping):
            final_status = str(final_phase.get("status") or "")
            if final_status == "timeout":
                lines.append(
                    "The final AI explanation timed out; the successful triage and independently verified local checks remain available."
                )
            elif final_status in {"provider_error", "invalid_response"}:
                lines.append(
                    "The final AI explanation was unavailable; the successful triage and independently verified local checks remain available."
                )
        causes = report.ai_review.get("likely_causes", [])
        if isinstance(causes, list) and causes:
            lines.append("AI-correlated causes:")
            for cause in causes[:3]:
                if not isinstance(cause, Mapping):
                    continue
                title = advisory_text_or_fallback(
                    cause.get("title") or "Possible cause",
                    max_chars=240,
                    fallback=INCIDENT_AI_FALLBACK,
                )
                confidence = str(cause.get("confidence") or "unknown")
                explanation = advisory_text_or_fallback(
                    cause.get("explanation"),
                    max_chars=1000,
                    fallback=INCIDENT_AI_FALLBACK,
                )
                lines.append(f"- {title} [{confidence} confidence]" + (f": {explanation}" if explanation else ""))
        recommended_ids = report.ai_review.get("recommended_action_ids", [])
        if isinstance(recommended_ids, list) and recommended_ids:
            action_titles = {action.action_id: action.title for action in report.eligible_actions}
            recommended = [action_titles[item] for item in recommended_ids if item in action_titles]
            if recommended:
                lines.append("AI recommends these already-verified AuraScan actions: " + "; ".join(recommended))
    if report.post_repair:
        resolved = len(report.post_repair.get("resolved_finding_keys", []))
        remaining = len(report.post_repair.get("remaining_finding_keys", []))
        lines.append(f"\nPost-repair diagnostics: {resolved} resolved, {remaining} still observed.")
    return "\n".join(lines)
