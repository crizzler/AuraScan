"""Terminal presentation for the recovery report.

Rendering lives in the presentation layer so ``RecoveryReport`` stays data and
semantics. This module displays recovery findings, verified actions and AI
advisory text that were already decided and recorded on the report. It performs
no probing, no repair and no eligibility decision.
"""

from typing import TYPE_CHECKING, List

from aurascan.core.recovery import (
    RECOVERY_AI_FALLBACK,
    recovery_recipe_order,
)
from aurascan.core.text_safety import advisory_text_or_fallback

if TYPE_CHECKING:  # pragma: no cover - annotations only, never executed
    from aurascan.core.recovery import RecoveryReport


def render_recovery(report: "RecoveryReport", *, verbose: bool = False) -> str:
    """Render a recovery report as terminal text."""
    lines: List[str] = [
        "\n[AuraScan] AI-Assisted Recovery",
        "=" * 56,
        f"Target: {report.target.distro.get('name', 'Unknown')} | Filesystem: {report.target.filesystem} | Bootloader: {report.target.bootloader.name}",
        f"Findings: {len(report.findings)} | Risk: {report.highest_severity.value} | Verified repairs: {len(report.eligible_actions)}",
        f"Network: {'connected' if report.network.connected else 'offline'} | AI: {report.ai_review.get('status', 'not run')}",
        "-" * 56,
    ]
    if not report.findings:
        lines.append("[OK] No recognized boot-blocking or package-state problem was found.")
    for index, finding in enumerate(report.findings if verbose else report.findings[:6], start=1):
        lines.append(f"{index}. {finding.title} [{finding.severity.value}]")
        lines.append(finding.summary)
        if finding.recommended_action:
            lines.append("AuraScan response: " + finding.recommended_action)
    if len(report.findings) > 6 and not verbose:
        lines.append(f"{len(report.findings) - 6} additional findings hidden. Use --verbose to show all.")
    if report.eligible_actions:
        lines.append("\nRecommended recovery plan:")
        ordered = sorted(report.eligible_actions, key=lambda item: (not item.ai_recommended, recovery_recipe_order(item.recipe_id)))
        for index, action in enumerate(ordered, start=1):
            suffix = " | AI recommended" if action.ai_recommended else ""
            lines.append(f"{index}. {action.title} [{action.risk.value}{suffix}]")
            lines.append(action.summary)
            if action.confirmation_phrase:
                lines.append("   Requires separate typed confirmation.")
            if verbose:
                for command in action.command_preview:
                    lines.append("   Command: " + " ".join(command))
    if report.probe_results:
        successful = sum(item.status not in {"failed", "timeout"} for item in report.probe_results)
        lines.append(f"\nLocal verification: {successful}/{len(report.probe_results)} probe(s) completed.")
    summary = advisory_text_or_fallback(
        report.ai_review.get("summary"),
        max_chars=2000,
        fallback=RECOVERY_AI_FALLBACK,
    )
    if summary:
        lines.append("\nAI explanation: " + summary)
    if report.notes:
        lines.append("\nRecovery notes:")
        lines.extend("- " + item for item in report.notes[:10])
    if report.repair_results:
        lines.append("\nRepair results:")
        lines.extend(f"- {item.status}: {item.message}" for item in report.repair_results)
    return "\n".join(lines)
