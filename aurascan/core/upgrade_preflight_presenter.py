"""Terminal presentation for upgrade preflight reports.

Rendering lives in the presentation layer so ``UpgradePreflightReport`` and
``UpgradeFailureDiagnosis`` stay data and semantics. This module displays the
action, severity, planned command and findings that preflight already decided.
It never decides whether an upgrade is allowed to continue.
"""

from typing import TYPE_CHECKING, List

from aurascan.core.models import Severity

if TYPE_CHECKING:  # pragma: no cover - annotations only, never executed
    from aurascan.core.upgrade_preflight import (
        UpgradeFailureDiagnosis,
        UpgradePreflightReport,
    )


def check_summary_lines(report: "UpgradePreflightReport") -> List[str]:
    """Render the per-check summary block shown under the preflight header."""
    lines: List[str] = []
    if report.repository_health and report.repository_health.issues:
        lines.append(f"Repository health: {report.repository_health.summary}.")
    if report.security_audit:
        campaign_count = len(report.security_audit.campaign_findings)
        advisory_count = len(report.security_audit.official_vulnerability_findings)
        if campaign_count:
            lines.append(f"Security audit: {campaign_count} known AUR campaign match(es) require attention.")
        elif advisory_count:
            lines.append(f"Security audit: no known AUR campaign match; {advisory_count} official package advisory finding(s).")
        else:
            lines.append("Security audit: no known AUR campaign match detected.")
    if report.kernel_module_check and report.kernel_module_check.enabled:
        lines.append(f"Kernel/module check: {report.kernel_module_check.summary}.")
    if report.snapshot.foreign_packages:
        issue_count = sum(1 for finding in report.findings if finding.rule_id in {"UPG-AUR-DEPENDENCY-MISSING", "UPG-AUR-CONFLICTS"})
        if report.plan.selected_helper != "none" and not report.plan.helper_error:
            status = "dependency issues not detected" if issue_count == 0 else f"dependency/conflict issues={issue_count}"
            lines.append(f"Foreign package check: {len(report.snapshot.foreign_packages)} installed, {len(report.plan.aur_packages)} helper updates, {status}.")
        elif report.plan.helper_error:
            lines.append(f"Foreign package check: {len(report.snapshot.foreign_packages)} installed, helper query unavailable.")
        else:
            lines.append(f"Foreign package check: {len(report.snapshot.foreign_packages)} installed, helper updates not checked.")
    if report.snapshot.pacnew_count or report.snapshot.pacsave_count:
        lines.append(f"Config drift check: {report.snapshot.pacnew_count} .pacnew, {report.snapshot.pacsave_count} .pacsave files counted under /etc.")
    if lines:
        lines.append("-" * 50)
    return lines


def render_upgrade_preflight(
    report: "UpgradePreflightReport",
    *,
    use_color: bool = True,
    verbose: bool = False,
) -> str:
    """Render an upgrade preflight report as terminal text."""
    reset = "\033[0m" if use_color else ""
    red = "\033[91m" if use_color else ""
    yellow = "\033[93m" if use_color else ""
    green = "\033[92m" if use_color else ""
    color = red if report.highest_severity == Severity.CRITICAL else yellow if report.requires_confirmation else green

    lines: List[str] = [
        "\n[AuraScan] Upgrade Preflight",
        "=" * 50,
        f"Repo upgrades: {len(report.plan.repo_packages)} | AUR upgrades: {len(report.plan.aur_packages)} | Removals/Replacements: {report.transaction_change_count()}",
        f"Risk: {color}{report.highest_severity.value}{reset} | Action: {color}{report.action.upper()}{reset} | Helper: {report.plan.selected_helper}",
        f"Planned command: {' '.join(report.plan.final_command) if report.plan.final_command else '(none)'}",
        "-" * 50,
    ]
    lines.extend(check_summary_lines(report))

    if report.plan.preview_error:
        lines.append("Preflight unavailable.")
        lines.append(report.plan.preview_error)
    elif not report.findings:
        lines.append("[INFO] No upgrade preflight findings were produced. This is not proof the upgrade is safe.")

    terminal_findings = report.terminal_findings()
    visible = terminal_findings if verbose else terminal_findings[:3]
    if visible:
        lines.append("Upgrade risks:")
        for index, finding in enumerate(visible, start=1):
            lines.append(f"{index}. {finding.title} [{finding.severity.value}]")
            lines.append(finding.summary)
            if finding.why_it_matters:
                lines.append(f"Why it matters: {finding.why_it_matters}")
            if finding.recommended_action:
                lines.append(f"Before upgrading: {finding.recommended_action}")
            if verbose and finding.evidence:
                lines.append(f"Technical details: {finding.rule_id}: {finding.evidence}")
            lines.append("")
        if lines[-1] == "":
            lines.pop()

    hidden = len(terminal_findings) - len(visible)
    if hidden > 0:
        note = "additional upgrade risk hidden" if hidden == 1 else "additional upgrade risks hidden"
        lines.append(f"{hidden} {note}. Use --verbose to show all.")

    if report.ai_review:
        status = str(report.ai_review.get("status") or "unknown")
        provider = str(report.ai_review.get("provider") or "")
        summary = str(report.ai_review.get("summary") or "")
        label = f"AI review: {status}" + (f" ({provider})" if provider else "")
        lines.append(label)
        if summary:
            lines.append(summary)

    if report.action == "block":
        lines.append("\nRecommended Action: Do not continue through AuraScan's automatic handoff; follow the blocking finding above.")
    elif report.action == "confirm":
        lines.append("\nRecommended Action: Review the risks above before continuing.")
    elif report.action == "unavailable":
        lines.append("\nRecommended Action: Do not run the upgrade from AuraScan until the preview problem is resolved.")
    else:
        lines.append("\nRecommended Action: Continue only with normal package-manager judgment.")
    return "\n".join(lines)


def render_upgrade_failure_diagnosis(diagnosis: "UpgradeFailureDiagnosis") -> str:
    """Render an upgrade failure diagnosis as terminal text."""
    lines: List[str] = [
        "\n[AuraScan] Upgrade failure diagnosis",
        f"{diagnosis.title}.",
        diagnosis.summary,
        f"Likely cause: {diagnosis.likely_cause}",
        f"Next step: {diagnosis.recommended_action}",
    ]
    if diagnosis.evidence:
        lines.append("Evidence:")
        for item in diagnosis.evidence[:6]:
            lines.append(f"- {item}")
    return "\n".join(lines)
