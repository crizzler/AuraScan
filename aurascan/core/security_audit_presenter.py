"""Terminal presentation for the security-audit report.

Rendering lives in the presentation layer so ``SecurityAuditReport`` stays data
and semantics. This module formats findings, advisory counts and collection notes
that were already decided and recorded on the report.

Known debt recorded here deliberately (not changed by the presentation move):
the recommended-action line below is derived from the findings' severities and
categories at render time. That is a policy-flavoured decision living in
presentation, and it is preserved byte-for-byte until a later stage moves it onto
the report as a decided field.
"""

from typing import TYPE_CHECKING, List

from aurascan.core.models import Severity

if TYPE_CHECKING:  # pragma: no cover - annotations only, never executed
    from aurascan.core.security_audit import SecurityAuditReport


# Display copy of the reviewed-advisory date. The audit engine keeps its own for
# evidence strings; ``tests/test_presentation_renderers.py`` asserts they agree.
CODEWHALE_ADVISORY_REVIEWED = "2026-09-09"


def arch_audit_summary(report: "SecurityAuditReport") -> str:
    """Describe the arch-audit collection status for the audit header."""
    if report.arch_audit.status == "ok":
        count = len(report.arch_audit.findings)
        return "no findings" if count == 0 else f"{count} finding(s)"
    if report.arch_audit.status == "not_installed":
        return "not checked (arch-audit is not installed)"
    if report.arch_audit.status == "skipped_offline":
        return "skipped in offline mode"
    if report.arch_audit.error:
        return f"{report.arch_audit.status} ({report.arch_audit.error})"
    return report.arch_audit.status


def render_security_audit(
    report: "SecurityAuditReport",
    *,
    verbose: bool = False,
    use_color: bool = True,
) -> str:
    """Render a security-audit report as terminal text."""
    reset = "\033[0m" if use_color else ""
    red = "\033[91m" if use_color else ""
    yellow = "\033[93m" if use_color else ""
    green = "\033[92m" if use_color else ""
    color = red if report.has_alert else yellow if report.findings or report.status != "ok" else green
    campaign_label = "unavailable"
    if report.campaign:
        campaign_label = (
            f"{report.campaign.title} ({len(report.campaign.package_names)} names, "
            f"{report.campaign.data_origin}; {report.campaign.source_kind})"
        )
    lines: List[str] = [
        "\n[AuraScan] Security Audit",
        "=" * 54,
        f"Risk: {color}{report.highest_severity.value}{reset} | Status: {report.status.upper()}",
        f"AUR campaign intelligence: {campaign_label}",
        (
            f"Packages checked: {report.installed_package_count} | "
            f"Pacman history records: {report.history_record_count}"
        ),
        f"Official package advisories: {arch_audit_summary(report)}",
        f"Bundled CodeWhale version advisories: {len(report.upstream_vulnerability_findings)} match(es); reviewed {CODEWHALE_ADVISORY_REVIEWED}",
        f"Emergency vendor/KEV advisories: {len(report.vendor_emergency_findings)} match(es)",
        "Runtime intelligence: " + str(report.intelligence.get("status", "legacy-unrecorded")),
        "-" * 54,
    ]
    if report.campaign is None:
        lines.append("[WARN] Known AUR campaign intelligence was unavailable, so that check is incomplete.")
    elif not report.campaign_findings:
        lines.append("[OK] No known AUR campaign package or campaign-window history matches were found.")
    if not report.official_vulnerability_findings and report.arch_audit.status == "ok":
        lines.append("[OK] arch-audit reported no applicable official-package advisories.")

    findings = report.sorted_findings()
    visible = findings if verbose else findings[:5]
    if visible:
        lines.append("Security findings:")
        for index, finding in enumerate(visible, start=1):
            lines.append(f"{index}. {finding.title} [{finding.severity.value}]")
            lines.append(finding.summary)
            lines.append(f"Why it matters: {finding.why_it_matters}")
            lines.append(f"Recommended action: {finding.recommended_action}")
            if verbose and finding.evidence:
                lines.append("Evidence: " + "; ".join(finding.evidence[:8]))
            lines.append("")
        if lines[-1] == "":
            lines.pop()
    hidden = len(findings) - len(visible)
    if hidden:
        lines.append(f"{hidden} additional finding(s) hidden. Use --verbose to show all.")
    if report.notes:
        lines.append("Collection notes:")
        for note in report.notes if verbose else report.notes[:4]:
            lines.append(f"- {note}")
    lines.append(
        "\nA clean-looking result means no known match was found; it is not proof that package code or the system is safe."
    )
    if any(item.severity in {Severity.HIGH, Severity.CRITICAL}
           and item.category not in {"official_vulnerability", "upstream_vulnerability", "vendor_emergency_advisory"}
           for item in report.findings):
        lines.append("Recommended Action: Treat the matched evidence as an incident and investigate from trusted media.")
    elif report.findings:
        lines.append("Recommended Action: Review the advisory context and package provenance, then apply verified fixed updates.")
    else:
        lines.append("Recommended Action: No campaign-specific response is indicated by the available evidence.")
    return "\n".join(lines)
