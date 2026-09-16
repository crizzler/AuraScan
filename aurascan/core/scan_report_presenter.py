"""Terminal presentation for the core scan report.

This module owns the human-readable rendering of a :class:`ScanReport`:
the audit header, risk summary line, intelligence and source-acquisition
notices, update-scan policy block, per-finding presentation and the
recommended-action footer.

Rendering lives in the presentation layer on purpose. The evidence model in
``aurascan.core.models`` stays pure data plus serialization, so it can be read,
tested and reused without pulling in terminal formatting, ANSI colour or the
rule explanation templates.

Presentation is one-way: this module imports the domain model, never the other
way round. Output wording is user-facing, not policy — no severity, blocking or
review decision is made here.
"""

import json
from typing import Dict, List, Tuple

from aurascan.core.models import (
    RecommendedAction,
    RiskSummary,
    ScanReport,
    Severity,
)
from aurascan.core.presenter import FindingPresenter
from aurascan.core.text_safety import sanitize_terminal_text


def render_scan_report(
    report: ScanReport,
    use_color: bool = True,
    verbose: bool = False,
) -> str:
    """Render one scan report as terminal text.

    ``use_color`` adds ANSI colour to the risk and action fields; ``verbose``
    includes per-finding technical details. Both defaults match the historical
    ``ScanReport.render_terminal`` behaviour.
    """
    reset = "\033[0m" if use_color else ""
    red = "\033[91m" if use_color else ""
    yellow = "\033[93m" if use_color else ""
    green = "\033[92m" if use_color else ""
    risk = report.risk_summary or RiskSummary(Severity.LOW, RecommendedAction.allow)
    action = "BLOCKED" if risk.blocks_installation else risk.action.value.upper()
    color = red if risk.blocks_installation else yellow if risk.requires_manual_review else green

    lines: List[str] = [
        "\n[AuraScan] Audit Complete: "
        + sanitize_terminal_text(report.package_metadata.name, max_chars=256)
        + " "
        + sanitize_terminal_text(report.package_metadata.version, max_chars=256),
        "=" * 50,
        f"Risk Score: {color}{risk.severity.value}{reset} | Action: {color}{action}{reset}",
        "-" * 50,
    ]

    if not report.findings:
        lines.append("[INFO] No findings were produced. This is not proof the package is safe.")

    if report.intelligence:
        status = str(report.intelligence.get("status", "unknown"))
        lines.append("Security intelligence: " + sanitize_terminal_text(status, max_chars=32))
        if status == "stale":
            lines.append("[WARNING] Security intelligence is stale; existing indicators remain active and update-scan shortcuts are disabled.")
        elif status == "unavailable":
            lines.append("[WARNING] Installed intelligence could not be validated; bundled detection is active with incomplete coverage.")

    if report.source_acquisition:
        counts: Dict[str, int] = {}
        for item in report.source_acquisition:
            status = str(item.get("status", "unknown"))
            counts[status] = counts.get(status, 0) + 1
        summary = ", ".join(f"{status}={count}" for status, count in sorted(counts.items()))
        lines.append(f"Source Acquisition: {summary}")

    if report.fast_path_decision:
        decision = report.fast_path_decision
        lines.append("Update Scan Policy:")
        if report.context_user_warning:
            lines.append("Update context was provided manually.")
            lines.append(sanitize_terminal_text(report.context_user_warning))
        elif (
            report.context_eligible_for_fast_path
            and report.scan_context == "update"
            and report.scan_context_authority in ("verified_local_package_db", "verified_transaction_provider")
        ):
            if report.context_provider_name == "local_package_db":
                lines.append("Package update verified locally")
                lines.append("AuraScan confirmed from the local package database that this package is already installed and this scan is for an update.")
                lines.append("Why it matters: Verified update context is required before AuraScan can safely consider the smart update fast path.")
                lines.append("What AuraScan checked: AuraScan checked local installed package information and the candidate package metadata.")
                lines.append("What AuraScan did not check: This does not prove the package is safe. It only proves the scan context.")
                lines.append("Recommended action: No action needed.")
            else:
                lines.append("Verified package update context.")
                lines.append("AuraScan confirmed this package was already installed and this scan is for an update.")
        elif report.context_provider_name == "local_package_db":
            lines.append("Package update context could not be proven")
            lines.append("AuraScan could not clearly prove whether this package is a fresh install or an update.")
            lines.append("Why it matters: The update fast path is only allowed when AuraScan can prove the package was already installed and this scan is an update.")
            lines.append("What AuraScan checked: AuraScan checked the available local package information.")
            lines.append("What AuraScan did not check: AuraScan did not prove this is an already-installed package update.")
            lines.append("Recommended action: No action needed. AuraScan used the safer normal scan.")
        lines.append(sanitize_terminal_text(decision.get("title") or "Update scan decision recorded."))
        if decision.get("summary"):
            lines.append(sanitize_terminal_text(decision["summary"]))
        if decision.get("why_it_matters"):
            lines.append("Why it matters: " + sanitize_terminal_text(decision["why_it_matters"]))
        if decision.get("what_checked"):
            lines.append("What AuraScan checked: " + sanitize_terminal_text(decision["what_checked"]))
        if decision.get("what_not_checked"):
            lines.append("What AuraScan did not check: " + sanitize_terminal_text(decision["what_not_checked"]))
        if decision.get("recommended_action"):
            lines.append("Recommended action: " + sanitize_terminal_text(decision["recommended_action"]))
        if verbose and decision.get("technical_details"):
            lines.append("Technical details:")
            lines.append(json.dumps(decision["technical_details"], indent=2, sort_keys=True))

    presented_lines, _hidden = FindingPresenter().render(report.findings, verbose=verbose)
    lines.extend(presented_lines)

    if risk.reason:
        lines.append("\nRisk reason: " + sanitize_terminal_text(risk.reason))
    if risk.blocks_installation:
        final_action = "DO NOT INSTALL."
    elif risk.requires_manual_review:
        final_action = "Manual review recommended before installation."
    else:
        final_action = "No blocking findings. Continue only with normal package trust checks."
    lines.append("\nRecommended Action: " + final_action)
    return "\n".join(lines)
