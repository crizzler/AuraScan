import pytest

from aurascan.core.models import PackageMetadata, RecommendedAction, RiskSummary, ScanReport, Severity
from aurascan.core.context_provider import build_scan_context_proof
from aurascan.core.update_policy import (
    ScanContext,
    ScanContextSource,
    TRUST_BOUNDARY_REASON_CODES,
    UpdateFastPathAction,
    UpdateScanPolicy,
    UpdateScanState,
    decide_update_fast_path,
)


def state(**overrides):
    data = {
        "policy": UpdateScanPolicy.smart,
        "context": ScanContext.update,
        "context_source": ScanContextSource.test_fixture,
        "already_installed": True,
        "prior_baseline_exists": True,
        "prior_baseline_accepted": True,
        "context_proof": build_scan_context_proof(
            context=ScanContext.update,
            source=ScanContextSource.test_fixture,
        ),
    }
    data.update(overrides)
    return UpdateScanState(**data)


def test_full_policy_scans_update_normally():
    decision = decide_update_fast_path(state(policy=UpdateScanPolicy.full))

    assert decision.action == UpdateFastPathAction.use_full_scan
    assert decision.scan_level == "full"
    assert decision.expensive_phases_skipped is False
    assert decision.may_update_history_baseline is True
    assert decision.reason_codes == ["policy_full"]


def test_smart_policy_requires_accepted_prior_baseline():
    decision = decide_update_fast_path(state(prior_baseline_exists=False, prior_baseline_accepted=False))

    assert decision.action == UpdateFastPathAction.use_full_scan
    assert "missing_accepted_baseline" in decision.reason_codes
    assert decision.expensive_phases_skipped is False


def test_smart_policy_requires_eligible_context_proof():
    decision = decide_update_fast_path(state(context_proof=None))

    assert decision.action == UpdateFastPathAction.use_full_scan
    assert "context_not_eligible_for_fast_path" in decision.reason_codes


@pytest.mark.parametrize(
    ("field", "reason_code"),
    [
        ("previous_scan_blocked", "previous_scan_blocked"),
        ("previous_scan_required_manual_review", "previous_scan_required_manual_review"),
        ("cache_stale", "cache_stale"),
        ("scanner_or_rules_changed", "scanner_or_rules_changed"),
    ],
)
def test_smart_policy_forces_full_scan_for_stale_or_risky_state(field, reason_code):
    decision = decide_update_fast_path(state(**{field: True}))

    assert decision.action == UpdateFastPathAction.use_full_scan
    assert reason_code in decision.reason_codes
    assert decision.skipped_phases == []


@pytest.mark.parametrize(
    "trust_change",
    [
        "maintainer_changed",
        "orphan_adopted",
        "source_host_changed",
        "pgp_removed",
        "install_hook_changed",
        "dependency_added",
        "build_function_changed",
    ],
)
def test_smart_policy_forces_full_scan_for_trust_boundary_changes(trust_change):
    decision = decide_update_fast_path(state(trust_boundary_changes=[trust_change]))

    assert decision.action == UpdateFastPathAction.use_full_scan
    assert "trust_boundary_changed" in decision.reason_codes
    assert trust_change in decision.reason_codes
    assert decision.expensive_phases_skipped is False


@pytest.mark.parametrize("trust_change", sorted(TRUST_BOUNDARY_REASON_CODES))
def test_smart_policy_forces_full_scan_for_all_named_trust_boundary_signals(trust_change):
    decision = decide_update_fast_path(state(trust_boundary_changes=[trust_change]))

    assert decision.action == UpdateFastPathAction.use_full_scan
    assert "trust_boundary_changed" in decision.reason_codes
    assert trust_change in decision.reason_codes
    assert decision.skipped_phases == []


def test_smart_policy_allows_fast_path_for_plain_version_bump():
    decision = decide_update_fast_path(state())

    assert decision.action == UpdateFastPathAction.use_smart_fast_path
    assert decision.scan_level == "smart_fast_path"
    assert decision.expensive_phases_skipped is True
    assert "deep_static" in decision.skipped_phases
    assert "no_trust_boundary_changes" in decision.reason_codes
    assert decision.may_update_history_baseline is False


def test_explicit_deep_static_overrides_smart_and_new_only_policies():
    smart = decide_update_fast_path(state(explicit_deep_static=True))
    new_only = decide_update_fast_path(state(policy=UpdateScanPolicy.new_only, explicit_deep_static=True))

    assert smart.action == UpdateFastPathAction.use_full_scan
    assert new_only.action == UpdateFastPathAction.use_full_scan
    assert smart.reason_codes == ["explicit_deep_static_requested"]
    assert new_only.reason_codes == ["explicit_deep_static_requested"]


def test_unknown_context_cannot_fast_path():
    decision = decide_update_fast_path(state(context=ScanContext.unknown))

    assert decision.action == UpdateFastPathAction.cannot_fast_path
    assert decision.scan_level == "full"
    assert "unknown_scan_context" in decision.reason_codes
    assert decision.expensive_phases_skipped is False


def test_new_only_skips_updates_for_already_installed_packages():
    decision = decide_update_fast_path(state(policy=UpdateScanPolicy.new_only))

    assert decision.action == UpdateFastPathAction.skip_update_scan
    assert decision.scan_level == "skipped_update"
    assert decision.expensive_phases_skipped is True
    assert "deterministic_static" in decision.skipped_phases
    assert decision.may_update_history_baseline is False
    assert "weaker protection" in decision.why_it_matters


def test_new_only_scans_new_packages_and_dependencies():
    install = decide_update_fast_path(state(policy=UpdateScanPolicy.new_only, context=ScanContext.install, already_installed=False))
    dependency = decide_update_fast_path(state(policy=UpdateScanPolicy.new_only, context=ScanContext.dependency, already_installed=False))

    assert install.action == UpdateFastPathAction.use_full_scan
    assert dependency.action == UpdateFastPathAction.use_full_scan
    assert install.expensive_phases_skipped is False
    assert dependency.expensive_phases_skipped is False


def test_fast_path_decision_serializes_reason_codes_and_skipped_phases():
    decision = decide_update_fast_path(state())
    data = decision.to_dict()

    assert data["policy"] == "smart"
    assert data["scan_context"] == "update"
    assert data["reason_codes"] == ["accepted_baseline", "no_trust_boundary_changes"]
    assert data["expensive_phases_skipped"] is True
    assert "deep_static" in data["skipped_phases"]
    assert data["technical_details"]["prior_baseline_accepted"] is True


def test_scan_report_json_records_policy_and_fast_path_decision():
    decision = decide_update_fast_path(state())
    report = ScanReport(
        PackageMetadata("pkg", "1"),
        risk_summary=RiskSummary(Severity.LOW, RecommendedAction.allow),
        scan_policy="smart",
        fast_path_decision=decision.to_dict(),
    )

    data = report.to_dict()

    assert data["scan_policy"] == "smart"
    assert data["fast_path_decision"]["action"] == "use_smart_fast_path"
    assert data["fast_path_decision"]["reason_codes"] == ["accepted_baseline", "no_trust_boundary_changes"]


def test_terminal_output_explains_smart_fast_path_and_new_only_tradeoff():
    smart = decide_update_fast_path(state())
    new_only = decide_update_fast_path(state(policy=UpdateScanPolicy.new_only))

    smart_report = ScanReport(
        PackageMetadata("pkg", "1"),
        risk_summary=RiskSummary(Severity.LOW, RecommendedAction.allow),
        scan_policy="smart",
        fast_path_decision=smart.to_dict(),
    )
    new_only_report = ScanReport(
        PackageMetadata("pkg", "1"),
        risk_summary=RiskSummary(Severity.LOW, RecommendedAction.allow),
        scan_policy="new-only",
        fast_path_decision=new_only.to_dict(),
    )

    smart_output = smart_report.render_terminal(use_color=False)
    new_only_output = new_only_report.render_terminal(use_color=False)

    assert "Smart update fast path selected." in smart_output
    assert "What AuraScan checked:" in smart_output
    assert "What AuraScan did not check:" in smart_output
    assert "Update scan skipped by new-only policy." in new_only_output
    assert "weaker protection mode" in new_only_output
