import json

import pytest

from aurascan.core.models import PackageMetadata, RecommendedAction, RiskSummary, ScanReport, Severity
from aurascan.core.context_provider import build_scan_context_proof
from aurascan.core.trust_diff import (
    TrustBoundaryClassification,
    TrustBoundaryDiffInput,
    classify_trust_boundary_diff,
)
from aurascan.core.update_policy import (
    ScanContext,
    ScanContextSource,
    UpdateFastPathAction,
    UpdateScanPolicy,
    UpdateScanState,
    decide_update_fast_path,
)


def snapshot(**overrides):
    data = {
        "package_name": "demo",
        "version": "1.2.3",
        "maintainer": "Alice <alice@example.invalid>",
        "source_urls": ["https://example.invalid/releases/demo-1.2.3.tar.gz"],
        "source_hosts": ["example.invalid"],
        "checksums": ["aaa"],
        "checksum_algorithms": ["sha256"],
        "validpgpkeys": ["0123456789ABCDEF0123456789ABCDEF01234567"],
        "depends": ["glibc"],
        "makedepends": ["make"],
        "checkdepends": ["pytest"],
        "optdepends": ["demo-docs"],
        "install_file_hash": "install-hash",
        "prepare_hash": "prepare-hash",
        "build_hash": "build-hash",
        "check_hash": "check-hash",
        "package_hash": "package-hash",
        "prepare_network_fetch": False,
        "build_network_fetch": False,
        "check_network_fetch": False,
        "package_network_fetch": False,
        "source_metadata_risk_summary": {},
    }
    data.update(overrides)
    return data


def classify(previous=None, current=None, **overrides):
    return classify_trust_boundary_diff(
        TrustBoundaryDiffInput(
            previous_snapshot=previous if previous is not None else snapshot(),
            current_snapshot=current if current is not None else snapshot(),
            **overrides,
        )
    )


def test_likely_normal_version_churn_allows_smart_fast_path():
    previous = snapshot()
    current = snapshot(
        version="1.2.4",
        source_urls=["https://example.invalid/releases/demo-1.2.4.tar.gz"],
        checksums=["bbb"],
    )

    result = classify(previous, current)

    assert result.classification == TrustBoundaryClassification.likely_normal_version_bump
    assert result.allow_smart_fast_path is True
    assert result.require_full_scan is False
    assert result.requires_manual_review is False
    assert result.severity == Severity.LOW
    assert "source_path_version_only_change" in result.reason_codes
    assert "checksum_changed_with_version_bump" in result.reason_codes
    assert "sources" in result.normal_churn_fields
    assert "checksums" in result.normal_churn_fields


@pytest.mark.parametrize(
    ("overrides", "expected_reason", "expected_classification"),
    [
        ({"previous_scan_blocked": True}, "previous_scan_blocked", TrustBoundaryClassification.trust_boundary_changed),
        ({"previous_scan_required_manual_review": True}, "previous_scan_manual_review", TrustBoundaryClassification.trust_boundary_changed),
        ({"scanner_or_rules_changed": True}, "scanner_or_rules_changed", TrustBoundaryClassification.trust_boundary_changed),
        ({"cache_stale": True}, "cache_stale", TrustBoundaryClassification.trust_boundary_changed),
    ],
)
def test_state_blockers_force_full_scan(overrides, expected_reason, expected_classification):
    result = classify(**overrides)

    assert result.classification == expected_classification
    assert result.require_full_scan is True
    assert result.allow_smart_fast_path is False
    assert expected_reason in result.reason_codes


def test_no_prior_baseline_forces_full_scan_without_manual_review():
    result = classify_trust_boundary_diff(
        TrustBoundaryDiffInput(previous_snapshot=None, current_snapshot=snapshot())
    )

    assert result.classification == TrustBoundaryClassification.insufficient_history
    assert result.require_full_scan is True
    assert result.requires_manual_review is False
    assert "no_prior_baseline" in result.reason_codes


@pytest.mark.parametrize(
    ("current", "reason", "classification"),
    [
        (
            snapshot(maintainer="Bob <bob@example.invalid>"),
            "maintainer_changed",
            TrustBoundaryClassification.maintainer_or_ownership_changed,
        ),
        (
            snapshot(maintainer="Bob <bob@example.invalid>"),
            "orphan_adopted",
            TrustBoundaryClassification.maintainer_or_ownership_changed,
        ),
        (
            snapshot(source_urls=["https://evil.example.invalid/demo-1.2.3.tar.gz"], source_hosts=["evil.example.invalid"]),
            "source_host_changed",
            TrustBoundaryClassification.source_location_changed,
        ),
        (
            snapshot(checksums=["SKIP"], checksum_algorithms=["skip"]),
            "checksum_became_skip",
            TrustBoundaryClassification.verification_weakened,
        ),
        (
            snapshot(checksum_algorithms=["md5"]),
            "checksum_algorithm_weakened",
            TrustBoundaryClassification.verification_weakened,
        ),
        (
            snapshot(validpgpkeys=[]),
            "validpgpkeys_removed",
            TrustBoundaryClassification.verification_weakened,
        ),
        (
            snapshot(
                source_urls=["https://example.invalid/releases/demo-1.2.3.tar.gz"],
                checksums=["aaa"],
            ),
            "signature_source_removed",
            TrustBoundaryClassification.verification_weakened,
        ),
        (
            snapshot(install_file_hash="new-install-hash"),
            "install_hook_changed",
            TrustBoundaryClassification.install_behavior_changed,
        ),
        (
            snapshot(depends=["glibc", "curl"]),
            "dependency_added",
            TrustBoundaryClassification.dependency_trust_chain_changed,
        ),
        (
            snapshot(depends=["musl"]),
            "dependency_replaced",
            TrustBoundaryClassification.dependency_trust_chain_changed,
        ),
        (
            snapshot(build_hash="new-build-hash"),
            "build_function_changed",
            TrustBoundaryClassification.build_logic_changed,
        ),
        (
            snapshot(build_network_fetch=True),
            "new_network_fetch_pattern",
            TrustBoundaryClassification.build_logic_changed,
        ),
        (
            snapshot(source_metadata_risk_summary={"credential_reference": True}),
            "new_credential_reference_pattern",
            TrustBoundaryClassification.build_logic_changed,
        ),
        (
            snapshot(source_metadata_risk_summary={"persistence": True}),
            "new_persistence_pattern",
            TrustBoundaryClassification.build_logic_changed,
        ),
        (
            snapshot(source_metadata_risk_summary={"suid": True}),
            "new_suid_pattern",
            TrustBoundaryClassification.build_logic_changed,
        ),
    ],
)
def test_trust_boundary_blockers_force_full_scan_and_manual_review(current, reason, classification):
    previous = snapshot()
    if reason == "orphan_adopted":
        previous = snapshot(maintainer="")
    if reason == "signature_source_removed":
        previous = snapshot(
            source_urls=[
                "https://example.invalid/releases/demo-1.2.3.tar.gz",
                "https://example.invalid/releases/demo-1.2.3.tar.gz.sig",
            ],
            checksums=["aaa", "SKIP"],
        )

    result = classify(previous, current)

    assert result.classification == classification
    assert result.require_full_scan is True
    assert result.allow_smart_fast_path is False
    assert result.requires_manual_review is True
    assert reason in result.reason_codes


def test_install_hook_added_forces_full_scan():
    previous = snapshot(install_file_hash="")
    current = snapshot(install_file_hash="new-install-hash")

    result = classify(previous, current)

    assert result.classification == TrustBoundaryClassification.install_behavior_changed
    assert "install_hook_added" in result.reason_codes
    assert result.require_full_scan is True


def test_same_source_url_with_unexpected_checksum_change_blocks_fast_path():
    result = classify(snapshot(), snapshot(checksums=["bbb"]))

    assert result.classification == TrustBoundaryClassification.verification_weakened
    assert "checksum_changed_without_source_version_pattern" in result.reason_codes
    assert result.require_full_scan is True


def test_source_host_change_with_checksum_change_blocks_fast_path():
    current = snapshot(
        version="1.2.4",
        source_urls=["https://mirror.example.invalid/releases/demo-1.2.4.tar.gz"],
        source_hosts=["mirror.example.invalid"],
        checksums=["bbb"],
    )

    result = classify(snapshot(), current)

    assert result.classification == TrustBoundaryClassification.source_location_changed
    assert "source_host_changed" in result.reason_codes
    assert result.require_full_scan is True


def test_checksum_algorithm_strengthening_does_not_count_as_weakened():
    result = classify(
        snapshot(checksum_algorithms=["md5"]),
        snapshot(checksum_algorithms=["sha256"]),
    )

    assert result.allow_smart_fast_path is True
    assert "checksum_algorithm_weakened" not in result.reason_codes
    assert "checksum_algorithms" in result.normal_churn_fields


def test_checksum_algorithm_weakening_blocks_fast_path():
    result = classify(
        snapshot(checksum_algorithms=["sha256"]),
        snapshot(checksum_algorithms=["md5"]),
    )

    assert result.require_full_scan is True
    assert "checksum_algorithm_weakened" in result.reason_codes


def test_skip_to_strong_checksum_is_reported_as_low_risk_metadata_change():
    result = classify(
        snapshot(checksums=["SKIP"], checksum_algorithms=["skip"]),
        snapshot(checksums=["aaa"], checksum_algorithms=["sha256"]),
    )

    assert result.classification == TrustBoundaryClassification.metadata_changed_but_low_risk
    assert result.allow_smart_fast_path is True
    assert "checksum_added" in result.reason_codes
    assert "checksums" in result.normal_churn_fields


def smart_state(diff_result=None, **overrides):
    data = {
        "policy": UpdateScanPolicy.smart,
        "context": ScanContext.update,
        "context_source": ScanContextSource.test_fixture,
        "already_installed": True,
        "prior_baseline_exists": True,
        "prior_baseline_accepted": True,
        "trust_diff_result": diff_result,
        "context_proof": build_scan_context_proof(
            context=ScanContext.update,
            source=ScanContextSource.test_fixture,
        ),
    }
    data.update(overrides)
    return UpdateScanState(**data)


def test_update_policy_smart_uses_classifier_result_when_provided():
    diff = classify(
        snapshot(),
        snapshot(
            version="1.2.4",
            source_urls=["https://example.invalid/releases/demo-1.2.4.tar.gz"],
            checksums=["bbb"],
        ),
    )

    decision = decide_update_fast_path(smart_state(diff))

    assert decision.action == UpdateFastPathAction.use_smart_fast_path
    assert decision.title == "Update looks like normal version churn."
    assert decision.technical_details["trust_boundary_diff"]["classification"] == "likely_normal_version_bump"
    assert "source_path_version_only_change" in decision.reason_codes


def test_update_policy_smart_uses_classifier_blocker_for_full_scan():
    diff = classify(snapshot(), snapshot(maintainer="Bob <bob@example.invalid>"))

    decision = decide_update_fast_path(smart_state(diff))

    assert decision.action == UpdateFastPathAction.use_full_scan
    assert decision.title == "Update changed an important trust boundary."
    assert "maintainer_changed" in decision.reason_codes
    assert decision.technical_details["trust_boundary_diff"]["requires_manual_review"] is True


def test_update_policy_full_new_only_deep_static_and_unknown_context_stay_conservative():
    diff = classify(
        snapshot(),
        snapshot(
            version="1.2.4",
            source_urls=["https://example.invalid/releases/demo-1.2.4.tar.gz"],
            checksums=["bbb"],
        ),
    )

    full = decide_update_fast_path(smart_state(diff, policy=UpdateScanPolicy.full))
    new_only = decide_update_fast_path(smart_state(diff, policy=UpdateScanPolicy.new_only))
    deep_static = decide_update_fast_path(smart_state(diff, explicit_deep_static=True))
    unknown = decide_update_fast_path(smart_state(diff, context=ScanContext.unknown))

    assert full.action == UpdateFastPathAction.use_full_scan
    assert new_only.action == UpdateFastPathAction.skip_update_scan
    assert new_only.may_update_history_baseline is False
    assert deep_static.action == UpdateFastPathAction.use_full_scan
    assert unknown.action == UpdateFastPathAction.cannot_fast_path


def test_terminal_and_json_render_normal_churn_without_raw_reason_codes_by_default():
    diff = classify(
        snapshot(),
        snapshot(
            version="1.2.4",
            source_urls=["https://example.invalid/releases/demo-1.2.4.tar.gz"],
            checksums=["bbb"],
        ),
    )
    decision = decide_update_fast_path(smart_state(diff))
    report = ScanReport(
        PackageMetadata("demo", "1.2.4"),
        risk_summary=RiskSummary(Severity.LOW, RecommendedAction.allow),
        scan_policy="smart",
        fast_path_decision=decision.to_dict(),
    )

    default_output = report.render_terminal(use_color=False)
    verbose_output = report.render_terminal(use_color=False, verbose=True)
    data = json.loads(report.to_json())

    assert "Update looks like normal version churn." in default_output
    assert "source_path_version_only_change" not in default_output
    assert "Technical details:" in verbose_output
    assert "source_path_version_only_change" in verbose_output
    assert data["fast_path_decision"]["technical_details"]["trust_boundary_diff"]["reason_codes"]


def test_terminal_render_trust_boundary_change_is_clear_and_actionable():
    diff = classify(snapshot(), snapshot(maintainer="Bob <bob@example.invalid>"))
    decision = decide_update_fast_path(smart_state(diff))
    report = ScanReport(
        PackageMetadata("demo", "1.2.4"),
        risk_summary=RiskSummary(Severity.MEDIUM, RecommendedAction.manual_review, requires_manual_review=True),
        scan_policy="smart",
        fast_path_decision=decision.to_dict(),
    )

    output = report.render_terminal(use_color=False)

    assert "Update changed an important trust boundary." in output
    assert "smart fast path should not be used" in output
    assert "Review the warning details." in output
    assert "maintainer_changed" not in output
