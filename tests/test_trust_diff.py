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


@pytest.mark.parametrize("version", ["1.2.3", "1.2.4"])
@pytest.mark.parametrize(
    ("previous_selector", "current_selector"),
    [
        ("commit=" + "a" * 40, "branch=main"),
        ("commit=" + "a" * 40, "tag=v1.2.4"),
        ("commit=" + "a" * 40, "commit=" + "b" * 40),
        ("tag=v1.2.3", "tag=v1.2.4"),
        ("branch=main", "branch=release"),
        ("commit=" + "a" * 40, ""),
    ],
)
def test_git_selector_changes_never_become_archive_version_churn(version, previous_selector, current_selector):
    repository = "git+https://example.invalid/repository.git"
    previous = snapshot(source_urls=[repository + "#" + previous_selector], checksums=["SKIP"])
    current = snapshot(
        version=version,
        source_urls=[repository + ("#" + current_selector if current_selector else "")],
        checksums=["SKIP"],
    )

    result = classify(previous, current)

    assert result.require_full_scan is True
    assert result.requires_manual_review is True
    assert result.allow_smart_fast_path is False
    assert result.classification == TrustBoundaryClassification.source_location_changed
    assert "source_url_changed" in result.reason_codes
    assert "source_path_version_only_change" not in result.reason_codes


def test_identical_git_selector_comparison_does_not_claim_remote_revision_inspection():
    unchanged = snapshot(source_urls=["git+https://example.invalid/repository.git#branch=main"], checksums=["SKIP"])

    result = classify(unchanged, unchanged)

    assert result.reason_codes == ["no_relevant_change"]
    assert "does not prove" in result.what_not_proved
    assert "metadata" in result.what_not_proved


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
            "maintainer_annotation_changed",
            TrustBoundaryClassification.trust_boundary_changed,
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


@pytest.mark.parametrize(
    ("previous_annotation", "current_annotation"),
    [
        ("", "Alice"),
        (None, "Alice"),
        ("Alice", ""),
        ("Alice", None),
        ("Alice", "Bob"),
    ],
)
def test_unverified_annotation_changes_preserve_review_without_ownership_claims(
    previous_annotation, current_annotation
):
    result = classify(
        snapshot(maintainer=previous_annotation),
        snapshot(maintainer=current_annotation),
    )

    assert result.reason_codes == ["maintainer_annotation_changed"]
    assert result.classification == TrustBoundaryClassification.trust_boundary_changed
    assert result.severity == Severity.MEDIUM
    assert result.require_full_scan is True
    assert result.requires_manual_review is True
    assert result.allow_smart_fast_path is False
    assert not {"maintainer_changed", "orphan_adopted"} & set(result.reason_codes)
    assert "Alice" not in json.dumps(result.to_dict())
    assert "Bob" not in json.dumps(result.to_dict())


def test_legacy_snapshot_missing_maintainer_is_not_an_orphan_record():
    previous = snapshot()
    previous.pop("maintainer")

    result = classify(previous, snapshot())

    assert result.reason_codes == ["maintainer_annotation_changed"]
    assert result.classification != TrustBoundaryClassification.maintainer_or_ownership_changed
    assert result.require_full_scan is True
    assert result.requires_manual_review is True


@pytest.mark.parametrize(("previous_annotation", "current_annotation"), [("", ""), (None, ""), ("", None), ("Alice", "Alice")])
def test_unchanged_or_unavailable_annotation_is_not_an_ownership_event(previous_annotation, current_annotation):
    result = classify(snapshot(maintainer=previous_annotation), snapshot(maintainer=current_annotation))

    assert result.reason_codes == ["no_relevant_change"]
    assert result.classification == TrustBoundaryClassification.no_relevant_change
    assert result.requires_manual_review is False


@pytest.mark.parametrize(
    ("annotation", "local_narrative"),
    [
        ("", {"states": ["deleted", "restored", "orphan"], "event": "restore"}),
        ("", {"state": "orphan", "event": "push", "actor_role": "unprivileged", "outcome": "denied"}),
        ("", {"state": "orphan", "event": "push", "actor_role": "co-maintainer", "outcome": "accepted"}),
        ("Bob", {"states": ["orphan", "maintained"], "event": "adoption", "reviewed": True}),
    ],
    ids=["deleted-restore-orphan", "orphan-unprivileged-push", "orphan-co-maintainer-push", "claimed-reviewed-adoption"],
)
def test_local_aur_narratives_do_not_establish_authoritative_ownership(annotation, local_narrative):
    # These are unverified local fields, not an AUR RPC response or server history.
    # In particular, a claimed review is not evidence that a platform review occurred.
    previous = snapshot(maintainer="")
    current = snapshot(maintainer=annotation, aur_history=local_narrative, commit_author="Bob")

    result = classify(previous, current)

    assert not {"maintainer_changed", "orphan_adopted", "restored", "package_restored"} & set(result.reason_codes)
    assert result.classification != TrustBoundaryClassification.maintainer_or_ownership_changed
    if annotation:
        assert result.reason_codes == ["maintainer_annotation_changed"]
        assert result.require_full_scan is True
        assert result.requires_manual_review is True
    else:
        assert result.reason_codes == ["no_relevant_change"]


@pytest.mark.parametrize(("previous_annotation", "current_annotation"), [("", "Bob"), ("Alice", "Bob")])
def test_explicit_maintainer_string_inputs_do_not_assert_aur_authority(previous_annotation, current_annotation):
    result = classify(
        previous_maintainer=previous_annotation,
        current_maintainer=current_annotation,
    )

    assert result.reason_codes == ["maintainer_annotation_changed"]
    assert result.classification == TrustBoundaryClassification.trust_boundary_changed
    assert result.require_full_scan is True
    assert result.requires_manual_review is True


def test_hostile_annotation_is_not_exposed_in_trust_details():
    hostile = "fake-secret-value \x1b[31m https://example.invalid/?token=fake-secret-value"

    result = classify(snapshot(), snapshot(maintainer=hostile))

    assert result.reason_codes == ["maintainer_annotation_changed"]
    serialized = json.dumps(result.to_dict())
    assert "fake-secret-value" not in serialized
    assert "\\u001b" not in serialized
    assert "alice@example.invalid" not in serialized


def test_install_hook_added_forces_full_scan():
    previous = snapshot(install_file_hash="")
    current = snapshot(install_file_hash="new-install-hash")

    result = classify(previous, current)

    assert result.classification == TrustBoundaryClassification.install_behavior_changed
    assert "install_hook_added" in result.reason_codes
    assert result.require_full_scan is True


def test_exact_install_hook_identity_detects_target_change_with_same_content_hash():
    previous = snapshot(
        install_file_hash="same-content",
        install_hook_input_digest="exact-first-target",
    )
    current = snapshot(
        install_file_hash="same-content",
        install_hook_input_digest="exact-second-target",
    )

    result = classify(previous, current)

    assert result.classification == TrustBoundaryClassification.install_behavior_changed
    assert "install_hook_changed" in result.reason_codes


def test_repository_only_identity_change_forces_full_scan_without_malware_claim():
    previous = snapshot(
        repository_input_digest="repository-a",
        repository_status="complete",
    )
    current = snapshot(
        repository_input_digest="repository-b",
        repository_status="complete",
    )

    result = classify(previous, current)

    assert result.classification == TrustBoundaryClassification.build_logic_changed
    assert result.require_full_scan is True
    assert result.allow_smart_fast_path is False
    assert result.requires_manual_review is False
    assert "repository_provenance_changed" in result.reason_codes
    assert result.technical_details["repository_provenance"] == {
        "previous_status": "complete",
        "current_status": "complete",
        "identity_changed": True,
    }


def test_legacy_install_hash_snapshot_is_compatible_with_new_exact_snapshot():
    previous = snapshot(install_file_hash="same-content")
    current = snapshot(
        install_file_hash="same-content",
        install_hook_input_digest="new-exact-identity",
    )

    result = classify(previous, current)

    assert "install_hook_changed" not in result.reason_codes
    assert "install_hook" not in result.changed_fields


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
    assert "maintainer_annotation_changed" in decision.reason_codes
    assert not {"maintainer_changed", "orphan_adopted"} & set(decision.reason_codes)
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
    assert "maintainer_annotation_changed" not in output
