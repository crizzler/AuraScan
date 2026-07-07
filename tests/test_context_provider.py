from aurascan.core.context_provider import (
    ScanContextAuthority,
    build_scan_context_proof,
)
from aurascan.core.update_policy import ScanContext, ScanContextSource


def test_unknown_context_is_not_fast_path_eligible():
    proof = build_scan_context_proof()

    assert proof.context == ScanContext.unknown
    assert proof.eligible_for_fast_path is False
    assert "unknown_context" in proof.proof_errors


def test_install_and_dependency_contexts_are_not_update_fast_path_eligible():
    install = build_scan_context_proof(context=ScanContext.install, source=ScanContextSource.explicit_cli)
    dependency = build_scan_context_proof(context=ScanContext.dependency, source=ScanContextSource.explicit_cli)

    assert install.eligible_for_fast_path is False
    assert dependency.eligible_for_fast_path is False
    assert "install_context_not_update" in install.proof_reasons
    assert "dependency_context_not_update_by_default" in dependency.proof_reasons


def test_test_fixture_update_context_is_eligible_for_tests():
    proof = build_scan_context_proof(context=ScanContext.update, source=ScanContextSource.test_fixture)

    assert proof.authority == ScanContextAuthority.test_only
    assert proof.eligible_for_fast_path is True
    assert "verified_update_context" in proof.proof_reasons


def test_explicit_cli_update_context_is_user_asserted_and_requires_opt_in():
    proof = build_scan_context_proof(context=ScanContext.update, source=ScanContextSource.explicit_cli)

    assert proof.authority == ScanContextAuthority.user_asserted
    assert proof.eligible_for_fast_path is False
    assert "user_asserted_update_context" in proof.proof_reasons
    assert "user_asserted_context_requires_opt_in" in proof.proof_errors
    assert "not verified" in proof.user_warning


def test_explicit_cli_update_context_can_be_allowed_with_clear_authority():
    proof = build_scan_context_proof(
        context=ScanContext.update,
        source=ScanContextSource.explicit_cli,
        allow_user_asserted_update_context=True,
    )

    assert proof.authority == ScanContextAuthority.user_asserted
    assert proof.eligible_for_fast_path is True
    assert proof.user_warning


def test_verified_provider_requires_identity_and_local_state():
    proof = build_scan_context_proof(context=ScanContext.update, source=ScanContextSource.pacman_hook)

    assert proof.authority == ScanContextAuthority.verified_transaction_provider
    assert proof.eligible_for_fast_path is False
    assert "missing_package_identity" in proof.proof_errors
    assert "installed_package_not_confirmed" in proof.proof_errors
    assert "missing_installed_version" in proof.proof_errors
    assert "missing_candidate_version" in proof.proof_errors
    assert "missing_transaction_operation" in proof.proof_errors


def test_verified_provider_with_complete_update_proof_is_eligible():
    proof = build_scan_context_proof(
        context=ScanContext.update,
        source=ScanContextSource.pacman_hook,
        package_name="demo",
        installed_version="1.0",
        candidate_version="1.1",
        transaction_operation="upgrade",
        installed_package_present=True,
    )

    assert proof.eligible_for_fast_path is True
    assert proof.proof_errors == []


def test_verified_provider_error_or_ambiguous_split_package_is_not_eligible():
    provider_error = build_scan_context_proof(
        context=ScanContext.update,
        source=ScanContextSource.pacman_hook,
        package_name="demo",
        installed_version="1.0",
        candidate_version="1.1",
        installed_package_present=True,
        proof_errors=["local_package_db_unavailable"],
    )
    ambiguous_split = build_scan_context_proof(
        context=ScanContext.update,
        source=ScanContextSource.makepkg_wrapper,
        installed_version="1.0",
        candidate_version="1.1",
        installed_package_present=True,
        proof_errors=["ambiguous_split_package"],
    )

    assert provider_error.eligible_for_fast_path is False
    assert ambiguous_split.eligible_for_fast_path is False
