"""Schema unit-test metadata, not a security dataset or validated sample set."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import sys

import pytest


_TOOL_PATH = Path(__file__).resolve().parents[1] / "tools/validate_security_data.py"
_SPEC = importlib.util.spec_from_file_location("validate_security_data", _TOOL_PATH)
contract = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = contract
_SPEC.loader.exec_module(contract)


def opaque(kind, number):
    return kind + "-" + format(number, "012x")


def digest(number):
    return hashlib.sha256(("contract-test-metadata-" + str(number)).encode("ascii")).hexdigest()


def item(number=1, partition="quarantine", eligible=False):
    value = {
        "id": opaque("item", number),
        "kinds": ["synthetic_adversarial"],
        "origin": "synthetic",
        "collected_at": "2026-09-10",
        "sources": [{"kind": "generated", "reference": opaque("ref", number),
                     "revision": None, "sha256": None}],
        "family_id": opaque("family", number),
        "parent_ids": [],
        "artifact": {"kind": "digest_only", "sha256": digest(number)},
        "classification": "unknown",
        "claim_level": "none",
        "behavior": {"verified": [], "suspected": ["credential_access"]},
        "affected_versions": [],
        "expected": {"outcome": "not_specified", "action": "not_specified", "rule_ids": []},
        "observations": [],
        "review": {"status": "unreviewed", "basis_refs": []},
        "rights": {"analysis": "unknown", "redistribution": "unknown", "training": "unknown",
                   "commercial_training": "unknown", "basis_refs": [],
                   "provider_training": "unknown", "provider_basis_refs": []},
        "provenance": {"status": "unknown", "basis_refs": [], "proprietary_provider_derived": "unknown"},
        "generation": {"method": "unknown", "model_refs": [], "basis_refs": []},
        "privacy": {"status": "unknown", "visibility": "private"},
        "partition": partition,
        "eligibility": {"training": False, "evaluation": False, "commercial_training": False, "redistribution": False},
    }
    if partition == "private_held_out":
        value["kinds"].append("private_held_out")
    if eligible:
        value["review"] = {"status": "human_validated", "basis_refs": [opaque("ref", number + 100)]}
        value["rights"]["analysis"] = "allowed"
        value["rights"]["basis_refs"] = [opaque("ref", number + 200)]
        value["privacy"]["status"] = "clear"
        value["provenance"] = {"status": "reviewed", "basis_refs": [opaque("ref", number + 300)],
                               "proprietary_provider_derived": "no"}
        value["generation"] = {"method": "human", "model_refs": [], "basis_refs": [opaque("ref", number + 400)]}
        value["rights"]["provider_training"] = "not_applicable"
        if partition == "training":
            value["eligibility"]["training"] = True
            value["rights"]["training"] = "allowed"
        else:
            value["eligibility"]["evaluation"] = True
    return value


def manifest(tmp_path, values, name="manifest.json"):
    path = tmp_path / name
    path.write_text(json.dumps({"schema_version": "aurascan-security-data/1.0", "items": values}), encoding="utf-8")
    return path


def rejected(tmp_path, value, code):
    with pytest.raises(contract.ContractError) as error:
        contract.validate_manifests([manifest(tmp_path, [value])])
    assert error.value.code == code
    return error.value


def test_quarantined_unreviewed_metadata_has_no_implied_permission(tmp_path):
    summary = contract.validate_manifests([manifest(tmp_path, [item()])])
    assert (summary.manifests, summary.items, summary.quarantined) == (1, 1, 1)
    assert summary.training == summary.evaluation == 0


def test_distinct_reviewed_partitions_validate_in_one_explicit_batch(tmp_path):
    paths = [manifest(tmp_path, [item(1, "training", True)], "train.json"),
             manifest(tmp_path, [item(2, "evaluation", True), item(3, "private_held_out", True)], "eval.json")]
    summary = contract.validate_manifests(paths)
    assert summary.items == 3 and summary.training == 1 and summary.evaluation == 2
    assert summary.private_held_out == 1


@pytest.mark.parametrize("right", ["unknown", "denied", "allowed"])
def test_local_evaluation_rights_do_not_imply_training_or_redistribution(tmp_path, right):
    value = item(1, "evaluation", True)
    value["rights"]["training"] = right
    value["rights"]["redistribution"] = right
    assert contract.validate_manifests([manifest(tmp_path, [value])]).evaluation == 1


def test_training_does_not_require_redistribution_permission(tmp_path):
    value = item(1, "training", True)
    value["rights"]["redistribution"] = "denied"
    assert contract.validate_manifests([manifest(tmp_path, [value])]).training == 1


@pytest.mark.parametrize("version", [None, "aurascan-security-data/0.9", "aurascan-security-data/1.1", "aurascan-security-data/2.0"])
def test_schema_versions_are_exact_and_never_implicitly_migrated(tmp_path, version):
    document = {"schema_version": version, "items": [item(1, "training", True)]}
    if version is None:
        del document["schema_version"]
    path = tmp_path / "old.json"
    path.write_text(json.dumps(document))
    with pytest.raises(contract.ContractError, match="fields" if version is None else "schema_version"):
        contract.validate_manifests([path])


@pytest.mark.parametrize("section,field", [
    ("rights", "commercial_training"), ("rights", "provider_training"),
    ("rights", "redistribution"), ("rights", "provider_basis_refs"),
    ("eligibility", "commercial_training"), ("eligibility", "redistribution"),
    ("provenance", "status"), ("provenance", "proprietary_provider_derived"),
    ("generation", "method"),
])
def test_new_permission_and_provenance_fields_cannot_be_omitted(tmp_path, section, field):
    value = item(1, "training", True)
    del value[section][field]
    rejected(tmp_path, value, "fields")


@pytest.mark.parametrize("right", ["unknown", "denied"])
def test_redistribution_eligibility_needs_its_own_permission(tmp_path, right):
    value = item(1, "evaluation", True)
    value["eligibility"]["redistribution"] = True
    value["rights"]["redistribution"] = right
    rejected(tmp_path, value, "redistribution_rights")


def test_redistribution_neither_grants_nor_requires_training_rights(tmp_path):
    value = item(1, "evaluation", True)
    value["eligibility"]["evaluation"] = False
    value["eligibility"]["redistribution"] = True
    value["rights"]["redistribution"] = "allowed"
    value["rights"]["training"] = "denied"
    summary = contract.validate_manifests([manifest(tmp_path, [value])])
    assert summary.redistribution == 1 and summary.training == summary.commercial_training == 0


def test_public_exposure_is_not_new_redistribution_authority(tmp_path):
    value = item()
    value["privacy"]["visibility"] = "public"
    value["rights"]["redistribution"] = "denied"
    assert contract.validate_manifests([manifest(tmp_path, [value])]).redistribution == 0


@pytest.mark.parametrize("right", ["unknown", "denied"])
def test_general_training_permission_does_not_grant_commercial_training(tmp_path, right):
    value = item(1, "training", True)
    value["rights"]["commercial_training"] = right
    assert contract.validate_manifests([manifest(tmp_path, [value])]).commercial_training == 0
    value["eligibility"]["commercial_training"] = True
    rejected(tmp_path, value, "commercial_training_rights")


def test_commercial_training_requires_general_training_eligibility(tmp_path):
    value = item(1, "training", True)
    value["rights"]["commercial_training"] = "allowed"
    value["eligibility"]["commercial_training"] = True
    assert contract.validate_manifests([manifest(tmp_path, [value])]).commercial_training == 1
    value["eligibility"]["training"] = False
    rejected(tmp_path, value, "commercial_training_requires_training")


@pytest.mark.parametrize("partition", ["training", "evaluation"])
def test_unknown_provenance_cannot_support_eligibility(tmp_path, partition):
    value = item(1, partition, True)
    value["provenance"]["status"] = "unknown"
    rejected(tmp_path, value, "eligibility_provenance")


def test_redistribution_requires_review_privacy_and_provenance_even_without_evaluation(tmp_path):
    value = item(1, "evaluation", True)
    value["eligibility"].update(evaluation=False, redistribution=True)
    value["rights"]["redistribution"] = "allowed"
    value["provenance"]["status"] = "unknown"
    rejected(tmp_path, value, "eligibility_provenance")
    value["provenance"]["status"] = "reviewed"
    value["privacy"]["status"] = "unknown"
    rejected(tmp_path, value, "eligibility_privacy")
    value["privacy"]["status"] = "clear"
    value["review"]["status"] = "unreviewed"
    rejected(tmp_path, value, "eligibility_review")


def proprietary_output(number=1, partition="training"):
    value = item(number, partition, True)
    value["provenance"]["proprietary_provider_derived"] = "yes"
    value["generation"] = {"method": "model", "model_refs": [opaque("model", number)],
                           "basis_refs": [opaque("ref", number + 500)]}
    value["rights"]["provider_training"] = "unknown"
    return value


@pytest.mark.parametrize("permission", ["unknown", "denied"])
def test_proprietary_provider_outputs_require_explicit_training_permission(tmp_path, permission):
    value = proprietary_output()
    value["rights"]["provider_training"] = permission
    rejected(tmp_path, value, "provider_training_rights")


def test_proprietary_training_requires_provider_basis_and_separate_commercial_scope(tmp_path):
    value = proprietary_output()
    value["rights"]["provider_training"] = "allowed"
    rejected(tmp_path, value, "provider_rights_basis")
    value["rights"]["provider_basis_refs"] = [opaque("ref", 901)]
    assert contract.validate_manifests([manifest(tmp_path, [value])]).training == 1
    value["eligibility"]["commercial_training"] = True
    rejected(tmp_path, value, "commercial_training_rights")
    value["rights"]["commercial_training"] = "allowed"
    assert contract.validate_manifests([manifest(tmp_path, [value])]).commercial_training == 1


def test_provider_training_is_distinct_from_authorized_local_evaluation(tmp_path):
    value = proprietary_output(partition="evaluation")
    value["rights"]["provider_training"] = "denied"
    assert contract.validate_manifests([manifest(tmp_path, [value])]).evaluation == 1


@pytest.mark.parametrize("purpose", ["training", "redistribution"])
def test_uncertain_provider_origin_blocks_training_and_redistribution(tmp_path, purpose):
    value = item(1, "training" if purpose == "training" else "evaluation", True)
    value["provenance"]["proprietary_provider_derived"] = "unknown"
    value["rights"]["provider_training"] = "unknown"
    value["eligibility"][purpose] = True
    value["rights"][purpose] = "allowed"
    rejected(tmp_path, value, "eligibility_provider_provenance")


def test_provider_applicability_cannot_be_waived_for_known_or_uncertain_provider_material(tmp_path):
    value = proprietary_output()
    value["rights"]["provider_training"] = "not_applicable"
    rejected(tmp_path, value, "provider_rights_applicability")


def test_explicit_provider_denial_cannot_be_ignored_by_an_origin_declaration(tmp_path):
    value = item(1, "training", True)
    value["rights"]["provider_training"] = "denied"
    rejected(tmp_path, value, "provider_training_rights")


@pytest.mark.parametrize("change,code", [
    ({"method": "unknown", "model_refs": [], "basis_refs": []}, "eligibility_provenance"),
    ({"method": "model", "model_refs": [], "basis_refs": [opaque("ref", 42)]}, "generation_model"),
    ({"method": "model", "model_refs": [opaque("model", 42)], "basis_refs": []}, "generation_basis"),
    ({"method": "human", "model_refs": [opaque("model", 42)], "basis_refs": [opaque("ref", 42)]}, "generation_method"),
    ({"method": "none", "model_refs": [], "basis_refs": []}, "generation_origin"),
])
def test_generation_provenance_requires_a_consistent_method_and_evidence(tmp_path, change, code):
    value = item(1, "training", True)
    value["generation"] = change
    rejected(tmp_path, value, code)


def test_reviewed_provenance_requires_a_basis(tmp_path):
    value = item(1, "training", True)
    value["provenance"]["basis_refs"] = []
    rejected(tmp_path, value, "provenance_basis")


@pytest.mark.parametrize("purpose", ["training", "commercial_training", "redistribution"])
def test_parent_permission_restrictions_survive_human_rewrites_and_intermediaries(tmp_path, purpose):
    parent = proprietary_output(1)
    parent["partition"] = "quarantine"
    parent["eligibility"] = dict.fromkeys(contract.USES, False)
    parent["rights"].update(training="allowed", commercial_training="allowed", redistribution="allowed")
    if purpose != "training":
        parent["rights"].update(provider_training="allowed", provider_basis_refs=[opaque("ref", 901)])
        parent["rights"][purpose] = "denied"
    middle = item(2, "training", True)
    middle["partition"] = "quarantine"
    middle["eligibility"] = dict.fromkeys(contract.USES, False)
    middle["rights"].update(commercial_training="allowed", redistribution="allowed")
    middle["parent_ids"] = [parent["id"]]
    child = item(3, "evaluation" if purpose == "redistribution" else "training", True)
    child["rights"].update(commercial_training="allowed", redistribution="allowed")
    child["eligibility"][purpose] = True
    child["parent_ids"] = [middle["id"]]
    with pytest.raises(contract.ContractError, match="lineage_rights"):
        contract.validate_manifests([manifest(tmp_path, [child, middle, parent])])


def test_independent_family_members_do_not_inherit_each_others_license(tmp_path):
    source = item(1, "training", True)
    source["eligibility"]["training"] = False
    source["rights"]["training"] = "denied"
    target = item(2, "training", True)
    target["family_id"] = source["family_id"]
    assert contract.validate_manifests([manifest(tmp_path, [source, target])]).training == 1


@pytest.mark.parametrize("uncertainty", ["provenance", "provider_origin", "generation"])
def test_all_parent_branches_must_support_the_requested_use(tmp_path, uncertainty):
    known = item(1, "training", True)
    uncertain = item(2, "training", True)
    uncertain["partition"] = "quarantine"
    uncertain["eligibility"] = dict.fromkeys(contract.USES, False)
    if uncertainty == "provenance":
        uncertain["provenance"]["status"] = "unknown"
    elif uncertainty == "provider_origin":
        uncertain["provenance"]["proprietary_provider_derived"] = "unknown"
        uncertain["rights"]["provider_training"] = "unknown"
    else:
        uncertain["generation"] = {"method": "unknown", "model_refs": [], "basis_refs": []}
    child = item(3, "training", True)
    child["parent_ids"] = [known["id"], uncertain["id"]]
    with pytest.raises(contract.ContractError, match="lineage_rights"):
        contract.validate_manifests([
            manifest(tmp_path, [child], "child.json"), manifest(tmp_path, [uncertain, known], "parents.json")])


def test_parent_rights_can_support_an_explicitly_reviewed_derivative(tmp_path):
    parent = proprietary_output(1)
    parent["partition"] = "quarantine"
    parent["eligibility"] = dict.fromkeys(contract.USES, False)
    parent["rights"].update(provider_training="allowed", provider_basis_refs=[opaque("ref", 901)])
    child = item(2, "training", True)
    child["parent_ids"] = [parent["id"]]
    assert contract.validate_manifests([manifest(tmp_path, [child, parent])]).training == 1


@pytest.mark.parametrize("permission", ["unknown", "denied"])
def test_parent_analysis_permission_is_required_for_local_evaluation(tmp_path, permission):
    parent = item(1, "evaluation", True)
    parent["partition"] = "quarantine"
    parent["eligibility"] = dict.fromkeys(contract.USES, False)
    parent["rights"]["analysis"] = permission
    child = item(2, "evaluation", True)
    child["parent_ids"] = [parent["id"]]
    with pytest.raises(contract.ContractError, match="lineage_rights"):
        contract.validate_manifests([manifest(tmp_path, [child, parent])])


def test_reserved_holdout_lineage_cannot_be_redistribution_eligible(tmp_path):
    heldout = item(1, "private_held_out", True)
    child = item(2, "evaluation", True)
    child["parent_ids"] = [heldout["id"]]
    child["rights"]["redistribution"] = "allowed"
    child["eligibility"]["redistribution"] = True
    with pytest.raises(contract.ContractError, match="heldout_redistribution"):
        contract.validate_manifests([manifest(tmp_path, [heldout, child])])


def test_candidate_review_does_not_automatically_grant_eligibility(tmp_path):
    value = item(1, "training", True)
    value["partition"] = "quarantine"
    value["eligibility"] = dict.fromkeys(contract.USES, False)
    assert contract.validate_manifests([manifest(tmp_path, [value])]).training == 0
    value["eligibility"]["training"] = True
    rejected(tmp_path, value, "quarantine_eligible")


@pytest.mark.parametrize("right", ["unknown", "denied"])
@pytest.mark.parametrize("partition", ["training", "evaluation"])
def test_analysis_permission_is_required_for_each_eligible_use(tmp_path, right, partition):
    value = item(1, partition, True)
    value["rights"]["analysis"] = right
    rejected(tmp_path, value, "eligibility_rights")


@pytest.mark.parametrize("right", ["unknown", "denied"])
def test_training_permission_is_separate_and_required(tmp_path, right):
    value = item(1, "training", True)
    value["rights"]["training"] = right
    rejected(tmp_path, value, "training_rights")


def test_allowed_rights_need_traceable_permission_basis(tmp_path):
    value = item(1, "evaluation", True)
    value["rights"]["basis_refs"] = []
    rejected(tmp_path, value, "rights_basis")


@pytest.mark.parametrize("privacy", ["sensitive", "unknown"])
def test_unknown_or_sensitive_privacy_cannot_be_eligible(tmp_path, privacy):
    value = item(1, "evaluation", True)
    value["privacy"]["status"] = privacy
    rejected(tmp_path, value, "eligibility_privacy")


@pytest.mark.parametrize("review", ["unreviewed", "rejected"])
def test_unvalidated_or_rejected_items_cannot_be_eligible(tmp_path, review):
    value = item(1, "evaluation", True)
    value["review"]["status"] = review
    rejected(tmp_path, value, "eligibility_review")


@pytest.mark.parametrize("kind", [
    "public_benign", "historical_malicious", "advisory_incident",
    "synthetic_adversarial", "detector_bypass", "false_positive",
    "remediation_fix", "model_disagreement", "regression_fixture", "private_held_out",
])
def test_taxonomy_is_orthogonal_to_origin_and_current_eligibility(tmp_path, kind):
    value = item(1, "private_held_out" if kind == "private_held_out" else "quarantine")
    value["kinds"] = [kind]
    assert contract.validate_manifests([manifest(tmp_path, [value])]).items == 1


@pytest.mark.parametrize("change,code", [
    ({"partition": "quarantine", "eligibility": {"training": True, "evaluation": False}}, "quarantine_eligible"),
    ({"eligibility": {"training": True, "evaluation": True}}, "eligibility_overlap"),
    ({"partition": "evaluation", "eligibility": {"training": True, "evaluation": False}}, "training_partition"),
    ({"partition": "training", "eligibility": {"training": False, "evaluation": True}}, "evaluation_partition"),
    ({"eligibility": {"training": 1, "evaluation": False}}, "json_number"),
    ({"eligibility": {"training": "true", "evaluation": False}}, "eligibility_type"),
])
def test_partition_and_eligibility_cannot_conflict(tmp_path, change, code):
    value = item()
    for key, replacement in change.items():
        if key == "eligibility":
            value[key].update(replacement)
        else:
            value[key] = replacement
    rejected(tmp_path, value, code)


def test_heldout_reservation_survives_retirement_from_active_evaluation(tmp_path):
    value = item(1, "private_held_out", False)
    summary = contract.validate_manifests([manifest(tmp_path, [value])])
    assert summary.private_held_out == 1 and summary.evaluation == 0
    value["eligibility"]["training"] = True
    rejected(tmp_path, value, "training_partition")


def test_public_item_cannot_be_labelled_private_heldout(tmp_path):
    value = item(1, "private_held_out", True)
    value["privacy"]["visibility"] = "public"
    rejected(tmp_path, value, "heldout_visibility")


@pytest.mark.parametrize("link", ["family", "artifact", "parent"])
def test_public_regression_and_heldout_derivatives_cannot_share_identity(tmp_path, link):
    public = item(1)
    public["kinds"] = ["regression_fixture"]
    public["privacy"]["visibility"] = "public"
    heldout = item(2, "private_held_out", True)
    if link == "family":
        heldout["family_id"] = public["family_id"]
    elif link == "artifact":
        heldout["artifact"] = public["artifact"].copy()
    else:
        heldout["parent_ids"] = [public["id"]]
    with pytest.raises(contract.ContractError, match="heldout_public_lineage"):
        contract.validate_manifests([manifest(tmp_path, [public, heldout])])


def test_public_non_regression_derivative_cannot_share_private_heldout_lineage(tmp_path):
    heldout = item(1, "private_held_out", True)
    derivative = item(2)
    derivative["privacy"]["visibility"] = "public"
    derivative["parent_ids"] = [heldout["id"]]
    with pytest.raises(contract.ContractError, match="heldout_public_lineage"):
        contract.validate_manifests([manifest(tmp_path, [derivative, heldout])])


def test_duplicate_ids_are_rejected_across_files(tmp_path):
    paths = [manifest(tmp_path, [item()], "one.json"), manifest(tmp_path, [item()], "two.json")]
    with pytest.raises(contract.ContractError) as error:
        contract.validate_manifests(paths)
    assert error.value.code == "duplicate_id"
    assert (error.value.manifest, error.value.item) == (2, 1)


@pytest.mark.parametrize("link", ["artifact", "family", "parent"])
def test_training_evaluation_overlap_is_rejected_across_files(tmp_path, link):
    train = item(1, "training", True)
    evaluate = item(2, "evaluation", True)
    if link == "artifact":
        evaluate["artifact"]["sha256"] = train["artifact"]["sha256"]
    elif link == "family":
        evaluate["family_id"] = train["family_id"]
    else:
        evaluate["parent_ids"] = [train["id"]]
    with pytest.raises(contract.ContractError, match="partition_overlap"):
        contract.validate_manifests([
            manifest(tmp_path, [train], "one.json"), manifest(tmp_path, [evaluate], "two.json"),
        ])


def test_transitive_quarantine_bridge_cannot_hide_partition_overlap(tmp_path):
    train = item(1, "training", True)
    first = item(2)
    first["parent_ids"] = [train["id"]]
    second = item(3)
    second["family_id"] = first["family_id"]
    evaluate = item(4, "evaluation", True)
    evaluate["parent_ids"] = [second["id"]]
    with pytest.raises(contract.ContractError, match="partition_overlap"):
        contract.validate_manifests([manifest(tmp_path, [evaluate, second, first, train])])


def test_ineligible_reservation_is_not_released_for_training(tmp_path):
    heldout = item(1, "private_held_out", False)
    train = item(2, "training", True)
    train["family_id"] = heldout["family_id"]
    with pytest.raises(contract.ContractError, match="partition_overlap"):
        contract.validate_manifests([manifest(tmp_path, [heldout, train])])


def metadata_only(value):
    value["artifact"] = {"kind": "metadata_only", "sha256": None}
    value["sources"] = [{"kind": "public", "reference": "https://example.invalid/advisory",
                         "revision": None, "sha256": digest(9000)}]
    return value


def test_metadata_only_evaluation_uses_bound_source_without_reading_content(tmp_path):
    value = metadata_only(item(1, "evaluation", True))
    assert contract.validate_manifests([manifest(tmp_path, [value])]).evaluation == 1
    value["sources"][0]["sha256"] = None
    rejected(tmp_path, value, "eligibility_identity")


@pytest.mark.parametrize("source_identity", ["hash", "revision"])
def test_metadata_only_source_identity_cannot_be_relabelled_across_partitions(tmp_path, source_identity):
    train = metadata_only(item(1, "training", True))
    evaluate = metadata_only(item(2, "evaluation", True))
    if source_identity == "revision":
        for value in (train, evaluate):
            value["sources"][0].update(sha256=None, revision="a" * 40)
        evaluate["sources"][0]["reference"] = "https://EXAMPLE.INVALID:443/advisory"
    with pytest.raises(contract.ContractError, match="partition_overlap"):
        contract.validate_manifests([manifest(tmp_path, [train]), manifest(tmp_path, [evaluate], "other.json")])


def test_metadata_source_hash_and_artifact_hash_share_the_same_overlap_namespace(tmp_path):
    train = item(1, "training", True)
    evaluate = metadata_only(item(2, "evaluation", True))
    evaluate["sources"][0]["sha256"] = train["artifact"]["sha256"]
    with pytest.raises(contract.ContractError, match="partition_overlap"):
        contract.validate_manifests([manifest(tmp_path, [evaluate, train])])


def test_shared_source_revision_still_joins_when_only_one_record_has_content_hash(tmp_path):
    train = metadata_only(item(1, "training", True))
    evaluate = metadata_only(item(2, "evaluation", True))
    train["sources"][0]["revision"] = "a" * 40
    evaluate["sources"][0].update(sha256=None, revision="a" * 40)
    with pytest.raises(contract.ContractError, match="partition_overlap"):
        contract.validate_manifests([manifest(tmp_path, [train, evaluate])])


def test_equal_revision_with_distinct_source_reference_does_not_join_unrelated_metadata(tmp_path):
    train = metadata_only(item(1, "training", True))
    evaluate = metadata_only(item(2, "evaluation", True))
    for value in (train, evaluate):
        value["sources"][0].update(sha256=None, revision="a" * 40)
    evaluate["sources"][0]["reference"] = "https://example.invalid/another-advisory"
    assert contract.validate_manifests([manifest(tmp_path, [train, evaluate])]).items == 2


def test_unknown_parent_requires_quarantine_and_cannot_support_eligible_descendants(tmp_path):
    unknown = opaque("item", 9999)
    value = item()
    value["parent_ids"] = [unknown]
    assert contract.validate_manifests([manifest(tmp_path, [value])]).quarantined == 1
    eligible = item(2, "evaluation", True)
    eligible["parent_ids"] = [value["id"]]
    with pytest.raises(contract.ContractError, match="unresolved_lineage"):
        contract.validate_manifests([manifest(tmp_path, [value, eligible])])
    eligible["parent_ids"] = [unknown]
    rejected(tmp_path, eligible, "unknown_parent")


def test_shared_absent_ancestor_does_not_break_transitive_overlap(tmp_path):
    left, right = item(1), item(2)
    left["parent_ids"] = right["parent_ids"] = [opaque("item", 9999)]
    train = item(3, "training", True)
    train["parent_ids"] = [left["id"]]
    evaluate = item(4, "evaluation", True)
    evaluate["parent_ids"] = [right["id"]]
    with pytest.raises(contract.ContractError, match="partition_overlap"):
        contract.validate_manifests([manifest(tmp_path, [left, right, train, evaluate])])


def test_cyclic_lineage_is_invalid_even_when_quarantined(tmp_path):
    left, right = item(1), item(2)
    left["parent_ids"] = [right["id"]]
    right["parent_ids"] = [left["id"]]
    with pytest.raises(contract.ContractError, match="lineage_cycle"):
        contract.validate_manifests([manifest(tmp_path, [left, right])])


def test_long_lineage_uses_bounded_iterative_graph_work(tmp_path):
    values = [item(number) for number in range(1, 251)]
    for index in range(1, len(values)):
        values[index]["parent_ids"] = [values[index - 1]["id"]]
    assert contract.validate_manifests([manifest(tmp_path, values)]).items == 250


def test_static_validation_does_not_establish_exploitability_or_compromise(tmp_path):
    value = item(1, "evaluation", True)
    value["review"]["status"] = "deterministic_validated"
    value["claim_level"] = "compromise"
    rejected(tmp_path, value, "static_claim_escalation")
    value["claim_level"] = "exploitability"
    rejected(tmp_path, value, "static_claim_escalation")


def test_suspected_and_verified_behavior_cannot_be_conflated(tmp_path):
    value = item()
    value["behavior"] = {"verified": ["credential_access"], "suspected": []}
    rejected(tmp_path, value, "unvalidated_behavior")
    value["review"] = {"status": "human_validated", "basis_refs": [opaque("ref", 10)]}
    value["behavior"]["suspected"] = ["credential_access"]
    rejected(tmp_path, value, "behavior_status_overlap")


def test_structured_observations_keep_detection_and_policy_action_separate(tmp_path):
    value = item()
    value["expected"] = {"outcome": "detected", "action": "block", "rule_ids": ["TEST-BOUNDARY-001"]}
    value["observations"] = [
        {"outcome": "detected", "action": "manual_review", "rule_ids": ["TEST-BOUNDARY-001"],
         "model_ref": None, "evidence_refs": [opaque("ref", 10)]},
        {"outcome": "incomplete", "action": "block", "rule_ids": [],
         "model_ref": opaque("model", 1), "evidence_refs": [opaque("ref", 11)]},
        {"outcome": "not_run", "action": "not_specified", "rule_ids": [],
         "model_ref": None, "evidence_refs": []},
    ]
    assert contract.validate_manifests([manifest(tmp_path, [value])]).items == 1
    value["observations"][2]["action"] = "allow"
    rejected(tmp_path, value, "not_run_action")


@pytest.mark.parametrize("value", [
    "https://example.invalid/advisory?token=fixture-secret",
    "https://fixture-secret@example.invalid/advisory",
    "https://example.invalid/advisory#fixture-secret",
    "/home/fixture-secret/advisory", "file:///fixture-secret",
    "http://example.invalid/advisory", "https://localhost/advisory",
])
def test_source_references_reject_private_paths_and_authority_bearing_url_parts(tmp_path, value):
    record = metadata_only(item())
    record["sources"][0]["reference"] = value
    rejected(tmp_path, record, "source_reference")


@pytest.mark.parametrize("field,value,code", [
    ("id", "fixture-secret", "format"),
    ("family_id", "../fixture-secret", "format"),
    ("origin", "model_says_real", "enum"),
    ("collected_at", "2026-02-30", "collection_date"),
    ("kinds", ["SAFE"], "enum"),
    ("parent_ids", [opaque("item", 2)] * 2, "duplicate_value"),
    ("artifact", {"kind": "metadata_only", "sha256": digest(1)}, "metadata_only_digest"),
    ("artifact", {"kind": "executable_payload", "sha256": digest(1)}, "enum"),
])
def test_invalid_typed_metadata_has_fixed_errors(tmp_path, field, value, code):
    record = item()
    record[field] = value
    rejected(tmp_path, record, code)


def test_unknown_fields_cannot_carry_payloads_commands_or_prose(tmp_path):
    record = item()
    record["payload"] = "fixture-secret do-not-execute"
    rejected(tmp_path, record, "fields")
    record = item()
    record["observations"] = [{"raw_model_output": "fixture-secret"}]
    rejected(tmp_path, record, "fields")


@pytest.mark.parametrize("payload,code", [
    (b'{"schema_version":"a","schema_version":"b","items":[]}', "json_duplicate_key"),
    (b'{"schema_version":"aurascan-security-data/1.0","items":[NaN]}', "json_constant"),
    (b'{"schema_version":"aurascan-security-data/1.0","items":[Infinity]}', "json_constant"),
    (b'{"schema_version":"aurascan-security-data/1.0","items":[],"fixture-secret":true}', "fields"),
    (b'{"schema_version":"aurascan-security-data/9.0","items":[]}', "schema_version"),
    (b'{"schema_version":"aurascan-security-data/1.0","items":"fixture-secret"}', "list_bound"),
    (b'[{"raw":"fixture-secret"}]', "fields"),
    (b'{', "json_invalid"), (b'\xff', "json_invalid"),
    (b'{"x":"\\ud800"}', "json_string"),
    (b'{"x":"\\u000a"}', "json_string"),
    (b'{"x":1234}', "json_number"), (b'{"x":1.25}', "json_number"),
    (b'{"x":1e999}', "json_number"),
])
def test_json_parser_refuses_ambiguous_and_non_json_values(tmp_path, payload, code):
    path = tmp_path / "manifest.json"
    path.write_bytes(payload)
    with pytest.raises(contract.ContractError) as error:
        contract.validate_manifests([path])
    assert error.value.code == code


def test_structural_and_byte_bounds_are_explicit(tmp_path, monkeypatch):
    path = manifest(tmp_path, [item()])
    size = path.stat().st_size
    monkeypatch.setattr(contract, "MAX_MANIFEST_BYTES", size - 1)
    with pytest.raises(contract.ContractError, match="manifest_size"):
        contract.validate_manifests([path])
    monkeypatch.setattr(contract, "MAX_MANIFEST_BYTES", 1024 * 1024)
    monkeypatch.setattr(contract, "MAX_TOTAL_BYTES", size - 1)
    with pytest.raises(contract.ContractError, match="total_bytes"):
        contract.validate_manifests([path])
    monkeypatch.setattr(contract, "MAX_TOTAL_BYTES", 8 * 1024 * 1024)
    monkeypatch.setattr(contract, "MAX_JSON_NODES", 4)
    with pytest.raises(contract.ContractError, match="json_nodes"):
        contract.validate_manifests([path])


def test_depth_limit_applies_before_json_recursion(tmp_path):
    path = tmp_path / "deep.json"
    path.write_text("[" * 1000 + "0" + "]" * 1000)
    with pytest.raises(contract.ContractError, match="json_depth"):
        contract.validate_manifests([path])


def test_manifest_and_batch_item_bounds(tmp_path, monkeypatch):
    with pytest.raises(contract.ContractError, match="manifest_count"):
        contract.validate_manifests([])
    with pytest.raises(contract.ContractError, match="manifest_count"):
        contract.validate_manifests(["never-read"] * (contract.MAX_MANIFESTS + 1))
    monkeypatch.setattr(contract, "MAX_TOTAL_ITEMS", 1)
    paths = [manifest(tmp_path, [item(1)]), manifest(tmp_path, [item(2)], "two.json")]
    with pytest.raises(contract.ContractError, match="total_items"):
        contract.validate_manifests(paths)


def test_reference_files_and_urls_are_never_opened(tmp_path, monkeypatch):
    value = metadata_only(item(1, "evaluation", True))
    path = manifest(tmp_path, [value])
    opened = set()
    original = contract.os.open
    allowed = set()
    for selected in (path,) + tuple(path.parents):
        info = selected.stat()
        allowed.add((info.st_dev, info.st_ino))
    info = path.stat()
    manifest_identity = (info.st_dev, info.st_ino)

    def forbidden_access(*_args, **_kwargs):
        pytest.fail("metadata validation must not access references or the network")

    def record_open(selected, *args, **kwargs):
        descriptor = original(selected, *args, **kwargs)
        info = os.fstat(descriptor)
        identity = (info.st_dev, info.st_ino)
        if identity not in allowed:
            os.close(descriptor)
            pytest.fail("only the explicit manifest and its parent directories may be opened")
        opened.add(identity)
        return descriptor

    monkeypatch.setattr(contract.os, "open", record_open)
    monkeypatch.setattr("builtins.open", forbidden_access)
    monkeypatch.setattr(Path, "open", forbidden_access)
    monkeypatch.setattr(socket, "socket", forbidden_access)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden_access)
    assert contract.validate_manifests([path]).evaluation == 1
    assert manifest_identity in opened


def test_final_and_parent_symlinks_are_refused(tmp_path):
    target = manifest(tmp_path, [item()])
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(contract.ContractError, match="manifest_unsafe_or_unreadable"):
        contract.validate_manifests([link])
    parent = tmp_path / "parent-link"
    parent.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(contract.ContractError, match="manifest_unsafe_or_unreadable"):
        contract.validate_manifests([parent / target.name])


def test_directories_fifos_and_parent_traversal_are_not_manifest_inputs(tmp_path):
    with pytest.raises(contract.ContractError, match="manifest_not_regular"):
        contract.validate_manifests([tmp_path])
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(contract.ContractError, match="manifest_not_regular"):
        contract.validate_manifests([fifo])
    with pytest.raises(contract.ContractError, match="manifest_path"):
        contract.validate_manifests([tmp_path / ".." / "manifest.json"])


def test_manifest_replacement_during_read_is_refused(tmp_path, monkeypatch):
    path = manifest(tmp_path, [item()])
    replacement = manifest(tmp_path, [item(2)], "replacement.json")
    original = contract.os.read
    swapped = False

    def replace_after_read(fd, limit):
        nonlocal swapped
        chunk = original(fd, limit)
        if chunk and not swapped:
            swapped = True
            os.replace(replacement, path)
        return chunk

    monkeypatch.setattr(contract.os, "read", replace_after_read)
    with pytest.raises(contract.ContractError, match="manifest_changed"):
        contract.validate_manifests([path])


def test_stable_short_read_is_incomplete_not_a_complete_manifest(tmp_path, monkeypatch):
    path = manifest(tmp_path, [item()])
    monkeypatch.setattr(contract.os, "read", lambda _fd, _limit: b"")
    with pytest.raises(contract.ContractError, match="manifest_changed"):
        contract.validate_manifests([path])


def test_parent_replacement_during_read_is_refused(tmp_path, monkeypatch):
    directory = tmp_path / "manifest-root"
    directory.mkdir()
    path = manifest(directory, [item()])
    original = contract.os.read
    moved = False

    def move_after_read(fd, limit):
        nonlocal moved
        chunk = original(fd, limit)
        if chunk and not moved:
            moved = True
            directory.rename(tmp_path / "retained-root")
            directory.mkdir()
        return chunk

    monkeypatch.setattr(contract.os, "read", move_after_read)
    with pytest.raises(contract.ContractError, match="manifest_changed"):
        contract.validate_manifests([path])


def test_cli_prints_aggregates_and_scope_without_paths_or_records(tmp_path, capsys):
    path = manifest(tmp_path, [item(1, "evaluation", True)], "fixture-secret.json")
    assert contract.main([str(path)]) == 0
    output = capsys.readouterr()
    assert "items=1" in output.out and "evaluation_eligible=1" in output.out
    assert "scope=provided-manifests-only" in output.out
    assert "fixture-secret" not in output.out + output.err
    assert str(tmp_path) not in output.out + output.err


def test_cli_rejects_errors_without_echoing_secret_values_paths_or_options(tmp_path, capsys):
    value = item()
    value["payload"] = "fixture-secret"
    path = manifest(tmp_path, [value], "fixture-secret.json")
    assert contract.main([str(path)]) == 1
    output = capsys.readouterr()
    assert output.err == "ERROR manifest=1 item=1 code=fields\n"
    assert "fixture-secret" not in output.out + output.err
    assert contract.main(["--fixture-secret"]) == 1
    output = capsys.readouterr()
    assert output.err == "ERROR manifest=0 item=0 code=cli_arguments\n"
    assert "fixture-secret" not in output.out + output.err


def test_cli_supports_help_relative_files_and_explicit_option_terminator(tmp_path, monkeypatch, capsys):
    assert contract.main(["--help"]) == 0
    assert "metadata" in capsys.readouterr().out
    manifest(tmp_path, [item()], "-manifest.json")
    monkeypatch.chdir(tmp_path)
    assert contract.main(["--", "-manifest.json"]) == 0
    assert "items=1" in capsys.readouterr().out
