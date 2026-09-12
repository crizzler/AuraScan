"""Independent admission regressions: unrelated records cannot mask withdrawals."""

from copy import deepcopy

import pytest

from aurascan.core.intelligence import (
    IntelligenceError, canonical_json, record_identities, validate_payload,
    validate_transition,
)
from tests.helpers.intelligence_fixtures import bundled_payload


def selected_data():
    data = bundled_payload()
    campaign = data["npm_campaigns"][0]
    campaign.update(id="vendor/x", payload_sha256=[], malicious_domains=[])
    campaign["packages"] = [{
        "name": "inert-package", "versions": ["1.2.3"],
        "advisory_ids": ["INERT-ADVISORY"],
        "references": ["https://example.invalid/review"], "broad_advisory": "none",
    }]
    return data


def validate(data):
    return validate_payload(canonical_json(data))


def correction(identity):
    return {"id": identity, "reason": "Review corrected the exact inert record.",
            "reviewed_at": "2026-09-12", "references": ["https://example.invalid/correction"],
            "rights": {"redistribution": "permitted", "basis": "Self-authored inert regression data."}}


def test_vendor_identity_cannot_mask_removed_npm_release():
    before = selected_data()
    # These source identities used to collide when concatenated with slashes.
    before["vendor_advisories"][0]["id"] = "x/npm/inert-package@1.2.3"
    before = validate(before)
    after = deepcopy(before)
    after["npm_campaigns"][0]["packages"] = []
    after = validate(after)
    with pytest.raises(IntelligenceError):
        validate_transition(before, after)
    assert len(record_identities(before)) == 2
    assert len(record_identities(after)) == 1


def test_explicit_correction_can_remove_exact_release_despite_similar_vendor_identity():
    before = selected_data()
    before["vendor_advisories"][0]["id"] = "x/npm/inert-package@1.2.3"
    before = validate(before)
    after = deepcopy(before)
    after["npm_campaigns"][0]["packages"] = []
    removed = set(record_identities(before)) - set(record_identities(after))
    assert len(removed) == 1
    after["withdrawals"] = [correction(removed.pop())]
    validate_transition(before, validate(after))


def test_maximum_length_source_identities_remain_correctable():
    before = selected_data()
    before["vendor_advisories"] = []
    campaign = before["npm_campaigns"][0]
    campaign["id"] = "x" * 256
    campaign["packages"][0]["name"] = "p" * 214
    campaign["packages"][0]["versions"] = ["1.2.3-" + "x" * 100]
    before = validate(before)
    after = deepcopy(before)
    after["npm_campaigns"][0]["packages"] = []
    identities = list(record_identities(before))
    assert len(identities) == 1
    after["withdrawals"] = [correction(identities[0])]
    # Passing ordinary payload validation proves the public correction can name
    # this admitted record; a separate special bypass must not be necessary.
    validate_transition(before, validate(after))


def test_each_vendor_floor_correction_requires_review_of_its_exact_prior_claim():
    before = selected_data()
    before["npm_campaigns"] = []
    before["vendor_advisories"][0]["fixed_floor"] = "2.0.0.0"
    before = validate(before)
    first = deepcopy(before)
    first["vendor_advisories"][0]["fixed_floor"] = "1.0.0.0"
    first["withdrawals"] = [correction(next(iter(record_identities(before))))]
    validate_transition(before, validate(first))
    second = deepcopy(first)
    second["vendor_advisories"][0]["fixed_floor"] = "0.0.0.0"
    with pytest.raises(IntelligenceError, match="explicit reviewed withdrawal"):
        validate_transition(first, validate(second))
    second["withdrawals"].append(correction(next(iter(record_identities(first)))))
    validate_transition(first, validate(second))
    assert len(second["withdrawals"]) == 2


def reintroduced_release():
    original = selected_data()
    original["vendor_advisories"] = []
    original = validate(original)
    removed = deepcopy(original)
    removed["npm_campaigns"][0]["packages"] = []
    removed["withdrawals"] = [correction(next(iter(record_identities(original))))]
    validate_transition(original, validate(removed))
    reintroduced = deepcopy(original)
    reintroduced["withdrawals"] = deepcopy(removed["withdrawals"])
    validate_transition(removed, validate(reintroduced))
    return reintroduced, removed


@pytest.mark.parametrize("cosmetic", ["unchanged", "rights", "whitespace", "reference_order", "backdated_review"])
def test_retained_review_cannot_authorize_removing_a_reintroduced_release(cosmetic):
    before, after = reintroduced_release()
    before["withdrawals"][0]["references"].append("https://example.invalid/second-source")
    after["withdrawals"] = deepcopy(before["withdrawals"])
    review = after["withdrawals"][0]
    if cosmetic == "rights":
        review["rights"]["basis"] = "Updated publication permission only."
    elif cosmetic == "whitespace":
        review["reason"] += "  "
    elif cosmetic == "reference_order":
        review["references"].reverse()
    elif cosmetic == "backdated_review":
        review["reviewed_at"] = "2026-09-11"
    with pytest.raises(IntelligenceError, match="renewed reviewed withdrawal"):
        validate_transition(validate(before), validate(after))


@pytest.mark.parametrize("field,value", [
    ("reason", "A new review corrects the reintroduced release claim."),
    ("reviewed_at", "2026-09-13"),
    ("references", ["https://example.invalid/new-review"]),
])
def test_reintroduced_release_can_be_removed_with_renewed_explicit_review(field, value):
    before, after = reintroduced_release()
    after["withdrawals"][0][field] = value
    validate_transition(before, validate(after))
    assert {entry["id"] for entry in before["withdrawals"]} <= {
        entry["id"] for entry in after["withdrawals"]}


@pytest.mark.parametrize("selector", ["1", "1.2", "1.x", "1.2.x", "1.X", "01.2.3", "1.02.3", "1.2.03"])
def test_registry_selector_is_not_an_exact_observed_npm_release(selector):
    data = selected_data()
    data["npm_campaigns"][0]["packages"][0]["versions"] = [selector]
    with pytest.raises(IntelligenceError):
        validate(data)


@pytest.mark.parametrize("version", ["1.2.3", "1.2.3-alpha.1", "1.2.3+build.7", "1.2.3-rc.1+build.7"])
def test_supported_exact_npm_release_can_retain_prerelease_or_build_identity(version):
    data = selected_data()
    data["npm_campaigns"][0]["packages"][0]["versions"] = [version]
    validated = validate(data)
    assert validated["npm_campaigns"][0]["packages"][0]["versions"] == [version]


@pytest.mark.parametrize("value", ["", " ", "\t", "\u2003"])
def test_empty_rights_basis_cannot_admit_runtime_intelligence(value):
    data = selected_data()
    data["npm_campaigns"][0]["rights"]["basis"] = value
    with pytest.raises(IntelligenceError):
        validate(data)
