"""Offline intake semantics, using only inert captures and temporary private stores."""

import copy
import json
import os
from pathlib import Path
import socket
import subprocess

import pytest

from tools import collect_security_data as cli
from tools import security_data_intake as intake
from tools import security_data_sources as sources
from tools.security_data_store import PrivateStore, StoreError


NOW = "2026-09-10T12:00:00Z"
LATER = "2026-09-11T12:00:00Z"
REV_A, REV_B, REV_C = (letter * 40 for letter in "abc")
BUILD = b"pkgname=inert\npkgver=1\npkgrel=1\n# inert static metadata\n"
SOURCE = "https://aur.archlinux.org/inert.git"


@pytest.fixture(autouse=True)
def deny_external_execution_and_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("intake tests must not execute a process or contact a network")
    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    monkeypatch.setattr(os, "popen", forbidden)
    monkeypatch.setattr(sources, "build_opener", forbidden)


@pytest.fixture
def store(tmp_path):
    with PrivateStore(tmp_path / "store", create=True) as selected:
        yield selected


def captured(revision=REV_A, payload=BUILD, parents=(), package="inert", retrieved_at=NOW,
             fixture=False, expected=None):
    files = {"PKGBUILD": payload}
    if fixture:
        files["expected.json"] = intake.canonical(expected if expected is not None else {
            "package_name": package, "package_version": "1-1", "category": "malicious",
            "expected_rule_ids": ["det-inert-test"], "expected_action": "block",
        })
    return sources.Capture(
        source_type="aurascan_fixture" if fixture else "aur_git",
        source_uri=("https://github.com/crizzler/AuraScan/tree/" + revision
                    + "/tests/fixtures/curated_packages/inert" if fixture
                    else "https://aur.archlinux.org/" + package + ".git"),
        package=package, package_version="1-1", revision=revision,
        parent_revisions=list(parents), retrieved_at=retrieved_at, files=files,
        coverage="selected_files", transport_sha256=[],
    )


def admit(store, captures, base=None):
    refs = [intake.save_capture(store, value) for value in captures]
    result = intake.intake(store, refs, base=base, now=NOW)
    batch, document = intake.load_batch(store, result["batch_sha256"])
    return result, batch, document


def review_request(result, item):
    return {
        "schema_version": "aurascan-security-review-request/1.0",
        "item_id": item["id"], "candidate_sha256": intake.digest(intake.canonical(item)),
        "manifest_sha256": result["manifest_sha256"], "reviewer_ref": "ref-" + "1" * 12,
        "status": "human_validated", "basis_refs": ["ref-" + "2" * 12],
        "classification": "suspicious", "claim_level": "suspicious_behavior",
        "verified_behaviors": ["credential_access"],
    }


def assessment_request(item):
    return {
        "schema_version": "aurascan-security-assessment-request/1.0",
        "candidate_sha256": intake.digest(intake.canonical(item)), "tool_revision": REV_C,
        "scanner_version": "0.10.6", "scope": "deterministic_control_text",
        "outcome": "detected", "action": "block", "rule_ids": ["det-inert-test"],
    }


def republish(store, batch, document):
    batch = copy.deepcopy(batch)
    batch["manifest_sha256"] = store.put("manifests", intake.canonical(document))
    return store.put("manifests", intake.canonical(batch))


def assert_ineligible(item):
    assert item["partition"] == "quarantine"
    assert item["eligibility"] == {"training": False, "commercial_training": False,
                                   "evaluation": False, "redistribution": False}
    assert all(value == "unknown" for name, value in item["rights"].items()
               if name not in {"basis_refs", "provider_basis_refs"})
    assert item["rights"]["basis_refs"] == item["rights"]["provider_basis_refs"] == []
    assert item["privacy"]["status"] == "unknown"
    assert item["provenance"]["status"] == "unknown"
    assert item["generation"]["method"] == "unknown"


def test_capture_is_separate_from_admission_and_labels(store):
    ref = intake.save_capture(store, captured())
    record = intake.load_capture(store, ref)
    assert record["schema_version"] == intake.CAPTURE_SCHEMA
    assert record["files"] == [{"path": "PKGBUILD", "sha256": intake.digest(BUILD), "size": len(BUILD)}]
    assert "classification" not in record and "eligibility" not in record
    assert list((store.root / "manifests").iterdir()) == []
    assert list((store.root / "reviews").iterdir()) == []
    result = intake.intake(store, [ref], now=NOW)
    _, document = intake.load_batch(store, result["batch_sha256"])
    item = document["items"][0]
    assert item["classification"] == "unknown" and item["claim_level"] == "none"
    assert item["review"] == {"status": "unreviewed", "basis_refs": []}
    assert item["observations"] == []
    assert_ineligible(item)


@pytest.mark.parametrize("category,action,rules", [
    ("malicious", "block", ["det-inert-test"]), ("benign", "allow", []),
    ("trusted_compromised_approved", "manual_review", ["det-inert-test"]),
])
def test_fixture_expected_results_do_not_become_ground_truth(store, category, action, rules):
    expected = {"package_name": "inert", "package_version": "1-1", "category": category,
                "expected_action": action, "expected_rule_ids": rules}
    _, _, document = admit(store, [captured(fixture=True, expected=expected)])
    item = document["items"][0]
    assert item["expected"] == {"outcome": "detected" if rules else "not_detected",
                                "action": action, "rule_ids": rules}
    assert item["kinds"] == ["regression_fixture"] and item["origin"] == "synthetic"
    assert item["classification"] == "unknown"
    assert item["claim_level"] == "none"
    assert item["behavior"] == {"verified": [], "suspected": []}
    assert item["observations"] == []
    assert_ineligible(item)


def test_repeated_identical_snapshot_and_retrieval_share_candidate(store):
    first = intake.save_capture(store, captured())
    assert intake.save_capture(store, captured()) == first
    later = intake.save_capture(store, captured(retrieved_at=LATER))
    assert later != first
    result = intake.intake(store, [first, first, later], now=NOW)
    batch, document = intake.load_batch(store, result["batch_sha256"])
    assert len(document["items"]) == 1
    item = document["items"][0]
    assert set(batch["capture_refs"][item["id"]]) == {first, later}
    assert len(item["sources"]) == 1
    assert len(list((store.root / "blobs").iterdir())) == 1


def test_changed_content_at_same_family_and_revision_fails_closed(store):
    original, _, _ = admit(store, [captured()])
    changed = intake.save_capture(store, captured(payload=BUILD + b"# changed\n"))
    with pytest.raises(intake.IntakeError, match="^upstream_revision_changed$"):
        intake.intake(store, [changed], base=original["batch_sha256"], now=NOW)
    _, document = intake.load_batch(store, original["batch_sha256"])
    assert len(document["items"]) == 1


def test_same_content_in_separate_family_is_not_accepted_as_independent(store):
    first, _, _ = admit(store, [captured()])
    collision = intake.save_capture(store, captured(package="other-inert"))
    with pytest.raises(intake.IntakeError, match="^lineage_collision$"):
        intake.intake(store, [collision], base=first["batch_sha256"], now=NOW)


def test_three_revision_history_preserves_revert_node_and_actual_parents(store):
    snapshots = [captured(REV_A), captured(REV_B, BUILD + b"# revision B\n", [REV_A]),
                 captured(REV_C, BUILD, [REV_B])]
    result, batch, document = admit(store, list(reversed(snapshots)))
    assert result["items"] == len(document["items"]) == 3
    by_revision = {item["sources"][0]["revision"]: item for item in document["items"]}
    a, b, c = (by_revision[revision] for revision in (REV_A, REV_B, REV_C))
    assert len({a["id"], b["id"], c["id"]}) == 3
    assert a["artifact"]["sha256"] == c["artifact"]["sha256"] != b["artifact"]["sha256"]
    assert a["parent_ids"] == []
    assert b["parent_ids"] == [a["id"]]
    assert c["parent_ids"] == [b["id"]]
    assert len({item["family_id"] for item in document["items"]}) == 1
    assert len(list((store.root / "blobs").iterdir())) == 2
    assert len(batch["capture_refs"]) == 3


def test_later_parent_admission_resolves_only_actual_retained_parent(store):
    result, _, first = admit(store, [captured(REV_B, BUILD + b"# B\n", [REV_A])])
    assert first["items"][0]["parent_ids"] == []
    result, _, second = admit(store, [captured(REV_A), captured(REV_C, BUILD + b"# unrelated\n")],
                              base=result["batch_sha256"])
    by_revision = {item["sources"][0]["revision"]: item for item in second["items"]}
    assert by_revision[REV_B]["parent_ids"] == [by_revision[REV_A]["id"]]
    assert by_revision[REV_C]["parent_ids"] == []


def test_review_declaration_stays_quarantined_and_preserves_immutable_base(store):
    result, _, before = admit(store, [captured()])
    request = review_request(result, before["items"][0])
    reviewed = intake.review(store, result["batch_sha256"], request, now=LATER)
    batch, document = intake.load_batch(store, reviewed["batch_sha256"])
    item = document["items"][0]
    assert item["classification"] == "suspicious"
    assert item["claim_level"] == "suspicious_behavior"
    assert item["behavior"]["verified"] == ["credential_access"]
    assert item["review"]["status"] == "human_validated"
    assert_ineligible(item)
    assert len(batch["review_refs"]) == 1
    receipt = intake.decode(store.get("reviews", batch["review_refs"][0]))
    assert receipt["schema_version"] == "aurascan-security-review/1.0"
    assert receipt["request"] == request
    _, original = intake.load_batch(store, result["batch_sha256"])
    assert original == before
    assert original["items"][0]["classification"] == "unknown"


@pytest.mark.parametrize("field", ["candidate_sha256", "manifest_sha256", "item_id"])
def test_stale_review_is_rejected_without_new_receipt(store, field):
    result, _, document = admit(store, [captured()])
    request = review_request(result, document["items"][0])
    request[field] = ("item-" if field == "item_id" else "") + "f" * 64
    with pytest.raises(intake.IntakeError, match="^stale_review$"):
        intake.review(store, result["batch_sha256"], request, now=LATER)
    assert list((store.root / "reviews").iterdir()) == []


def test_old_review_cannot_be_replayed_after_new_assessment(store):
    result, _, document = admit(store, [captured()])
    item = document["items"][0]
    request = review_request(result, item)
    assessed = intake.attach_assessment(store, result["batch_sha256"], item["id"],
                                        assessment_request(item), now=LATER)
    with pytest.raises(intake.IntakeError, match="^stale_review$"):
        intake.review(store, assessed["batch_sha256"], request, now=LATER)


def test_new_actual_ancestry_invalidates_prior_review_only_in_new_batch(store):
    result, _, document = admit(store, [captured(REV_B, BUILD + b"# B\n", [REV_A])])
    reviewed = intake.review(store, result["batch_sha256"], review_request(result, document["items"][0]), now=NOW)
    _, reviewed_document = intake.load_batch(store, reviewed["batch_sha256"])
    _, _, expanded = admit(store, [captured(REV_A)], base=reviewed["batch_sha256"])
    child = next(item for item in expanded["items"] if item["sources"][0]["revision"] == REV_B)
    assert child["parent_ids"]
    assert child["review"] == {"status": "unreviewed", "basis_refs": []}
    assert child["classification"] == "unknown"
    assert child["claim_level"] == "none"
    assert child["behavior"]["verified"] == []
    _, retained = intake.load_batch(store, reviewed["batch_sha256"])
    assert retained == reviewed_document


def test_assessment_is_recorded_separately_from_expected_and_reviewed_labels(store):
    result, _, document = admit(store, [captured()])
    item = document["items"][0]
    assessed = intake.attach_assessment(store, result["batch_sha256"], item["id"],
                                        assessment_request(item), now=LATER)
    batch, after = intake.load_batch(store, assessed["batch_sha256"])
    changed = after["items"][0]
    assert changed["expected"] == item["expected"]
    assert changed["classification"] == "unknown"
    assert changed["claim_level"] == "none"
    assert changed["review"] == {"status": "unreviewed", "basis_refs": []}
    assert changed["behavior"] == {"verified": [], "suspected": []}
    assert changed["observations"][0]["outcome"] == "detected"
    assert changed["observations"][0]["rule_ids"] == ["det-inert-test"]
    assert len(batch["assessment_refs"]) == 1
    assert batch["review_refs"] == []
    assert_ineligible(changed)


def test_assessment_cannot_escalate_static_result_into_compromise(store):
    result, _, document = admit(store, [captured()])
    item = document["items"][0]
    request = assessment_request(item)
    request["outcome"] = "compromised"
    with pytest.raises(intake.IntakeError):
        intake.attach_assessment(store, result["batch_sha256"], item["id"], request, now=LATER)
    assert list((store.root / "reviews").iterdir()) == []


@pytest.mark.parametrize("operation", ["review", "assessment"])
def test_receipt_schema_cannot_be_submitted_as_a_new_request(store, operation):
    result, _, document = admit(store, [captured()])
    item = document["items"][0]
    if operation == "review":
        request = review_request(result, item)
        request["schema_version"] = "aurascan-security-review/1.0"
        with pytest.raises(intake.IntakeError, match="^review_schema$"):
            intake.review(store, result["batch_sha256"], request, now=NOW)
    else:
        request = assessment_request(item)
        request["schema_version"] = "aurascan-security-assessment/1.0"
        with pytest.raises(intake.IntakeError, match="^assessment_schema$"):
            intake.attach_assessment(store, result["batch_sha256"], item["id"], request, now=NOW)
    assert list((store.root / "reviews").iterdir()) == []


@pytest.mark.parametrize("operation,alteration", [
    ("review", "schema"), ("review", "candidate"), ("review", "missing"),
    ("assessment", "schema"), ("assessment", "candidate"), ("assessment", "missing"),
])
def test_retained_receipts_require_typed_bound_evidence(store, operation, alteration):
    result, _, document = admit(store, [captured()])
    item = document["items"][0]
    if operation == "review":
        result = intake.review(store, result["batch_sha256"], review_request(result, item), now=NOW)
        field = "review_refs"
    else:
        result = intake.attach_assessment(store, result["batch_sha256"], item["id"],
                                          assessment_request(item), now=NOW)
        field = "assessment_refs"
    batch, document = intake.load_batch(store, result["batch_sha256"])
    if alteration == "missing":
        batch[field] = []
    else:
        evidence = intake.decode(store.get("reviews", batch[field][0]))
        if alteration == "schema":
            evidence["schema_version"] = "aurascan-unrelated/1.0"
        else:
            evidence["request"]["candidate_sha256"] = "f" * 64
        batch[field] = [store.put("reviews", intake.canonical(evidence))]
    forged = republish(store, batch, document)
    with pytest.raises(intake.IntakeError):
        intake.load_batch(store, forged)


def test_changed_ancestry_cannot_restore_the_old_review_from_a_retained_receipt(store):
    result, _, document = admit(store, [captured(REV_B, BUILD + b"# B\n", [REV_A])])
    result = intake.review(store, result["batch_sha256"], review_request(result, document["items"][0]), now=NOW)
    _, reviewed_document = intake.load_batch(store, result["batch_sha256"])
    prior = reviewed_document["items"][0]
    _, batch, expanded = admit(store, [captured(REV_A)], base=result["batch_sha256"])
    child = next(item for item in expanded["items"] if item["id"] == prior["id"])
    assert child["parent_ids"] != prior["parent_ids"]
    for field in ("review", "classification", "claim_level", "behavior"):
        child[field] = copy.deepcopy(prior[field])
    forged = republish(store, batch, expanded)
    with pytest.raises(intake.IntakeError):
        intake.load_batch(store, forged)


@pytest.mark.parametrize("operation", ["review", "assessment"])
def test_unused_historical_evidence_still_requires_valid_claim_semantics(store, operation):
    result, _, document = admit(store, [captured()])
    item = document["items"][0]
    if operation == "review":
        changed = intake.review(store, result["batch_sha256"], review_request(result, item), now=NOW)
        field = "review_refs"
    else:
        changed = intake.attach_assessment(store, result["batch_sha256"], item["id"], assessment_request(item), now=NOW)
        field = "assessment_refs"
    later, _ = intake.load_batch(store, changed["batch_sha256"])
    receipt = intake.decode(store.get("reviews", later[field][0]))
    if operation == "review":
        receipt["request"].update(status="deterministic_validated", claim_level="compromise")
    else:
        receipt["request"].update(outcome="compromised", action="unsupported_action", rule_ids={"invalid": True})
    original, _ = intake.load_batch(store, result["batch_sha256"])
    original[field] = [store.put("reviews", intake.canonical(receipt))]
    forged = republish(store, original, document)
    with pytest.raises(intake.IntakeError):
        intake.load_batch(store, forged)


@pytest.mark.parametrize("field,value", [
    ("status", []), ("reviewer_ref", True), ("classification", ["benign"]),
    ("claim_level", False), ("verified_behaviors", "credential_access"),
    ("basis_refs", "ref-111111111111"), ("candidate_sha256", []),
    ("manifest_sha256", {}), ("item_id", []),
])
def test_malformed_review_types_are_rejected_as_intake_errors(store, field, value):
    result, _, document = admit(store, [captured()])
    request = review_request(result, document["items"][0])
    request[field] = value
    with pytest.raises(intake.IntakeError):
        intake.review(store, result["batch_sha256"], request, now=LATER)
    assert list((store.root / "reviews").iterdir()) == []


@pytest.mark.parametrize("base", ["", [], {}, False, 0])
def test_falsey_malformed_base_cannot_silently_start_a_fresh_history(store, base):
    ref = intake.save_capture(store, captured())
    with pytest.raises(intake.IntakeError):
        intake.intake(store, [ref], base=base, now=NOW)
    assert list((store.root / "manifests").iterdir()) == []


@pytest.mark.parametrize("payload", [
    b'{"status":"unreviewed","status":"human_validated"}',
    b'{"nested":{"value":1,"value":2}}', b'{"value":NaN}', b'{"value":1.0}',
    b'{"value":123456789012345678901234567890}', b'"\\ud800"', b'\xff',
])
def test_duplicate_or_malformed_json_never_reaches_intake(payload):
    with pytest.raises(intake.IntakeError):
        intake.decode(payload)


@pytest.mark.parametrize("target_kind", ["blobs", "captures"])
def test_capture_or_source_blob_tampering_blocks_admission(store, target_kind):
    ref = intake.save_capture(store, captured())
    selected = ref if target_kind == "captures" else intake.digest(BUILD)
    suffix = ".json" if target_kind == "captures" else ".blob"
    target = store.root / target_kind / (selected + suffix)
    target.write_bytes(b"changed inert bytes")
    with pytest.raises(StoreError, match="^store_corrupt$"):
        intake.intake(store, [ref], now=NOW)
    assert list((store.root / "manifests").iterdir()) == []


def test_capture_metadata_cannot_lie_about_blob_size(store):
    ref = intake.save_capture(store, captured())
    record = intake.load_capture(store, ref)
    record["files"][0]["size"] += 1
    record["content_sha256"] = intake.digest(intake.canonical(record["files"]))
    forged = store.put("captures", intake.canonical(record))
    with pytest.raises(intake.IntakeError, match="^capture_blob$"):
        intake.intake(store, [forged], now=NOW)


def test_manifest_source_rebinding_is_rejected(store):
    _, batch, document = admit(store, [captured()])
    document["items"][0]["sources"][0]["reference"] = "https://aur.archlinux.org/different.git"
    forged = republish(store, batch, document)
    with pytest.raises(intake.IntakeError, match="^capture_binding$"):
        intake.load_batch(store, forged)


def test_manifest_cannot_invent_a_retained_parent(store):
    _, batch, document = admit(store, [captured(REV_A), captured(REV_B, BUILD + b"# independent\n")])
    by_revision = {item["sources"][0]["revision"]: item for item in document["items"]}
    by_revision[REV_B]["parent_ids"] = [by_revision[REV_A]["id"]]
    forged = republish(store, batch, document)
    with pytest.raises(intake.IntakeError):
        intake.load_batch(store, forged)


def test_contradictory_parent_metadata_at_same_revision_is_not_merged(store):
    first, _, _ = admit(store, [captured(REV_B, parents=[REV_A])])
    conflicting = intake.save_capture(store, captured(REV_B, parents=[REV_C], retrieved_at=LATER))
    with pytest.raises(intake.IntakeError):
        intake.intake(store, [conflicting], base=first["batch_sha256"], now=LATER)


def run_cli(capsys, root, *arguments):
    code = cli.main(["--store", str(root), *arguments])
    output = capsys.readouterr()
    assert output.err == ""
    return code, json.loads(output.out), output.out


def test_cli_offline_fixture_capture_intake_inspect_review_end_to_end(tmp_path, capsys):
    root, fixture = tmp_path / "store", tmp_path / "fixture"
    fixture.mkdir(mode=0o700)
    (fixture / "PKGBUILD").write_bytes(BUILD)
    (fixture / "expected.json").write_bytes(intake.canonical({
        "package_name": "inert", "package_version": "1-1", "category": "malicious",
        "expected_rule_ids": ["det-inert-test"], "expected_action": "block",
    }))
    assert run_cli(capsys, root, "init")[:2] == (0, {"initialized": True})
    code, result, output = run_cli(capsys, root, "fixture", "--root", str(fixture),
                                  "--source-uri", "https://github.com/crizzler/AuraScan/tree/" + REV_A,
                                  "--revision", REV_A)
    assert code == 0 and result["scope"] == "acquisition_only"
    assert str(tmp_path) not in output and "pkgname=" not in output
    assert list((root / "manifests").iterdir()) == []
    code, admitted, _ = run_cli(capsys, root, "intake", "--capture", result["capture_sha256"][0])
    assert code == 0 and admitted["items"] == 1
    code, inspected, output = run_cli(capsys, root, "inspect", "--base", admitted["batch_sha256"])
    assert code == 0 and inspected["scope"] == "provided_batch_only"
    assert inspected["items"][0]["classification"] == "unknown"
    assert not any(inspected["items"][0]["eligibility"].values())
    assert str(fixture) not in output and "pkgname=" not in output
    with PrivateStore(root) as selected:
        _, document = intake.load_batch(selected, admitted["batch_sha256"])
    request = tmp_path / "request.json"
    request.write_bytes(intake.canonical(review_request(admitted, document["items"][0])))
    code, reviewed, _ = run_cli(capsys, root, "review", "--base", admitted["batch_sha256"],
                                "--request", str(request))
    assert code == 0
    with PrivateStore(root) as selected:
        _, document = intake.load_batch(selected, reviewed["batch_sha256"])
        assert document["items"][0]["review"]["status"] == "human_validated"
        assert_ineligible(document["items"][0])


def test_cli_package_snapshot_and_advisory_reference_remain_unreviewed(tmp_path, capsys):
    root, package = tmp_path / "cli-store", tmp_path / "package"
    package.mkdir(mode=0o700)
    (package / "PKGBUILD").write_bytes(BUILD)
    assert run_cli(capsys, root, "init")[0] == 0
    code, snapshot, _ = run_cli(capsys, root, "package", "--type", "aur_git", "--root", str(package),
                                "--source-uri", SOURCE, "--package", "inert", "--revision", REV_A)
    assert code == 0 and snapshot["scope"] == "acquisition_only"
    identifier = "CVE-2099-99999"
    code, advisory, _ = run_cli(capsys, root, "advisory", "--identifier", identifier,
                                "--source-uri", "https://nvd.nist.gov/vuln/detail/" + identifier)
    assert code == 0 and advisory["scope"] == "acquisition_only"
    code, result, _ = run_cli(capsys, root, "intake", "--capture", snapshot["capture_sha256"][0],
                              "--capture", advisory["capture_sha256"][0])
    assert code == 0 and result["items"] == 2
    with PrivateStore(root) as selected:
        record = intake.load_capture(selected, advisory["capture_sha256"][0])
        assert record["coverage"] == "reference_only"
        assert record["transport_sha256"] == []
        _, document = intake.load_batch(selected, result["batch_sha256"])
        assert {item["kinds"][0] for item in document["items"]} == {"package_observation", "advisory_incident"}
        for item in document["items"]:
            assert item["classification"] == "unknown" and item["claim_level"] == "none"
            assert item["observations"] == []
            assert_ineligible(item)


@pytest.mark.parametrize("command,extra", [
    ("arch", ["--revision", REV_A]), ("aur", ["--revision", REV_A]),
    ("aur-metadata", []), ("arch-history", []), ("aur-history", []),
])
def test_cli_live_source_commands_require_explicit_network_flag(tmp_path, capsys, command, extra):
    code, result, _ = run_cli(capsys, tmp_path / "store", command, "--package", "inert", *extra)
    assert code == 1 and result == {"error": "network_disabled"}
    assert not (tmp_path / "store").exists()


def test_cli_invalid_arguments_do_not_echo_private_values(tmp_path, capsys):
    code, result, output = run_cli(capsys, tmp_path / "private-store", "private-invalid-command")
    assert code == 1 and result == {"error": "arguments"}
    assert "private" not in output


def test_cli_duplicate_json_request_fails_without_review(tmp_path, capsys):
    root = tmp_path / "store"
    with PrivateStore(root, create=True) as selected:
        result, _, _ = admit(selected, [captured()])
    request = tmp_path / "private-request.json"
    request.write_bytes(b'{"status":"unreviewed","status":"human_validated"}')
    code, response, output = run_cli(capsys, root, "review", "--base", result["batch_sha256"],
                                    "--request", str(request))
    assert code == 1 and "error" in response
    assert "private-request" not in output and "human_validated" not in output
    assert list((root / "reviews").iterdir()) == []


def test_cli_review_request_symlink_is_rejected_without_following_it(tmp_path, capsys):
    root = tmp_path / "store"
    with PrivateStore(root, create=True) as selected:
        result, _, document = admit(selected, [captured()])
    target = tmp_path / "target.json"
    target.write_bytes(intake.canonical(review_request(result, document["items"][0])))
    request = tmp_path / "private-request.json"
    request.symlink_to(target)
    code, response, output = run_cli(capsys, root, "review", "--base", result["batch_sha256"],
                                    "--request", str(request))
    assert code == 1 and response == {"error": "request_unreadable"}
    assert "private-request" not in output and "target.json" not in output
    assert list((root / "reviews").iterdir()) == []
