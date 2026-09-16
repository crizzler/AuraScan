"""Consent gate, capture boundaries and export immutability regressions."""

import io
import json
import os
from pathlib import Path

import pytest

from aurascan.core.evidence_cli import run_evidence
from aurascan.core.research_evidence import (
    ADJUDICATION_LABELS,
    CONSENT_PURPOSES,
    EVIDENCE_DIRNAME,
    LOG_FILENAME,
    EvidenceError,
    evidence_root,
    export_candidates,
    grant_consent,
    read_adjudications,
    read_consent,
    revoke_consent,
    status,
)
from aurascan.core.review import ReviewDecisionStore, ScanFingerprint


def fingerprint(*, package_name="fixture-package", package_base="fixture-base"):
    return ScanFingerprint(
        package_name=package_name,
        package_base=package_base,
        package_version="1.0",
        pkgbuild_hash="pkgbuild-hash-fixture",
        source_metadata_hash="source-hash-fixture",
        scan_fingerprint="scan-fingerprint-fixture",
        finding_ids=["finding-manual-fixture"],
        finding_fingerprints=["finding-fingerprint-fixture"],
        scanner_version="test-scanner",
        rule_version="test-rules",
    )


def store_for(tmp_path):
    return ReviewDecisionStore(tmp_path / "review.db")


def accept(tmp_path, label="", *, remember=True, reason=""):
    store = store_for(tmp_path)
    return store.record_acceptance(
        fingerprint(), remember=remember, reason=reason, adjudication_label=label,
    )


def test_acceptance_capture_is_local_default_on_and_unlabeled(tmp_path):
    accept(tmp_path)

    records, error = read_adjudications(evidence_root(tmp_path / "review.db"))
    assert error == ""
    assert len(records) == 1
    record = records[0]
    assert record["label"] == "" and record["label_source"] == "none"
    assert record["schema"].startswith("aurascan-research-evidence/")
    assert record["pkgbuild_hash"] == "pkgbuild-hash-fixture"
    assert record["findings"] == [{"finding_id": "finding-manual-fixture"}]
    assert "fixture-package" not in json.dumps(record)


def test_unlabeled_capture_is_not_exportable(tmp_path):
    accept(tmp_path)
    grant_consent(evidence_root(tmp_path / "review.db"), "training", confirm="training")

    with pytest.raises(EvidenceError, match="no labeled"):
        export_candidates(evidence_root(tmp_path / "review.db"), "training", tmp_path / "out.json")
    assert not (tmp_path / "out.json").exists()


def test_export_is_refused_until_consent_is_recorded_for_that_purpose(tmp_path):
    accept(tmp_path, "confirmed_malicious")
    root = evidence_root(tmp_path / "review.db")

    with pytest.raises(EvidenceError, match="no recorded consent"):
        export_candidates(root, "training", tmp_path / "out.json")
    assert not (tmp_path / "out.json").exists()

    grant_consent(root, "analysis", confirm="analysis")
    with pytest.raises(EvidenceError, match="no recorded consent"):
        export_candidates(root, "training", tmp_path / "out.json")

    grant_consent(root, "training", confirm="training")
    result = export_candidates(root, "training", tmp_path / "out.json")
    assert result["candidates"] == 1
    assert (tmp_path / "out.json").exists()


def test_consent_requires_the_exact_purpose_confirmation(tmp_path):
    root = evidence_root(tmp_path / "review.db")

    with pytest.raises(EvidenceError, match="exact purpose confirmation"):
        grant_consent(root, "training", confirm="")
    with pytest.raises(EvidenceError, match="exact purpose confirmation"):
        grant_consent(root, "training", confirm="commercial_training")

    assert read_consent(root)[0]["purposes"] == {}


def test_consent_is_not_inherited_between_purposes_and_can_be_revoked(tmp_path):
    root = evidence_root(tmp_path / "review.db")
    grant_consent(root, "commercial_training", confirm="commercial_training")

    consent, error = read_consent(root)
    assert error == ""
    assert set(consent["purposes"]) == {"commercial_training"}
    assert consent["purposes"]["commercial_training"]["rights_granted"] == "none"

    assert revoke_consent(root, "commercial_training") is True
    assert read_consent(root)[0]["purposes"] == {}
    assert revoke_consent(root, "commercial_training") is False


def test_exported_candidates_stay_quarantined_and_carry_no_private_material(tmp_path):
    accept(tmp_path, "benign_false_positive",
           reason="operator note with /home/private/path and SECRET=fixture-only")
    root = evidence_root(tmp_path / "review.db")
    grant_consent(root, "analysis", confirm="analysis")

    result = export_candidates(root, "analysis", tmp_path / "candidates.json")
    document = json.loads((tmp_path / "candidates.json").read_text(encoding="utf-8"))
    serialized = json.dumps(document)

    assert document["admission"] == "not_admitted"
    assert document["partition"] == "quarantine"
    assert document["rights"] == {
        "analysis": "unresolved", "training": "unresolved",
        "commercial_training": "unresolved", "redistribution": "unresolved",
    }
    candidate = document["candidates"][0]
    assert candidate["partition"] == "quarantine"
    assert candidate["admission"] == "not_admitted"
    assert candidate["content_binding"] == "hash_only"
    assert candidate["label"] == "benign_false_positive"
    assert candidate["label_source"] == "human_review"
    assert candidate["rights"]["training"] == "unresolved"
    assert candidate["requires_offline_intake"] is True
    assert candidate["derivation_family"]
    # No free-text operator note, host path, secret or raw package identity.
    assert "SECRET" not in serialized
    assert "/home/private" not in serialized
    assert "operator note" not in serialized
    assert "fixture-package" not in serialized
    assert "fixture-base" not in serialized
    assert result["digest"] == __import__("hashlib").sha256(
        (tmp_path / "candidates.json").read_bytes()).hexdigest()
    assert set(document["counts"]) == {"candidates", "excluded_unlabeled"}


def test_revocation_withdraws_the_recorded_judgment(tmp_path):
    decision = accept(tmp_path, "benign_expected_behavior")
    root = evidence_root(tmp_path / "review.db")
    grant_consent(root, "training", confirm="training")
    assert export_candidates(root, "training", tmp_path / "first.json")["candidates"] == 1

    store_for(tmp_path).revoke(decision.decision_id)

    records, _ = read_adjudications(root)
    assert len(records) == 2
    assert records[-1]["label"] == "" and records[-1]["decision_status"] == "revoked"
    with pytest.raises(EvidenceError, match="no labeled"):
        export_candidates(root, "training", tmp_path / "second.json")


def test_relabel_supersedes_the_previous_judgment_deterministically(tmp_path):
    store = store_for(tmp_path)
    store.record_acceptance(fingerprint(), remember=True, adjudication_label="suspicious_unconfirmed")
    decision = store.list_decisions()[0]

    from aurascan.core.research_evidence import adjudication_record, append_adjudication

    root = evidence_root(tmp_path / "review.db")
    append_adjudication(root, adjudication_record(
        decision, "confirmed_malicious", now="2026-09-16T00:00:00Z", previous="earlier"))

    grant_consent(root, "training", confirm="training")
    export_candidates(root, "training", tmp_path / "out.json")
    document = json.loads((tmp_path / "out.json").read_text(encoding="utf-8"))
    candidates = document["candidates"]
    assert len(candidates) == 1
    assert candidates[0]["label"] == "confirmed_malicious"
    assert candidates[0]["supersedes"] == "earlier"


def test_identical_capture_is_never_written_twice(tmp_path):
    from aurascan.core.research_evidence import adjudication_record, append_adjudication

    decision = accept(tmp_path, "benign_false_positive")
    root = evidence_root(tmp_path / "review.db")
    record = adjudication_record(decision, "benign_false_positive", now="2026-09-16T00:00:00Z")

    append_adjudication(root, record)
    append_adjudication(root, record)

    records, _ = read_adjudications(root)
    assert len([item for item in records
                if item["adjudication_id"] == record.adjudication_id]) == 1


def test_malformed_or_symlinked_log_fails_closed(tmp_path):
    root = evidence_root(tmp_path / "review.db")
    accept(tmp_path)
    grant_consent(root, "training", confirm="training")
    (root / LOG_FILENAME).write_text("not-json\n", encoding="utf-8")

    summary = status(root)
    assert summary["log_error"]
    with pytest.raises(EvidenceError, match="malformed"):
        export_candidates(root, "training", tmp_path / "out.json")
    assert not (tmp_path / "out.json").exists()

    (root / LOG_FILENAME).unlink()
    (root / LOG_FILENAME).symlink_to(tmp_path / "elsewhere.jsonl")
    with pytest.raises(EvidenceError):
        read_adjudications(root)


def test_capture_failure_never_blocks_a_review_acceptance(tmp_path):
    # A file where the evidence directory belongs makes capture impossible.
    (tmp_path / EVIDENCE_DIRNAME).write_text("not a directory\n", encoding="utf-8")

    decision = accept(tmp_path, "confirmed_malicious")

    assert decision.decision_id
    assert store_for(tmp_path).decision_by_id(decision.decision_id) is not None


def test_evidence_directory_and_log_are_private(tmp_path):
    accept(tmp_path)
    root = evidence_root(tmp_path / "review.db")

    assert (os.stat(root).st_mode & 0o777) == 0o700
    assert (os.stat(root / LOG_FILENAME).st_mode & 0o777) == 0o600


def test_status_reports_capture_and_consent_without_private_content(tmp_path):
    accept(tmp_path, "benign_false_positive")
    accept(tmp_path)
    root = evidence_root(tmp_path / "review.db")
    grant_consent(root, "training", confirm="training", operator="operator@fixture")

    summary = status(root)

    assert summary["records"] == 2
    assert summary["labeled_records"] == 1
    assert summary["unlabeled_records"] == 1
    assert summary["labels"]["benign_false_positive"] == 1
    assert summary["consent"]["training"] is True
    assert summary["consent"]["analysis"] is False
    assert summary["admission"] == "not_admitted"
    assert summary["capture"] == "local_only"
    assert "operator@fixture" not in json.dumps(summary)


def test_cli_status_consent_and_export_flow(tmp_path):
    out = io.StringIO()
    errors = io.StringIO()
    db = tmp_path / "review.db"
    accept(tmp_path, "confirmed_malicious")

    assert run_evidence(["status", "--review-db", str(db)], stdout=out, stderr=errors) == 0
    assert "Research use: off unless consent is granted" in out.getvalue()

    # A grant without the exact confirmation is refused and records nothing.
    assert run_evidence(["consent", "--purpose", "training", "--review-db", str(db)],
                        stdout=out, stderr=errors) == 1
    assert read_consent(evidence_root(db))[0]["purposes"] == {}

    assert run_evidence(["consent", "--purpose", "training", "--confirm", "training",
                         "--review-db", str(db)], stdout=out, stderr=errors) == 0
    assert read_consent(evidence_root(db))[0]["purposes"]["training"]["purpose"] == "training"

    # Export for a purpose that was never granted is refused.
    assert run_evidence(["export", "--purpose", "analysis", "--out", str(tmp_path / "no.json"),
                         "--review-db", str(db)], stdout=out, stderr=errors) == 1
    assert "Export refused" in errors.getvalue()
    assert not (tmp_path / "no.json").exists()

    assert run_evidence(["export", "--purpose", "training", "--out", str(tmp_path / "yes.json"),
                         "--review-db", str(db)], stdout=out, stderr=errors) == 0
    document = json.loads((tmp_path / "yes.json").read_text(encoding="utf-8"))
    assert document["admission"] == "not_admitted"
    assert document["counts"]["candidates"] == 1


def test_cli_export_never_reports_admission(tmp_path):
    out = io.StringIO()
    errors = io.StringIO()
    db = tmp_path / "review.db"

    assert run_evidence(["export", "--purpose", "training", "--out", str(tmp_path / "x.json"),
                         "--review-db", str(db)], stdout=out, stderr=errors) == 1
    assert "Export refused" in errors.getvalue()
    assert not (tmp_path / "x.json").exists()


def test_label_vocabulary_is_bounded_and_documented():
    assert ADJUDICATION_LABELS == (
        "benign_false_positive", "benign_expected_behavior",
        "suspicious_unconfirmed", "confirmed_malicious",
    )
    assert "" not in ADJUDICATION_LABELS
    assert CONSENT_PURPOSES == ("analysis", "training", "commercial_training", "redistribution")
    assert len(set(ADJUDICATION_LABELS)) == len(ADJUDICATION_LABELS)
