"""Small inert contract examples generated in temporary roots, not corpus data."""

from datetime import datetime, timezone
import json
from pathlib import Path

import pytest

from aurascan.core.intelligence import IntelligenceError, canonical_json
from tools.intelligence_repository.bundle import main, prepare_bundle, read_payload


def payload():
    return {
        "schema_version": "1.0", "feed_id": "aurascan-intelligence", "reviewed_at": "2026-09-12",
        "npm_campaigns": [{"id": "inert-regression", "reviewed_at": "2026-09-12",
                           "references": ["https://example.invalid/advisory"],
                           "rights": {"redistribution": "permitted", "basis": "Test author created these inert indicators."},
                           "packages": [{"name": "inert-regression-package", "versions": ["1.0.0"],
                                         "advisory_ids": ["TEST-1"], "references": ["https://example.invalid/advisory"],
                                         "broad_advisory": "none"}],
                           "payload_sha256": [], "malicious_domains": []}],
        "vendor_advisories": [], "withdrawals": [],
    }


def test_deterministic_unsigned_bundle_and_explicit_30_day_window(tmp_path):
    source = tmp_path / "reviewed.json"
    source.write_bytes(canonical_json(payload()))
    issued = datetime(2026, 9, 12, tzinfo=timezone.utc)
    for name in ("first", "second"):
        prepare_bundle(source, source, tmp_path / name, 7, issued)
    first, second = tmp_path / "first", tmp_path / "second"
    assert sorted(item.name for item in first.iterdir()) == ["intelligence.json", "manifest.json"]
    for item in first.iterdir():
        assert item.read_bytes() == (second / item.name).read_bytes()
    manifest = json.loads((first / "manifest.json").read_bytes())
    assert manifest["sequence"] == 7
    assert manifest["issued_at"] == "2026-09-12T00:00:00Z"
    assert manifest["expires_at"] == "2026-10-12T00:00:00Z"
    assert not (first / "manifest.json.asc").exists()


@pytest.mark.parametrize("rights", [{}, {"redistribution": "unknown", "basis": "Unreviewed"},
                                  {"redistribution": "permitted", "basis": ""}])
def test_uncertain_rights_never_emit_unsigned_bundle(tmp_path, rights):
    source = tmp_path / "reviewed.json"
    data = payload()
    data["npm_campaigns"][0]["rights"] = rights
    source.write_bytes(canonical_json(data))
    with pytest.raises(IntelligenceError):
        prepare_bundle(source, source, tmp_path / "out", 1, datetime.now(timezone.utc))
    assert not (tmp_path / "out").exists()


def test_removal_needs_the_exact_explicit_correction(tmp_path, capsys):
    previous = tmp_path / "previous.json"
    previous.write_bytes(canonical_json(payload()))
    assert main(["identities", str(previous)]) == 0
    published_identity = next(iter(json.loads(capsys.readouterr().out)))
    candidate = payload()
    candidate["npm_campaigns"] = []
    source = tmp_path / "candidate.json"
    source.write_bytes(canonical_json(candidate))
    assert main(["validate", str(source), "--previous", str(previous)]) == 1
    candidate["withdrawals"] = [{"id": published_identity,
                                "reason": "Inert regression correction", "reviewed_at": "2026-09-12",
                                "references": ["https://example.invalid/correction"],
                                "rights": {"redistribution": "permitted", "basis": "Created by the test author."}}]
    source.write_bytes(canonical_json(candidate))
    assert main(["validate", str(source), "--previous", str(previous)]) == 0


def test_symlink_input_and_existing_output_are_not_replaced(tmp_path):
    source = tmp_path / "source.json"
    source.write_bytes(canonical_json(payload()))
    linked = tmp_path / "linked.json"
    linked.symlink_to(source)
    with pytest.raises(OSError):
        read_payload(linked)
    output = tmp_path / "out"
    output.mkdir()
    (output / "keep").write_text("unrelated")
    with pytest.raises(FileExistsError):
        prepare_bundle(source, source, output, 1, datetime.now(timezone.utc))
    assert (output / "keep").read_text() == "unrelated"


def test_malformed_input_is_not_interpreted_or_copied(tmp_path, capsys):
    source = tmp_path / "bad.json"
    source.write_bytes(b'{"schema_version":"1.0","schema_version":"$(fake-secret)"}')
    assert main(["validate", str(source), "--previous", str(source)]) == 1
    assert "fake-secret" not in capsys.readouterr().err
