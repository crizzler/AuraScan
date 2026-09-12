"""Externally meaningful update, offline, and transaction invariants."""

import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from aurascan.core.intelligence import (
    IntelligenceError, MANIFEST_FILENAME, SIGNATURE_FILENAME, PAYLOAD_FILENAME,
    MAX_PAYLOAD_BYTES, build_manifest, bundled_snapshot, canonical_json,
    record_identities, snapshot_from_payload, strict_json, validate_manifest, validate_payload,
)
from aurascan.core.intelligence_crypto import PinnedKey
from aurascan.core.intelligence_store import IntelligenceStore, capture_bundle, _stage_offline_bundle


NOW = datetime(2026, 9, 12, 12, tzinfo=timezone.utc)
KEY = PinnedKey("A" * 40, b"inert-test-public-key")


def baseline():
    return json.loads((Path(__file__).parents[1] / "aurascan/assets/runtime-intelligence.json").read_bytes())


def write_bundle(path, sequence=1, *, data=None, issued=NOW, signature=b"inert-signature"):
    path.mkdir(parents=True, exist_ok=True)
    payload = canonical_json(baseline() if data is None else data)
    manifest = canonical_json(build_manifest(payload, sequence, issued))
    for name, raw in ((MANIFEST_FILENAME, manifest), (PAYLOAD_FILENAME, payload), (SIGNATURE_FILENAME, signature)):
        (path / name).write_bytes(raw)
    return path


def store(tmp_path, *, clock=lambda: NOW, verifier=lambda *_args: KEY.fingerprint):
    return IntelligenceStore(tmp_path / "installed", expected_uid=os.getuid(), keys=(KEY,), clock=clock, verifier=verifier)


@pytest.mark.parametrize("change", [
    lambda x: x.update(schema_version="2.0"),
    lambda x: x.update(feed_id="another-feed"),
    lambda x: x.update(command="inert unsupported authority"),
    lambda x: x["npm_campaigns"][0]["rights"].update(redistribution="unknown"),
    lambda x: x["npm_campaigns"][0].pop("rights"),
    lambda x: x["vendor_advisories"][0].update(comparator="arbitrary-python"),
    lambda x: x["vendor_advisories"][0].update(known_exploited=False),
    lambda x: x["npm_campaigns"][0]["packages"].append(x["npm_campaigns"][0]["packages"][0]),
    lambda x: x["npm_campaigns"][0]["payload_sha256"].append(x["npm_campaigns"][0]["payload_sha256"][0]),
    lambda x: x["vendor_advisories"][0]["rights"].update(basis=" "),
])
def test_invalid_or_unreviewed_intelligence_is_not_admitted(change):
    data = baseline()
    change(data)
    with pytest.raises(IntelligenceError):
        validate_payload(canonical_json(data))


@pytest.mark.parametrize("raw", [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1.2}', b'{"x":' + b"9" * 10000 + b'}', b'{' + b'"x":[' * 30 + b'0' + b']' * 30 + b'}'])
def test_hostile_json_fails_before_unbounded_numeric_or_structural_work(raw):
    with pytest.raises(IntelligenceError):
        strict_json(raw, MAX_PAYLOAD_BYTES)


def test_snapshot_cannot_be_mutated_through_nested_records():
    snap = bundled_snapshot()
    with pytest.raises(TypeError):
        snap.payload["npm_campaigns"][0]["packages"][0]["broad_advisory"] = "none"
    with pytest.raises(AttributeError):
        snap.payload["npm_campaigns"].append({})


@pytest.mark.parametrize("change", [
    lambda x: x.update(sequence=True),
    lambda x: x.update(sequence=0),
    lambda x: x.update(engine_capability="2.0"),
    lambda x: x.update(expires_at="2026-10-13T12:00:00Z"),
    lambda x: x.update(issued_at="2026-09-12T12:06:00Z"),
    lambda x: x.update(expires_at="2026-09-12T12:00:00Z"),
    lambda x: x.update(payload_size=MAX_PAYLOAD_BYTES + 1),
])
def test_manifest_rejects_unsupported_time_size_and_identity(change):
    value = build_manifest(canonical_json(baseline()), 1, NOW)
    change(value)
    with pytest.raises(IntelligenceError):
        validate_manifest(canonical_json(value), NOW)


def test_missing_store_is_bundled_and_does_not_create_state(tmp_path):
    target = store(tmp_path)
    assert target.load().status == "bundled"
    assert not target.root.exists()


def test_activation_is_verified_before_any_detection_becomes_available(tmp_path):
    calls = []
    target = store(tmp_path, verifier=lambda *args: calls.append(args) or KEY.fingerprint)
    bundle = write_bundle(tmp_path / "input")
    result = target.activate(bundle)
    assert len(calls) == 1
    assert calls[0][0] == (bundle / MANIFEST_FILENAME).read_bytes()
    assert result["activation"] == "updated"
    assert target.load().metadata()["identity"] == result["identity"]
    assert target.activate(bundle)["activation"] == "unchanged"


def test_unconfigured_trust_never_accepts_an_unsigned_local_bundle(tmp_path):
    target = IntelligenceStore(tmp_path / "state", expected_uid=os.getuid(), keys=(), clock=lambda: NOW)
    with pytest.raises(IntelligenceError, match="not configured"):
        target.activate(write_bundle(tmp_path / "input"))
    assert not target.root.exists()


def test_wrong_signature_preserves_last_verified_generation(tmp_path):
    target = store(tmp_path)
    original = target.activate(write_bundle(tmp_path / "one"))
    def reject(*_args):
        raise IntelligenceError("inert signature refusal")
    target.verifier = reject
    with pytest.raises(IntelligenceError):
        target.activate(write_bundle(tmp_path / "two", 2))
    assert target.load().identity == original["identity"]


def test_new_sequence_and_same_sequence_conflicts_are_distinguished(tmp_path):
    target = store(tmp_path)
    target.activate(write_bundle(tmp_path / "two", 2))
    with pytest.raises(IntelligenceError, match="rollback"):
        target.activate(write_bundle(tmp_path / "one", 1))
    data = baseline()
    data["reviewed_at"] = "2026-09-12"
    with pytest.raises(IntelligenceError, match="conflicting"):
        target.activate(write_bundle(tmp_path / "conflict", 2, data=data))
    assert target.load().sequence == 2


def test_payload_replacement_is_not_validated_by_manifest_mentions(tmp_path):
    target = store(tmp_path)
    bundle = write_bundle(tmp_path / "input")
    (bundle / PAYLOAD_FILENAME).write_bytes(canonical_json({"sha256": hashlib.sha256((bundle / MANIFEST_FILENAME).read_bytes()).hexdigest()}))
    with pytest.raises(IntelligenceError, match="does not match"):
        target.activate(bundle)


def test_withdrawing_detection_requires_reviewed_correction(tmp_path):
    target = store(tmp_path)
    target.activate(write_bundle(tmp_path / "one"))
    data = baseline()
    old_ids = record_identities(data)
    data["npm_campaigns"][0]["payload_sha256"] = []
    with pytest.raises(IntelligenceError, match="withdrawal"):
        target.activate(write_bundle(tmp_path / "two", 2, data=data))
    removed = set(old_ids) - set(record_identities(data))
    data["withdrawals"] = [{"id": identity, "reason": "Inert test correction", "reviewed_at": "2026-09-12", "references": ["https://example.invalid/correction"], "rights": {"redistribution": "permitted", "basis": "Original inert test metadata"}} for identity in removed]
    assert target.activate(write_bundle(tmp_path / "corrected", 2, data=data))["sequence"] == 2
    data["withdrawals"] = []
    with pytest.raises(IntelligenceError, match="correction history"):
        target.activate(write_bundle(tmp_path / "forgot-correction", 3, data=data))


def test_expired_installed_records_remain_available_with_stale_status(tmp_path):
    clock = [NOW]
    target = store(tmp_path, clock=lambda: clock[0])
    original = target.activate(write_bundle(tmp_path / "one"))
    clock[0] += timedelta(days=31)
    stale = target.load()
    assert stale.status == "stale" and not stale.shortcut_eligible
    assert not stale.coverage_error and stale.digest == original["digest"]
    assert stale.identity != original["identity"]


def test_clock_rollback_is_coverage_failure_and_cannot_activate(tmp_path):
    clock = [NOW]
    target = store(tmp_path, clock=lambda: clock[0])
    target.activate(write_bundle(tmp_path / "one"))
    clock[0] -= timedelta(hours=1)
    assert target.load().status == "unavailable"
    with pytest.raises(IntelligenceError):
        target.activate(write_bundle(tmp_path / "two", 2))


@pytest.mark.parametrize("kind", ["file-link", "directory-link", "fifo", "hardlink"])
def test_untrusted_input_links_and_special_files_are_never_followed(tmp_path, kind):
    bundle = write_bundle(tmp_path / "input")
    if kind == "directory-link":
        link = tmp_path / "link"
        link.symlink_to(bundle, target_is_directory=True)
        bundle = link
    else:
        source = bundle / PAYLOAD_FILENAME
        source.rename(tmp_path / "outside")
        if kind == "file-link":
            source.symlink_to(tmp_path / "outside")
        elif kind == "fifo":
            os.mkfifo(str(source))
        else:
            os.link(str(tmp_path / "outside"), str(source))
    with pytest.raises(IntelligenceError):
        capture_bundle(bundle)


def test_untrusted_payload_replacement_during_capture_is_rejected(tmp_path, monkeypatch):
    bundle = write_bundle(tmp_path / "input")
    original_read = os.read
    replaced = []
    def changing_read(fd, size):
        result = original_read(fd, size)
        if not replaced:
            replacement = bundle / "replacement"
            replacement.write_bytes((bundle / MANIFEST_FILENAME).read_bytes())
            os.replace(str(replacement), str(bundle / MANIFEST_FILENAME))
            replaced.append(True)
        return result
    monkeypatch.setattr(os, "read", changing_read)
    with pytest.raises(IntelligenceError, match="changed"):
        capture_bundle(bundle)


def test_corrupt_installed_bytes_do_not_silently_revert_to_allowance(tmp_path):
    target = store(tmp_path)
    result = target.activate(write_bundle(tmp_path / "one"))
    (target.root / result["manifest_digest"] / PAYLOAD_FILENAME).write_bytes(b"{}")
    snapshot = target.load()
    assert snapshot.status == "unavailable" and snapshot.coverage_error
    assert snapshot.npm_campaigns and not snapshot.shortcut_eligible


def test_world_writable_storage_is_not_accepted(tmp_path):
    target = store(tmp_path)
    target.activate(write_bundle(tmp_path / "one"))
    target.root.chmod(0o777)
    assert target.load().status == "unavailable"


def test_retention_is_bounded_across_many_verified_updates(tmp_path):
    target = store(tmp_path)
    for sequence in range(1, 7):
        target.activate(write_bundle(tmp_path / str(sequence), sequence))
    assert target.load().sequence == 6
    assert len([p for p in target.root.iterdir() if p.is_dir()]) == 2


def test_offline_import_stages_only_captured_bytes_under_private_lock(tmp_path):
    bundle = write_bundle(tmp_path / "input")
    inbox = tmp_path / "private-import"
    with _stage_offline_bundle(bundle, root=inbox, expected_uid=os.getuid()):
        (bundle / PAYLOAD_FILENAME).write_bytes(b"changed after capture")
        assert (inbox / PAYLOAD_FILENAME).read_bytes() != b"changed after capture"
        assert inbox.stat().st_mode & 0o077 == 0
        assert (inbox / PAYLOAD_FILENAME).stat().st_mode & 0o077 == 0
        assert (inbox / "activation.lock").stat().st_mode & 0o077 == 0


def test_no_follow_store_parent_prevents_hidden_installed_state(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "linked"
    link.symlink_to(real, target_is_directory=True)
    target = IntelligenceStore(link / "missing", expected_uid=os.getuid(), keys=(KEY,))
    assert target.load().status == "unavailable"
