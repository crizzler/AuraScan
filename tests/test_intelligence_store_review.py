"""Independent regressions for protected installation and interrupted publication.

All ownership checks use the current test UID and private temporary roots. The
injected verifier is deliberately inert; real GPG verification has its own tests.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat

import pytest

import aurascan.core.intelligence as intelligence
import aurascan.core.intelligence_store as store_module
from aurascan.core.intelligence import (
    IntelligenceError, MANIFEST_FILENAME, PAYLOAD_FILENAME, SIGNATURE_FILENAME,
    build_manifest, canonical_json,
)
from aurascan.core.intelligence_crypto import PinnedKey
from aurascan.core.intelligence_store import IntelligenceStore


NOW = datetime(2026, 9, 12, 12, tzinfo=timezone.utc)
FINGERPRINT = "A" * 40


def bundle(tmp_path, sequence):
    directory = tmp_path / ("incoming-%d" % sequence)
    directory.mkdir()
    payload = (Path(intelligence.__file__).resolve().parents[1] / "assets" / "runtime-intelligence.json").read_bytes()
    manifest = canonical_json(build_manifest(payload, sequence, NOW))
    (directory / MANIFEST_FILENAME).write_bytes(manifest)
    (directory / PAYLOAD_FILENAME).write_bytes(payload)
    (directory / SIGNATURE_FILENAME).write_bytes(b"inert fixture signature; verification injected")
    return directory


def store_for(tmp_path):
    return IntelligenceStore(
        tmp_path / "protected" / "intelligence",
        expected_uid=os.getuid(),
        keys=(PinnedKey(FINGERPRINT, b"inert fixture key"),),
        clock=lambda: NOW,
        verifier=lambda *_args: FINGERPRINT,
    )


def active_generation(store):
    metadata = json.loads((store.root / "active.json").read_text())
    return store.root / metadata["generation"]


def test_restrictive_service_umask_does_not_make_public_intelligence_private(tmp_path):
    incoming = bundle(tmp_path, 1)
    store = store_for(tmp_path)
    previous = os.umask(0o077)
    try:
        assert store.activate(incoming)["activation"] == "updated"
    finally:
        os.umask(previous)

    # Every scan user needs search/read access to published bytes; writes must
    # remain confined to the protected owner. The lock is separately private.
    for directory in (store.root.parent, store.root, active_generation(store)):
        assert stat.S_IMODE(directory.stat().st_mode) == 0o755
    for path in [store.root / "active.json"] + list(active_generation(store).iterdir()):
        assert stat.S_IMODE(path.stat().st_mode) == 0o644
    assert stat.S_IMODE((store.root / "activation.lock").stat().st_mode) == 0o600
    assert store.load().status == "current"


def test_generation_publication_and_retention_do_not_look_like_directory_replacement(tmp_path):
    store = store_for(tmp_path)
    roots = []
    for sequence in (1, 2, 3):
        assert store.activate(bundle(tmp_path, sequence))["activation"] == "updated"
        roots.append(active_generation(store))
        assert store.load().sequence == sequence
    assert not roots[0].exists()
    assert roots[1].is_dir() and roots[2].is_dir()


def test_missing_activation_pointer_cannot_reset_accepted_sequence_history(tmp_path):
    older, latest = bundle(tmp_path, 1), bundle(tmp_path, 2)
    store = store_for(tmp_path)
    store.activate(latest)
    retained = active_generation(store)
    (store.root / "active.json").unlink()

    assert store.load().status == "unavailable"
    with pytest.raises(IntelligenceError):
        store.activate(older)
    assert retained.is_dir()
    assert not (store.root / "active.json").exists()
    assert store.load().status == "unavailable"


def test_interrupted_replacement_preserves_previous_bytes_and_can_retry(tmp_path, monkeypatch):
    first, second = bundle(tmp_path, 1), bundle(tmp_path, 2)
    store = store_for(tmp_path)
    store.activate(first)
    prior_state = (store.root / "active.json").read_bytes()
    prior_snapshot = store.load()
    original_write = store_module._write_file

    def fail_during_payload(directory_fd, name, payload, mode=0o644):
        if name == PAYLOAD_FILENAME:
            # Emulate power loss after a bounded partial regular file write.
            original_write(directory_fd, name, payload[:17], mode)
            raise OSError("inert injected write interruption")
        return original_write(directory_fd, name, payload, mode)

    monkeypatch.setattr(store_module, "_write_file", fail_during_payload)
    with pytest.raises(IntelligenceError):
        store.activate(second)
    assert (store.root / "active.json").read_bytes() == prior_state
    assert store.load().identity == prior_snapshot.identity

    monkeypatch.setattr(store_module, "_write_file", original_write)
    assert store.activate(second)["activation"] == "updated"
    assert store.load().sequence == 2


def test_first_publication_interruption_cannot_be_mistaken_for_unconfigured_state(tmp_path, monkeypatch):
    incoming = bundle(tmp_path, 1)
    store = store_for(tmp_path)
    original_write = store_module._write_file

    def fail_before_activation_pointer(directory_fd, name, payload, mode=0o644):
        if name == "active.pending":
            raise OSError("inert injected pointer interruption")
        return original_write(directory_fd, name, payload, mode)

    monkeypatch.setattr(store_module, "_write_file", fail_before_activation_pointer)
    with pytest.raises(IntelligenceError):
        store.activate(incoming)
    assert store.load().status == "unavailable"
    monkeypatch.setattr(store_module, "_write_file", original_write)
    with pytest.raises(IntelligenceError):
        store.activate(incoming)
    assert not (store.root / "active.json").exists()


def test_reader_keeps_complete_snapshot_when_publication_commits_during_read(tmp_path, monkeypatch):
    first, second = bundle(tmp_path, 1), bundle(tmp_path, 2)
    reader, publisher = store_for(tmp_path), store_for(tmp_path)
    publisher.activate(first)
    original_state = reader._state
    published = []

    def capture_then_publish(root):
        captured = original_state(root)
        if not published:
            published.append(True)
            publisher.activate(second)
        return captured

    monkeypatch.setattr(reader, "_state", capture_then_publish)
    retained_snapshot = reader.load()
    assert retained_snapshot.status == "current"
    assert retained_snapshot.sequence == 1
    assert reader.load().sequence == 2


@pytest.mark.parametrize("replacement", ["generation", "payload"])
def test_replaced_generation_or_payload_link_fails_closed(tmp_path, replacement):
    incoming = bundle(tmp_path, 1)
    store = store_for(tmp_path)
    store.activate(incoming)
    generation = active_generation(store)
    target = generation if replacement == "generation" else generation / PAYLOAD_FILENAME
    moved = tmp_path / ("moved-" + replacement)
    target.rename(moved)
    target.symlink_to(moved, target_is_directory=replacement == "generation")
    result = store.load()
    assert result.status == "unavailable"
    assert result.coverage_error
    assert not result.shortcut_eligible
