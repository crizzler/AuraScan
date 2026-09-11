"""Temporary-root checks for the developer-only immutable research store."""

from contextlib import contextmanager
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import sys

import pytest


_TOOL_PATH = Path(__file__).resolve().parents[1] / "tools/security_data_store.py"
_SPEC = importlib.util.spec_from_file_location("security_data_store", _TOOL_PATH)
storage = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = storage
_SPEC.loader.exec_module(storage)


def error_code(code):
    return pytest.raises(storage.StoreError, match="^" + code + "$")


def private_file(path, payload):
    path.write_bytes(payload)
    path.chmod(0o600)


@pytest.mark.parametrize("kind", sorted(storage.KINDS))
def test_round_trip_is_immutable_private_and_idempotent(tmp_path, kind):
    root = tmp_path / "store"
    payload = b'{"inert":"example.invalid"}'
    expected = hashlib.sha256(payload).hexdigest()
    with storage.PrivateStore(root, create=True) as store:
        assert store.put(kind, payload) == expected
        path = root / kind / (expected + (".blob" if kind == "blobs" else ".json"))
        before = path.stat()
        assert store.get(kind, expected) == payload
        assert store.put(kind, payload) == expected
        after = path.stat()
        assert (before.st_ino, before.st_mtime_ns) == (after.st_ino, after.st_mtime_ns)
        assert stat.S_IMODE(after.st_mode) == 0o600
        assert after.st_nlink == 1
        assert {entry.name for entry in root.iterdir()} == storage.KINDS | {".lock"}
        for directory in storage.KINDS:
            assert stat.S_IMODE((root / directory).stat().st_mode) == 0o700
        assert stat.S_IMODE(root.stat().st_mode) == 0o700
        assert stat.S_IMODE((root / ".lock").stat().st_mode) == 0o600
    with storage.PrivateStore(root) as reopened:
        assert reopened.get(kind, expected) == payload


def test_creation_is_explicit_and_parent_must_already_exist(tmp_path):
    root = tmp_path / "missing"
    with error_code("store_io"):
        with storage.PrivateStore(root):
            pass
    assert not root.exists()
    with error_code("store_io"):
        with storage.PrivateStore(root / "nested", create=True):
            pass
    assert not root.exists()


def test_existing_empty_directory_needs_explicit_initialization(tmp_path):
    root = tmp_path / "store"
    root.mkdir(mode=0o700)
    with error_code("store_io"):
        with storage.PrivateStore(root):
            pass
    assert list(root.iterdir()) == []
    with storage.PrivateStore(root, create=True):
        pass


@pytest.mark.parametrize("kind", ["../blobs", "blob", "latest", "", None, []])
def test_unknown_kind_never_becomes_a_path(tmp_path, kind):
    with storage.PrivateStore(tmp_path / "store", create=True) as store:
        with error_code("store_kind"):
            store.put(kind, b"inert")
        with error_code("store_kind"):
            store.get(kind, "a" * 64)


@pytest.mark.parametrize("digest", ["a" * 63, "A" * 64, "a" * 65, "g" * 64,
                                     "../capture", "a" * 64 + "\n", None, []])
def test_digest_requires_exact_lowercase_sha256(tmp_path, digest):
    with storage.PrivateStore(tmp_path / "store", create=True) as store:
        with error_code("store_digest"):
            store.get("blobs", digest)


@pytest.mark.parametrize("payload", ["text", bytearray(b"text"), memoryview(b"text"), None])
def test_only_explicit_bytes_are_accepted(tmp_path, payload):
    with storage.PrivateStore(tmp_path / "store", create=True) as store:
        with error_code("store_payload"):
            store.put("blobs", payload)


@pytest.mark.parametrize("kind,limit", [("blobs", storage.MAX_BLOB_BYTES),
                                       ("captures", storage.MAX_OBJECT_BYTES)])
def test_per_object_bounds_and_empty_content(tmp_path, kind, limit):
    with storage.PrivateStore(tmp_path / "store", create=True) as store:
        digest = store.put(kind, b"")
        assert store.get(kind, digest) == b""
        digest = store.put(kind, b"x" * limit)
        assert len(store.get(kind, digest)) == limit
        with error_code("store_limit"):
            store.put(kind, b"x" * (limit + 1))


def test_store_entry_and_byte_limits_prevent_growth(tmp_path, monkeypatch):
    root = tmp_path / "store"
    with storage.PrivateStore(root, create=True) as store:
        first = store.put("blobs", b"one")
        monkeypatch.setattr(storage, "MAX_STORE_ENTRIES", 1)
        assert store.put("blobs", b"one") == first
        with error_code("store_limit"):
            store.put("captures", b"two")
        monkeypatch.setattr(storage, "MAX_STORE_ENTRIES", 4096)
        monkeypatch.setattr(storage, "MAX_STORE_BYTES", 5)
        with error_code("store_limit"):
            store.put("captures", b"two")
        assert len(list((root / "blobs").iterdir())) == 1
        assert list((root / "captures").iterdir()) == []


@pytest.mark.parametrize("location", ["root", "ancestor", "kind", "lock", "object"])
def test_symlinks_are_refused_without_reading_targets(tmp_path, location):
    root = tmp_path / "store"
    with storage.PrivateStore(root, create=True) as store:
        digest = store.put("blobs", b"inert")
    if location == "ancestor":
        link = tmp_path / "alias"
        link.symlink_to(tmp_path, target_is_directory=True)
        selected = link / "store"
    elif location == "root":
        selected = tmp_path / "alias"
        selected.symlink_to(root, target_is_directory=True)
    else:
        selected = root
        target = root / ("blobs" if location == "kind" else ".lock")
        if location == "object":
            target = root / "blobs" / (digest + ".blob")
        saved = tmp_path / "saved"
        target.rename(saved)
        target.symlink_to(saved, target_is_directory=location == "kind")
    with pytest.raises(storage.StoreError):
        with storage.PrivateStore(selected):
            pass


@pytest.mark.parametrize("location", ["root", "ancestor", "kind", "lock", "object"])
def test_unsafe_modes_are_rejected_not_repaired(tmp_path, location):
    root = tmp_path / "store"
    with storage.PrivateStore(root, create=True) as store:
        digest = store.put("blobs", b"inert")
    selected = {"root": root, "ancestor": tmp_path, "kind": root / "blobs",
                "lock": root / ".lock", "object": root / "blobs" / (digest + ".blob")}[location]
    selected.chmod(0o777 if selected.is_dir() else 0o644)
    try:
        with error_code("store_unsafe"):
            with storage.PrivateStore(root, create=True):
                pass
        assert stat.S_IMODE(selected.stat().st_mode) in (0o777, 0o644)
    finally:
        selected.chmod(0o700 if selected.is_dir() else 0o600)


def test_wrong_owner_is_rejected_without_requiring_root(tmp_path):
    root = tmp_path / "store"
    with storage.PrivateStore(root, create=True):
        pass
    selected = storage.PrivateStore(root)
    selected._uid = os.getuid() + 12345
    with error_code("store_unsafe"):
        with selected:
            pass


@pytest.mark.parametrize("location", ["lock", "object"])
def test_hard_links_are_not_accepted_as_private_files(tmp_path, location):
    root = tmp_path / "store"
    with storage.PrivateStore(root, create=True) as store:
        digest = store.put("blobs", b"inert")
    selected = root / ".lock" if location == "lock" else root / "blobs" / (digest + ".blob")
    os.link(selected, tmp_path / "foreign-name")
    with error_code("store_unsafe"):
        with storage.PrivateStore(root):
            pass


def test_existing_corruption_is_never_replaced(tmp_path):
    root = tmp_path / "store"
    with storage.PrivateStore(root, create=True) as store:
        digest = store.put("blobs", b"original")
        target = root / "blobs" / (digest + ".blob")
        target.write_bytes(b"modified")
        changed_inode = target.stat().st_ino
        with error_code("store_corrupt"):
            store.get("blobs", digest)
        with error_code("store_corrupt"):
            store.put("blobs", b"original")
        assert target.read_bytes() == b"modified"
        assert target.stat().st_ino == changed_inode


def test_missing_object_is_distinct_from_corrupt_object(tmp_path):
    with storage.PrivateStore(tmp_path / "store", create=True) as store:
        with error_code("store_missing"):
            store.get("blobs", "a" * 64)


@pytest.mark.parametrize("entry", ["unexpected", ".tmp-interrupted", "a" * 64 + ".json"])
def test_unrecognized_or_interrupted_entries_block_store(tmp_path, entry):
    root = tmp_path / "store"
    with storage.PrivateStore(root, create=True):
        pass
    target = root / "blobs" / entry
    private_file(target, b"inert")
    with error_code("store_incomplete" if entry.startswith(".tmp-") else "store_layout"):
        with storage.PrivateStore(root):
            pass
    assert target.read_bytes() == b"inert"


def test_inventory_does_not_recurse_into_unrecognized_directories(tmp_path):
    root = tmp_path / "store"
    with storage.PrivateStore(root, create=True):
        pass
    target = root / "blobs" / ("a" * 64 + ".blob")
    target.mkdir(mode=0o700)
    (target / "must-not-read").write_bytes(b"inert")
    with error_code("store_unsafe"):
        with storage.PrivateStore(root):
            pass


@pytest.mark.parametrize("location", ["lock", "object"])
def test_fifo_entries_fail_without_blocking(tmp_path, location):
    root = tmp_path / "store"
    with storage.PrivateStore(root, create=True):
        pass
    target = root / ".lock" if location == "lock" else root / "blobs" / ("a" * 64 + ".blob")
    if target.exists():
        target.unlink()
    os.mkfifo(target, mode=0o600)
    with error_code("store_unsafe"):
        with storage.PrivateStore(root):
            pass


@pytest.mark.parametrize("bound", ["size", "count"])
def test_preexisting_over_limit_store_is_not_opened(tmp_path, monkeypatch, bound):
    root = tmp_path / "store"
    with storage.PrivateStore(root, create=True) as store:
        store.put("blobs", b"inert")
    monkeypatch.setattr(storage, "MAX_STORE_BYTES" if bound == "size" else "MAX_STORE_ENTRIES", 0)
    with error_code("store_limit"):
        with storage.PrivateStore(root):
            pass


@pytest.mark.parametrize("location", ["root", "ancestor", "kind", "lock"])
def test_held_store_refuses_path_replacement(tmp_path, location):
    parent = tmp_path / "parent"
    parent.mkdir(mode=0o700)
    root = parent / "store"
    with storage.PrivateStore(root, create=True) as store:
        target = {"root": root, "ancestor": parent, "kind": root / "blobs",
                  "lock": root / ".lock"}[location]
        saved = tmp_path / "saved"
        target.rename(saved)
        if location == "lock":
            private_file(target, b"")
        else:
            target.mkdir(mode=0o700)
        with error_code("store_changed"):
            store.put("blobs", b"inert")


def test_concurrent_context_fails_immediately_and_lock_releases(tmp_path):
    root = tmp_path / "store"
    with storage.PrivateStore(root, create=True) as first:
        with error_code("store_busy"):
            with storage.PrivateStore(root, create=True):
                pass
        digest = first.put("blobs", b"inert")
    with storage.PrivateStore(root) as later:
        assert later.get("blobs", digest) == b"inert"


def test_closed_or_unentered_store_cannot_read_or_write(tmp_path):
    selected = storage.PrivateStore(tmp_path / "store", create=True)
    for entered in (False, True):
        if entered:
            with selected:
                pass
        with error_code("store_closed"):
            selected.put("blobs", b"inert")
        with error_code("store_closed"):
            selected.get("blobs", "a" * 64)


def test_interruption_before_publication_removes_only_own_temporary(tmp_path, monkeypatch):
    root = tmp_path / "store"
    with storage.PrivateStore(root, create=True) as store:
        complete = store.put("blobs", b"complete")
        def interrupted(*args, **kwargs):
            raise KeyboardInterrupt()
        monkeypatch.setattr(storage.os, "link", interrupted)
        with pytest.raises(KeyboardInterrupt):
            store.put("blobs", b"interrupted")
        assert store.get("blobs", complete) == b"complete"
        assert [item.name for item in (root / "blobs").iterdir()] == [complete + ".blob"]


def test_interruption_after_publication_preserves_complete_orphan(tmp_path, monkeypatch):
    root = tmp_path / "store"
    payload = b"complete orphan"
    digest = hashlib.sha256(payload).hexdigest()
    with storage.PrivateStore(root, create=True) as store:
        original_fsync = storage.os.fsync
        def interrupted(descriptor):
            if descriptor == store._dirs["blobs"]:
                raise OSError("private failure detail")
            return original_fsync(descriptor)
        monkeypatch.setattr(storage.os, "fsync", interrupted)
        with error_code("store_io") as caught:
            store.put("blobs", payload)
        assert "private" not in str(caught.value)
        monkeypatch.setattr(storage.os, "fsync", original_fsync)
        assert store.get("blobs", digest) == payload
    with storage.PrivateStore(root) as store:
        assert store.put("blobs", payload) == digest


def test_reused_object_is_synced_before_success(tmp_path, monkeypatch):
    root = tmp_path / "store"
    with storage.PrivateStore(root, create=True) as store:
        digest = store.put("blobs", b"inert")
        original_fsync = storage.os.fsync
        synced = []
        def record_sync(descriptor):
            synced.append(os.fstat(descriptor).st_ino)
            return original_fsync(descriptor)
        monkeypatch.setattr(storage.os, "fsync", record_sync)
        assert store.put("blobs", b"inert") == digest
        assert (root / "blobs" / (digest + ".blob")).stat().st_ino in synced
        assert (root / "blobs").stat().st_ino in synced


def test_replaced_temporary_is_never_deleted(tmp_path, monkeypatch):
    root = tmp_path / "store"
    with storage.PrivateStore(root, create=True) as store:
        def replace_temporary(source, destination, **kwargs):
            target = root / "blobs" / source
            target.rename(tmp_path / "original-temporary")
            private_file(target, b"foreign replacement")
            raise OSError("injected interruption")
        monkeypatch.setattr(storage.os, "link", replace_temporary)
        with error_code("store_changed"):
            store.put("blobs", b"inert")
        entries = list((root / "blobs").iterdir())
        assert len(entries) == 1
        assert entries[0].read_bytes() == b"foreign replacement"
        assert (tmp_path / "original-temporary").read_bytes() == b"inert"


def test_publish_never_overwrites_racing_destination(tmp_path, monkeypatch):
    root = tmp_path / "store"
    with storage.PrivateStore(root, create=True) as store:
        original_link = storage.os.link
        def race(source, destination, **kwargs):
            private_file(root / "blobs" / destination, b"foreign destination")
            return original_link(source, destination, **kwargs)
        monkeypatch.setattr(storage.os, "link", race)
        with error_code("store_corrupt"):
            store.put("blobs", b"inert")
        entries = list((root / "blobs").iterdir())
        assert len(entries) == 1
        assert entries[0].read_bytes() == b"foreign destination"


def test_replacement_during_read_is_not_returned_as_stable_evidence(tmp_path, monkeypatch):
    root = tmp_path / "store"
    with storage.PrivateStore(root, create=True) as store:
        digest = store.put("blobs", b"inert")
        target = root / "blobs" / (digest + ".blob")
        original_read = storage.os.read
        replaced = []
        def race(descriptor, count):
            result = original_read(descriptor, count)
            if not replaced:
                replaced.append(True)
                target.rename(tmp_path / "saved")
                private_file(target, b"inert")
            return result
        monkeypatch.setattr(storage.os, "read", race)
        with error_code("store_changed"):
            store.get("blobs", digest)


def test_size_change_during_read_is_not_returned_as_stable_evidence(tmp_path, monkeypatch):
    root = tmp_path / "store"
    with storage.PrivateStore(root, create=True) as store:
        digest = store.put("blobs", b"inert")
        target = root / "blobs" / (digest + ".blob")
        original_read = storage.os.read
        changed = []
        def race(descriptor, count):
            result = original_read(descriptor, count)
            if not changed:
                changed.append(True)
                target.write_bytes(b"changed size")
            return result
        monkeypatch.setattr(storage.os, "read", race)
        with error_code("store_changed"):
            store.get("blobs", digest)


@pytest.mark.parametrize("value", ["../store", "store/../other", "store\nprivate", "//store"])
def test_ambiguous_paths_fail_with_fixed_codes(value):
    with error_code("store_path"):
        with storage.PrivateStore(Path(value), create=True):
            pass


def test_unrecognized_error_codes_cannot_include_private_details():
    assert storage.StoreError("private-path-or-payload").code == "store_error"
    assert str(storage.StoreError("store_busy")) == "store_busy"


@pytest.mark.parametrize("preexisting", [False, True])
def test_inventory_observes_children_added_after_directory_open(tmp_path, monkeypatch, preexisting):
    """Model Btrfs enumeration boundaries independently of the test filesystem."""
    root = tmp_path / "store"
    if preexisting:
        with storage.PrivateStore(root, create=True):
            pass
    original_open, original_scandir = storage.os.open, storage.os.scandir
    snapshots = {}

    def snapshot_open(name, flags, mode=0o777, *, dir_fd=None):
        descriptor = original_open(name, flags, mode, dir_fd=dir_fd)
        if flags & os.O_DIRECTORY and (name == "store" or dir_fd in snapshots):
            with original_scandir(descriptor) as entries:
                snapshots[descriptor] = {entry.name for entry in entries}
        return descriptor

    @contextmanager
    def snapshot_scandir(descriptor):
        with original_scandir(descriptor) as entries:
            if isinstance(descriptor, int) and descriptor in snapshots:
                yield (entry for entry in entries if entry.name in snapshots[descriptor])
            else:
                yield entries

    monkeypatch.setattr(storage.os, "open", snapshot_open)
    monkeypatch.setattr(storage.os, "scandir", snapshot_scandir)
    with storage.PrivateStore(root, create=not preexisting) as store:
        first = store.put("blobs", b"first inert object")
        assert store.get("blobs", first) == b"first inert object"
        monkeypatch.setattr(storage, "MAX_STORE_ENTRIES", 1)
        with error_code("store_limit"):
            store.put("blobs", b"second inert object")
        assert len(list((root / "blobs").iterdir())) == 1
        private_file(root / "reviews" / "unexpected", b"inert added entry")
        with pytest.raises(storage.StoreError):
            store.get("blobs", first)
