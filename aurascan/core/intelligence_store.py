"""Protected, transactional runtime intelligence activation and offline reads.

The public entry points have fixed trust and destinations. Alternate roots,
owners, clocks and verifiers are internal test seams, never CLI/environment
configuration. Root compromise is outside this filesystem trust boundary.
"""

import fcntl
import hashlib
import os
import re
import stat
import time
from contextlib import contextmanager
from pathlib import Path

from aurascan.core.intelligence import (
    IntelligenceError, IntelligenceSnapshot, MANIFEST_FILENAME, SIGNATURE_FILENAME,
    PAYLOAD_FILENAME, MAX_MANIFEST_BYTES, MAX_SIGNATURE_BYTES, MAX_PAYLOAD_BYTES,
    MAX_CLOCK_SKEW, SCHEMA_VERSION, _time, bundled_snapshot, canonical_json,
    format_time, snapshot_from_payload, strict_json, utc_now, validate_manifest,
    validate_payload, validate_transition,
)
from aurascan.core.intelligence_crypto import PinnedKey, PRODUCTION_KEYS, assert_production_trust_configured, verify_detached


SYSTEM_ROOT = Path("/var/lib/aurascan/intelligence")
IMPORT_ROOT = Path("/var/lib/aurascan-intelligence-import")
_STATE = "active.json"
_LOCK = "activation.lock"
_GENERATION = re.compile(r"[0-9a-f]{64}\Z")
_FILES = {MANIFEST_FILENAME: MAX_MANIFEST_BYTES, SIGNATURE_FILENAME: MAX_SIGNATURE_BYTES, PAYLOAD_FILENAME: MAX_PAYLOAD_BYTES}
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


def _identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid, metadata.st_gid, metadata.st_nlink)


def _file_identity(metadata):
    return _identity(metadata) + (metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)


def _dir_identity(metadata):
    # Child publication/removal changes directory link counts legitimately.
    return _identity(metadata)[:-1]


def _entries(fd, limit=64):
    names = []
    with os.scandir(fd) as entries:
        for entry in entries:
            if len(names) >= limit:
                raise IntelligenceError("intelligence storage exceeds its entry bound")
            names.append(entry.name)
    return names


class _Directory:
    def __init__(self, path, *, owner=None, create=False, strict_parents=False, create_mode=0o755):
        self.path = Path(path)
        if not self.path.is_absolute() or ".." in self.path.parts or str(self.path) != os.path.normpath(str(self.path)):
            raise IntelligenceError("intelligence directory path is not absolute and normalized")
        self.chain = []
        self.fds = []
        self.fd = None
        try:
            parent = os.open("/", _DIRECTORY_FLAGS)
            self.fds.append(parent)
            anchor = os.fstat(parent)
            if strict_parents and (anchor.st_uid != 0 or anchor.st_mode & 0o022):
                raise IntelligenceError("intelligence filesystem root is not protected")
            for index, component in enumerate(self.path.parts[1:], 1):
                try:
                    child = os.open(component, _DIRECTORY_FLAGS, dir_fd=parent)
                except FileNotFoundError:
                    if not create:
                        raise
                    os.mkdir(component, 0o755, dir_fd=parent)
                    child = os.open(component, _DIRECTORY_FLAGS, dir_fd=parent)
                    os.fchmod(child, create_mode if index == len(self.path.parts) - 1 else 0o755)
                    os.fsync(parent)
                metadata = os.fstat(child)
                self.fds.append(child)
                if strict_parents and (metadata.st_uid != 0 or metadata.st_mode & 0o022):
                    raise IntelligenceError("intelligence directory ancestry is not protected")
                self.chain.append((parent, component, _dir_identity(metadata)))
                parent = child
            self.fd = parent
            metadata = os.fstat(self.fd)
            if owner is not None and (metadata.st_uid != owner or metadata.st_mode & 0o022):
                raise IntelligenceError("intelligence directory ownership or permissions are unsafe")
            self.verify()
        except Exception:
            self.close()
            raise

    def verify(self):
        for parent, name, identity in self.chain:
            if _dir_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != identity:
                raise IntelligenceError("intelligence directory was replaced during inspection")

    def close(self):
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()


def _read_file(directory_fd, name, limit, *, owner=None):
    fd = os.open(name, _READ_FLAGS, dir_fd=directory_fd)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= limit:
            raise IntelligenceError("intelligence input is not a bounded regular file")
        if owner is not None and (before.st_uid != owner or before.st_mode & 0o022):
            raise IntelligenceError("intelligence file ownership or permissions are unsafe")
        chunks = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) != before.st_size or _file_identity(os.fstat(fd)) != _file_identity(before) or _file_identity(os.stat(name, dir_fd=directory_fd, follow_symlinks=False)) != _file_identity(before):
            raise IntelligenceError("intelligence file changed during capture")
        return data
    finally:
        os.close(fd)


def capture_bundle(directory):
    """Capture untrusted input as inert bytes; no owner or signature inference."""
    try:
        with _Directory(Path(directory).absolute()) as root:
            result = {name: _read_file(root.fd, name, limit) for name, limit in _FILES.items()}
            root.verify()
            return result
    except IntelligenceError:
        raise
    except OSError as exc:
        raise IntelligenceError("intelligence bundle could not be captured without following links") from exc


def _write_file(directory_fd, name, payload, mode=0o644):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode, dir_fd=directory_fd)
    try:
        os.fchmod(fd, mode)
        offset = 0
        while offset < len(payload):
            written = os.write(fd, payload[offset:])
            if written <= 0:
                raise IntelligenceError("intelligence durable write was incomplete")
            offset += written
        os.fsync(fd)
    finally:
        os.close(fd)


class IntelligenceStore:
    def __init__(self, root=SYSTEM_ROOT, *, expected_uid=0, keys=None, clock=utc_now, verifier=verify_detached):
        self.root = Path(root)
        self.expected_uid = expected_uid
        self.keys = PRODUCTION_KEYS if keys is None else keys
        self.clock = clock
        self.verifier = verifier
        if self.root == SYSTEM_ROOT and expected_uid != 0:
            raise IntelligenceError("system intelligence requires root-owned state")

    def _directory(self, create=False):
        return _Directory(self.root, owner=self.expected_uid, create=create, strict_parents=self.root == SYSTEM_ROOT)

    @contextmanager
    def _lock(self, root):
        fd = os.open(_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, 0o600, dir_fd=root.fd)
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != self.expected_uid or metadata.st_nlink != 1 or metadata.st_mode & 0o077:
                raise IntelligenceError("intelligence activation lock is unsafe")
            deadline = time.monotonic() + 10
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise IntelligenceError("intelligence activation lock timed out")
                    time.sleep(0.02)
            if _identity(os.stat(_LOCK, dir_fd=root.fd, follow_symlinks=False)) != _identity(metadata):
                raise IntelligenceError("intelligence activation lock was replaced")
            root.verify()
            yield
        finally:
            os.close(fd)

    def _state(self, root):
        data = strict_json(_read_file(root.fd, _STATE, MAX_MANIFEST_BYTES, owner=self.expected_uid), MAX_MANIFEST_BYTES)
        expected = {"schema_version", "generation", "sequence", "payload_sha256", "signature_sha256", "signer", "accepted_at"}
        if set(data) != expected or data["schema_version"] != SCHEMA_VERSION:
            raise IntelligenceError("intelligence activation metadata is malformed")
        if any(not isinstance(data[key], str) or not _GENERATION.fullmatch(data[key]) for key in ("generation", "payload_sha256", "signature_sha256")):
            raise IntelligenceError("intelligence activation hashes are malformed")
        if type(data["sequence"]) is not int or not 1 <= data["sequence"] <= 2 ** 53 - 1 or not isinstance(data["signer"], str):
            raise IntelligenceError("intelligence activation sequence or signer is malformed")
        if data["signer"] not in {key.fingerprint for key in self.keys}:
            raise IntelligenceError("activated intelligence signer is no longer packaged trust")
        _time(data["accepted_at"])
        return data

    def _read_generation(self, root, state, now):
        name = state["generation"]
        fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=root.fd)
        try:
            metadata = os.fstat(fd)
            if metadata.st_uid != self.expected_uid or metadata.st_mode & 0o022:
                raise IntelligenceError("intelligence generation is not protected")
            bundle = {name: _read_file(fd, name, limit, owner=self.expected_uid) for name, limit in _FILES.items()}
            if _dir_identity(metadata) != _dir_identity(os.stat(name, dir_fd=root.fd, follow_symlinks=False)):
                raise IntelligenceError("intelligence generation was replaced")
        finally:
            os.close(fd)
        manifest_raw = bundle[MANIFEST_FILENAME]
        if hashlib.sha256(manifest_raw).hexdigest() != state["generation"] or hashlib.sha256(bundle[SIGNATURE_FILENAME]).hexdigest() != state["signature_sha256"]:
            raise IntelligenceError("intelligence activation manifest or signature changed")
        manifest = validate_manifest(manifest_raw, now=now, allow_expired=True)
        payload = bundle[PAYLOAD_FILENAME]
        if manifest["sequence"] != state["sequence"] or manifest["payload_sha256"] != state["payload_sha256"] or hashlib.sha256(payload).hexdigest() != manifest["payload_sha256"] or len(payload) != manifest["payload_size"]:
            raise IntelligenceError("intelligence activation payload binding changed")
        if now + MAX_CLOCK_SKEW < _time(state["accepted_at"]):
            raise IntelligenceError("intelligence clock moved behind the accepted update time")
        status = "stale" if _time(manifest["expires_at"]) <= now else "current"
        return snapshot_from_payload(payload, source="installed", sequence=manifest["sequence"], manifest_digest=state["generation"], status=status, expires_at=manifest["expires_at"], activated_at=state["accepted_at"])

    def load(self):
        baseline = bundled_snapshot()
        try:
            with self._directory() as root:
                try:
                    state = self._state(root)
                except FileNotFoundError:
                    if set(_entries(root.fd)) <= {_LOCK}:
                        return baseline
                    raise IntelligenceError("intelligence activation metadata is missing")
                snapshot = self._read_generation(root, state, self.clock())
                validate_transition(baseline.payload, snapshot.payload)
                # A concurrently committed generation is a different complete
                # snapshot; the opened, validated generation remains this scan's.
                root.verify()
                return snapshot
        except FileNotFoundError:
            # Only a missing store ancestry is an unconfigured installation.
            if not self.root.exists() and not self.root.is_symlink():
                return baseline
            error = "installed intelligence could not be captured"
        except (OSError, IntelligenceError, ValueError):
            error = "installed intelligence is invalid, unsafe, or incomplete"
        return IntelligenceSnapshot(baseline.payload, baseline.digest, source="bundled-fallback", status="unavailable", coverage_error=error)

    def activate(self, directory):
        if os.geteuid() != self.expected_uid:
            raise IntelligenceError("system intelligence activation requires administrative authorization")
        if not self.keys:
            raise IntelligenceError("production intelligence trust is not configured")
        bundle = capture_bundle(directory)
        try:
            with self._directory(create=True) as root, self._lock(root):
                now = self.clock()
                manifest_raw = bundle[MANIFEST_FILENAME]
                manifest = validate_manifest(manifest_raw, now=now)
                payload = bundle[PAYLOAD_FILENAME]
                if len(payload) != manifest["payload_size"] or hashlib.sha256(payload).hexdigest() != manifest["payload_sha256"]:
                    raise IntelligenceError("intelligence payload does not match the signed manifest")
                signer = self.verifier(manifest_raw, bundle[SIGNATURE_FILENAME], self.keys)
                candidate = validate_payload(payload)
                digest = hashlib.sha256(manifest_raw).hexdigest()
                try:
                    previous_state = self._state(root)
                except FileNotFoundError:
                    if not set(_entries(root.fd)) <= {_LOCK}:
                        raise IntelligenceError("intelligence activation metadata is missing; refusing to reset sequence history")
                    previous_state = None
                previous = self._read_generation(root, previous_state, now) if previous_state else bundled_snapshot()
                if previous_state:
                    if manifest["sequence"] < previous_state["sequence"]:
                        raise IntelligenceError("intelligence sequence rollback was rejected")
                    if manifest["sequence"] == previous_state["sequence"]:
                        if digest != previous_state["generation"]:
                            raise IntelligenceError("intelligence sequence has conflicting contents")
                        result = previous.metadata()
                        result["activation"] = "unchanged"
                        return result
                validate_transition(previous.payload, candidate)
                validate_transition(bundled_snapshot().payload, candidate)
                if signer not in {key.fingerprint for key in self.keys}:
                    raise IntelligenceError("intelligence verification did not return a pinned signer")
                previous_name = previous_state["generation"] if previous_state else None
                self._prune(root, {previous_name} - {None})
                os.mkdir(digest, 0o755, dir_fd=root.fd)
                fd = os.open(digest, _DIRECTORY_FLAGS, dir_fd=root.fd)
                try:
                    os.fchmod(fd, 0o755)
                    for name, data in bundle.items():
                        _write_file(fd, name, data)
                    os.fsync(fd)
                finally:
                    os.close(fd)
                os.fsync(root.fd)
                state = {"schema_version": SCHEMA_VERSION, "generation": digest, "sequence": manifest["sequence"],
                         "payload_sha256": manifest["payload_sha256"], "signature_sha256": hashlib.sha256(bundle[SIGNATURE_FILENAME]).hexdigest(),
                         "signer": signer, "accepted_at": format_time(now)}
                temporary = "active.pending"
                try:
                    os.unlink(temporary, dir_fd=root.fd)
                except FileNotFoundError:
                    pass
                _write_file(root.fd, temporary, canonical_json(state))
                root.verify()
                os.replace(temporary, _STATE, src_dir_fd=root.fd, dst_dir_fd=root.fd)
                os.fsync(root.fd)
                result = self._read_generation(root, state, now).metadata()
                result["activation"] = "updated"
                return result
        except IntelligenceError:
            raise
        except (OSError, ValueError) as exc:
            raise IntelligenceError("intelligence activation could not complete its protected transaction") from exc

    def _prune(self, root, keep):
        names = _entries(root.fd)
        for name in names:
            if name in keep or not _GENERATION.fullmatch(name):
                continue
            fd = os.open(name, _DIRECTORY_FLAGS, dir_fd=root.fd)
            try:
                metadata = os.fstat(fd)
                if metadata.st_uid != self.expected_uid or metadata.st_mode & 0o022:
                    raise IntelligenceError("retained intelligence generation is unsafe")
                entries = _entries(fd, 4)
                if not set(entries) <= set(_FILES):
                    raise IntelligenceError("retained intelligence generation has unexpected entries")
                for entry in entries:
                    entry_state = os.stat(entry, dir_fd=fd, follow_symlinks=False)
                    if not stat.S_ISREG(entry_state.st_mode) or entry_state.st_uid != self.expected_uid or entry_state.st_mode & 0o022 or entry_state.st_nlink != 1 or entry_state.st_size > _FILES[entry]:
                        raise IntelligenceError("retained intelligence file is unsafe")
                    os.unlink(entry, dir_fd=fd)
                os.fsync(fd)
            finally:
                os.close(fd)
            os.rmdir(name, dir_fd=root.fd)
        os.fsync(root.fd)


def activate_bundle(directory):
    return IntelligenceStore().activate(directory)


def load_intelligence_snapshot():
    return IntelligenceStore().load()


@contextmanager
def _stage_offline_bundle(directory, *, root=IMPORT_ROOT, expected_uid=0):
    """Hold the import lock until the caller's isolated service has finished."""
    root = Path(root)
    if os.geteuid() != expected_uid or (root == IMPORT_ROOT and expected_uid != 0):
        raise IntelligenceError("system intelligence import requires administrative authorization")
    bundle = capture_bundle(directory)
    try:
        with _Directory(root, owner=expected_uid, create=True, strict_parents=root == IMPORT_ROOT, create_mode=0o700) as inbox:
            if os.fstat(inbox.fd).st_mode & 0o077:
                raise IntelligenceError("intelligence import inbox is not private")
            store = IntelligenceStore(root=root, expected_uid=expected_uid)
            with store._lock(inbox):
                for name, payload in bundle.items():
                    temporary = name + ".pending"
                    try:
                        os.unlink(temporary, dir_fd=inbox.fd)
                    except FileNotFoundError:
                        pass
                    _write_file(inbox.fd, temporary, payload, 0o600)
                    os.replace(temporary, name, src_dir_fd=inbox.fd, dst_dir_fd=inbox.fd)
                os.fsync(inbox.fd)
                inbox.verify()
                yield
                inbox.verify()
    except IntelligenceError:
        raise
    except OSError as exc:
        raise IntelligenceError("intelligence offline import staging was unsafe or incomplete") from exc


def stage_offline_bundle(directory):
    return _stage_offline_bundle(directory)
