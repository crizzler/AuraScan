"""Private, bounded, immutable bytes for explicitly requested offline research.

This developer-only store confers no review, execution, or data-use authority.
Descriptor checks detect observed replacement; they are not a same-UID sandbox.
"""

from contextlib import contextmanager
import fcntl
import hashlib
import os
from pathlib import Path
import re
import secrets
import stat


MAX_BLOB_BYTES = 256 * 1024
MAX_OBJECT_BYTES = 1024 * 1024
MAX_STORE_ENTRIES = 4096
MAX_STORE_BYTES = 256 * 1024 * 1024
KINDS = frozenset(("blobs", "captures", "manifests", "reviews"))
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_CODES = frozenset((
    "store_error", "store_path", "store_unsafe", "store_changed", "store_busy",
    "store_closed", "store_kind", "store_digest", "store_payload", "store_limit",
    "store_missing", "store_corrupt", "store_layout", "store_incomplete", "store_io",
))


class StoreError(Exception):
    """A fixed diagnostic code, never a path, payload, or operating-system error."""

    def __init__(self, code):
        self.code = code if isinstance(code, str) and code in _CODES else "store_error"
        super().__init__(self.code)


def _identity(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid


def _snapshot(info):
    return _identity(info) + (info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


class PrivateStore:
    """Hold one nonblocking exclusive lock until context exit; never collect data."""

    def __init__(self, root: Path, create=False):
        self.root = root
        self.create = create
        self._uid = os.getuid()
        self._fds = []
        self._chain = []
        self._dirs = {}
        self._lock = None
        self._root = None
        self._active = False

    def _directory(self, info, private=False):
        mode = stat.S_IMODE(info.st_mode)
        if not stat.S_ISDIR(info.st_mode):
            raise StoreError("store_unsafe")
        if private:
            safe = info.st_uid == self._uid and mode == 0o700
        else:
            safe = info.st_uid in (0, self._uid) and (
                not mode & 0o022 or (info.st_uid == 0 and bool(mode & stat.S_ISVTX)))
        if not safe:
            raise StoreError("store_unsafe")

    def _regular(self, info):
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != self._uid
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
            raise StoreError("store_unsafe")

    def _open_directory(self, parent, name, private=False):
        descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                             dir_fd=parent)
        self._fds.append(descriptor)
        info = os.fstat(descriptor)
        self._directory(info, private)
        self._chain.append((parent, name, descriptor, _identity(info), private))
        return descriptor

    def __enter__(self):
        if self._fds or self._active:
            raise StoreError("store_closed")
        try:
            value = os.fspath(self.root)
            if (not isinstance(value, str) or not value or len(value.encode("utf-8")) > 4096
                    or any(ord(char) < 32 or ord(char) == 127 for char in value)
                    or ".." in value.split("/") or type(self.create) is not bool):
                raise StoreError("store_path")
            selected = Path(value)
            selected = selected if selected.is_absolute() else Path.cwd() / selected
            parts = selected.parts[1:]
            if not parts or len(parts) > 64 or str(selected).startswith("//"):
                raise StoreError("store_path")
            parent = self._open_directory(None, "/")
            for component in parts[:-1]:
                parent = self._open_directory(parent, component)
            if self.create:
                try:
                    os.mkdir(parts[-1], 0o700, dir_fd=parent)
                    os.fsync(parent)
                except FileExistsError:
                    pass
            self._root = self._open_directory(parent, parts[-1], private=True)
            flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
            if self.create:
                try:
                    self._lock = os.open(".lock", flags | os.O_CREAT | os.O_EXCL,
                                         0o600, dir_fd=self._root)
                except FileExistsError:
                    self._lock = os.open(".lock", flags, dir_fd=self._root)
            else:
                self._lock = os.open(".lock", flags, dir_fd=self._root)
            self._fds.append(self._lock)
            self._regular(os.fstat(self._lock))
            try:
                fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise StoreError("store_busy") from None
            self._active = True
            self._check()
            for kind in sorted(KINDS):
                if self.create:
                    try:
                        os.mkdir(kind, 0o700, dir_fd=self._root)
                    except FileExistsError:
                        pass
                self._dirs[kind] = self._open_directory(self._root, kind, private=True)
            if self.create:
                os.fsync(self._lock)
                os.fsync(self._root)
            self._inventory()
            return self
        except BaseException as error:
            self._close()
            if isinstance(error, (OSError, ValueError, TypeError, UnicodeError)):
                raise StoreError("store_io") from None
            raise

    def _close(self):
        self._active = False
        for descriptor in reversed(self._fds):
            try:
                os.close(descriptor)
            except OSError:
                pass
        self._fds.clear()
        self._chain.clear()
        self._dirs.clear()
        self._root = self._lock = None

    def __exit__(self, *_):
        self._close()

    def _check(self):
        if not self._active:
            raise StoreError("store_closed")
        for parent, name, descriptor, expected, private in self._chain:
            held = os.fstat(descriptor)
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            self._directory(held, private)
            if _identity(held) != expected or _identity(named) != expected:
                raise StoreError("store_changed")
        held = os.fstat(self._lock)
        self._regular(held)
        if held.st_size or _snapshot(held) != _snapshot(os.stat(
                ".lock", dir_fd=self._root, follow_symlinks=False)):
            raise StoreError("store_changed")

    @staticmethod
    def _name(kind, digest):
        if not isinstance(kind, str) or kind not in KINDS:
            raise StoreError("store_kind")
        if not isinstance(digest, str) or _DIGEST.fullmatch(digest) is None:
            raise StoreError("store_digest")
        return digest + (".blob" if kind == "blobs" else ".json")

    @contextmanager
    def _entries(self, descriptor):
        # Btrfs can retain an enumeration boundary from directory-open time.
        # Open a new description anchored to the held inode for each inventory;
        # dup(), rewinding, or retrying the old description does not establish
        # coverage of children created since that description was opened.
        cursor = os.open(".", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                         dir_fd=descriptor)
        try:
            fresh = os.fstat(cursor)
            self._directory(fresh, private=True)
            if _snapshot(fresh) != _snapshot(os.fstat(descriptor)):
                raise StoreError("store_changed")
            with os.scandir(cursor) as entries:
                yield entries
        finally:
            os.close(cursor)

    def _inventory(self):
        self._check()
        count, size = 0, 0
        root_before = _snapshot(os.fstat(self._root))
        with self._entries(self._root) as entries:
            names = set()
            for entry in entries:
                if len(names) >= 5 or entry.name not in KINDS | {".lock"}:
                    raise StoreError("store_layout")
                names.add(entry.name)
        if names != KINDS | {".lock"}:
            raise StoreError("store_layout")
        for kind, descriptor in self._dirs.items():
            before = _snapshot(os.fstat(descriptor))
            with self._entries(descriptor) as entries:
                for entry in entries:
                    count += 1
                    if count > MAX_STORE_ENTRIES:
                        raise StoreError("store_limit")
                    if entry.name.startswith(".tmp-"):
                        raise StoreError("store_incomplete")
                    suffix = ".blob" if kind == "blobs" else ".json"
                    if (not entry.name.endswith(suffix)
                            or _DIGEST.fullmatch(entry.name[:-len(suffix)]) is None):
                        raise StoreError("store_layout")
                    info = entry.stat(follow_symlinks=False)
                    self._regular(info)
                    limit = MAX_BLOB_BYTES if kind == "blobs" else MAX_OBJECT_BYTES
                    size += info.st_size
                    if info.st_size > limit or size > MAX_STORE_BYTES:
                        raise StoreError("store_limit")
            if before != _snapshot(os.fstat(descriptor)):
                raise StoreError("store_changed")
        if root_before != _snapshot(os.fstat(self._root)):
            raise StoreError("store_changed")
        self._check()
        return count, size

    def _read(self, kind, digest, sync=False):
        name = self._name(kind, digest)
        try:
            descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                                 dir_fd=self._dirs[kind])
        except FileNotFoundError:
            raise StoreError("store_missing") from None
        try:
            before = os.fstat(descriptor)
            self._regular(before)
            limit = MAX_BLOB_BYTES if kind == "blobs" else MAX_OBJECT_BYTES
            if before.st_size > limit:
                raise StoreError("store_limit")
            chunks, size = [], 0
            while size <= limit:
                chunk = os.read(descriptor, min(65536, limit + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
            after = os.fstat(descriptor)
            named = os.stat(name, dir_fd=self._dirs[kind], follow_symlinks=False)
            if (size != before.st_size or _snapshot(before) != _snapshot(after)
                    or _snapshot(after) != _snapshot(named)):
                raise StoreError("store_changed")
            payload = b"".join(chunks)
            if hashlib.sha256(payload).hexdigest() != digest:
                raise StoreError("store_corrupt")
            if sync:
                os.fsync(descriptor)
            self._check()
            return payload
        finally:
            os.close(descriptor)

    def get(self, kind, digest):
        self._name(kind, digest)
        try:
            self._inventory()
            payload = self._read(kind, digest)
            self._inventory()
            return payload
        except OSError:
            raise StoreError("store_io") from None

    def put(self, kind, payload: bytes):
        self._name(kind, "0" * 64)
        if type(payload) is not bytes:
            raise StoreError("store_payload")
        limit = MAX_BLOB_BYTES if kind == "blobs" else MAX_OBJECT_BYTES
        if len(payload) > limit:
            raise StoreError("store_limit")
        digest = hashlib.sha256(payload).hexdigest()
        name = self._name(kind, digest)
        temporary, descriptor = None, None
        try:
            count, size = self._inventory()
            directory = self._dirs[kind]
            try:
                existing = self._read(kind, digest, sync=True)
            except StoreError as error:
                if error.code != "store_missing":
                    raise
            else:
                if existing != payload:
                    raise StoreError("store_corrupt")
                os.fsync(directory)
                self._inventory()
                return digest
            if count + 1 > MAX_STORE_ENTRIES or size + len(payload) > MAX_STORE_BYTES:
                raise StoreError("store_limit")
            temporary = ".tmp-" + secrets.token_hex(16)
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                 | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            self._regular(os.fstat(descriptor))
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:offset + 65536])
                if written <= 0:
                    raise StoreError("store_io")
                offset += written
            os.fsync(descriptor)
            self._check()
            if _snapshot(os.fstat(descriptor)) != _snapshot(os.stat(
                    temporary, dir_fd=directory, follow_symlinks=False)):
                raise StoreError("store_changed")
            try:
                os.link(temporary, name, src_dir_fd=directory, dst_dir_fd=directory,
                        follow_symlinks=False)
                published = True
            except FileExistsError:
                published = False
            self._remove_temporary(directory, temporary, descriptor)
            temporary = None
            os.fsync(directory)
            if published and _identity(os.fstat(descriptor)) != _identity(os.stat(
                    name, dir_fd=directory, follow_symlinks=False)):
                raise StoreError("store_changed")
            if self.get(kind, digest) != payload:
                raise StoreError("store_corrupt")
            return digest
        except OSError:
            raise StoreError("store_io") from None
        finally:
            if descriptor is not None:
                try:
                    if temporary is not None:
                        self._remove_temporary(directory, temporary, descriptor)
                except OSError:
                    raise StoreError("store_io") from None
                finally:
                    try:
                        os.close(descriptor)
                    except OSError:
                        raise StoreError("store_io") from None

    @staticmethod
    def _remove_temporary(directory, name, descriptor):
        held = os.fstat(descriptor)
        named = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if _identity(held) != _identity(named):
            raise StoreError("store_changed")
        os.unlink(name, dir_fd=directory)
