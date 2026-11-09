"""Root containment, regular-file and byte-cap guards.

The guard order is load-bearing: containment is decided on resolved paths, and the object that is
read is bound to the object that passed those checks. ``resolve_regular_file`` captures the file
identity (``st_dev``, ``st_ino``) at check time; ``read_capped`` opens only that captured path with
``O_NOFOLLOW`` and refuses unless the opened descriptor's own ``fstat`` still carries the same type,
identity and size. A path-only recheck cannot make that promise: the final component or any parent
directory can be swapped between resolution and open, so every mismatch is an explicit refusal
(``path_changed``) rather than a fallback read.

``O_NONBLOCK`` is a no-op for a regular file and is what keeps a FIFO swapped in between the
pre-check and the open from blocking inside ``open`` forever. A file that grows between ``fstat`` and
``read`` is caught by the ``cap + 1`` read, and invalid UTF-8 decodes with ``errors="replace"``
instead of raising.

Content is not bound: a same-inode in-place rewrite after the identity check can still change the
bytes that are read. The guard protects object identity and root containment, not file immutability.
"""

import collections
import errno
import os
import stat

from .errors import ToolError

MAX_FILE_BYTES = 262144

#: A path that passed containment/type/size checks plus the identity it denoted at that moment.
ResolvedFile = collections.namedtuple("ResolvedFile", ("path", "st_dev", "st_ino"))


def _contains(resolved_root, candidate):
    if candidate == resolved_root:
        return True
    return candidate.startswith(resolved_root + os.sep)


def _is_filesystem_root(resolved_root):
    return resolved_root.rstrip(os.sep) == ""


def resolve_regular_file(roots, raw):
    """Resolve ``raw`` inside one configured root and return its :class:`ResolvedFile` identity.

    Rejections: ``invalid_arguments`` (type/empty/NUL), ``invalid_root`` (a configured root resolves
    to ``/``), ``path_outside_root`` (``..``, an absolute path outside every root, a symlink escaping
    a root), ``path_not_found``, ``path_not_regular_file`` (directory, FIFO, socket, device) and
    ``path_unreadable`` for an unreadable candidate.
    """
    if not isinstance(raw, str) or not raw:
        raise ToolError("invalid_arguments", "path: must be a non-empty string")
    if "\x00" in raw:
        raise ToolError("invalid_arguments", "path: must not contain a NUL byte")

    chosen = None
    for root in roots:
        normalized_root = str(root).strip()
        resolved_root = os.path.realpath(normalized_root)
        if _is_filesystem_root(resolved_root):
            raise ToolError("invalid_root", "roots: a configured root resolves to the filesystem root")
        candidate = os.path.realpath(raw if os.path.isabs(raw) else os.path.join(normalized_root, raw))
        if _contains(resolved_root, candidate):
            chosen = candidate
            break
    if chosen is None:
        raise ToolError("path_outside_root", "path: resolves outside the configured roots")

    try:
        info = os.stat(chosen)
    except FileNotFoundError:
        raise ToolError("path_not_found", "path: does not exist")
    except OSError as exc:
        raise ToolError("path_unreadable", "path: %s" % (exc.strerror or "unreadable",))
    if not stat.S_ISREG(info.st_mode):
        raise ToolError("path_not_regular_file", "path: is not a regular file")
    if info.st_size > MAX_FILE_BYTES:
        raise ToolError("path_too_large", "path: exceeds %d bytes" % (MAX_FILE_BYTES,))
    return ResolvedFile(chosen, info.st_dev, info.st_ino)


def read_capped(resolved):
    """Open the captured file identity and read at most ``MAX_FILE_BYTES + 1`` bytes.

    ``resolved`` must be a :class:`ResolvedFile` returned by ``resolve_regular_file``; a bare path
    string raises ``TypeError`` because it carries no identity to bind the open to. The open uses
    ``O_NOFOLLOW`` and the descriptor is refused unless its type, ``(st_dev, st_ino)`` and size still
    match what was checked, so a symlink swap, a rename swap or a directory-component swap raises
    ``path_changed`` instead of reading a different object.
    """
    if not isinstance(resolved, ResolvedFile):
        raise TypeError("read_capped requires a ResolvedFile from resolve_regular_file")
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise ToolError("path_unreadable", "path: cannot refuse a symbolic-link swap on this platform")
    try:
        fd = os.open(resolved.path, os.O_RDONLY | os.O_NONBLOCK | no_follow)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ToolError("path_changed", "path: became a symbolic link between resolution and open")
        if exc.errno == errno.ENOENT:
            raise ToolError("path_changed", "path: disappeared between resolution and open")
        raise ToolError("path_unreadable", "path: %s" % (exc.strerror or "could not be opened",))
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ToolError("path_not_regular_file", "path: is not a regular file")
        if (info.st_dev, info.st_ino) != (resolved.st_dev, resolved.st_ino):
            raise ToolError("path_changed", "path: no longer denotes the file that was checked")
        if info.st_size > MAX_FILE_BYTES:
            raise ToolError("path_too_large", "path: exceeds %d bytes" % (MAX_FILE_BYTES,))
    except OSError as exc:
        os.close(fd)
        raise ToolError("path_unreadable", "path: %s" % (exc.strerror or "could not be opened",))
    except BaseException:
        os.close(fd)
        raise
    try:
        handle = os.fdopen(fd, "rb")
    except OSError:
        # ``fdopen`` does not close the descriptor it was handed.
        os.close(fd)
        raise ToolError("path_unreadable", "path: could not be opened")
    try:
        data = handle.read(MAX_FILE_BYTES + 1)
    finally:
        handle.close()
    if len(data) > MAX_FILE_BYTES:
        raise ToolError("path_too_large", "path: grew past %d bytes while reading" % (MAX_FILE_BYTES,))
    return data.decode("utf-8", errors="replace")


def text_argument(arguments, key, maximum, minimum=0):
    """Return a validated bounded string argument or raise ``invalid_arguments``."""
    value = arguments.get(key, "")
    if not isinstance(value, str):
        raise ToolError("invalid_arguments", "%s: must be a string" % (key,))
    if len(value) > maximum:
        raise ToolError("invalid_arguments", "%s: exceeds %d characters" % (key, maximum))
    if len(value) < minimum:
        raise ToolError("invalid_arguments", "%s: must not be empty" % (key,))
    return value
