"""Root containment, regular-file and byte-cap guards.

The guard order is load-bearing: containment is decided on resolved paths, and every rejection that
matters is re-decided on the *opened descriptor* rather than on a path that may already have changed.

``O_NONBLOCK`` is a no-op for a regular file and is what keeps a FIFO swapped in between the
pre-check and the open from blocking inside ``open`` forever. A file that grows between ``fstat`` and
``read`` is caught by the ``cap + 1`` read, and invalid UTF-8 decodes with ``errors="replace"``
instead of raising.
"""

import os
import stat

from .errors import ToolError

MAX_FILE_BYTES = 262144


def _contains(resolved_root, candidate):
    if candidate == resolved_root:
        return True
    return candidate.startswith(resolved_root + os.sep)


def resolve_regular_file(roots, raw):
    """Resolve ``raw`` inside one configured root and return the resolved path.

    Rejections: ``invalid_arguments`` (type/empty/NUL), ``path_outside_root`` (``..``, an absolute
    path outside every root, a symlink escaping a root), ``path_not_found``, ``path_not_regular_file``
    (directory, FIFO, socket, device) and ``path_unreadable`` for an unreadable candidate.
    """
    if not isinstance(raw, str) or not raw:
        raise ToolError("invalid_arguments", "path: must be a non-empty string")
    if "\x00" in raw:
        raise ToolError("invalid_arguments", "path: must not contain a NUL byte")

    chosen = None
    for root in roots:
        resolved_root = os.path.realpath(root)
        candidate = os.path.realpath(raw if os.path.isabs(raw) else os.path.join(root, raw))
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
    return chosen


def read_capped(resolved):
    """Open, re-validate on the descriptor and read at most ``MAX_FILE_BYTES + 1`` bytes."""
    try:
        fd = os.open(resolved, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    except OSError as exc:
        raise ToolError("path_unreadable", "path: %s" % (exc.strerror or "could not be opened",))
    try:
        handle = os.fdopen(fd, "rb")
    except OSError:
        # ``fdopen`` does not close the descriptor it was handed.
        os.close(fd)
        raise ToolError("path_unreadable", "path: could not be opened")
    try:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ToolError("path_not_regular_file", "path: is not a regular file")
        if info.st_size > MAX_FILE_BYTES:
            raise ToolError("path_too_large", "path: exceeds %d bytes" % (MAX_FILE_BYTES,))
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
