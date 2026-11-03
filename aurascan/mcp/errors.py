"""Stable error codes for the ``aurascan-mcp`` server.

Two surfaces live here. JSON-RPC envelope codes are produced by the protocol layer and are the
specification's, not ours. ``ToolError`` is the only exception a handler may raise for an expected
runtime failure: it carries a stable code string so a caller can branch without reading prose and
so no traceback ever reaches the wire.
"""

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603

#: Stable codes a handler may raise. They are the whole vocabulary of ``isError`` results.
TOOL_ERROR_CODES = (
    "invalid_arguments",
    "path_outside_root",
    "path_not_found",
    "path_not_regular_file",
    "path_too_large",
    "path_unreadable",
    "content_too_large",
    "timeout",
    "cancelled",
    "internal",
)


class ToolError(Exception):
    """An expected tool failure with a stable, caller-visible code."""

    def __init__(self, code, detail):
        if code not in TOOL_ERROR_CODES:
            raise AssertionError("unknown tool error code %r" % (code,))
        super(ToolError, self).__init__(detail)
        self.code = code
        self.detail = detail


class TimeoutExpired(Exception):
    """Raised by the SIGALRM handler inside a budgeted dispatch."""
