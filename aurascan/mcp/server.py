"""Server identity, handshake and the method surface the protocol dispatches to.

The handshake is the legacy one only, so the client never probes ``server/discover``. Instructions
name the boundary explicitly: the honesty line, the resolved roots, and the fact that nothing here
blocks, quarantines or certifies anything.
"""

from aurascan.core.models import SCANNER_VERSION

from . import registry
from .registry import TOOLS, TOOLS_BY_NAME

SERVER_INFO = {"name": "aurascan", "version": SCANNER_VERSION}

DEFAULT_PROTOCOL_VERSION = "2025-06-18"

_PROTOCOL_RE = None


def _valid_protocol_version(value):
    import re

    global _PROTOCOL_RE
    if _PROTOCOL_RE is None:
        _PROTOCOL_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
    return isinstance(value, str) and bool(_PROTOCOL_RE.match(value))


def build_instructions(roots):
    root_list = "\n".join("  - %s" % (root,) for root in roots)
    return "\n".join((
        "AuraScan is a safety layer for Arch-family package and maintenance workflows. This server "
        "exposes its static injection detector, its agent/MCP configuration audit and its host audit "
        "(offline by default, one opt-in online variant) as tools.",
        "",
        registry.HONESTY_LINE,
        "",
        "Nothing is written, nothing is blocked or quarantined, and no result certifies a package or "
        "a host as safe. Findings are evidence, and an empty result is not proof of integrity. The "
        "offline tools never leave the host; `security_audit_online` fetches the campaign feed once "
        "and executes `pacman`/`arch-audit` under a filtered environment, writing no AuraScan state "
        "while `arch-audit` may keep its own cache.",
        "",
        "scan_path resolves only inside these roots:",
        root_list,
        "",
        "`scan_content` with no source type reproduces the pathless detection table; the quoted "
        "corpus numbers elsewhere are a different, documented measurement. Neither proves what a "
        "detector would do on unreleased text.",
    ))


class Server(object):
    def __init__(self, roots):
        self.roots = tuple(roots)
        self.tools = TOOLS_BY_NAME
        self.tool_table = TOOLS

    def initialize(self, params):
        requested = params.get("protocolVersion") if isinstance(params, dict) else None
        version = requested if _valid_protocol_version(requested) else DEFAULT_PROTOCOL_VERSION
        return {
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": dict(SERVER_INFO),
            "instructions": build_instructions(self.roots),
        }

    def ping(self, params):
        return {}

    def tools_list(self, params):
        return {"tools": [tool.listing() for tool in self.tool_table]}

    def shutdown(self, params):
        self.stopping = True
        return None

    def notify(self, method, params):
        """Accepted notifications. Nothing is enforced; an unopened handshake is tolerated."""
        if method == "notifications/initialized":
            return None
        return None

    @staticmethod
    def validate(tool, arguments):
        return registry.validate(tool.schema, arguments)


def run_server(roots, budgets=None, max_line_bytes=None):
    """Serve on stdin/stdout until EOF, ``exit`` or a signal."""
    from .protocol import MAX_LINE_BYTES, Protocol, guard_stdout

    out = guard_stdout()
    loop = Protocol(
        out,
        Server(roots),
        budgets=budgets,
        max_line_bytes=MAX_LINE_BYTES if max_line_bytes is None else max_line_bytes,
    )
    loop.run()
