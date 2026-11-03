"""``audit_agent_config``: audit one agent/MCP configuration document as untrusted data."""

from .. import results
from ..errors import ToolError
from ..guards import text_argument

MAX_CONFIG_CHARS = 262144
MAX_PATH_HINT_CHARS = 1024
MAX_FINDINGS = 64
DEFAULT_SURFACE = "cursor-mcp-manifest"


def handle(ctx, arguments):
    config = arguments.get("config")
    if not isinstance(config, str):
        raise ToolError("invalid_arguments", "config: must be a string")
    if not config:
        raise ToolError("invalid_arguments", "config: must not be empty")
    if len(config) > MAX_CONFIG_CHARS:
        raise ToolError(
            "content_too_large", "config: exceeds %d characters" % (MAX_CONFIG_CHARS,)
        )
    surface = arguments.get("surface", DEFAULT_SURFACE)
    path_hint = text_argument(arguments, "path_hint", MAX_PATH_HINT_CHARS)

    # Lazy: starting the server must not pay the whole module import, and a broken
    # ``instruction_guard`` cannot take ``scan_content`` down with it.
    from aurascan.core.instruction_guard import audit_agent_config_text

    try:
        findings = audit_agent_config_text(config, surface)
    except ValueError as exc:
        raise ToolError("invalid_arguments", str(exc))

    kept, truncated = results.project_findings(findings, MAX_FINDINGS)
    payload = {
        "surface": surface,
        "path_hint": path_hint,
        "advisory": True,
        "coverage_complete": results.coverage_complete(findings),
        "count": len(kept),
        "truncated": truncated,
        "findings": [item.to_dict() for item in kept],
    }
    return results.text_result(payload)
