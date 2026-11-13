"""``audit_agent_runtime``: read-only blast-radius facts for one agent surface.

The MCP projection is deliberately narrower than the CLI report: it exposes
aggregate facts and counts only, never the inspected root, file paths, channel
locations, secret paths, or input digests. The server's first configured root is
the audit root; a caller that needs another root starts a dedicated server.
"""

from .. import results
from ..errors import ToolError

SURFACES = ("codex", "claude", "cursor", "mcp")
MAX_SURFACE_CHARS = 16


def handle(ctx, arguments):
    surface = arguments.get("surface")
    if not isinstance(surface, str) or not surface:
        raise ToolError("invalid_arguments", "surface: must be a non-empty string")
    if len(surface) > MAX_SURFACE_CHARS or surface not in SURFACES:
        raise ToolError("invalid_arguments", "surface: is not a supported agent surface")
    roots = tuple(getattr(ctx, "roots", ()) or ())
    if not roots:
        raise ToolError("invalid_arguments", "root: the server has no configured root")
    if ctx.cancelled():
        raise ToolError("cancelled", "cancelled before the audit started")

    # Lazy import keeps server startup and unrelated tools independent of the
    # agent-audit module and its parser dependencies.
    from aurascan.core.agent_runtime_audit import (
        AgentAuditUsageError,
        build_report,
    )

    try:
        report = build_report(roots[0], surface)
    except AgentAuditUsageError:
        raise ToolError("invalid_arguments", "root: is not a readable project directory")
    if ctx.cancelled():
        raise ToolError("cancelled", "cancelled after the audit completed")

    finding_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for finding in report.findings:
        if finding.severity in finding_counts:
            finding_counts[finding.severity] += 1
    payload = {
        "surface": surface,
        "coverage_complete": report.coverage_complete,
        "execution_authority_observed": report.execution_authority,
        "approval_mode": report.approval.normalized,
        "secret_class_count": len(report.secrets),
        "secret_counts": [
            {"class": item.secret_class, "count": item.count}
            for item in report.secrets
        ],
        "host_isolation": "unknown",
        "aggregate": {
            "status": report.aggregate_status,
        },
        "finding_counts": finding_counts,
        "not_verified": list(report.not_verified),
    }
    return results.text_result(payload)
