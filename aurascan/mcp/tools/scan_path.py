"""``scan_path``: scan one bounded UTF-8 file from inside a configured root."""

from aurascan.analyzers.injection import scanner

from .. import guards, results
from ..errors import ToolError
from ..guards import MAX_FILE_BYTES

MAX_PATH_CHARS = 4096
MAX_FINDINGS_LIMIT = 32
DEFAULT_MAX_FINDINGS = 32


def handle(ctx, arguments):
    raw = arguments.get("path")
    if not isinstance(raw, str) or not raw:
        raise ToolError("invalid_arguments", "path: must be a non-empty string")
    if len(raw) > MAX_PATH_CHARS:
        raise ToolError("invalid_arguments", "path: exceeds %d characters" % (MAX_PATH_CHARS,))
    max_findings = arguments.get("max_findings", DEFAULT_MAX_FINDINGS)
    include_snippet = bool(arguments.get("include_snippet", False))
    include_raw = bool(arguments.get("include_raw_snippet", False))

    resolved = guards.resolve_regular_file(ctx.roots, raw)
    if ctx.cancelled():
        raise ToolError("cancelled", "cancelled before the file was read")
    text = guards.read_capped(resolved)

    source_type = scanner.derive_source_type(raw)
    fetch = max_findings + 1 if max_findings < MAX_FINDINGS_LIMIT else MAX_FINDINGS_LIMIT
    try:
        evidence = scanner.scan_content(
            text,
            source_type=source_type,
            path_hint=raw,
            max_findings=fetch,
        )
    except ValueError as exc:
        raise ToolError("invalid_arguments", str(exc))

    payload = results.scan_payload(
        evidence, source_type, raw, max_findings, include_snippet, include_raw
    )
    payload["requested_path"] = raw
    payload["resolved_path"] = resolved
    payload["byte_cap"] = MAX_FILE_BYTES
    return results.text_result(payload)
