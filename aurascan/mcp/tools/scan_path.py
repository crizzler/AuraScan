"""``scan_path``: scan one bounded UTF-8 file from inside a configured root.

``run`` is the whole production path and returns the bare payload; ``handle`` only validates the
arguments and wraps that payload. ``verify_evidence`` calls ``run`` so a re-derivation cannot drift
from a scan.
"""

from aurascan.analyzers.injection import scanner

from .. import bundle, guards, results
from ..errors import ToolError
from ..guards import MAX_FILE_BYTES

MAX_PATH_CHARS = 4096
MAX_FINDINGS_LIMIT = 32
DEFAULT_MAX_FINDINGS = 32


def _path(arguments):
    raw = arguments.get("path")
    if not isinstance(raw, str) or not raw:
        raise ToolError("invalid_arguments", "path: must be a non-empty string")
    if len(raw) > MAX_PATH_CHARS:
        raise ToolError("invalid_arguments", "path: exceeds %d characters" % (MAX_PATH_CHARS,))
    return raw


def run(
    ctx,
    raw,
    max_findings=DEFAULT_MAX_FINDINGS,
    include_snippet=False,
    include_raw=False,
    emit_bundle=False,
):
    """Read and scan the file at ``raw``, returning the payload."""
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
    if emit_bundle:
        payload["evidence_bundle"] = bundle.build(
            "scan_path",
            {"path": raw},
            max_findings,
            include_snippet,
            include_raw,
            payload,
            text,
        )
    return payload


def handle(ctx, arguments):
    return results.text_result(
        run(
            ctx,
            _path(arguments),
            arguments.get("max_findings", DEFAULT_MAX_FINDINGS),
            bool(arguments.get("include_snippet", False)),
            bool(arguments.get("include_raw_snippet", False)),
            bool(arguments.get("emit_bundle", False)),
        )
    )
