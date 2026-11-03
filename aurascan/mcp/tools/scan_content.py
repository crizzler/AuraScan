"""``scan_content``: scan caller-supplied text for prompt-injection signals.

The text is never executed and nothing is fetched or written. The package owns policy: the server
passes ``source_type`` by keyword, defaults it to ``unknown`` (which the package treats like
``source``) and re-ranks nothing.
"""

from aurascan.analyzers.injection import scanner

from .. import results
from ..errors import ToolError
from ..guards import text_argument

MAX_CONTENT_CHARS = 262144
MAX_PATH_HINT_CHARS = 1024
MAX_FINDINGS_LIMIT = 32
DEFAULT_MAX_FINDINGS = 32


def _arguments(arguments):
    content = arguments.get("content")
    if not isinstance(content, str):
        raise ToolError("invalid_arguments", "content: must be a string")
    if len(content) > MAX_CONTENT_CHARS:
        raise ToolError(
            "content_too_large", "content: exceeds %d characters" % (MAX_CONTENT_CHARS,)
        )
    return content


def handle(ctx, arguments):
    content = _arguments(arguments)
    path_hint = text_argument(arguments, "path_hint", MAX_PATH_HINT_CHARS)
    source_type = arguments.get("source_type", "unknown")
    max_findings = arguments.get("max_findings", DEFAULT_MAX_FINDINGS)
    include_snippet = bool(arguments.get("include_snippet", False))

    # One match is over-fetched so ``truncated`` is decidable below the scanner's own cap. At the
    # cap the package limit applies and the flag is always false.
    fetch = max_findings + 1 if max_findings < MAX_FINDINGS_LIMIT else MAX_FINDINGS_LIMIT
    try:
        evidence = scanner.scan_content(
            content,
            source_type=source_type,
            path_hint=path_hint,
            max_findings=fetch,
        )
    except ValueError as exc:
        raise ToolError("invalid_arguments", str(exc))

    resolved_type = source_type
    if resolved_type == "unknown" and path_hint:
        resolved_type = scanner.derive_source_type(path_hint)

    payload = results.scan_payload(
        evidence, resolved_type, path_hint, max_findings, include_snippet
    )
    return results.text_result(payload)
