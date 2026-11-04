"""Result envelopes and finding projection for the ``aurascan-mcp`` tools.

Every accepted call returns one text block containing one JSON document. The envelope is fixed:
``{"content": [{"type": "text", "text": "<json>"}], "isError": <bool>}`` — no ``outputSchema`` exists
to drift, and ``isError`` is the only channel a caller has to branch on.

``COVERAGE_INCOMPLETE_RULES`` resolves the two agent-config coverage rule IDs from
``core.rule_metadata`` instead of typing them: a literal ``IG-CONFIG-INVALID-SHAPE`` in this package
would demand a presenter template (``tools/audit_presenter_coverage.py``), and a suffix fragment does
not match its rule-ID regex.

Snippet redaction happens here, on the projection only. ``decoded_text`` is redacted first: when that
finds anything, the encoded ``matched_text`` is replaced whole by ``<redacted:encoded>``, because the
encoded bytes carry no credential pattern themselves and a caller can trivially decode them. Both
halves therefore stay consistent, and the untouched copy is opt-in behind ``include_raw_snippet``.
"""

import json

from aurascan.analyzers.injection import catalog
from aurascan.core.models import SCANNER_VERSION
from aurascan.core.rule_metadata import RULE_METADATA

from . import redaction


MAX_SNIPPET_CHARS = 512
MAX_DECODED_CHARS = 2048

# The operative cut is upstream of this module: the analyzer already capped ``matched_text`` at 120
# and ``decoded_text`` at 1024, so the 512/2048 slices below are inert headroom. The two values are
# mirrored rather than imported because the import allowlist admits ``aurascan.analyzers.injection``
# only; ``tests/test_mcp_redaction.py`` pins both against ``injection_text``.
ANALYZER_SNIPPET_LIMIT = 120
ANALYZER_DECODED_LIMIT = 1024


def _rule_id(suffix):
    matches = [rule_id for rule_id in RULE_METADATA if rule_id.endswith(suffix)]
    if len(matches) != 1:
        raise LookupError("expected exactly one rule ending %r, got %d" % (suffix, len(matches)))
    return matches[0]


COVERAGE_INCOMPLETE_RULES = frozenset((_rule_id("-INVALID-JSON"), _rule_id("-INVALID-SHAPE")))


def text_result(payload, is_error=False):
    """Wrap one JSON document in the fixed result envelope."""
    text = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=False)
    return {"content": [{"type": "text", "text": text}], "isError": bool(is_error)}


def error_result(code, detail):
    """Wrap a stable tool error. ``code`` is from ``errors.TOOL_ERROR_CODES``."""
    return text_result({"error": {"code": code, "detail": detail}}, is_error=True)


def project_findings(findings, max_findings):
    """Return ``(kept, truncated)``; ``truncated`` is decided on the pre-slice list."""
    truncated = len(findings) > max_findings
    return findings[:max_findings], truncated


def coverage_complete(findings):
    """False when any finding says the document could not be fully inspected."""
    return not any(item.rule_id in COVERAGE_INCOMPLETE_RULES for item in findings)


def _fit(text, limit, notes):
    """Slice one emitted half, labelling a marker the slice cut in half."""
    if len(text) > limit:
        text = text[:limit]
    if text.rfind("<redacted:") > text.rfind(">"):
        notes.append(redaction.NOTE_TRUNCATED_TOKEN)
    return text


def _span_was_cut(evidence):
    """True when the analyzer's own bound cut a half, so a decode can recover more than is shown."""
    return (
        len(evidence.matched_text or "") >= ANALYZER_SNIPPET_LIMIT
        or len(evidence.decoded_text or "") >= ANALYZER_DECODED_LIMIT
    )


def _plain(text):
    """Redact and slice one plain half; returns ``(text, classes, notes)``."""
    redacted, classes, notes = redaction.redact(text or "")
    notes = list(notes)
    return _fit(redacted, MAX_SNIPPET_CHARS, notes), classes, notes


def evidence_item(evidence, include_snippet, include_raw=False):
    """Project one ``InjectionEvidence`` onto the wire shape as ``(item, applied, incomplete)``.

    Raw text is opt-in: a matched snippet may carry a token, so it is only emitted when the caller
    asked. Both snippets are bounded, and ``decoded_text`` only accompanies an encoded match.
    """
    item = {
        "class_id": evidence.class_id,
        "detector_id": evidence.detector_id,
        "rule_id": catalog.rule_id_for(evidence.detector_id),
        "severity": evidence.severity,
        "confidence": evidence.confidence,
        "line": evidence.line,
        "description": evidence.description,
        "path": evidence.path,
    }
    if not include_snippet:
        return item, False, False

    notes = []
    classes = []
    matched_raw = evidence.matched_text or ""
    decoded_raw = evidence.decoded_text or ""

    decoded_classes = []
    if decoded_raw:
        decoded, decoded_classes, decoded_notes = redaction.redact(decoded_raw)
        notes.extend(decoded_notes)
    else:
        decoded = ""

    if decoded_classes:
        # The encoded half carries no pattern of its own, so the whole blob is replaced: the emitted
        # pair cannot then disagree with what a decode recovers.
        item["matched_text"] = redaction.ENCODED_TEXT
        classes.extend(decoded_classes)
        notes.append(redaction.ENCODED_SPAN_NOTE)
        if _span_was_cut(evidence):
            notes.append(redaction.NOTE_DECODED_WIDER)
        if include_raw:
            item["matched_text_raw"] = matched_raw[:MAX_SNIPPET_CHARS]
    else:
        item["matched_text"], plain_classes, plain_notes = _plain(matched_raw)
        classes.extend(plain_classes)
        notes.extend(plain_notes)
        if include_raw:
            item["matched_text_raw"] = matched_raw[:MAX_SNIPPET_CHARS]

    if decoded_raw:
        item["decoded_text"] = _fit(decoded, MAX_DECODED_CHARS, notes)
        if include_raw:
            item["decoded_text_raw"] = decoded_raw[:MAX_DECODED_CHARS]

    classes = sorted(set(classes))
    notes = sorted(set(notes))
    item["redaction_applied"] = bool(classes)
    item["redaction_classes"] = classes
    item["redaction_notes"] = notes
    item["redaction_incomplete"] = bool(notes)
    return item, bool(classes), bool(notes)


def scan_payload(
    evidence_list, source_type, path_hint, max_findings, include_snippet, include_raw=False
):
    """Build the shared scan result body; ``truncated`` is decided before the slice."""
    kept, truncated = project_findings(evidence_list, max_findings)
    items = []
    with_redactions = 0
    incomplete = 0
    for evidence in kept:
        item, applied, is_incomplete = evidence_item(evidence, include_snippet, include_raw)
        items.append(item)
        with_redactions += int(applied)
        incomplete += int(is_incomplete)
    return {
        "advisory": True,
        "scanner_version": SCANNER_VERSION,
        "source_type": source_type,
        "path_hint": path_hint,
        "count": len(items),
        "truncated": truncated,
        "snippet_redaction": {
            "version": redaction.REDACTION_VERSION,
            "mode": "raw" if include_raw else "default",
            "findings_with_redactions": with_redactions,
            "findings_incomplete": incomplete,
        },
        "snippet_policy": redaction.SNIPPET_POLICY,
        "findings": items,
    }
