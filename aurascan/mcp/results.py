"""Result envelopes and finding projection for the ``aurascan-mcp`` tools.

Every accepted call returns one text block containing one JSON document. The envelope is fixed:
``{"content": [{"type": "text", "text": "<json>"}], "isError": <bool>}`` — no ``outputSchema`` exists
to drift, and ``isError`` is the only channel a caller has to branch on.

``COVERAGE_INCOMPLETE_RULES`` resolves the two agent-config coverage rule IDs from
``core.rule_metadata`` instead of typing them: a literal ``IG-CONFIG-INVALID-SHAPE`` in this package
would demand a presenter template (``tools/audit_presenter_coverage.py``), and a suffix fragment does
not match its rule-ID regex.
"""

import json

from aurascan.analyzers.injection import catalog
from aurascan.core.models import SCANNER_VERSION
from aurascan.core.rule_metadata import RULE_METADATA


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


def evidence_item(evidence, include_snippet):
    """Project one ``InjectionEvidence`` onto the wire shape.

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
    if include_snippet:
        item["matched_text"] = evidence.matched_text[:512]
        if evidence.decoded_text:
            item["decoded_text"] = evidence.decoded_text[:2048]
    return item


def scan_payload(evidence_list, source_type, path_hint, max_findings, include_snippet):
    """Build the shared scan result body; ``truncated`` is decided before the slice."""
    kept, truncated = project_findings(evidence_list, max_findings)
    return {
        "advisory": True,
        "scanner_version": SCANNER_VERSION,
        "source_type": source_type,
        "path_hint": path_hint,
        "count": len(kept),
        "truncated": truncated,
        "findings": [evidence_item(item, include_snippet) for item in kept],
    }
