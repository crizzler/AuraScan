"""Evidence bundle: canonical hashing, construction and validation.

A bundle pins what a caller already holds: the exact payload returned to them and a digest of the scan
input, both under one canonical SHA-256. It is a consistency device, not a signature — anyone can
recompute every field — so a consumer must repeat that caveat instead of saying "verified".

Canonicalisation is fixed and single: ``json.dumps(obj, ensure_ascii=True, sort_keys=True,
separators=(",", ":"))`` encoded UTF-8, standard library only. Text digests encode with
``surrogatepass`` because a lone surrogate is a valid Python string but is not UTF-8 encodable, and a
partial digest is the worst place to discover that. Full 64-character lowercase hex only.

Validation splits in two on purpose. A structurally unusable bundle raises ``bundle_unsupported`` /
``bundle_too_large`` (the caller gets ``isError``); a *usable* bundle whose internals disagree with
each other only collects stable strings, because a wrapped line is evidence, not a transport failure.
"""

import hashlib
import json

from aurascan.analyzers.injection import catalog
from aurascan.core.models import SCANNER_VERSION
from aurascan.core.rule_metadata import RULE_METADATA

from . import redaction, results
from .errors import ToolError

BUNDLE_VERSION = 1
SCAN_TOOLS = ("scan_content", "scan_path")
MAX_BUNDLE_CHARS = 262144

#: ``scan_path`` decorations re-derived from ``arguments``; the bundle payload excludes them so the
#: digest covers only what the caller was actually handed plus what they can recompute.
DECORATIONS = ("requested_path", "resolved_path", "byte_cap")

_SOURCE_TYPES = ("documentation", "fixture", "source", "unknown")
_HEX = frozenset("0123456789abcdef")

_REQUIRED = (
    ("bundle_version", int),
    ("tool", str),
    ("scanner_version", str),
    ("redaction_version", int),
    ("arguments", dict),
    ("max_findings", int),
    ("include_snippet", bool),
    ("include_raw_snippet", bool),
    ("source_sha256", str),
    ("payload_sha256", str),
    ("payload", dict),
    ("bundle_sha256", str),
)


def canonical_bytes(obj):
    """Encode ``obj`` canonically: sorted keys, no whitespace, ASCII-escaped, UTF-8."""
    text = json.dumps(obj, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return text.encode("utf-8")


def canonical_hash(obj):
    """Return the canonical SHA-256 hex digest of one JSON-able object."""
    return hashlib.sha256(canonical_bytes(obj)).hexdigest()


def text_digest(text):
    """Return the SHA-256 hex digest of one scan input string, surrogates included."""
    return hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def without_digest(bundle):
    """Return ``bundle`` minus ``bundle_sha256`` — the exact object its own digest covers."""
    return dict((key, value) for key, value in bundle.items() if key != "bundle_sha256")


def payload_view(payload):
    """Return ``payload`` minus the ``scan_path`` decorations."""
    return dict((key, value) for key, value in payload.items() if key not in DECORATIONS)


def build(tool, arguments, max_findings, include_snippet, include_raw, payload, source_text):
    """Build one bundle over ``payload`` and ``source_text``.

    ``payload`` must be the caller-visible dict; the bundle takes a shallow copy minus the
    ``scan_path`` decorations, so the bundle can live *inside* that same payload without a cycle.
    ``source_text`` is the exact scan input, not the redacted projection.
    """
    bundle = {
        "bundle_version": BUNDLE_VERSION,
        "tool": tool,
        "scanner_version": SCANNER_VERSION,
        "redaction_version": redaction.REDACTION_VERSION,
        "arguments": dict(arguments),
        "max_findings": max_findings,
        "include_snippet": bool(include_snippet),
        "include_raw_snippet": bool(include_raw),
        "source_sha256": text_digest(source_text),
        "payload_sha256": canonical_hash(payload_view(payload)),
        "payload": payload_view(payload),
    }
    bundle["bundle_sha256"] = canonical_hash(bundle)
    return bundle


def _unsupported(detail):
    return ToolError("bundle_unsupported", "bundle: %s" % (detail,))


def _is_digest(value):
    return isinstance(value, str) and len(value) == 64 and set(value) <= _HEX


def _plain_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def validate(bundle):
    """Check ``bundle`` and return its stable ``mismatches`` list.

    Raises ``bundle_unsupported`` / ``bundle_too_large`` (``isError``) when the bundle cannot be
    re-derived at all; internal disagreement is only reported as a mismatch.
    """
    if not isinstance(bundle, dict):
        raise _unsupported("must be an object")
    try:
        size = len(json.dumps(bundle, ensure_ascii=True, separators=(",", ":")))
    except (TypeError, ValueError):
        raise _unsupported("is not JSON-serialisable")
    if size > MAX_BUNDLE_CHARS:
        raise ToolError("bundle_too_large", "bundle: exceeds %d characters" % (MAX_BUNDLE_CHARS,))

    for key, expected in _REQUIRED:
        if key not in bundle:
            raise _unsupported("%s is required" % (key,))
        value = bundle[key]
        if expected is bool:
            if not isinstance(value, bool):
                raise _unsupported("%s must be a boolean" % (key,))
        elif expected is int:
            if not _plain_int(value):
                raise _unsupported("%s must be an integer" % (key,))
        elif not isinstance(value, expected):
            raise _unsupported("%s must be a %s" % (key, expected.__name__))

    if bundle["bundle_version"] != BUNDLE_VERSION:
        raise _unsupported("bundle_version must be %d" % (BUNDLE_VERSION,))
    if not 1 <= bundle["max_findings"] <= 32:
        raise _unsupported("max_findings must be between 1 and 32")
    if bundle["tool"] not in SCAN_TOOLS:
        raise _unsupported("tool must be one of %s" % (", ".join(SCAN_TOOLS),))
    for key in ("source_sha256", "payload_sha256", "bundle_sha256"):
        if not _is_digest(bundle[key]):
            raise _unsupported("%s must be 64 lowercase hex characters" % (key,))

    arguments = bundle["arguments"]
    payload = bundle["payload"]
    if bundle["tool"] == "scan_path":
        path = arguments.get("path")
        if not isinstance(path, str) or not path:
            raise _unsupported("arguments.path must be a non-empty string")
    else:
        hint = arguments.get("path_hint", "")
        if not isinstance(hint, str):
            raise _unsupported("arguments.path_hint must be a string")
        source_type = arguments.get("source_type", "unknown")
        if source_type not in _SOURCE_TYPES:
            raise _unsupported("arguments.source_type must be one of %s" % (", ".join(_SOURCE_TYPES),))

    if payload.get("advisory") is not True:
        raise _unsupported("payload.advisory must be true")
    if not isinstance(payload.get("findings"), list):
        raise _unsupported("payload.findings must be an array")
    if not isinstance(payload.get("truncated"), bool):
        raise _unsupported("payload.truncated must be a boolean")
    if not _plain_int(payload.get("count")):
        raise _unsupported("payload.count must be an integer")

    return _payload_mismatches(bundle)


def rule_is_known(item):
    """True when a finding's ``rule_id`` is a catalog rule or the one its detector derives.

    Injection rule IDs are derived (``override.literal.x`` -> ``INJ-OVERRIDE-LITERAL-X``) and are not
    listed in ``core.rule_metadata``, so the catalog mapping is the second half of the check.
    """
    rule_id = item.get("rule_id")
    if rule_id in RULE_METADATA:
        return True
    detector_id = item.get("detector_id")
    return isinstance(detector_id, str) and rule_id == catalog.rule_id_for(detector_id)


def _payload_mismatches(bundle):
    """Return the stable mismatch strings for violated payload invariants."""
    mismatches = []
    payload = bundle["payload"]
    findings = payload["findings"]

    if payload["count"] != len(findings):
        mismatches.append("count_mismatch")
    if payload["truncated"] and payload["count"] != bundle["max_findings"]:
        mismatches.append("truncated_inconsistent")

    previous = 0
    for item in findings:
        if not isinstance(item, dict):
            raise _unsupported("payload.findings[] must be objects")
        if not rule_is_known(item):
            mismatches.append("unknown_rule")
        line = item.get("line")
        if isinstance(line, int) and not isinstance(line, bool):
            if line < previous:
                mismatches.append("lines_unordered")
            previous = line
        matched = item.get("matched_text")
        if isinstance(matched, str) and len(matched) > results.MAX_SNIPPET_CHARS:
            mismatches.append("snippet_over_cap")
        decoded = item.get("decoded_text")
        if isinstance(decoded, str) and len(decoded) > results.MAX_DECODED_CHARS:
            mismatches.append("snippet_over_cap")
        applied = item.get("redaction_applied")
        if isinstance(applied, bool):
            observed = "<redacted:" in (matched if isinstance(matched, str) else "")
            if applied != observed:
                mismatches.append("redaction_flag_mismatch")

    return sorted(set(mismatches))
