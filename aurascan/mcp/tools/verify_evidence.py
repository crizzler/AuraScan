"""``verify_evidence``: does an AuraScan bundle still re-derive from its own source?

Three separable questions, and the result never blurs them:

1. **Digest.** The caller's ``bundle_sha256`` is recomputed from the bundle body.
2. **Self.** The bundled payload is re-hashed and compared with the bundled ``payload_sha256``.
3. **Re-derivation.** The *same production ``run()``* re-scans the source and the resulting payload is
   hashed and compared to the bundled payload digest.

Only re-derivation closes B6: a tampered payload whose two digests were recomputed passes (1) and (2)
and still fails (3) with ``rederivation_mismatch``. Re-derivation is the only reason this module
imports the scan tools instead of re-implementing them.

``consistent`` therefore requires all four of ``digest_matches``, ``payload_self_matches``,
``payload_matches`` and — in path mode — ``file_unchanged``. Without a supplied source it degrades to
``unchecked`` (``source_absent``) and never to a pass, and content mode always carries
``content_mode_circular`` because the caller handed over both the bytes and the hash.
"""

import hmac

from .. import bundle as bundle_module
from .. import guards, results
from ..errors import ToolError
from . import scan_content, scan_path

MAX_PATH_CHARS = 4096
MAX_CONTENT_CHARS = 262144

#: Fixed and always present: what this tool does *not* establish, in one word each.
DOES_NOT_VERIFY = (
    "origin",
    "truth",
    "no_tamper",
    "execution",
    "file_identity_beyond_bytes",
    "rule_catalog",
)

VERDICT_LINE = "Internally consistent. Not signed, not proof of correctness, not proof the scan ran."

NOTE_SOURCE_ABSENT = "source_absent"
NOTE_PATH_UNAVAILABLE = "path_unavailable"
NOTE_SOURCE_UNAVAILABLE = "source_unavailable"
NOTE_CONTENT_CIRCULAR = "content_mode_circular"
NOTE_REDERIVATION_FAILED = "rederivation_failed"


def _matches(left, right):
    return hmac.compare_digest(left, right)


def _source(arguments):
    """Return ``(mode, text)`` for the optional source; ``text`` is None while a path is unresolved."""
    has_path = "path" in arguments
    has_content = "content" in arguments
    if has_path and has_content:
        raise ToolError("invalid_arguments", "path and content: at most one may be supplied")
    if has_content:
        content = arguments["content"]
        if not isinstance(content, str):
            raise ToolError("invalid_arguments", "content: must be a string")
        if len(content) > MAX_CONTENT_CHARS:
            raise ToolError(
                "content_too_large", "content: exceeds %d characters" % (MAX_CONTENT_CHARS,)
            )
        return "content", content
    if has_path:
        raw = arguments["path"]
        if not isinstance(raw, str) or not raw:
            raise ToolError("invalid_arguments", "path: must be a non-empty string")
        if len(raw) > MAX_PATH_CHARS:
            raise ToolError("invalid_arguments", "path: exceeds %d characters" % (MAX_PATH_CHARS,))
        return "path", None
    return None, None


def _read_path(ctx, raw):
    """Return the decoded text at ``raw`` or None when the guards refuse it."""
    try:
        return guards.read_capped(guards.resolve_regular_file(ctx.roots, raw))
    except ToolError:
        return None


def _rederive(ctx, bundle, mode, source_text):
    """Re-run the production scan the bundle names; ``(payload, note)``.

    ``note`` is the reason a payload could not be produced, or None on success. A scan that is only
    possible because a source was supplied must not report a source note.
    """
    tool = bundle["tool"]
    arguments = bundle["arguments"]
    if tool == "scan_content":
        if source_text is None:
            return None, NOTE_SOURCE_UNAVAILABLE
        try:
            return scan_content.run(
                source_text,
                arguments.get("source_type", "unknown"),
                arguments.get("path_hint", ""),
                bundle["max_findings"],
                bundle["include_snippet"],
                bundle["include_raw_snippet"],
            ), None
        except ToolError:
            return None, NOTE_REDERIVATION_FAILED
    try:
        return scan_path.run(
            ctx,
            arguments["path"],
            bundle["max_findings"],
            bundle["include_snippet"],
            bundle["include_raw_snippet"],
        ), None
    except ToolError:
        return None, NOTE_PATH_UNAVAILABLE


def _checked(bundle, mismatches):
    findings = bundle["payload"]["findings"]
    return {
        "findings": len(findings),
        "rules_known": sum(1 for item in findings if bundle_module.rule_is_known(item)),
        "offsets_ordered": "lines_unordered" not in mismatches,
    }


def run(ctx, bundle, path=None, content=None):
    """Verify ``bundle`` against the optional source and return the result dict."""
    mismatches = bundle_module.validate(bundle)
    tool = bundle["tool"]

    digest_matches = _matches(
        bundle_module.canonical_hash(bundle_module.without_digest(bundle)), bundle["bundle_sha256"]
    )
    payload_self_matches = _matches(
        bundle_module.canonical_hash(bundle["payload"]), bundle["payload_sha256"]
    )
    if not digest_matches:
        mismatches.append("digest_mismatch")
    if not payload_self_matches:
        mismatches.append("payload_self_mismatch")

    notes = []
    file_unchanged = None
    source_matches = None
    mode = None
    source_text = None
    if content is not None:
        mode, source_text = "content", content
        notes.append(NOTE_CONTENT_CIRCULAR)
    elif path is not None:
        mode = "path"
        source_text = _read_path(ctx, path)
        if source_text is None:
            notes.append(NOTE_PATH_UNAVAILABLE)

    if source_text is not None:
        source_matches = _matches(bundle_module.text_digest(source_text), bundle["source_sha256"])
        if mode == "path":
            file_unchanged = source_matches
        if not source_matches:
            mismatches.append("source_changed")

    rederived = None
    if mode is None or source_text is not None:
        # With no source at all, a ``scan_path`` bundle can still be re-derived from its own path.
        rederived, note = _rederive(ctx, bundle, mode, source_text)
        if note is not None:
            notes.append(note)
    elif mode == "path":
        notes.append(NOTE_PATH_UNAVAILABLE)

    payload_matches = None
    if rederived is not None:
        payload_matches = _matches(
            bundle_module.canonical_hash(bundle_module.payload_view(rederived)),
            bundle["payload_sha256"],
        )
        if not payload_matches:
            mismatches.append("rederivation_mismatch")

    mismatches = sorted(set(mismatches))
    notes = sorted(set(notes))
    if mismatches:
        consistency = "inconsistent"
    elif source_matches is None:
        consistency = "unchecked"
        if mode is None:
            notes = sorted(set(notes) | set((NOTE_SOURCE_ABSENT,)))
    else:
        consistency = "consistent"

    return {
        "advisory": True,
        "bundle_version": bundle_module.BUNDLE_VERSION,
        "bundle_tool": tool,
        "digest_matches": digest_matches,
        "payload_self_matches": payload_self_matches,
        "payload_matches": payload_matches,
        "re_derived": rederived is not None,
        "file_unchanged": file_unchanged,
        "source_matches": source_matches,
        "consistency": consistency,
        "mismatches": mismatches,
        "notes": notes,
        "checked": _checked(bundle, mismatches),
        "does_not_verify": list(DOES_NOT_VERIFY),
        "verdict_line": VERDICT_LINE,
    }


def handle(ctx, arguments):
    bundle = arguments.get("bundle")
    if not isinstance(bundle, dict):
        raise ToolError("bundle_unsupported", "bundle: must be an object")
    mode, text = _source(arguments)
    path = arguments.get("path") if mode == "path" else None
    return results.text_result(run(ctx, bundle, path, text))
