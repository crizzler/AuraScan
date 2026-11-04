"""Best-effort redaction of credential-shaped substrings inside an emitted snippet.

Pure data and pure functions: no file, no clock, no ``socket``, no ``os.environ``. That matters
because snippet bytes are what a bundle re-derivation hashes, so a hostname or ``USER`` read here
would make the bytes depend on the machine. ``core.redaction`` is imported for its three compiled
patterns (``PRIVATE_KEY_RE``, ``URL_USERINFO_RE``, ``AUTHORIZATION_TOKEN_RE``) only;
``redact_incident_text`` is deliberately *not* used, because that wrapper reads the ambient host.

The transform is lossy by construction. Only the span the caller is already being shown is
rewritten: text that matches nothing is returned as-is and may still carry a secret, so a
``redaction_applied: false`` value is not a cleanliness claim.

Ordering is priority-first and single pass (see ``_collect``). Chained ``sub()`` calls would let a
later family re-eat an earlier ``<redacted:class>`` token.
"""

import re

from aurascan.core.redaction import AUTHORIZATION_TOKEN_RE, PRIVATE_KEY_RE, URL_USERINFO_RE


REDACTION_VERSION = 1

# Headroom over the analyzer's own 120/1024 bounds (``analyzers/injection/injection_text.py:21-22``);
# a longer direct call is cut and labelled instead of being scanned unbounded.
MAX_REDACTION_INPUT = 4096
MAX_REDACTIONS = 32

ENCODED_TEXT = "<redacted:encoded>"
ENCODED_SPAN_NOTE = "encoded_span_redacted"

NOTE_INPUT_TRUNCATED = "input_truncated"
NOTE_TOO_MANY = "too_many_matches"
NOTE_TRUNCATED_TOKEN = "truncated_token"
NOTE_UNTERMINATED_KEY = "unterminated_private_key"
NOTE_PARTIAL_TOKEN_EDGE = "partial_token_at_edge"
NOTE_DECODED_WIDER = "decoded_text_wider_than_snippet"

# Closed vocabulary. Nothing outside this tuple can reach ``redaction_classes``.
CLASSES = (
    "assignment",
    "aws",
    "bearer",
    "cookie",
    "encoded",
    "entropy",
    "github",
    "jwt",
    "openai",
    "private-key",
    "url-userinfo",
)

SNIPPET_POLICY = (
    "Snippets are best effort: text that matches no pattern is returned as-is and may still carry a "
    "secret. `redaction_applied: false` means no pattern matched in this snippet, not that the "
    "snippet is secret-free."
)

_MARKER = "<redacted:%s>"

_GITHUB_RE = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}")
_OPENAI_RE = re.compile(r"\bsk-(?:proj-|ant-api\d+-|ant-)?[A-Za-z0-9_-]{20,}")
_AWS_RE = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{0,}")
_COOKIE_RE = re.compile(r"(?i)\b(?:set-)?cookie\s*:\s*[^\r\n]{8,}")
_ASSIGNMENT_RE = re.compile(
    r"(?i)(?<![\w-])([\w-]*(?:password|passwd|passphrase|secret|token|api[_-]?key|apikey"
    r"|authorization|credential|private[_-]?key)[\w-]*)(\s*[:=]\s*)([\"']?)"
    r"(<redacted:[a-z-]+>|[^\s\"',;]+)\3"
)
_ENTROPY_RE = re.compile(r"[A-Za-z0-9+/=_-]{32,}")

# An existing marker is accepted as its own span so a second pass re-reports the same classes and
# leaves the text byte-identical (idempotence of the whole tuple, not just the text).
_MARKER_RE = re.compile(r"<(?:redacted:[a-z-]+|redacted-user|redacted-password)>")

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_ALLCAPS_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
_SNAKE_RE = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)+$")
_HEX_RE = re.compile(r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}|[0-9a-fA-F]{128})$")

_TOKEN_RUN_RE = re.compile(r"[A-Za-z0-9+/=_-]+")
_TAIL_RUN_RE = re.compile(r"[A-Za-z0-9+/=_-]+$")
_FAMILY_PREFIX_RE = re.compile(r"^(?:gh[pousr]_|sk-|AKIA|ASIA|eyJ)")

# (priority, class, compiled pattern, replacement template). Templated families keep readable
# framing; everything else is replaced whole by its marker.
_FAMILIES = (
    (0, "private-key", PRIVATE_KEY_RE, None),
    (1, "url-userinfo", URL_USERINFO_RE, r"\1<redacted-user>:<redacted-password>@"),
    (2, "github", _GITHUB_RE, None),
    (3, "openai", _OPENAI_RE, None),
    (4, "aws", _AWS_RE, None),
    (5, "bearer", _BEARER_RE, None),
    (6, "jwt", _JWT_RE, None),
    (7, "cookie", _COOKIE_RE, None),
    (8, "assignment", _ASSIGNMENT_RE, None),
)

_ENTROPY_PRIORITY = 9


def _entropy_ok(token):
    """False for the measured false positives of a bare "32+ mixed characters" rule."""
    if len(token) < 32:
        return False
    if not any(character.isdigit() for character in token):
        return False
    if _UUID_RE.match(token):
        return False
    if _ALLCAPS_RE.match(token):
        return False
    if _SNAKE_RE.match(token):
        return False
    if _HEX_RE.match(token):
        return False
    return True


def _looks_partial(run):
    """True when ``run`` looks like the visible end of a token that continues past the span."""
    if len(run) < 4:
        return False
    return any(character.isdigit() for character in run) or bool(_FAMILY_PREFIX_RE.match(run))


def _edge_notes(text):
    """Label a token straddling the span. Head and tail carry the same note on purpose."""
    notes = []
    head = _TOKEN_RUN_RE.match(text)
    tail = _TAIL_RUN_RE.search(text)
    if (head and _looks_partial(head.group(0))) or (tail and _looks_partial(tail.group(0))):
        notes.append(NOTE_PARTIAL_TOKEN_EDGE)
    return notes


def _assignment(text):
    prefix, separator, quote, value = text.groups()
    if value.startswith("<redacted:"):
        # Idempotence: an already-redacted value keeps its original label.
        return text.group(0)
    return "%s%s%s%s%s" % (prefix, separator, quote, _MARKER % "assignment", quote)


def _marker_class(marker):
    """Class of one existing marker; the two URL halves both report ``url-userinfo``."""
    if marker in ("<redacted-user>", "<redacted-password>"):
        return "url-userinfo"
    inner = marker[len("<redacted:"):-1]
    return inner if inner in CLASSES else "assignment"


def _collect(text, notes):
    """Return ``[(start, end, priority, length, class, replacement)]`` for every candidate."""
    found = []
    for match in _MARKER_RE.finditer(text):
        found.append(
            (
                match.start(),
                match.end(),
                -1,
                match.end() - match.start(),
                _marker_class(match.group(0)),
                match.group(0),
            )
        )
    for priority, class_id, pattern, template in _FAMILIES:
        for match in pattern.finditer(text):
            if class_id == "private-key" and "-----END" not in match.group(0):
                notes.append(NOTE_UNTERMINATED_KEY)
            if class_id == "assignment":
                replacement = _assignment(match)
            elif template is None:
                replacement = _MARKER % class_id
            else:
                replacement = match.expand(template)
            found.append(
                (
                    match.start(),
                    match.end(),
                    priority,
                    match.end() - match.start(),
                    class_id,
                    replacement,
                )
            )
    for match in _ENTROPY_RE.finditer(text):
        if _entropy_ok(match.group(0)):
            found.append(
                (
                    match.start(),
                    match.end(),
                    _ENTROPY_PRIORITY,
                    match.end() - match.start(),
                    "entropy",
                    _MARKER % "entropy",
                )
            )
    return found


def redact(text):
    """Return ``(text, classes, notes)``; total, so ``None`` and non-``str`` yield empty results."""
    if not isinstance(text, str) or not text:
        return "", [], []

    notes = []
    value = text
    if len(value) > MAX_REDACTION_INPUT:
        value = value[:MAX_REDACTION_INPUT]
        notes.append(NOTE_INPUT_TRUNCATED)

    accepted = []
    for start, end, priority, length, class_id, replacement in sorted(
        _collect(value, notes), key=lambda item: (item[2], item[0], -item[3])
    ):
        if any(start < taken_end and end > taken_start for taken_start, taken_end, _, _ in accepted):
            continue
        if len(accepted) >= MAX_REDACTIONS:
            notes.append(NOTE_TOO_MANY)
            break
        accepted.append((start, end, class_id, replacement))

    accepted.sort(key=lambda item: item[0])
    if accepted:
        pieces = []
        cursor = 0
        for start, end, _class, replacement in accepted:
            pieces.append(value[cursor:start])
            pieces.append(replacement)
            cursor = end
        pieces.append(value[cursor:])
        value = "".join(pieces)

    classes = sorted(set(item[2] for item in accepted))
    notes.extend(_edge_notes(value))
    return value, classes, sorted(set(notes))
