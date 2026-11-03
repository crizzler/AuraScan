"""``encoded-obfuscated`` detector (mirrors ``EncodedObfuscatedDetector.cs``, 1007 lines).

Bounded decoding of base64, HTML entities, backslash and percent escapes, leet substitution and
NFKC/zero-width normalization. A decoded window is reported only when it re-matches a higher-tier rule
(override, persona, exfiltration), and only for the part of the window that the decoding actually
changed: plain prose that merely shares the window stays with the primary rules instead of being
re-labelled as obfuscation.

Locked discipline, unchanged from the original: decoded text is report data only, never executed,
evaluated, written or fed back into a scanner. Every decode works on a hard-bounded window (backslash
runs and leet clusters are walked in overlapping slices) and every decoded character keeps the raw
offset it came from, so evidence points at the text that justified the signal.

Fidelity surface this port must not lose (``01b`` §4.2): ``-``/``_`` translation plus padding before a
validating base64 decode, ``utf-8`` with ``replace`` for malformed input, per-character ``NFKC`` with a
``ValueError`` fallback, the 85 % printable gate, and surrogate-pair emission for supplementary planes.
"""

from . import catalog, injection_text
from .exfiltration import DataExfiltrationDetector
from .model import InjectionDetector, InjectionMatch
from .override import InstructionOverrideDetector
from .persona import PersonaHijackDetector

MAX_BASE64_CANDIDATE_CHARS = 5460
MAX_BASE64_DECODED_BYTES = 4096
MAX_ENTITY_RUN_CHARS = 8192
MAX_NORMALIZATION_WINDOW = 4096
NORMALIZATION_CONTEXT_BEFORE = 64
LEET_CONTEXT_BEFORE = 64
LEET_CONTEXT_AFTER = 192
MAX_LEET_WINDOW_CHARS = 4096
LEET_WINDOW_OVERLAP = 640
MAX_BACKSLASH_CHUNK_CHARS = 8192
BACKSLASH_CHUNK_OVERLAP = 640
MAX_INNER_MATCHES_PER_CANDIDATE = 8

ENCODED_CONFIDENCE = "LOW"

_OVERRIDE_RULES = InstructionOverrideDetector()
_PERSONA_RULES = PersonaHijackDetector()
_EXFIL_RULES = DataExfiltrationDetector()

_ZERO_WIDTH = ("\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad")

# The leet map is the M5 mutation seam: ``tools/injection_parity.py`` patches ``LEET_MAP``.
LEET_MAP = {
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
}

# ``LEET_MIN_LENGTH`` / ``LEET_MIN_HITS`` are the M6 seam (the ``i - start < 5 || leetCount < 2`` guard).
LEET_MIN_LENGTH = 5
LEET_MIN_HITS = 2


class DecodedCandidate(object):
    """Decoded text plus the raw offset of every decoded character (display and mapping data only).

    ``starts``/``ends`` may be ``None`` (identity mapping). A trailing entry in ``raw_ends`` is allowed
    so a byte-mapped decoder stays exact for a match that reaches the end of the candidate; the clamps
    mirror the original ``RawIndexAt``/``RawEndAt``.
    """

    __slots__ = ("text", "raw_start", "raw_end", "changed", "_starts", "_ends")

    def __init__(self, text, raw_start, raw_end, starts=None, ends=None, changed=False):
        self.text = text or ""
        self.raw_start = 0 if raw_start < 0 else raw_start
        self.raw_end = self.raw_start if raw_end < self.raw_start else raw_end
        self.changed = changed
        self._starts = starts
        self._ends = ends

    def raw_index_at(self, index):
        if index < 0:
            return self.raw_start
        if self._starts is None:
            return self.raw_start + index
        if index >= len(self._starts):
            return self.raw_end
        return self._starts[index]

    def raw_end_at(self, index):
        if self._ends is not None and 0 <= index < len(self._ends):
            return self._ends[index]
        return self.raw_index_at(index)


class EncodedObfuscatedDetector(InjectionDetector):
    class_id = catalog.ENCODED_OBFUSCATED
    severity = "MEDIUM"

    def detect(self, content, folded):
        matches = []
        if not content:
            return matches

        _detect_base64(content, matches)
        _detect_html_entities(content, matches)
        _detect_backslash_escapes(content, matches)
        _detect_percent_encoding(content, matches)
        _detect_leet_substitution(content, matches)
        _detect_normalization_windows(content, matches)

        matches.sort(key=lambda item: (item.start, item.detector_id))
        return matches


# ------------------------------------------------------------------------------------- base64


def _detect_base64(content, matches):
    index = 0
    while index < len(content) and len(matches) < injection_text.MAX_MATCHES_PER_DETECTOR:
        if not _is_base64_char(content[index]):
            index += 1
            continue

        run_start = index
        run_end = index
        while run_end < len(content) and _is_base64_char(content[run_end]):
            run_end += 1

        candidate_length = min(run_end - run_start, MAX_BASE64_CANDIDATE_CHARS)
        if candidate_length >= 16:
            candidate = content[run_start:run_start + candidate_length]
            decoded = _try_decode_base64(candidate, run_start, candidate_length)
            if decoded is not None:
                _add_encoded_matches(matches, content, "encoded.base64", decoded)

        index = run_end


def _try_decode_base64(candidate, raw_start, raw_length):
    normalized = candidate.replace("-", "+").replace("_", "/").rstrip("=")
    if len(normalized) % 4 == 1:
        return None

    padding = (4 - len(normalized) % 4) % 4
    if padding:
        normalized += "=" * padding

    try:
        payload = _b64decode(normalized)
    except ValueError:
        return None

    if not payload or len(payload) > MAX_BASE64_DECODED_BYTES:
        return None

    text = payload.decode("utf-8", "replace")
    if not injection_text.is_mostly_printable(text):
        return None

    return _build_base64_candidate(text, payload, raw_start, raw_length)


def _b64decode(normalized):
    import base64

    return base64.b64decode(normalized.encode("ascii"), validate=True)


def _is_base64_char(ch):
    return (
        ("A" <= ch <= "Z")
        or ("a" <= ch <= "z")
        or ("0" <= ch <= "9")
        or ch in ("+", "/", "=", "-", "_")
    )


# ------------------------------------------------------------------------------ HTML entities


def _detect_html_entities(content, matches):
    search = 0
    while search < len(content) and len(matches) < injection_text.MAX_MATCHES_PER_DETECTOR:
        start = content.find("&#", search)
        if start < 0:
            break

        end = _extend_entity_run(content, start)
        if end > start:
            raw = content[start:end]
            decoded = _decode_html_entities(raw, start)
            if decoded.changed:
                _add_encoded_matches(matches, content, "encoded.html-entities", decoded)

        search = end if end > start else start + 2


def _extend_entity_run(content, start):
    end = start
    limit = min(len(content), start + MAX_ENTITY_RUN_CHARS)

    while end < limit:
        if content[end] == "&" and end + 1 < limit and content[end + 1] == "#":
            semi = content.find(";", end + 2, min(end + 2 + 12, limit))
            if semi < 0:
                break
            end = semi + 1
            continue

        # Entities separated by a single space are still one encoded phrase.
        if content[end] == " " and end + 2 < limit and content[end + 1] == "&" and content[end + 2] == "#":
            end += 1
            continue

        break

    return end


def _decode_html_entities(raw, raw_start):
    out = []
    starts = []
    i = 0

    while i < len(raw):
        if raw[i] == "&" and i + 2 < len(raw) and raw[i + 1] == "#":
            cursor = i + 2
            hexa = cursor < len(raw) and raw[cursor] in ("x", "X")
            if hexa:
                cursor += 1

            digits_start = cursor
            while cursor < len(raw) and (_is_hex_digit(raw[cursor]) if hexa else _is_digit(raw[cursor])):
                cursor += 1
            digits = cursor - digits_start

            if digits > 0 and cursor < len(raw) and raw[cursor] == ";":
                value = _try_parse_hex(raw, digits_start, digits) if hexa else _try_parse_decimal(
                    raw, digits_start, digits
                )
                if value is not None and _is_valid_code_point(value):
                    _append_code_point(out, starts, value, raw_start + i)
                    i = cursor + 1
                    continue

        out.append(raw[i])
        starts.append(raw_start + i)
        i += 1

    text = "".join(out)
    return DecodedCandidate(text, raw_start, raw_start + len(raw), starts, None, text != raw)


def _is_valid_code_point(value):
    return value > 0 and value <= 0x10FFFF and not (0xD800 <= value <= 0xDFFF)


# ---------------------------------------------------------------------------- backslash escapes


def _detect_backslash_escapes(content, matches):
    i = 0
    while i < len(content) - 1 and len(matches) < injection_text.MAX_MATCHES_PER_DETECTOR:
        if not _is_escape_start(content, i):
            i += 1
            continue

        run_end = _find_escape_run_end(content, i)
        chunk_start = i

        while chunk_start < run_end and len(matches) < injection_text.MAX_MATCHES_PER_DETECTOR:
            chunk_end = min(run_end, chunk_start + MAX_BACKSLASH_CHUNK_CHARS)
            raw = content[chunk_start:chunk_end]
            decoded = _decode_backslash_escapes(raw, chunk_start)
            if decoded.changed:
                _add_encoded_matches(matches, content, "encoded.backslash-escapes", decoded)

            if chunk_end >= run_end:
                break

            next_start = chunk_end - BACKSLASH_CHUNK_OVERLAP
            chunk_start = next_start if next_start > chunk_start else chunk_end

        i = run_end


def _find_escape_run_end(content, start):
    end = start
    while end < len(content):
        if _is_escape_start(content, end):
            end += _escape_length(content, end)
            continue

        if content[end] in (" ", "-") and end + 2 < len(content) and _is_escape_start(content, end + 1):
            end += 1
            continue

        break

    return end


def _is_escape_start(content, index):
    if index + 1 >= len(content) or content[index] != "\\":
        return False

    kind = content[index + 1]
    if kind in ("u", "U"):
        return index + 5 < len(content)
    if kind in ("x", "X"):
        return index + 3 < len(content)
    return False


def _escape_length(content, index):
    return 6 if content[index + 1] in ("u", "U") else 4


def _decode_backslash_escapes(raw, raw_start):
    out = []
    starts = []
    i = 0

    while i < len(raw):
        if _is_escape_start(raw, i):
            kind = raw[i + 1]
            digits = 4 if kind in ("u", "U") else 2
            if i + 2 + digits <= len(raw):
                value = _try_parse_hex(raw, i + 2, digits)
                if value is not None and _is_valid_code_point(value):
                    _append_code_point(out, starts, value, raw_start + i)
                    i += 2 + digits
                    continue

        out.append(raw[i])
        starts.append(raw_start + i)
        i += 1

    text = "".join(out)
    return DecodedCandidate(text, raw_start, raw_start + len(raw), starts, None, text != raw)


# ---------------------------------------------------------------------------- percent encoding


def _detect_percent_encoding(content, matches):
    i = 0
    while i < len(content) - 2 and len(matches) < injection_text.MAX_MATCHES_PER_DETECTOR:
        if not _is_percent_escape(content, i):
            i += 1
            continue

        start = i
        end = i
        payload = []
        raw_starts = []

        while (
            end < len(content) - 2
            and _is_percent_escape(content, end)
            and len(payload) < MAX_BASE64_DECODED_BYTES
        ):
            payload.append((_hex_value(content[end + 1]) * 16 + _hex_value(content[end + 2])) & 0xFF)
            raw_starts.append(end)
            end += 3

        if len(payload) >= 4:
            decoded = bytes(payload).decode("utf-8", "replace")
            if injection_text.is_mostly_printable(decoded):
                _add_encoded_matches(
                    matches,
                    content,
                    "encoded.percent-escapes",
                    _build_percent_candidate(decoded, bytes(payload), raw_starts, start, end),
                )

        i = end if end > i else i + 1


def _build_percent_candidate(decoded, payload, raw_starts, raw_start, raw_end):
    """Map each decoded character to the triplet that produced its first UTF-8 byte."""
    byte_starts = _map_utf8_char_starts(payload, len(decoded))
    starts = [0] * (len(decoded) + 1)

    for i in range(len(decoded)):
        byte_index = byte_starts[i]
        starts[i] = raw_starts[byte_index] if byte_index < len(raw_starts) else raw_end

    starts[len(decoded)] = raw_end
    return DecodedCandidate(decoded, raw_start, raw_end, starts, None, True)


def _is_percent_escape(content, index):
    return (
        index + 2 < len(content)
        and content[index] == "%"
        and _is_hex_digit(content[index + 1])
        and _is_hex_digit(content[index + 2])
    )


# --------------------------------------------------------------------------- leet substitution


def _detect_leet_substitution(content, matches):
    i = 0
    cluster_start = -1
    cluster_end = -1

    while i < len(content) and len(matches) < injection_text.MAX_MATCHES_PER_DETECTOR:
        if not _is_leet_word_char(content[i]):
            i += 1
            continue

        start = i
        leet_count = 0
        while i < len(content) and _is_leet_word_char(content[i]):
            if _is_leet_char(content[i]):
                leet_count += 1
            i += 1

        if i - start < LEET_MIN_LENGTH or leet_count < LEET_MIN_HITS:
            continue

        coverage_start = max(0, start - LEET_CONTEXT_BEFORE)
        coverage_end = min(len(content), i + LEET_CONTEXT_AFTER)

        if cluster_start < 0:
            cluster_start = coverage_start
            cluster_end = coverage_end
            continue

        if coverage_start <= cluster_end:
            if coverage_end > cluster_end:
                cluster_end = coverage_end
            continue

        _process_leet_cluster(content, cluster_start, cluster_end, matches)
        cluster_start = coverage_start
        cluster_end = coverage_end

    if cluster_start >= 0:
        _process_leet_cluster(content, cluster_start, cluster_end, matches)


def _process_leet_cluster(content, start, end, matches):
    window_start = start
    while window_start < end and len(matches) < injection_text.MAX_MATCHES_PER_DETECTOR:
        window_end = min(end, window_start + MAX_LEET_WINDOW_CHARS)
        window = content[window_start:window_end]
        decoded = _apply_leet_map(window, window_start)
        if decoded.changed:
            _add_encoded_matches(matches, content, "encoded.leet", decoded)

        if window_end >= end:
            break

        next_start = window_end - LEET_WINDOW_OVERLAP
        window_start = next_start if next_start > window_start else window_end


def _is_leet_word_char(ch):
    return ("A" <= ch <= "Z") or ("a" <= ch <= "z") or ("0" <= ch <= "9") or ch in ("@", "$")


def _is_leet_char(ch):
    return ch in ("0", "1", "3", "4", "5", "7", "@", "$")


def _apply_leet_map(text, raw_start):
    decoded = "".join(LEET_MAP.get(ch, ch) for ch in text)
    return DecodedCandidate(decoded, raw_start, raw_start + len(text), None, None, decoded != text)


# ------------------------------------------------------------------- normalization windows


def _detect_normalization_windows(content, matches):
    i = 0
    while i < len(content) and len(matches) < injection_text.MAX_MATCHES_PER_DETECTOR:
        if not _is_normalization_indicator(content[i]):
            i += 1
            continue

        window_start = max(0, i - NORMALIZATION_CONTEXT_BEFORE)
        window_end = min(len(content), i + MAX_NORMALIZATION_WINDOW)
        window = content[window_start:window_end]
        decoded = _normalize_for_detection(window, window_start)

        if decoded.changed:
            _add_encoded_matches(matches, content, "encoded.normalization", decoded)

        i = window_end if window_end > i else i + 1


def _is_normalization_indicator(ch):
    return (
        ch in _ZERO_WIDTH
        or ("\uff01" <= ch <= "\uff5e")
        or ch == "\u3000"
    )


def _is_zero_width(ch):
    return ch in _ZERO_WIDTH


def _normalize_for_detection(window, raw_start):
    out = []
    starts = []

    for offset, ch in enumerate(window):
        if _is_zero_width(ch):
            continue

        if "\uff01" <= ch <= "\uff5e":
            out.append(chr(ord(ch) - 0xFEE0))
            starts.append(raw_start + offset)
            continue

        if ch == "\u3000":
            out.append(" ")
            starts.append(raw_start + offset)
            continue

        if ch < "\u007f":
            out.append(ch)
            starts.append(raw_start + offset)
            continue

        try:
            piece = _nfkc(ch)
        except ValueError:
            piece = ch

        for piece_char in piece:
            out.append(piece_char)
            starts.append(raw_start + offset)

    text = "".join(out)
    return DecodedCandidate(text, raw_start, raw_start + len(window), starts, None, text != window)


def _nfkc(ch):
    import unicodedata

    return unicodedata.normalize("NFKC", ch)


# ----------------------------------------------------------------------------------- shared


def _add_encoded_matches(matches, content, detector_prefix, candidate):
    """Map each inner hit back to its raw span, skipping plain prose and per-id overlaps."""
    inner = _find_inner_matches(content, candidate)

    for hit in inner:
        if len(matches) >= injection_text.MAX_MATCHES_PER_DETECTOR:
            break

        decoded_start = hit.start
        decoded_end = hit.start + hit.length
        if decoded_start < 0 or decoded_end > len(candidate.text) or decoded_end <= decoded_start:
            continue

        raw_start = candidate.raw_index_at(decoded_start)
        raw_end = candidate.raw_end_at(decoded_end)

        if raw_start < 0:
            raw_start = 0
        if raw_end > len(content):
            raw_end = len(content)
        if raw_end <= raw_start:
            raw_end = min(len(content), raw_start + 1)
        if raw_start >= len(content):
            continue

        detector_id = detector_prefix + ".to-" + hit.class_id
        if _overlaps_existing(matches, detector_id, raw_start, raw_end):
            continue

        matches.append(
            InjectionMatch(
                catalog.ENCODED_OBFUSCATED,
                detector_id,
                raw_start,
                raw_end - raw_start,
                _snippet_around(content, raw_start, raw_end, injection_text.MAX_SNIPPET_LENGTH),
                _snippet_around(
                    candidate.text, decoded_start, decoded_end, injection_text.MAX_DECODED_LENGTH
                ),
                hit.class_id,
            )
        )


def _is_unchanged_span(content, raw_start, raw_end, decoded, decoded_start, decoded_end):
    length = decoded_end - decoded_start
    if raw_end - raw_start != length:
        return False
    return content[raw_start:raw_end] == decoded[decoded_start:decoded_end]


def _overlaps_existing(matches, detector_id, start, end):
    for existing in matches:
        if existing.detector_id != detector_id:
            continue
        if start < existing.start + existing.length and end > existing.start:
            return True
    return False


def _overlaps(kept, start, end):
    for existing in kept:
        if start < existing.start + existing.length and end > existing.start:
            return True
    return False


def _snippet_around(text, start, end, max_length):
    """Bounded snippet that always begins at the match and keeps context around it."""
    if start < 0:
        start = 0
    if end > len(text):
        end = len(text)
    if end <= start or start >= len(text):
        return ""

    length = end - start
    source = start
    if length >= max_length:
        take = max_length
    else:
        context = (max_length - length) // 2
        source = max(0, start - context)
        take = min(len(text) - source, max_length)

    return injection_text.bound(text[source:source + take], max_length)


def _find_inner_matches(content, candidate):
    """Distinct higher-tier hits inside one candidate, already mapped to raw spans.

    Unchanged plain prose and duplicates are rejected *before* the retention cap, so plaintext sharing
    the window can never consume the budget an encoded span needs.
    """
    decoded_text = candidate.text
    if not decoded_text:
        return []

    found = []
    _collect(found, _OVERRIDE_RULES.detect(decoded_text, injection_text.fold(decoded_text)))
    _collect(found, _PERSONA_RULES.detect(decoded_text, injection_text.fold(decoded_text)))
    _collect(found, _EXFIL_RULES.detect(decoded_text, injection_text.fold(decoded_text)))
    found.sort(key=lambda item: (item.start, item.detector_id))

    distinct = []
    for hit in found:
        if len(distinct) >= MAX_INNER_MATCHES_PER_CANDIDATE:
            break

        decoded_start = hit.start
        decoded_end = decoded_start + hit.length
        if decoded_start < 0 or decoded_end > len(decoded_text) or decoded_end <= decoded_start:
            continue

        raw_start = candidate.raw_index_at(decoded_start)
        raw_end = candidate.raw_end_at(decoded_end)
        if raw_start < 0:
            raw_start = 0
        if raw_end > len(content):
            raw_end = len(content)
        if raw_end <= raw_start:
            raw_end = min(len(content), raw_start + 1)
        if raw_start >= len(content):
            continue

        if _is_unchanged_span(content, raw_start, raw_end, decoded_text, decoded_start, decoded_end):
            continue
        if _overlaps(distinct, decoded_start, decoded_end):
            continue

        distinct.append(hit)

    return distinct


def _collect(into, matches):
    if not matches:
        return
    for match in matches:
        if match is not None:
            into.append(match)


# ------------------------------------------------------------------------------ primitives


def _is_hex_digit(ch):
    return ("0" <= ch <= "9") or ("a" <= ch <= "f") or ("A" <= ch <= "F")


def _is_digit(ch):
    return "0" <= ch <= "9"


def _hex_value(ch):
    if "0" <= ch <= "9":
        return ord(ch) - ord("0")
    if "a" <= ch <= "f":
        return ord(ch) - ord("a") + 10
    return ord(ch) - ord("A") + 10


def _try_parse_hex(text, start, length):
    """Hex value, or ``None`` when malformed or above ``U+10FFFF``."""
    if length <= 0 or length > 8:
        return None
    value = 0
    for i in range(length):
        ch = text[start + i]
        if not _is_hex_digit(ch):
            return None
        value = (value << 4) | _hex_value(ch)
        if value > 0x10FFFF:
            return None
    return value


def _try_parse_decimal(text, start, length):
    if length <= 0 or length > 8:
        return None
    value = 0
    for i in range(length):
        ch = text[start + i]
        if not _is_digit(ch):
            return None
        value = value * 10 + (ord(ch) - ord("0"))
        if value > 0x10FFFF:
            return None
    return value


def _append_code_point(out, starts, value, raw_index):
    """Append one code point, emitting a surrogate pair above the BMP while advancing the map once."""
    if value <= 0xFFFF:
        out.append(chr(value))
        starts.append(raw_index)
        return

    pair = chr(0x10000 + (value - 0x10000))
    out.append(pair)
    starts.append(raw_index)


def _build_base64_candidate(text, payload, raw_start, raw_length):
    """Map every decoded character to the quartet carrying its first UTF-8 byte, plus the quartet end."""
    byte_starts = _map_utf8_char_starts(payload, len(text))
    starts = [0] * len(text)
    ends = [0] * (len(text) + 1)

    for i in range(len(text)):
        starts[i] = raw_start + _quartet_start(byte_starts[i], raw_length)
        ends[i] = raw_start + _quartet_end(byte_starts[i], raw_length)

    ends[len(text)] = raw_start + _quartet_end(byte_starts[len(text)], raw_length)
    return DecodedCandidate(text, raw_start, raw_start + raw_length, starts, ends, True)


def _quartet_start(byte_index, raw_length):
    offset = byte_index // 3 * 4
    return offset if offset <= raw_length else raw_length


def _quartet_end(byte_index, raw_length):
    offset = (byte_index + 2) // 3 * 4
    return offset if offset <= raw_length else raw_length


def _map_utf8_char_starts(payload, char_count):
    """For every produced character, the offset of the first byte that contributed to it.

    Replacement characters keep the offset of the malformed byte, and a truncated tail keeps the
    sequence start, so spans stay on bytes that actually produced text.
    """
    starts = [0] * (char_count + 1)
    if char_count <= 0:
        starts[0] = len(payload)
        return starts

    byte_index = 0
    char_index = 0
    pending_start = 0

    while byte_index < len(payload) and char_index < char_count:
        length = _utf8_sequence_length(payload, byte_index)
        piece = payload[byte_index:byte_index + length].decode("utf-8", "replace")

        byte_index += length
        if not piece:
            continue

        for ch in piece:
            if char_index >= char_count:
                break
            starts[char_index] = pending_start
            char_index += 1

        pending_start = byte_index

    while char_index < char_count:
        starts[char_index] = len(payload)
        char_index += 1

    starts[char_count] = len(payload)
    return starts


def _utf8_sequence_length(payload, index):
    """Length of the UTF-8 sequence at ``index``, narrowed to its valid prefix on malformed input."""
    lead = payload[index]
    if lead < 0x80:
        return 1
    if 0xC2 <= lead <= 0xDF:
        maximum = 2
    elif 0xE0 <= lead <= 0xEF:
        maximum = 3
    elif 0xF0 <= lead <= 0xF4:
        maximum = 4
    else:
        return 1

    length = 1
    while length < maximum and index + length < len(payload) and 0x80 <= payload[index + length] <= 0xBF:
        length += 1
        candidate = payload[index:index + length]
        if len(candidate) == maximum and candidate.decode("utf-8", "replace") != "\ufffd":
            return length

    if length >= maximum:
        return maximum
    return length
