"""Ported ``DetectionText``: pure, allocation-conscious text helpers.

Every function is a pure function of its arguments. Two boundary predicates exist on purpose and
they are *not* interchangeable:

* :func:`is_phrase_word_char` mirrors ``DetectionText.IsWordChar`` (``char.IsLetterOrDigit(c) || c == '_'``),
  used by the literal phrase scan.
* :func:`is_regex_word_char` mirrors .NET ``\\w`` (L* | Mn | Nd | Pc), used to replace ``\\b`` around the
  stem-family pattern because Python's ``\\b`` excludes ``Mn``.

Both predicates return ``False`` for any code point above ``U+FFFF``: C# inspects a single ``char``,
which for an astral neighbour is a lone surrogate, and ``char.IsLetterOrDigit(surrogate)`` is
``False``. This is a named residual (see ``SPIKE-A.md``): astral characters are not word characters
in either predicate, which is faithful, but UTF-16 vs code-point index arithmetic still differs
beyond the BMP.
"""

import unicodedata

# Locked constants, mirrored from DetectionText.cs:12-15.
MAX_SNIPPET_LENGTH = 120
MAX_DECODED_LENGTH = 1024
PAIR_WINDOW = 256
MAX_MATCHES_PER_DETECTOR = 256

_WORD = "_"

# char.IsWhiteSpace set (explicit, so U+001C..U+001F stay non-whitespace and U+180E stays excluded).
_WHITESPACE = frozenset(
    [0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0x85, 0xA0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000]
    + list(range(0x2000, 0x200B))
)

_DOCUMENTATION_SUFFIXES = (".md", ".txt", ".html", ".htm", ".rst", ".adoc")


def fold_char(ch):
    """Length-preserving simple fold (``ß`` stays ``ß``, ``İ`` stays ``İ``)."""
    lowered = ch.lower()
    return lowered if len(lowered) == 1 else ch


def fold(text):
    """Fold every character, preserving length so offsets stay aligned."""
    return "".join(fold_char(ch) for ch in text)


def is_phrase_word_char(ch):
    """``DetectionText.IsWordChar``: letters, decimal digits and underscore, BMP only."""
    if not ch:
        return False
    if ord(ch) > 0xFFFF:
        return False
    return ch == _WORD or ch.isalpha() or ch.isdecimal()


def is_regex_word_char(ch):
    """.NET ``\\w``: the phrase predicate plus combining marks and connector punctuation, BMP only."""
    if not ch:
        return False
    if ord(ch) > 0xFFFF:
        return False
    if is_phrase_word_char(ch):
        return True
    return unicodedata.category(ch) in ("Mn", "Pc")


def is_whitespace(ch):
    if not ch:
        return False
    return ord(ch) in _WHITESPACE


def index_of_word(text, word, start, end):
    """Case-insensitive word search; returns ``-1`` when not found in ``[start, end)``."""
    if not text or not word:
        return -1
    if start < 0:
        start = 0
    if end > len(text):
        end = len(text)

    haystack = fold(text)
    needle = fold(word)
    index = start
    while index < end:
        index = haystack.find(needle, index, end)
        if index < 0:
            return -1

        after = index + len(needle)
        left_ok = index == 0 or not is_phrase_word_char(text[index - 1])
        right_ok = after >= len(text) or not is_phrase_word_char(text[after])
        if left_ok and right_ok:
            return index

        index += 1

    return -1


def contains_word(text, word, start, end):
    return index_of_word(text, word, start, end) >= 0


def index_of_phrase(text, phrase, start):
    """Find a phrase whose own edges are word characters, requiring clean boundaries.

    Returns ``(index, length)`` or ``(-1, 0)``. A rejected hit advances by one character.
    """
    if not text or not phrase:
        return -1, 0
    if start < 0:
        start = 0

    haystack = fold(text)
    needle = fold(phrase)
    length = len(needle)
    if length == 0:
        return -1, 0

    index = start
    while index < len(haystack):
        index = haystack.find(needle, index)
        if index < 0:
            return -1, 0

        after = index + length
        left_ok = not is_phrase_word_char(needle[0]) or index == 0 or not is_phrase_word_char(text[index - 1])
        right_ok = (
            not is_phrase_word_char(needle[-1])
            or after >= len(text)
            or not is_phrase_word_char(text[after])
        )
        if left_ok and right_ok:
            return index, length

        index += 1

    return -1, 0


def bound(text, max_length):
    """Collapse whitespace runs and truncate to ``max_length`` characters."""
    if not text:
        return ""
    out = []
    last_was_space = False
    for ch in text:
        if len(out) >= max_length:
            break
        if is_whitespace(ch):
            if not out or last_was_space:
                continue
            out.append(" ")
            last_was_space = True
            continue
        out.append(ch)
        last_was_space = False
    end = len(out)
    while end > 0 and is_whitespace(out[end - 1]):
        end -= 1
    return "".join(out[:end])


def is_mostly_printable(text):
    """True when a decoded buffer looks like text rather than binary noise.

    Mirrors ``DetectionText.IsMostlyPrintable``: CR/LF/TAB, ``0x20``-``0x7E`` and everything from
    ``0xA0`` up count as printable, and 85 % is enough. A per-character ratio, not a code-point test,
    so a short binary blob with a few letters does not pass.
    """
    if not text:
        return False

    printable = 0
    for ch in text:
        code = ord(ch)
        if code == 0x0D or code == 0x0A or code == 0x09 or (0x20 <= code <= 0x7E) or code >= 0xA0:
            printable += 1

    return printable * 100 >= len(text) * 85


def _is_test_directory_name(segment):
    if segment.lower() == "test" or segment.lower() == "tests":
        return True
    # Camel-case compounds (SomeTests, EditorTests, TestData): a plain case-insensitive substring
    # match would also catch Latest/Contest, whose "test" is not a name boundary.
    if "Test" in segment:
        return True
    lowered = segment.lower()
    return (
        lowered.endswith("_tests")
        or lowered.endswith("-tests")
        or lowered.endswith("_test")
        or lowered.endswith("-test")
    )


def _is_test_file_name(file_name):
    dot = file_name.rfind(".")
    stem = file_name[:dot] if dot > 0 else file_name
    if not stem:
        return False
    if "Test" in stem:
        return True
    if stem.lower().startswith("test"):
        after = 4
        if after < len(stem) and stem[after] in ("s", "S"):
            after += 1
        if after >= len(stem) or not is_phrase_word_char(stem[after]):
            return True
    return False


def is_test_fixture_path(project_relative_path):
    """True for the fixture shapes the design names (``Test``/``Tests`` dirs, test file names)."""
    if not project_relative_path:
        return False
    normalized = project_relative_path.replace("\\", "/")
    segments = normalized.split("/")
    for position, segment in enumerate(segments):
        if not segment:
            continue
        last = position == len(segments) - 1
        if last and segment.find(".") > 0:
            if _is_test_file_name(segment):
                return True
            continue
        if _is_test_directory_name(segment):
            return True
    return False


def is_documentation_path(project_relative_path):
    """Documentation formats where quoting attack examples is normal; confidence is capped there."""
    if not project_relative_path:
        return False
    path = project_relative_path.replace("\\", "/").lower()
    return path.endswith(_DOCUMENTATION_SUFFIXES)


def is_suppressed(project_relative_path, suppressed_paths):
    """Exact file or anything under a listed folder; both sides use project-relative slashes."""
    if not project_relative_path or not suppressed_paths:
        return False
    path = project_relative_path.replace("\\", "/").strip().lower()
    while path.startswith("./"):
        path = path[2:]
    for suppressed in suppressed_paths:
        if not suppressed:
            continue
        candidate = suppressed.replace("\\", "/").strip().lower()
        while candidate.startswith("./"):
            candidate = candidate[2:]
        candidate = candidate.strip("/")
        if not candidate:
            continue
        if path == candidate or path.startswith(candidate + "/"):
            return True
    return False
