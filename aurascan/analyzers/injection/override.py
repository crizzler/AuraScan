"""``instruction-override`` detector (mirrors ``InstructionOverrideDetector.cs``).

Exact phrases are reported with the literal rule ids; a bounded regex family covers inflection and
object variations the literal list does not spell out. Literals run first, and a stem-family hit that
overlaps an existing literal is suppressed, so one phrase cannot double-count.

The module-level tables below are the mutation seam for ``tools/injection_parity.py --selftest``:
``LITERAL_PHRASES``, ``LITERAL_IDS``, ``STEM_FAMILY_PATTERN``, ``STEM_FAMILY`` and ``_overlaps`` are
patched by name through restoring context managers, so mutants grade the production detector rather
than a copy of it.
"""

import re

from . import catalog, injection_text
from .model import InjectionDetector, InjectionMatch

# Index-aligned with LITERAL_PHRASES. The ids drive the High-confidence rule.
LITERAL_IDS = (
    "override.literal.ignore-previous",
    "override.literal.ignore-all-previous",
    "override.literal.ignore-the-previous",
    "override.literal.ignore-prior",
    "override.literal.ignore-all-prior",
    "override.literal.disregard-previous",
    "override.literal.disregard-all-previous",
    "override.literal.disregard-prior",
    "override.literal.ignore-previous-commands",
    "override.literal.ignore-all-previous-commands",
    "override.literal.forget-previous",
    "override.literal.forget-all-previous",
    "override.literal.ignore-your-instructions",
    "override.literal.ignore-the-above",
    "override.literal.override-your-instructions",
    "override.literal.ignore-preceding",
    "override.literal.ignore-everything-above",
    "override.literal.disregard-everything-above",
)

LITERAL_PHRASES = (
    "ignore previous instructions",
    "ignore all previous instructions",
    "ignore the previous instructions",
    "ignore prior instructions",
    "ignore all prior instructions",
    "disregard previous instructions",
    "disregard all previous instructions",
    "disregard prior instructions",
    "ignore previous commands",
    "ignore all previous commands",
    "forget previous instructions",
    "forget all previous instructions",
    "ignore your instructions",
    "ignore the above instructions",
    "override your instructions",
    "ignore preceding instructions",
    "ignore everything above",
    "disregard everything above",
)

# Linear-time family: flat alternation, single \s+ gaps, no nested quantifiers. The C# pattern's
# leading/trailing \b is replaced by explicit boundary predicates (injection_text.is_regex_word_char)
# because Python's \b excludes Mn where .NET's \w includes it.
STEM_FAMILY_PATTERN = (
    r"(?:ignore|disregard|forget)\s+(?:all\s+|any\s+|the\s+|your\s+)?"
    r"(?:previous|prior|above|earlier|preceding)\s+"
    r"(?:instructions?|commands?|directives?|prompts?|rules?)"
)

STEM_FAMILY = re.compile(STEM_FAMILY_PATTERN)

RE_STEM_FAMILY_ID = "override.regex.stem-family"


class InstructionOverrideDetector(InjectionDetector):
    class_id = catalog.INSTRUCTION_OVERRIDE
    severity = "HIGH"

    def detect(self, content, folded):
        matches = []
        if not content:
            return matches

        for position, phrase in enumerate(LITERAL_PHRASES):
            index = 0
            while index < len(content):
                found, length = injection_text.index_of_phrase(folded, phrase, index)
                if found < 0:
                    break

                _add_match(matches, content, LITERAL_IDS[position], found, length)
                if len(matches) >= injection_text.MAX_MATCHES_PER_DETECTOR:
                    return matches

                index = found + length

        for match in STEM_FAMILY.finditer(folded):
            start, end = match.span()
            if start != 0 and injection_text.is_regex_word_char(content[start - 1]):
                continue
            if end < len(content) and injection_text.is_regex_word_char(content[end]):
                continue
            if _overlaps(matches, start, end - start):
                continue

            _add_match(matches, content, RE_STEM_FAMILY_ID, start, end - start)
            if len(matches) >= injection_text.MAX_MATCHES_PER_DETECTOR:
                break

        matches.sort(key=lambda item: (item.start, item.detector_id))
        return matches


def _add_match(matches, content, detector_id, index, length):
    if index < 0 or length <= 0 or index >= len(content):
        return
    if index + length > len(content):
        length = len(content) - index

    matches.append(
        InjectionMatch(
            catalog.INSTRUCTION_OVERRIDE,
            detector_id,
            index,
            length,
            injection_text.bound(content[index:index + length], injection_text.MAX_SNIPPET_LENGTH),
        )
    )


def _overlaps(matches, index, length):
    end = index + length
    for existing in matches:
        existing_end = existing.start + existing.length
        if index < existing_end and end > existing.start:
            return True
    return False
