"""``data-exfiltration`` detector (mirrors ``DataExfiltrationDetector.cs``).

A sensitive artifact named together with an exfiltration verb inside a +/-256-character window. Both
signals are required, so a sentence that merely mentions ``.env`` stays silent. Ported in Card B as an
inner matcher for ``encoded-obfuscated``; the class itself is reported, never gated.

The reported span covers verb-to-artifact (``min(start)`` .. ``max(end)``), exactly as the original.
"""

from . import catalog, injection_text
from .model import InjectionDetector, InjectionMatch

SENSITIVE_IDS = (
    "system-prompt",
    "your-instructions",
    "env-file",
    "api-key",
    "api-key-compact",
    "api-key-hyphen",
    "environment-variables",
    "credentials",
    "secret-key",
    "ssh-private-key",
    "access-token",
    "password-file",
)

SENSITIVE_PHRASES = (
    "system prompt",
    "your instructions",
    ".env",
    "api key",
    "apikey",
    "api-key",
    "environment variables",
    "credentials",
    "secret key",
    "id_rsa",
    "access token",
    "password file",
)

VERB_IDS = (
    "send",
    "post",
    "email",
    "upload",
    "exfiltrate",
    "reveal",
    "leak",
    "forward",
    "transmit",
    "print-to-chat",
    "output-in-full",
    "include-in-response",
    "paste",
)

VERB_PHRASES = (
    "send",
    "post",
    "email",
    "upload",
    "exfiltrate",
    "reveal",
    "leak",
    "forward",
    "transmit",
    "print to the chat",
    "output in full",
    "include in your response",
    "paste",
)


class DataExfiltrationDetector(InjectionDetector):
    class_id = catalog.DATA_EXFILTRATION
    severity = "HIGH"

    def detect(self, content, folded):
        matches = []
        if not content:
            return matches

        for position, phrase in enumerate(SENSITIVE_PHRASES):
            index = 0
            while index < len(content):
                found, sensitive_length = injection_text.index_of_phrase(folded, phrase, index)
                if found < 0:
                    break

                window_start = max(0, found - injection_text.PAIR_WINDOW)
                window_end = min(len(content), found + sensitive_length + injection_text.PAIR_WINDOW)

                verb = _find_verb(folded, window_start, window_end)
                if verb is not None:
                    verb_start, verb_length = verb
                    start = min(found, verb_start)
                    end = max(found + sensitive_length, verb_start + verb_length)
                    matches.append(
                        InjectionMatch(
                            catalog.DATA_EXFILTRATION,
                            "exfil.pair." + SENSITIVE_IDS[position],
                            start,
                            end - start,
                            injection_text.bound(
                                content[start:end], injection_text.MAX_SNIPPET_LENGTH
                            ),
                        )
                    )

                    if len(matches) >= injection_text.MAX_MATCHES_PER_DETECTOR:
                        return matches

                index = found + sensitive_length

        matches.sort(key=lambda item: (item.start, item.detector_id))
        return matches


def _find_verb(folded, start, end):
    """Closest word-boundary verb inside the window, as ``(start, length)``; ``None`` when absent."""
    best = None
    for phrase in VERB_PHRASES:
        found = injection_text.index_of_word(folded, phrase, start, end)
        if found < 0:
            continue
        if best is None or found < best[0]:
            best = (found, len(phrase))
    return best
