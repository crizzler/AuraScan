#!/usr/bin/env python3
"""Independent label audit for the injection corpus (dev tool, never shipped).

The lists below are **literal copies** of the C# tables, not imports from
``aurascan/analyzers/injection``. A label therefore cannot be right merely because the detector
agrees with it: the audit re-derives the structural property from its own bytes.

Extraction source is ``tests/fixtures/injection_corpus/csharp_label_lists.txt`` (a verbatim ``sed``
extract, pinned by ``CSHARP_LABEL_LISTS_SHA256``). ``LABEL_BLOCK_SHA256`` pins *this* module's tuple
block, so editing either side is visible on its own.
"""

import hashlib

TRANSCRIPTION_SOURCE = "tests/fixtures/injection_corpus/csharp_label_lists.txt#InstructionOverrideDetector.cs:20-56+DataExfiltrationDetector.cs:14-77"

OVERRIDE_LITERAL_IDS = (
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

OVERRIDE_LITERAL_PHRASES = (
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

EXFIL_VERBS = (
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


def _block_bytes():
    lines = []
    for name in (
        "OVERRIDE_LITERAL_IDS",
        "OVERRIDE_LITERAL_PHRASES",
        "SENSITIVE_IDS",
        "SENSITIVE_PHRASES",
        "EXFIL_VERBS",
    ):
        lines.append("%s:" % name)
        lines.extend(globals()[name])
    return ("\n".join(lines) + "\n").encode("utf-8")


LABEL_BLOCK_SHA256 = hashlib.sha256(_block_bytes()).hexdigest()
CSHARP_LABEL_LISTS_SHA256 = "9626b5eabb4fdcd083da4a977e4075b57259c199e358211a46410b060976546c"


def label_block_sha256(block=None):
    """Hash of the audit lists, recomputed rather than read from the module constant."""
    if block is None:
        return hashlib.sha256(_block_bytes()).hexdigest()
    return hashlib.sha256(block).hexdigest()


def contains_any(text, fragments):
    lowered = text.lower()
    for fragment in fragments:
        if fragment.lower() in lowered:
            return True
    return False


def audit_injection_labels(samples):
    """Structural audit of the positive labels. Returns an error string, or ``None``.

    ``samples`` is any iterable of objects with ``.class_id`` / ``.path`` / ``.content``.
    """
    paths = set()
    for sample in samples:
        if sample.path in paths:
            return "duplicate injection path '%s'" % sample.path
        paths.add(sample.path)

        if sample.class_id == "data-exfiltration":
            if not (contains_any(sample.content, SENSITIVE_PHRASES) and contains_any(sample.content, EXFIL_VERBS)):
                return (
                    "data-exfiltration sample '%s' contains no sensitive-artifact + exfiltration-verb "
                    "pair; move it to the benign corpus" % sample.path
                )
    return None


def audit_override_labels(samples):
    """Every override sample must be reachable by a literal phrase or the stem family, i.e. the class
    label is not vacuous. Returns the offending paths (empty when the labels are all plausible)."""
    suspicious = []
    for sample in samples:
        if sample.class_id != "instruction-override":
            continue
        lowered = sample.content.lower()
        reachable = any(phrase in lowered for phrase in OVERRIDE_LITERAL_PHRASES)
        if not reachable:
            for stem in ("ignore", "disregard", "forget"):
                if stem in lowered:
                    reachable = True
                    break
        if not reachable:
            suspicious.append(sample.path)
    return suspicious


def main(argv=None):
    import os
    import sys

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from tools.injection_corpus_export import derive_records

    class _Sample(object):
        __slots__ = ("class_id", "path", "content")

        def __init__(self, class_id, path, content):
            self.class_id = class_id
            self.path = path
            self.content = content

    samples, _ = derive_records()
    wrapped = [_Sample(record["class"], record["path"], record["content"]) for record in samples]

    print("label_block_sha256=%s" % LABEL_BLOCK_SHA256)
    print("csharp_label_lists_sha256=%s" % CSHARP_LABEL_LISTS_SHA256)
    print("override_literals=%d phrases=%d" % (len(OVERRIDE_LITERAL_IDS), len(OVERRIDE_LITERAL_PHRASES)))

    error = audit_injection_labels(wrapped)
    if error:
        print("AUDIT FAILED: " + error)
        return 2

    suspicious = audit_override_labels(wrapped)
    if suspicious:
        print("override samples reachable by neither literal nor stem (expected misses): "
              + ", ".join(path.rsplit("/", 1)[-1] for path in suspicious))

    print("audit ok: %d injection samples" % len(wrapped))
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
