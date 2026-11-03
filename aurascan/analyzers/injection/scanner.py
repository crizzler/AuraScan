"""Scanner: enabled classes, confidence policy, caps and evidence construction.

Mirrors ``InjectionScanner.cs``. This is the only module that knows a path. Card A keeps the
path-based confidence model only; ``source_type`` (and the pathless ``unknown`` table) belongs to
Card B.

Confidence ladder, in this order (the ordering is load-bearing — step 1 precedes the documentation
downgrade, and the downgrade only ever lowers HIGH):

1. test fixture -> LOW (short-circuits everything else);
2. ``encoded-obfuscated`` -> LOW;
3. ``instruction-override`` + ``override.literal.`` prefix -> HIGH, otherwise MEDIUM;
4. other classes -> MEDIUM;
5. documentation path + HIGH -> MEDIUM.

``_confidence_for`` is module-level on purpose: ``tools/injection_parity.py --selftest`` mutates it
in place for M3.
"""

from pathlib import Path
from typing import List, Optional, Sequence

from . import catalog, injection_text
from .engine import InjectionDetectionEngine, RuleBasedDetectionEngine
from .model import InjectionEvidence, InjectionSettings

LOCKED_MAX_FINDINGS_PER_FILE = 32


class InjectionScanner(object):
    def __init__(self, engine: InjectionDetectionEngine, settings: Optional[InjectionSettings] = None) -> None:
        self._engine = engine
        self._settings = settings if settings is not None else InjectionSettings()

    def scan_target(self, project_relative_path, content):
        results = []
        if not content:
            return results
        if not self._settings.enabled:
            return results

        path = project_relative_path or ""
        if injection_text.is_suppressed(path, self._settings.suppressed_paths):
            return results

        enabled = self._settings.enabled_classes
        if not enabled:
            return results

        matches = self._engine.scan(content, enabled)
        if not matches:
            return results

        ordered = sorted(matches, key=compare_by_position)

        fixture = injection_text.is_test_fixture_path(path)
        documentation = injection_text.is_documentation_path(path)
        cap = self._settings.max_findings_per_file
        if cap <= 0 or cap > LOCKED_MAX_FINDINGS_PER_FILE:
            cap = LOCKED_MAX_FINDINGS_PER_FILE

        cursor = 0
        line = 1
        for match in ordered:
            if len(results) >= cap:
                break
            if match is None:
                continue

            line_number = line_number_at(content, match.start, cursor, line)
            cursor, line = line_number[1], line_number[2]
            severity = severity_for(match)
            confidence = _confidence_for(match, fixture, documentation)

            results.append(
                InjectionEvidence(
                    path,
                    line_number[0],
                    match.class_id,
                    match.detector_id,
                    severity,
                    confidence,
                    match.matched_text or "",
                    match.decoded_text,
                    fixture,
                    describe(match, severity, confidence, fixture),
                )
            )

        return results


def severity_for(match):
    severity = catalog.severity_of(match.class_id)
    if match.class_id == catalog.ENCODED_OBFUSCATED and match.decoded_class_id:
        inner = catalog.severity_of(match.decoded_class_id)
        if _severity_rank(inner) > _severity_rank(severity):
            severity = inner
    return severity


def _severity_rank(value):
    return {"LOW": 1, "MEDIUM": 2, "HIGH": 3}.get(value, 0)


def _confidence_for(match, fixture, documentation):
    if fixture:
        return "LOW"

    class_id = match.class_id
    if class_id == catalog.ENCODED_OBFUSCATED:
        return "LOW"

    if class_id == catalog.INSTRUCTION_OVERRIDE:
        confidence = "HIGH" if match.detector_id.startswith("override.literal.") else "MEDIUM"
    elif class_id in (catalog.PERSONA_HIJACK, catalog.DATA_EXFILTRATION, catalog.TOOL_COMMAND):
        confidence = "MEDIUM"
    else:
        confidence = "LOW"

    if documentation and confidence == "HIGH":
        confidence = "MEDIUM"
    return confidence


def describe(match, severity, confidence, fixture):
    text = (
        catalog.display_name(match.class_id)
        + " signal (rule '"
        + match.detector_id
        + "', "
        + severity
        + " severity, "
        + confidence
        + " confidence)"
        + (" in a test fixture" if fixture else "")
        + "; potential attack text for human review, never proof of an attack."
    )
    if match.decoded_text:
        text += " The decoded text is display-only and was never executed."
    return text


def line_number_at(content, index, cursor, line):
    """1-based line for ``index``. Returns ``(line, cursor, current_line)``."""
    if index < 0:
        index = 0
    if index > len(content):
        index = len(content)
    if index < cursor:
        cursor = 0
        line = 1

    while cursor < index:
        if content[cursor] == "\n":
            line += 1
        cursor += 1

    return line, cursor, line


def compare_by_position(match):
    return (match.start, match.class_id, match.detector_id)


_DEFAULT_ENGINE = None


def _default_engine():
    global _DEFAULT_ENGINE
    if _DEFAULT_ENGINE is None:
        _DEFAULT_ENGINE = RuleBasedDetectionEngine()
    return _DEFAULT_ENGINE


def scan_content(content, path_hint="", enabled_classes=None, max_findings=None, engine=None):
    """Scan text. ``path_hint`` is echoed as the evidence path and drives the path policy."""
    if not isinstance(content, str):
        raise TypeError("content must be str")
    settings = InjectionSettings()
    if enabled_classes is not None:
        settings = InjectionSettings(enabled_classes=tuple(enabled_classes))
    if max_findings is not None:
        settings = InjectionSettings(
            enabled_classes=settings.enabled_classes, max_findings_per_file=max_findings
        )
    instance = InjectionScanner(engine if engine is not None else _default_engine(), settings)
    return instance.scan_target(path_hint, content)


def scan_path(path, enabled_classes=None):
    """Scan a UTF-8 file from disk. The ``str`` of ``path`` is the policy input."""
    target = Path(path)
    text = target.read_text(encoding="utf-8", errors="replace")
    return scan_content(text, path_hint=str(path), enabled_classes=enabled_classes)
