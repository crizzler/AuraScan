"""Deterministic prompt-injection signal detection over untrusted text.

Analysis-layer, stdlib-only, raise-only. Text is inspected as bytes-in-a-string: nothing is
executed, fetched, or written while scanning.

Spike scope (Card B): ``instruction-override`` and ``encoded-obfuscated`` are the gated pair;
``persona-hijack`` and ``data-exfiltration`` are ported as inner matchers for the encoded class and
reported but never gated. ``source_type`` replaces the raw path policy. Three classes remain
unported (multilingual, tool-command, delimiter-escape) and are never enabled.
"""

from .catalog import (
    CLASS_IDS,
    DEFAULT_ENABLED_CLASS_IDS,
    ENCODED_OBFUSCATED,
    DATA_EXFILTRATION,
    INSTRUCTION_OVERRIDE,
    PERSONA_HIJACK,
    display_name,
    normalize,
    rule_id_for,
    severity_of,
)
from .detectors import InjectionDetector, create_default_detectors
from .engine import InjectionDetectionEngine, RuleBasedDetectionEngine
from .findings import to_findings
from .model import SOURCE_TYPES, InjectionEvidence, InjectionMatch, InjectionSettings
from .scanner import InjectionScanner, derive_source_type, scan_content, scan_path

__all__ = [
    "CLASS_IDS",
    "DEFAULT_ENABLED_CLASS_IDS",
    "DATA_EXFILTRATION",
    "ENCODED_OBFUSCATED",
    "INSTRUCTION_OVERRIDE",
    "PERSONA_HIJACK",
    "SOURCE_TYPES",
    "InjectionDetectionEngine",
    "InjectionDetector",
    "InjectionEvidence",
    "InjectionMatch",
    "InjectionScanner",
    "InjectionSettings",
    "RuleBasedDetectionEngine",
    "create_default_detectors",
    "derive_source_type",
    "display_name",
    "normalize",
    "rule_id_for",
    "scan_content",
    "scan_path",
    "severity_of",
    "to_findings",
]
