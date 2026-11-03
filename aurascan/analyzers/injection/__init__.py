"""Deterministic prompt-injection signal detection over untrusted text.

Analysis-layer, stdlib-only, raise-only. Text is inspected as bytes-in-a-string: nothing is
executed, fetched, or written while scanning.

Spike scope (Card A): ``instruction-override`` only. The class set, the ported detector and the
confidence ladder are deliberately narrow; ``encoded-obfuscated`` and its inner matchers follow in
Card B, and ``source_type`` replaces the raw path policy there.
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
from .model import InjectionEvidence, InjectionMatch, InjectionSettings
from .scanner import InjectionScanner, scan_content, scan_path

__all__ = [
    "CLASS_IDS",
    "DEFAULT_ENABLED_CLASS_IDS",
    "DATA_EXFILTRATION",
    "ENCODED_OBFUSCATED",
    "INSTRUCTION_OVERRIDE",
    "PERSONA_HIJACK",
    "InjectionDetectionEngine",
    "InjectionDetector",
    "InjectionEvidence",
    "InjectionMatch",
    "InjectionScanner",
    "InjectionSettings",
    "RuleBasedDetectionEngine",
    "create_default_detectors",
    "display_name",
    "normalize",
    "rule_id_for",
    "scan_content",
    "scan_path",
    "severity_of",
    "to_findings",
]
