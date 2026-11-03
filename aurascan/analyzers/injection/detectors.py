"""The default detector set (mirrors ``InjectionDetectorCatalog.cs``, minus the unported classes)."""

from .model import InjectionDetector

__all__ = ["InjectionDetector", "create_default_detectors"]


def create_default_detectors():
    """The registered detectors: override, persona, exfiltration and encoded.

    ``persona-hijack`` and ``data-exfiltration`` are also inner matchers for ``encoded-obfuscated``;
    they are registered here so those surfaces stay reachable on their own too.
    """
    from .encoded import EncodedObfuscatedDetector
    from .exfiltration import DataExfiltrationDetector
    from .override import InstructionOverrideDetector
    from .persona import PersonaHijackDetector

    return [
        InstructionOverrideDetector(),
        PersonaHijackDetector(),
        DataExfiltrationDetector(),
        EncodedObfuscatedDetector(),
    ]
