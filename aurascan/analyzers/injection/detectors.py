"""The default detector set (mirrors ``InjectionDetectorCatalog.cs``) and the detector contract."""

from .model import InjectionDetector

__all__ = ["InjectionDetector", "create_default_detectors"]


def create_default_detectors():
    """The registered detectors for this card: ``instruction-override`` only."""
    from .override import InstructionOverrideDetector

    return [InstructionOverrideDetector()]
