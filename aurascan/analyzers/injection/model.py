"""Frozen value objects mirrored from ``InjectionMatch.cs``/``InjectionEvidence.cs`` plus the detector
contract.

The ``InjectionDetector`` ABC lives here rather than in ``detectors.py`` so that ``override.py`` can
subclass it without ``detectors.py`` (which imports the concrete detectors to build the default set)
importing it back. That keeps ``analyzers.injection`` free of an import cycle.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Literal, Optional, Tuple

from . import catalog

# Where the scanned text came from (Card B). ``unknown`` deliberately behaves like ``source``: that is
# what the original does for a pathless scan, and making it safer would break fidelity.
SourceType = Literal["documentation", "fixture", "source", "unknown"]

SOURCE_TYPES = ("documentation", "fixture", "source", "unknown")


@dataclass(frozen=True)
class InjectionMatch:
    """Raw text match before policy. Offsets are code-point offsets into the scanned text."""

    class_id: str
    detector_id: str
    start: int
    length: int
    matched_text: str = ""
    decoded_text: Optional[str] = None
    decoded_class_id: Optional[str] = None


@dataclass(frozen=True)
class InjectionEvidence:
    """One signal for the report; describes matched text, never an accusation."""

    path: str
    line: int
    class_id: str
    detector_id: str
    severity: str
    confidence: str
    matched_text: str
    decoded_text: Optional[str]
    test_fixture_context: bool
    description: str


@dataclass(frozen=True)
class InjectionSettings:
    enabled: bool = True
    enabled_classes: Tuple[str, ...] = catalog.DEFAULT_ENABLED_CLASS_IDS
    max_findings_per_file: int = 32
    suppressed_paths: Tuple[str, ...] = ()


class InjectionDetector(ABC):
    """One detector per class. Deterministic and pure: ``detect`` is a function of its arguments.

    ``content`` is the raw text; ``folded`` is the same text after a length-preserving fold, so spans
    computed on ``folded`` index into ``content`` directly.
    """

    class_id = ""
    severity = "LOW"

    @abstractmethod
    def detect(self, content, folded):
        """Return ``InjectionMatch`` objects for this class."""
