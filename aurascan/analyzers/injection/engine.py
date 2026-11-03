"""Engine seam and the only shipped implementation (mirrors ``RuleBasedDetectionEngine.cs``).

The seam sits below all path/policy knowledge and above the detectors: confidence and fixture
tagging live in the scanner, exactly as in the original. A future offline model engine implements
``scan()`` and nothing else changes.
"""

from abc import ABC, abstractmethod
from typing import List, Sequence

from . import catalog, injection_text
from .model import InjectionMatch


class InjectionDetectionEngine(ABC):
    @abstractmethod
    def scan(self, content: str, enabled_class_ids: Sequence[str]) -> List[InjectionMatch]:
        """Run the enabled detectors over one text and return bounded, deduplicated matches."""


class RuleBasedDetectionEngine(InjectionDetectionEngine):
    MAX_MATCHES_PER_FILE = 32

    def __init__(self, detectors: Sequence[object] = None) -> None:
        if detectors is None:
            from .detectors import create_default_detectors

            detectors = create_default_detectors()
        self._detectors = [detector for detector in detectors if detector is not None]

    def scan(self, content, enabled_class_ids):
        results = []
        if not content or not enabled_class_ids:
            return results

        enabled = set()
        for class_id in enabled_class_ids:
            if class_id:
                enabled.add(catalog.normalize(class_id))
        if not enabled:
            return results

        folded = injection_text.fold(content)

        # Detector ids compare case-insensitively: "CustomRule" and "customrule" are the same rule and
        # must not produce a duplicate finding at the same span (C# F7 review note).
        seen = set()
        for detector in self._detectors:
            if catalog.normalize(detector.class_id) not in enabled:
                continue

            found = detector.detect(content, folded)
            if not found:
                continue

            for match in found:
                if match is None:
                    continue
                if match.start < 0 or match.start >= len(content):
                    continue

                length = match.length
                if length <= 0:
                    continue
                if match.start + length > len(content):
                    length = len(content) - match.start

                class_id = catalog.normalize(match.class_id)
                key = "%s|%s|%d|%d" % (class_id, match.detector_id.lower(), match.start, length)
                if key in seen:
                    continue
                seen.add(key)

                snippet = match.matched_text or content[match.start:match.start + length]
                decoded = (
                    injection_text.bound(match.decoded_text, injection_text.MAX_DECODED_LENGTH)
                    if match.decoded_text
                    else None
                )

                results.append(
                    InjectionMatch(
                        class_id,
                        match.detector_id,
                        match.start,
                        length,
                        injection_text.bound(snippet, injection_text.MAX_SNIPPET_LENGTH),
                        decoded,
                        match.decoded_class_id,
                    )
                )

        results.sort(key=compare_by_position)
        if len(results) > self.MAX_MATCHES_PER_FILE:
            del results[self.MAX_MATCHES_PER_FILE:]
        return results


def compare_by_position(match):
    return (match.start, match.class_id, match.detector_id)
