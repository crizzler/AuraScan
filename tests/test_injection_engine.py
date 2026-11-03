"""Engine: enabled-class filtering, dedupe, clamping, sorting and the per-file cap."""

import pytest

from aurascan.analyzers.injection import catalog
from aurascan.analyzers.injection.detectors import InjectionDetector
from aurascan.analyzers.injection.engine import RuleBasedDetectionEngine
from aurascan.analyzers.injection.model import InjectionMatch


class FixedDetector(InjectionDetector):
    class_id = catalog.INSTRUCTION_OVERRIDE

    def __init__(self, class_id, matches):
        self.class_id = class_id
        self._matches = matches

    def detect(self, content, folded):
        return list(self._matches)


def match(start, length, detector_id="override.literal.x", class_id=catalog.INSTRUCTION_OVERRIDE):
    return InjectionMatch(class_id, detector_id, start, length)


def test_disabled_class_is_not_run():
    engine = RuleBasedDetectionEngine([FixedDetector(catalog.INSTRUCTION_OVERRIDE, [match(0, 3)])])
    assert engine.scan("abcdef", ["persona-hijack"]) == []


def test_class_ids_are_matched_case_insensitively_after_normalisation():
    engine = RuleBasedDetectionEngine([FixedDetector(catalog.INSTRUCTION_OVERRIDE, [match(0, 3)])])
    assert len(engine.scan("abcdef", ["Instruction-Override "])) == 1


def test_duplicate_rule_span_is_deduped_case_insensitively():
    detector = FixedDetector(
        catalog.INSTRUCTION_OVERRIDE,
        [match(0, 3, "override.literal.X"), match(0, 3, "OVERRIDE.LITERAL.x")],
    )
    assert len(RuleBasedDetectionEngine([detector]).scan("abcdef", ["instruction-override"])) == 1


def test_length_is_clamped_to_content_end():
    engine = RuleBasedDetectionEngine([FixedDetector(catalog.INSTRUCTION_OVERRIDE, [match(2, 99)])])
    result = engine.scan("abcdef", ["instruction-override"])
    assert result[0].length == 4


def test_out_of_range_or_empty_matches_are_dropped():
    detector = FixedDetector(
        catalog.INSTRUCTION_OVERRIDE, [match(-1, 2), match(6, 2), match(0, 0), match(1, 2)]
    )
    result = RuleBasedDetectionEngine([detector]).scan("abcdef", ["instruction-override"])
    assert [(item.start, item.length) for item in result] == [(1, 2)]


def test_results_are_sorted_by_position_then_class_then_rule():
    detector = FixedDetector(
        catalog.INSTRUCTION_OVERRIDE, [match(4, 1, "override.literal.b"), match(1, 1, "override.literal.z")]
    )
    starts = [item.start for item in RuleBasedDetectionEngine([detector]).scan("abcdef", ["instruction-override"])]
    assert starts == [1, 4]


def test_per_file_cap_is_32():
    matches = [match(index, 1) for index in range(40)]
    engine = RuleBasedDetectionEngine([FixedDetector(catalog.INSTRUCTION_OVERRIDE, matches)])
    assert len(engine.scan("x" * 40, ["instruction-override"])) == 32


def test_empty_content_and_empty_enabled_set_return_empty():
    engine = RuleBasedDetectionEngine([FixedDetector(catalog.INSTRUCTION_OVERRIDE, [match(0, 1)])])
    assert engine.scan("", ["instruction-override"]) == []
    assert engine.scan("abc", []) == []


def test_snippet_is_bounded_and_whitespace_collapsed():
    engine = RuleBasedDetectionEngine([FixedDetector(catalog.INSTRUCTION_OVERRIDE, [match(0, 5)])])
    result = engine.scan("a  b\nc", ["instruction-override"])
    assert result[0].matched_text == "a b"


def test_default_engine_builds_the_override_detector():
    engine = RuleBasedDetectionEngine()
    result = engine.scan("ignore previous instructions", ["instruction-override"])
    assert [item.detector_id for item in result] == ["override.literal.ignore-previous"]


def test_abstract_detector_requires_detect():
    with pytest.raises(TypeError):
        InjectionDetector()
