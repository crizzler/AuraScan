#!/usr/bin/env python3
"""Acceptance harness for the reverse-AntiCopy ``instruction-override`` spike (dev tool).

Three modes:

* ``--report``  run the metric pass, print the table, write the evidence JSON;
* ``--gate``    re-derive the corpus hash from the retained raw tree, re-anchor the golden to the
  live AntiCopy HEAD, then gate every row; exits ``0`` only when every delta is zero;
* ``--selftest`` apply each mutant to the *production* module through a restoring context manager,
  run the full metric pass, and print the **measured** mutated value next to expected/actual.

Exit codes: ``0`` pass, ``2`` metric delta, ``3`` corpus drift, ``4`` golden mismatch, ``5`` shape or
enabled-set mismatch, ``6`` inert mutant.

Anti-cheat properties, in the order they matter:

1. the corpus is re-derived from ``tests/fixtures/injection_corpus/raw/`` on every gated run and
   compared to the pinned hash *before* the first metric;
2. the golden header carries the AntiCopy HEAD it was generated from and ``--gate`` compares that to
   the live ``rev-parse HEAD``;
3. ``--selftest`` prints numbers produced by the metric pass, never constants, and each mutant goes
   through the same comparison function as ``--gate``;
4. mutants patch module-level constants / ``_confidence_for`` on the production modules, so the
   detector is graded, not a copy of it.
"""

import argparse
import contextlib
import json
import os
import subprocess
import sys
from collections import OrderedDict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from aurascan.analyzers.injection import catalog, injection_text, scanner  # noqa: E402
from aurascan.analyzers.injection.engine import RuleBasedDetectionEngine  # noqa: E402
from aurascan.analyzers.injection.model import InjectionSettings  # noqa: E402
from aurascan.analyzers.injection import override  # noqa: E402

import injection_corpus_export as exporter  # noqa: E402

ENABLED_CLASSES = (catalog.INSTRUCTION_OVERRIDE,)

EXIT_PASS = 0
EXIT_METRIC = 2
EXIT_CORPUS = 3
EXIT_GOLDEN = 4
EXIT_SHAPE = 5
EXIT_SELFTEST = 6

FIXTURES = os.path.join(ROOT, "tests", "fixtures")
CORPUS_DIR = os.path.join(FIXTURES, "injection_corpus")
RAW = os.path.join(CORPUS_DIR, "raw")
HARVEST = os.path.join(CORPUS_DIR, "harvest.json")
GOLDEN = os.path.join(FIXTURES, "injection_golden", "spans.json")
EVIDENCE = os.path.join(ROOT, "SPIKE-A-evidence.json")

ANTICOPY = os.environ.get("ANTICOPY_ROOT", "/home/arawn/Unity Projects/AntiCopy")

# The gate table. ``gated=False`` rows are printed, never compared.
EXPECTED = (
    ("corpus.samples_total", 550, True),
    ("corpus.injection", 240, True),
    ("corpus.benign", 310, True),
    ("corpus.class.instruction-override", 50, True),
    ("corpus.class.encoded-obfuscated", 50, True),
    ("corpus.class.persona-hijack", 40, True),
    ("corpus.class.data-exfiltration", 40, True),
    ("corpus.class.multilingual", 40, True),
    ("corpus.class.tool-command", 10, True),
    ("corpus.class.delimiter-escape", 10, True),
    ("enabled_classes", "instruction-override", True),
    ("override.tp", 45, True),
    ("override.fp_non_fixture", 12, True),
    ("override.matches", 45, True),
    ("override.recall", "0.900", True),
    ("override.precision", "0.789", True),
    ("benign.medium_plus_files", 12, True),
    ("benign.high_findings", 0, True),
    ("golden.sample_mismatches", 0, True),
    ("report.override.samples", 50, False),
    ("report.benign.files", 310, False),
)

ROW_ORDER = [name for name, _, _ in EXPECTED]
GATED = dict((name, gated) for name, _, gated in EXPECTED)
EXPECTED_VALUE = dict((name, value) for name, value, _ in EXPECTED)


class Sample(object):
    __slots__ = ("class_id", "path", "content")

    def __init__(self, class_id, path, content):
        self.class_id = class_id
        self.path = path
        self.content = content


# --------------------------------------------------------------------------- corpus


def load_corpus():
    samples, benign = exporter.derive_records(RAW)
    injections = [Sample(record["class"], record["path"], record["content"]) for record in samples]
    controls = [Sample(None, record["path"], record["content"]) for record in benign]
    return injections, controls


def git(*args):
    result = subprocess.run(
        ["git", "-C", ANTICOPY] + list(args), stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
    )
    return result.returncode, result.stdout.decode("utf-8", "replace").strip()


# --------------------------------------------------------------------------- metrics


def _scan(content, path):
    settings = InjectionSettings(enabled_classes=ENABLED_CLASSES)
    return scanner.InjectionScanner(ENGINE, settings).scan_target(path, content)


ENGINE = RuleBasedDetectionEngine()


def measure(injections, controls, golden):
    rows = OrderedDict()
    class_counts = {}
    for sample in injections:
        class_counts[sample.class_id] = class_counts.get(sample.class_id, 0) + 1

    rows["corpus.samples_total"] = len(injections) + len(controls)
    rows["corpus.injection"] = len(injections)
    rows["corpus.benign"] = len(controls)
    for class_id in catalog.CLASS_IDS:
        rows["corpus.class." + class_id] = class_counts.get(class_id, 0)

    rows["enabled_classes"] = ",".join(ENABLED_CLASSES)

    for class_id in ENABLED_CLASSES:
        label = "override" if class_id == catalog.INSTRUCTION_OVERRIDE else class_id
        detected = 0
        matches = 0
        for sample in injections:
            if sample.class_id != class_id:
                continue
            found = [item for item in _scan(sample.content, sample.path) if item.class_id == class_id]
            if found:
                detected += 1
            matches += len(found)
        rows[label + ".tp"] = detected
        rows[label + ".matches"] = matches
        rows[label + ".recall"] = "%.3f" % (float(detected) / class_counts.get(class_id, 1))

    fp_non_fixture = 0
    medium_plus_files = 0
    high_findings = 0
    for sample in controls:
        evidence = _scan(sample.content, sample.path)
        if any(item.class_id == catalog.INSTRUCTION_OVERRIDE and not item.test_fixture_context for item in evidence):
            fp_non_fixture += 1
        if any(item.confidence in ("MEDIUM", "HIGH") for item in evidence):
            medium_plus_files += 1
        high_findings += sum(1 for item in evidence if item.confidence == "HIGH")

    if catalog.INSTRUCTION_OVERRIDE in ENABLED_CLASSES:
        detected = rows["override.tp"]
        rows["override.fp_non_fixture"] = fp_non_fixture
        rows["override.precision"] = "%.3f" % (float(detected) / (detected + fp_non_fixture)) if (detected + fp_non_fixture) else "1.000"

    rows["benign.medium_plus_files"] = medium_plus_files
    rows["benign.high_findings"] = high_findings
    rows["report.override.samples"] = class_counts.get(catalog.INSTRUCTION_OVERRIDE, 0)
    rows["report.benign.files"] = len(controls)

    mismatches, paths = compare_golden(injections + controls, golden)
    rows["golden.sample_mismatches"] = mismatches

    ordered = OrderedDict()
    for name in ROW_ORDER:
        ordered[name] = rows.get(name)
    differing = {}
    if paths:
        differing["golden.sample_mismatches"] = paths
    return ordered, differing


def compare_golden(samples, golden):
    """Per-sample tuple + confidence equality against the C#-generated golden."""
    by_path = dict((record["path"], record) for record in golden["samples"])
    mismatches = 0
    paths = []
    seen = set()
    for sample in samples:
        record = by_path.get(sample.path)
        if record is None:
            mismatches += 1
            paths.append(sample.path + " (absent from golden)")
            continue
        seen.add(sample.path)

        expected_hits = [
            (hit["class"], hit["detector_id"], hit["start"], hit["length"]) for hit in record["hits"]
        ]
        found = ENGINE.scan(sample.content, ENABLED_CLASSES)
        actual_hits = [(item.class_id, item.detector_id, item.start, item.length) for item in found]

        fixture = injection_text.is_test_fixture_path(sample.path)
        documentation = injection_text.is_documentation_path(sample.path)
        actual_confidence = scanner._confidence_for(found[0], fixture, documentation) if found else None
        unknown_confidence = (
            scanner._confidence_for(found[0], False, False) if found else None
        )

        if (
            actual_hits != expected_hits
            or actual_confidence != record["confidence"]
            or unknown_confidence != record["confidence_unknown"]
        ):
            mismatches += 1
            paths.append(sample.path)

    for control_path in sorted(set(by_path) - seen):
        mismatches += 1
        paths.append(control_path + " (absent from corpus)")
    return mismatches, paths


# --------------------------------------------------------------------------- comparison


def _delta(expected, actual):
    if actual is None or expected is None:
        return "n/a"
    try:
        return "%+g" % (float(actual) - float(expected))
    except (TypeError, ValueError):
        return "match" if actual == expected else "!= " + str(expected)


def compare_rows(actual_rows, differing, only=None):
    """The single comparison function shared by ``--gate`` and ``--selftest``.

    Returns ``(lines, code)`` where every line is ``metric, expected, actual, delta, paths``.
    Precedence when several rows fail: shape (5) > golden (4) > metric (2).
    """
    lines = []
    failures = []
    for name in ROW_ORDER:
        if only is not None and name not in only:
            continue
        expected = EXPECTED_VALUE[name]
        actual = actual_rows.get(name)
        delta = _delta(expected, actual)
        paths = differing.get(name, [])
        lines.append(
            "%s, expected=%s, actual=%s, delta=%s, paths=%s"
            % (name, expected, actual, delta, ",".join(paths[:10]))
        )
        if GATED[name] and actual != expected:
            failures.append(name)

    code = EXIT_PASS
    if failures:
        if any(name.startswith("corpus.") or name == "enabled_classes" for name in failures):
            code = EXIT_SHAPE
        elif any(name == "golden.sample_mismatches" for name in failures):
            code = EXIT_GOLDEN
        else:
            code = EXIT_METRIC
    return lines, code


def print_table(actual_rows, differing, only=None):
    for name in ROW_ORDER:
        if only is not None and name not in only:
            continue
        expected = EXPECTED_VALUE[name]
        actual = actual_rows.get(name)
        delta = _delta(expected, actual)
        paths = ",".join(differing.get(name, [])[:10])
        flag = "" if not GATED[name] else (" PASS" if actual == expected else " FAIL")
        print(
            "%-34s expected=%-18s actual=%-18s delta=%-6s paths=%s%s"
            % (name, expected, actual, delta, paths, "" if GATED[name] else "  (reported only)")
        )


# --------------------------------------------------------------------------- mutants


@contextlib.contextmanager
def _patch(module, name, value):
    original = getattr(module, name)
    setattr(module, name, value)
    try:
        yield
    finally:
        setattr(module, name, original)


@contextlib.contextmanager
def mutant_drop_literal_16():
    """M1: drop ``ignore everything above`` and its id from the literal table."""
    phrases = list(override.LITERAL_PHRASES)
    ids = list(override.LITERAL_IDS)
    del phrases[16]
    del ids[16]
    with _patch(override, "LITERAL_PHRASES", tuple(phrases)):
        with _patch(override, "LITERAL_IDS", tuple(ids)):
            yield


@contextlib.contextmanager
def mutant_no_overlap():
    """M2: ``Overlaps()`` always false, so a literal and its regex twin both report."""
    with _patch(override, "_overlaps", lambda matches, index, length: False):
        yield


@contextlib.contextmanager
def mutant_confidence_order():
    """M3: the documentation downgrade runs *before* the literal->High step."""

    def swapped(match, fixture, documentation):
        if fixture:
            return "LOW"
        if match.class_id == catalog.ENCODED_OBFUSCATED:
            return "LOW"
        confidence = "MEDIUM" if documentation else "LOW"
        if match.class_id == catalog.INSTRUCTION_OVERRIDE:
            return "HIGH" if match.detector_id.startswith("override.literal.") else "MEDIUM"
        if match.class_id in (catalog.PERSONA_HIJACK, catalog.DATA_EXFILTRATION, catalog.TOOL_COMMAND):
            return "MEDIUM"
        return confidence

    with _patch(scanner, "_confidence_for", swapped):
        yield


@contextlib.contextmanager
def mutant_drop_forget():
    """M4: drop the ``forget`` verb from the stem family."""
    pattern = override.STEM_FAMILY_PATTERN.replace("(?:ignore|disregard|forget)", "(?:ignore|disregard)")
    with _patch(override, "STEM_FAMILY_PATTERN", pattern):
        with _patch(override, "STEM_FAMILY", __import__("re").compile(pattern)):
            yield


@contextlib.contextmanager
def mutant_inert():
    """A mutant that changes nothing: the exit-6 path is exercised with it in the test suite."""
    with _patch(override, "LITERAL_PHRASES", tuple(override.LITERAL_PHRASES)):
        yield


MUTANTS = (
    {
        "name": "M1",
        "what": "drop LiteralPhrases[16]",
        "factory": mutant_drop_literal_16,
        "expected": {"override.tp": 43, "override.matches": 43},
        "derived": {"override.recall", "override.precision", "golden.sample_mismatches"},
    },
    {
        "name": "M2",
        "what": "Overlaps() returns false",
        "factory": mutant_no_overlap,
        "expected": {"override.matches": 65},
        "derived": {"golden.sample_mismatches"},
    },
    {
        "name": "M3",
        "what": "confidence order swapped",
        "factory": mutant_confidence_order,
        "expected": {"benign.high_findings": 12},
        "derived": {"golden.sample_mismatches"},
    },
    {
        "name": "M4",
        "what": "drop forget from StemFamily",
        "factory": mutant_drop_forget,
        "expected": {"override.tp": 41, "override.matches": 41},
        "derived": {"override.recall", "override.precision", "golden.sample_mismatches"},
    },
)


def run_selftest(injections, controls, golden, extra_mutants=()):
    """Baseline must reproduce, then every mutant must bite with the pinned delta.

    ``derived`` names the rows a mutant is allowed to move *because* its target moved (a ratio of a
    changed count, or the frozen-golden comparison). Any other gated row moving is a failure.
    """
    baseline, baseline_diff = measure(injections, controls, golden)
    lines, code = compare_rows(baseline, baseline_diff)
    if code != EXIT_PASS:
        print("baseline does not reproduce; mutants would grade the wrong thing")
        print_table(baseline, baseline_diff)
        return EXIT_SELFTEST

    print("baseline reproduces the gate exactly")

    failed = []
    for mutant in tuple(MUTANTS) + tuple(extra_mutants):
        name = mutant["name"]
        expected = mutant["expected"]
        derived = mutant.get("derived", set())

        with mutant["factory"]():
            mutated, mutated_diff = measure(injections, controls, golden)

        print("%s %s:" % (name, mutant["what"]))
        bit = True
        for metric in expected:
            bitten = mutated.get(metric) == expected[metric]
            if not bitten:
                bit = False
            print(
                "  %s expected=%s actual=%s delta=%s %s"
                % (
                    metric,
                    baseline.get(metric),
                    mutated.get(metric),
                    _delta(baseline.get(metric), mutated.get(metric)),
                    "BIT (measured)" if bitten else "INERT",
                )
            )

        collateral = [
            metric
            for metric in ROW_ORDER
            if GATED[metric]
            and metric not in expected
            and metric not in derived
            and mutated.get(metric) != baseline.get(metric)
        ]
        observed_derived = sorted(metric for metric in derived if mutated.get(metric) != baseline.get(metric))
        if observed_derived:
            print("  also moved (derived): " + ", ".join(observed_derived))
        if collateral:
            bit = False
            print("  unexpected movement: " + ", ".join(collateral))

        if not expected:
            moved = [metric for metric in ROW_ORDER if GATED[metric] and mutated.get(metric) != baseline.get(metric)]
            if not moved:
                bit = False
                print("  inert mutant moved nothing, so it proves nothing")
            else:
                print("  bit: " + ", ".join(moved))

        if not bit:
            failed.append(name)
        print("  -> %s" % ("PASS" if bit else "FAIL"))

    if failed:
        print("selftest FAILED: " + ", ".join(failed))
        return EXIT_SELFTEST
    print("selftest PASSED: all mutants bit with the pinned delta")
    return EXIT_PASS


# --------------------------------------------------------------------------- modes


def check_anchors():
    """Corpus and golden anchors. Returns an exit code (0 when both hold)."""
    if not os.path.exists(HARVEST):
        print("corpus drift: harvest.json missing")
        return EXIT_CORPUS

    with open(HARVEST, "r", encoding="utf-8") as handle:
        harvest = json.load(handle)
    harvest_sha = harvest.get("anticopy_head")

    code, status = git("status", "--porcelain")
    if code != 0:
        print("corpus drift: git status failed in " + ANTICOPY)
        return EXIT_CORPUS
    if status:
        print("corpus drift: AntiCopy checkout is dirty:\n" + status)
        return EXIT_CORPUS

    code, head = git("rev-parse", "HEAD")
    if head != harvest_sha:
        print("corpus drift: harvest head %s but live head %s" % (harvest_sha, head))
        return EXIT_CORPUS

    pinned = exporter.pinned_sha256()
    derived = exporter.sha256_bytes(exporter.derive_bytes(RAW, harvest_sha))
    print("corpus.sha256 harvest=%s gate=%s %s" % (pinned, derived, "MATCH" if pinned == derived else "DRIFT"))
    if pinned != derived:
        return EXIT_CORPUS

    with open(GOLDEN, "r", encoding="utf-8") as handle:
        golden = json.load(handle)
    print("golden.anticopy_head=%s live=%s %s" % (golden["anticopy_head"], head, "MATCH" if golden["anticopy_head"] == head else "MISMATCH"))
    if golden["anticopy_head"] != head:
        print("golden is anchored to a different AntiCopy commit; regenerate it")
        return EXIT_GOLDEN
    if tuple(golden["enabled_classes"]) != ENABLED_CLASSES:
        print("golden enabled set %s != %s" % (golden["enabled_classes"], ENABLED_CLASSES))
        return EXIT_SHAPE
    return EXIT_PASS


def load_golden():
    with open(GOLDEN, "r", encoding="utf-8") as handle:
        return json.load(handle)


def write_evidence(rows, differing, corpus_pinned, corpus_gate, golden_sha):
    payload = OrderedDict()
    payload["generated_at_utc"] = __import__("datetime").datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    payload["anticopy_head"] = git("rev-parse", "HEAD")[1]
    payload["enabled_classes"] = list(ENABLED_CLASSES)
    payload["corpus_sha256"] = corpus_pinned
    payload["corpus_sha256_at_gate"] = corpus_gate
    payload["golden_sha256"] = golden_sha
    payload["tables_sha256"] = tables_sha256()
    payload["table"] = [
        OrderedDict(
            (
                ("metric", name),
                ("expected", EXPECTED_VALUE[name]),
                ("actual", rows.get(name)),
                ("delta", _delta(EXPECTED_VALUE[name], rows.get(name))),
                ("gated", GATED[name]),
                ("differing_paths", differing.get(name, [])[:50]),
            )
        )
        for name in ROW_ORDER
    ]
    with open(EVIDENCE, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")
    return EVIDENCE


def tables_sha256():
    """Hash over the detector tables and the confidence ladder — freeze before the first gate run."""
    import hashlib

    digest = hashlib.sha256()
    for block in (
        override.LITERAL_IDS,
        override.LITERAL_PHRASES,
        (override.STEM_FAMILY_PATTERN,),
        (injection_text.MAX_SNIPPET_LENGTH, injection_text.MAX_DECODED_LENGTH,
         injection_text.PAIR_WINDOW, injection_text.MAX_MATCHES_PER_DETECTOR),
    ):
        for item in block:
            digest.update(str(item).encode("utf-8"))
            digest.update(b"\n")
    digest.update(open(scanner.__file__, "rb").read())
    return digest.hexdigest()


def golden_sha256():
    import hashlib

    with open(GOLDEN, "rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", action="store_true", help="write the evidence file")
    parser.add_argument("--gate", action="store_true", help="gate the metric table")
    parser.add_argument("--selftest", action="store_true", help="run the mutant selftest")
    args = parser.parse_args(argv)

    if not (args.report or args.gate or args.selftest):
        parser.print_help()
        return EXIT_SHAPE

    injections, controls = load_corpus()
    golden = load_golden()

    if args.selftest:
        return run_selftest(injections, controls, golden)

    if args.gate:
        anchor = check_anchors()
        if anchor != EXIT_PASS:
            return anchor

    rows, differing = measure(injections, controls, golden)
    print_table(rows, differing)

    if args.report:
        path = write_evidence(rows, differing, exporter.pinned_sha256(), exporter.sha256_bytes(
            exporter.derive_bytes(RAW)), golden_sha256())
        print("evidence written: " + os.path.relpath(path, ROOT))

    if not args.gate:
        return EXIT_PASS

    lines, code = compare_rows(rows, differing)
    if code == EXIT_PASS:
        print("GATE PASSED")
    else:
        print("GATE FAILED (exit %d)" % code)
    return code


if __name__ == "__main__":
    sys.exit(main())
