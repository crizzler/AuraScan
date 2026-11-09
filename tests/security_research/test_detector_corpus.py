"""Deterministic regression harness for the public Daybreak detector corpus.

The corpus is inert data. Every fixture is copied into ``tmp_path`` and read as
text by the existing analyzers; nothing here executes package code, install
hooks, npm lifecycle scripts, a shell, a package manager, or a network client.
No test writes outside ``tmp_path``.

Expected outcomes in ``manifest.json`` are tied to real rule IDs from
``aurascan.core.rule_metadata`` and to an explicit ``NO_FINDING`` or
``INCOMPLETE`` classification. A clean report is asserted only where the
manifest declares a benign control; an incomplete inspection is asserted as
incomplete, never as clean.

Run the per-case metrics report with::

    .venv/bin/python tests/security_research/test_detector_corpus.py
"""

import hashlib
import json
from pathlib import Path
import shutil
import tempfile

import pytest

from aurascan.analyzers.deterministic import DeterministicAnalyzer
from aurascan.analyzers.npm_install_audit import audit_npm_install
from aurascan.analyzers.source_metadata import SourceMetadataAnalyzer
from aurascan.core.install_hook import capture_package_scan_input
from aurascan.core.rule_metadata import RULE_METADATA


REPO_ROOT = Path(__file__).resolve().parents[2]
CORPUS_ROOT = REPO_ROOT / "security-research" / "testing" / "corpus"
MANIFEST_PATH = CORPUS_ROOT / "manifest.json"
SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def load_manifest():
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def corpus_cases():
    return load_manifest()["cases"]


def case_ids():
    return [case["id"] for case in corpus_cases()]


def fixture_files(case):
    return [(CORPUS_ROOT / item["path"], item["sha256"]) for item in case["files"]]


def copy_case_inputs(case, destination):
    """Copy one case's fixture tree into the test's temporary directory.

    The analyzers then read the copy, so no test can mutate the committed
    corpus and any accidental write lands under ``tmp_path``.
    """

    relative = Path(case["files"][0]["path"])
    parents = {Path(item["path"]).parent for item in case["files"]}
    assert parents == {relative.parent}, f"{case['id']}: fixture files span directories"
    source = CORPUS_ROOT / relative.parent
    work = destination / case["id"]
    shutil.copytree(source, work)
    return work


def scan_case(case, work):
    scanner = case["scanner"]
    if scanner == "deterministic_pkgbuild":
        path = work / "PKGBUILD"
        text = path.read_text(encoding="utf-8")
        return DeterministicAnalyzer().analyze_pkgbuild(str(path), text).findings
    if scanner == "source_metadata":
        path = work / "PKGBUILD"
        text = path.read_text(encoding="utf-8")
        return SourceMetadataAnalyzer().analyze_pkgbuild(str(path), text).findings
    if scanner == "install_hook":
        captured = capture_package_scan_input(work / "PKGBUILD")
        assert captured.install_hook.inspectable, "declared hook must be inspectable"
        return DeterministicAnalyzer().analyze_install_script(
            str(captured.install_hook.path),
            captured.install_hook.content,
        ).findings
    if scanner == "npm_install_audit":
        manifest_path = work / "package.json"
        captured = {
            str(work / name): (work / name).read_text(encoding="utf-8")
            for name in case.get("entry_files", [])
        }
        return audit_npm_install(
            str(manifest_path),
            manifest_path.read_text(encoding="utf-8"),
            captured,
        )
    pytest.fail(f"unknown corpus scanner {scanner!r} in {case['id']}")


def classification_passed(case, classification):
    expected = case["expected"]
    if classification["actual_rules"] != sorted(expected["rule_ids"]):
        return False
    if not set(classification["actual_rules"]).isdisjoint(expected["absent_rule_ids"]):
        return False
    min_severity = expected["min_severity"]
    if min_severity is not None:
        if classification["severity"] is None:
            return False
        if SEVERITY_ORDER[classification["severity"]] < SEVERITY_ORDER[min_severity]:
            return False
    return (
        classification["blocking"] == expected["blocking"]
        and classification["manual_review"] == expected["manual_review"]
        and classification["phases"] == sorted(expected["phases"])
    )


def classify(case, findings):
    """Return a secret-free classification tuple for the report."""

    expected = case["expected"]
    actual_rules = sorted(finding.rule_id for finding in findings)
    severity = max(
        (finding.severity.value for finding in findings),
        key=lambda value: SEVERITY_ORDER[value],
        default=None,
    )
    result = {
        "id": case["id"],
        "family": case["family"],
        "role": case["role"],
        "expected_outcome": expected["outcome"],
        "actual_rules": actual_rules,
        "severity": severity,
        "blocking": any(finding.blocks_installation for finding in findings),
        "manual_review": any(finding.requires_manual_review for finding in findings),
        "phases": sorted({finding.phase.value for finding in findings}),
    }
    result["passed"] = classification_passed(case, result)
    return result


def assert_case_classification(case, findings):
    expected = case["expected"]
    actual = {finding.rule_id for finding in findings}

    # Exact equality, not a subset: an unexpected rule on a benign control is a
    # false positive and an unexpected rule on a malicious case is a
    # classification drift that the benchmark must surface.
    assert actual == set(expected["rule_ids"]), (
        f"{case['id']}: expected rules {sorted(expected['rule_ids'])}, "
        f"got {sorted(actual)}"
    )
    assert actual.isdisjoint(expected["absent_rule_ids"]), (
        f"{case['id']}: fired rules that must stay absent: "
        f"{sorted(actual & set(expected['absent_rule_ids']))}"
    )

    outcome = expected["outcome"]
    if outcome == "NO_FINDING":
        assert findings == [], f"{case['id']}: benign control produced findings"
    else:
        assert findings, f"{case['id']}: expected a classification, got a clean report"
    if outcome == "INCOMPLETE":
        assert not any(finding.blocks_installation for finding in findings), (
            f"{case['id']}: incomplete coverage must not block as a confirmed finding"
        )
        assert all(finding.requires_manual_review for finding in findings), (
            f"{case['id']}: incomplete coverage must be marked for manual review"
        )

    min_severity = expected["min_severity"]
    if min_severity is not None:
        assert findings, f"{case['id']}: no severity to compare against {min_severity}"
        assert SEVERITY_ORDER[max(
            (finding.severity.value for finding in findings),
            key=lambda value: SEVERITY_ORDER[value],
        )] >= SEVERITY_ORDER[min_severity], (
            f"{case['id']}: severity below expected floor {min_severity}"
        )
    assert any(finding.blocks_installation for finding in findings) is expected["blocking"], (
        f"{case['id']}: blocking classification changed"
    )
    assert any(finding.requires_manual_review for finding in findings) is expected["manual_review"], (
        f"{case['id']}: manual-review classification changed"
    )
    assert sorted({finding.phase.value for finding in findings}) == sorted(expected["phases"]), (
        f"{case['id']}: evidence phase changed"
    )


@pytest.mark.parametrize("case", corpus_cases(), ids=case_ids())
def test_corpus_case(case, tmp_path):
    for path, expected_sha256 in fixture_files(case):
        assert path.is_file(), f"{case['id']}: missing fixture {path}"
        actual_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
        assert actual_sha256 == expected_sha256, (
            f"{case['id']}: fixture bytes changed for {path.name}"
        )
    work = copy_case_inputs(case, tmp_path)
    findings = scan_case(case, work)
    assert_case_classification(case, findings)


def test_manifest_identifiers_are_unique_and_rules_are_real():
    cases = corpus_cases()
    identifiers = case_ids()
    assert len(identifiers) == len(set(identifiers)), "duplicate corpus case id"

    outcomes = {"FINDING", "NO_FINDING", "INCOMPLETE"}
    roles = {"malicious-intent", "benign-control", "coverage"}
    scanners = {
        "deterministic_pkgbuild",
        "source_metadata",
        "install_hook",
        "npm_install_audit",
    }
    for case in cases:
        assert case["expected"]["outcome"] in outcomes, f"{case['id']}: bad outcome"
        assert case["role"] in roles, f"{case['id']}: bad role"
        assert case["scanner"] in scanners, f"{case['id']}: bad scanner"
        if case["expected"]["outcome"] == "NO_FINDING":
            assert case["expected"]["rule_ids"] == [], (
                f"{case['id']}: a clean outcome cannot expect rules"
            )
        assert case["files"], f"{case['id']}: no fixture files"

    referenced = set()
    for case in cases:
        referenced.update(case["expected"]["rule_ids"])
        referenced.update(case["expected"]["absent_rule_ids"])
    unknown = sorted(referenced - set(RULE_METADATA))
    assert unknown == [], f"corpus references unknown rule ids: {unknown}"


def test_manifest_pairs_every_family_with_controls():
    cases = corpus_cases()
    families = {case["family"] for case in cases}
    for family in families:
        roles = {case["role"] for case in cases if case["family"] == family}
        assert "malicious-intent" in roles, f"{family}: no malicious-intent case"
        assert "benign-control" in roles, f"{family}: no benign-control case"


def collect_results():
    """Scan every case in a private temporary root and classify the result."""

    results = []
    with tempfile.TemporaryDirectory(prefix="aurascan-corpus-") as temporary:
        root = Path(temporary)
        for case in corpus_cases():
            work = copy_case_inputs(case, root)
            results.append(classify(case, scan_case(case, work)))
    return results


def metrics(results):
    malicious = [item for item in results if item["role"] == "malicious-intent"]
    benign = [item for item in results if item["role"] == "benign-control"]
    detected = [item for item in malicious if item["passed"]]
    by_family = {}
    for item in benign:
        family = by_family.setdefault(item["family"], {"total": 0, "clean": 0})
        family["total"] += 1
        family["clean"] += 1 if item["passed"] else 0
    return {
        "corpus_version": load_manifest()["corpus_version"],
        "cases": len(results),
        "detection_rate": (len(detected), len(malicious)),
        "false_negative_rate": (len(malicious) - len(detected), len(malicious)),
        "false_positive_by_family": {
            family: (values["total"] - values["clean"], values["total"])
            for family, values in sorted(by_family.items())
        },
        "regression_rate": "not_measured: no prior corpus release",
    }


def main():
    results = collect_results()
    for item in results:
        print(
            f"{item['id']} family={item['family']} role={item['role']} "
            f"expected={item['expected_outcome']} actual_rules={item['actual_rules']} "
            f"severity={item['severity']} blocking={item['blocking']} "
            f"manual_review={item['manual_review']}"
        )
    summary = metrics(results)
    detected, malicious = summary["detection_rate"]
    missed, _ = summary["false_negative_rate"]
    print(f"corpus_version={summary['corpus_version']} cases={summary['cases']}")
    print(f"detection_rate={detected}/{malicious}")
    print(f"false_negative_rate={missed}/{malicious}")
    for family, (false_positives, total) in summary["false_positive_by_family"].items():
        print(f"false_positive_rate[{family}]={false_positives}/{total}")
    print(f"regression_rate={summary['regression_rate']}")
    print(
        "new_surface_coverage=first corpus release; "
        f"{len({item['family'] for item in results})} families, {len(results)} cases"
    )


if __name__ == "__main__":
    main()
