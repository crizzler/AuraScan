"""The real-text fixture: provenance completeness, hash integrity and the report tool's contract.

The detector stays offline; ``tools/injection_real_harvest.py`` is the only networked piece and is not
part of this test's runtime.
"""

import hashlib
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURE = os.path.join(ROOT, "tests", "fixtures", "injection_real")
MANIFEST = os.path.join(FIXTURE, "manifest.json")
REPORT_TOOL = os.path.join(ROOT, "tools", "injection_real_report.py")

KIND_BOUNDS = {"cve": (20, 30), "issue": (20, 30), "tool-result": (10, 10)}


def manifest():
    with open(MANIFEST, "r", encoding="utf-8") as handle:
        return json.load(handle)


def test_manifest_is_present_and_large_enough():
    payload = manifest()
    assert payload["public_data_only"] is True
    assert payload["total"] == len(payload["documents"])
    assert payload["total"] >= 50


def test_every_kind_is_within_its_bound():
    counts = manifest()["counts"]
    for kind, (low, high) in KIND_BOUNDS.items():
        assert low <= counts.get(kind, 0) <= high, (kind, counts.get(kind))


def test_every_document_records_url_date_and_hash():
    for entry in manifest()["documents"]:
        assert entry["source_url"].startswith("https://")
        assert entry["fetched_at_utc"].endswith("Z")
        assert len(entry["sha256"]) == 64
        assert entry["kind"] in KIND_BOUNDS


def test_every_stored_byte_matches_its_recorded_hash():
    for entry in manifest()["documents"]:
        path = os.path.join(ROOT, entry["path"])
        with open(path, "rb") as handle:
            payload = handle.read()
        assert hashlib.sha256(payload).hexdigest() == entry["sha256"], entry["path"]


def test_manifest_paths_stay_inside_the_fixture():
    for entry in manifest()["documents"]:
        assert entry["path"].startswith("tests/fixtures/injection_real/")
        assert os.path.exists(os.path.join(ROOT, entry["path"]))


def test_report_tool_runs_offline_and_writes_the_disclaimer(tmp_path):
    result = subprocess.run(
        [sys.executable, REPORT_TOOL], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
    )
    assert result.returncode == 0, result.stderr
    report = os.path.join(ROOT, "SPIKE-B-real-text.md")
    assert os.path.exists(report)
    with open(report, "r", encoding="utf-8") as handle:
        text = handle.read()
    assert "first real-text signal" in text
    assert "not** a precision or recall claim" in text


def test_report_lists_every_high_finding_with_a_disposition():
    report = os.path.join(ROOT, "SPIKE-B-real-text.md")
    with open(report, "r", encoding="utf-8") as handle:
        text = handle.read()
    if "No High finding" in text:
        return
    for line in text.splitlines():
        if line.startswith("| ") and "**" in line:
            assert any(word in line for word in ("**true**", "**false**", "**uncertain**"))
