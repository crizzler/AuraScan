#!/usr/bin/env python3
"""Run the frozen detector over the real-text fixture and print a first-signal report (dev tool).

The fixture is public CVE descriptions, public GitHub issue bodies and tool-result-shaped JSON from
public KEV/EPSS/NVD/OSV/GHSA payloads, each with its source URL, fetch date and SHA-256 in
``manifest.json``. Nothing here is tuned against the results: the rules and thresholds are the ones the
parity gate already pins, and every High finding is dispositioned by hand in
``tests/fixtures/injection_real/dispositions.json`` (``true`` / ``false`` / ``uncertain``) — a missing
disposition prints as ``uncertain``.

This is a first real-text signal, not a precision or recall claim: the sample is small, hand-picked to
be security-adjacent, and unlabelled apart from the High rows.

Exit codes: ``0`` report written, ``2`` fixture or manifest problem.
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from aurascan.analyzers.injection import catalog, scanner  # noqa: E402
from aurascan.analyzers.injection import exfiltration as _exfiltration  # noqa: E402
from aurascan.analyzers.injection import override as _override  # noqa: E402
from aurascan.analyzers.injection import persona as _persona  # noqa: E402

FIXTURE = os.path.join(ROOT, "tests", "fixtures", "injection_real")
MANIFEST = os.path.join(FIXTURE, "manifest.json")
DISPOSITIONS = os.path.join(FIXTURE, "dispositions.json")
REPORT = os.path.join(ROOT, "SPIKE-B-real-text.md")

SOURCE_TYPE_BY_KIND = {"cve": "documentation", "issue": "source", "tool-result": "source"}
SNIPPET = 110


def load_manifest():
    with open(MANIFEST, "r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    documents = manifest.get("documents") or []
    if not documents:
        raise SystemExit("manifest has no documents")
    return manifest, documents


def load_dispositions():
    if not os.path.exists(DISPOSITIONS):
        return {}
    with open(DISPOSITIONS, "r", encoding="utf-8") as handle:
        return json.load(handle)


def snippet(text, start, length):
    window = text[max(0, start - 20):start + length + 20]
    return " ".join(window.split())[:SNIPPET]


def main():
    manifest, documents = load_manifest()
    dispositions = load_dispositions()

    by_confidence = {}
    by_class = {}
    high_rows = []
    totals = {"documents": 0, "with_findings": 0, "findings": 0}

    for entry in documents:
        path = os.path.join(ROOT, entry["path"])
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()

        source_type = SOURCE_TYPE_BY_KIND.get(entry["kind"], "source")
        evidence = scanner.scan_content(text, source_type=source_type, path_hint=entry["path"])
        totals["documents"] += 1
        if evidence:
            totals["with_findings"] += 1
        totals["findings"] += len(evidence)

        for item in evidence:
            by_confidence[item.confidence] = by_confidence.get(item.confidence, 0) + 1
            key = item.class_id + "/" + item.confidence
            by_class[key] = by_class.get(key, 0) + 1
            if item.confidence == "HIGH":
                identity = "%s|%s|%d" % (entry["path"], item.detector_id, item.start)
                record = dispositions.get(identity) or {}
                high_rows.append(
                    {
                        "url": entry["source_url"],
                        "path": entry["path"],
                        "detector_id": item.detector_id,
                        "snippet": snippet(text, item.start, item.length),
                        "disposition": record.get("disposition", "uncertain"),
                        "note": record.get("note", "no disposition recorded"),
                    }
                )

    lines = []
    lines.append("# SPIKE-B — real-text first signal")
    lines.append("")
    lines.append("Fixture: `tests/fixtures/injection_real/` — %d public documents " % manifest["total"])
    lines.append("(%s), fetched %s; every source URL, fetch date and SHA-256 is in `manifest.json`."
                 % (", ".join("%s %d" % (kind, count) for kind, count in sorted(manifest["counts"].items())),
                    manifest["generated_at_utc"]))
    lines.append("")
    lines.append("Rules and thresholds are unchanged from the parity gate; the only knob is the declared")
    lines.append("`source_type` per kind (%s)." % json.dumps(SOURCE_TYPE_BY_KIND, sort_keys=True))
    lines.append("")
    lines.append("## Findings by class and confidence")
    lines.append("")
    lines.append("| class | LOW | MEDIUM | HIGH |")
    lines.append("|---|---|---|---|")
    for class_id in catalog.CLASS_IDS:
        row = [str(by_class.get(class_id + "/" + level, 0)) for level in ("LOW", "MEDIUM", "HIGH")]
        if any(value != "0" for value in row):
            lines.append("| `%s` | %s |" % (class_id, " | ".join(row)))
    lines.append("")
    lines.append("Totals: %d findings over %d documents (%d documents with at least one finding); "
                 "by confidence %s."
                 % (totals["findings"], totals["documents"], totals["with_findings"],
                    json.dumps(by_confidence, sort_keys=True)))
    lines.append("")
    lines.append("## Every High finding")
    lines.append("")
    if not high_rows:
        lines.append("No High finding. Every real document sits at MEDIUM or below.")
    else:
        lines.append("| # | disposition | class/rule | source | snippet |")
        lines.append("|---|---|---|---|---|")
        for index, row in enumerate(high_rows, 1):
            lines.append(
                "| %d | **%s** — %s | `%s` | %s | `%s` |"
                % (index, row["disposition"], row["note"], row["detector_id"], row["url"], row["snippet"])
            )
    lines.append("")
    lines.append("## Rule-family presence in the fixture")
    lines.append("")
    lines.append("Measured, not tuned: how many documents contain at least one phrase from each ported table.")
    lines.append("")
    lines.append("| table | documents containing a phrase |")
    lines.append("|---|---|")
    corpus = []
    for entry in documents:
        path = os.path.join(ROOT, entry["path"])
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            corpus.append(handle.read().lower())
    for label, table in (
        ("override literals (18)", _override.LITERAL_PHRASES),
        ("persona literals (19)", _persona.LITERAL_PHRASES),
        ("exfiltration phrases (12)", _exfiltration.SENSITIVE_PHRASES),
    ):
        present = sum(1 for text in corpus if any(phrase in text for phrase in table))
        lines.append("| %s | %d / %d |" % (label, present, len(corpus)))
    lines.append("")
    lines.append("## What this does and does not say")
    lines.append("")
    lines.append("This is a first real-text signal, **not** a precision or recall claim. The set is small,")
    lines.append("security-adjacent by construction, and has no labels beyond the High dispositions above.")
    lines.append("A High here means the text looks like instructions aimed at an AI reader, never that")
    lines.append("anything ran. Nothing was executed and no network call happens inside the detector.")
    lines.append("")

    with open(REPORT, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))

    print("\n".join(lines))
    print("report written: " + os.path.relpath(REPORT, ROOT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
