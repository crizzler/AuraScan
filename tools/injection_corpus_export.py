#!/usr/bin/env python3
"""Corpus exporter for the reverse-AntiCopy injection probe (dev tool, never shipped).

Two jobs, deliberately separated:

* ``--derive`` rebuilds ``corpus.json`` **from the retained raw tree** and re-pins
  ``corpus.sha256``. This is the only writer of the fixture.
* ``derive_bytes(raw_dir)`` / ``pinned_sha256()`` are what ``tools/injection_parity.py --gate``
  calls: the gate re-derives the corpus from the raw files on every run and compares that hash to
  the pinned one, so a kept sample is a plain ``git diff`` in review rather than a claim.

``--harvest-info`` records provenance next to the fixture (UTC timestamp, the exact harvest
invocation, the counts, the AntiCopy HEAD and its ``status --porcelain``). A dirty AntiCopy checkout
is refused: the harvested bytes must correspond to a commit the golden can be anchored to.

The raw tree is the *harness's* own output (built binary + ``TMPDIR`` + SIGKILL inside the
materialise->scan window, ``01-architect-design.md`` §5.2) so the corpus is never retyped.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXTURE = os.path.join(ROOT, "tests", "fixtures", "injection_corpus")
RAW = os.path.join(FIXTURE, "raw")
CORPUS = os.path.join(FIXTURE, "corpus.json")
PINNED = os.path.join(FIXTURE, "corpus.sha256")
HARVEST = os.path.join(FIXTURE, "harvest.json")

DATA_PREFIX = "Assets/Corpus/"
INJECTION_PREFIX = DATA_PREFIX + "Injection/"
BENIGN_PREFIX = DATA_PREFIX + "Benign/"

CLASS_BY_DIRECTORY = {
    "override": "instruction-override",
    "persona": "persona-hijack",
    "exfil": "data-exfiltration",
    "encoded": "encoded-obfuscated",
    "multilingual": "multilingual",
    "tool": "tool-command",
    "delimiter": "delimiter-escape",
}

EXPECTED_TOTAL = 550
EXPECTED_INJECTION = 240
EXPECTED_BENIGN = 310


def sha256_bytes(payload):
    return hashlib.sha256(payload).hexdigest()


def _walk_raw(raw_dir):
    """Yield ``(project_relative_path, full_path)`` for every retained file, sorted."""
    found = []
    for directory, _, files in os.walk(raw_dir):
        for name in files:
            full = os.path.join(directory, name)
            rel = os.path.relpath(full, raw_dir).replace(os.sep, "/")
            found.append((rel, full))
    found.sort()
    return found


def classify(relative_path):
    """Class id for an injection sample path, ``None`` for benign files."""
    if relative_path.startswith(INJECTION_PREFIX):
        directory = relative_path[len(INJECTION_PREFIX):].split("/", 1)[0]
        return CLASS_BY_DIRECTORY.get(directory)
    if relative_path.startswith(BENIGN_PREFIX):
        return None
    raise ValueError("unexpected corpus path: %s" % relative_path)


def derive_records(raw_dir=RAW):
    """Read the raw tree into canonical records. Raises when the tree is not the expected shape."""
    samples = []
    benign = []
    seen = set()

    for relative_path, full_path in _walk_raw(raw_dir):
        if relative_path in seen:
            raise ValueError("duplicate corpus path: %s" % relative_path)
        seen.add(relative_path)

        with open(full_path, "rb") as handle:
            raw = handle.read()
        content = raw.decode("utf-8")

        record = {"class": classify(relative_path), "path": relative_path, "content": content}
        if record["class"] is None:
            benign.append(record)
        else:
            samples.append(record)

    shape = shape_of(samples)
    if len(samples) != EXPECTED_INJECTION or len(benign) != EXPECTED_BENIGN:
        raise ValueError(
            "corpus shape %d injection + %d benign, expected %d + %d"
            % (len(samples), len(benign), EXPECTED_INJECTION, EXPECTED_BENIGN)
        )
    for class_id, count in sorted(shape.items()):
        if count == 0:
            raise ValueError("no samples for class %s" % class_id)
    return samples, benign


def shape_of(samples):
    shape = {}
    for record in samples:
        shape[record["class"]] = shape.get(record["class"], 0) + 1
    return shape


def render(samples, benign, head):
    """Canonical JSON: one record per line so a BCL-only reader can scan it without a dependency."""
    lines = ["{", '  "version": 1,', '  "harvested_from": %s,' % json.dumps(head)]
    for key, records in (("samples", samples), ("benign", benign)):
        lines.append('  "%s": [' % key)
        for index, record in enumerate(records):
            suffix = "," if index + 1 < len(records) else ""
            lines.append("    " + json.dumps(record, ensure_ascii=False, sort_keys=True) + suffix)
        lines.append("  ]" + ("," if key == "samples" else ""))
    lines.append("}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def derive_bytes(raw_dir=RAW, head=None):
    """Derived corpus bytes. ``head`` defaults to the recorded ``harvest.json`` value."""
    if head is None:
        head = recorded_head()
    samples, benign = derive_records(raw_dir)
    return render(samples, benign, head)


def recorded_head():
    with open(HARVEST, "r", encoding="utf-8") as handle:
        return json.load(handle)["anticopy_head"]


def pinned_sha256():
    with open(PINNED, "r", encoding="utf-8") as handle:
        return handle.read().strip()


def tree_digest(raw_dir=RAW):
    """SHA-256 over ``path\\0size\\0sha256(content)`` for every retained file, sorted."""
    digest = hashlib.sha256()
    for relative_path, full_path in _walk_raw(raw_dir):
        with open(full_path, "rb") as handle:
            payload = handle.read()
        digest.update(relative_path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(len(payload)).encode("ascii"))
        digest.update(b"\0")
        digest.update(sha256_bytes(payload).encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def _git(anticopy, *args):
    result = subprocess.run(
        ["git", "-C", anticopy] + list(args),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return result.returncode, result.stdout.decode("utf-8", "replace").strip(), result.stderr.decode(
        "utf-8", "replace"
    ).strip()


def write_harvest_info(anticopy):
    status_code, status, _ = _git(anticopy, "status", "--porcelain")
    if status_code != 0:
        raise SystemExit("git status failed in %s" % anticopy)
    if status:
        raise SystemExit("AntiCopy checkout is dirty, commit or clean it first:\n" + status)

    code, head, _ = _git(anticopy, "rev-parse", "HEAD")
    if code != 0 or not head:
        raise SystemExit("could not read the AntiCopy HEAD")

    samples, benign = derive_records()
    payload = {
        "harvested_at_utc": __import__("datetime").datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "anticopy_root": anticopy,
        "anticopy_head": head,
        "anticopy_status_porcelain": status,
        "harvest_invocation": (
            "TMPDIR=<scratch>; timeout -s KILL <delay> "
            "dotnet <antiCopy>/Tools/InjectionHarness/bin/Release/net10.0/"
            "AntiCopy.InjectionHarness.dll; then copy the orphaned tree"
        ),
        "sample_counts": {
            "total": len(samples) + len(benign),
            "injection": len(samples),
            "benign": len(benign),
            "per_class": shape_of(samples),
        },
        "tree_sha256": tree_digest(),
    }
    with open(HARVEST, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    return payload


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--derive", action="store_true", help="rebuild corpus.json from raw/ and re-pin the hash")
    parser.add_argument("--harvest-info", action="store_true", help="record harvest provenance")
    parser.add_argument("--anticopy", default=os.environ.get("ANTICOPY_ROOT", "/home/arawn/Unity Projects/AntiCopy"))
    parser.add_argument("--check", action="store_true", help="derive and compare, writing nothing")
    args = parser.parse_args(argv)

    if args.harvest_info:
        payload = write_harvest_info(args.anticopy)
        print("harvest info written: head=%s tree=%s" % (payload["anticopy_head"], payload["tree_sha256"]))

    if args.derive:
        payload = derive_bytes()
        with open(CORPUS, "wb") as handle:
            handle.write(payload)
        digest = sha256_bytes(payload)
        with open(PINNED, "w", encoding="utf-8") as handle:
            handle.write(digest + "\n")
        print("corpus written: %d bytes sha256=%s" % (len(payload), digest))

    if args.check:
        digest = sha256_bytes(derive_bytes())
        pinned = pinned_sha256()
        print("corpus.sha256 pinned=%s derived=%s %s" % (pinned, digest, "MATCH" if pinned == digest else "DRIFT"))
        return 0 if pinned == digest else 3

    if not (args.harvest_info or args.derive or args.check):
        parser.print_help()
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
