"""CLI for consent-gated research-evidence capture and export.

This command is deliberately narrow. It reports what the local adjudication log
contains, records or revokes one per-purpose consent, and exports consented,
labeled adjudications as quarantine candidates. It never admits data, grants
rights, contacts a network, loads AI credentials, or trains anything.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional, TextIO

from aurascan.core.research_evidence import (
    ADJUDICATION_LABELS,
    CONSENT_PURPOSES,
    EvidenceError,
    evidence_root,
    export_candidates,
    grant_consent,
    revoke_consent,
    status as evidence_status,
)


EXIT_OK = 0
EXIT_REFUSED = 1
EXIT_UNAVAILABLE = 2


def _review_db_path(value: str) -> Path:
    if value:
        return Path(value)
    return Path.home() / ".local" / "share" / "aurascan" / "review_decisions.db"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aurascan evidence",
        description=(
            "Inspect consent-gated review adjudications and export them as "
            "quarantine corpus candidates. Exports are never admitted, never "
            "grant rights, and never feed training directly."
        ),
        epilog=(
            "Example:\n"
            "  aurascan evidence status\n"
            "  aurascan evidence consent --purpose training --confirm training\n"
            "  aurascan evidence export --purpose training --out /tmp/candidates.json\n\n"
            "Capture is local and best effort. Research use stays off until an "
            "operator grants consent for one named purpose."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", dest="json_output",
                        help="emit a structured JSON document")
    common.add_argument("--review-db", default="", metavar="PATH",
                        help="private review decision store to read (defaults to the user store)")
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("status", parents=[common],
                          help="show capture counts, labels and consent state")

    consent = subparsers.add_parser("consent", parents=[common],
                                    help="record or revoke one per-purpose consent")
    consent.add_argument("--purpose", required=True, choices=list(CONSENT_PURPOSES))
    consent.add_argument("--confirm", default="",
                         help="echo the exact purpose string to confirm the grant")
    consent.add_argument("--revoke", action="store_true", help="revoke instead of granting")

    export = subparsers.add_parser("export", parents=[common],
                                   help="write consented candidates to a file")
    export.add_argument("--purpose", required=True, choices=list(CONSENT_PURPOSES))
    export.add_argument("--out", required=True, metavar="PATH", help="destination file for candidates")
    return parser


def _print_json(stream: TextIO, payload) -> None:
    json.dump(payload, stream, sort_keys=True, indent=2)
    stream.write("\n")


def _status(root: Path, stdout: TextIO, json_output: bool) -> int:
    summary = evidence_status(root)
    if json_output:
        _print_json(stdout, dict(summary, labels_available=list(ADJUDICATION_LABELS)))
        return EXIT_OK
    print("AuraScan review adjudication capture", file=stdout)
    print(f"  Records: {summary['records']} "
          f"({summary['labeled_records']} labeled, {summary['unlabeled_records']} unlabeled)",
          file=stdout)
    for label in ADJUDICATION_LABELS:
        print(f"    {label}: {summary['labels'][label]}", file=stdout)
    granted = [purpose for purpose, value in summary["consent"].items() if value]
    print(f"  Consent: {', '.join(granted) if granted else 'none recorded'}", file=stdout)
    for key in ("consent_error", "log_error"):
        if summary.get(key):
            print(f"  Problem: {summary[key]}", file=stdout)
    print(f"  Capture: {summary['capture']} (local only, best effort)", file=stdout)
    print("  Research use: off unless consent is granted for a named purpose", file=stdout)
    print(f"  Retention: {summary['retention_days']} days", file=stdout)
    print("  Admission: never automatic; this command cannot admit data or grant rights", file=stdout)
    if not summary["labeled_records"]:
        print("  Next step: label a review decision, then grant consent and export", file=stdout)
    return EXIT_OK


def _consent(root: Path, args, stdout: TextIO, stderr: TextIO) -> int:
    try:
        if args.revoke:
            removed = revoke_consent(root, args.purpose)
            if args.json_output:
                _print_json(stdout, {"purpose": args.purpose, "revoked": removed})
            else:
                print(f"Consent for '{args.purpose}' "
                      + ("revoked." if removed else "was not recorded; nothing changed."),
                      file=stdout)
            return EXIT_OK
        record = grant_consent(root, args.purpose, confirm=args.confirm)
    except EvidenceError as exc:
        print(f"[AuraScan] {exc}", file=stderr)
        return EXIT_UNAVAILABLE if "invalid" in str(exc) else EXIT_REFUSED
    if args.json_output:
        _print_json(stdout, record)
    else:
        print(f"Consent recorded for purpose '{record['purpose']}'.", file=stdout)
        print("This record grants no rights, admits no data, and cannot be inherited "
              "by another purpose.", file=stdout)
    return EXIT_OK


def _export(root: Path, args, stdout: TextIO, stderr: TextIO) -> int:
    try:
        result = export_candidates(root, args.purpose, Path(args.out))
    except EvidenceError as exc:
        print(f"[AuraScan] Export refused: {exc}", file=stderr)
        return EXIT_REFUSED
    if args.json_output:
        _print_json(stdout, result)
    else:
        print(f"Wrote {result['candidates']} quarantine candidate(s) to {result['path']}", file=stdout)
        print(f"  Purpose: {result['purpose']}", file=stdout)
        print(f"  Digest: {result['digest']}", file=stdout)
        if result["excluded_unlabeled"]:
            print(f"  Excluded unlabeled decisions: {result['excluded_unlabeled']}", file=stdout)
        print("Admission is not automatic: rights stay unresolved and nothing here can "
              "train a model.", file=stdout)
    return EXIT_OK


def run_evidence(argv: Optional[List[str]] = None, *,
                 stdout: Optional[TextIO] = None,
                 stderr: Optional[TextIO] = None) -> int:
    stdout = stdout if stdout is not None else sys.stdout
    stderr = stderr if stderr is not None else sys.stderr
    parser = _build_parser()
    try:
        args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))
    except SystemExit as exc:
        return int(exc.code or 0)
    if not args.command:
        parser.print_help(stdout)
        return EXIT_OK
    root = evidence_root(_review_db_path(args.review_db))
    if args.command == "status":
        return _status(root, stdout, args.json_output)
    if args.command == "consent":
        return _consent(root, args, stdout, stderr)
    return _export(root, args, stdout, stderr)
