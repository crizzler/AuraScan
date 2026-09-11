#!/usr/bin/env python3
"""Explicit developer intake CLI. Offline by default; never executes samples."""

import argparse
import json
from pathlib import Path

try:
    from . import security_data_intake as intake
    from . import security_data_sources as sources
    from .security_data_store import PrivateStore, StoreError
except ImportError:
    import security_data_intake as intake
    import security_data_sources as sources
    from security_data_store import PrivateStore, StoreError


class Parser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default includes rejected paths and source-supplied values.
        raise intake.IntakeError("arguments")


def parser():
    result = Parser(description=__doc__)
    result.add_argument("--store", type=Path, required=True, help="Explicit private store; use init first")
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="Create a private empty store under an existing safe parent")
    fixture = commands.add_parser("fixture", help="Capture selected existing regression fixture bytes")
    fixture.add_argument("--root", type=Path, required=True)
    fixture.add_argument("--source-uri", required=True)
    fixture.add_argument("--revision", required=True)
    fixture.add_argument("--file", action="append", default=[], help="Additional explicit relative fixture data path")
    package = commands.add_parser("package", help="Capture an explicitly exported local package snapshot")
    package.add_argument("--type", choices=("arch_git", "aur_git"), required=True)
    package.add_argument("--root", type=Path, required=True)
    package.add_argument("--source-uri", required=True)
    package.add_argument("--package", required=True)
    package.add_argument("--revision", required=True)
    package.add_argument("--parent", action="append", default=[])
    for name in ("arch", "aur", "aur-metadata", "arch-history", "aur-history"):
        command = commands.add_parser(name, help="Explicit selected public metadata acquisition; requires --network")
        command.add_argument("--package", required=True)
        command.add_argument("--network", action="store_true")
        if name in {"arch", "aur"}:
            command.add_argument("--revision", action="append", required=True)
        elif name.endswith("-history"):
            command.add_argument("--limit", type=int, default=2, choices=(1, 2, 3))
    advisory = commands.add_parser("advisory", help="Retain a supplied public reference, without fetching it")
    advisory.add_argument("--identifier", required=True)
    advisory.add_argument("--source-uri", required=True)
    admission = commands.add_parser("intake", help="Admit captures to quarantine; performs no acquisition")
    admission.add_argument("--capture", action="append", required=True)
    admission.add_argument("--base", help="Explicit previous batch SHA-256")
    inspect = commands.add_parser("inspect", help="Print bounded metadata and hashes for explicit review")
    inspect.add_argument("--base", required=True)
    review = commands.add_parser("review", help="Apply an explicit review declaration; retain quarantine")
    review.add_argument("--base", required=True)
    review.add_argument("--request", type=Path, required=True)
    assessment = commands.add_parser("assessment", help="Attach an independently obtained sanitized assessment")
    assessment.add_argument("--base", required=True)
    assessment.add_argument("--item", required=True)
    assessment.add_argument("--request", type=Path, required=True)
    return result


def run(args):
    command = args.command
    if command == "init":
        with PrivateStore(args.store, create=True):
            return {"initialized": True}
    if command in {"arch-history", "aur-history"}:
        function = sources.resolve_arch_history if command == "arch-history" else sources.resolve_aur_history
        return {"revisions": function(args.package, limit=args.limit, network=args.network),
                "scope": "upstream_commit_metadata_only"}
    captures = None
    if command == "fixture":
        captures = [sources.capture_fixture(args.root, args.source_uri, args.revision, selected_files=args.file)]
    elif command == "package":
        captures = [sources.capture_package(args.type, args.root, args.source_uri, args.package,
                                            args.revision, parent_revisions=args.parent)]
    elif command in {"arch", "aur"}:
        function = sources.capture_arch if command == "arch" else sources.capture_aur
        captures = function(args.package, args.revision, network=args.network)
    elif command == "aur-metadata":
        captures = [sources.capture_aur_metadata(args.package, network=args.network)]
    elif command == "advisory":
        captures = [sources.capture_advisory(args.identifier, args.source_uri)]
    with PrivateStore(args.store) as store:
        if captures is not None:
            return {"capture_sha256": [intake.save_capture(store, value) for value in captures],
                    "scope": "acquisition_only"}
        if command == "intake":
            return intake.intake(store, args.capture, base=args.base)
        if command == "review":
            return intake.review(store, args.base, intake.read_request(args.request))
        if command == "assessment":
            return intake.attach_assessment(store, args.base, args.item, intake.read_request(args.request))
        batch, document = intake.load_batch(store, args.base)
        return {"manifest_sha256": batch["manifest_sha256"], "items": [
            {"id": item["id"], "candidate_sha256": intake.digest(intake.canonical(item)),
             "family_id": item["family_id"], "parent_ids": item["parent_ids"],
             "source_refs": item["sources"], "classification": item["classification"],
             "review": item["review"], "partition": item["partition"], "eligibility": item["eligibility"]}
            for item in document["items"]], "scope": "provided_batch_only"}


def main(argv=None):
    try:
        result = run(parser().parse_args(argv))
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (intake.IntakeError, sources.SourceError, StoreError) as error:
        print(json.dumps({"error": error.code}, sort_keys=True))
        return 1
    except (OSError, ValueError, RecursionError):
        print('{"error":"intake_failed"}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
