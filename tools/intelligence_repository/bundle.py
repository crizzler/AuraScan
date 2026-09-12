"""Offline publisher preparation; never signs, publishes, or executes input.

Run with a pinned compatible AuraScan source on PYTHONPATH, or its isolated
developer installation. This template intentionally shares the engine contract.
"""

import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import stat
import sys

from aurascan.core.intelligence import (
    IntelligenceError, MANIFEST_FILENAME, MAX_PAYLOAD_BYTES, PAYLOAD_FILENAME,
    build_manifest, canonical_json, record_identities, validate_payload, validate_transition,
)


def _directory(path):
    candidate = Path(path).absolute()
    if ".." in candidate.parts:
        raise IntelligenceError("publisher directory path is not normalized")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in candidate.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except Exception:
        os.close(fd)
        raise


def read_payload(path):
    path = Path(path)
    directory = _directory(path.parent)
    fd = -1
    try:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= MAX_PAYLOAD_BYTES:
            raise IntelligenceError("publisher input is not bounded regular data")
        captured = bytearray()
        while len(captured) <= MAX_PAYLOAD_BYTES:
            chunk = os.read(fd, min(65536, MAX_PAYLOAD_BYTES + 1 - len(captured)))
            if not chunk:
                break
            captured.extend(chunk)
        after = os.fstat(fd)
        named = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        identity = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_size,
                                 info.st_mtime_ns, info.st_ctime_ns)
        if identity(before) != identity(after) or identity(after) != identity(named):
            raise IntelligenceError("publisher input changed during capture")
        return validate_payload(bytes(captured))
    finally:
        if fd >= 0:
            os.close(fd)
        os.close(directory)


def prepare_bundle(source, previous, output, sequence, issued_at, validity_days=30):
    candidate = read_payload(source)
    validate_transition(read_payload(previous), candidate)
    payload = canonical_json(candidate)
    manifest = canonical_json(build_manifest(payload, sequence, issued_at, validity_days))
    output = Path(output)
    parent = _directory(output.parent)
    directory = -1
    try:
        if output.name in {"", ".", ".."}:
            raise IntelligenceError("publisher output directory is invalid")
        os.mkdir(output.name, 0o700, dir_fd=parent)
        directory = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        for name, data in ((PAYLOAD_FILENAME, payload), (MANIFEST_FILENAME, manifest)):
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory)
            try:
                offset = 0
                while offset < len(data):
                    written = os.write(fd, data[offset:])
                    if written <= 0:
                        raise IntelligenceError("publisher output write failed")
                    offset += written
                os.fsync(fd)
            finally:
                os.close(fd)
        os.fsync(directory)
        os.fsync(parent)
    finally:
        if directory >= 0:
            os.close(directory)
        os.close(parent)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    identities = commands.add_parser("identities", help="list stable detection identities for explicit corrections")
    identities.add_argument("source", type=Path)
    validate = commands.add_parser("validate", help="offline payload structure and rights-decision validation")
    validate.add_argument("source", type=Path)
    validate.add_argument("--previous", type=Path, required=True)
    build = commands.add_parser("build", help="prepare deterministic unsigned release files")
    build.add_argument("source", type=Path)
    build.add_argument("--previous", type=Path, required=True)
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--sequence", type=int, required=True)
    build.add_argument("--issued-at", required=True, help="explicit UTC YYYY-MM-DDTHH:MM:SSZ")
    build.add_argument("--validity-days", type=int, default=30)
    args = parser.parse_args(argv)
    try:
        if args.operation == "identities":
            print(canonical_json(record_identities(read_payload(args.source))).decode("ascii"), end="")
        elif args.operation == "validate":
            validate_transition(read_payload(args.previous), read_payload(args.source))
            print("Payload structure and explicit rights decisions validated; no signature or factual verification performed.")
        else:
            issued = datetime.strptime(args.issued_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            if issued.strftime("%Y-%m-%dT%H:%M:%SZ") != args.issued_at:
                raise IntelligenceError("publisher issue time is malformed")
            prepare_bundle(args.source, args.previous, args.output, args.sequence, issued, args.validity_days)
            print("Unsigned payload and manifest prepared; signing and publication remain separate.")
        return 0
    except IntelligenceError as exc:
        print("Intelligence publisher: " + str(exc), file=sys.stderr)
    except (OSError, ValueError):
        print("Intelligence publisher: input, output, or timestamp refused.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
