"""``aurascan npm-audit``: check a project before ``npm install`` runs it.

This is an unprivileged, offline, non-executing pre-install check. It reads the
project manifest and only the files a lifecycle command names, then reports what
would run during installation. It never runs npm, node, a shell, or the project,
and it never contacts a registry, so dependency lifecycle scripts are reported
as unknown rather than guessed.
"""

import argparse
import json
import os
import posixpath
import shlex
import stat
import sys
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence

from aurascan.analyzers.npm_install_audit import (
    LIFECYCLE_HOOKS,
    MAX_MANIFEST_CHARS,
    MAX_SCRIPT_FILE_CHARS,
    audit_npm_install,
)

AUDIT_SCHEMA = "aurascan-npm-audit/1"
EXIT_CLEAR = 0
EXIT_ATTENTION = 1
EXIT_ERROR = 2


def _capture_regular_file(path: Path, limit: int) -> Optional[str]:
    """Read a bounded regular file without following a final symlink."""

    try:
        descriptor = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            return None
        chunks: List[bytes] = []
        remaining = limit + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
    except OSError:
        return None
    finally:
        os.close(descriptor)
    if len(data) > limit:
        return None
    return data.decode("utf-8", errors="replace")


def _lifecycle_entries(manifest_text: str) -> List[str]:
    """Return project-relative files named by install lifecycle commands."""

    try:
        manifest = json.loads(manifest_text)
    except (ValueError, RecursionError):
        return []
    if not isinstance(manifest, dict):
        return []
    hooks = manifest.get("scripts")
    if not isinstance(hooks, dict):
        return []
    entries: List[str] = []
    for hook in LIFECYCLE_HOOKS:
        command = hooks.get(hook)
        if not isinstance(command, str):
            continue
        try:
            words = shlex.split(command, comments=False, posix=True)
        except ValueError:
            continue
        if not words or posixpath.basename(words[0]) not in {"node", "bun"}:
            continue
        for argument in words[1:]:
            if argument.startswith("-"):
                continue
            entries.append(argument)
            break
    return entries


def audit_project(path: Path) -> Dict[str, object]:
    manifest_path = path / "package.json"
    manifest_text = _capture_regular_file(manifest_path, MAX_MANIFEST_CHARS)
    if manifest_text is None:
        raise FileNotFoundError(f"no readable package.json in {path}")

    lifecycle_files: Dict[str, str] = {}
    root = path.resolve()
    manifest_abs = str(root / "package.json")
    for entry in _lifecycle_entries(manifest_text):
        # Stay lexical: a resolved path would silently follow a symlink out of
        # the project, and the no-follow capture below must be able to refuse it.
        candidate = Path(os.path.normpath(str(root / entry)))
        try:
            candidate.relative_to(root)
        except ValueError:
            continue
        text = _capture_regular_file(candidate, MAX_SCRIPT_FILE_CHARS)
        if text is not None:
            lifecycle_files[
                posixpath.normpath(posixpath.join(str(root), entry))
            ] = text

    findings = audit_npm_install(manifest_abs, manifest_text, lifecycle_files)
    blocking = [finding for finding in findings if finding.blocks_installation]
    return {
        "schema": AUDIT_SCHEMA,
        "path": str(root),
        "manifest": "package.json",
        "lifecycle_hooks": list(LIFECYCLE_HOOKS),
        "inspected_install_files": sorted(lifecycle_files),
        "findings": [
            {
                "rule_id": finding.rule_id,
                "severity": finding.severity.value,
                "confidence": finding.confidence.value,
                "file": finding.file_path,
                "line": finding.line_number,
                "explanation": finding.explanation,
                "recommendation": finding.recommendation,
                "blocks_installation": finding.blocks_installation,
                "requires_manual_review": finding.requires_manual_review,
                "evidence": finding.evidence_snippet,
            }
            for finding in findings
        ],
        "counts": {
            "total": len(findings),
            "blocking": len(blocking),
        },        "coverage": {
            "project_install_code": "inspected" if lifecycle_files else "no local lifecycle entry",
            "dependency_lifecycle_scripts": (
                "unknown: they require package metadata that this offline audit does not fetch"
            ),
        },
        "ok": not findings,
    }


def _print_human(payload: Mapping[str, object], stream) -> None:
    findings = payload.get("findings") or []
    print(f"[AuraScan] npm pre-install audit: {payload.get('path')}", file=stream)
    print(
        "This read the project's install-time code as inert text. It did not run npm, "
        "node, a shell, or the project, and it did not contact a registry.",
        file=stream,
    )
    if not findings:
        print(
            "[AuraScan] No problem was found in the project's own install-time code. "
            "This is not proof that the project is safe.",
            file=stream,
        )
    for finding in findings:
        severity = finding.get("severity")
        prefix = "BLOCK" if finding.get("blocks_installation") else "REVIEW"
        location = finding.get("file")
        if finding.get("line"):
            location = f"{location}:{finding.get('line')}"
        print(f"\n[{prefix}] {severity} {finding.get('rule_id')}", file=stream)
        print(f"  where: {location}", file=stream)
        print(f"  why: {finding.get('explanation')}", file=stream)
        print(f"  do: {finding.get('recommendation')}", file=stream)
    print(
        "\n[AuraScan] Dependency lifecycle scripts are unknown offline. If you must install "
        "this project, use a disposable environment without credentials, or install with "
        "npm install --ignore-scripts and run only the scripts you reviewed.",
        file=stream,
    )


def build_npm_audit_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aurascan npm-audit",
        description=(
            "Inspect a JavaScript project's install-time code before running npm install. "
            "Nothing is executed and no registry is contacted."
        ),
    )
    parser.add_argument("path", nargs="?", default=".", help="project directory containing package.json")
    parser.add_argument("--json", action="store_true", dest="json_mode", help="emit a structured JSON document")
    return parser


def run_npm_audit(argv: Sequence[str], *, stdout=None, stderr=None) -> int:
    parser = build_npm_audit_parser()
    try:
        args = parser.parse_args(list(argv))
    except SystemExit:
        return EXIT_ERROR
    out = stdout or sys.stdout
    err = stderr or sys.stderr
    target = Path(args.path).expanduser()
    if not target.is_dir():
        print(f"[AuraScan] Not a project directory: {target}", file=err)
        return EXIT_ERROR
    try:
        payload = audit_project(target)
    except FileNotFoundError as exc:
        print(f"[AuraScan] {exc}", file=err)
        return EXIT_ERROR
    if args.json_mode:
        print(json.dumps(payload, indent=2, sort_keys=True), file=out)
    else:
        _print_human(payload, out)
    return EXIT_CLEAR if payload["ok"] else EXIT_ATTENTION
