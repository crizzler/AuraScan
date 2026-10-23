"""Read-only desktop snapshot contract for AuraScan user interfaces.

``aurascan ui --json`` composes evidence that existing AuraScan workflows
already own into one bounded, versioned snapshot. It is a user-facing entry
point: it never changes policy, mutates state, starts a service, calls an AI
provider, executes package content, or performs network access of its own.

The contract is documented in ``docs/DESKTOP_UI_DESIGN.md``. Changes are
additive; removing, renaming, or retyping a key requires a new contract string
and a matching renderer update.
"""

import argparse
import importlib.metadata
import json
import platform
import re
import sys
import time
from collections.abc import Mapping as MappingABC
from pathlib import Path
from typing import Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from aurascan.core.text_safety import sanitize_terminal_text
from aurascan.core.ui_actions import action_catalog

UI_CONTRACT = "aurascan-ui/1"
CHECK_STATUSES = ("ok", "warn", "error")
SEVERITY_RANK = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
MAX_CHECKS = 1000
MAX_MARKERS = 100
MAX_REPORT_BYTES = 16 * 1024 * 1024
MAX_FINDINGS = 500
MAX_MESSAGES = 20
MAX_FINDING_SUMMARY = 800
MAX_FINDING_TEXT = 400
MAX_MESSAGE_TEXT = 300
REPORT_SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
REPORT_CONFIDENCES = ("LOW", "MEDIUM", "HIGH", "CONFIRMED")
REPORT_ACTIONS = ("ALLOW", "WARN", "MANUAL_REVIEW", "BLOCK", "BLOCKED")
RULE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
INTELLIGENCE_KEYS = (
    "status",
    "source",
    "schema_version",
    "sequence",
    "digest",
    "identity",
    "manifest_digest",
    "reviewed_at",
    "activated_at",
    "expires_at",
    "update_channel",
    "feed_id",
    "coverage_error",
    "automatic_updates",
    "refresh_status",
)


class UISnapshotError(RuntimeError):
    """Raised when collected evidence cannot be shaped into the contract."""


def installed_app_version() -> str:
    try:
        return importlib.metadata.version("aurascan")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def _project_doctor_checks(
    checks: Sequence[Mapping[str, object]],
) -> List[Dict[str, object]]:
    if len(checks) > MAX_CHECKS:
        raise UISnapshotError("doctor evidence exceeds the contract bound")
    projected: List[Dict[str, object]] = []
    for check in checks:
        if not isinstance(check, MappingABC):
            raise UISnapshotError("doctor evidence entry is not an object")
        name = check.get("name")
        status = check.get("status")
        message = check.get("message")
        if not isinstance(name, str) or not name:
            raise UISnapshotError("doctor evidence entry has no name")
        if status not in CHECK_STATUSES:
            raise UISnapshotError("doctor evidence entry has an unsupported status")
        if not isinstance(message, str):
            raise UISnapshotError("doctor evidence entry has no message")
        entry: Dict[str, object] = {
            "name": name,
            "status": status,
            "message": message,
        }
        details = check.get("details")
        if isinstance(details, MappingABC):
            entry["details"] = dict(details)
        projected.append(entry)
    return projected


def _project_intelligence(
    payload: Optional[Mapping[str, object]],
) -> Dict[str, object]:
    if not isinstance(payload, MappingABC):
        return {"status": "unavailable"}
    projected: Dict[str, object] = {}
    for key in INTELLIGENCE_KEYS:
        if key not in payload:
            continue
        value = payload[key]
        if value is None or isinstance(value, (str, int, float, bool)):
            projected[key] = value
    if not projected.get("status"):
        projected["status"] = "unknown"
    return projected


def _marker_severity(marker: Mapping[str, object]) -> str:
    value = str(marker.get("severity") or "UNKNOWN").upper()
    return value if value in SEVERITY_RANK else "UNKNOWN"


def _project_incidents(
    markers: Sequence[Mapping[str, object]],
    unseen_markers: Sequence[Mapping[str, object]],
    *,
    available: bool,
) -> Dict[str, object]:
    if not available:
        return {
            "available": False,
            "pending": 0,
            "unseen": 0,
            "highest_severity": None,
        }
    bounded = list(markers)[:MAX_MARKERS]
    highest: Optional[str] = None
    if bounded:
        highest = max(
            (_marker_severity(marker) for marker in bounded),
            key=lambda value: SEVERITY_RANK[value],
        )
    return {
        "available": True,
        "pending": min(len(markers), MAX_MARKERS),
        "unseen": min(len(unseen_markers), MAX_MARKERS),
        "highest_severity": highest,
    }


def _bounded_text(value: object, limit: int) -> str:
    return sanitize_terminal_text(value, max_chars=limit)


def _bounded_label(value: object, limit: int = 40) -> str:
    return sanitize_terminal_text(value, max_chars=limit)


def _basename(value: object) -> str:
    text = sanitize_terminal_text(value, max_chars=1024)
    if not text:
        return ""
    try:
        name = Path(text).name
    except (OSError, ValueError):
        return ""
    return sanitize_terminal_text(name, max_chars=128)


def _project_risk(risk: Optional[Mapping[str, object]]) -> Optional[Dict[str, object]]:
    if risk is None:
        return None
    if not isinstance(risk, MappingABC):
        raise UISnapshotError("report risk summary is not an object")
    severity = risk.get("severity")
    if severity not in REPORT_SEVERITIES:
        raise UISnapshotError("report risk summary has an unsupported severity")
    action = risk.get("action")
    if not isinstance(action, str):
        raise UISnapshotError("report risk summary has no action")
    action = action.upper()
    if action not in REPORT_ACTIONS:
        raise UISnapshotError("report risk summary has an unsupported action")
    return {
        "severity": severity,
        "action": action,
        "recommended_action": _bounded_label(risk.get("recommended_action"), 32),
        "blocks_installation": bool(risk.get("blocks_installation")),
        "requires_manual_review": bool(risk.get("requires_manual_review")),
        "reason": _bounded_text(risk.get("reason"), MAX_FINDING_TEXT),
    }


def _project_finding(finding: Mapping[str, object]) -> Dict[str, object]:
    rule_id = finding.get("rule_id")
    if not isinstance(rule_id, str) or not RULE_ID_PATTERN.match(rule_id):
        raise UISnapshotError("report finding has an unsupported rule identifier")
    severity = finding.get("severity")
    if severity not in REPORT_SEVERITIES:
        raise UISnapshotError("report finding has an unsupported severity")
    confidence = finding.get("confidence")
    if confidence not in REPORT_CONFIDENCES:
        raise UISnapshotError("report finding has an unsupported confidence")
    line = finding.get("line_number")
    line_number = line if type(line) is int and 0 < line < 10 ** 7 else None
    return {
        "rule_id": rule_id,
        "severity": severity,
        "confidence": confidence,
        "evidence_quality": _bounded_label(finding.get("evidence_quality"), 40),
        "phase": _bounded_label(finding.get("phase"), 40),
        "source": _bounded_label(finding.get("source"), 40),
        "file_name": _basename(finding.get("file_path")),
        "line_number": line_number,
        "title": _bounded_text(finding.get("user_title"), 200),
        "summary": _bounded_text(
            finding.get("user_summary") or finding.get("explanation"),
            MAX_FINDING_SUMMARY,
        ),
        "recommendation": _bounded_text(
            finding.get("recommended_user_action") or finding.get("recommendation"),
            MAX_FINDING_TEXT,
        ),
        "checked": _bounded_text(
            finding.get("what_aurascan_checked"), MAX_FINDING_TEXT
        ),
        "not_checked": _bounded_text(
            finding.get("what_aurascan_did_not_check"), MAX_FINDING_TEXT
        ),
        "blocks_installation": bool(finding.get("blocks_installation")),
        "requires_manual_review": bool(finding.get("requires_manual_review")),
    }


def project_scan_report(report: Mapping[str, object]) -> Dict[str, object]:
    """Project a saved ``ScanReport`` JSON into the bounded UI contract.

    Raw package bytes (``evidence_snippet``, ``raw_output``,
    ``technical_details``), absolute paths, finding identifiers and file hashes
    are deliberately dropped: the renderer is a view, not an evidence export.
    """

    if not isinstance(report, MappingABC):
        raise UISnapshotError("report is not a JSON object")
    schema_version = report.get("schema_version")
    if not isinstance(schema_version, str) or not schema_version:
        raise UISnapshotError("report has no schema version")
    package = report.get("package_metadata")
    if not isinstance(package, MappingABC):
        raise UISnapshotError("report has no package metadata")
    name = package.get("name")
    if not isinstance(name, str) or not name:
        raise UISnapshotError("report has no package name")
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise UISnapshotError("report has no findings list")

    projected_findings: List[Dict[str, object]] = []
    severity_counts = {severity: 0 for severity in REPORT_SEVERITIES}
    blocking = 0
    manual_review = 0
    for entry in findings:
        if not isinstance(entry, MappingABC):
            raise UISnapshotError("report finding is not an object")
        projected = _project_finding(entry)
        severity_counts[projected["severity"]] += 1
        blocking += 1 if projected["blocks_installation"] else 0
        manual_review += 1 if projected["requires_manual_review"] else 0
        if len(projected_findings) < MAX_FINDINGS:
            projected_findings.append(projected)

    messages: List[str] = []
    raw_messages = report.get("messages")
    if isinstance(raw_messages, list):
        for message in raw_messages[:MAX_MESSAGES]:
            text = _bounded_text(message, MAX_MESSAGE_TEXT)
            if text:
                messages.append(text)

    context: Dict[str, object] = {}
    for key in ("scan_policy", "scan_context", "scan_context_source"):
        value = report.get(key)
        if isinstance(value, str) and value:
            context[key] = _bounded_label(value, 64)

    return {
        "schema_version": _bounded_label(schema_version, 32),
        "scanner_version": _bounded_label(report.get("scanner_version"), 32),
        "package": {
            "name": _bounded_label(name, 128),
            "version": _bounded_label(package.get("version"), 64),
            "pkgbase": _bounded_label(package.get("pkgbase"), 128),
            "maintainer": _bounded_label(package.get("maintainer"), 128),
        },
        "risk": _project_risk(report.get("risk_summary")),
        "counts": {
            "total": len(findings),
            "by_severity": severity_counts,
            "blocking": blocking,
            "manual_review": manual_review,
            "truncated": len(findings) > MAX_FINDINGS,
        },
        "findings": projected_findings,
        "messages": messages,
        "context": context,
    }


def load_report_file(path: Path) -> Mapping[str, object]:
    try:
        with open(path, "rb") as handle:
            data = handle.read(MAX_REPORT_BYTES + 1)
    except OSError:
        raise UISnapshotError("report file could not be read") from None
    if len(data) > MAX_REPORT_BYTES:
        raise UISnapshotError("report file exceeds the contract bound")
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise UISnapshotError("report file is not a valid AuraScan JSON report") from None
    if not isinstance(parsed, MappingABC):
        raise UISnapshotError("report file is not a JSON object")
    return parsed


def build_report_snapshot(
    *,
    report: Mapping[str, object],
    app_version: str,
    generated_at: int,
    python_version: str,
    platform_name: str,
) -> Dict[str, object]:
    return {
        "app": {
            "version": app_version,
            "python": python_version,
            "platform": platform_name,
        },
        "contract": UI_CONTRACT,
        "generated_at": int(generated_at),
        "report": project_scan_report(report),
    }


def build_actions_snapshot(
    *,
    actions: Sequence[Mapping[str, object]],
    app_version: str,
    generated_at: int,
    python_version: str,
    platform_name: str,
) -> Dict[str, object]:
    return {
        "actions": [dict(action) for action in actions],
        "app": {
            "version": app_version,
            "python": python_version,
            "platform": platform_name,
        },
        "contract": UI_CONTRACT,
        "generated_at": int(generated_at),
    }


def build_ui_snapshot(
    *,
    doctor_checks: Sequence[Mapping[str, object]],
    intelligence: Optional[Mapping[str, object]],
    markers: Sequence[Mapping[str, object]],
    unseen_markers: Sequence[Mapping[str, object]],
    app_version: str,
    generated_at: int,
    python_version: str,
    platform_name: str,
    incidents_available: bool = True,
) -> Dict[str, object]:
    """Compose the ``aurascan-ui/1`` snapshot from already-collected evidence.

    This function is pure: callers supply evidence and a timestamp, so the
    contract can be tested without a host, a package manager, or the clock.
    """

    doctor_entries = _project_doctor_checks(doctor_checks)
    return {
        "app": {
            "version": app_version,
            "python": python_version,
            "platform": platform_name,
        },
        "contract": UI_CONTRACT,
        "doctor": {
            "ok": not any(entry["status"] == "error" for entry in doctor_entries),
            "checks": doctor_entries,
        },
        "generated_at": int(generated_at),
        "incidents": _project_incidents(
            markers, unseen_markers, available=incidents_available
        ),
        "intelligence": _project_intelligence(intelligence),
    }


def _default_doctor_checks() -> List[Mapping[str, object]]:
    from aurascan.core.config import user_env_path
    from aurascan.setup_wizard import build_doctor_checks

    return [
        check.to_dict()
        for check in build_doctor_checks(env_path=user_env_path())
    ]


def _default_intelligence() -> Optional[Mapping[str, object]]:
    from aurascan.core.intelligence_cli import intelligence_status_metadata

    try:
        return intelligence_status_metadata()
    except Exception:
        # A snapshot must degrade to an explicit unavailable state rather than
        # crash or silently claim a healthy detection-data identity.
        return None


def _default_incidents() -> Tuple[
    List[Mapping[str, object]], List[Mapping[str, object]], bool
]:
    from aurascan.core.incidents import pending_markers, unseen_pending_markers

    try:
        markers = pending_markers()
        unseen = unseen_pending_markers()
    except Exception:
        return [], [], False
    return markers, unseen, True


def _print_summary(snapshot: Mapping[str, object], stream) -> None:
    app = snapshot["app"]
    doctor = snapshot["doctor"]
    incidents = snapshot["incidents"]
    intelligence = snapshot["intelligence"]
    counts = {"ok": 0, "warn": 0, "error": 0}
    for check in doctor["checks"]:
        counts[check["status"]] += 1
    print("AuraScan UI snapshot ({0})".format(snapshot["contract"]), file=stream)
    print(
        "  AuraScan {0} on {1} (Python {2})".format(
            app["version"], app["platform"], app["python"]
        ),
        file=stream,
    )
    print(
        "  Checks: {0} ok, {1} warn, {2} error".format(
            counts["ok"], counts["warn"], counts["error"]
        ),
        file=stream,
    )
    print("  Intelligence: {0}".format(intelligence.get("status", "unknown")), file=stream)
    if incidents["available"]:
        print(
            "  Incidents: {0} pending, {1} unseen".format(
                incidents["pending"], incidents["unseen"]
            ),
            file=stream,
        )
    else:
        print("  Incidents: state unavailable", file=stream)
    print(
        "  Evidence only: this snapshot is not a certification of safety.",
        file=stream,
    )


def _print_report_summary(snapshot: Mapping[str, object], stream) -> None:
    report = snapshot["report"]
    package = report["package"]
    risk = report["risk"]
    counts = report["counts"]
    print("AuraScan report ({0})".format(snapshot["contract"]), file=stream)
    identity = "{0} {1}".format(package["name"], package["version"]).strip()
    print("  Package: {0}".format(identity), file=stream)
    if risk:
        print(
            "  Risk: {0} ({1})".format(risk["severity"], risk["action"]),
            file=stream,
        )
    print(
        "  Findings: {0} total, {1} blocking, {2} manual review".format(
            counts["total"], counts["blocking"], counts["manual_review"]
        ),
        file=stream,
    )
    for finding in report["findings"][:5]:
        location = finding["file_name"] or "report"
        if finding["line_number"]:
            location = "{0}:{1}".format(location, finding["line_number"])
        print(
            "  - {0} [{1}] {2}".format(
                finding["rule_id"], finding["severity"], location
            ),
            file=stream,
        )
    if counts["truncated"]:
        print(
            "  Display truncated to {0} findings; counts cover the full report.".format(
                MAX_FINDINGS
            ),
            file=stream,
        )
    print(
        "  Evidence only: this report is not a certification of safety.",
        file=stream,
    )


def _print_actions_summary(snapshot: Mapping[str, object], stream) -> None:
    print("AuraScan actions ({0})".format(snapshot["contract"]), file=stream)
    for action in snapshot["actions"]:
        scope = (
            "renderer may request"
            if action["renderer_may_request"]
            else "terminal only"
        )
        print(
            "  - {0} [{1}] {2}".format(action["id"], action["kind"], scope),
            file=stream,
        )
    print(
        "  The renderer supplies an action ID and declared arguments, never a command.",
        file=stream,
    )
    print(
        "  Mutating actions require a fresh confirmation of the exact command.",
        file=stream,
    )


def build_ui_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aurascan ui",
        description=(
            "Emit a read-only evidence snapshot for AuraScan desktop user "
            "interfaces, project a saved AuraScan JSON report, or list the fixed "
            "action catalog. The command never changes policy or local state."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_mode",
        help="emit the aurascan-ui/1 snapshot as JSON",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--report",
        type=Path,
        metavar="FILE",
        help="project a saved AuraScan JSON report instead of live evidence",
    )
    mode.add_argument(
        "--actions",
        action="store_true",
        dest="actions_mode",
        help="list the fixed desktop action catalog instead of live evidence",
    )
    return parser


def run_ui(
    argv=None,
    *,
    stdout=None,
    stderr=None,
    doctor_checks_provider: Optional[Callable] = None,
    intelligence_provider: Optional[Callable] = None,
    incidents_provider: Optional[Callable] = None,
    now: Optional[Callable[[], float]] = None,
    report_loader: Optional[Callable] = None,
) -> int:
    args = build_ui_parser().parse_args(argv)
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    doctor_provider = doctor_checks_provider or _default_doctor_checks
    intelligence_source = intelligence_provider or _default_intelligence
    incident_source = incidents_provider or _default_incidents
    report_source = report_loader or load_report_file
    timestamp = int(now() if callable(now) else time.time())
    try:
        if args.actions_mode:
            snapshot = build_actions_snapshot(
                actions=action_catalog(),
                app_version=installed_app_version(),
                generated_at=timestamp,
                python_version=platform.python_version(),
                platform_name=sys.platform,
            )
        elif args.report is not None:
            snapshot = build_report_snapshot(
                report=report_source(args.report),
                app_version=installed_app_version(),
                generated_at=timestamp,
                python_version=platform.python_version(),
                platform_name=sys.platform,
            )
        else:
            doctor_checks = doctor_provider()
            markers, unseen_markers, incidents_available = incident_source()
            snapshot = build_ui_snapshot(
                doctor_checks=doctor_checks,
                intelligence=intelligence_source(),
                markers=markers,
                unseen_markers=unseen_markers,
                app_version=installed_app_version(),
                generated_at=timestamp,
                python_version=platform.python_version(),
                platform_name=sys.platform,
                incidents_available=incidents_available,
            )
    except UISnapshotError as exc:
        print(
            "[AuraScan] Desktop snapshot unavailable: {0}".format(exc),
            file=stderr,
        )
        return 1
    except Exception:
        print(
            "[AuraScan] Desktop snapshot unavailable: evidence collection failed.",
            file=stderr,
        )
        return 1
    if args.json_mode:
        print(json.dumps(snapshot, indent=2, sort_keys=True), file=stdout)
    elif args.actions_mode:
        _print_actions_summary(snapshot, stdout)
    elif args.report is not None:
        _print_report_summary(snapshot, stdout)
    else:
        _print_summary(snapshot, stdout)
    return 0
