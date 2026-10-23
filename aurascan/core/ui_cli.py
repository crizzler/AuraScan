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
import sys
import time
from collections.abc import Mapping as MappingABC
from typing import Callable, Dict, List, Mapping, Optional, Sequence, Tuple

UI_CONTRACT = "aurascan-ui/1"
CHECK_STATUSES = ("ok", "warn", "error")
SEVERITY_RANK = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
MAX_CHECKS = 1000
MAX_MARKERS = 100
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


def build_ui_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aurascan ui",
        description=(
            "Emit a read-only evidence snapshot for AuraScan desktop user "
            "interfaces. The command never changes policy or local state."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_mode",
        help="emit the aurascan-ui/1 snapshot as JSON",
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
) -> int:
    args = build_ui_parser().parse_args(argv)
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    doctor_provider = doctor_checks_provider or _default_doctor_checks
    intelligence_source = intelligence_provider or _default_intelligence
    incident_source = incidents_provider or _default_incidents
    timestamp = int(now() if callable(now) else time.time())
    try:
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
    else:
        _print_summary(snapshot, stdout)
    return 0
