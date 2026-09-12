"""Local intelligence status and explicit administrative update operations."""

import argparse
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys

from aurascan.core.intelligence import IntelligenceError
from aurascan.core.intelligence_store import (
    IMPORT_ROOT, activate_bundle, assert_production_trust_configured,
    load_intelligence_snapshot, stage_offline_bundle,
)
from aurascan.core.intelligence_transport import STAGING_ROOT, assert_feed_configured, fetch_bundle
from aurascan.core.trusted_tools import (
    TrustedToolError, capture_trusted_system_tool, revalidate_trusted_system_tool,
    run_bounded_trusted_tool,
)


ACTIVATION_SERVICE = "aurascan-intelligence-activate.service"
IMPORT_SERVICE = "aurascan-intelligence-import.service"
UPDATE_TIMER = "aurascan-intelligence-update.timer"
FETCH_ACCOUNT = "aurascan-intel"
FETCH_SERVICE = "aurascan-intelligence-fetch.service"
AUTO_ENABLE_SERVICE = "aurascan-intelligence-auto-enable.service"
AUTO_DISABLE_SERVICE = "aurascan-intelligence-auto-disable.service"
STATUS_SCHEMA = "intelligence-status/1.0"
_STATUS_UNITS = (UPDATE_TIMER, FETCH_SERVICE, ACTIVATION_SERVICE, IMPORT_SERVICE,
                 AUTO_ENABLE_SERVICE, AUTO_DISABLE_SERVICE)
_STATUS_PROPERTIES = ("Id", "LoadState", "ActiveState", "UnitFileState", "Result")
_STATUS_OUTPUT_LIMIT = 8192


def _parse_service_status(output):
    """Reduce selected local unit properties to fixed, public status values."""
    if not isinstance(output, str) or len(output) > _STATUS_OUTPUT_LIMIT:
        raise ValueError("invalid service status")
    units = {}
    for block in output.strip().split("\n\n"):
        properties = {}
        for line in block.splitlines():
            name, separator, value = line.partition("=")
            if (not separator or name not in _STATUS_PROPERTIES or name in properties
                    or len(value) > 160 or any(not 32 <= ord(char) <= 126 for char in value)):
                raise ValueError("invalid service status")
            properties[name] = value
        unit = properties.get("Id")
        if (unit not in _STATUS_UNITS or unit in units
                or not {"Id", "LoadState", "ActiveState", "UnitFileState"} <= set(properties)):
            raise ValueError("incomplete service status")
        units[unit] = properties
    if set(units) != set(_STATUS_UNITS):
        raise ValueError("incomplete service status")

    timer = units[UPDATE_TIMER]
    automatic = "unavailable"
    if timer["LoadState"] == "loaded":
        state = (timer["UnitFileState"], timer["ActiveState"])
        if state == ("enabled", "active"):
            automatic = "enabled"
        elif state == ("disabled", "inactive"):
            automatic = "disabled"
        else:
            # Runtime-only enablement, masks and partial enable/stop operations
            # must not look like a verified disabled timer that can be enabled.
            automatic = "inconsistent"

    refresh_states = []
    for unit in _STATUS_UNITS[1:]:
        properties = units[unit]
        active = properties["ActiveState"]
        result = properties.get("Result", "")
        if properties["LoadState"] != "loaded" or not result:
            refresh_states.append("unavailable")
        elif active in ("active", "activating", "reloading", "deactivating", "refreshing"):
            refresh_states.append("running")
        elif active == "failed" or (active == "inactive" and result != "success"):
            refresh_states.append("failed")
        elif active == "inactive":
            refresh_states.append("idle")
        else:
            refresh_states.append("unavailable")
    refresh = next((state for state in ("running", "failed", "unavailable")
                    if state in refresh_states), "idle")
    return {"automatic_updates": automatic, "refresh_status": refresh}


def _service_status():
    """Inspect fixed system units locally; never start or authorize them."""
    unavailable = {"automatic_updates": "unavailable", "refresh_status": "unavailable"}
    try:
        tool = capture_trusted_system_tool("systemctl", which=lambda _name: "/usr/bin/systemctl")
        if tool is None:
            return unavailable
        revalidate_trusted_system_tool(tool)
        result = run_bounded_trusted_tool(
            [tool.path, "--no-pager", "--no-ask-password", "show", "--all",
             "--property=" + ",".join(_STATUS_PROPERTIES)] + list(_STATUS_UNITS),
            capture_output=True, timeout=10, text=True, cwd="/",
            env={"PATH": "/usr/bin:/usr/sbin", "LANG": "C", "LC_ALL": "C",
                 "HOME": "/", "SYSTEMD_PAGER": "cat", "SYSTEMD_COLORS": "0"},
        )
        revalidate_trusted_system_tool(tool)
        if result.returncode:
            return unavailable
        return _parse_service_status(result.stdout)
    except (OSError, ValueError, TrustedToolError, subprocess.SubprocessError):
        return unavailable


def _systemctl(arguments):
    tool = capture_trusted_system_tool("systemctl", which=lambda _name: "/usr/bin/systemctl")
    if tool is None:
        raise IntelligenceError("system service control is unavailable")
    revalidate_trusted_system_tool(tool)
    result = run_bounded_trusted_tool(
        [tool.path, "--no-pager", "--no-ask-password"] + list(arguments),
        capture_output=True, timeout=240, text=True, cwd="/",
        env={"PATH": "/usr/bin:/usr/sbin", "LANG": "C", "LC_ALL": "C",
             "HOME": "/", "SYSTEMD_PAGER": "cat", "SYSTEMD_COLORS": "0"},
    )
    if result.returncode:
        raise IntelligenceError("intelligence system service operation failed")


def _require_root():
    if os.geteuid() != 0:
        raise IntelligenceError("administrative authorization required; run this operation with sudo")


def _status(json_mode=False, include_services=False):
    metadata = load_intelligence_snapshot().metadata()
    try:
        assert_production_trust_configured()
        assert_feed_configured()
        metadata["update_channel"] = "configured"
    except IntelligenceError:
        metadata["update_channel"] = "unconfigured"
    if include_services:
        metadata["status_schema"] = STATUS_SCHEMA
        metadata.update(_service_status())
    if json_mode:
        print(json.dumps(metadata, sort_keys=True))
    else:
        print("AuraScan intelligence: " + str(metadata.get("status", "unknown")))
        print("Update channel: " + metadata["update_channel"])
        for name in ("source", "schema_version", "sequence", "digest", "reviewed_at", "activated_at", "expires_at",
                     "automatic_updates", "refresh_status"):
            if name in metadata:
                print(name.replace("_", " ") + ": " + str(metadata[name]))
    return metadata


def run_intelligence(argv=None):
    parser = argparse.ArgumentParser(prog="aurascan intelligence")
    operations = parser.add_subparsers(dest="operation", required=True)
    status = operations.add_parser("status", help="inspect local intelligence without network access")
    status.add_argument("--json", action="store_true")
    status.add_argument("--include-services", action="store_true",
                        help="also inspect local timer and refresh service state without changing it")
    operations.add_parser("update", help="download and activate the configured signed feed")
    offline = operations.add_parser("import", help="verify and activate an offline signed bundle")
    offline.add_argument("directory", type=Path)
    timer = operations.add_parser("auto-update", help="explicitly enable or disable the daily timer")
    timer.add_argument("state", choices=("enable", "disable"))
    args = parser.parse_args(argv)
    try:
        if args.operation == "status":
            _status(args.json, args.include_services)
            return 0
        _require_root()
        if args.operation == "auto-update" and args.state == "disable":
            _systemctl(["disable", "--now", UPDATE_TIMER])
            print("Automatic intelligence updates disabled.")
            return 0
        assert_production_trust_configured()
        if args.operation == "import":
            with stage_offline_bundle(args.directory.absolute()):
                _systemctl(["start", IMPORT_SERVICE])
        elif args.operation == "update":
            assert_feed_configured()
            _systemctl(["start", ACTIVATION_SERVICE])
        else:
            assert_feed_configured()
            _systemctl(["enable", "--now", UPDATE_TIMER])
            print("Daily automatic intelligence updates enabled.")
            return 0
        _status()
        return 0
    except (IntelligenceError, TrustedToolError) as exc:
        print("AuraScan intelligence: " + str(exc), file=sys.stderr)
        return 1
    except (OSError, subprocess.SubprocessError):
        print("AuraScan intelligence: local operation failed.", file=sys.stderr)
        return 1


def _service_main(argv):
    """Fixed installed service entry points; never expose trust/path overrides."""
    try:
        if argv == ["_fetch"]:
            if os.geteuid() == 0 or pwd.getpwuid(os.geteuid()).pw_name != FETCH_ACCOUNT:
                raise IntelligenceError("intelligence fetch requires its dedicated unprivileged account")
            assert_production_trust_configured()
            fetch_bundle()
        elif argv == ["_activate"]:
            _require_root()
            assert_production_trust_configured()
            activate_bundle(STAGING_ROOT)
        elif argv == ["_activate-import"]:
            _require_root()
            assert_production_trust_configured()
            activate_bundle(IMPORT_ROOT)
        elif argv == ["_auto-enable"]:
            return run_intelligence(["auto-update", "enable"])
        elif argv == ["_auto-disable"]:
            return run_intelligence(["auto-update", "disable"])
        else:
            raise IntelligenceError("invalid intelligence service operation")
        return 0
    except (IntelligenceError, TrustedToolError) as exc:
        print("AuraScan intelligence: " + str(exc), file=sys.stderr)
        return 1
    except (OSError, KeyError, subprocess.SubprocessError):
        print("AuraScan intelligence: service operation failed.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(_service_main(sys.argv[1:]))
