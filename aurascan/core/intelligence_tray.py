"""Bounded, asynchronous tray clients for the fixed intelligence CLI operations."""

import datetime
import json

from aurascan.core.trusted_tools import (
    TrustedToolError, capture_trusted_system_tool, revalidate_trusted_system_tool,
)


UPDATE_LABEL = "Update detection data"
AUTOMATIC_LABEL = "Automatic detection updates"
STATUS_LABEL = "Detection data status"
OUTPUT_LIMIT = 65_536
STATUS_TIMEOUT_MS = 30_000
MUTATION_TIMEOUT_MS = 300_000
CHILD_ENVIRONMENT = {
    "PATH": "/usr/bin:/usr/sbin", "HOME": "/", "LANG": "C", "LC_ALL": "C",
    "PYTHONNOUSERSITE": "1", "PYTHONSAFEPATH": "1",
}
_OPERATIONS = {
    "status": ("status", "--json", "--include-services"),
    "update": ("aurascan-intelligence-activate.service",),
    "enable": ("aurascan-intelligence-auto-enable.service",),
    "disable": ("aurascan-intelligence-auto-disable.service",),
}
UNAVAILABLE = (
    "Detection data status is unavailable. The installed AuraScan may need an "
    "update, or its local data/services need attention. Run aurascan intelligence "
    "status --json --include-services for details."
)


def trusted_command(operation):
    """No PATH, project setting, downloaded value, or caller-selected command."""
    if operation not in _OPERATIONS:
        raise ValueError("unsupported tray operation")
    names = ["aurascan"] if operation == "status" else ["systemctl", "setsid"]
    captured = []
    for name in names:
        tool = capture_trusted_system_tool(name, which=lambda item: "/usr/bin/" + item)
        if tool is None:
            raise TrustedToolError("required installed tool is unavailable")
        captured.append(tool)
    for tool in captured:
        revalidate_trusted_system_tool(tool)
    if operation == "status":
        return [captured[0].path, "intelligence"] + list(_OPERATIONS[operation])
    # systemctl remains unprivileged. systemd asks the desktop polkit agent to
    # authorize the fixed service; the root service owns the bounded operation.
    # No --no-ask-password: that would also suppress desktop authorization.
    # Detach from any controlling terminal so systemctl cannot start a tty
    # authentication agent behind the tray, including with older Qt bindings.
    return [captured[1].path, "--wait", captured[0].path, "--no-pager", "start"] + list(_OPERATIONS[operation])


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate status field")
        result[key] = value
    return result


def parse_status(raw):
    """Validate display fields; never render arbitrary child stdout or stderr."""
    if len(raw) > OUTPUT_LIMIT:
        raise ValueError("oversized status")
    data = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    if not isinstance(data, dict) or data.get("status_schema") != "intelligence-status/1.0":
        raise ValueError("unsupported status")
    if data.get("schema_version") != "1.0" or data.get("feed_id") != "aurascan-intelligence":
        raise ValueError("unsupported intelligence")
    choices = {
        "source": {"bundled", "installed", "bundled-fallback"},
        "status": {"bundled", "current", "stale", "unavailable"},
        "update_channel": {"configured", "unconfigured"},
        "automatic_updates": {"enabled", "disabled", "inconsistent", "unavailable"},
        "refresh_status": {"running", "failed", "idle", "unavailable"},
    }
    for key, allowed in choices.items():
        if not isinstance(data.get(key), str) or data[key] not in allowed:
            raise ValueError("invalid status field")
    sequence = data.get("sequence")
    if type(sequence) is not int or not 0 <= sequence <= 2 ** 63 - 1:
        raise ValueError("invalid sequence")
    digest = data.get("digest")
    if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError("invalid digest")
    for key in ("reviewed_at", "expires_at", "activated_at"):
        value = data.get(key)
        if not isinstance(value, str) or len(value) > 20:
            raise ValueError("invalid date")
        if not value and key != "reviewed_at":
            continue
        fmt = "%Y-%m-%d" if key == "reviewed_at" and len(value) == 10 else "%Y-%m-%dT%H:%M:%SZ"
        if datetime.datetime.strptime(value, fmt).strftime(fmt) != value:
            raise ValueError("invalid date")
    if data["status"] in {"current", "stale"}:
        if data["source"] != "installed" or not data["expires_at"] or not data["activated_at"] or not sequence:
            raise ValueError("incomplete installed status")
    if data["status"] == "bundled" and (data["source"] != "bundled" or sequence != 0):
        raise ValueError("inconsistent baseline status")
    coverage = data.get("coverage_error")
    if not isinstance(coverage, str) or len(coverage) > 1024 or (coverage and data["status"] != "unavailable"):
        raise ValueError("inconsistent coverage status")
    if data["source"] == "bundled-fallback" and (
            data["status"] != "unavailable" or not coverage or sequence != 0
            or data["activated_at"] or data["expires_at"] or data.get("manifest_digest") != ""):
        raise ValueError("inconsistent fallback status")
    return data


def status_text(data):
    freshness = {
        "bundled": "Bundled baseline; no independent update installed",
        "current": "Verified update has not expired",
        "stale": "Expired: detections retained; refresh recommended",
        "unavailable": "Coverage failure: active storage cannot be trusted",
    }[data["status"]]
    timer = {
        "enabled": "Enabled (daily, with randomized delay)",
        "disabled": "Disabled", "inconsistent": "Needs attention: timer state disagrees",
        "unavailable": "Cannot determine local timer state",
    }[data["automatic_updates"]]
    refresh = {
        "running": "Refresh in progress", "failed": "A refresh service reports failure",
        "idle": "No refresh running or service failure reported",
        "unavailable": "Service status unavailable",
    }[data["refresh_status"]]
    return "\n".join([
        "Source: " + ("Active storage unavailable; bundled fallback" if data["status"] == "unavailable"
                      else "Signed installed update" if data["source"] == "installed" else "Bundled with AuraScan"),
        "Data version: sequence {} (schema {})".format(data["sequence"], data["schema_version"]),
        "Content SHA-256: " + data["digest"][:16] + "…",
        "Reviewed: " + data["reviewed_at"],
        "Last successful activation (UTC): " + ("Unavailable" if data["status"] == "unavailable" else data["activated_at"] or "No signed update installed"),
        "Expiry (UTC): " + ("Unavailable" if data["status"] == "unavailable" else data["expires_at"] or "Not applicable to bundled baseline"),
        "Freshness: " + freshness,
        "Update channel: " + ("Configured" if data["update_channel"] == "configured" else "Not yet configured; bundled detections remain available"),
        "Automatic detection updates: " + timer,
        "Update services: " + refresh,
        "", "This local status cannot establish whether a newer public bundle exists.",
        "ClamAV signatures and AuraScan application updates are managed separately.",
    ])


class IntelligenceMenuController:
    def __init__(self, menu, *, process_factory, schedule_timeout, notify, show_status,
                 command_builder=trusted_command, busy_changed=lambda: None):
        self.update_action = menu.addAction(UPDATE_LABEL)
        self.auto_action = menu.addAction(AUTOMATIC_LABEL)
        self.auto_action.setCheckable(True)
        self.status_action = menu.addAction(STATUS_LABEL)
        self.process_factory = process_factory
        self.schedule_timeout = schedule_timeout
        self.notify = notify
        self.show_status = show_status
        self.command_builder = command_builder
        self.busy_changed = busy_changed
        self.current_process = None
        self.timer = None
        self.operation = ""
        self.stdout = bytearray()
        self.output_bytes = 0
        self.failure = ""
        self.last_error = ""
        self.data = None
        self.show_requested = False
        self.pending_mutation = ""
        self.mutation_active = False
        self.update_action.triggered.connect(lambda *_: self.mutate("update"))
        self.auto_action.triggered.connect(self.toggle)
        self.status_action.triggered.connect(lambda *_: self.refresh(show=True))
        self._apply()

    def _busy(self, active):
        self.mutation_active = active
        self.busy_changed()

    def _apply(self):
        data = self.data
        idle = self.current_process is None and not self.mutation_active
        configured = bool(data and data["update_channel"] == "configured")
        timer = data["automatic_updates"] if data else "unavailable"
        running = bool(data and data["refresh_status"] == "running")
        self.update_action.setEnabled(idle and configured and not running)
        # A disagreement needs explicit repair, not an optimistic checkbox toggle.
        self.auto_action.setChecked(timer == "enabled")
        self.auto_action.setEnabled(idle and not running and (timer == "enabled" or (timer == "disabled" and configured)))
        tooltip = "Administrator authorization required; refresh signed AuraScan indicators."
        if not data:
            tooltip = UNAVAILABLE
        elif not configured:
            tooltip = "The production update feed and signing keys are not yet configured."
        elif running:
            tooltip = "A detection data refresh is already running."
        self.update_action.setToolTip(tooltip)
        self.auto_action.setToolTip("Daily signed-data updates. " + (
            "Timer state needs review in Detection data status." if timer in {"inconsistent", "unavailable"}
            else tooltip))
        self.status_action.setToolTip("Inspect local data identity, freshness, and update services without downloading.")

    def toggle(self, *args):
        desired = args[0] if args and type(args[0]) is bool else self.auto_action.isChecked()
        self._apply()  # Restore observed state until the service confirms the change.
        return self.mutate("enable" if desired else "disable")

    def mutate(self, operation):
        if operation not in {"update", "enable", "disable"} or self.current_process is not None or self.mutation_active:
            return False
        if not self.data or self.data["refresh_status"] == "running":
            return False
        timer = self.data["automatic_updates"]
        if operation == "disable":
            allowed = timer == "enabled"
        else:
            allowed = self.data["update_channel"] == "configured"
            allowed = allowed and (timer == "disabled" if operation == "enable" else self.data["refresh_status"] != "running")
        if not allowed:
            return False
        self._busy(True)
        return self._start(operation)

    def refresh(self, show=False):
        self.show_requested = self.show_requested or show
        if self.current_process is not None or self.mutation_active:
            return False
        return self._start("status")

    def _start(self, operation):
        self.operation = operation
        self.stdout = bytearray()
        self.output_bytes = 0
        self.failure = ""
        try:
            command = self.command_builder(operation)
            process = self.process_factory()
            self.current_process = process
            process.setProgram(command[0])
            process.setArguments(command[1:])
            process.readyReadStandardOutput.connect(lambda: self._drain(process, False))
            process.readyReadStandardError.connect(lambda: self._drain(process, True))
            process.finished.connect(lambda code, status=0: self._finished(process, code, status))
            process.errorOccurred.connect(lambda *_: self._stop(process, "The detection data command could not complete."))
            timeout = STATUS_TIMEOUT_MS if operation == "status" else MUTATION_TIMEOUT_MS
            self.timer = self.schedule_timeout(process, timeout, lambda: self._stop(
                process, "The detection data command timed out. An already started system service may still finish; inspect Detection data status."))
            self._apply()
            process.start()
            return True
        except (TrustedToolError, OSError, ValueError, TypeError, AttributeError, RuntimeError):
            self.failure = "The trusted installed AuraScan command or system service client is unavailable. Use the intelligence CLI with sudo if needed."
            if self.current_process is not None:
                self._stop(self.current_process, self.failure)
            else:
                self._complete(False, 1)
            return False

    def _drain(self, process, error):
        if process is not self.current_process:
            return
        chunk = bytes(process.readAllStandardError() if error else process.readAllStandardOutput())
        if not chunk:
            return
        self.output_bytes += len(chunk)
        if not error:
            self.stdout.extend(chunk[:max(0, OUTPUT_LIMIT - len(self.stdout))])
        if self.output_bytes > OUTPUT_LIMIT:
            self._stop(process, "The detection data command exceeded its output limit.")

    def _stop(self, process, message):
        if process is not self.current_process:
            return
        if not self.failure:
            self.failure = message
        # Keep the child and mutation guard until Qt observes its exit.
        state = process.state()
        running = getattr(state, "name", "") != "NotRunning" if hasattr(state, "name") else state != 0
        if running:
            process.kill()
        else:
            self._finished(process, 1, 1)

    def _finished(self, process, code, exit_status):
        if process is not self.current_process:
            return
        self._drain(process, False)
        self._drain(process, True)
        if process is not self.current_process:
            return
        self.current_process = None
        if self.timer is not None:
            self.timer.stop()
            self.timer.deleteLater()
            self.timer = None
        process.deleteLater()
        normal = getattr(exit_status, "name", "") == "NormalExit" if hasattr(exit_status, "name") else exit_status == 0
        self._complete(not self.failure and normal and code == 0, code)

    def _complete(self, ok, code):
        operation = self.operation
        if operation != "status":
            if ok:
                self.pending_mutation = operation
            else:
                self.last_error = self.failure or (
                    "The detection data request failed or administrator authorization was canceled or denied. "
                    "Inspect Detection data status; check the desktop authentication agent or use the intelligence CLI with sudo. "
                    "An already started system service may still finish.")
                self.notify("AuraScan detection data", self.last_error)
            # Always re-read state, including after cancellation or timeout.
            self._start("status")
            return
        try:
            self.data = parse_status(bytes(self.stdout)) if ok else None
        except (ValueError, UnicodeError, TypeError, RecursionError, OverflowError):
            self.data = None
        if self.pending_mutation:
            pending = self.pending_mutation
            self.pending_mutation = ""
            confirmed = False
            if self.data:
                if pending == "update":
                    confirmed = self.data["status"] == "current" and self.data["source"] == "installed"
                else:
                    confirmed = self.data["automatic_updates"] == ("enabled" if pending == "enable" else "disabled")
            if confirmed:
                self.last_error = ""
                message = ("Signed detection data verified; installed sequence {}.".format(self.data["sequence"]) if pending == "update"
                           else "Automatic detection updates are now {}.".format("enabled" if pending == "enable" else "disabled"))
            else:
                self.last_error = "The command finished, but its resulting detection data state could not be confirmed. Inspect Detection data status."
                message = self.last_error
            self.notify("AuraScan detection data", message)
        self._busy(False)
        self._apply()
        if self.show_requested:
            self.show_requested = False
            message = status_text(self.data) if self.data else UNAVAILABLE
            if self.last_error:
                message += "\n\nLast tray operation: " + self.last_error
            self.show_status("AuraScan detection data", message)


def build_intelligence_menu(menu, tray, QtCore, QtWidgets, *, clear_notification, busy_changed):
    def process_factory():
        process = QtCore.QProcess(tray)
        environment = QtCore.QProcessEnvironment()
        for key, value in CHILD_ENVIRONMENT.items():
            environment.insert(key, value)
        process.setProcessEnvironment(environment)
        process.setWorkingDirectory("/")
        process.setStandardInputFile("/dev/null")
        return process

    def schedule(process, timeout, callback):
        timer = QtCore.QTimer(process)
        timer.setSingleShot(True)
        timer.timeout.connect(callback)
        timer.start(timeout)
        return timer

    def notify(title, message):
        clear_notification()
        tray.showMessage(title, message)

    def show_status(title, message):
        dialog = QtWidgets.QMessageBox()
        dialog.setWindowTitle(title)
        dialog.setTextFormat(QtCore.Qt.TextFormat.PlainText)
        dialog.setText(message)
        dialog.exec()

    return IntelligenceMenuController(menu, process_factory=process_factory,
        schedule_timeout=schedule, notify=notify, show_status=show_status,
        busy_changed=busy_changed)
