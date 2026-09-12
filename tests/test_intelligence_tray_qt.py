"""Optional real-Qt checks with inert children, private files and no services."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest


# Each binding gets its own interpreter: importing both into one Qt application
# can hide ownership/lifetime failures. This is trusted test code, never a
# collected package, fixture command or instruction-file payload.
_SMOKE = r'''
import errno
import json
import os
from pathlib import Path
import sys
import time

sys.path.insert(0, sys.argv[1])
binding = __import__(sys.argv[2], fromlist=("QtCore", "QtWidgets"))
QtCore, QtWidgets = binding.QtCore, binding.QtWidgets
from aurascan.core import intelligence_tray as ui

scratch = Path(sys.argv[3])
witness = scratch / "enabled.json"
cancel_started = scratch / "cancel-started"
app = QtWidgets.QApplication([])
app.setQuitOnLastWindowClosed(False)
menu = QtWidgets.QMenu()

class Tray(QtCore.QObject):
    def __init__(self):
        super().__init__()
        self.messages = []

    def showMessage(self, title, message):
        self.messages.append((title, message))

tray = Tray()
cleared = []
busy = []
controller = ui.build_intelligence_menu(
    menu, tray, QtCore, QtWidgets,
    clear_notification=lambda: cleared.append(True),
    busy_changed=lambda: busy.append(controller.mutation_active),
)
dialogs = []
controller.show_status = lambda *args: dialogs.append(args)
calls, destroyed, finished = [], [], []
factory = controller.process_factory

def record_process():
    process = factory()
    number = len(calls)
    process.destroyed.connect(lambda *_: destroyed.append(number))
    process.finished.connect(lambda code, *_: finished.append((number, code)))
    assert process.workingDirectory() == "/"
    environment = process.processEnvironment()
    assert set(environment.keys()) == set(ui.CHILD_ENVIRONMENT)
    assert environment.value("HOME") == "/"
    assert not environment.contains("AURASCAN_AI_KEY")
    return process

controller.process_factory = record_process
schedule = controller.schedule_timeout

def short_cancel_timeout(process, timeout, callback):
    # Exercise the actual QTimer -> kill -> Qt error/finished ordering. A
    # sleeping child owns no authority and changes no service state.
    delay = 300 if calls[-1] == "update" else 5000
    return schedule(process, delay, callback)

controller.schedule_timeout = short_cancel_timeout
payload = {
    "status_schema": "intelligence-status/1.0",
    "schema_version": "1.0", "feed_id": "aurascan-intelligence",
    "source": "bundled", "status": "bundled", "sequence": 0,
    "digest": "a" * 64, "reviewed_at": "2026-09-12",
    "activated_at": "", "expires_at": "",
    "update_channel": "configured", "automatic_updates": "disabled",
    "refresh_status": "idle", "coverage_error": "",
}
status_code = (
    "import json,sys; from pathlib import Path; "
    "data=json.loads(sys.argv[1]); "
    "data['automatic_updates']='enabled' if Path(sys.argv[2]).exists() else 'disabled'; "
    "print(json.dumps(data))"
)
enable_code = r"""
import errno, json, os, sys
from pathlib import Path
try:
    fd = os.open('/dev/tty', os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY)
except OSError as exc:
    assert exc.errno == errno.ENXIO
    terminal = False
else:
    os.close(fd)
    terminal = True
Path(sys.argv[1]).write_text(json.dumps({
    'pid': os.getpid(), 'sid': os.getsid(0), 'pgrp': os.getpgrp(),
    'uid': os.getuid(), 'terminal': terminal,
}), encoding='utf-8')
"""
cancel_code = (
    "import sys,time; from pathlib import Path; "
    "Path(sys.argv[1]).write_text('started',encoding='utf-8'); time.sleep(3)"
)

def command(operation):
    calls.append(operation)
    if operation == "status":
        return [sys.executable, "-I", "-c", status_code, json.dumps(payload), str(witness)]
    code, target = (enable_code, witness) if operation == "enable" else (cancel_code, cancel_started)
    assert operation in {"enable", "update"}
    # Match the production session boundary without contacting systemd or
    # invoking authentication. No --fork: the child remains directly owned.
    return ["/usr/bin/setsid", "--wait", sys.executable, "-I", "-c", code, str(target)]

controller.command_builder = command

def wait_until(predicate):
    deadline = time.monotonic() + 8
    while not predicate():
        app.processEvents()
        if time.monotonic() >= deadline:
            raise AssertionError("real Qt child did not complete within test deadline")
        time.sleep(0.002)
    QtCore.QCoreApplication.sendPostedEvents(None, QtCore.QEvent.Type.DeferredDelete)
    app.processEvents()

assert controller.refresh()
assert controller.current_process is not None and controller.data is None
wait_until(lambda: controller.current_process is None)
assert calls == ["status"] and destroyed == [1]
assert controller.update_action.isEnabled()
assert not controller.auto_action.isChecked()

controller.auto_action.trigger()
assert controller.mutation_active
assert not controller.auto_action.isChecked()
wait_until(lambda: controller.current_process is None)
assert calls == ["status", "enable", "status"]
assert not controller.mutation_active and controller.auto_action.isChecked()
identity = json.loads(witness.read_text(encoding="utf-8"))
assert identity['uid'] == os.getuid()
assert identity['pid'] == identity['sid'] == identity['pgrp']
assert identity['sid'] != os.getsid(0) and not identity['terminal']
assert len(destroyed) == 3 and len(finished) == 3

assert controller.mutate("update")
assert controller.mutation_active
controller.refresh(show=True)
wait_until(lambda: controller.current_process is None)
assert cancel_started.read_text(encoding="utf-8") == "started"
assert calls == ["status", "enable", "status", "update", "status"]
assert not controller.mutation_active and controller.auto_action.isChecked()
assert len(destroyed) == 5 and len(finished) == 5
assert next(code for number, code in finished if number == 4) != 0
assert dialogs and controller.last_error
assert 'timed out' in controller.last_error.lower()
assert all('signed detection data verified' not in message.lower() for _, message in tray.messages)
assert len(cleared) == len(tray.messages)
assert busy[-1] is False
print(json.dumps({'binding': sys.argv[2], 'retired': len(destroyed), 'session_isolated': True}))
'''


@pytest.mark.parametrize("binding", ["PyQt6", "PySide6"])
def test_real_qt_intelligence_child_lifecycle_and_session_boundary(binding, tmp_path):
    if importlib.util.find_spec(binding) is None:
        pytest.skip("optional Qt binding is not installed in this interpreter")
    if not Path("/usr/bin/setsid").is_file():
        pytest.skip("the supported Linux session helper is unavailable")
    home = tmp_path / "home"
    home.mkdir()
    runtime = tmp_path / "runtime"
    runtime.mkdir(mode=0o700)
    result = subprocess.run(
        [sys.executable, "-I", "-c", _SMOKE, str(Path(__file__).resolve().parents[1]),
         binding, str(tmp_path)],
        cwd=str(tmp_path), stdin=subprocess.DEVNULL, capture_output=True,
        text=True, timeout=20,
        env={"PATH": "/usr/bin:/usr/sbin", "HOME": str(home), "LANG": "C", "LC_ALL": "C",
             "XDG_RUNTIME_DIR": str(runtime), "QT_QPA_PLATFORM": "offscreen",
             "AURASCAN_AI_KEY": "inert-environment-canary"},
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == {
        "binding": binding, "retired": 5, "session_isolated": True,
    }
    assert "inert-environment-canary" not in result.stdout + result.stderr
