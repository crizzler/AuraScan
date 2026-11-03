"""Newline-delimited JSON-RPC 2.0 framing, dispatch, timeouts and cancellation.

Three rules hold the whole module together:

1. **stdout is protocol.** fd 1 is duplicated at startup and fd 2 is dup'ed onto fd 1, so a stray
   ``print`` anywhere below lands on stderr. One message per line, one flush per message, and every
   message is built with ``ensure_ascii=True`` — a lone surrogate is valid JSON but is not
   UTF-8-encodable, and a partial line is the worst place to find that out.
2. **Ingest is threaded, dispatch is not.** A reader thread owns stdin and the over-cap discard;
   the main thread alone writes. A handler therefore never blocks the arrival of
   ``notifications/cancelled``.
3. **Timeouts are ours.** ``setitimer`` around the handler with the previous ``SIGALRM`` handler
   saved and restored, so a slow tool produces a useful ``isError`` instead of a client kill.
"""

import json
import os
import queue
import signal
import sys
import threading

from . import errors, results
from .errors import TimeoutExpired, ToolError

MAX_LINE_BYTES = 8 * 1024 * 1024
_READ_CHUNK = 65536
_MISSING = object()

_METHODS_WITHOUT_PARAMS = ("ping", "tools/list", "shutdown")


def _id_key(value):
    if isinstance(value, bool):
        return ("bool", value)
    if isinstance(value, (int, float)):
        return ("number", float(value))
    if isinstance(value, str):
        return ("string", value)
    return ("other", repr(value))


def _is_scalar_id(value):
    return isinstance(value, (str, int, float)) and not isinstance(value, bool)


class Context(object):
    """Per-call state a handler may poll. ``roots`` is the resolved root list."""

    __slots__ = ("roots", "_event")

    def __init__(self, roots):
        self.roots = roots
        self._event = threading.Event()

    def cancel(self):
        self._event.set()

    def cancelled(self):
        return self._event.is_set()


class Protocol(object):
    def __init__(self, out, server, budgets=None, max_line_bytes=MAX_LINE_BYTES):
        self._out = out
        self._server = server
        self._budgets = dict(budgets or {})
        self._max_line_bytes = max_line_bytes
        self.queue = queue.Queue()
        self.closing = False
        self._stopping = False
        self._lock = threading.Lock()
        self._current = None
        self._context = None
        self._reader = None

    # -- output ---------------------------------------------------------- #

    def _write(self, message):
        line = json.dumps(message, ensure_ascii=True, separators=(",", ":"))
        try:
            self._out.write(line + "\n")
            self._out.flush()
        except (BrokenPipeError, ValueError):
            self._stopping = True

    def _write_error(self, request_id, code, message, data=None):
        payload = {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}
        if data is not None:
            payload["error"]["data"] = data
        self._write(payload)

    # -- ingest ---------------------------------------------------------- #

    def _note_cancel(self, line):
        try:
            message = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return
        if not isinstance(message, dict) or "id" in message:
            return
        if message.get("method") != "notifications/cancelled":
            return
        params = message.get("params")
        if not isinstance(params, dict) or "requestId" not in params:
            return
        key = _id_key(params["requestId"])
        with self._lock:
            current = self._current
            context = self._context
        # A cancel for a queued-but-not-started id is dropped: only the running id is compared.
        if current is not None and context is not None and current == key:
            context.cancel()

    def _read_loop(self, read_fd):
        buffer = bytearray()
        discarding = False
        while True:
            try:
                chunk = os.read(read_fd, _READ_CHUNK)
            except OSError:
                chunk = b""
            if not chunk:
                if buffer and not discarding and buffer.strip():
                    self._note_cancel(bytes(buffer))
                    self.queue.put(("line", bytes(buffer)))
                    buffer = bytearray()
                self.queue.put(("eof", None))
                return
            start = 0
            while True:
                index = chunk.find(b"\n", start)
                if index < 0:
                    if not discarding:
                        buffer += chunk[start:]
                        if len(buffer) > self._max_line_bytes:
                            discarding = True
                            self.queue.put(("oversize", len(buffer)))
                            buffer = bytearray()
                    break
                piece = chunk[start:index]
                start = index + 1
                if discarding:
                    discarding = False
                    continue
                buffer += piece
                if len(buffer) > self._max_line_bytes:
                    self.queue.put(("oversize", len(buffer)))
                    buffer = bytearray()
                    continue
                line = bytes(buffer)
                buffer = bytearray()
                if line.strip():
                    self._note_cancel(line)
                    self.queue.put(("line", line))

    # -- run ------------------------------------------------------------- #

    def run(self, read_fd=0):
        self._reader = threading.Thread(target=self._read_loop, args=(read_fd,))
        self._reader.daemon = True
        self._reader.start()
        try:
            self.run_queue()
        finally:
            if self._reader is not None:
                self._reader.join(0.2)

    def run_queue(self):
        while True:
            kind, payload = self.queue.get()
            if kind == "eof":
                return
            if kind == "oversize":
                self._write_error(
                    None,
                    errors.PARSE_ERROR,
                    "Parse error",
                    "line exceeds %d bytes" % (self._max_line_bytes,),
                )
                continue
            self.dispatch(payload)
            if self._stopping:
                return

    def dispatch(self, line):
        try:
            text = line.decode("utf-8")
        except UnicodeDecodeError:
            self._write_error(None, errors.PARSE_ERROR, "Parse error", "line is not valid UTF-8")
            return
        try:
            message = json.loads(text)
        except ValueError:
            self._write_error(None, errors.PARSE_ERROR, "Parse error", "line is not JSON")
            return
        if isinstance(message, list):
            self._write_error(None, errors.INVALID_REQUEST, "Invalid Request", "batch not supported")
            return
        if not isinstance(message, dict):
            self._write_error(None, errors.INVALID_REQUEST, "Invalid Request", "not an object")
            return

        request_id = message.get("id", _MISSING)
        echo_id = request_id if _is_scalar_id(request_id) else None
        if message.get("jsonrpc") != "2.0":
            self._write_error(echo_id, errors.INVALID_REQUEST, "Invalid Request", "jsonrpc must be 2.0")
            return
        if request_id is not _MISSING and not _is_scalar_id(request_id):
            self._write_error(None, errors.INVALID_REQUEST, "Invalid Request", "id must be scalar")
            return
        method = message.get("method")
        if not isinstance(method, str):
            self._write_error(echo_id, errors.INVALID_REQUEST, "Invalid Request", "method must be a string")
            return

        params = message.get("params", _MISSING)
        if request_id is _MISSING:
            self._handle_notification(method, params)
        else:
            self._handle_request(request_id, method, params)

    # -- notifications --------------------------------------------------- #

    def _handle_notification(self, method, params):
        if method == "exit":
            self._stopping = True
            return
        try:
            self._server.notify(method, params)
        except Exception:  # a notification never gets an answer, successful or not
            pass

    # -- requests -------------------------------------------------------- #

    def _handle_request(self, request_id, method, params):
        if params is _MISSING:
            params = {}
        elif params is None:
            # The only exception to the non-object rule: ``null`` is absent, except for
            # ``tools/call`` which genuinely needs a params object.
            if method == "tools/call":
                self._write_error(
                    request_id, errors.INVALID_PARAMS, "Invalid params", "params must be an object"
                )
                return
            params = {}
        elif not isinstance(params, dict):
            self._write_error(request_id, errors.INVALID_PARAMS, "Invalid params", "params must be an object")
            return

        if method == "tools/call":
            self._handle_tool_call(request_id, params)
            return
        if method in _METHODS_WITHOUT_PARAMS or method == "initialize":
            handler = getattr(self._server, method.replace("/", "_"))
            try:
                self._write({"jsonrpc": "2.0", "id": request_id, "result": handler(params)})
            except Exception as exc:
                self._write_error(
                    request_id,
                    errors.INTERNAL_ERROR,
                    "Internal error",
                    "%s: %s" % (type(exc).__name__, str(exc)[:200]),
                )
            return
        self._write_error(request_id, errors.METHOD_NOT_FOUND, "Method not found", "unknown method")

    def _handle_tool_call(self, request_id, params):
        name = params.get("name")
        if not isinstance(name, str) or name not in self._server.tools:
            self._write_error(
                request_id, errors.INVALID_PARAMS, "Invalid params", "unknown tool: %s" % (name,)
            )
            return
        tool = self._server.tools[name]
        arguments = params.get("arguments", {})
        if not isinstance(arguments, dict):
            self._write_error(
                request_id, errors.INVALID_PARAMS, "Invalid params", "arguments must be an object"
            )
            return
        problems = self._server.validate(tool, arguments)
        if problems:
            self._write(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": results.error_result("invalid_arguments", "; ".join(problems)),
                }
            )
            return
        try:
            envelope = self._run_tool(tool, arguments, request_id)
        except Exception as exc:
            self._write_error(
                request_id,
                errors.INTERNAL_ERROR,
                "Internal error",
                "%s: %s" % (type(exc).__name__, str(exc)[:200]),
            )
            return
        self._write({"jsonrpc": "2.0", "id": request_id, "result": envelope})

    def _run_tool(self, tool, arguments, request_id):
        context = Context(self._server.roots)
        budget = self._budgets.get(tool.name, tool.budget)
        previous_handler = signal.getsignal(signal.SIGALRM)
        with self._lock:
            self._current = _id_key(request_id)
            self._context = context
        try:
            signal.signal(signal.SIGALRM, _alarm)
            signal.setitimer(signal.ITIMER_REAL, budget)
            try:
                return tool.handler(context, arguments)
            except TimeoutExpired:
                return results.error_result(
                    "timeout", "tool exceeded its %ss budget" % (budget,)
                )
            except ToolError as exc:
                return results.error_result(exc.code, exc.detail)
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)
        finally:
            signal.signal(signal.SIGALRM, previous_handler)
            with self._lock:
                self._current = None
                self._context = None


def _alarm(signum, frame):
    raise TimeoutExpired("budget expired")


def guard_stdout():
    """Duplicate fd 1 for the protocol and point fd 1 at stderr; return the protocol stream."""
    out = os.fdopen(os.dup(1), "w", encoding="utf-8", newline="\n", buffering=1)
    os.dup2(2, 1)
    sys.stdout = sys.stderr
    return out
