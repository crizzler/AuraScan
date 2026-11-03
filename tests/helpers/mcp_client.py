"""Harness for ``aurascan-mcp`` tests: one spawned subprocess client and one in-process loop.

The spawned client is a real pipe, so framing, stdout purity and signal behaviour are exercised as
shipped. Protocol-only variants (timeout, cancellation, injected handlers) run in-process against the
same ``Protocol`` object with a ``StringIO`` sink — ``setitimer`` needs the main thread, which pytest
gives us.

Outbound encoding is ``ensure_ascii=True`` here too: a lone surrogate is the same trap on the client
side that it is on the server side.
"""

import io
import json
import os
import queue
import subprocess
import sys
import threading

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def honour_line():
    from aurascan.mcp.registry import HONESTY_LINE

    return HONESTY_LINE


def encode(message):
    return json.dumps(message, ensure_ascii=True, separators=(",", ":")).encode("utf-8") + b"\n"


class Client(object):
    def __init__(self, root, args=(), env=None):
        command = [sys.executable, "-m", "aurascan.mcp", "--root", str(root)]
        command.extend(args)
        environment = dict(os.environ)
        environment["PYTHONPATH"] = REPO_ROOT
        if env:
            environment.update(env)
        self.proc = subprocess.Popen(
            command,
            cwd=REPO_ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )
        self._lines = queue.Queue()
        self._errors = []
        self._out = threading.Thread(target=self._pump)
        self._out.daemon = True
        self._out.start()
        self._err = threading.Thread(target=self._err_pump)
        self._err.daemon = True
        self._err.start()

    def _pump(self):
        for line in self.proc.stdout:
            self._lines.put(line)
        self._lines.put(b"")

    def _err_pump(self):
        for line in self.proc.stderr:
            self._errors.append(line)

    # -- sending --------------------------------------------------------- #

    def send(self, message):
        self.send_raw(encode(message))

    def send_raw(self, data):
        self.proc.stdin.write(data)
        self.proc.stdin.flush()

    # -- reading --------------------------------------------------------- #

    def read_raw(self, timeout=10.0):
        line = self._lines.get(timeout=timeout)
        assert line != b"", "server closed stdout before answering"
        return line

    def read(self, timeout=10.0):
        return json.loads(self.read_raw(timeout).decode("utf-8"))

    def read_none(self, timeout=0.5):
        try:
            line = self._lines.get(timeout=timeout)
        except queue.Empty:
            return True
        return line == b""

    def read_result(self, timeout=10.0):
        """Return the decoded text body of a successful tool result."""
        message = self.read(timeout)
        assert message["result"]["isError"] is False, message["result"]
        return json.loads(message["result"]["content"][0]["text"])

    def read_error(self, timeout=10.0):
        message = self.read(timeout)
        assert message["result"]["isError"] is True, message["result"]
        return json.loads(message["result"]["content"][0]["text"])["error"]

    def initialize(self):
        self.send({
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18"},
            "id": 1,
        })
        return self.read()

    def call(self, tool, arguments=None, request_id=99):
        self.send({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments or {}},
            "id": request_id,
        })

    # -- lifecycle ------------------------------------------------------- #

    def stderr_text(self):
        return b"".join(self._errors).decode("utf-8", "replace")

    def wait(self, timeout=10.0):
        return self.proc.wait(timeout=timeout)

    def close(self):
        try:
            self.proc.stdin.close()
        except (BrokenPipeError, ValueError):
            pass
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def spawn(root, args=(), env=None):
    return Client(root, args=args, env=env)


class Loop(object):
    """In-process server loop over a ``StringIO`` sink."""

    def __init__(self, roots, budgets=None):
        from aurascan.mcp.protocol import Protocol
        from aurascan.mcp.server import Server

        self.out = io.StringIO()
        self.server = Server(roots)
        self.server.tools = dict(self.server.tools)
        self.protocol = Protocol(self.out, self.server, budgets=budgets)

    def feed(self, message):
        self.protocol.dispatch(encode(message))

    def call(self, tool, arguments=None):
        self.feed({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments or {}},
            "id": len(self.lines()) + 1,
        })

    def feed_raw(self, data):
        self.protocol.dispatch(data)

    def enqueue(self, message):
        self.protocol.queue.put(("line", encode(message).rstrip(b"\n")))

    def lines(self):
        text = self.out.getvalue()
        return [json.loads(line) for line in text.splitlines() if line.strip()]

    def only(self):
        lines = self.lines()
        assert len(lines) == 1, lines
        return lines[0]
