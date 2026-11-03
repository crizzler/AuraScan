"""Console-script entry point: ``aurascan-mcp --root <dir> [--root <dir>] ...``.

Everything diagnostic goes to stderr, prefixed, because stdout carries protocol only.
"""

import os
import signal
import sys

from . import protocol, registry, server as server_module

BANNER = "[aurascan-mcp] "


def _log(message):
    sys.stderr.write(BANNER + message + "\n")
    sys.stderr.flush()


def _parse_budget(text):
    name, _, raw = text.partition("=")
    if not name or not raw:
        raise ValueError("expected <tool>=<seconds>, got %r" % (text,))
    if name not in registry.TOOLS_BY_NAME:
        raise ValueError("unknown tool %r" % (name,))
    try:
        seconds = int(raw)
    except ValueError:
        raise ValueError("seconds must be an integer, got %r" % (raw,))
    if seconds < 1:
        raise ValueError("seconds must be at least 1, got %d" % (seconds,))
    return name, seconds


def build_parser():
    import argparse

    parser = argparse.ArgumentParser(
        prog="aurascan-mcp",
        description=(
            "Read-only stdio MCP server for AuraScan. One JSON-RPC 2.0 message per line. "
            "Four tools: %s." % (", ".join(registry.TOOLS_BY_NAME),)
        ),
    )
    parser.add_argument(
        "--root",
        action="append",
        default=None,
        metavar="DIR",
        help="root a scan_path may resolve inside; repeatable (default: the current directory)",
    )
    parser.add_argument(
        "--budget",
        action="append",
        default=None,
        metavar="TOOL=SECONDS",
        help="override a per-call timeout in seconds; repeatable, integer >= 1",
    )
    parser.add_argument(
        "--max-line-bytes",
        type=int,
        default=protocol.MAX_LINE_BYTES,
        metavar="N",
        help="reject an inbound line longer than N bytes (default: %d)" % (protocol.MAX_LINE_BYTES,),
    )
    return parser


def main(argv=None):
    out = protocol.guard_stdout()
    args = build_parser().parse_args(argv)

    budgets = {}
    for entry in args.budget or ():
        try:
            name, seconds = _parse_budget(entry)
        except ValueError as exc:
            _log("--budget: %s" % (exc,))
            return 2
        budgets[name] = seconds

    if args.max_line_bytes < 1:
        _log("--max-line-bytes: must be at least 1")
        return 2

    roots = [os.path.realpath(item) for item in (args.root or [os.getcwd()])]
    _log("aurascan-mcp %s; roots: %s" % (server_module.SERVER_INFO["version"], ", ".join(roots)))

    server = server_module.Server(roots)
    loop = protocol.Protocol(out, server, budgets=budgets, max_line_bytes=args.max_line_bytes)

    def stop(signum, frame):
        loop.queue.put(("eof", None))

    previous = {}
    for number in (signal.SIGTERM, signal.SIGINT):
        previous[number] = signal.getsignal(number)
        signal.signal(number, stop)
    try:
        loop.run()
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
    return 0


if __name__ == "__main__":
    sys.exit(main())
