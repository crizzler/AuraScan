"""``aurascan-mcp``: a read-only stdio MCP server over AuraScan's deterministic surface.

Importing this package has no side effects: no fd is duplicated and no stream is read until
``run_server`` or ``main`` is called.
"""

from .registry import TOOLS

__all__ = ("run_server", "main", "TOOLS")


def run_server(roots, budgets=None, max_line_bytes=None):
    from .server import run_server as _run_server

    return _run_server(roots, budgets=budgets, max_line_bytes=max_line_bytes)


def main(argv=None):
    from .__main__ import main as _main

    return _main(argv)
