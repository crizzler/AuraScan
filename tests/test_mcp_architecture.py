"""Architecture: layer assignment, import allowlist, rule-ID hygiene and the capability record."""

import ast
import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "tools" / "architecture_audit.py"
RULE_METADATA_PATH = ROOT / "aurascan" / "core" / "rule_metadata.py"
MCP = ROOT / "aurascan" / "mcp"

RULE_ID_RE = re.compile(r"^[A-Z][A-Z0-9]+(?:-[A-Z0-9]+)+$")

ALLOWED_AURASCAN = frozenset((
    "aurascan.analyzers.injection",
    "aurascan.core.models",
    "aurascan.core.instruction_guard",
    "aurascan.core.agent_runtime_audit",
    "aurascan.core.security_audit",
    "aurascan.core.rule_metadata",
    "aurascan.core.redaction",
))

_spec = importlib.util.spec_from_file_location("architecture_audit", TOOL_PATH)
architecture_audit = importlib.util.module_from_spec(_spec)
sys.modules["architecture_audit"] = architecture_audit
_spec.loader.exec_module(architecture_audit)


def _sources():
    return sorted(MCP.rglob("*.py"))


def _run_audit():
    return architecture_audit.run_audit(ROOT / "aurascan", "aurascan", RULE_METADATA_PATH)


def test_40_no_shell_eval_exec_or_pickle():
    for path in _sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                for keyword in node.keywords:
                    if keyword.arg == "shell":
                        assert isinstance(keyword.value, ast.Constant)
                        assert keyword.value.value is False, path
                if isinstance(node.func, ast.Name):
                    assert node.func.id not in ("eval", "exec", "compile"), (path, node.func.id)
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name not in ("pickle", "marshal"), path
            if isinstance(node, ast.ImportFrom):
                assert (node.module or "") not in ("pickle", "marshal"), path


def test_41_every_module_gets_the_mcp_layer():
    for path in _sources():
        relative = path.relative_to(ROOT / "aurascan").as_posix()
        assert architecture_audit.assign_layer(path.stem, relative) == "mcp", relative


def test_42_no_mcp_module_is_unclassified():
    result = _run_audit()
    mcp_modules = [info for info in result.modules if info.path.startswith("aurascan/mcp/")]
    assert mcp_modules
    assert [info.path for info in mcp_modules if info.layer == "unclassified"] == []
    assert all(info.layer == "mcp" for info in mcp_modules)


def test_43_import_allowlist_is_stdlib_plus_seven_named_modules():
    for path in _sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    continue
                names = [node.module or ""]
            for name in names:
                root = name.split(".")[0]
                if root == "aurascan":
                    assert name in ALLOWED_AURASCAN, (path, name)
                elif hasattr(sys, "stdlib_module_names"):
                    assert root in sys.stdlib_module_names, (path, name)


def test_44_no_presenter_cli_or_ui_cli_import():
    for path in _sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            module = ""
            if isinstance(node, ast.ImportFrom) and not node.level:
                module = node.module or ""
            elif isinstance(node, ast.Import):
                module = ",".join(alias.name for alias in node.names)
            if not module:
                continue
            for part in module.split(","):
                leaf = part.rsplit(".", 1)[-1]
                assert leaf != "cli", (path, part)
                assert not leaf.endswith("_presenter"), (path, part)
                assert not leaf.endswith("_cli"), (path, part)
                assert leaf not in ("__main__", "setup_wizard", "makepkg_wrapper"), (path, part)


def test_45_no_rule_id_literal():
    offenders = []
    for path in _sources():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if RULE_ID_RE.match(node.value):
                    offenders.append((path.name, node.value))
    assert offenders == []


def test_60_security_audit_is_the_recorded_process_owner():
    result = _run_audit()
    records = {
        info.path: info for info in result.modules
        if info.path.startswith("aurascan/mcp/")
    }
    module = records["aurascan/mcp/tools/security_audit.py"]
    assert "process" in module.capabilities

    from test_architecture_audit import PROCESS_MODULES

    assert PROCESS_MODULES[-2:] == [
        "aurascan/mcp/tools/security_audit.py",
        "aurascan/mcp/tools/security_audit_online.py",
    ]
    online = records["aurascan/mcp/tools/security_audit_online.py"]
    assert "process" in online.capabilities
    assert "network" not in online.capabilities
