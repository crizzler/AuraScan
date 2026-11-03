"""Architecture contract for the injection subpackage: layer, import allowlist, capability.

The detector is analysis-layer static inspection: no process, no network, no file writes, and the
only ``core`` edge is ``aurascan.core.models`` in ``findings.py``.
"""

import ast
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKAGE = os.path.join(ROOT, "aurascan", "analyzers", "injection")
AUDIT = os.path.join(ROOT, "tools")
if AUDIT not in sys.path:
    sys.path.insert(0, AUDIT)

import architecture_audit  # noqa: E402

STDLIB_ALLOWED = {
    "re",
    "unicodedata",
    "abc",
    "dataclasses",
    "typing",
    "pathlib",
    "os",
    "sys",
    "json",
    "base64",
}

FORBIDDEN_MODULES = {
    "subprocess",
    "socket",
    "http",
    "urllib",
    "ssl",
    "shutil",
    "tempfile",
    "time",
    "random",
    "os.path",
}


def modules():
    return sorted(
        name for name in os.listdir(PACKAGE) if name.endswith(".py") and name != "__init__.py"
    )


def test_every_module_is_analysis_layer():
    for name in modules():
        relative = "analyzers/injection/" + name
        assert architecture_audit.assign_layer("analyzers.injection." + name[:-3], relative) == "analysis"


def test_imports_are_stdlib_relative_or_core_models():
    offenders = []
    for name in os.listdir(PACKAGE):
        if not name.endswith(".py"):
            continue
        path = os.path.join(PACKAGE, name)
        with open(path, "r", encoding="utf-8") as handle:
            tree = ast.parse(handle.read(), filename=name)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    if top not in STDLIB_ALLOWED:
                        offenders.append((name, alias.name))
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    continue
                module = node.module or ""
                if module == "aurascan.core.models":
                    if name != "findings.py":
                        offenders.append((name, module))
                    continue
                if module.startswith("aurascan."):
                    offenders.append((name, module))
                    continue
                if module.split(".")[0] not in STDLIB_ALLOWED:
                    offenders.append((name, module))
    assert offenders == []


def test_only_findings_imports_core_models():
    importers = []
    for name in os.listdir(PACKAGE):
        if not name.endswith(".py"):
            continue
        with open(os.path.join(PACKAGE, name), "r", encoding="utf-8") as handle:
            if "aurascan.core.models" in handle.read():
                importers.append(name)
    assert importers == ["findings.py"]


def test_no_core_engine_or_instruction_guard_import():
    for name in os.listdir(PACKAGE):
        if not name.endswith(".py"):
            continue
        with open(os.path.join(PACKAGE, name), "r", encoding="utf-8") as handle:
            text = handle.read()
        assert "core.engine" not in text
        assert "instruction_guard" not in text
        assert "ai_provider" not in text


def test_no_process_or_network_capability():
    for name in os.listdir(PACKAGE):
        if not name.endswith(".py"):
            continue
        with open(os.path.join(PACKAGE, name), "r", encoding="utf-8") as handle:
            tree = ast.parse(handle.read(), filename=name)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] not in FORBIDDEN_MODULES, (name, alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] not in FORBIDDEN_MODULES, (name, node.module)


def test_no_open_call_outside_findings_or_scan_path():
    # Scans themselves never write; only scan_path() reads a caller-supplied file.
    for name in os.listdir(PACKAGE):
        if not name.endswith(".py"):
            continue
        with open(os.path.join(PACKAGE, name), "r", encoding="utf-8") as handle:
            tree = ast.parse(handle.read(), filename=name)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open":
                assert name in ("scanner.py", "findings.py"), name


def test_package_exports_the_ported_surface():
    from aurascan.analyzers import injection

    for attribute in ("scan_content", "scan_path", "to_findings", "create_default_detectors"):
        assert hasattr(injection, attribute)
