"""Architecture invariant tests.

These tests run the offline ``tools/architecture_audit.py`` report against the
real package and assert that the narrow architectural and security boundaries
documented in ``docs/ARCHITECTURE.md`` still hold. They also exercise the audit
tool itself on temporary fixtures so a broken detector cannot silently pass.

The audit tool never imports ``aurascan`` and never executes candidate content,
so these tests stay offline, deterministic and rootless.
"""

import importlib.util
import json
import sys
from pathlib import Path
from typing import Dict, Optional

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = ROOT / "tools" / "architecture_audit.py"
RULE_METADATA_PATH = ROOT / "aurascan" / "core" / "rule_metadata.py"

_spec = importlib.util.spec_from_file_location("architecture_audit", TOOL_PATH)
assert _spec is not None and _spec.loader is not None
architecture_audit = importlib.util.module_from_spec(_spec)
sys.modules["architecture_audit"] = architecture_audit
_spec.loader.exec_module(architecture_audit)


def write_module(root: Path, relative: str, source: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return path


def run_tool(package_root: Path, package_name: str, rule_metadata: Optional[Path] = None):
    return architecture_audit.run_audit(package_root, package_name, rule_metadata)


# --------------------------------------------------------------------------- #
# The real package must satisfy every invariant.
# --------------------------------------------------------------------------- #


def test_production_package_satisfies_every_architecture_invariant():
    result = run_tool(ROOT / "aurascan", "aurascan", RULE_METADATA_PATH)

    failures = [
        "{0} {1}: {2}: {3}".format(
            violation.invariant_id,
            violation.title,
            violation.module,
            violation.detail,
        )
        for violation in result.violations
    ]
    assert failures == []


def test_audit_covers_the_whole_package():
    result = run_tool(ROOT / "aurascan", "aurascan", RULE_METADATA_PATH)

    assert len(result.modules) >= 60
    assert all(info.layer != "unclassified" for info in result.modules)
    assert all(info.path.startswith("aurascan/") for info in result.modules)


def test_domain_and_catalog_layers_stay_pure():
    result = run_tool(ROOT / "aurascan", "aurascan", RULE_METADATA_PATH)
    by_name = {info.name: info for info in result.modules}

    for name in architecture_audit.pure_modules("aurascan"):
        info = by_name[name]
        for imported in info.internal_imports:
            assert imported in architecture_audit.pure_modules("aurascan")
        for category in ("process", "network", "fs_write", "privilege", "sqlite"):
            assert category not in info.capabilities


def test_production_has_no_third_party_runtime_imports():
    result = run_tool(ROOT / "aurascan", "aurascan", RULE_METADATA_PATH)

    third_party = sorted(
        {
            external
            for info in result.modules
            for external in info.external_imports
            if not architecture_audit._is_stdlib(external)
        }
    )
    assert set(third_party).issubset(set(architecture_audit.ALLOWED_EXTERNAL_IMPORTS))


PROCESS_MODULES = [
    "aurascan/core/agent.py",
    "aurascan/core/local_package_db.py",
    "aurascan/core/package_archive.py",
    "aurascan/core/trusted_tools.py",
]

NETWORK_MODULES = [
    "aurascan/core/ai_provider.py",
    "aurascan/core/intelligence_transport.py",
    "aurascan/core/recovery_boot.py",
    "aurascan/core/security_audit.py",
    "aurascan/core/source_acquisition.py",
    "aurascan/core/upgrade_preflight.py",
]

PRIVILEGE_MODULES = [
    "aurascan/core/config.py",
    "aurascan/core/intelligence_cli.py",
]


def capability_owners(capability: str):
    result = run_tool(ROOT / "aurascan", "aurascan", RULE_METADATA_PATH)
    return sorted(
        info.path for info in result.modules if capability in info.capabilities
    )


def test_no_analyzer_executes_a_process():
    result = run_tool(ROOT / "aurascan", "aurascan", RULE_METADATA_PATH)
    executing = sorted(
        info.path
        for info in result.modules
        if info.layer == "analysis" and "process" in info.capabilities
    )

    assert executing == []


def test_process_execution_is_confined_to_documented_modules():
    # Adding a module here means updating docs/SECURITY_BOUNDARIES.md too.
    assert capability_owners("process") == PROCESS_MODULES


def test_network_access_is_confined_to_documented_modules():
    assert capability_owners("network") == NETWORK_MODULES


def test_privilege_lookup_is_confined_to_documented_modules():
    assert capability_owners("privilege") == PRIVILEGE_MODULES


def test_audit_tool_does_not_import_production_code():
    source = TOOL_PATH.read_text(encoding="utf-8")
    tree = architecture_audit.ast.parse(source)
    imported = set()
    for node in architecture_audit.ast.walk(tree):
        if isinstance(node, architecture_audit.ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, architecture_audit.ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])

    assert "aurascan" not in imported


# --------------------------------------------------------------------------- #
# Detector behaviour on synthetic fixtures.
# --------------------------------------------------------------------------- #

DETECTOR_FIXTURE = '''
import os
import socket
import subprocess
from pathlib import Path


def run_candidate(command):
    subprocess.run([command], shell=True)


def read_bytes(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def write_bytes(path, data):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(data)
    Path(path).write_text(data)
    os.remove(path)


def connect(host, port):
    return socket.create_connection((host, port))


def evaluate(payload):
    return eval(payload)


def drop_privileges():
    os.setuid(0)
'''


def test_detector_finds_every_capability_category(tmp_path):
    package_root = tmp_path / "samplepkg"
    write_module(package_root, "__init__.py", "")
    write_module(package_root, "core/sample.py", DETECTOR_FIXTURE)

    result = run_tool(package_root, "samplepkg")
    info = {module.name: module for module in result.modules}["samplepkg.core.sample"]

    assert "process" in info.capabilities
    assert "network" in info.capabilities
    assert "fs_write" in info.capabilities
    assert "fs_read" in info.capabilities
    assert "privilege" in info.capabilities
    patterns = {hit.pattern_id for hit in info.risk_patterns}
    assert "shell-true" in patterns
    assert "dynamic-eval" in patterns


def test_open_mode_decides_read_versus_write(tmp_path):
    package_root = tmp_path / "modepkg"
    write_module(package_root, "__init__.py", "")
    write_module(
        package_root,
        "reader.py",
        'def load(path):\n    with open(path) as handle:\n        return handle.read()\n',
    )
    write_module(
        package_root,
        "writer.py",
        'def store(path):\n    with open(path, "wb") as handle:\n        handle.write(b"x")\n',
    )

    result = run_tool(package_root, "modepkg")
    by_name = {module.name: module for module in result.modules}

    assert "fs_read" in by_name["modepkg.reader"].capabilities
    assert "fs_write" not in by_name["modepkg.reader"].capabilities
    assert "fs_write" in by_name["modepkg.writer"].capabilities
    assert "fs_read" not in by_name["modepkg.writer"].capabilities


def test_string_replace_is_not_reported_as_filesystem_mutation(tmp_path):
    package_root = tmp_path / "strpkg"
    write_module(package_root, "__init__.py", "")
    write_module(
        package_root,
        "text.py",
        'def normalize(value):\n    return value.replace("-", "_")\n',
    )

    result = run_tool(package_root, "strpkg")
    info = {module.name: module for module in result.modules}["strpkg.text"]

    assert "fs_write" not in info.capabilities


def test_literal_lazy_import_is_not_dynamic_evaluation(tmp_path):
    package_root = tmp_path / "lazypkg"
    write_module(package_root, "__init__.py", "")
    write_module(
        package_root,
        "lazy.py",
        'def load():\n    return __import__("urllib.request", fromlist=["urlopen"])\n',
    )
    write_module(
        package_root,
        "dynamic.py",
        "def load(name):\n    return __import__(name)\n",
    )

    result = run_tool(package_root, "lazypkg")
    by_name = {module.name: module for module in result.modules}

    assert by_name["lazypkg.lazy"].risk_patterns == []
    patterns = {hit.pattern_id for hit in by_name["lazypkg.dynamic"].risk_patterns}
    assert "dynamic-eval" in patterns


def test_import_cycles_are_detected(tmp_path):
    package_root = tmp_path / "cyclepkg"
    write_module(package_root, "__init__.py", "")
    write_module(package_root, "alpha.py", "from cyclepkg import beta\n")
    write_module(package_root, "beta.py", "from cyclepkg import alpha\n")
    write_module(package_root, "lonely.py", "import json\n")

    result = run_tool(package_root, "cyclepkg")

    assert result.cycles == [["cyclepkg.alpha", "cyclepkg.beta"]]


def test_upward_dependency_from_a_pure_module_is_reported(tmp_path):
    package_root = tmp_path / "purepkg"
    write_module(package_root, "__init__.py", "")
    write_module(package_root, "core/__init__.py", "")
    write_module(package_root, "core/models.py", "from purepkg.core.engine import run\n")
    write_module(package_root, "core/engine.py", "def run():\n    return None\n")

    result = run_tool(package_root, "purepkg")
    ids = {violation.invariant_id for violation in result.violations}

    assert "INV-012" in ids
    assert "INV-007" not in ids


def test_analysis_module_with_process_capability_is_reported(tmp_path):
    package_root = tmp_path / "analysispkg"
    write_module(package_root, "__init__.py", "")
    write_module(package_root, "analyzers/__init__.py", "")
    write_module(
        package_root,
        "analyzers/sneaky.py",
        'import subprocess\n\n\ndef scan(path):\n    return subprocess.run([path])\n',
    )

    result = run_tool(package_root, "analysispkg")
    ids = {violation.invariant_id for violation in result.violations}

    assert "INV-001" in ids


def test_undeclared_third_party_import_is_reported(tmp_path):
    package_root = tmp_path / "thirdpkg"
    write_module(package_root, "__init__.py", "")
    write_module(package_root, "core/thing.py", "import torch\n")

    result = run_tool(package_root, "thirdpkg")
    ids = {violation.invariant_id for violation in result.violations}

    assert "INV-003" in ids


def test_rule_id_literals_are_reported_only_in_ui_entry_points(tmp_path):
    package_root = tmp_path / "uipkg"
    write_module(package_root, "__init__.py", "")
    write_module(package_root, "core/__init__.py", "")
    write_module(
        package_root,
        "core/presenter.py",
        'TEMPLATE = {"SAMPLE-RULE-001": "text"}\n',
    )
    write_module(
        package_root,
        "core/instruction_cli.py",
        'RULE = "SAMPLE-RULE-001"\n',
    )
    rule_metadata = write_module(package_root, "rule_metadata.py", "")
    rule_metadata.write_text(
        'RULE_METADATA = {\n    "SAMPLE-RULE-001": None,\n}\n',
        encoding="utf-8",
    )

    result = run_tool(package_root, "uipkg", rule_metadata)
    reported = {violation.module for violation in result.violations if violation.invariant_id == "INV-011"}

    assert reported == {"uipkg/core/instruction_cli.py"}


def test_size_alone_never_fails_the_audit(tmp_path):
    package_root = tmp_path / "bigpkg"
    write_module(package_root, "__init__.py", "")
    body = "".join(
        "def function_{0}():\n    return {0}\n\n\n".format(index) for index in range(900)
    )
    write_module(package_root, "big.py", body)

    result = run_tool(package_root, "bigpkg")

    assert result.violations == []
    assert result.budget  # the advisory budget still reports the module
    assert architecture_audit.main(
        ["--package-root", str(package_root), "--package-name", "bigpkg", "--strict"]
    ) == 0


def test_cli_json_report_has_stable_shape(tmp_path, capsys):
    package_root = tmp_path / "jsonpkg"
    write_module(package_root, "__init__.py", "")
    write_module(package_root, "thing.py", "def value():\n    return 1\n")

    exit_code = architecture_audit.main(
        [
            "--package-root",
            str(package_root),
            "--package-name",
            "jsonpkg",
            "--format",
            "json",
        ]
    )
    payload: Dict[str, object] = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["schema_version"] == "aurascan-architecture-audit/1.0"
    assert payload["module_count"] == 2
    assert payload["violations"] == []
    assert len(payload["invariants"]) == len(architecture_audit.INVARIANTS)


def test_missing_package_root_reports_an_error(tmp_path, capsys):
    exit_code = architecture_audit.main(
        ["--package-root", str(tmp_path / "absent"), "--package-name", "absent"]
    )

    assert exit_code == 1
    assert "package root not found" in capsys.readouterr().err


def test_markdown_report_lists_every_module():
    result = run_tool(ROOT / "aurascan", "aurascan", RULE_METADATA_PATH)
    markdown = architecture_audit.render_markdown(result, 5)

    assert "| Module | Layer | Lines |" in markdown
    for info in result.modules:
        assert "`{0}`".format(info.path) in markdown


def test_hotspot_score_components_are_reported():
    result = run_tool(ROOT / "aurascan", "aurascan", RULE_METADATA_PATH)
    top = result.hotspots[0]

    assert top.hotspot_score() > 0
    assert top.capabilities or top.concerns
    assert top.loc > 0


@pytest.mark.parametrize("relative", ["core/instruction_guard.py", "core/agent.py"])
def test_large_modules_are_reported_by_the_advisory_budget(relative):
    result = run_tool(ROOT / "aurascan", "aurascan", RULE_METADATA_PATH)
    warned = " ".join(result.budget)

    assert "aurascan/{0}".format(relative) in warned
