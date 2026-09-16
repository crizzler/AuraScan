"""Architecture invariant tests.

These tests run the offline ``tools/architecture_audit.py`` report against the
real package and assert that the narrow architectural and security boundaries
documented in ``docs/ARCHITECTURE.md`` still hold. They also exercise the audit
tool itself on temporary fixtures so a broken detector cannot silently pass.

The audit tool never imports ``aurascan`` and never executes candidate content,
so these tests stay offline, deterministic and rootless.
"""

import ast
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
    domain = architecture_audit.domain_modules("aurascan")
    pure = architecture_audit.pure_modules("aurascan")

    for name in domain:
        info = by_name[name]
        for imported in info.internal_imports:
            assert imported in domain, "/".join([name, imported])

    for name in architecture_audit.catalog_modules("aurascan"):
        info = by_name[name]
        allowed = set(domain) | set(architecture_audit.catalog_modules("aurascan"))
        for imported in info.internal_imports:
            assert imported in allowed, "/".join([name, imported])

    for name in pure:
        info = by_name[name]
        for category in ("process", "network", "fs_write", "privilege", "sqlite"):
            assert category not in info.capabilities


def test_scan_report_rendering_lives_in_the_presentation_layer():
    result = run_tool(ROOT / "aurascan", "aurascan", RULE_METADATA_PATH)
    by_name = {info.name: info for info in result.modules}

    renderer = by_name["aurascan.core.scan_report_presenter"]
    assert renderer.layer == "presentation"
    assert "render_scan_report" in renderer.public_symbols
    assert "aurascan.core.models" in renderer.internal_imports

    models = by_name["aurascan.core.models"]
    assert "render_terminal" not in models.public_symbols


def test_evidence_model_does_not_depend_on_risk_or_presentation():
    """The Stage 2 and Stage 3 claim, expressed as layer edges.

    The evidence model imported the terminal presenter to render itself (Stage
    2) and the risk engine to assemble its own report (Stage 3). Each formed an
    import cycle. Assert the architectural rule rather than an exact import
    list so a future legitimate domain-to-domain import stays possible.
    """

    result = run_tool(ROOT / "aurascan", "aurascan", RULE_METADATA_PATH)
    models = {info.name: info for info in result.modules}["aurascan.core.models"]

    forbidden = (
        set(architecture_audit.risk_modules("aurascan"))
        | set(architecture_audit.catalog_modules("aurascan"))
        | {"aurascan.core.scan_report_presenter"}
    )

    assert set(models.internal_imports).isdisjoint(forbidden)
    assert models.imports_by, "the evidence model should still be widely used"


def test_domain_evidence_modules_have_no_upward_layer_edges():
    """No domain module may depend on anything outside the domain layer."""

    result = run_tool(ROOT / "aurascan", "aurascan", RULE_METADATA_PATH)
    by_name = {info.name: info for info in result.modules}
    domain = set(architecture_audit.domain_modules("aurascan"))

    for name in sorted(domain):
        info = by_name[name]
        offenders = [imported for imported in info.internal_imports if imported not in domain]
        assert offenders == [], name


def test_risk_module_depends_only_on_the_evidence_vocabulary():
    result = run_tool(ROOT / "aurascan", "aurascan", RULE_METADATA_PATH)
    by_name = {info.name: info for info in result.modules}
    risk = by_name["aurascan.core.risk"]

    assert risk.layer == "risk"
    for imported in risk.internal_imports:
        assert imported in architecture_audit.domain_modules("aurascan")


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


def test_upward_dependency_from_a_domain_module_is_reported(tmp_path):
    package_root = tmp_path / "purepkg"
    write_module(package_root, "__init__.py", "")
    write_module(package_root, "core/__init__.py", "")
    write_module(package_root, "core/models.py", "from purepkg.core.engine import run\n")
    write_module(package_root, "core/engine.py", "def run():\n    return None\n")

    result = run_tool(package_root, "purepkg")
    ids = {violation.invariant_id for violation in result.violations}

    assert "INV-013" in ids
    assert "INV-007" not in ids


def test_domain_module_importing_the_risk_service_is_reported(tmp_path):
    """Regression for the defect Stage 3 removed.

    ``AnalysisResult.to_report`` imported the risk engine to assemble a report,
    which formed the models<->risk cycle. A domain module must not reach the
    risk service, and the audit must say so.
    """

    package_root = tmp_path / "riskcycle"
    write_module(package_root, "__init__.py", "")
    write_module(package_root, "core/__init__.py", "")
    write_module(
        package_root,
        "core/models.py",
        "def to_report(self):\n"
        "    from riskcycle.core.risk import RiskEngine\n"
        "    return RiskEngine()\n",
    )
    write_module(
        package_root,
        "core/risk.py",
        "from riskcycle.core.models import ScanReport\n\n\nclass RiskEngine:\n    pass\n",
    )

    result = run_tool(package_root, "riskcycle")
    by_id = {violation.invariant_id: violation for violation in result.violations}

    assert "INV-013" in by_id
    assert by_id["INV-013"].module == "riskcycle/core/models.py"
    assert "riskcycle.core.risk" in by_id["INV-013"].detail
    assert result.cycles == [["riskcycle.core.models", "riskcycle.core.risk"]]


def test_risk_module_importing_application_code_is_reported(tmp_path):
    package_root = tmp_path / "risklayer"
    write_module(package_root, "__init__.py", "")
    write_module(package_root, "core/__init__.py", "")
    write_module(package_root, "core/risk.py", "from risklayer.core.engine import run\n")
    write_module(package_root, "core/engine.py", "def run():\n    return None\n")

    result = run_tool(package_root, "risklayer")
    ids = {violation.invariant_id for violation in result.violations}

    assert "INV-014" in ids


def test_domain_module_importing_the_catalog_is_reported(tmp_path):
    """Regression for the defect Stage 2 removed.

    When the evidence model rendered its own terminal output it imported the
    rule presenter, forming the models<->presenter cycle.
    """

    package_root = tmp_path / "regresspkg"
    write_module(package_root, "__init__.py", "")
    write_module(package_root, "core/__init__.py", "")
    write_module(
        package_root,
        "core/models.py",
        "def render(self):\n"
        "    from regresspkg.core.presenter import FindingPresenter\n"
        "    return FindingPresenter()\n",
    )
    write_module(package_root, "core/__init__.py", "")
    write_module(
        package_root,
        "core/presenter.py",
        "from regresspkg.core.models import ScanReport\n\n\nclass FindingPresenter:\n    pass\n",
    )
    write_module(package_root, "core/risk.py", "from regresspkg.core.models import ScanReport\n")

    result = run_tool(package_root, "regresspkg")
    by_id = {violation.invariant_id: violation for violation in result.violations}

    assert "INV-013" in by_id
    assert by_id["INV-013"].module == "regresspkg/core/models.py"
    assert result.cycles == [["regresspkg.core.models", "regresspkg.core.presenter"]]


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


def test_application_module_importing_the_incident_cli_is_reported(tmp_path):
    """Stage 5 regression: the incident workflow must not reach back into the CLI.

    Automation-control flag dispatch used to live inside the incident workflow,
    which made the workflow and the automation subsystem import each other.
    Moving dispatch to the CLI layer is only a real fix if the workflow is
    forbidden from importing that layer back.
    """

    package_root = tmp_path / "clipkg"
    write_module(package_root, "__init__.py", "")
    write_module(package_root, "core/__init__.py", "")
    write_module(
        package_root,
        "core/incidents.py",
        "from clipkg.core.incident_cli import run_incident_command\n",
    )
    write_module(
        package_root,
        "core/incident_cli.py",
        "def run_incident_command(argv=None):\n    return 0\n",
    )

    result = run_tool(package_root, "clipkg")
    ids = {violation.invariant_id for violation in result.violations}

    assert "INV-007" in ids


def test_incident_cli_owns_automation_dispatch_not_the_incident_workflow():
    """The dispatch seam lives in one place and points one way only."""

    result = run_tool(ROOT / "aurascan", "aurascan", RULE_METADATA_PATH)
    module = {info.name: info for info in result.modules}

    cli = module["aurascan.core.incident_cli"]
    workflow = module["aurascan.core.incidents"]

    assert cli.layer == "presentation"
    assert "aurascan.core.incident_automation" in cli.internal_imports
    assert "aurascan.core.incidents" in cli.internal_imports
    # The workflow keeps one genuine orchestration call into automation, but it
    # must not import the CLI layer or the privileged helper client.
    assert "aurascan.core.incident_cli" not in workflow.internal_imports


def test_domain_vocabulary_declaring_a_side_effect_capability_is_reported(tmp_path):
    """Stage 6 regression for the new domain modules.

    ``incident_models`` and ``redaction`` were moved into the domain layer, so
    INV-010 now applies to them: a value or text module that starts executing
    processes, opening sockets or writing files is a violation.
    """

    package_root = tmp_path / "vocabpkg"
    write_module(package_root, "__init__.py", "")
    write_module(package_root, "core/__init__.py", "")
    write_module(
        package_root,
        "core/incident_models.py",
        "import subprocess\n\n\ndef helper():\n    return subprocess.run(['true'])\n",
    )

    result = run_tool(package_root, "vocabpkg")
    by_id = {violation.invariant_id: violation for violation in result.violations}

    assert "INV-010" in by_id
    assert by_id["INV-010"].module == "vocabpkg/core/incident_models.py"


def test_incident_vocabulary_and_redaction_are_domain_modules():
    """Stage 6 ownership: the moved vocabulary sits below every consumer."""

    result = run_tool(ROOT / "aurascan", "aurascan", RULE_METADATA_PATH)
    module = {info.name: info for info in result.modules}

    for name in ("aurascan.core.incident_models", "aurascan.core.redaction"):
        info = module[name]
        assert info.layer == "domain", name
        # A domain module may only depend on other domain modules (INV-013).
        for imported in info.internal_imports:
            assert imported in {
                "aurascan.core.models",
                "aurascan.core.redaction",
                "aurascan.core.text_safety",
                "aurascan.core.update_policy",
            }, (name, imported)

    assert module["aurascan.core.incident_models"].internal_imports == [
        "aurascan.core.models",
        "aurascan.core.redaction",
    ]
    assert module["aurascan.core.redaction"].internal_imports == []


def test_state_and_bounded_process_helpers_are_adapters():
    """Stage 6 ownership: the side-effecting helpers are visible adapters."""

    result = run_tool(ROOT / "aurascan", "aurascan", RULE_METADATA_PATH)
    module = {info.name: info for info in result.modules}

    state_file = module["aurascan.core.state_file"]
    bounded_process = module["aurascan.core.bounded_process"]

    assert state_file.layer == "adapters"
    assert bounded_process.layer == "adapters"
    assert "fs_write" in state_file.capabilities
    assert state_file.internal_imports == []
    assert bounded_process.internal_imports == []


def test_incident_repair_planner_does_not_import_the_upgrade_workflow():
    """Stage 7 regression: repair planning must not reach the upgrade workflow."""

    source = (ROOT / "aurascan" / "core" / "incident_repairs.py").read_text(encoding="utf-8")
    tree = ast.parse(source)

    imported = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    imported |= {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }

    assert "aurascan.core.upgrade_preflight" not in imported
    assert not any(name.startswith("aurascan.core.upgrade_preflight.") for name in imported)
    assert "aurascan.core.incidents" not in imported


def test_incident_repair_planner_is_not_in_an_import_cycle():
    """The Stage 7 seam: ``incident_repairs`` left the planner component."""

    result = run_tool(ROOT / "aurascan", "aurascan", RULE_METADATA_PATH)
    cycles = {module for component in result.cycles for module in component}

    assert "aurascan.core.incident_repairs" not in cycles
    assert "aurascan.core.repository_state" not in cycles
    assert "aurascan.core.repository_repair" not in cycles


def test_repository_state_and_repair_modules_are_adapters():
    """Stage 7 ownership: interpreted state stays below every workflow."""

    result = run_tool(ROOT / "aurascan", "aurascan", RULE_METADATA_PATH)
    module = {info.name: info for info in result.modules}

    state = module["aurascan.core.repository_state"]
    repair = module["aurascan.core.repository_repair"]

    assert state.layer == "adapters"
    assert repair.layer == "adapters"
    assert state.internal_imports == []
    # Reading pacman.conf is a bounded local read: no process, network, write
    # or privilege capability may appear in the state interpreter.
    for category in ("process", "network", "fs_write", "privilege", "sqlite"):
        assert category not in state.capabilities, category
    assert "fs_write" in repair.capabilities
    assert repair.internal_imports == [
        "aurascan.core.repository_state",
        "aurascan.core.trusted_executable",
    ]


def test_adapter_importing_an_application_module_is_reported(tmp_path):
    """INV-017 negative fixture: an adapter may not depend upward."""

    package_root = tmp_path / "adaptpkg"
    write_module(package_root, "__init__.py", "")
    write_module(package_root, "core/__init__.py", "")
    write_module(
        package_root,
        "core/repository_state.py",
        "from adaptpkg.core.upgrade_workflow import run_upgrade\n\n\ndef status():\n    return run_upgrade\n",
    )
    write_module(package_root, "core/upgrade_workflow.py", "def run_upgrade():\n    return 0\n")

    result = run_tool(package_root, "adaptpkg")
    by_id = {violation.invariant_id: violation for violation in result.violations}

    assert "INV-017" in by_id
    assert by_id["INV-017"].module == "adaptpkg/core/repository_state.py"


def test_network_capability_stays_with_the_upgrade_workflow():
    """Moving the parser out must not move or hide network authority."""

    result = run_tool(ROOT / "aurascan", "aurascan", RULE_METADATA_PATH)
    module = {info.name: info for info in result.modules}

    assert "network" in module["aurascan.core.upgrade_preflight"].capabilities
    assert "network" not in module["aurascan.core.repository_state"].capabilities
    assert "network" not in module["aurascan.core.repository_repair"].capabilities


def test_followup_framework_does_not_import_the_upgrade_workflow():
    """Stage 8 regression: the refresh capability is supplied, not imported.

    The follow-up framework imports the lifecycles whose retained contexts it
    serves, but the upgrade lifecycle supplies its own refresh operation so the
    framework and the upgrade workflow do not call each other.
    """

    source = (ROOT / "aurascan" / "core" / "followup.py").read_text(encoding="utf-8")
    tree = ast.parse(source)

    imported = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    imported |= {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }

    assert "aurascan.core.upgrade_preflight" not in imported
    assert not any(name.startswith("aurascan.core.upgrade_preflight.") for name in imported)


def test_upgrade_refresh_is_owned_by_the_upgrade_lifecycle():
    """The lifecycle defines the refresh operation and supplies it everywhere."""

    upgrade_source = (ROOT / "aurascan" / "core" / "upgrade_preflight.py").read_text(encoding="utf-8")
    upgrade_tree = ast.parse(upgrade_source)
    defined = {
        node.name
        for node in upgrade_tree.body
        if isinstance(node, (ast.FunctionDef, ast.ClassDef))
    }
    assert "refresh_upgrade_preflight" in defined

    # Both upgrade-runtime build sites in the workflow supply the provider.
    assert upgrade_source.count("refresh_report=refresh_upgrade_preflight") == 3

    cli_source = (ROOT / "aurascan" / "cli.py").read_text(encoding="utf-8")
    assert "refresh_upgrade_preflight" in cli_source
    assert "run_ask(raw_argv[1:], refresh_upgrade_report=refresh_upgrade_preflight)" in cli_source
    assert "run_agent(raw_argv[1:], refresh_upgrade_report=refresh_upgrade_preflight)" in cli_source


def test_upgrade_preflight_and_followup_direction_is_one_way():
    """Stage 8 topology: the lifecycle runs upgrade -> follow-up only."""

    result = run_tool(ROOT / "aurascan", "aurascan", RULE_METADATA_PATH)
    module = {info.name: info for info in result.modules}

    followup = module["aurascan.core.followup"]
    assert "aurascan.core.upgrade_preflight" not in followup.internal_imports
    assert "aurascan.core.followup" in module["aurascan.core.upgrade_preflight"].internal_imports


def test_incident_collection_does_not_import_the_upgrade_workflow():
    """Stage 9 regression: incident reasoning owns no upgrade-workflow edge."""

    source = (ROOT / "aurascan" / "core" / "incidents.py").read_text(encoding="utf-8")
    tree = ast.parse(source)

    imported = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module
    }
    imported |= {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }

    assert "aurascan.core.upgrade_preflight" not in imported
    assert not any(name.startswith("aurascan.core.upgrade_preflight.") for name in imported)

    result = run_tool(ROOT / "aurascan", "aurascan", RULE_METADATA_PATH)
    module = {info.name: info for info in result.modules}
    assert "aurascan.core.upgrade_preflight" not in module["aurascan.core.incidents"].internal_imports


def test_upgrade_value_types_are_inert_domain_values():
    """The shared upgrade values are a leaf: no imports, no capabilities."""

    result = run_tool(ROOT / "aurascan", "aurascan", RULE_METADATA_PATH)
    module = {info.name: info for info in result.modules}

    models = module["aurascan.core.upgrade_models"]
    assert models.layer == "domain"
    assert models.internal_imports == []
    for category in ("process", "network", "fs_write", "privilege", "sqlite"):
        assert category not in models.capabilities, category

    # Both consumers depend downward on the same values.
    assert "aurascan.core.upgrade_models" in module["aurascan.core.upgrade_preflight"].internal_imports
    assert "aurascan.core.upgrade_models" in module["aurascan.core.incidents"].internal_imports


def test_snapshot_collection_stays_with_the_workflow():
    """Reading the machine is not inert: only the value is shared."""

    models_source = (ROOT / "aurascan" / "core" / "upgrade_models.py").read_text(encoding="utf-8")
    workflow_source = (ROOT / "aurascan" / "core" / "upgrade_preflight.py").read_text(encoding="utf-8")

    assert "def collect" not in models_source
    assert "subprocess" not in models_source
    assert "def collect_system_snapshot(" in workflow_source
    assert "SystemSnapshot.collect(" not in workflow_source


def test_upgrade_preflight_left_the_planner_component():
    """Stage 9 topology: the upgrade workflow is no longer in a cycle."""

    result = run_tool(ROOT / "aurascan", "aurascan", RULE_METADATA_PATH)
    cycles = {module for component in result.cycles for module in component}

    assert "aurascan.core.upgrade_preflight" not in cycles
    assert "aurascan.core.upgrade_models" not in cycles
    # The remaining component is the incident/agent/follow-up planner group.
    planner = next(component for component in result.cycles if "aurascan.core.followup" in component)
    assert len(planner) == 6
    assert "aurascan.core.incidents" in planner
    assert "aurascan.core.upgrade_preflight" not in planner
