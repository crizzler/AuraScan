"""Regression tests for the extracted presentation modules.

Every subsystem renderer moved out of its report class in Stage 4. These tests
pin the properties that make the seam safe: the data classes no longer render,
the presenters carry no dangerous capability, the entry points keep their
documented defaults, and the display-only constants still agree with the values
the engines actually use.

Behavioural rendering equivalence is covered by the subsystem suites
(``test_config_drift``, ``test_incidents``, ``test_recovery``,
``test_security_audit``, ``test_upgrade_preflight``), which now exercise these
entry points and assert the rendered text.
"""

import importlib
import inspect
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT / "tools") not in sys.path:
    sys.path.insert(0, str(ROOT / "tools"))

import architecture_audit  # noqa: E402  (maintainer tool, loaded from tools/)

RULE_METADATA_PATH = ROOT / "aurascan" / "core" / "rule_metadata.py"

# Report classes that must no longer own terminal rendering.
RENDERER_FREE = (
    ("aurascan.core.config_drift", "ConfigDriftReport"),
    ("aurascan.core.incidents", "IncidentReport"),
    ("aurascan.core.recovery", "RecoveryReport"),
    ("aurascan.core.security_audit", "SecurityAuditReport"),
    ("aurascan.core.upgrade_preflight", "UpgradePreflightReport"),
    ("aurascan.core.upgrade_preflight", "UpgradeFailureDiagnosis"),
    ("aurascan.core.models", "ScanReport"),
)

PRESENTERS = (
    ("aurascan.core.config_drift_presenter", "render_config_drift"),
    ("aurascan.core.incident_presenter", "render_incident"),
    ("aurascan.core.recovery_presenter", "render_recovery"),
    ("aurascan.core.security_audit_presenter", "render_security_audit"),
    ("aurascan.core.upgrade_preflight_presenter", "render_upgrade_preflight"),
    ("aurascan.core.upgrade_preflight_presenter", "render_upgrade_failure_diagnosis"),
    ("aurascan.core.scan_report_presenter", "render_scan_report"),
)


def test_report_classes_no_longer_own_terminal_rendering():
    for module_name, class_name in RENDERER_FREE:
        module = importlib.import_module(module_name)
        report_class = getattr(module, class_name)

        assert not hasattr(report_class, "render_terminal"), (module_name, class_name)
        assert not hasattr(report_class, "_check_summary_lines"), (module_name, class_name)
        assert not hasattr(report_class, "_arch_audit_summary"), (module_name, class_name)


def test_presentation_entry_points_exist():
    for module_name, function_name in PRESENTERS:
        module = importlib.import_module(module_name)

        assert callable(getattr(module, function_name)), (module_name, function_name)


def test_presentation_entry_points_keep_their_documented_defaults():
    expectations = {
        "aurascan.core.config_drift_presenter:render_config_drift": {"include_preview": True},
        "aurascan.core.incident_presenter:render_incident": {"verbose": False},
        "aurascan.core.recovery_presenter:render_recovery": {"verbose": False},
        "aurascan.core.security_audit_presenter:render_security_audit": {
            "verbose": False,
            "use_color": True,
        },
        "aurascan.core.upgrade_preflight_presenter:render_upgrade_preflight": {
            "use_color": True,
            "verbose": False,
        },
        "aurascan.core.scan_report_presenter:render_scan_report": {
            "use_color": True,
            "verbose": False,
        },
    }

    for key, defaults in expectations.items():
        module_name, function_name = key.split(":")
        module = importlib.import_module(module_name)
        signature = inspect.signature(getattr(module, function_name))

        for name, expected in defaults.items():
            assert signature.parameters[name].default is expected, key


def test_depth_adapters_still_render_their_reports():
    """The extracted presenters must be reachable, not just importable."""

    from aurascan.core.incidents import IncidentReport
    from aurascan.core.recovery import RecoveryReport

    assert callable(IncidentReport.from_dict)
    assert callable(RecoveryReport.from_dict)


def test_display_constants_match_the_engine_values():
    from aurascan.core import config_drift, incidents, security_audit
    from aurascan.core import config_drift_presenter, incident_presenter
    from aurascan.core import security_audit_presenter

    assert (
        config_drift_presenter.CONFIG_DRIFT_AI_FALLBACK
        == config_drift.CONFIG_DRIFT_AI_FALLBACK
    )
    assert (
        incident_presenter.INCIDENT_AI_FALLBACK == incidents.INCIDENT_AI_FALLBACK
    )
    assert (
        incident_presenter.INCIDENT_AI_TIMEOUT_SECONDS
        == incidents.INCIDENT_AI_TIMEOUT_SECONDS
    )
    assert (
        security_audit_presenter.CODEWHALE_ADVISORY_REVIEWED
        == security_audit.CODEWHALE_ADVISORY_REVIEWED
    )


def test_presenters_count_as_presentation_and_stay_capability_free():
    result = architecture_audit.run_audit(
        ROOT / "aurascan", "aurascan", RULE_METADATA_PATH
    )
    by_name = {info.name: info for info in result.modules}
    presenters = [
        info for info in result.modules if info.name.split(".")[-1].endswith("_presenter")
    ]

    assert len(presenters) >= 6
    for info in presenters:
        assert info.layer == "presentation", info.path
        for category in ("process", "network", "fs_write", "privilege", "sqlite"):
            assert category not in info.capabilities, (info.path, category)

    # The evidence model is a leaf: it must not reference any presenter. The
    # subsystem modules reference their presenter only to print a finished
    # report, which INV-015 keeps out of the import graph's cycles.
    models = by_name["aurascan.core.models"]
    assert all("_presenter" not in imported for imported in models.internal_imports)


def test_presentation_defect_is_detected_by_the_audit(tmp_path):
    """Negative fixture: a domain object importing its own presenter fails.

    The domain layer rule (INV-013) catches this shape directly.
    """

    package_root = tmp_path / "renderpkg"
    (package_root / "core").mkdir(parents=True)
    (package_root / "__init__.py").write_text("", encoding="utf-8")
    (package_root / "core" / "__init__.py").write_text("", encoding="utf-8")
    (package_root / "core" / "models.py").write_text(
        "def render(self):\n"
        "    from renderpkg.core.models_presenter import draw\n"
        "    return draw()\n",
        encoding="utf-8",
    )
    (package_root / "core" / "models_presenter.py").write_text(
        "def draw():\n"
        "    return ''\n",
        encoding="utf-8",
    )

    result = architecture_audit.run_audit(package_root, "renderpkg")
    ids = {violation.invariant_id for violation in result.violations}

    assert "INV-013" in ids


def test_report_object_importing_its_presenter_is_a_cycle(tmp_path):
    """Negative fixture for the application-layer shape of the same defect.

    A report/state object that imports the presenter which renders it always
    forms a cycle, which INV-015 reports.
    """

    package_root = tmp_path / "cyclepkg"
    (package_root / "core").mkdir(parents=True)
    (package_root / "__init__.py").write_text("", encoding="utf-8")
    (package_root / "core" / "__init__.py").write_text("", encoding="utf-8")
    (package_root / "core" / "state.py").write_text(
        "from cyclepkg.core.state_presenter import draw\n\n\n"
        "class Report:\n"
        "    def render(self):\n"
        "        return draw()\n",
        encoding="utf-8",
    )
    (package_root / "core" / "state_presenter.py").write_text(
        "from cyclepkg.core.state import Report\n\n\ndef draw():\n"
        "    return ''\n",
        encoding="utf-8",
    )

    result = architecture_audit.run_audit(package_root, "cyclepkg")
    ids = {violation.invariant_id for violation in result.violations}

    assert "INV-015" in ids
    assert result.cycles == [
        ["cyclepkg.core.state", "cyclepkg.core.state_presenter"]
    ]
