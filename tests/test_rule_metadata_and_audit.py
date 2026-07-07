import importlib.util
import json
from pathlib import Path
import sys

from aurascan.core.rule_metadata import (
    get_display_group,
    get_display_priority,
    get_rule_metadata,
    has_known_template,
    is_known_rule,
)


TOOLS_PATH = Path(__file__).resolve().parents[1] / "tools" / "audit_presenter_coverage.py"
spec = importlib.util.spec_from_file_location("audit_presenter_coverage", TOOLS_PATH)
audit_presenter_coverage = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = audit_presenter_coverage
spec.loader.exec_module(audit_presenter_coverage)


def write_rule_file(path: Path, rule_id: str = "LOCAL-HIGH-RULE", severity: str = "HIGH") -> Path:
    path.write_text(
        f'''
from aurascan.core.models import Confidence, EvidenceQuality, Finding, Phase, Severity, Source

def make():
    return Finding(
        rule_id="{rule_id}",
        package_name="pkg",
        package_version="1",
        phase=Phase.pkgbuild_static,
        source=Source.deterministic_rule,
        severity=Severity.{severity},
        confidence=Confidence.HIGH,
        evidence_quality=EvidenceQuality.strong_heuristic,
        file_path="PKGBUILD",
        explanation="test",
        recommendation="review",
        blocks_installation=False,
        requires_manual_review=True,
    )
''',
        encoding="utf-8",
    )
    return path


def test_optional_metadata_lookup_for_known_rule():
    metadata = get_rule_metadata("SOURCE-META-HTTP-NOT-HTTPS")

    assert metadata is not None
    assert is_known_rule("SOURCE-META-HTTP-NOT-HTTPS")
    assert get_display_group("SOURCE-META-HTTP-NOT-HTTPS") == "source-http"
    assert get_display_priority("SOURCE-META-HTTP-NOT-HTTPS") == metadata.display_priority
    assert has_known_template("SOURCE-META-HTTP-NOT-HTTPS")
    assert not is_known_rule("LOCAL-HIGH-RULE")


def test_audit_tool_reports_missing_templates(tmp_path: Path):
    path = write_rule_file(tmp_path / "fake_rules.py")

    result = audit_presenter_coverage.audit_paths([path])
    missing = {item["rule_id"] for item in result["missing_template_rules"]}
    high_missing = {item["rule_id"] for item in result["high_critical_missing_template_rules"]}

    assert "LOCAL-HIGH-RULE" in missing
    assert "LOCAL-HIGH-RULE" in high_missing


def test_audit_tool_exits_zero_by_default_with_missing_templates(tmp_path: Path, capsys):
    path = write_rule_file(tmp_path / "fake_rules.py")

    status = audit_presenter_coverage.run(["--path", str(path)])
    output = capsys.readouterr().out

    assert status == 0
    assert "LOCAL-HIGH-RULE" in output
    assert "Rules relying on fallback wording" in output


def test_audit_tool_strict_fails_for_high_critical_missing_templates(tmp_path: Path):
    path = write_rule_file(tmp_path / "fake_rules.py")

    status = audit_presenter_coverage.run(["--strict", "--path", str(path)])

    assert status == 1


def test_audit_tool_strict_passes_for_current_codebase():
    status = audit_presenter_coverage.run(["--strict"])

    assert status == 0


def test_audit_tool_default_passes_for_current_codebase():
    status = audit_presenter_coverage.run([])

    assert status == 0


def test_audit_tool_strict_allows_low_missing_templates(tmp_path: Path):
    path = write_rule_file(tmp_path / "fake_rules.py", "LOCAL-LOW-RULE", "LOW")

    status = audit_presenter_coverage.run(["--strict", "--path", str(path)])

    assert status == 0


def test_audit_tool_min_severity_filters_displayed_missing_templates(tmp_path: Path, capsys):
    path = write_rule_file(tmp_path / "fake_rules.py", "LOCAL-LOW-RULE", "LOW")

    status = audit_presenter_coverage.run(["--min-severity", "MEDIUM", "--path", str(path)])
    output = capsys.readouterr().out

    assert status == 0
    assert "Rules relying on fallback wording (MEDIUM+): 0" in output
    assert "All fallback rules: 1" in output
    assert "LOCAL-LOW-RULE" not in output


def test_audit_tool_strict_medium_fails_for_medium_missing_templates(tmp_path: Path):
    path = write_rule_file(tmp_path / "fake_rules.py", "LOCAL-MEDIUM-RULE", "MEDIUM")

    strict_status = audit_presenter_coverage.run(["--strict", "--path", str(path)])
    strict_medium_status = audit_presenter_coverage.run(["--strict-medium", "--path", str(path)])

    assert strict_status == 0
    assert strict_medium_status == 1


def test_audit_tool_strict_medium_passes_for_current_codebase():
    status = audit_presenter_coverage.run(["--strict-medium"])

    assert status == 0


def test_audit_tool_json_output(tmp_path: Path, capsys):
    path = write_rule_file(tmp_path / "fake_rules.py")

    status = audit_presenter_coverage.run(["--json", "--path", str(path)])
    data = json.loads(capsys.readouterr().out)

    assert status == 0
    assert data["summary"]["discovered"] >= 1
    assert data["summary"]["medium_or_higher_missing_templates"] >= 1
    assert any(item["rule_id"] == "LOCAL-HIGH-RULE" for item in data["discovered_rules"])
