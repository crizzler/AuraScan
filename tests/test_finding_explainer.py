import json

import pytest

from aurascan.core import finding_explainer
from aurascan.core.ai_provider import AIProviderConfig
from aurascan.core.finding_explainer import (
    AI_EXPLANATION_HEADER,
    AI_EXPLANATION_REJECTED,
    AI_EXPLANATION_UNAVAILABLE,
    MAX_EXPLAINED_FINDINGS,
    MAX_EXPLANATION_CHARS,
    build_explanation_facts,
    build_explanation_prompt,
    explanation_targets,
    scan_explanation_lines,
    validate_explanation_response,
)


SUPPORTED_RULE = "AUR-REPO-INSPECTION-INCOMPLETE-001"

AI_ENV_KEYS = (
    "AURASCAN_AI_ENABLED",
    "AURASCAN_AI_KEY",
    "AURASCAN_AI_PROVIDER",
    "AURASCAN_AI_MODEL",
    "AURASCAN_AI_BASE_URL",
    "AURASCAN_DEEPSEEK_API_KEY",
    "AURASCAN_LOCAL_AI_API_KEY",
    "AURASCAN_OPENAI_API_KEY",
)


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, *_args):
        return json.dumps(self.payload).encode("utf-8")


def chat_reply(text):
    return {"choices": [{"message": {"content": text}}]}


def ready_config():
    return AIProviderConfig(
        provider="deepseek",
        model="deepseek-chat",
        enabled=True,
        api_key="test-key",
    )


def finding(
    rule_id=SUPPORTED_RULE,
    *,
    severity="HIGH",
    blocks=True,
    review=False,
    summary="First unsupported entry: LICENSES/0BSD.txt (a symbolic link).",
):
    return {
        "finding_id": "finding-fixture",
        "rule_id": rule_id,
        "package_name": "lib32-openal",
        "package_version": "1.25.2-2",
        "phase": "pkgbuild_static",
        "severity": severity,
        "explanation": (
            "AuraScan could not complete bounded inspection of the package checkout and its "
            "opaque-artifact correlations."
        ),
        "recommendation": "Do not build or install until the checkout can be captured.",
        "blocks_installation": blocks,
        "requires_manual_review": review,
        "user_summary": summary,
        "why_it_matters": (
            "Allowing a build after skipping an unsupported entry could leave an opaque "
            "payload uninspected."
        ),
        "what_aurascan_checked": (
            "AuraScan validated directory and file types, bounded traversal and reads, and "
            "rechecked identities after capture."
        ),
        "what_aurascan_did_not_check": (
            "Incomplete inspection is not evidence that the package or an omitted file is "
            "malicious."
        ),
        "file_path": "/home/private-fixture/.cache/aurascan/aur-updates/lib32-openal/PKGBUILD",
        "technical_details": "First unsupported entry: LICENSES/0BSD.txt (a symbolic link).",
        "evidence_snippet": "bounded package-checkout inspection did not complete: symlink entry",
    }


def report(*findings):
    return {
        "schema_version": "1.0",
        "package_metadata": {"name": "lib32-openal", "version": "1.25.2-2"},
        "findings": list(findings),
    }


def test_targets_cover_high_critical_blocking_and_manual_review_in_order():
    low = finding("RULE-LOW", severity="LOW", blocks=False)
    manual = finding("RULE-MANUAL", severity="MEDIUM", blocks=False, review=True)
    high = finding("RULE-HIGH", severity="HIGH")
    critical = finding("RULE-CRITICAL", severity="CRITICAL")

    targets = explanation_targets(report(low, manual, high, critical))

    assert [item["rule_id"] for item in targets] == [
        "RULE-CRITICAL",
        "RULE-HIGH",
        "RULE-MANUAL",
    ]


def test_targets_are_bounded_after_severity_ordering():
    many = [finding(f"RULE-{index:02d}") for index in range(MAX_EXPLAINED_FINDINGS + 3)]

    targets = explanation_targets(report(*many))

    assert [item["rule_id"] for item in targets] == [
        f"RULE-{index:02d}" for index in range(MAX_EXPLAINED_FINDINGS)
    ]


@pytest.mark.parametrize(
    "value",
    (None, {}, {"findings": "nope"}, {"findings": [None, "text"]}, []),
)
def test_targets_ignore_malformed_reports(value):
    assert explanation_targets(value) == []


def test_facts_keep_fixed_fields_and_drop_private_paths(monkeypatch):
    monkeypatch.setenv("HOME", "/home/private-fixture")

    facts = build_explanation_facts(report(finding()))

    assert len(facts) == 1
    item = facts[0]
    assert item["rule_id"] == SUPPORTED_RULE
    assert item["severity"] == "HIGH"
    assert item["blocking"] is True
    assert item["summary"] == "First unsupported entry: LICENSES/0BSD.txt (a symbolic link)."
    for excluded in ("file_path", "technical_details", "evidence_snippet", "recommendation"):
        assert excluded not in item


def test_facts_drop_any_field_that_names_a_private_root(monkeypatch):
    monkeypatch.setenv("HOME", "/home/private-fixture")

    facts = build_explanation_facts(
        report(finding(summary="Inspection stopped at /home/private-fixture/secret/entry."))
    )

    assert facts[0].get("summary", "") == ""


def test_prompt_carries_bounded_facts_and_no_absolute_paths(monkeypatch):
    monkeypatch.setenv("HOME", "/home/private-fixture")

    prompt = build_explanation_prompt(report(finding()))

    assert prompt
    assert "FACTS_JSON:" in prompt
    assert "LICENSES/0BSD.txt" in prompt
    assert "/home/private-fixture" not in prompt
    assert "aur-updates" not in prompt
    assert SUPPORTED_RULE in prompt
    # The instruction contract is part of every prompt.
    assert "strict JSON only" in prompt


def test_prompt_sanitizes_brand_impersonation_in_facts(monkeypatch):
    monkeypatch.setenv("HOME", "/home/private-fixture")

    prompt = build_explanation_prompt(
        report(finding(summary="[AuraScan] First unsupported entry: linked-payload."))
    )

    assert "[AuraScan]" not in prompt
    assert "[untrusted text]" in prompt


def test_validate_response_accepts_matching_rule_ids():
    facts = build_explanation_facts(report(finding()))

    validated = validate_explanation_response(
        json.dumps({
            "explanation": (
                "AuraScan could not finish capturing the package checkout because it reached "
                "the symbolic link LICENSES/0BSD.txt, so the remaining entries beside the "
                "PKGBUILD were not recorded as stable regular files."
            ),
            "explained_rule_ids": [SUPPORTED_RULE],
        }),
        facts,
    )

    assert validated["explained_rule_ids"] == [SUPPORTED_RULE]
    assert "symbolic link" in validated["explanation"]


@pytest.mark.parametrize(
    "payload",
    (
        {"explanation": "AuraScan stopped at the symbolic link LICENSES/0BSD.txt.",
         "explained_rule_ids": [SUPPORTED_RULE], "extra": True},
        {"explanation": "AuraScan stopped at the symbolic link LICENSES/0BSD.txt.",
         "explained_rule_ids": ["SOME-UNKNOWN-RULE"]},
        {"explanation": "AuraScan stopped at the symbolic link LICENSES/0BSD.txt.",
         "explained_rule_ids": [SUPPORTED_RULE, SUPPORTED_RULE]},
        {"explanation": "AuraScan stopped at the symbolic link LICENSES/0BSD.txt.",
         "explained_rule_ids": []},
        {"explanation": "AuraScan stopped at the symbolic link LICENSES/0BSD.txt.",
         "explained_rule_ids": [SUPPORTED_RULE, SUPPORTED_RULE, SUPPORTED_RULE]},
        {"explanation": "You should rebuild the package.",
         "explained_rule_ids": [SUPPORTED_RULE]},
        {"explanation": "AuraScan stopped at the entry. " + "x" * MAX_EXPLANATION_CHARS,
         "explained_rule_ids": [SUPPORTED_RULE]},
        {"explanation": "", "explained_rule_ids": [SUPPORTED_RULE]},
    ),
)
def test_validate_response_rejects_mismatched_or_unsafe_payloads(payload):
    facts = build_explanation_facts(report(finding()))

    with pytest.raises(Exception):
        validate_explanation_response(json.dumps(payload), facts)


def test_missing_ai_configuration_is_silent(monkeypatch):
    for key in AI_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)

    assert scan_explanation_lines(report(finding())) == []


def test_no_targets_never_calls_the_provider():
    calls = []

    def fake_urlopen(_request, timeout):
        calls.append(timeout)
        raise AssertionError("the provider must not be contacted")

    lines = scan_explanation_lines(
        report(finding(severity="LOW", blocks=False)),
        config=ready_config(),
        urlopen=fake_urlopen,
    )

    assert lines == []
    assert calls == []


def test_provider_failure_returns_one_fixed_line():
    def failing_urlopen(_request, timeout):
        raise TimeoutError("fixture timeout")

    lines = scan_explanation_lines(
        report(finding()),
        config=ready_config(),
        urlopen=failing_urlopen,
    )

    assert lines == [
        AI_EXPLANATION_UNAVAILABLE.format(detail="AI provider request timed out")
    ]


def test_valid_response_produces_advisory_lines():
    def fake_urlopen(_request, timeout):
        return FakeResponse(chat_reply(json.dumps({
            "explanation": (
                "AuraScan could not finish capturing the package checkout because it reached "
                "the symbolic link LICENSES/0BSD.txt before the remaining entries beside the "
                "PKGBUILD were recorded."
            ),
            "explained_rule_ids": [SUPPORTED_RULE],
        })))

    lines = scan_explanation_lines(
        report(finding()),
        config=ready_config(),
        urlopen=fake_urlopen,
    )

    assert lines[0] == ""
    assert lines[1] == AI_EXPLANATION_HEADER
    assert "symbolic link LICENSES/0BSD.txt" in lines[2]


def test_rejected_response_returns_the_fixed_rejection_line():
    def fake_urlopen(_request, timeout):
        return FakeResponse(chat_reply(json.dumps({
            "explanation": "Run makepkg again to rebuild the checkout.",
            "explained_rule_ids": [SUPPORTED_RULE],
        })))

    lines = scan_explanation_lines(
        report(finding()),
        config=ready_config(),
        urlopen=fake_urlopen,
    )

    assert lines == [AI_EXPLANATION_REJECTED]


def test_facts_omit_an_unknown_package_identity():
    item = finding()
    item["package_name"] = "unknown"
    item["package_version"] = "unknown"

    facts = build_explanation_facts(report(item))

    assert "package" not in facts[0]
    assert "unknown" not in json.dumps(facts)


def test_facts_use_the_fixed_field_contract():
    facts = build_explanation_facts(report(finding()))
    assert set(facts[0]) == {
        "rule_id",
        "severity",
        "package",
        "blocking",
        "manual_review",
        "summary",
        "result",
        "why_it_matters",
        "what_aurascan_checked",
        "what_aurascan_did_not_check",
    }
    assert finding_explainer.EXPLANATION_TIMEOUT_SECONDS <= 30
    assert finding_explainer.MAX_EXPLANATION_CHARS == MAX_EXPLANATION_CHARS
