"""Advisory AI explanation for high-impact deterministic findings.

Deterministic policy remains authoritative.  This module only restates
already recorded finding fields as one bounded, non-executable explanation for
a non-expert reader.  It never adds or removes findings, never lowers
severity, never establishes trust, and never authorizes any action.  It is
silent unless an AI provider is already configured and enabled by the user,
and a provider failure or a rejected response leaves the deterministic report
unchanged.
"""

import json
import os
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

from aurascan.core.ai_provider import (
    AIProviderConfig,
    call_ai_provider,
    resolve_ai_config,
    safe_provider_error_detail,
)
from aurascan.core.text_safety import (
    load_strict_json_object,
    sanitize_terminal_text,
    validate_model_advisory_text,
)


AI_EXPLANATION_HEADER = "[AuraScan] AI explanation (advisory):"
AI_EXPLANATION_UNAVAILABLE = (
    "[AuraScan] AI explanation unavailable: {detail}. "
    "The deterministic findings above remain authoritative."
)
AI_EXPLANATION_REJECTED = (
    "[AuraScan] AI explanation was rejected by the advisory contract. "
    "The deterministic findings above remain authoritative."
)

MAX_EXPLAINED_FINDINGS = 6
MAX_EXPLANATION_CHARS = 800
MAX_EXPLANATION_RESPONSE_CHARS = 8192
MAX_EXPLANATION_FACT_CHARS = 600
EXPLANATION_TIMEOUT_SECONDS = 20
EXPLAINABLE_SEVERITIES = frozenset({"HIGH", "CRITICAL"})
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1}

# Only fixed, already user-facing finding fields are sent.  File paths,
# evidence snippets, raw tool output, hashes and review metadata stay local.
_FACT_FIELDS = (
    ("summary", "user_summary"),
    ("result", "explanation"),
    ("why_it_matters", "why_it_matters"),
    ("what_aurascan_checked", "what_aurascan_checked"),
    ("what_aurascan_did_not_check", "what_aurascan_did_not_check"),
)

_PROMPT_INSTRUCTIONS = (
    "Explain AuraScan's findings to a non-expert user. AuraScan is a static "
    "package-scanning safety tool; its deterministic findings are the "
    "authoritative result.\n"
    "\n"
    "Rules for the explanation:\n"
    "- Use only FACTS_JSON. Never invent paths, versions, causes or "
    "consequences.\n"
    "- In two to four short declarative sentences, state what AuraScan "
    "observed or could not finish inspecting, why that stops or pauses the "
    "build or install, and where it happened; name the exact observed entry "
    "when one appears in the facts.\n"
    '- Never use second person ("you") and never suggest, request or describe '
    "actions, commands, tools or fixes.\n"
    "- Never state or imply that a package, artifact, entry or system is safe, "
    "clean, trusted, malicious, compromised or already executed; keep every "
    "qualifier that appears in the facts.\n"
    "- Do not ask questions. Do not include links, code, or package-manager or "
    "shell text used as advice. Do not use prescriptive words such as "
    '"should", "must", "recommend", "consider", "necessary", "required" or '
    '"best".\n'
    "- The explanation is one plain-text paragraph of at most 800 characters.\n"
    "\n"
    "Reply with strict JSON only, with no markdown and no extra keys:\n"
    '{"explanation": "<plain text>", "explained_rule_ids": '
    '["<rule_id from FACTS_JSON>", ...]}'
)


def explanation_targets(report: Any) -> List[Mapping[str, Any]]:
    """Return the bounded, severity-ordered findings worth explaining."""

    if not isinstance(report, Mapping):
        return []
    findings = report.get("findings")
    if isinstance(findings, (str, bytes)) or not isinstance(findings, Sequence):
        return []
    selected: List[Any] = []
    for index, finding in enumerate(findings):
        if not isinstance(finding, Mapping):
            continue
        severity = str(finding.get("severity") or "")
        if (
            severity in EXPLAINABLE_SEVERITIES
            or bool(finding.get("blocks_installation"))
            or bool(finding.get("requires_manual_review"))
        ):
            selected.append((index, finding))
    selected.sort(
        key=lambda item: (
            _SEVERITY_ORDER.get(str(item[1].get("severity") or ""), 2),
            item[0],
        )
    )
    return [finding for _index, finding in selected[:MAX_EXPLAINED_FINDINGS]]


def build_explanation_facts(report: Any) -> List[Dict[str, Any]]:
    """Build the bounded, path-free fact list sent to the AI provider."""

    private_roots = _private_roots()
    facts: List[Dict[str, Any]] = []
    for finding in explanation_targets(report):
        rule_id = _fact_text(finding.get("rule_id"), private_roots, max_chars=200)
        if not rule_id:
            continue
        item: Dict[str, Any] = {
            "rule_id": rule_id,
            "severity": _fact_text(finding.get("severity"), (), max_chars=40),
            "blocking": bool(finding.get("blocks_installation")),
            "manual_review": bool(finding.get("requires_manual_review")),
        }
        package_name = str(finding.get("package_name") or "").strip()
        if package_name and package_name.lower() != "unknown":
            version = str(finding.get("package_version") or "").strip()
            item["package"] = _fact_text(
                (package_name + " " + version).strip(),
                private_roots,
                max_chars=200,
            )
        for key, source in _FACT_FIELDS:
            value = finding.get(source)
            text = _fact_text(value, private_roots)
            if text:
                item[key] = text
        facts.append(item)
    return facts


def build_explanation_prompt(report: Any) -> str:
    """Return the bounded explanation prompt, or an empty string."""

    facts = build_explanation_facts(report)
    if not facts:
        return ""
    return _prompt_from_facts(facts)


def validate_explanation_response(
    value: Any,
    facts: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    """Validate the strict response object against the sent fact list."""

    data = load_strict_json_object(value, max_chars=MAX_EXPLANATION_RESPONSE_CHARS)
    if set(data) != {"explanation", "explained_rule_ids"}:
        raise ValueError("AI explanation response schema did not match")
    raw_ids = data.get("explained_rule_ids")
    if not isinstance(raw_ids, list) or not raw_ids or len(raw_ids) > len(facts):
        raise ValueError("AI explanation covered an invalid rule set")
    known = {str(item.get("rule_id") or "") for item in facts}
    seen = set()
    for item in raw_ids:
        if not isinstance(item, str) or item not in known or item in seen:
            raise ValueError("AI explanation referenced an unknown rule id")
        seen.add(item)
    explanation = validate_model_advisory_text(
        data.get("explanation"),
        max_chars=MAX_EXPLANATION_CHARS,
        allow_empty=False,
    )
    return {"explanation": explanation, "explained_rule_ids": sorted(seen)}


def scan_explanation_lines(
    report: Any,
    *,
    urlopen: Optional[Callable] = None,
    config: Optional[AIProviderConfig] = None,
) -> List[str]:
    """Return advisory display lines for a scan report, or an empty list.

    The caller prints these lines only in interactive, non-JSON output.
    A missing or disabled AI configuration is silent; a provider failure or a
    rejected response produces one fixed, evidence-free line instead.
    """

    facts = build_explanation_facts(report)
    if not facts:
        return []
    if config is None:
        config = resolve_ai_config(os.environ)
    if config.error or not config.ready:
        return []
    prompt = _prompt_from_facts(facts)
    try:
        text = call_ai_provider(
            config,
            prompt,
            timeout=EXPLANATION_TIMEOUT_SECONDS,
            urlopen=urlopen,
        )
    except Exception as exc:
        return [AI_EXPLANATION_UNAVAILABLE.format(detail=safe_provider_error_detail(exc))]
    try:
        validated = validate_explanation_response(text, facts)
    except Exception:
        return [AI_EXPLANATION_REJECTED]
    return ["", AI_EXPLANATION_HEADER, validated["explanation"]]


def _prompt_from_facts(facts: Sequence[Mapping[str, Any]]) -> str:
    payload = json.dumps(
        {"findings": list(facts)},
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    return _PROMPT_INSTRUCTIONS + "\n\nFACTS_JSON:\n" + payload


def _fact_text(
    value: Any,
    private_roots: Sequence[str],
    max_chars: int = MAX_EXPLANATION_FACT_CHARS,
) -> str:
    if not isinstance(value, str) or not value.strip():
        return ""
    text = sanitize_terminal_text(value, max_chars=max_chars, single_line=True)
    for root in private_roots:
        if root and root in text:
            return ""
    return text


def _private_roots() -> List[str]:
    roots = []
    for candidate in (os.environ.get("HOME", ""), os.path.expanduser("~")):
        if candidate and candidate not in ("/", "~") and candidate not in roots:
            roots.append(candidate)
    return roots
