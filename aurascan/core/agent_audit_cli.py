"""CLI for the read-only external-agent runtime audit."""

import argparse
import json
import sys

from aurascan.core.agent_runtime_audit import (
    EXIT_SCHEMA,
    EXIT_USAGE,
    MODEL_SAFETY_BANNER,
    AgentAuditSchemaError,
    AgentAuditUsageError,
    build_report,
)
from aurascan.core.presenter import EXACT_TEMPLATES
from aurascan.core.text_safety import sanitize_terminal_text

BANNER = MODEL_SAFETY_BANNER


def build_parser():
    parser = argparse.ArgumentParser(
        prog="aurascan agent-audit",
        description=(
            "Report execution authority and readable project secret classes for one "
            "external agent surface. Read-only; never runs the agent, a model, an MCP "
            "server, a hook, or project code."
        ),
    )
    parser.add_argument(
        "--root", default=".", help="project root to inspect (default: current directory)"
    )
    parser.add_argument(
        "--surface",
        required=True,
        choices=("codex", "claude", "cursor", "mcp"),
        help="agent surface to inspect",
    )
    parser.add_argument("--json", action="store_true", help="emit one JSON report")
    parser.add_argument(
        "--explain", action="store_true", help="include the checked/not-proved explanation"
    )
    return parser


def _coverage_label(report):
    return "COMPLETE" if report.coverage_complete else "INCOMPLETE"


def _channel_label(kind):
    return {
        "shell-tool": "built-in shell/exec tool",
        "hook-command": "lifecycle hook command",
        "mcp-stdio-command": "MCP stdio command",
    }.get(kind, kind)


def render_text(report, explain=False):
    lines = [
        "AuraScan agent runtime audit",
        "Root: " + sanitize_terminal_text(report.root),
        "Surface: " + sanitize_terminal_text(report.surface),
        "Coverage: " + _coverage_label(report),
        "Captured: " + sanitize_terminal_text(report.captured_at),
        "",
    ]
    lines.append(
        "Execution authority: "
        + ("OBSERVED" if report.execution_authority else "not observed")
    )
    if report.channels:
        for channel in report.channels:
            lines.append(
                "  - "
                + _channel_label(channel.kind)
                + " at "
                + sanitize_terminal_text(channel.source.path)
                + ":"
                + str(channel.source.line_start)
            )
    lines.append(
        "Approval mode: "
        + sanitize_terminal_text(report.approval.normalized)
        + " (evidence: "
        + sanitize_terminal_text(report.approval.evidence)
        + ")"
    )
    if report.secrets:
        lines.append("Readable project secret classes:")
        for secret in report.secrets:
            lines.append(
                "  - "
                + sanitize_terminal_text(secret.secret_class)
                + ": "
                + str(secret.count)
            )
    else:
        lines.append("Readable project secret classes: none observed in scope")
    lines.append("Host isolation: unknown (declared settings are not proof)")
    lines.append(
        "Aggregate: AGENT-CREDENTIAL-EXFIL-RISK-001 "
        + report.aggregate_status
    )
    if not report.coverage_complete:
        lines.append("Incomplete: " + ", ".join(
            sanitize_terminal_text(item) for item in report.reasons
        ))
    lines.append("")
    lines.append("Findings:")
    if not report.findings:
        lines.append("  none")
    for finding in report.findings:
        template = EXACT_TEMPLATES.get(finding.rule_id, {})
        lines.append(
            "  - "
            + finding.rule_id
            + " ("
            + finding.severity
            + "): "
            + sanitize_terminal_text(template.get("title") or finding.rule_id)
        )
        if template.get("action"):
            lines.append("    Action: " + sanitize_terminal_text(template["action"]))
        if explain and template.get("checked"):
            lines.append("    Checked: " + sanitize_terminal_text(template["checked"]))
        if explain and template.get("not_prove"):
            lines.append(
                "    Not proved: " + sanitize_terminal_text(template["not_prove"])
            )
    lines.append("")
    lines.append("Not verified:")
    for item in report.not_verified:
        lines.append("  - " + sanitize_terminal_text(item))
    lines.append("")
    lines.append(BANNER)
    return "\n".join(lines)


def run_agent_audit(argv=None, *, stdout=None, stderr=None):
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    args = build_parser().parse_args(argv)
    try:
        report = build_report(args.root, args.surface)
    except AgentAuditUsageError as exc:
        print("agent-audit: " + sanitize_terminal_text(exc), file=stderr)
        return EXIT_USAGE
    except AgentAuditSchemaError as exc:
        print("agent-audit schema failure: " + sanitize_terminal_text(exc), file=stderr)
        return EXIT_SCHEMA

    if args.json:
        print(
            json.dumps(report.serializable(), indent=2, sort_keys=True, ensure_ascii=True),
            file=stdout,
        )
    else:
        print(render_text(report, explain=args.explain), file=stdout)
    return report.exit_code
