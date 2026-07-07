#!/usr/bin/env python3
"""Audit optional presenter coverage for AuraScan rule IDs.

This maintainer tool is intentionally passive: it parses local Python files,
does not import analyzer modules, does not execute package code, and does not
use the network.
"""

import argparse
import ast
from dataclasses import dataclass
import json
from pathlib import Path
import re
import sys
from typing import Dict, Iterable, List, Optional

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aurascan.core.models import Severity
from aurascan.core.presenter import has_presenter_template, known_presenter_template_rules
from aurascan.core.rule_metadata import RULE_METADATA, has_known_template, is_known_rule


RULE_ID_RE = re.compile(r"^[A-Z][A-Z0-9]+(?:-[A-Z0-9]+)+$")
SEVERITY_ORDER = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
SEVERITY_RANK = {severity: index for index, severity in enumerate(SEVERITY_ORDER)}
DEFAULT_SCAN_PATHS = [ROOT / "aurascan"]
SKIP_FILES = {
    ROOT / "aurascan" / "core" / "presenter.py",
    ROOT / "aurascan" / "core" / "rule_metadata.py",
}


@dataclass
class DiscoveredRule:
    rule_id: str
    severity: Optional[Severity] = None
    path: str = ""
    line_number: int = 0

    def to_dict(self) -> Dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value if self.severity else None,
            "path": self.path,
            "line_number": self.line_number,
        }


class RuleVisitor(ast.NodeVisitor):
    def __init__(self, path: Path):
        self.path = path
        self.rules: List[DiscoveredRule] = []

    def visit_Call(self, node: ast.Call) -> None:
        rule_id = self._call_rule_id(node)
        if rule_id:
            self._add(rule_id, self._call_severity(node), node.lineno)
        self.generic_visit(node)

    def visit_Tuple(self, node: ast.Tuple) -> None:
        if node.elts:
            rule_id = literal_string(node.elts[0])
            if is_rule_id(rule_id):
                severity = first_severity(node.elts)
                if severity:
                    self._add(rule_id, severity, node.lineno)
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str) and is_rule_id(node.value):
            self._add(node.value, None, node.lineno)

    def _call_rule_id(self, node: ast.Call) -> Optional[str]:
        for keyword in node.keywords:
            if keyword.arg == "rule_id":
                value = literal_string(keyword.value)
                return value if is_rule_id(value) else None
        if node.args:
            value = literal_string(node.args[0])
            if is_rule_id(value):
                return value
        return None

    def _call_severity(self, node: ast.Call) -> Optional[Severity]:
        values = list(node.args) + [keyword.value for keyword in node.keywords]
        return first_severity(values)

    def _add(self, rule_id: str, severity: Optional[Severity], line_number: int) -> None:
        self.rules.append(DiscoveredRule(rule_id, severity, str(self.path), line_number))


def is_rule_id(value: Optional[str]) -> bool:
    return bool(value and RULE_ID_RE.fullmatch(value))


def literal_string(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def severity_from_node(node: ast.AST) -> Optional[Severity]:
    if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id == "Severity":
        try:
            return Severity[node.attr]
        except KeyError:
            return None
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        try:
            return Severity[node.value]
        except (KeyError, ValueError):
            return None
    return None


def first_severity(nodes: Iterable[ast.AST]) -> Optional[Severity]:
    for node in nodes:
        severity = severity_from_node(node)
        if severity:
            return severity
        for child in ast.iter_child_nodes(node):
            severity = first_severity([child])
            if severity:
                return severity
    return None


def discover_rules(paths: Iterable[Path]) -> List[DiscoveredRule]:
    by_id: Dict[str, DiscoveredRule] = {}
    for path in python_files(paths):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"), filename=str(path))
        except SyntaxError:
            continue
        visitor = RuleVisitor(path)
        visitor.visit(tree)
        for item in visitor.rules:
            existing = by_id.get(item.rule_id)
            if existing is None:
                by_id[item.rule_id] = item
                continue
            if item.severity and (existing.severity is None or SEVERITY_ORDER.index(item.severity) > SEVERITY_ORDER.index(existing.severity)):
                by_id[item.rule_id] = item
    return sorted(by_id.values(), key=lambda item: item.rule_id)


def python_files(paths: Iterable[Path]) -> Iterable[Path]:
    for path in paths:
        path = path.resolve()
        if path.is_file() and path.suffix == ".py" and path not in SKIP_FILES:
            yield path
            continue
        if not path.is_dir():
            continue
        for candidate in sorted(path.rglob("*.py")):
            if "__pycache__" in candidate.parts or candidate.resolve() in SKIP_FILES:
                continue
            yield candidate


def rule_has_template(rule_id: str) -> bool:
    return has_presenter_template(rule_id) or has_known_template(rule_id)


def severity_at_least(severity: Optional[Severity], minimum: Severity) -> bool:
    if severity is None:
        return minimum == Severity.LOW
    return SEVERITY_RANK[severity] >= SEVERITY_RANK[minimum]


def audit_paths(paths: Iterable[Path], min_severity: Severity = Severity.LOW) -> Dict[str, object]:
    discovered = discover_rules(paths)
    all_missing_templates = [item for item in discovered if not rule_has_template(item.rule_id)]
    missing_templates = [
        item for item in all_missing_templates
        if severity_at_least(item.severity, min_severity)
    ]
    high_critical_missing = [
        item for item in all_missing_templates
        if item.severity in (Severity.HIGH, Severity.CRITICAL)
    ]
    medium_or_higher_missing = [
        item for item in all_missing_templates
        if item.severity in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
    ]
    uncataloged = [item for item in discovered if not is_known_rule(item.rule_id)]

    return {
        "min_severity": min_severity.value,
        "discovered_rules": [item.to_dict() for item in discovered],
        "cataloged_rules": sorted(RULE_METADATA),
        "presenter_templates": known_presenter_template_rules(),
        "all_missing_template_rules": [item.to_dict() for item in all_missing_templates],
        "missing_template_rules": [item.to_dict() for item in missing_templates],
        "high_critical_missing_template_rules": [item.to_dict() for item in high_critical_missing],
        "medium_or_higher_missing_template_rules": [item.to_dict() for item in medium_or_higher_missing],
        "uncataloged_rules": [item.to_dict() for item in uncataloged],
        "summary": {
            "discovered": len(discovered),
            "cataloged": len(RULE_METADATA),
            "missing_templates": len(missing_templates),
            "all_missing_templates": len(all_missing_templates),
            "high_critical_missing_templates": len(high_critical_missing),
            "medium_or_higher_missing_templates": len(medium_or_higher_missing),
            "uncataloged": len(uncataloged),
        },
    }


def render_text(result: Dict[str, object]) -> str:
    summary = result["summary"]
    min_severity = result.get("min_severity", Severity.LOW.value)
    missing_label = "Rules relying on fallback wording"
    if min_severity != Severity.LOW.value:
        missing_label = f"Rules relying on fallback wording ({min_severity}+)"
    lines = [
        "AuraScan presenter coverage audit",
        f"Discovered rule IDs: {summary['discovered']}",
        f"Optional metadata entries: {summary['cataloged']}",
        f"{missing_label}: {summary['missing_templates']}",
        f"All fallback rules: {summary['all_missing_templates']}",
        f"MEDIUM+ fallback rules: {summary['medium_or_higher_missing_templates']}",
        f"HIGH/CRITICAL fallback rules: {summary['high_critical_missing_templates']}",
        f"Uncataloged rules: {summary['uncataloged']}",
    ]

    missing = result["missing_template_rules"]
    if missing:
        lines.append("")
        lines.append(f"{missing_label}:")
        for item in missing:
            severity = item["severity"] or "unknown"
            location = f"{item['path']}:{item['line_number']}" if item["path"] else ""
            lines.append(f"- {item['rule_id']} ({severity}) {location}".rstrip())

    high = result["high_critical_missing_template_rules"]
    if high:
        lines.append("")
        lines.append("HIGH/CRITICAL rules without custom presenter coverage:")
        for item in high:
            location = f"{item['path']}:{item['line_number']}" if item["path"] else ""
            lines.append(f"- {item['rule_id']} ({item['severity']}) {location}".rstrip())

    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit optional AuraScan rule metadata and presenter template coverage.")
    parser.add_argument("--strict", action="store_true", help="exit non-zero if HIGH/CRITICAL rules rely on fallback wording")
    parser.add_argument("--strict-medium", action="store_true", help="exit non-zero if MEDIUM or higher rules rely on fallback wording")
    parser.add_argument("--min-severity", choices=[severity.value for severity in SEVERITY_ORDER], default=Severity.LOW.value, help="minimum severity to list in fallback-rule output")
    parser.add_argument("--json", action="store_true", help="emit machine-readable audit data")
    parser.add_argument("--path", action="append", type=Path, help="file or directory to scan; may be repeated")
    return parser


def run(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    paths = args.path or DEFAULT_SCAN_PATHS
    result = audit_paths(paths, min_severity=Severity(args.min_severity))
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(render_text(result))
    if args.strict_medium and result["summary"]["medium_or_higher_missing_templates"]:
        return 1
    if args.strict and result["summary"]["high_critical_missing_templates"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
