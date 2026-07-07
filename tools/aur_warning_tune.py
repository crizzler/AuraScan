#!/usr/bin/env python3
"""Sample AUR source metadata warning volume for UX tuning.

This helper intentionally performs metadata-only analysis:

* fetches PKGBUILD/.SRCINFO text from aur.archlinux.org
* does not run makepkg
* does not execute PKGBUILD functions
* does not download declared package sources
* does not clone Git repositories
* does not fetch PGP keys or run GPG
"""

import argparse
from collections import Counter
import json
from math import ceil
from pathlib import Path
from statistics import median
import tempfile
from typing import Callable, Dict, Iterable, List, Optional
import urllib.error
import urllib.parse
import urllib.request

from aurascan.analyzers.deterministic import DeterministicAnalyzer
from aurascan.analyzers.source_metadata import SourceMetadataAnalyzer
from aurascan.core.models import PackageMetadata, ScanReport, Severity
from aurascan.core.presenter import FindingPresenter
from aurascan.core.risk import RiskEngine


DEFAULT_SAMPLE = [
    "yay",
    "paru",
    "google-chrome",
    "visual-studio-code-bin",
    "brave-bin",
    "spotify",
    "discord",
    "zoom",
    "slack-desktop",
    "postman-bin",
    "obsidian",
    "teams-for-linux",
    "mongodb-bin",
    "android-studio",
    "onlyoffice-bin",
    "protonvpn",
    "librewolf-bin",
    "microsoft-edge-stable-bin",
    "vmware-workstation",
    "dropbox",
]

DEFAULT_USER_AGENT = "AuraScan-warning-tune/0.1"

RULE_FAMILIES = {
    "eval": {"EXEC-EVAL-001", "EXEC-EVAL-NET-001"},
    "systemd_unit": {"SYS-SYSTEMD-UNIT-001"},
    "systemd_auto": {"SYS-SYSTEMD-AUTO-001"},
    "systemd_user": {"SYS-SYSTEMD-USER-001"},
    "cron": {"SYS-CRON-FILE-001", "SYS-CRONTAB-001", "SYS-CRON-REBOOT-001"},
}


class AurFetchError(RuntimeError):
    pass


def aur_plain_url(pkgbase: str, filename: str) -> str:
    encoded_file = urllib.parse.quote(filename)
    encoded_pkg = urllib.parse.quote(pkgbase)
    return f"https://aur.archlinux.org/cgit/aur.git/plain/{encoded_file}?h={encoded_pkg}"


def fetch_text(url: str, timeout: float = 20, user_agent: str = DEFAULT_USER_AGENT) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": user_agent})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read(2 * 1024 * 1024).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        raise AurFetchError(f"{url}: HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise AurFetchError(f"{url}: {exc}") from exc
    except TimeoutError as exc:
        raise AurFetchError(f"{url}: timed out") from exc
    except OSError as exc:
        raise AurFetchError(f"{url}: {exc}") from exc


def make_fetcher(timeout: float = 20, user_agent: str = DEFAULT_USER_AGENT) -> Callable[[str], str]:
    return lambda url: fetch_text(url, timeout=timeout, user_agent=user_agent)


def fetch_package_metadata(pkgbase: str, workdir: Path, fetcher: Callable[[str], str] = fetch_text) -> Path:
    pkgdir = workdir / pkgbase
    pkgdir.mkdir(parents=True, exist_ok=True)

    pkgbuild = fetcher(aur_plain_url(pkgbase, "PKGBUILD"))
    pkgbuild_path = pkgdir / "PKGBUILD"
    pkgbuild_path.write_text(pkgbuild, encoding="utf-8")

    try:
        srcinfo = fetcher(aur_plain_url(pkgbase, ".SRCINFO"))
    except AurFetchError:
        srcinfo = ""
    if srcinfo:
        (pkgdir / ".SRCINFO").write_text(srcinfo, encoding="utf-8")
    return pkgbuild_path


def analyze_pkgbuild(
    pkgbase: str,
    pkgbuild_path: Path,
    verbose: bool = False,
    warning_budget: int = 3,
    include_hidden_notes: bool = False,
) -> Dict[str, object]:
    content = pkgbuild_path.read_text(encoding="utf-8", errors="replace")
    source_result = SourceMetadataAnalyzer().analyze_pkgbuild(str(pkgbuild_path), content)
    deterministic_result = DeterministicAnalyzer().analyze_pkgbuild(str(pkgbuild_path), content)
    findings = source_result.findings + deterministic_result.findings
    report = ScanReport(PackageMetadata(pkgbase, "unknown"), findings)
    report.risk_summary = RiskEngine().evaluate(findings)
    group_details = warning_group_details(findings, verbose=verbose, max_groups=warning_budget)
    severity_counts = Counter(finding.severity.value for finding in findings)
    rule_counts = Counter(finding.rule_id for finding in findings)
    family_flags = rule_family_flags(rule_counts)
    family_counts = rule_family_counts(rule_counts)

    result = {
        "package": pkgbase,
        "finding_count": len(findings),
        "visible_group_count": len(group_details["visible_titles"]),
        "hidden_note_count": len(group_details["hidden_titles"]),
        "visible_titles": group_details["visible_titles"],
        "severity_counts": dict(sorted(severity_counts.items())),
        "rule_counts": dict(sorted(rule_counts.items())),
        "rule_families": family_flags,
        "rule_family_counts": family_counts,
        "manual_review_count": sum(1 for finding in findings if finding.requires_manual_review),
        "hard_blocker_count": sum(1 for finding in findings if finding.blocks_installation),
        "source_metadata_finding_count": sum(1 for finding in findings if finding.rule_id.startswith("SOURCE-META-")),
        "history_finding_count": sum(1 for finding in findings if finding.rule_id.startswith("HIST-")),
    }
    if include_hidden_notes:
        result["hidden_titles"] = group_details["hidden_titles"]
    return result


def visible_warning_titles(findings, verbose: bool = False, max_groups: int = 3) -> tuple:
    details = warning_group_details(findings, verbose=verbose, max_groups=max_groups)
    return details["visible_titles"], len(details["hidden_titles"])


def warning_group_details(findings, verbose: bool = False, max_groups: int = 3) -> Dict[str, List[str]]:
    presenter = FindingPresenter(max_groups=max_groups)
    groups = presenter._groups(findings)
    visible = []
    hidden = []
    for item in groups:
        if item.synthetic or verbose or item.severity in (Severity.HIGH, Severity.CRITICAL) or any(f.show_by_default for f in item.findings):
            visible.append(item)
        else:
            hidden.append(item)
    protected = [item for item in visible if item.severity in (Severity.HIGH, Severity.CRITICAL)]
    lower = [item for item in visible if item.severity not in (Severity.HIGH, Severity.CRITICAL)]
    if not verbose and len(lower) > max_groups:
        hidden.extend(lower[max_groups:])
        visible = protected + lower[:max_groups]
    return {
        "visible_titles": [item.title for item in visible],
        "hidden_titles": [item.title for item in hidden],
    }


def rule_family_flags(rule_counts: Dict[str, int]) -> Dict[str, bool]:
    rules = set(rule_counts)
    return {
        family: bool(rules & family_rules)
        for family, family_rules in RULE_FAMILIES.items()
    }


def rule_family_counts(rule_counts: Dict[str, int]) -> Dict[str, int]:
    return {
        family: sum(int(rule_counts.get(rule_id, 0)) for rule_id in family_rules)
        for family, family_rules in RULE_FAMILIES.items()
    }


def nearest_rank_percentile(values: List[int], percentile: float) -> float:
    if not values:
        return 0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, ceil((percentile / 100) * len(ordered)) - 1))
    return ordered[index]


def summarize(results: Iterable[Dict[str, object]], warning_budget: int = 3) -> Dict[str, object]:
    results = list(results)
    aggregate_rules = Counter()
    aggregate_severity = Counter()
    aggregate_families = Counter()
    rule_examples: Dict[str, List[str]] = {}
    family_examples: Dict[str, List[str]] = {family: [] for family in RULE_FAMILIES}
    visible_counts: List[int] = []
    hidden_counts: List[int] = []
    family_packages = {family: [] for family in RULE_FAMILIES}
    visible_groups_by_package: Dict[str, int] = {}
    manual_review_count = 0
    hard_blocker_count = 0
    source_metadata_finding_count = 0
    history_finding_count = 0
    for item in results:
        aggregate_rules.update(item["rule_counts"])
        aggregate_severity.update(item["severity_counts"])
        package = str(item["package"])
        visible_count = int(item["visible_group_count"])
        visible_counts.append(visible_count)
        hidden_counts.append(int(item["hidden_note_count"]))
        visible_groups_by_package[package] = visible_count
        manual_review_count += int(item.get("manual_review_count", 0))
        hard_blocker_count += int(item.get("hard_blocker_count", 0))
        source_metadata_finding_count += int(item.get("source_metadata_finding_count", 0))
        history_finding_count += int(item.get("history_finding_count", 0))
        for rule_id in item["rule_counts"]:
            rule_examples.setdefault(rule_id, [])
            if len(rule_examples[rule_id]) < 5 and package not in rule_examples[rule_id]:
                rule_examples[rule_id].append(package)
        family_flags = item.get("rule_families", {})
        family_counts = item.get("rule_family_counts", {})
        aggregate_families.update(family_counts)
        for family in RULE_FAMILIES:
            if family_flags.get(family):
                family_packages[family].append(package)
                if len(family_examples[family]) < 5:
                    family_examples[family].append(package)

    noisy = [item for item in results if int(item["visible_group_count"]) > warning_budget]
    top_rules = aggregate_rules.most_common(10)
    top_families = [(family, count) for family, count in aggregate_families.most_common() if count > 0]
    return {
        "packages_scanned": len(results),
        "average_visible_groups": round(sum(visible_counts) / len(visible_counts), 2) if visible_counts else 0,
        "median_visible_groups": median(visible_counts) if visible_counts else 0,
        "p95_visible_groups": nearest_rank_percentile(visible_counts, 95),
        "max_visible_groups": max(visible_counts) if visible_counts else 0,
        "warning_budget": warning_budget,
        "packages_over_warning_budget": [item["package"] for item in noisy],
        "packages_over_default_budget": [item["package"] for item in noisy],
        "visible_groups_by_package": dict(sorted(visible_groups_by_package.items())),
        "packages_with_eval_warnings": family_packages["eval"],
        "packages_with_systemd_unit_notes": family_packages["systemd_unit"],
        "packages_with_systemd_auto_warnings": family_packages["systemd_auto"],
        "packages_with_systemd_user_warnings": family_packages["systemd_user"],
        "packages_with_cron_warnings": family_packages["cron"],
        "eval_warning_package_count": len(family_packages["eval"]),
        "systemd_unit_package_count": len(family_packages["systemd_unit"]),
        "systemd_auto_package_count": len(family_packages["systemd_auto"]),
        "systemd_user_package_count": len(family_packages["systemd_user"]),
        "cron_warning_package_count": len(family_packages["cron"]),
        "eval_finding_count": aggregate_families["eval"],
        "systemd_unit_finding_count": aggregate_families["systemd_unit"],
        "systemd_auto_finding_count": aggregate_families["systemd_auto"],
        "systemd_user_finding_count": aggregate_families["systemd_user"],
        "cron_finding_count": aggregate_families["cron"],
        "source_metadata_finding_count": source_metadata_finding_count,
        "history_finding_count": history_finding_count,
        "manual_review_count": manual_review_count,
        "hard_blocker_count": hard_blocker_count,
        "total_hidden_notes": sum(hidden_counts),
        "aggregate_severity_counts": dict(sorted(aggregate_severity.items())),
        "top_rules": top_rules,
        "top_noisy_rule_ids": top_rules,
        "top_noisy_rule_families": top_families,
        "rule_examples": {rule: examples for rule, examples in sorted(rule_examples.items())},
        "rule_family_examples": {family: examples for family, examples in sorted(family_examples.items()) if examples},
        "suggested_tuning_notes": suggested_tuning_notes(family_packages, top_rules),
    }


def suggested_tuning_notes(family_packages: Dict[str, List[str]], top_rules: List[tuple]) -> List[str]:
    notes: List[str] = []
    if family_packages["systemd_unit"] and not family_packages["systemd_auto"] and not family_packages["systemd_user"]:
        notes.append("Systemd unit files appeared without auto-enable/user persistence; keep these as calm lower-severity notes.")
    if family_packages["systemd_auto"]:
        notes.append("Systemd auto-enable/start warnings appeared; inspect whether they are package install behavior or documentation before tuning further.")
    if family_packages["cron"]:
        notes.append("Cron warnings appeared; confirm they involve crontab or cron paths rather than documentation comments.")
    if family_packages["eval"]:
        notes.append("Eval warnings appeared; review whether they are dynamic execution or packaging helper boilerplate.")
    if top_rules and top_rules[0][1] > 5:
        notes.append(f"{top_rules[0][0]} dominates the sample; consider a targeted false-positive fixture before changing severity.")
    return notes or ["No specific tuning note from this sample."]


def render_text(payload: Dict[str, object]) -> str:
    summary = payload["summary"]
    lines = [
        "AuraScan AUR warning tuning sample",
        f"Packages scanned: {summary['packages_scanned']}",
        f"Fetch errors: {summary['fetch_error_count']}",
        f"Average visible warning groups: {summary['average_visible_groups']}",
        f"Median visible warning groups: {summary['median_visible_groups']}",
        f"P95 visible warning groups: {summary['p95_visible_groups']}",
        f"Max visible warning groups: {summary['max_visible_groups']}",
        f"Warning budget: {summary['warning_budget']}",
        f"Packages over warning budget: {', '.join(summary['packages_over_warning_budget']) if summary['packages_over_warning_budget'] else 'none'}",
        f"Total hidden lower-risk notes: {summary['total_hidden_notes']}",
        f"Manual-review findings: {summary['manual_review_count']}",
        f"Hard-blocker findings: {summary['hard_blocker_count']}",
        f"Source metadata findings: {summary['source_metadata_finding_count']}",
        f"History findings: {summary['history_finding_count']}",
        f"Packages with eval warnings: {summary['eval_warning_package_count']} ({summary['eval_finding_count']} findings)",
        f"Packages with systemd unit notes: {summary['systemd_unit_package_count']} ({summary['systemd_unit_finding_count']} findings)",
        f"Packages with systemd auto-enable warnings: {summary['systemd_auto_package_count']} ({summary['systemd_auto_finding_count']} findings)",
        f"Packages with systemd user warnings: {summary['systemd_user_package_count']} ({summary['systemd_user_finding_count']} findings)",
        f"Packages with cron warnings: {summary['cron_warning_package_count']} ({summary['cron_finding_count']} findings)",
        "\nSeverity distribution:",
    ]
    for severity, count in summary["aggregate_severity_counts"].items():
        lines.append(f"  {severity}: {count}")
    lines.append("\nVisible warning groups by package:")
    for pkgbase, count in summary["visible_groups_by_package"].items():
        lines.append(f"  {pkgbase}: {count}")
    lines.append("\nTop noisy rule IDs:")
    for rule, count in summary["top_rules"]:
        examples = ", ".join(summary["rule_examples"].get(rule, []))
        suffix = f" (examples: {examples})" if examples else ""
        lines.append(f"  {rule}: {count}{suffix}")
    lines.append("\nTop noisy rule families:")
    if summary["top_noisy_rule_families"]:
        for family, count in summary["top_noisy_rule_families"]:
            examples = ", ".join(summary["rule_family_examples"].get(family, []))
            suffix = f" (examples: {examples})" if examples else ""
            lines.append(f"  {family}: {count}{suffix}")
    else:
        lines.append("  none")
    lines.append("\nSuggested tuning notes:")
    for note in summary["suggested_tuning_notes"]:
        lines.append(f"  - {note}")
    if payload["errors"]:
        lines.append("\nFetch errors:")
        for pkgbase, error in payload["errors"].items():
            lines.append(f"  {pkgbase}: {error}")
    if payload.get("threshold_failures"):
        lines.append("\nThreshold failures:")
        for failure in payload["threshold_failures"]:
            lines.append(f"  - {failure}")
    return "\n".join(lines)


def _markdown_escape(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_markdown(payload: Dict[str, object], category_label: Optional[str] = None) -> str:
    summary = payload["summary"]
    lines = ["# AuraScan AUR Warning Tuning Report", ""]
    if category_label:
        lines.extend([f"Category: `{category_label}`", ""])
    lines.extend([
        "## Summary",
        "",
        f"- Packages scanned: {summary['packages_scanned']}",
        f"- Fetch errors: {summary['fetch_error_count']}",
        f"- Average visible warning groups: {summary['average_visible_groups']}",
        f"- Median visible warning groups: {summary['median_visible_groups']}",
        f"- P95 visible warning groups: {summary['p95_visible_groups']}",
        f"- Max visible warning groups: {summary['max_visible_groups']}",
        f"- Warning budget: {summary['warning_budget']}",
        f"- Packages over warning budget: {', '.join(summary['packages_over_warning_budget']) if summary['packages_over_warning_budget'] else 'none'}",
        f"- Hidden lower-risk notes: {summary['total_hidden_notes']}",
        f"- Manual-review findings: {summary['manual_review_count']}",
        f"- Hard-blocker findings: {summary['hard_blocker_count']}",
        "",
        "## Package Warning Groups",
        "",
        "| Package | Visible Groups | Hidden Notes | Visible Titles |",
        "| --- | ---: | ---: | --- |",
    ])
    for item in payload["packages"]:
        titles = "; ".join(item["visible_titles"]) if item["visible_titles"] else "none"
        lines.append(
            "| "
            + " | ".join(
                [
                    _markdown_escape(item["package"]),
                    _markdown_escape(item["visible_group_count"]),
                    _markdown_escape(item["hidden_note_count"]),
                    _markdown_escape(titles),
                ]
            )
            + " |"
        )
    lines.extend(["", "## Top Noisy Rule IDs", "", "| Rule | Count | Examples |", "| --- | ---: | --- |"])
    for rule, count in summary["top_rules"]:
        examples = ", ".join(summary["rule_examples"].get(rule, []))
        lines.append(f"| {_markdown_escape(rule)} | {count} | {_markdown_escape(examples)} |")
    lines.extend(["", "## Top Noisy Rule Families", "", "| Family | Count | Examples |", "| --- | ---: | --- |"])
    if summary["top_noisy_rule_families"]:
        for family, count in summary["top_noisy_rule_families"]:
            examples = ", ".join(summary["rule_family_examples"].get(family, []))
            lines.append(f"| {_markdown_escape(family)} | {count} | {_markdown_escape(examples)} |")
    else:
        lines.append("| none | 0 |  |")
    lines.extend(["", "## Suggested Tuning Notes", ""])
    for note in summary["suggested_tuning_notes"]:
        lines.append(f"- {note}")
    if payload["errors"]:
        lines.extend(["", "## Fetch Errors", ""])
        for pkgbase, error in payload["errors"].items():
            lines.append(f"- `{pkgbase}`: {error}")
    return "\n".join(lines) + "\n"


def evaluate_thresholds(
    payload: Dict[str, object],
    *,
    fail_if_average_visible_warnings_above: Optional[float] = None,
    fail_if_any_package_over_budget: Optional[int] = None,
) -> List[str]:
    summary = payload["summary"]
    failures: List[str] = []
    if (
        fail_if_average_visible_warnings_above is not None
        and float(summary["average_visible_groups"]) > fail_if_average_visible_warnings_above
    ):
        failures.append(
            "average visible warning groups "
            f"{summary['average_visible_groups']} exceeded {fail_if_average_visible_warnings_above}"
        )
    if fail_if_any_package_over_budget is not None:
        over = [
            pkgbase for pkgbase, count in summary["visible_groups_by_package"].items()
            if int(count) > fail_if_any_package_over_budget
        ]
        if over:
            failures.append(
                "packages exceeded visible warning budget "
                f"{fail_if_any_package_over_budget}: {', '.join(over)}"
            )
    return failures


def run(
    packages: List[str],
    *,
    output_json: bool = False,
    output_json_path: Optional[Path] = None,
    output_markdown_path: Optional[Path] = None,
    category_label: Optional[str] = None,
    verbose: bool = False,
    warning_budget: int = 3,
    include_hidden_notes: bool = False,
    timeout: float = 20,
    user_agent: str = DEFAULT_USER_AGENT,
    fail_if_average_visible_warnings_above: Optional[float] = None,
    fail_if_any_package_over_budget: Optional[int] = None,
    fetcher: Optional[Callable[[str], str]] = None,
) -> int:
    results: List[Dict[str, object]] = []
    errors: Dict[str, str] = {}
    active_fetcher = fetcher or make_fetcher(timeout=timeout, user_agent=user_agent)
    with tempfile.TemporaryDirectory(prefix="aurascan-aur-sample-") as tmp:
        workdir = Path(tmp)
        for pkgbase in packages:
            try:
                pkgbuild_path = fetch_package_metadata(pkgbase, workdir, fetcher=active_fetcher)
                results.append(
                    analyze_pkgbuild(
                        pkgbase,
                        pkgbuild_path,
                        verbose=verbose,
                        warning_budget=warning_budget,
                        include_hidden_notes=include_hidden_notes,
                    )
                )
            except AurFetchError as exc:
                errors[pkgbase] = str(exc)

    payload = {"summary": summarize(results, warning_budget=warning_budget), "packages": results, "errors": errors}
    payload["summary"]["fetch_error_count"] = len(errors)
    payload["summary"]["fetch_error_packages"] = sorted(errors)
    payload["threshold_failures"] = evaluate_thresholds(
        payload,
        fail_if_average_visible_warnings_above=fail_if_average_visible_warnings_above,
        fail_if_any_package_over_budget=fail_if_any_package_over_budget,
    )
    if output_json_path:
        output_json_path.parent.mkdir(parents=True, exist_ok=True)
        output_json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if output_markdown_path:
        output_markdown_path.parent.mkdir(parents=True, exist_ok=True)
        output_markdown_path.write_text(render_markdown(payload, category_label=category_label), encoding="utf-8")
    if output_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(render_text(payload))
    if not results:
        return 1
    return 2 if payload["threshold_failures"] else 0


def collect_packages(
    positional_packages: List[str],
    option_packages: Optional[List[str]] = None,
    sample_file: Optional[Path] = None,
    limit: Optional[int] = None,
) -> List[str]:
    packages = list(positional_packages)
    if option_packages:
        packages.extend(option_packages)
    if sample_file:
        packages.extend(
            line.strip() for line in sample_file.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.strip().startswith("#")
        )
    if not packages:
        packages = list(DEFAULT_SAMPLE)
    if limit is not None:
        packages = packages[:max(limit, 0)]
    return packages


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Sample default AuraScan source-metadata warning volume on AUR packages.")
    parser.add_argument("packages", nargs="*", help="AUR pkgbase names to sample")
    parser.add_argument("--packages", dest="option_packages", nargs="+", help="additional AUR pkgbase names to sample")
    parser.add_argument("--json", action="store_true", help="emit machine-readable summary")
    parser.add_argument("--output-json", type=Path, help="write machine-readable summary to this path")
    parser.add_argument("--output-markdown", type=Path, help="write a concise Markdown report to this path")
    parser.add_argument("--category-label", help="label for this package sample in Markdown reports")
    parser.add_argument("--verbose", action="store_true", help="render using verbose presenter rules for counting")
    parser.add_argument("--warning-budget", type=int, default=3, help="visible warning group budget before a package is counted as noisy")
    parser.add_argument("--sample-file", "--package-list-file", dest="sample_file", type=Path, help="newline-delimited pkgbase sample list")
    parser.add_argument("--limit", type=int, help="scan only the first N packages after combining inputs")
    parser.add_argument("--timeout", type=float, default=20, help="metadata fetch timeout in seconds")
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT, help="User-Agent used for metadata fetches")
    parser.add_argument("--include-hidden-notes", action="store_true", help="include hidden lower-risk note titles in JSON package results")
    parser.add_argument("--fail-if-average-visible-warnings-above", type=float, help="exit non-zero when average visible warning groups exceed this value")
    parser.add_argument("--fail-if-any-package-over-budget", type=int, help="exit non-zero when any package has more than this many visible warning groups")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    packages = collect_packages(
        list(args.packages),
        option_packages=args.option_packages,
        sample_file=args.sample_file,
        limit=args.limit,
    )
    return run(
        packages,
        output_json=args.json,
        output_json_path=args.output_json,
        output_markdown_path=args.output_markdown,
        category_label=args.category_label,
        verbose=args.verbose,
        warning_budget=args.warning_budget,
        include_hidden_notes=args.include_hidden_notes,
        timeout=args.timeout,
        user_agent=args.user_agent,
        fail_if_average_visible_warnings_above=args.fail_if_average_visible_warnings_above,
        fail_if_any_package_over_budget=args.fail_if_any_package_over_budget,
    )


if __name__ == "__main__":
    raise SystemExit(main())
