"""Terminal presentation for the configuration-drift report.

Rendering lives in the presentation layer so ``ConfigDriftReport`` stays data and
semantics. This module reads a finished report and formats it; it never decides
whether a drift file is sensitive, whether an action applies, or what risk a file
carries — those are set on the report before it gets here.
"""

import difflib
from pathlib import Path
from typing import TYPE_CHECKING, List

from aurascan.core.text_safety import advisory_text_or_fallback

if TYPE_CHECKING:  # pragma: no cover - annotations only, never executed
    from aurascan.core.config_drift import ConfigDriftReport


# Presentation copy of the advisory fallback wording shown beside a drift plan.
# The drift engine keeps its own copy for the persisted AI review state;
# ``tests/test_presentation_renderers.py`` asserts the two still agree.
CONFIG_DRIFT_AI_FALLBACK = (
    "AI explanation was omitted because the provider response did not meet AuraScan's guarded advisory contract."
)


def _read_text_lossy(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def preview_diff(target_path: Path, candidate_text: str, *, max_lines: int = 30) -> str:
    """Render a bounded before/after preview of a proposed config edit.

    This is a display formatter: it reads the current target file to show the
    "before" side of a candidate AuraScan would write. The drift engine owns the
    validation and the write; nothing here decides or applies a change.
    """
    target_text = _read_text_lossy(target_path) if target_path.exists() else ""
    lines = list(difflib.unified_diff(
        target_text.splitlines(),
        candidate_text.splitlines(),
        fromfile=str(target_path),
        tofile="AuraScan candidate",
        lineterm="",
    ))
    if len(lines) > max_lines:
        lines = lines[:max_lines] + ["... diff truncated ..."]
    return "\n".join(lines)


def render_config_drift(report: "ConfigDriftReport", *, include_preview: bool = True) -> str:
    """Render a config-drift report as terminal text."""
    lines: List[str] = [
        "\n[AuraScan] Config Drift Assistant",
        "=" * 50,
        f"Files: {len(report.files)} | Planned fixes: {len(report.apply_actions)} | Manual review: {len(report.manual_actions)} | Sensitive: {sum(1 for item in report.files if item.sensitive)}",
        "-" * 50,
    ]
    if report.scan_truncated:
        lines.append("Scan was truncated; some drift files may be missing from this report.")
    if not report.files:
        lines.append("[OK] No .pacnew or .pacsave files were found.")
    for index, action in enumerate(report.actions, start=1):
        label = "will apply" if action.applies else "manual"
        sensitive = " sensitive" if action.drift_file.sensitive else ""
        lines.append(f"{index}. {action.drift_file.path} [{action.drift_file.kind}/{action.drift_file.risk}{sensitive}]")
        lines.append(f"Plan: {action.summary} ({label})")
        if action.ai_note:
            note = advisory_text_or_fallback(
                action.ai_note,
                max_chars=500,
                fallback=CONFIG_DRIFT_AI_FALLBACK,
            )
            if note:
                lines.append(f"AI note: {note}")
        if include_preview and action.candidate_text and action.applies:
            diff = preview_diff(action.drift_file.target_path, action.candidate_text, max_lines=18)
            if diff:
                lines.append("Preview:")
                lines.extend(f"  {line}" for line in diff.splitlines())
        lines.append("")
    if lines and lines[-1] == "":
        lines.pop()
    if report.ai_review and str(report.ai_review.get("status") or "") not in {"disabled", "not_run"}:
        status = str(report.ai_review.get("status") or "unknown")
        provider = str(report.ai_review.get("provider") or "")
        label = f"AI diff review: {status}" + (f" ({provider})" if provider else "")
        lines.append(label)
        if status == "invalid_response":
            lines.append(CONFIG_DRIFT_AI_FALLBACK)
    if report.applied:
        lines.append(f"Applied fixes: {len(report.applied)}")
        if report.backup_root:
            lines.append(f"Backups: {report.backup_root}")
    if report.errors:
        lines.append("Errors:")
        lines.extend(f"- {error}" for error in report.errors)
    return "\n".join(lines)
