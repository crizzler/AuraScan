import argparse
import difflib
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from aurascan.core.ai_provider import call_ai_provider, resolve_ai_config
from aurascan.core.ai_provider import parse_bool as parse_config_bool
from aurascan.core.models import SCANNER_VERSION


CONFIG_DRIFT_SCHEMA_VERSION = "1.0"
CONFIG_DRIFT_ENABLED_ENV = "AURASCAN_CONFIG_DRIFT_ENABLED"
CONFIG_DRIFT_AI_DIFFS_ENV = "AURASCAN_CONFIG_DRIFT_AI_DIFFS"
CONFIG_DRIFT_AI_DIFFS_VALUES = {"ask", "always", "never"}
CONFIG_DRIFT_BACKUP_ROOT = Path("/var/lib/aurascan/config-drift")
EXIT_CONFIG_DRIFT_APPLY_FAILED = 30
EXIT_CONFIG_DRIFT_USER_DECLINED = 31

LOW_RISK_NAMES = {
    "mirrorlist",
    "cachyos-mirrorlist",
    "cachyos-v3-mirrorlist",
    "cachyos-v4-mirrorlist",
}
PACMAN_CONF_SAFE_BOOLEAN_OPTIONS = {
    "CheckSpace",
}
SENSITIVE_PATTERNS = (
    re.compile(r"(^|/)pacman\.conf$"),
    re.compile(r"(^|/)sudoers($|/)"),
    re.compile(r"(^|/)pam\.d/"),
    re.compile(r"(^|/)mkinitcpio(\.conf|\.d/)"),
    re.compile(r"(^|/)dracut\.conf($|\.d/)"),
    re.compile(r"(^|/)default/grub$"),
    re.compile(r"(^|/)grub\.d/"),
    re.compile(r"(^|/)systemd/"),
    re.compile(r"(^|/)fstab$"),
    re.compile(r"(^|/)crypttab$"),
    re.compile(r"(^|/)(passwd|group|shadow|gshadow)$"),
    re.compile(r"(^|/)ssh/"),
    re.compile(r"(^|/)resolv\.conf$"),
    re.compile(r"(^|/)hosts$"),
    re.compile(r"(^|/)NetworkManager/"),
    re.compile(r"(^|/)systemd/network/"),
    re.compile(r"(^|/)modprobe\.d/"),
    re.compile(r"(^|/)modules-load\.d/"),
    re.compile(r"(^|/)sysctl\.d/"),
    re.compile(r"(^|/)security/"),
    re.compile(r"(^|/)polkit-1/"),
    re.compile(r"(^|/)limine"),
    re.compile(r"(^|/)bootloader/"),
)
SECRET_LINE_RE = re.compile(
    r"(?i)\b(password|passwd|passphrase|secret|token|key|api[_-]?key|apikey|private[_-]?key|auth|credential)\b"
)
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
URL_USERINFO_RE = re.compile(r"([a-z][a-z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@", re.IGNORECASE)


@dataclass
class ConfigDriftConfig:
    enabled: bool = True
    ai_diffs: str = "ask"
    error: str = ""


@dataclass
class ConfigDriftOptions:
    dry_run: bool = False
    json_output: bool = False
    yes: bool = False
    no_ai: bool = False
    ai_diffs: bool = False
    root: Path = Path("/etc")
    enabled: bool = True
    config_ai_diffs: str = "ask"
    config_error: str = ""


@dataclass
class ConfigDriftFile:
    path: Path
    target_path: Path
    kind: str
    risk: str
    sensitive: bool = False
    low_risk: bool = False
    supported: bool = True
    reason: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "path": str(self.path),
            "target_path": str(self.target_path),
            "kind": self.kind,
            "risk": self.risk,
            "sensitive": self.sensitive,
            "low_risk": self.low_risk,
            "supported": self.supported,
            "reason": self.reason,
        }


@dataclass
class ConfigDriftAction:
    drift_file: ConfigDriftFile
    action: str
    summary: str
    candidate_text: str = ""
    applies: bool = False
    requires_confirmation: bool = True
    remove_drift: bool = False
    backup_required: bool = True
    ai_note: str = ""
    status: str = "planned"
    error: str = ""

    def to_dict(self, *, include_preview: bool = False) -> Dict[str, object]:
        data = {
            "path": str(self.drift_file.path),
            "target_path": str(self.drift_file.target_path),
            "kind": self.drift_file.kind,
            "risk": self.drift_file.risk,
            "sensitive": self.drift_file.sensitive,
            "action": self.action,
            "summary": self.summary,
            "applies": self.applies,
            "requires_confirmation": self.requires_confirmation,
            "remove_drift": self.remove_drift,
            "backup_required": self.backup_required,
            "ai_note": self.ai_note,
            "status": self.status,
            "error": self.error,
        }
        if self.candidate_text:
            data["candidate_sha256"] = sha256_text(self.candidate_text)
        if include_preview and self.candidate_text:
            data["preview"] = preview_diff(self.drift_file.target_path, self.candidate_text)
        return data


@dataclass
class ConfigDriftReport:
    files: List[ConfigDriftFile] = field(default_factory=list)
    actions: List[ConfigDriftAction] = field(default_factory=list)
    ai_review: Dict[str, object] = field(default_factory=dict)
    applied: List[Dict[str, object]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    backup_root: str = ""
    root: str = "/etc"
    scanner_version: str = SCANNER_VERSION
    schema_version: str = CONFIG_DRIFT_SCHEMA_VERSION
    scan_truncated: bool = False

    @property
    def apply_actions(self) -> List[ConfigDriftAction]:
        return [action for action in self.actions if action.applies]

    @property
    def manual_actions(self) -> List[ConfigDriftAction]:
        return [action for action in self.actions if not action.applies]

    @property
    def requires_confirmation(self) -> bool:
        return any(action.requires_confirmation and action.applies for action in self.actions)

    @property
    def apply_prompt_default_yes(self) -> bool:
        return bool(
            self.apply_actions
            and not self.manual_actions
            and not self.errors
            and not self.scan_truncated
            and all(action.applies for action in self.actions)
        )

    def to_dict(self, *, include_preview: bool = False) -> Dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "scanner_version": self.scanner_version,
            "report_type": "config_drift",
            "root": self.root,
            "scan_truncated": self.scan_truncated,
            "summary": {
                "files": len(self.files),
                "applicable_actions": len(self.apply_actions),
                "manual_actions": len(self.manual_actions),
                "sensitive_files": sum(1 for item in self.files if item.sensitive),
                "errors": len(self.errors),
            },
            "files": [item.to_dict() for item in self.files],
            "actions": [action.to_dict(include_preview=include_preview) for action in self.actions],
            "ai_review": dict(self.ai_review),
            "applied": list(self.applied),
            "errors": list(self.errors),
            "backup_root": self.backup_root,
        }

    def to_json(self, *, indent: Optional[int] = 2, include_preview: bool = False) -> str:
        return json.dumps(self.to_dict(include_preview=include_preview), indent=indent)

    def render_terminal(self, *, include_preview: bool = True) -> str:
        lines = [
            "\n[AuraScan] Config Drift Assistant",
            "=" * 50,
            f"Files: {len(self.files)} | Planned fixes: {len(self.apply_actions)} | Manual review: {len(self.manual_actions)} | Sensitive: {sum(1 for item in self.files if item.sensitive)}",
            "-" * 50,
        ]
        if self.scan_truncated:
            lines.append("Scan was truncated; some drift files may be missing from this report.")
        if not self.files:
            lines.append("[OK] No .pacnew or .pacsave files were found.")
        for index, action in enumerate(self.actions, start=1):
            label = "will apply" if action.applies else "manual"
            sensitive = " sensitive" if action.drift_file.sensitive else ""
            lines.append(f"{index}. {action.drift_file.path} [{action.drift_file.kind}/{action.drift_file.risk}{sensitive}]")
            lines.append(f"Plan: {action.summary} ({label})")
            if action.ai_note:
                lines.append(f"AI note: {action.ai_note}")
            if include_preview and action.candidate_text and action.applies:
                diff = preview_diff(action.drift_file.target_path, action.candidate_text, max_lines=18)
                if diff:
                    lines.append("Preview:")
                    lines.extend(f"  {line}" for line in diff.splitlines())
            lines.append("")
        if lines and lines[-1] == "":
            lines.pop()
        if self.ai_review and str(self.ai_review.get("status") or "") not in {"disabled", "not_run"}:
            status = str(self.ai_review.get("status") or "unknown")
            provider = str(self.ai_review.get("provider") or "")
            label = f"AI diff review: {status}" + (f" ({provider})" if provider else "")
            lines.append(label)
        if self.applied:
            lines.append(f"Applied fixes: {len(self.applied)}")
            if self.backup_root:
                lines.append(f"Backups: {self.backup_root}")
        if self.errors:
            lines.append("Errors:")
            lines.extend(f"- {error}" for error in self.errors)
        return "\n".join(lines)


def build_config_drift_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aurascan config-drift",
        description="Find and safely resolve .pacnew/.pacsave configuration drift.",
    )
    parser.add_argument("--dry-run", action="store_true", help="show the plan without applying changes")
    parser.add_argument("--json", action="store_true", dest="json_output", help="emit a structured JSON report")
    parser.add_argument("--yes", action="store_true", help="apply planned safe fixes without prompting")
    parser.add_argument("--no-ai", action="store_true", help="disable AI config-diff review for this run")
    parser.add_argument("--ai-diffs", action="store_true", help="allow network AI to inspect redacted bounded config diffs")
    parser.add_argument("--root", default="/etc", help="configuration root to scan")
    return parser


def resolve_config_drift_config(env: Optional[Mapping[str, str]] = None) -> ConfigDriftConfig:
    source = env if env is not None else os.environ
    enabled_raw = source.get(CONFIG_DRIFT_ENABLED_ENV)
    enabled = parse_config_bool(enabled_raw)
    if enabled_raw is not None and enabled is None:
        return ConfigDriftConfig(error=f"invalid {CONFIG_DRIFT_ENABLED_ENV} value")
    if enabled is None:
        enabled = True

    ai_diffs = source.get(CONFIG_DRIFT_AI_DIFFS_ENV, "ask").strip().lower() or "ask"
    if ai_diffs not in CONFIG_DRIFT_AI_DIFFS_VALUES:
        return ConfigDriftConfig(error=f"invalid {CONFIG_DRIFT_AI_DIFFS_ENV} value")
    return ConfigDriftConfig(enabled=bool(enabled), ai_diffs=ai_diffs)


def config_drift_options_from_args(args: argparse.Namespace, env: Optional[Mapping[str, str]] = None) -> ConfigDriftOptions:
    config = resolve_config_drift_config(env)
    ai_diffs = bool(args.ai_diffs) or config.ai_diffs == "always"
    return ConfigDriftOptions(
        dry_run=bool(args.dry_run),
        json_output=bool(args.json_output),
        yes=bool(args.yes),
        no_ai=bool(args.no_ai) or config.ai_diffs == "never",
        ai_diffs=ai_diffs,
        root=Path(str(args.root)),
        enabled=config.enabled,
        config_ai_diffs=config.ai_diffs,
        config_error=config.error,
    )


def run_config_drift(
    argv: Optional[Sequence[str]] = None,
    *,
    input_func: Callable[[str], str] = input,
    stdout=None,
    stderr=None,
    runner: Callable = subprocess.run,
    urlopen: Optional[Callable] = None,
    backup_root: Path = CONFIG_DRIFT_BACKUP_ROOT,
) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    args = build_config_drift_parser().parse_args(list(argv or []))
    options = config_drift_options_from_args(args)

    if options.config_error:
        report = ConfigDriftReport(root=str(options.root), errors=[options.config_error])
        _emit_config_report(report, options, stdout)
        return EXIT_CONFIG_DRIFT_APPLY_FAILED
    if not options.enabled:
        report = ConfigDriftReport(root=str(options.root), errors=["config drift assistant is disabled"])
        _emit_config_report(report, options, stdout)
        return 0

    report = build_config_drift_report(options.root)
    apply_ai_config_drift_review(report, disabled=options.no_ai or not options.ai_diffs, urlopen=urlopen)

    if not report.apply_actions or options.dry_run:
        _emit_config_report(report, options, stdout)
        return 0
    if options.json_output and not options.yes:
        _emit_config_report(report, options, stdout)
        return 0
    if not options.json_output:
        _emit_config_report(report, options, stdout)
    if not options.yes:
        default_yes = report.apply_prompt_default_yes
        suffix = "[Y/n]" if default_yes else "[y/N]"
        answer = input_func(f"AuraScan prepared config drift fixes. Apply now? {suffix} ").strip().lower()
        declined = answer in {"n", "no"} if default_yes else answer not in {"y", "yes"}
        if declined:
            print("[AuraScan] Config drift fixes were not applied.", file=stderr)
            return EXIT_CONFIG_DRIFT_USER_DECLINED

    sudo_status = maybe_reexec_config_drift_with_sudo(
        list(argv or []),
        backup_root=backup_root,
        runner=runner,
        stdout=stdout,
        stderr=stderr,
    )
    if sudo_status is not None:
        return sudo_status

    ok = apply_config_drift_actions(report, backup_root=backup_root)
    if options.json_output:
        print(report.to_json(include_preview=True), file=stdout)
    elif report.applied or report.errors:
        print(report.render_terminal(include_preview=False), file=stdout)
    return 0 if ok else EXIT_CONFIG_DRIFT_APPLY_FAILED


def maybe_reexec_config_drift_with_sudo(
    argv: List[str],
    *,
    backup_root: Path,
    runner: Callable,
    stdout,
    stderr,
) -> Optional[int]:
    if os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() == 0:
        return None
    if backup_root != CONFIG_DRIFT_BACKUP_ROOT:
        return None
    if "--yes" not in argv:
        argv = list(argv) + ["--yes"]
    cmd = ["sudo", sys.executable, "-m", "aurascan", "config-drift"] + argv
    print("[AuraScan] Applying config drift fixes requires root privileges; re-running with sudo.", file=stderr)
    try:
        result = runner(cmd, check=False)
    except OSError as exc:
        print(f"[AuraScan] Could not start sudo config drift apply: {exc}", file=stderr)
        return EXIT_CONFIG_DRIFT_APPLY_FAILED
    return int(getattr(result, "returncode", 0))


def _emit_config_report(report: ConfigDriftReport, options: ConfigDriftOptions, stdout) -> None:
    if options.json_output:
        print(report.to_json(include_preview=True), file=stdout)
    else:
        print(report.render_terminal(), file=stdout)


def build_config_drift_report(root: Path = Path("/etc"), *, max_entries: int = 20000) -> ConfigDriftReport:
    files, truncated = discover_config_drift_files(root, max_entries=max_entries)
    actions = [plan_config_drift_action(item) for item in files]
    return ConfigDriftReport(
        files=files,
        actions=actions,
        root=str(root),
        scan_truncated=truncated,
        ai_review={"enabled": False, "status": "not_run"},
    )


def discover_config_drift_files(root: Path, *, max_entries: int = 20000) -> Tuple[List[ConfigDriftFile], bool]:
    found: List[ConfigDriftFile] = []
    seen = 0
    try:
        for current, dirs, files in os.walk(str(root)):
            dirs[:] = [name for name in dirs if name not in {".git", "pacman.d/gnupg"}]
            for filename in files:
                seen += 1
                if filename.endswith((".pacnew", ".pacsave")):
                    path = Path(current) / filename
                    found.append(classify_config_drift_file(path, root=root))
                if seen >= max_entries:
                    return sorted(found, key=lambda item: str(item.path)), True
    except OSError:
        return sorted(found, key=lambda item: str(item.path)), False
    return sorted(found, key=lambda item: str(item.path)), False


def classify_config_drift_file(path: Path, *, root: Path = Path("/etc")) -> ConfigDriftFile:
    kind = "pacnew" if path.name.endswith(".pacnew") else "pacsave"
    target_path = drift_target_path(path)
    rel = _relative_config_path(target_path, root)
    low_risk = is_low_risk_config(rel)
    sensitive = is_sensitive_config(rel)
    supported = True
    reason = ""
    if path.is_symlink() or (target_path.exists() and target_path.is_symlink()):
        supported = False
        reason = "symlink paths need manual review"
    risk = "low" if low_risk and not sensitive else "sensitive" if sensitive else "normal"
    return ConfigDriftFile(
        path=path,
        target_path=target_path,
        kind=kind,
        risk=risk,
        sensitive=sensitive,
        low_risk=low_risk,
        supported=supported,
        reason=reason,
    )


def drift_target_path(path: Path) -> Path:
    name = path.name
    if name.endswith(".pacnew"):
        return path.with_name(name[:-7])
    if name.endswith(".pacsave"):
        return path.with_name(name[:-8])
    return path


def is_low_risk_config(relative_path: str) -> bool:
    name = Path(relative_path).name
    return name in LOW_RISK_NAMES or name.endswith("-mirrorlist") or "mirrorlist" in name


def is_sensitive_config(relative_path: str) -> bool:
    normalized = relative_path.strip("/")
    return any(pattern.search(normalized) for pattern in SENSITIVE_PATTERNS)


def plan_config_drift_action(item: ConfigDriftFile) -> ConfigDriftAction:
    if item.kind == "pacsave":
        return ConfigDriftAction(
            drift_file=item,
            action="explain_pacsave",
            summary=".pacsave means a locally modified config was preserved when a package stopped owning it; AuraScan will not restore or delete it automatically in v1.",
            applies=False,
        )
    if not item.supported:
        return ConfigDriftAction(
            drift_file=item,
            action="manual_review",
            summary=item.reason or "This path needs manual review.",
            applies=False,
        )
    if not item.path.is_file():
        return ConfigDriftAction(
            drift_file=item,
            action="manual_review",
            summary="This drift entry is not a regular file.",
            applies=False,
        )
    if is_binary_file(item.path) or (item.target_path.exists() and is_binary_file(item.target_path)):
        return ConfigDriftAction(
            drift_file=item,
            action="manual_review",
            summary="Binary or non-text config drift needs manual review.",
            applies=False,
        )

    drift_text = read_text_lossy(item.path)
    target_exists = item.target_path.exists()
    target_text = read_text_lossy(item.target_path) if target_exists and item.target_path.is_file() else ""

    if not target_exists:
        return ConfigDriftAction(
            drift_file=item,
            action="install_missing_target",
            summary="The original config file is missing, so AuraScan can install the packaged config with a backup record.",
            candidate_text=drift_text,
            applies=True,
            requires_confirmation=item.sensitive,
            remove_drift=True,
        )
    if drift_text == target_text:
        return ConfigDriftAction(
            drift_file=item,
            action="remove_identical_drift",
            summary="The .pacnew content already matches the active config, so AuraScan can remove the duplicate drift file.",
            applies=True,
            requires_confirmation=False,
            remove_drift=True,
        )
    if item.low_risk:
        return ConfigDriftAction(
            drift_file=item,
            action="replace_low_risk_config",
            summary="This looks like mirrorlist-style package data, so AuraScan can replace it with the packaged version after backing it up.",
            candidate_text=drift_text,
            applies=True,
            requires_confirmation=False,
            remove_drift=True,
        )
    if meaningful_lines(target_text) == meaningful_lines(drift_text):
        return ConfigDriftAction(
            drift_file=item,
            action="replace_comments_only_config",
            summary="Only comments or blank lines appear to differ, so AuraScan can take the packaged formatting after backing up the current file.",
            candidate_text=drift_text,
            applies=True,
            requires_confirmation=item.sensitive,
            remove_drift=True,
        )
    if not meaningful_lines(drift_text):
        return ConfigDriftAction(
            drift_file=item,
            action="preserve_active_remove_packaged_comments",
            summary="The packaged .pacnew contains only comments or blank lines while the active config contains real local settings, so AuraScan can keep the active file and remove the drift after backing it up.",
            applies=True,
            requires_confirmation=item.sensitive,
            remove_drift=True,
        )
    pacman_candidate = plan_pacman_conf_candidate(item, target_text, drift_text)
    if pacman_candidate is not None:
        return ConfigDriftAction(
            drift_file=item,
            action="merge_pacman_conf_safe_options" if pacman_candidate != target_text else "preserve_pacman_conf_local_policy",
            summary=(
                "AuraScan can preserve the active local repository and pacman settings while merging safe packaged pacman.conf defaults."
                if pacman_candidate != target_text
                else "AuraScan can preserve the active pacman.conf because the packaged baseline would remove local repository policy."
            ),
            candidate_text=pacman_candidate if pacman_candidate != target_text else "",
            applies=True,
            requires_confirmation=True,
            remove_drift=True,
        )
    return ConfigDriftAction(
        drift_file=item,
        action="manual_merge_required",
        summary="The active config and packaged config both contain meaningful differences. AuraScan will explain it, but v1 will not guess this merge.",
        applies=False,
    )


def apply_config_drift_actions(
    report: ConfigDriftReport,
    *,
    backup_root: Path = CONFIG_DRIFT_BACKUP_ROOT,
) -> bool:
    run_id = time.strftime("%Y%m%d-%H%M%S") + f"-{os.getpid()}"
    run_root = backup_root / run_id
    manifest: Dict[str, object] = {
        "schema_version": CONFIG_DRIFT_SCHEMA_VERSION,
        "created_at": int(time.time()),
        "actions": [],
    }
    ok = True
    for action in report.apply_actions:
        try:
            backup_entry = backup_action_files(action, run_root)
            manifest["actions"].append(backup_entry)
            apply_one_action(action)
            action.status = "applied"
            report.applied.append({
                "path": str(action.drift_file.path),
                "target_path": str(action.drift_file.target_path),
                "action": action.action,
                "backup": backup_entry,
            })
        except Exception as exc:
            ok = False
            action.status = "error"
            action.error = str(exc)
            report.errors.append(f"{action.drift_file.path}: {exc}")
            restore_backup_entry(manifest["actions"][-1] if manifest["actions"] else {})
    if manifest["actions"]:
        run_root.mkdir(parents=True, exist_ok=True)
        manifest_path = run_root / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        report.backup_root = str(run_root)
    return ok


def backup_action_files(action: ConfigDriftAction, run_root: Path) -> Dict[str, object]:
    entry: Dict[str, object] = {
        "path": str(action.drift_file.path),
        "target_path": str(action.drift_file.target_path),
        "action": action.action,
        "target_exists": action.drift_file.target_path.exists(),
        "drift_sha256": sha256_file(action.drift_file.path) if action.drift_file.path.exists() else "",
        "target_sha256": sha256_file(action.drift_file.target_path) if action.drift_file.target_path.exists() else "",
    }
    files_root = run_root / "files"
    for label, path in (("drift", action.drift_file.path), ("target", action.drift_file.target_path)):
        if not path.exists() or not path.is_file():
            continue
        backup_path = files_root / label / safe_backup_relative(path)
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, backup_path)
        stat = path.stat()
        entry[f"{label}_backup"] = str(backup_path)
        entry[f"{label}_mode"] = stat.st_mode & 0o777
        entry[f"{label}_uid"] = stat.st_uid
        entry[f"{label}_gid"] = stat.st_gid
    return entry


def restore_backup_entry(entry: Mapping[str, object]) -> None:
    target_backup = str(entry.get("target_backup") or "")
    target_path = str(entry.get("target_path") or "")
    if target_backup and target_path and Path(target_backup).exists():
        shutil.copy2(target_backup, target_path)


def apply_one_action(action: ConfigDriftAction) -> None:
    target = action.drift_file.target_path
    drift = action.drift_file.path
    if action.action == "remove_identical_drift" or (action.remove_drift and not action.candidate_text):
        drift.unlink()
        return
    if not action.candidate_text:
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    mode = _path_mode(target) or _path_mode(drift) or 0o644
    uid_gid = _path_uid_gid(target) or _path_uid_gid(drift)
    tmp = target.parent / f".{target.name}.aurascan-tmp-{os.getpid()}"
    try:
        tmp.write_text(action.candidate_text, encoding="utf-8")
        os.chmod(tmp, mode)
        if uid_gid is not None:
            try:
                os.chown(tmp, uid_gid[0], uid_gid[1])
            except PermissionError:
                pass
        os.replace(tmp, target)
        if action.remove_drift and drift.exists():
            drift.unlink()
    finally:
        if tmp.exists():
            tmp.unlink()


def apply_ai_config_drift_review(
    report: ConfigDriftReport,
    *,
    disabled: bool = False,
    urlopen: Optional[Callable] = None,
) -> None:
    if disabled:
        report.ai_review = {"enabled": False, "status": "disabled"}
        return
    config = resolve_ai_config(os.environ)
    if config.error:
        report.ai_review = {"enabled": False, "status": "config_error", "error": config.error}
        return
    if not config.enabled or not config.api_key_present:
        report.ai_review = {"enabled": False, "status": "not_configured"}
        return
    prompt = build_config_drift_ai_prompt(report)
    try:
        text = call_ai_provider(config, prompt, timeout=20, urlopen=urlopen)
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError("AI response was not a JSON object")
    except Exception as exc:
        report.ai_review = {"enabled": True, "provider": config.provider, "status": "invalid_response", "error": str(exc)}
        return
    apply_ai_notes(report, data)
    report.ai_review = {
        "enabled": True,
        "provider": config.provider,
        "status": "ok",
        "summary": str(data.get("summary") or ""),
    }


def build_config_drift_ai_prompt(report: ConfigDriftReport) -> str:
    payload = {
        "files": [
            {
                "path": str(action.drift_file.path),
                "target_path": str(action.drift_file.target_path),
                "risk": action.drift_file.risk,
                "action": action.action,
                "summary": action.summary,
                "redacted_diff": redacted_preview_diff(action.drift_file.target_path, action.drift_file.path),
            }
            for action in report.actions[:20]
        ]
    }
    return (
        "You are AuraScan's config drift reviewer for Arch-family .pacnew files.\n"
        "Use only the redacted bounded diffs below. Do not claim a merge is guaranteed safe.\n"
        "You may explain risks and suggest caution, but you cannot override AuraScan's deterministic action, backups, or sensitive-file confirmation rules.\n"
        "Return strict JSON only with this shape:\n"
        "{\"summary\":\"short summary\",\"files\":[{\"path\":\"path from input\",\"risk_notes\":\"short note\",\"confidence\":\"low|medium|high\"}]}\n\n"
        + json.dumps(payload, sort_keys=True)
    )


def apply_ai_notes(report: ConfigDriftReport, data: Mapping[str, object]) -> None:
    by_path = {str(action.drift_file.path): action for action in report.actions}
    items = data.get("files", [])
    if not isinstance(items, list):
        return
    for item in items:
        if not isinstance(item, Mapping):
            continue
        path = str(item.get("path") or "")
        note = str(item.get("risk_notes") or "").strip()
        if path in by_path and note:
            by_path[path].ai_note = note[:500]


def redacted_preview_diff(target_path: Path, drift_path: Path, *, max_chars: int = 6000) -> str:
    target_text = read_text_lossy(target_path) if target_path.exists() else ""
    drift_text = read_text_lossy(drift_path) if drift_path.exists() else ""
    diff = "\n".join(difflib.unified_diff(
        redact_text(target_text).splitlines(),
        redact_text(drift_text).splitlines(),
        fromfile=str(target_path),
        tofile=str(drift_path),
        lineterm="",
    ))
    return diff[:max_chars]


def redact_text(text: str) -> str:
    text = PRIVATE_KEY_RE.sub("<redacted-private-key>", text)
    text = URL_USERINFO_RE.sub(r"\1<redacted>:<redacted>@", text)
    redacted_lines = []
    for line in text.splitlines():
        if SECRET_LINE_RE.search(line):
            if "=" in line:
                key, _value = line.split("=", 1)
                redacted_lines.append(f"{key}=<redacted>")
            elif ":" in line:
                key, _value = line.split(":", 1)
                redacted_lines.append(f"{key}: <redacted>")
            else:
                redacted_lines.append("<redacted-secret-line>")
        else:
            redacted_lines.append(line)
    return "\n".join(redacted_lines)


def preview_diff(target_path: Path, candidate_text: str, *, max_lines: int = 30) -> str:
    target_text = read_text_lossy(target_path) if target_path.exists() else ""
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


def read_text_lossy(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def is_binary_file(path: Path) -> bool:
    try:
        return b"\x00" in path.read_bytes()[:4096]
    except OSError:
        return False


def meaningful_lines(text: str) -> List[str]:
    result = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        result.append(stripped)
    return result


def plan_pacman_conf_candidate(item: ConfigDriftFile, target_text: str, drift_text: str) -> Optional[str]:
    if item.target_path.name != "pacman.conf":
        return None
    if not has_cachyos_pacman_policy(target_text):
        return None
    active_options = enabled_pacman_options(target_text)
    packaged_options = enabled_pacman_options(drift_text)
    candidate = target_text
    for option in sorted(PACMAN_CONF_SAFE_BOOLEAN_OPTIONS):
        if option in packaged_options and option not in active_options:
            candidate = enable_pacman_boolean_option(candidate, option)
    return candidate


def has_cachyos_pacman_policy(text: str) -> bool:
    for line in meaningful_lines(text):
        lowered = line.lower()
        if lowered.startswith("[cachyos") or "cachyos-mirrorlist" in lowered:
            return True
    return False


def enabled_pacman_options(text: str) -> Dict[str, str]:
    options: Dict[str, str] = {}
    section = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped.strip("[]").strip().lower()
            continue
        if section != "options":
            continue
        key = re.split(r"\s|=", stripped, maxsplit=1)[0].strip()
        if key:
            options[key] = stripped
    return options


def enable_pacman_boolean_option(text: str, option: str) -> str:
    lines = text.splitlines(keepends=True)
    in_options = False
    insert_at: Optional[int] = None
    commented = re.compile(rf"^(\s*)#\s*{re.escape(option)}\s*$")
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            if in_options:
                insert_at = index
                break
            in_options = stripped.strip("[]").strip().lower() == "options"
            continue
        if not in_options:
            continue
        newline = "\n" if line.endswith("\n") else ""
        match = commented.match(line.rstrip("\n"))
        if match:
            lines[index] = f"{match.group(1)}{option}{newline}"
            return "".join(lines)
    if insert_at is None:
        insert_at = len(lines)
    lines.insert(insert_at, f"{option}\n")
    return "".join(lines)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def safe_backup_relative(path: Path) -> Path:
    parts = [part for part in path.parts if part not in {"/", ""}]
    return Path(*parts) if parts else Path(path.name)


def _relative_config_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path).lstrip("/")


def _path_mode(path: Path) -> Optional[int]:
    try:
        return path.stat().st_mode & 0o777
    except OSError:
        return None


def _path_uid_gid(path: Path) -> Optional[Tuple[int, int]]:
    try:
        stat = path.stat()
    except OSError:
        return None
    return stat.st_uid, stat.st_gid
