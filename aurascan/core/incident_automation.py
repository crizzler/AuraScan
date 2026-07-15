import fcntl
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Mapping, Optional, Tuple

from aurascan.core.ai_provider import resolve_ai_config
from aurascan.core.config import write_user_env
from aurascan.core.incidents import (
    EXIT_INCIDENT_CONFIG_ERROR,
    EXIT_INCIDENT_REPAIR_FAILED,
    INCIDENT_BACKGROUND_AI_ENV,
    INCIDENT_SYSTEM_ROOT,
    IncidentReport,
    Severity,
    apply_ai_incident_review,
    atomic_write_json,
    build_incident_report,
    current_user_uid,
    highest_priority_pending_marker,
    incident_reviewed_state_path,
    load_incident_report,
    marker_active_categories,
    marker_key,
    persist_incident_report,
    persist_system_incident_report,
    resolve_incident_config,
    run_bounded_command,
    unseen_pending_markers,
    update_pending_marker_repair_state,
    user_incident_root,
)


INCIDENT_AUTO_REPAIR_ENV = "AURASCAN_INCIDENT_AUTO_REPAIR"
INCIDENT_AUTO_REPAIR_VALUES = {"off", "safe"}
INCIDENT_AUTO_REPAIR_POLICY_PATH = Path("/etc/aurascan/incident-autopilot.conf")
INCIDENT_BACKGROUND_SERVICE = "aurascan-incident-assistant.service"
INCIDENT_BACKGROUND_TIMER = "aurascan-incident-assistant.timer"
INCIDENT_SAFE_AUTOPILOT_SERVICE = "aurascan-incident-safe-autopilot.service"
INCIDENT_USER_UNIT_ROOT = Path("/usr/lib/systemd/user")
BACKGROUND_RETRY_SECONDS = (15 * 60, 60 * 60, 6 * 60 * 60, 24 * 60 * 60)
SAFE_AUTOPILOT_COOLDOWN_USEC = 24 * 60 * 60 * 1_000_000
SAFE_AUTOPILOT_MAX_ACTIONS = 2


@dataclass
class AutoRepairPolicy:
    policy: str = "off"
    error: str = ""
    path: Path = INCIDENT_AUTO_REPAIR_POLICY_PATH


def read_auto_repair_policy(
    path: Path = INCIDENT_AUTO_REPAIR_POLICY_PATH,
    *,
    required_uid: int = 0,
) -> AutoRepairPolicy:
    if not path.exists():
        return AutoRepairPolicy(path=path)
    if path.is_symlink() or not path.is_file():
        return AutoRepairPolicy(error="Safe Autopilot policy is not a regular file", path=path)
    try:
        metadata = path.stat()
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return AutoRepairPolicy(error=f"Safe Autopilot policy could not be read: {exc}", path=path)
    if metadata.st_uid != required_uid or metadata.st_mode & 0o022:
        return AutoRepairPolicy(error="Safe Autopilot policy ownership or permissions are unsafe", path=path)
    values: Dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip("\"'").lower()
    policy = values.get(INCIDENT_AUTO_REPAIR_ENV, "off") or "off"
    if policy not in INCIDENT_AUTO_REPAIR_VALUES:
        return AutoRepairPolicy(error=f"invalid {INCIDENT_AUTO_REPAIR_ENV} value", path=path)
    return AutoRepairPolicy(policy=policy, path=path)


def write_auto_repair_policy(
    policy: str,
    path: Path = INCIDENT_AUTO_REPAIR_POLICY_PATH,
    *,
    require_root: bool = True,
) -> Tuple[bool, str]:
    value = str(policy or "").strip().lower()
    if value not in INCIDENT_AUTO_REPAIR_VALUES:
        return False, f"Invalid Safe Autopilot policy: {policy}"
    if require_root and (not hasattr(os, "geteuid") or os.geteuid() != 0):
        return False, "Safe Autopilot policy writes require root privileges."
    try:
        path.parent.mkdir(parents=True, mode=0o755, exist_ok=True)
        fd, tmp_name = tempfile.mkstemp(prefix=".incident-autopilot.", dir=str(path.parent), text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(f"{INCIDENT_AUTO_REPAIR_ENV}={value}\n")
            os.chmod(tmp_name, 0o644)
            os.replace(tmp_name, path)
            os.chmod(path, 0o644)
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)
    except OSError as exc:
        return False, f"Could not write Safe Autopilot policy: {exc}"
    label = "enabled for reversible repairs" if value == "safe" else "disabled"
    return True, f"AuraScan Safe Autopilot is {label}."


def configure_auto_repair_policy(
    policy: str,
    *,
    runner: Callable = subprocess.run,
    helper: Path = Path("/usr/bin/aurascan"),
) -> Tuple[bool, str]:
    value = str(policy or "").strip().lower()
    if value not in INCIDENT_AUTO_REPAIR_VALUES:
        return False, f"Invalid Safe Autopilot policy: {policy}"
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return write_auto_repair_policy(value)
    if not helper.is_file():
        return False, "Safe Autopilot configuration requires the package-managed /usr/bin/aurascan executable."
    try:
        result = runner(
            ["sudo", str(helper), "incidents", "--set-auto-repair-policy", value],
            check=False,
        )
    except OSError as exc:
        return False, f"Could not configure Safe Autopilot: {exc}"
    if int(getattr(result, "returncode", 0)) != 0:
        return False, f"Safe Autopilot policy command failed with exit code {result.returncode}."
    label = "enabled for reversible repairs" if value == "safe" else "disabled"
    return True, f"AuraScan Safe Autopilot is {label}."


def background_unit_status(
    *,
    runner: Callable = subprocess.run,
    unit_root: Path = INCIDENT_USER_UNIT_ROOT,
) -> Dict[str, object]:
    enabled = run_bounded_command(
        runner,
        ["systemctl", "--user", "is-enabled", INCIDENT_BACKGROUND_TIMER],
        max_chars=2000,
        timeout=10,
    )
    active = run_bounded_command(
        runner,
        ["systemctl", "--user", "is-active", INCIDENT_BACKGROUND_TIMER],
        max_chars=2000,
        timeout=10,
    )
    service = run_bounded_command(
        runner,
        ["systemctl", "--user", "is-active", INCIDENT_BACKGROUND_SERVICE],
        max_chars=2000,
        timeout=10,
    )
    return {
        "installed": (unit_root / INCIDENT_BACKGROUND_SERVICE).exists() and (unit_root / INCIDENT_BACKGROUND_TIMER).exists(),
        "timer_enabled": enabled.stdout.strip() or "unknown",
        "timer_active": active.stdout.strip() or "unknown",
        "service_active": service.stdout.strip() or "unknown",
    }


def set_background_ai_enabled(
    enabled: bool,
    *,
    runner: Callable = subprocess.run,
    env_path: Optional[Path] = None,
) -> Tuple[bool, str]:
    command = [
        "systemctl",
        "--user",
        "enable" if enabled else "disable",
        "--now",
        INCIDENT_BACKGROUND_TIMER,
    ]
    try:
        result = runner(command, check=False)
    except OSError as exc:
        return False, f"Could not configure background incident AI: {exc}"
    if int(getattr(result, "returncode", 0)) != 0:
        if enabled:
            return False, f"Background incident AI timer command failed with exit code {result.returncode}."
        status = background_unit_status(runner=runner)
        already_disabled = (
            status.get("timer_enabled") in {"disabled", "not-found", "masked"}
            and status.get("timer_active") in {"inactive", "failed", "unknown"}
        )
        if not already_disabled:
            return False, f"Background incident AI timer command failed with exit code {result.returncode}."
    try:
        write_user_env({INCIDENT_BACKGROUND_AI_ENV: "1" if enabled else "0"}, path=env_path)
    except (OSError, ValueError) as exc:
        rollback = [
            "systemctl",
            "--user",
            "disable" if enabled else "enable",
            "--now",
            INCIDENT_BACKGROUND_TIMER,
        ]
        try:
            runner(rollback, check=False)
        except OSError:
            pass
        return False, f"Background incident AI config could not be written: {exc}"
    if enabled:
        try:
            runner(
                ["systemctl", "--user", "start", "--no-block", INCIDENT_BACKGROUND_SERVICE],
                check=False,
            )
        except OSError:
            pass
        return True, "Background incident AI is enabled for this logged-in user."
    return True, "Background incident AI is disabled for this user."


def user_automation_root(report_root: Path) -> Path:
    return report_root / "automation"


def background_state_path(report_root: Path) -> Path:
    return user_automation_root(report_root) / "background-ai-state.json"


def background_result_path(report_root: Path) -> Path:
    return user_automation_root(report_root) / "background-ai-result.json"


def background_result_seen_path(report_root: Path) -> Path:
    return user_automation_root(report_root) / "background-ai-result-seen.json"


def load_reusable_background_plan(
    fresh_report: IncidentReport,
    marker: Mapping[str, object],
    report_root: Path,
    *,
    now_usec: Optional[int] = None,
) -> Optional[IncidentReport]:
    from aurascan.core.incident_diagnostics import (
        INCIDENT_BACKGROUND_PLAN_MAX_AGE_SECONDS,
        incident_analysis_fingerprint,
    )

    result_path = background_result_path(report_root)
    if not private_user_file(result_path):
        return None
    result = load_private_json(result_path)
    completed_at = int(result.get("completed_at_usec") or 0)
    now = int(time.time() * 1_000_000) if now_usec is None else int(now_usec)
    if completed_at <= 0 or completed_at > now:
        return None
    if now - completed_at > INCIDENT_BACKGROUND_PLAN_MAX_AGE_SECONDS * 1_000_000:
        return None
    if str(result.get("marker_key") or "") != marker_key(marker):
        return None
    expected_fingerprint = str(result.get("analysis_fingerprint") or "")
    if not expected_fingerprint or expected_fingerprint != incident_analysis_fingerprint(fresh_report):
        return None
    report_id = str(result.get("report_id") or "")
    cached = load_incident_report(report_id, report_root)
    if cached is None:
        return None
    report_path = report_root / f"{report_id}.json"
    if not private_user_file(report_path) or incident_analysis_fingerprint(cached) != expected_fingerprint:
        return None
    return cached


def private_user_file(path: Path) -> bool:
    try:
        metadata = path.stat()
    except OSError:
        return False
    if path.is_symlink() or not path.is_file() or metadata.st_uid != current_user_uid():
        return False
    return metadata.st_mode & 0o077 == 0


def load_private_json(path: Path) -> Dict[str, object]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return dict(data) if isinstance(data, Mapping) else {}


def ensure_private_directory(path: Path) -> None:
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass


def _record_background_wait(
    state: Dict[str, object],
    marker_id: str,
    *,
    status: str,
    now_usec: int,
    error: str = "",
) -> None:
    raw_markers = state.get("markers", {})
    markers = dict(raw_markers) if isinstance(raw_markers, Mapping) else {}
    prior = markers.get(marker_id, {})
    attempts = int(prior.get("attempts") or 0) + 1 if isinstance(prior, Mapping) else 1
    delay = BACKGROUND_RETRY_SECONDS[min(attempts - 1, len(BACKGROUND_RETRY_SECONDS) - 1)]
    markers[marker_id] = {
        "status": status,
        "attempts": attempts,
        "last_attempt_usec": now_usec,
        "next_retry_usec": now_usec + delay * 1_000_000,
        "error": str(error)[:500],
    }
    state["markers"] = dict(list(markers.items())[-200:])
    state["last_attempt_usec"] = now_usec
    state["last_status"] = status
    state["last_error"] = str(error)[:500]


def run_background_assistant(
    *,
    env: Mapping[str, str],
    system_root: Path = INCIDENT_SYSTEM_ROOT,
    user_root: Optional[Path] = None,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
    urlopen: Optional[Callable] = None,
    stdout=None,
    stderr=None,
    now_usec: Optional[int] = None,
) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    report_root = user_root or user_incident_root(env)
    automation_root = user_automation_root(report_root)
    ensure_private_directory(automation_root)
    lock_path = automation_root / "background-ai.lock"
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 0
        now = int(time.time() * 1_000_000) if now_usec is None else int(now_usec)
        state_path = background_state_path(report_root)
        state = load_private_json(state_path)
        state.setdefault("schema", "incident_background_ai_state/1.0")
        config = resolve_incident_config(env)
        if config.error or not config.background_ai_enabled or not config.ai_enabled:
            state["last_status"] = "disabled" if not config.error else "config_error"
            state["last_error"] = config.error
            atomic_write_json(state_path, state, mode=0o600)
            return 0
        ai_config = resolve_ai_config(env)
        reviewed_path = incident_reviewed_state_path(env, report_root=report_root)
        markers = unseen_pending_markers(
            uid=current_user_uid(),
            marker_root=system_root / "pending",
            seen_path=reviewed_path,
            include_resolved=True,
        )
        raw_marker_state = state.get("markers", {})
        marker_state = raw_marker_state if isinstance(raw_marker_state, Mapping) else {}
        candidates = []
        for marker in markers:
            identity = marker_key(marker)
            prior = marker_state.get(identity, {})
            if isinstance(prior, Mapping) and str(prior.get("status") or "") == "ok":
                continue
            if isinstance(prior, Mapping) and int(prior.get("next_retry_usec") or 0) > now:
                continue
            candidates.append(marker)
        marker = highest_priority_pending_marker(candidates)
        if marker is None:
            state["last_status"] = "idle"
            state["last_error"] = ""
            atomic_write_json(state_path, state, mode=0o600)
            return 0
        identity = marker_key(marker)
        if ai_config.error or not ai_config.enabled or not ai_config.api_key_present:
            error = ai_config.error or "configured AI provider or API key is unavailable"
            _record_background_wait(state, identity, status="not_configured", now_usec=now, error=error)
            atomic_write_json(state_path, state, mode=0o600)
            return 0
        target_boot = str(marker.get("boot_id") or "")
        report = build_incident_report(
            target_boot,
            trigger="background_ai",
            runner=runner,
            which=which,
        )
        from aurascan.core.incident_diagnostics import (
            incident_analysis_fingerprint,
            prepare_ai_guided_repair_plan,
            repair_plan_fingerprint,
        )
        from aurascan.core.incident_repairs import plan_repair_actions

        report.repair_actions = plan_repair_actions(
            report,
            runner=runner,
            which=which,
            include_package_integrity=False,
        )
        report.system_facts["safe_autopilot"] = {
            "state": str(marker.get("auto_repair_state") or "not_run"),
            "resolved_categories": list(marker.get("resolved_categories", [])) if isinstance(marker.get("resolved_categories"), list) else [],
            "active_categories": marker_active_categories(marker),
        }
        prepare_ai_guided_repair_plan(
            report,
            disabled=False,
            facts_only=config.ai_evidence == "facts-only",
            runner=runner,
            which=which,
            urlopen=urlopen,
            env=env,
            ai_reviewer=apply_ai_incident_review,
        )
        ai_status = str(report.ai_review.get("status") or "unknown")
        report.automation["background_ai"] = {
            "marker_key": identity,
            "status": ai_status,
            "attempted_at_usec": now,
        }
        persist_incident_report(report, report_root)
        if ai_status != "ok":
            error = str(report.ai_review.get("error") or "AI analysis did not complete")
            _record_background_wait(state, identity, status="retry", now_usec=now, error=error)
            atomic_write_json(state_path, state, mode=0o600)
            print("[AuraScan] Background incident AI will retry after a provider or network failure.", file=stderr)
            return 0
        raw_markers = state.get("markers", {})
        completed = dict(raw_markers) if isinstance(raw_markers, Mapping) else {}
        completed[identity] = {
            "status": "ok",
            "attempts": int(completed.get(identity, {}).get("attempts") or 0) + 1 if isinstance(completed.get(identity), Mapping) else 1,
            "last_attempt_usec": now,
            "next_retry_usec": 0,
            "report_id": report.incident_id,
        }
        state["markers"] = dict(list(completed.items())[-200:])
        state["last_attempt_usec"] = now
        state["last_success_usec"] = now
        state["last_status"] = "ok"
        state["last_error"] = ""
        refreshed_marker = next(
            (
                item for item in unseen_pending_markers(
                    uid=current_user_uid(),
                    marker_root=system_root / "pending",
                    seen_path=reviewed_path,
                    include_resolved=True,
                )
                if marker_key(item) == identity
            ),
            marker,
        )
        summary = str(report.ai_review.get("summary") or "AuraScan completed background incident analysis.")[:1000]
        guided_state = report.automation.get("ai_guided_repair", {})
        if not isinstance(guided_state, Mapping):
            guided_state = {}
        result_id = f"{identity}:{report.incident_id}"
        atomic_write_json(
            background_result_path(report_root),
            {
                "schema": "incident_background_ai_result/1.0",
                "result_id": result_id,
                "marker_key": identity,
                "completed_at_usec": now,
                "report_id": report.incident_id,
                "summary": summary,
                "safe_repair_state": str(refreshed_marker.get("auto_repair_state") or "not_run"),
                "prepared_repair_count": len(report.eligible_actions),
                "analysis_fingerprint": incident_analysis_fingerprint(report),
                "repair_plan_fingerprint": repair_plan_fingerprint(report),
                "planner_status": str(guided_state.get("status") or ai_status),
                "provider_requests": int(guided_state.get("provider_requests") or 0),
                "completed_probe_count": int(guided_state.get("completed_probe_count") or 0),
            },
            mode=0o600,
        )
        atomic_write_json(state_path, state, mode=0o600)
        print("[AuraScan] Background incident AI analysis completed.", file=stdout)
        return 0
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(lock_fd)


def print_background_ai_status(
    *,
    env: Mapping[str, str],
    runner: Callable = subprocess.run,
    user_root: Optional[Path] = None,
    stdout=None,
    json_output: bool = False,
) -> int:
    stdout = stdout or sys.stdout
    report_root = user_root or user_incident_root(env)
    config = resolve_incident_config(env)
    provider = resolve_ai_config(env)
    units = background_unit_status(runner=runner)
    state = load_private_json(background_state_path(report_root))
    policy = read_auto_repair_policy()
    payload = {
        "report_type": "incident_background_ai_status",
        "enabled": config.background_ai_enabled if not config.error else False,
        "incident_ai_enabled": config.ai_enabled if not config.error else False,
        "evidence_mode": config.ai_evidence if not config.error else "unknown",
        "provider_ready": not provider.error and provider.enabled and provider.api_key_present,
        "units": units,
        "state": state,
        "auto_repair": {"policy": policy.policy, "error": policy.error},
    }
    if json_output:
        print(json.dumps(payload, indent=2), file=stdout)
    else:
        print("AuraScan background incident AI", file=stdout)
        print(f"Configured: {'enabled' if payload['enabled'] else 'disabled'}", file=stdout)
        print(f"Provider ready: {'yes' if payload['provider_ready'] else 'no'}", file=stdout)
        print(f"User timer installed: {'yes' if units['installed'] else 'no'}", file=stdout)
        print(f"User timer enabled: {units['timer_enabled']}", file=stdout)
        print(f"Last status: {state.get('last_status', 'never')}", file=stdout)
        print(f"Safe Autopilot: {policy.policy}" + (f" ({policy.error})" if policy.error else ""), file=stdout)
    return 0 if not config.error else EXIT_INCIDENT_CONFIG_ERROR


def safe_automation_paths(system_root: Path = INCIDENT_SYSTEM_ROOT) -> Tuple[Path, Path, Path]:
    root = system_root / "automation"
    return root / "safe-autopilot-state.json", root / "safe-autopilot-status.json", root / "safe-autopilot.lock"


def _write_safe_status(path: Path, **values: object) -> None:
    payload = {
        "schema": "incident_safe_autopilot_status/1.0",
        "last_attempt_usec": int(values.get("last_attempt_usec") or 0),
        "last_success_usec": int(values.get("last_success_usec") or 0),
        "state": str(values.get("state") or "never"),
        "categories": sorted({str(item) for item in values.get("categories", []) if str(item)}),
        "action_count": int(values.get("action_count") or 0),
    }
    atomic_write_json(path, payload, mode=0o644)


def run_safe_autopilot(
    *,
    system_root: Path = INCIDENT_SYSTEM_ROOT,
    policy_path: Path = INCIDENT_AUTO_REPAIR_POLICY_PATH,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
    stdout=None,
    stderr=None,
    now_usec: Optional[int] = None,
) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        print("[AuraScan] Safe Autopilot capture requires root privileges.", file=stderr)
        return EXIT_INCIDENT_CONFIG_ERROR
    policy = read_auto_repair_policy(policy_path)
    state_path, status_path, lock_path = safe_automation_paths(system_root)
    state_path.parent.mkdir(parents=True, mode=0o755, exist_ok=True)
    if policy.error or policy.policy != "safe":
        _write_safe_status(status_path, state="disabled" if not policy.error else "config_error")
        return 0 if not policy.error else EXIT_INCIDENT_CONFIG_ERROR
    lock_fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 0
        now = int(time.time() * 1_000_000) if now_usec is None else int(now_usec)
        state = load_private_json(state_path)
        state.setdefault("schema", "incident_safe_autopilot_state/1.0")
        processed = [str(item) for item in state.get("processed_reports", [])] if isinstance(state.get("processed_reports"), list) else []
        raw_cooldowns = state.get("action_cooldowns", {})
        cooldowns = dict(raw_cooldowns) if isinstance(raw_cooldowns, Mapping) else {}
        reports_root = system_root / "reports"
        try:
            report_paths = sorted(reports_root.glob("*.json"), key=lambda path: path.stat().st_mtime, reverse=True)
        except OSError:
            report_paths = []
        report: Optional[IncidentReport] = None
        for path in report_paths[:50]:
            candidate = load_incident_report(path.stem, reports_root)
            if candidate and candidate.incident_id not in processed and candidate.trigger in {"boot_monitor", "weekly_maintenance"}:
                report = candidate
                break
        if report is None:
            _write_safe_status(status_path, last_attempt_usec=now, state="idle")
            return 0
        processed.append(report.incident_id)
        state["processed_reports"] = processed[-100:]
        if report.collection_status != "complete" or report.truncated or any(
            finding.severity in {Severity.HIGH, Severity.CRITICAL} for finding in report.findings
        ):
            report.automation["safe_autopilot"] = {"status": "refused", "reason": "incomplete_or_high_risk"}
            persist_system_incident_report(report, root=reports_root)
            update_pending_marker_repair_state(report, categories=[], state="refused", root=system_root / "pending")
            atomic_write_json(state_path, state, mode=0o600)
            _write_safe_status(status_path, last_attempt_usec=now, state="refused")
            return 0
        from aurascan.core.incident_repairs import (
            execute_background_safe_actions,
            is_background_safe_action,
            plan_repair_actions,
        )

        planned = plan_repair_actions(report, runner=runner, which=which)
        actions = []
        for action in planned:
            last_attempt = int(cooldowns.get(action.action_id) or 0)
            if last_attempt and now - last_attempt < SAFE_AUTOPILOT_COOLDOWN_USEC:
                continue
            if is_background_safe_action(action):
                actions.append(action)
            if len(actions) >= SAFE_AUTOPILOT_MAX_ACTIONS:
                break
        if not actions:
            report.automation["safe_autopilot"] = {"status": "no_action", "action_count": 0}
            persist_system_incident_report(report, root=reports_root)
            update_pending_marker_repair_state(report, categories=[], state="no_action", root=system_root / "pending")
            atomic_write_json(state_path, state, mode=0o600)
            _write_safe_status(status_path, last_attempt_usec=now, state="no_action")
            return 0
        results, ok = execute_background_safe_actions(
            actions,
            runner=runner,
            which=which,
            repair_root=system_root / "repairs",
        )
        report.repair_results.extend(results)
        applied_categories: List[str] = []
        failed_categories: List[str] = []
        for action, result in zip(actions, results):
            cooldowns[action.action_id] = now
            category = str(action.parameters.get("category") or "")
            if result.status == "applied" and result.verified:
                applied_categories.append(category)
            else:
                failed_categories.append(category)
        report.automation["safe_autopilot"] = {
            "status": "applied" if ok else "failed",
            "action_count": len(results),
            "categories": sorted(set(applied_categories + failed_categories)),
            "completed_at_usec": now,
        }
        persist_system_incident_report(report, root=reports_root)
        if applied_categories:
            update_pending_marker_repair_state(
                report,
                categories=applied_categories,
                state="applied",
                root=system_root / "pending",
            )
        if failed_categories:
            update_pending_marker_repair_state(
                report,
                categories=failed_categories,
                state="failed",
                root=system_root / "pending",
            )
        state["action_cooldowns"] = {
            str(key): int(value) for key, value in list(cooldowns.items())[-200:]
            if now - int(value) <= 30 * 24 * 60 * 60 * 1_000_000
        }
        state["last_attempt_usec"] = now
        if ok:
            state["last_success_usec"] = now
        state["last_status"] = "applied" if ok else "failed"
        atomic_write_json(state_path, state, mode=0o600)
        _write_safe_status(
            status_path,
            last_attempt_usec=now,
            last_success_usec=now if ok else int(state.get("last_success_usec") or 0),
            state="applied" if ok else "failed",
            categories=applied_categories + failed_categories,
            action_count=len(results),
        )
        if ok:
            print(f"[AuraScan] Safe Autopilot applied and verified {len(results)} reversible repair(s).", file=stdout)
            return 0
        print("[AuraScan] Safe Autopilot stopped after a repair failed fresh validation.", file=stderr)
        return EXIT_INCIDENT_REPAIR_FAILED
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(lock_fd)
