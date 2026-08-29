import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Mapping, Optional, Sequence, Tuple

from aurascan.core.ai_provider import (
    AIProviderError,
    call_ai_provider,
    parse_bool,
    resolve_ai_config,
)
from aurascan.core.config import user_env_path, write_user_env


INSTRUCTION_MONITOR_ENABLED_ENV = "AURASCAN_INSTRUCTION_MONITOR_ENABLED"
INSTRUCTION_AI_ENABLED_ENV = "AURASCAN_INSTRUCTION_AI_ENABLED"
INSTRUCTION_SCAN_MODE_ENV = "AURASCAN_INSTRUCTION_SCAN_MODE"
INSTRUCTION_SCAN_MODES = {"agent-surfaces", "all-markdown"}
INSTRUCTION_MONITOR_SERVICE = "aurascan-instruction-monitor.service"
INSTRUCTION_MONITOR_TIMER = "aurascan-instruction-monitor.timer"
INSTRUCTION_ASSISTANT_SERVICE = "aurascan-instruction-assistant.service"
INSTRUCTION_ASSISTANT_TIMER = "aurascan-instruction-assistant.timer"
INSTRUCTION_USER_UNIT_ROOT = Path("/usr/lib/systemd/user")
EXIT_CLEAR = 0
EXIT_REVIEW = 1
EXIT_ERROR = 2


@dataclass(frozen=True)
class InstructionGuardPreferences:
    monitor_enabled: bool = False
    ai_enabled: bool = False
    scan_mode: str = "agent-surfaces"
    error: str = ""


@dataclass(frozen=True)
class _UserTimerState:
    timer_enabled: bool
    timer_active: bool
    service_active: bool


def resolve_instruction_guard_preferences(
    env: Optional[Mapping[str, str]] = None,
) -> InstructionGuardPreferences:
    source = os.environ if env is None else env
    monitor_raw = source.get(INSTRUCTION_MONITOR_ENABLED_ENV)
    ai_raw = source.get(INSTRUCTION_AI_ENABLED_ENV)
    monitor = parse_bool(monitor_raw)
    ai = parse_bool(ai_raw)
    mode = str(source.get(INSTRUCTION_SCAN_MODE_ENV, "agent-surfaces") or "").strip().lower()
    errors = []
    if monitor_raw is not None and monitor is None:
        errors.append(f"invalid {INSTRUCTION_MONITOR_ENABLED_ENV}")
    if ai_raw is not None and ai is None:
        errors.append(f"invalid {INSTRUCTION_AI_ENABLED_ENV}")
    if mode not in INSTRUCTION_SCAN_MODES:
        errors.append(f"invalid {INSTRUCTION_SCAN_MODE_ENV}")
        mode = "agent-surfaces"
    return InstructionGuardPreferences(
        monitor_enabled=bool(monitor),
        ai_enabled=bool(ai),
        scan_mode=mode,
        error="; ".join(errors),
    )


def read_instruction_guard_preferences(
    path: Optional[Path] = None,
    *,
    max_bytes: int = 256 * 1024,
) -> InstructionGuardPreferences:
    """Read only Instruction Guard keys, without retaining provider secrets."""

    target = path or user_env_path()
    selected: Dict[str, str] = {}
    try:
        before = target.lstat()
    except FileNotFoundError:
        return InstructionGuardPreferences()
    except OSError as exc:
        return InstructionGuardPreferences(error=f"could not read user config: {exc}")
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.getuid()
        or stat.S_IMODE(before.st_mode) & 0o077
    ):
        return InstructionGuardPreferences(error="user config failed no-follow type or ownership validation")
    if before.st_size > max_bytes:
        return InstructionGuardPreferences(error="user config exceeds the bounded read limit")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(str(target), flags)
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                return InstructionGuardPreferences(error="user config changed while opening")
            chunks = []
            total = 0
            while True:
                chunk = os.read(fd, min(65536, max_bytes + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                if total > max_bytes:
                    return InstructionGuardPreferences(error="user config exceeds the bounded read limit")
            after = os.fstat(fd)
        finally:
            os.close(fd)
        current = target.lstat()
    except OSError as exc:
        return InstructionGuardPreferences(error=f"could not read user config safely: {exc}")
    opened_state = (
        opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns,
        opened.st_ctime_ns, stat.S_IMODE(opened.st_mode), opened.st_uid,
    )
    after_state = (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
        after.st_ctime_ns, stat.S_IMODE(after.st_mode), after.st_uid,
    )
    current_state = (
        current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns,
        current.st_ctime_ns, stat.S_IMODE(current.st_mode), current.st_uid,
    )
    if opened_state != after_state or current_state != after_state:
        return InstructionGuardPreferences(error="user config changed while reading")
    raw = b"".join(chunks)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return InstructionGuardPreferences(error="user config is not valid UTF-8")
    allowed = {
        INSTRUCTION_MONITOR_ENABLED_ENV,
        INSTRUCTION_AI_ENABLED_ENV,
        INSTRUCTION_SCAN_MODE_ENV,
    }
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        if key in allowed:
            selected[key] = value.strip().strip("'\"")
    return resolve_instruction_guard_preferences(selected)


def _run_unit_command(
    runner: Callable,
    command: Sequence[str],
    *,
    timeout: int = 10,
):
    kwargs = {
        "capture_output": True,
        "text": True,
        "check": False,
        "timeout": timeout,
    }
    try:
        return runner(list(command), **kwargs)
    except TypeError:
        kwargs.pop("timeout", None)
        try:
            return runner(list(command), **kwargs)
        except TypeError:
            return runner(list(command), check=False)


def instruction_guard_unit_status(
    *,
    runner: Callable = subprocess.run,
    unit_root: Path = INSTRUCTION_USER_UNIT_ROOT,
) -> Dict[str, object]:
    def status(command: Sequence[str]) -> str:
        try:
            result = _run_unit_command(runner, command)
        except (OSError, subprocess.SubprocessError):
            return "unavailable"
        value = str(getattr(result, "stdout", "") or "").strip()
        if value:
            return value[:200]
        return "unknown" if int(getattr(result, "returncode", 1)) else "inactive"

    return {
        "monitor_installed": all(
            (unit_root / name).is_file()
            for name in (INSTRUCTION_MONITOR_SERVICE, INSTRUCTION_MONITOR_TIMER)
        ),
        "assistant_installed": all(
            (unit_root / name).is_file()
            for name in (INSTRUCTION_ASSISTANT_SERVICE, INSTRUCTION_ASSISTANT_TIMER)
        ),
        "monitor_timer_enabled": status(
            ["systemctl", "--user", "is-enabled", INSTRUCTION_MONITOR_TIMER]
        ),
        "monitor_timer_active": status(
            ["systemctl", "--user", "is-active", INSTRUCTION_MONITOR_TIMER]
        ),
        "monitor_service_active": status(
            ["systemctl", "--user", "is-active", INSTRUCTION_MONITOR_SERVICE]
        ),
        "assistant_timer_enabled": status(
            ["systemctl", "--user", "is-enabled", INSTRUCTION_ASSISTANT_TIMER]
        ),
        "assistant_timer_active": status(
            ["systemctl", "--user", "is-active", INSTRUCTION_ASSISTANT_TIMER]
        ),
        "assistant_service_active": status(
            ["systemctl", "--user", "is-active", INSTRUCTION_ASSISTANT_SERVICE]
        ),
    }


def _configure_user_timer(
    enabled: bool,
    *,
    timer: str,
    service: str,
    label: str,
    runner: Callable,
) -> Tuple[bool, str]:
    command = [
        "systemctl",
        "--user",
        "enable" if enabled else "disable",
        "--now",
        timer,
    ]
    try:
        result = _run_unit_command(runner, command)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"Could not configure {label}: {exc}"
    if int(getattr(result, "returncode", 1)) != 0:
        if not enabled:
            try:
                enabled_result = _run_unit_command(
                    runner,
                    ["systemctl", "--user", "is-enabled", timer],
                )
                active_result = _run_unit_command(
                    runner,
                    ["systemctl", "--user", "is-active", timer],
                )
                enabled_state = str(getattr(enabled_result, "stdout", "") or "").strip()
                active_state = str(getattr(active_result, "stdout", "") or "").strip()
                if enabled_state in {"disabled", "masked", "not-found"} and active_state in {
                    "inactive",
                    "failed",
                    "unknown",
                    "",
                }:
                    return True, f"{label} is already disabled for this user."
            except (OSError, subprocess.SubprocessError):
                pass
        detail = str(getattr(result, "stderr", "") or "").strip()
        suffix = f": {detail[:300]}" if detail else ""
        return False, f"{label} timer command failed with exit code {result.returncode}{suffix}."
    if enabled:
        try:
            _run_unit_command(
                runner,
                ["systemctl", "--user", "start", "--no-block", service],
            )
        except (OSError, subprocess.SubprocessError):
            pass
        return True, f"{label} is enabled for this logged-in user."
    return True, f"{label} is disabled for this user."


def _query_user_unit_boolean(
    *,
    runner: Callable,
    query: str,
    unit: str,
) -> Optional[bool]:
    try:
        result = _run_unit_command(
            runner,
            ["systemctl", "--user", query, unit],
        )
    except (OSError, subprocess.SubprocessError):
        return None
    value = str(getattr(result, "stdout", "") or "").strip().lower()
    if query == "is-enabled":
        if value == "enabled":
            return True
        if value in {"disabled", "not-found"}:
            return False
    elif query == "is-active":
        if value == "active":
            return True
        if value in {"inactive", "failed", "not-found"}:
            return False
    return None


def _capture_user_timer_state(
    *,
    timer: str,
    service: str,
    runner: Callable,
) -> Optional[_UserTimerState]:
    timer_enabled = _query_user_unit_boolean(
        runner=runner,
        query="is-enabled",
        unit=timer,
    )
    timer_active = _query_user_unit_boolean(
        runner=runner,
        query="is-active",
        unit=timer,
    )
    service_active = _query_user_unit_boolean(
        runner=runner,
        query="is-active",
        unit=service,
    )
    if timer_enabled is None or timer_active is None or service_active is None:
        return None
    return _UserTimerState(
        timer_enabled=timer_enabled,
        timer_active=timer_active,
        service_active=service_active,
    )


def _restore_user_timer_state(
    state: _UserTimerState,
    *,
    timer: str,
    service: str,
    runner: Callable,
) -> bool:
    commands = [
        [
            "systemctl",
            "--user",
            "enable" if state.timer_enabled else "disable",
            "--now",
            timer,
        ],
    ]
    if state.timer_active != state.timer_enabled:
        commands.append([
            "systemctl",
            "--user",
            "start" if state.timer_active else "stop",
            timer,
        ])
    if state.service_active:
        commands.append([
            "systemctl",
            "--user",
            "start",
            "--no-block",
            service,
        ])
    else:
        commands.append(["systemctl", "--user", "stop", service])
    restored = True
    for command in commands:
        try:
            result = _run_unit_command(runner, command)
        except (OSError, subprocess.SubprocessError):
            restored = False
            continue
        if int(getattr(result, "returncode", 1)) != 0:
            restored = False
    return restored


def set_instruction_monitor_enabled(
    enabled: bool,
    *,
    runner: Callable = subprocess.run,
    env_path: Optional[Path] = None,
    write_config: bool = True,
) -> Tuple[bool, str]:
    prior_state = None
    if write_config:
        prior_state = _capture_user_timer_state(
            timer=INSTRUCTION_MONITOR_TIMER,
            service=INSTRUCTION_MONITOR_SERVICE,
            runner=runner,
        )
        if prior_state is None:
            return False, "Could not safely capture the monitor's prior user-unit state."
    ok, message = _configure_user_timer(
        enabled,
        timer=INSTRUCTION_MONITOR_TIMER,
        service=INSTRUCTION_MONITOR_SERVICE,
        label="Agent Instruction Guard monitor",
        runner=runner,
    )
    if not ok:
        if prior_state is not None and not _restore_user_timer_state(
            prior_state,
            timer=INSTRUCTION_MONITOR_TIMER,
            service=INSTRUCTION_MONITOR_SERVICE,
            runner=runner,
        ):
            message += " The prior user-unit state could not be fully restored."
        return ok, message
    if write_config:
        try:
            write_user_env(
                {INSTRUCTION_MONITOR_ENABLED_ENV: "1" if enabled else "0"},
                path=env_path,
            )
        except (OSError, ValueError) as exc:
            rollback_ok = _restore_user_timer_state(
                prior_state,
                timer=INSTRUCTION_MONITOR_TIMER,
                service=INSTRUCTION_MONITOR_SERVICE,
                runner=runner,
            )
            rollback = "" if rollback_ok else " The prior user-unit state could not be fully restored."
            return False, f"Instruction Guard config could not be written: {exc}.{rollback}"
    return ok, message


def set_instruction_ai_enabled(
    enabled: bool,
    *,
    runner: Callable = subprocess.run,
    env_path: Optional[Path] = None,
    env: Optional[Mapping[str, str]] = None,
    write_config: bool = True,
) -> Tuple[bool, str]:
    if enabled:
        provider = resolve_ai_config(env)
        if not provider.ready:
            return False, "Agent Instruction Guard AI requires a ready configured AI provider."
    prior_state = None
    if write_config:
        prior_state = _capture_user_timer_state(
            timer=INSTRUCTION_ASSISTANT_TIMER,
            service=INSTRUCTION_ASSISTANT_SERVICE,
            runner=runner,
        )
        if prior_state is None:
            return False, "Could not safely capture the AI assistant's prior user-unit state."
    ok, message = _configure_user_timer(
        enabled,
        timer=INSTRUCTION_ASSISTANT_TIMER,
        service=INSTRUCTION_ASSISTANT_SERVICE,
        label="Agent Instruction Guard AI assistant",
        runner=runner,
    )
    if not ok:
        if prior_state is not None and not _restore_user_timer_state(
            prior_state,
            timer=INSTRUCTION_ASSISTANT_TIMER,
            service=INSTRUCTION_ASSISTANT_SERVICE,
            runner=runner,
        ):
            message += " The prior user-unit state could not be fully restored."
        return ok, message
    if write_config:
        try:
            write_user_env(
                {INSTRUCTION_AI_ENABLED_ENV: "1" if enabled else "0"},
                path=env_path,
            )
        except (OSError, ValueError) as exc:
            rollback_ok = _restore_user_timer_state(
                prior_state,
                timer=INSTRUCTION_ASSISTANT_TIMER,
                service=INSTRUCTION_ASSISTANT_SERVICE,
                runner=runner,
            )
            rollback = "" if rollback_ok else " The prior user-unit state could not be fully restored."
            return False, f"Instruction Guard AI config could not be written: {exc}.{rollback}"
    return ok, message


def _default_root(env: Optional[Mapping[str, str]] = None) -> Path:
    source = os.environ if env is None else env
    return Path(source.get("HOME") or str(Path.home()))


def _confirm(prompt: str, *, input_func: Callable[[str], str]) -> bool:
    try:
        answer = input_func(f"{prompt} [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    return answer in {"y", "yes"}


def build_instruction_audit_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aurascan instruction-audit",
        description="Audit AI-agent instruction and skill files without executing them.",
    )
    parser.add_argument("--root", type=Path, help="scan an explicitly selected root instead of HOME")
    parser.add_argument("--all-markdown", action="store_true", help="also analyze other Markdown files without baselining them")
    parser.add_argument("--json", action="store_true", dest="json_mode", help="emit structured JSON")
    ai = parser.add_mutually_exclusive_group()
    ai.add_argument("--no-ai", action="store_true", help="perform deterministic analysis only")
    ai.add_argument("--ai", action="store_true", help="perform one explicitly requested raise-only AI review")
    parser.add_argument("--review", nargs="?", const="", metavar="REPORT_ID", help="review the latest or selected report")
    parser.add_argument("--approve", metavar="FILE_ID", help="approve an unchanged file from the latest report")
    parser.add_argument("--disable", metavar="FILE_ID", help="disable an eligible unchanged standalone instruction file")
    parser.add_argument("--restore", metavar="ACTION_ID", help="restore an unchanged file disabled by AuraScan")
    parser.add_argument("--yes", action="store_true", help="confirm an eligible disable or restore action non-interactively")
    parser.add_argument("--status", action="store_true", help="show monitor, AI consent, service, and review status")
    monitor = parser.add_mutually_exclusive_group()
    monitor.add_argument("--enable-monitor", action="store_true", help="opt in to login and five-minute deterministic scans")
    monitor.add_argument("--disable-monitor", action="store_true", help="disable periodic deterministic scans")
    assistant = parser.add_mutually_exclusive_group()
    assistant.add_argument("--enable-ai", action="store_true", help="opt in to separately scheduled raise-only AI analysis")
    assistant.add_argument("--disable-ai", action="store_true", help="disable background Instruction Guard AI analysis")
    parser.add_argument("--background-capture", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--background-assist", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--state-root", type=Path, help=argparse.SUPPRESS)
    return parser


def _print_json_or_text(payload: Mapping[str, object], *, json_mode: bool, stdout) -> None:
    if json_mode:
        print(json.dumps(dict(payload), indent=2, sort_keys=True), file=stdout)
        return
    for key, value in payload.items():
        print(f"{key.replace('_', ' ').capitalize()}: {value}", file=stdout)


def _provider_reviewer(
    env: Optional[Mapping[str, str]],
    *,
    urlopen: Optional[Callable],
    explicit_one_shot: bool = False,
):
    config = resolve_ai_config(env)
    if explicit_one_shot and config.supported and config.authentication_ready:
        config.enabled = True
    if not config.ready:
        raise AIProviderError("a configured and enabled AI provider is required")

    def review(prompt: str) -> str:
        return call_ai_provider(config, prompt, timeout=30, urlopen=urlopen)

    return review


def _notify_generic(*, which: Callable, runner: Callable) -> bool:
    executable = which("notify-send")
    if not executable:
        return False
    try:
        result = runner(
            [
                executable,
                "AuraScan Agent Instruction Guard",
                "Agent file findings need review in AuraScan.",
            ],
            check=False,
            timeout=10,
        )
    except (OSError, TypeError, subprocess.SubprocessError):
        return False
    return int(getattr(result, "returncode", 1)) == 0


def _acknowledge_delivered_alerts(
    guard,
    *,
    state_root: Path,
    env: Mapping[str, str],
) -> int:
    """Suppress duplicate tray notifications without approving any file."""

    try:
        alerts = guard.pending_instruction_guard_alerts(
            state_root=state_root,
            env=env,
        )
    except (AttributeError, OSError, TypeError, ValueError):
        return 0
    if not isinstance(alerts, Sequence) or isinstance(alerts, (str, bytes)):
        return 0
    acknowledged = 0
    for alert in alerts[:1000]:
        if not isinstance(alert, Mapping):
            continue
        alert_id = str(alert.get("alert_id") or "")
        if not alert_id:
            continue
        try:
            guard.acknowledge_alert(
                alert_id,
                state_root=state_root,
                env=env,
            )
        except (AttributeError, OSError, TypeError, ValueError):
            continue
        acknowledged += 1
    return acknowledged


def run_instruction_audit(
    argv=None,
    *,
    stdout=None,
    stderr=None,
    env: Optional[Mapping[str, str]] = None,
    env_path: Optional[Path] = None,
    input_func: Callable[[str], str] = input,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
    urlopen: Optional[Callable] = None,
) -> int:
    """Run the public command. Scanner imports stay local for service isolation."""

    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    args = build_instruction_audit_parser().parse_args(argv)
    source_env = dict(os.environ if env is None else env)
    target_env = env_path or user_env_path()

    control_count = sum(bool(value) for value in (
        args.review is not None,
        args.approve,
        args.disable,
        args.restore,
        args.status,
        args.enable_monitor,
        args.disable_monitor,
        args.enable_ai,
        args.disable_ai,
        args.background_capture,
        args.background_assist,
    ))
    if control_count > 1:
        print("Choose only one Instruction Guard action at a time.", file=stderr)
        return EXIT_ERROR

    if args.enable_monitor or args.disable_monitor:
        ok, message = set_instruction_monitor_enabled(
            args.enable_monitor,
            runner=runner,
            env_path=target_env,
        )
        print(message, file=stdout if ok else stderr)
        return EXIT_CLEAR if ok else EXIT_ERROR

    if args.enable_ai or args.disable_ai:
        ok, message = set_instruction_ai_enabled(
            args.enable_ai,
            runner=runner,
            env_path=target_env,
            env=source_env,
        )
        print(message, file=stdout if ok else stderr)
        return EXIT_CLEAR if ok else EXIT_ERROR

    # The remaining implementation is kept below the core import so the
    # credential-free monitor process does not import provider transports until
    # it has already selected an offline action.
    from aurascan.core import instruction_guard as guard

    state_root = args.state_root or guard.default_instruction_guard_state_root(source_env)
    if args.status:
        preferences = read_instruction_guard_preferences(target_env)
        units = instruction_guard_unit_status(runner=runner)
        status = guard.instruction_guard_status(state_root=state_root, env=source_env)
        payload = {
            "monitor_enabled": preferences.monitor_enabled,
            "ai_enabled": preferences.ai_enabled,
            "scan_mode": preferences.scan_mode,
            "config_error": preferences.error,
        }
        payload.update(units)
        payload.update(status)
        _print_json_or_text(payload, json_mode=args.json_mode, stdout=stdout)
        if preferences.error or status.get("state") == "unavailable":
            return EXIT_ERROR
        if status.get("state") == "review_required":
            return EXIT_REVIEW
        return EXIT_CLEAR

    if args.review is not None:
        try:
            report = guard.review_report(args.review or None, state_root=state_root, env=source_env)
        except (OSError, ValueError) as exc:
            print(f"Could not load Instruction Guard report: {exc}", file=stderr)
            return EXIT_ERROR
        payload = report.to_dict() if hasattr(report, "to_dict") else dict(report)
        if args.json_mode:
            print(json.dumps(payload, indent=2, sort_keys=True), file=stdout)
        else:
            print(guard.render_instruction_report(report), file=stdout)
        return EXIT_REVIEW if payload.get("review_required") else EXIT_CLEAR

    if args.approve:
        try:
            result = guard.approve_candidate(args.approve, state_root=state_root, env=source_env)
        except (OSError, ValueError) as exc:
            print(f"Approval failed: {exc}", file=stderr)
            return EXIT_ERROR
        _print_json_or_text(result, json_mode=args.json_mode, stdout=stdout)
        return EXIT_CLEAR

    if args.disable:
        if not args.yes and not _confirm(
            "Disable this unchanged standalone instruction file? AuraScan will keep a restore receipt.",
            input_func=input_func,
        ):
            print("Disable cancelled.", file=stderr)
            return EXIT_ERROR
        try:
            result = guard.disable_candidate(args.disable, state_root=state_root, env=source_env)
        except (OSError, ValueError) as exc:
            print(f"Disable failed: {exc}", file=stderr)
            return EXIT_ERROR
        _print_json_or_text(result, json_mode=args.json_mode, stdout=stdout)
        return EXIT_CLEAR

    if args.restore:
        if not args.yes and not _confirm(
            "Restore this unchanged disabled file and return it to unreviewed state?",
            input_func=input_func,
        ):
            print("Restore cancelled.", file=stderr)
            return EXIT_ERROR
        try:
            result = guard.restore_disabled(args.restore, state_root=state_root, env=source_env)
        except (OSError, ValueError) as exc:
            print(f"Restore failed: {exc}", file=stderr)
            return EXIT_ERROR
        _print_json_or_text(result, json_mode=args.json_mode, stdout=stdout)
        return EXIT_CLEAR

    if args.background_assist:
        preferences = read_instruction_guard_preferences(target_env)
        if preferences.error:
            return EXIT_ERROR
        if not preferences.ai_enabled:
            return EXIT_CLEAR
        try:
            reviewer = _provider_reviewer(source_env, urlopen=urlopen)
            guard.process_one_ai_job(state_root=state_root, ai_reviewer=reviewer, env=source_env)
        except (AIProviderError, OSError, ValueError):
            # The private job retains bounded retry state. A provider outage is
            # not a deterministic monitor failure and never clears a finding.
            return EXIT_CLEAR
        return EXIT_CLEAR

    if args.background_capture:
        preferences = read_instruction_guard_preferences(target_env)
        if preferences.error:
            return EXIT_ERROR
        if not preferences.monitor_enabled:
            return EXIT_CLEAR
        root = args.root or _default_root(source_env)
        try:
            report = guard.scan_instruction_files(
                root,
                state_root=state_root,
                all_markdown=preferences.scan_mode == "all-markdown",
                ai_enabled=preferences.ai_enabled,
                ai_reviewer=None,
                background=True,
                env=source_env,
            )
        except (OSError, ValueError):
            return EXIT_ERROR
        if getattr(report, "new_alert_count", 0):
            if _notify_generic(which=which, runner=runner):
                _acknowledge_delivered_alerts(
                    guard,
                    state_root=state_root,
                    env=source_env,
                )
        return EXIT_CLEAR

    preferences = read_instruction_guard_preferences(target_env)
    if preferences.error:
        print(f"Instruction Guard configuration error: {preferences.error}", file=stderr)
        return EXIT_ERROR
    use_ai = bool(args.ai or (preferences.ai_enabled and not args.no_ai))
    reviewer = None
    if use_ai:
        try:
            reviewer = _provider_reviewer(
                source_env,
                urlopen=urlopen,
                explicit_one_shot=args.ai,
            )
        except AIProviderError as exc:
            print(f"Instruction Guard AI is unavailable: {exc}", file=stderr)
            return EXIT_ERROR
    root = args.root or _default_root(source_env)
    all_markdown = args.all_markdown or preferences.scan_mode == "all-markdown"
    try:
        report = guard.scan_instruction_files(
            root,
            state_root=state_root,
            all_markdown=all_markdown,
            ai_enabled=use_ai,
            ai_reviewer=reviewer,
            background=False,
            env=source_env,
        )
    except (OSError, ValueError) as exc:
        print(f"Instruction Guard scan failed: {exc}", file=stderr)
        return EXIT_ERROR
    payload = report.to_dict() if hasattr(report, "to_dict") else dict(report)
    if args.json_mode:
        print(json.dumps(payload, indent=2, sort_keys=True), file=stdout)
    else:
        print(guard.render_instruction_report(report), file=stdout)
    return EXIT_REVIEW if payload.get("review_required") else EXIT_CLEAR
