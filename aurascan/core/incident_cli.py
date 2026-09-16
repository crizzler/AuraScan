"""Incident command dispatch, including the automation control flags.

This is the presentation/entry layer for ``aurascan incidents``. It parses the
command line, handles the flags that *control other subsystems* (Safe Autopilot
policy, background-AI configuration, the privileged repair helper and the
background assistant), and otherwise delegates to
:func:`aurascan.core.incidents.run_incidents` for the incident workflow itself.

The split exists because the incident workflow module used to import the
automation and repair-execution modules purely to service command-line flags.
That made dependency direction ambiguous between two planner subsystems for no
reason: automation is a downstream policy and scheduling layer that consumes
incident vocabulary, not something the incident workflow needs to know about.

Privilege checks are preserved exactly as they were: each privileged branch still
verifies ``geteuid`` before doing anything, and the privileged repair helper
still validates its request file before execution.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable, Mapping, Optional, Sequence

from aurascan.core.config import read_env_file, user_env_path
from aurascan.core.incidents import (
    EXIT_INCIDENT_CONFIG_ERROR,
    EXIT_INCIDENT_REPAIR_FAILED,
    INCIDENT_SYSTEM_ROOT,
    build_incidents_parser,
    run_incidents,
    validate_privileged_request_file,
)


def run_incident_command(
    argv: Optional[Sequence[str]] = None,
    *,
    runner: Callable = subprocess.run,
    which: Callable[[str], Optional[str]] = shutil.which,
    input_func: Callable[[str], str] = input,
    stdout=None,
    stderr=None,
    env: Optional[Mapping[str, str]] = None,
    env_path: Optional[Path] = None,
    user_root: Optional[Path] = None,
    system_root: Path = INCIDENT_SYSTEM_ROOT,
    urlopen: Optional[Callable] = None,
    followup_context_root: Optional[Path] = None,
    followup_interactive: Optional[bool] = None,
) -> int:
    """Run the incident command line, dispatching subsystem-control flags first.

    Returns the process exit status. Flags that belong to the incident workflow
    itself are passed through to :func:`run_incidents` unchanged.
    """
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr

    args = build_incidents_parser().parse_args(list(argv or []))

    if args.set_auto_repair_policy:
        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            print("[AuraScan] Safe Autopilot policy writes require root privileges.", file=stderr)
            return EXIT_INCIDENT_CONFIG_ERROR
        from aurascan.core.incident_automation import write_auto_repair_policy

        ok, message = write_auto_repair_policy(str(args.set_auto_repair_policy))
        print(message, file=stdout if ok else stderr)
        return 0 if ok else EXIT_INCIDENT_CONFIG_ERROR
    if args.safe_autopilot_enabled:
        from aurascan.core.incident_automation import read_auto_repair_policy

        return 0 if read_auto_repair_policy().policy == "safe" else 1
    if args.apply_request:
        if not hasattr(os, "geteuid") or os.geteuid() != 0:
            print("[AuraScan] Privileged incident repair helper refused a non-root invocation.", file=stderr)
            return EXIT_INCIDENT_REPAIR_FAILED
        request_ok, request_error = validate_privileged_request_file(Path(args.apply_request))
        if not request_ok:
            print(f"[AuraScan] Privileged incident repair helper refused the request: {request_error}", file=stderr)
            return EXIT_INCIDENT_REPAIR_FAILED
        from aurascan.core.incident_repairs import execute_repair_request

        results, ok = execute_repair_request(
            Path(args.apply_request),
            runner=runner,
            which=which,
            repair_root=system_root / "repairs",
        )
        print(json.dumps({"ok": ok, "results": [result.to_dict() for result in results]}), file=stdout)
        return 0 if ok else EXIT_INCIDENT_REPAIR_FAILED

    effective_env = dict(os.environ if env is None else env)
    if env_path and env_path.exists():
        try:
            effective_env.update(read_env_file(env_path))
        except OSError:
            pass

    if args.enable_background_ai or args.disable_background_ai:
        from aurascan.core.incident_automation import set_background_ai_enabled

        enabled = bool(args.enable_background_ai and not args.disable_background_ai)
        ok, message = set_background_ai_enabled(enabled, runner=runner, env_path=env_path or user_env_path())
        print(message, file=stdout if ok else stderr)
        return 0 if ok else EXIT_INCIDENT_CONFIG_ERROR
    if args.auto_repair:
        from aurascan.core.incident_automation import configure_auto_repair_policy

        ok, message = configure_auto_repair_policy(str(args.auto_repair), runner=runner)
        print(message, file=stdout if ok else stderr)
        return 0 if ok else EXIT_INCIDENT_CONFIG_ERROR
    if args.background_ai_status:
        from aurascan.core.incident_automation import print_background_ai_status

        return print_background_ai_status(
            env=effective_env,
            runner=runner,
            user_root=user_root,
            stdout=stdout,
            json_output=bool(args.json_output),
        )
    if args.capture_safe_autopilot:
        from aurascan.core.incident_automation import run_safe_autopilot

        return run_safe_autopilot(
            system_root=system_root, runner=runner, which=which, stdout=stdout, stderr=stderr
        )
    if args.background_assist:
        from aurascan.core.incident_automation import run_background_assistant

        return run_background_assistant(
            env=effective_env,
            system_root=system_root,
            user_root=user_root,
            runner=runner,
            which=which,
            urlopen=urlopen,
            stdout=stdout,
            stderr=stderr,
        )

    return run_incidents(
        argv,
        runner=runner,
        which=which,
        input_func=input_func,
        stdout=stdout,
        stderr=stderr,
        env=env,
        env_path=env_path,
        user_root=user_root,
        system_root=system_root,
        urlopen=urlopen,
        followup_context_root=followup_context_root,
        followup_interactive=followup_interactive,
    )
