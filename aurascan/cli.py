import argparse
import os
from pathlib import Path
import sys
from typing import Callable, List, Optional

from aurascan.analyzers.deterministic import DeterministicAnalyzer
from aurascan.core.agent import run_agent, run_agent_escalation
from aurascan.core.config import load_env, user_env_path
from aurascan.core.config_drift import (
    build_config_drift_runtime,
    prepare_config_drift_remediation,
    run_config_drift,
)
from aurascan.core.engine import AuraScanEngine
from aurascan.core.finding_explainer import scan_explanation_lines
from aurascan.core.followup import run_ask
from aurascan.core.incident_followup import (
    build_incident_followup_runtime,
    load_incident_followup_context,
)
from aurascan.core.incident_cli import run_incident_command
from aurascan.core.instruction_cli import run_instruction_audit
from aurascan.core.package_archive import (
    PACKAGE_IDENTITY_RESOLVED,
    PackageIdentityCapture,
    capture_package_identity,
)
from aurascan.core.pacman_sync_db import (
    OfficialPackageIndex,
    load_official_package_index,
    package_matches_official,
)
from aurascan.core.recovery_cli import run_recovery
from aurascan.core.security_audit import run_security_audit
from aurascan.core.upgrade_followup import build_upgrade_runtime
from aurascan.core.upgrade_preflight import refresh_upgrade_preflight, run_upgrade
from aurascan.core.updater_tray import run_updater
from aurascan.setup_wizard import run_doctor, run_init


OFFLINE_INCIDENT_SERVICE_FLAGS = {
    "--capture-monitor",
    "--capture-maintenance",
    "--capture-safe-autopilot",
    "--safe-autopilot-enabled",
    "--set-auto-repair-policy",
    "--apply-request",
}

OFFLINE_AGENT_HELPER_FLAGS = {
    "--set-root-policy",
    "--issue-root-session",
    "--execute-request",
    "--revoke-root-session",
}


def run_aur_update_wrapper(makepkg_args, cwd, stdout, stderr):
    """Run one guided AUR update step through the aurascan-makepkg wrapper.

    The guided flow in ``aurascan.core.aur_update_review`` orchestrates the
    download, consent prompts and verification, but core modules must not
    import the makepkg wrapper (a UI entry point). The CLI supplies this
    operation and normalizes the wrapper's exit status; every scan, blocking,
    review-token and makepkg handoff decision stays inside the wrapper.
    """

    from aurascan import makepkg_wrapper
    from aurascan.core.aur_update_review import (
        WRAPPER_RESULT_BLOCKED,
        WRAPPER_RESULT_FAILED,
        WRAPPER_RESULT_OK,
        WRAPPER_RESULT_REVIEW_REQUIRED,
        WRAPPER_RESULT_TOOL_UNAVAILABLE,
    )

    sandbox_config = None
    if "--aurascan-sandbox" in makepkg_args:
        from aurascan.core.build_sandbox import SandboxConfig, resolve_sandbox_config

        configured = resolve_sandbox_config(os.environ)
        sandbox_config = SandboxConfig(
            backend="devtools",
            work_root=configured.work_root,
            timeout_seconds=configured.timeout_seconds,
        )

    try:
        code = makepkg_wrapper.run(
            list(makepkg_args),
            cwd=Path(cwd),
            stdout=stdout,
            stderr=stderr,
            sudo_invalidator=makepkg_wrapper.invalidate_cached_sudo,
            sandbox_config=sandbox_config,
        )
    except Exception:  # bounded: a failed guided step must not abort the upgrade flow
        return WRAPPER_RESULT_FAILED
    if code == 0:
        return WRAPPER_RESULT_OK
    if code == makepkg_wrapper.EXIT_SCAN_BLOCKED:
        return WRAPPER_RESULT_BLOCKED
    if code == makepkg_wrapper.EXIT_MANUAL_REVIEW:
        return WRAPPER_RESULT_REVIEW_REQUIRED
    if code in {
        makepkg_wrapper.EXIT_MAKEPKG_NOT_FOUND,
        makepkg_wrapper.EXIT_SANDBOX_UNAVAILABLE,
    }:
        return WRAPPER_RESULT_TOOL_UNAVAILABLE
    return WRAPPER_RESULT_FAILED


def load_command_environment(raw_argv: List[str]) -> None:
    if raw_argv and raw_argv[0] == "intelligence":
        return
    if raw_argv and raw_argv[0] == "evidence":
        return
    if raw_argv and raw_argv[0] == "recovery":
        recovery_args = set(raw_argv[1:])
        if recovery_args & {"--runtime", "--refresh-from-hook"}:
            return
    if raw_argv and raw_argv[0] == "incidents":
        incident_args = set(raw_argv[1:])
        if "--background-assist" in incident_args:
            load_env(paths=[user_env_path()])
            return
        if incident_args & OFFLINE_INCIDENT_SERVICE_FLAGS:
            return
    if raw_argv and raw_argv[0] == "agent":
        if set(raw_argv[1:]) & OFFLINE_AGENT_HELPER_FLAGS:
            return
    if raw_argv and raw_argv[0] == "instruction-audit":
        instruction_args = set(raw_argv[1:])
        if "--background-assist" in instruction_args:
            load_env(paths=[user_env_path()])
            return
        if "--background-capture" in instruction_args:
            return
    load_env()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aurascan",
        description="Scan Arch-family/AUR package metadata, PKGBUILDs, and package archives.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Setup commands:\n"
            "  aurascan init      First-run configuration wizard.\n"
            "  aurascan doctor    Local diagnostics for config, tools, AI, and hooks.\n\n"
            "Upgrade command:\n"
            "  aurascan upgrade   Preflight a system upgrade, then hand off to pacman/paru/yay/shelly.\n\n"
            "Maintenance command:\n"
            "  aurascan config-drift   Resolve .pacnew/.pacsave configuration drift with backups.\n\n"
            "Recovery command:\n"
            "  aurascan incidents  Diagnose crashes and prepare guarded system repairs.\n"
            "  aurascan recovery   Manage or enter the optional boot recovery environment.\n\n"
            "Security command:\n"
            "  aurascan security-audit  Check known AUR campaigns and official package advisories.\n\n"
            "  aurascan intelligence  Inspect or explicitly update signed intelligence.\n\n"
            "Agent file security command:\n"
            "  aurascan instruction-audit  Audit AI-agent control files without executing them.\n\n"
            "Research evidence command:\n"
            "  aurascan evidence   Inspect consent-gated review adjudications and export candidates.\n\n"
            "Follow-up command:\n"
            "  aurascan ask        Ask AI about the latest retained AuraScan result.\n\n"
            "Repair agent command:\n"
            "  aurascan agent      Open the foreground contextual repair agent.\n\n"
            "Desktop command:\n"
            "  aurascan updater   Run or configure the AuraScan Updater tray applet.\n\n"
            "Pacman hook mode: when no --pkg or --pkgbuild is supplied, AuraScan "
            "reads pacman NeedsTargets from stdin and scans package archives. This "
            "mode is conservative, does not prove update context for smart fast "
            "paths, and is not a replacement for aurascan-makepkg build-time protection."
        ),
    )
    parser.add_argument("--json", action="store_true", dest="json_mode", help="emit a structured JSON report")
    parser.add_argument("--verbose", action="store_true", help="show technical finding details in terminal output")
    parser.add_argument("--deep-static", action="store_true", help="safely inspect local declared source archives without executing package code")
    parser.add_argument("--offline", action="store_true", help="disable network acquisition in explicit deep static flows")
    parser.add_argument("--no-auto-key-fetch", action="store_true", help="do not automatically fetch public keys for detached signature verification")
    parser.add_argument("--keyserver", help="HKPS keyserver URL for public-key lookup by full fingerprint")
    parser.add_argument("--trusted-key-dir", action="append", default=[], help="directory containing explicitly trusted public keys")
    parser.add_argument(
        "--update-scan-policy",
        choices=["full", "smart", "new-only"],
        default="full",
        help="update scan policy scaffold; runtime scans remain conservative unless AuraScan has reliable update context",
    )
    parser.add_argument(
        "--scan-context",
        choices=["install", "update", "dependency", "unknown", "auto"],
        default="unknown",
        help="scan context for controlled integrations; auto checks the local package DB, default unknown uses the normal conservative scan path",
    )
    parser.add_argument(
        "--allow-user-asserted-update-context",
        action="store_true",
        help="allow manually supplied --scan-context update to participate in smart/new-only update decisions",
    )
    target = parser.add_mutually_exclusive_group()
    target.add_argument("--pkgbuild", help="scan a PKGBUILD file")
    target.add_argument("--pkg", help="scan a package archive")
    return parser


def _scan_context_source(scan_context: str) -> str:
    if scan_context == "auto":
        return "local_package_db"
    if scan_context != "unknown":
        return "explicit_cli"
    return "unknown"


def read_pacman_hook_targets(stream) -> List[str]:
    return stream.read().splitlines()


def _hook_scan_identity_matches(
    archive: Path,
    target: str,
    identity_capture: Callable[[Path], PackageIdentityCapture],
) -> bool:
    """Return True when the archive's own metadata proves it is ``target``.

    A bare file-name match is not enough: the package cache is user-writable,
    so a same-prefix decoy or a stale corrupted archive could otherwise shadow
    the package pacman is about to install.  Entries whose identity cannot be
    proven are skipped rather than scanned or trusted.
    """

    try:
        captured = identity_capture(archive)
    except (OSError, ValueError):
        return False
    if captured.status != PACKAGE_IDENTITY_RESOLVED:
        return False
    return captured.name == target


def resolve_pacman_hook_target(
    target: str,
    cache_dir: Path = Path("/var/cache/pacman/pkg"),
    identity_capture: Optional[Callable[[Path], PackageIdentityCapture]] = None,
) -> str:
    if os.path.exists(target):
        return target
    capture = identity_capture or capture_package_identity
    matches = [
        path
        for path in cache_dir.glob(f"{target}-*.pkg.tar.zst")
        if _hook_scan_identity_matches(path, target, capture)
    ]
    if not matches:
        return ""
    try:
        return str(max(matches, key=lambda path: path.stat().st_mtime))
    except OSError:
        return ""


def scan_pacman_hook_targets(
    engine: AuraScanEngine,
    targets: List[str],
    *,
    cache_dir: Path = Path("/var/cache/pacman/pkg"),
    stderr=None,
    stdout=None,
    identity_capture: Optional[Callable[[Path], PackageIdentityCapture]] = None,
    official_index: Optional[OfficialPackageIndex] = None,
) -> bool:
    stderr = stderr or sys.stderr
    stdout = stdout or sys.stdout
    failed = False
    official_count = 0
    local_count = 0
    blocked = []
    if official_index is not None and not official_index.complete:
        print(
            f"[AuraScan] Warning: the official package index is incomplete "
            f"({official_index.reason}); unknown archives receive the full scan.",
            file=stderr,
        )
    for target in targets:
        resolved = resolve_pacman_hook_target(
            target, cache_dir=cache_dir, identity_capture=identity_capture
        )
        if not resolved:
            print(f"[AuraScan] Warning: Could not locate package file for {target}", file=stderr)
            continue
        if resolved != target:
            print(
                f"[AuraScan] Note: auditing cached archive {resolved}; "
                "this may not be the archive pacman is about to install",
                file=stderr,
            )
        official = bool(
            official_index is not None
            and package_matches_official(Path(resolved), official_index)
        )
        if official:
            deterministic = [
                analyzer
                for analyzer in getattr(engine, "analyzers", [])
                if isinstance(analyzer, DeterministicAnalyzer)
            ]
            ok = engine.scan_package(
                resolved,
                analyzers=deterministic,
                official_repo=True,
                quiet=True,
            )
            official_count += 1
        else:
            ok = engine.scan_package(resolved)
            local_count += 1
        if not ok:
            failed = True
            report = getattr(engine, "last_report", None)
            rules = []
            if isinstance(report, dict):
                for finding in report.get("findings", []):
                    if isinstance(finding, dict) and finding.get("blocks_installation"):
                        rule_id = finding.get("rule_id") or ""
                        if rule_id and rule_id not in rules:
                            rules.append(rule_id)
            reason = ", ".join(rules[:3]) if rules else "blocking finding"
            blocked.append(f"{target} ({reason})")
    print(
        f"[AuraScan] Transaction audit: {official_count} verified official package(s) "
        f"checked with the fast deterministic hook policy; {local_count} "
        "local/unknown package(s) received the full scan.",
        file=stdout,
    )
    if blocked:
        shown = ", ".join(blocked[:10])
        suffix = " ..." if len(blocked) > 10 else ""
        print(f"[AuraScan] Blocked package(s): {shown}{suffix}", file=stderr)
    return not failed


def print_scan_explanation(engine: AuraScanEngine, *, json_mode: bool) -> None:
    """Print the optional advisory explanation for the last interactive scan.

    JSON output must stay one parseable object, and a missing or disabled AI
    configuration prints nothing at all.  The deterministic report that the
    engine already printed remains the complete authority on the result.
    """

    if json_mode:
        return
    report = getattr(engine, "last_report", None)
    if not isinstance(report, dict):
        return
    for line in scan_explanation_lines(report):
        print(line)


def main(argv=None):
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    if raw_argv and raw_argv[0] == "intelligence":
        from aurascan.core.intelligence_cli import run_intelligence
        sys.exit(run_intelligence(raw_argv[1:]))
    if raw_argv and raw_argv[0] == "evidence":
        from aurascan.core.evidence_cli import run_evidence
        sys.exit(run_evidence(raw_argv[1:]))
    load_command_environment(raw_argv)
    if raw_argv and raw_argv[0] == "init":
        sys.exit(run_init(raw_argv[1:]))
    if raw_argv and raw_argv[0] == "doctor":
        sys.exit(run_doctor(raw_argv[1:]))
    if raw_argv and raw_argv[0] == "upgrade":
        sys.exit(run_upgrade(
            raw_argv[1:],
            agent_escalation_provider=run_agent_escalation,
            aur_update_wrapper=run_aur_update_wrapper,
        ))
    if raw_argv and raw_argv[0] == "config-drift":
        sys.exit(run_config_drift(raw_argv[1:], agent_escalation_provider=run_agent_escalation))
    if raw_argv and raw_argv[0] == "incidents":
        sys.exit(run_incident_command(raw_argv[1:]))
    if raw_argv and raw_argv[0] == "recovery":
        sys.exit(run_recovery(raw_argv[1:]))
    if raw_argv and raw_argv[0] == "security-audit":
        sys.exit(run_security_audit(raw_argv[1:]))
    if raw_argv and raw_argv[0] == "updater":
        sys.exit(run_updater(raw_argv[1:]))
    if raw_argv and raw_argv[0] == "ask":
        sys.exit(run_ask(
            raw_argv[1:],
            refresh_upgrade_report=refresh_upgrade_preflight,
            incident_context_provider=load_incident_followup_context,
            incident_runtime_provider=build_incident_followup_runtime,
            config_drift_runtime_provider=build_config_drift_runtime,
            config_drift_remediation_provider=prepare_config_drift_remediation,
            agent_escalation_provider=run_agent_escalation,
            upgrade_runtime_provider=build_upgrade_runtime,
        ))
    if raw_argv and raw_argv[0] == "agent":
        sys.exit(run_agent(
            raw_argv[1:],
            refresh_upgrade_report=refresh_upgrade_preflight,
            incident_context_provider=load_incident_followup_context,
            incident_runtime_provider=build_incident_followup_runtime,
            config_drift_runtime_provider=build_config_drift_runtime,
            config_drift_remediation_provider=prepare_config_drift_remediation,
            agent_escalation_provider=run_agent_escalation,
            upgrade_runtime_provider=build_upgrade_runtime,
        ))
    if raw_argv and raw_argv[0] == "instruction-audit":
        sys.exit(run_instruction_audit(raw_argv[1:]))

    args = build_parser().parse_args(raw_argv)
    engine = AuraScanEngine(
        json_output=args.json_mode,
        deep_static=args.deep_static,
        offline=args.offline,
        auto_key_fetch=not args.no_auto_key_fetch,
        keyserver=args.keyserver,
        trusted_key_dirs=args.trusted_key_dir,
        verbose=args.verbose,
        update_scan_policy=args.update_scan_policy,
        scan_context=args.scan_context,
        scan_context_source=_scan_context_source(args.scan_context),
        allow_user_asserted_update_context=args.allow_user_asserted_update_context,
    )

    if args.pkgbuild:
        scan_ok = engine.scan_pkgbuild(args.pkgbuild)
        print_scan_explanation(engine, json_mode=args.json_mode)
        if not scan_ok:
            sys.exit(1)
        return

    if args.pkg:
        scan_ok = engine.scan_package(args.pkg)
        print_scan_explanation(engine, json_mode=args.json_mode)
        if not scan_ok:
            sys.exit(1)
        return

    targets = read_pacman_hook_targets(sys.stdin)
    if not targets:
        return

    official_index = load_official_package_index()
    if not scan_pacman_hook_targets(engine, targets, official_index=official_index):
        print("\n[AuraScan] Transaction blocked due to security threats.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
