import argparse
import os
from pathlib import Path
import sys
from typing import List

from aurascan.core.config import load_env
from aurascan.core.config_drift import run_config_drift
from aurascan.core.engine import AuraScanEngine
from aurascan.core.upgrade_preflight import run_upgrade
from aurascan.core.updater_tray import run_updater
from aurascan.setup_wizard import run_doctor, run_init


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aurascan",
        description="Scan Arch/CachyOS/AUR package metadata, PKGBUILDs, and package archives.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Setup commands:\n"
            "  aurascan init      First-run configuration wizard.\n"
            "  aurascan doctor    Local diagnostics for config, tools, AI, and hooks.\n\n"
            "Upgrade command:\n"
            "  aurascan upgrade   Preflight a system upgrade, then hand off to pacman/paru/yay/shelly.\n\n"
            "Maintenance command:\n"
            "  aurascan config-drift   Resolve .pacnew/.pacsave configuration drift with backups.\n\n"
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


def resolve_pacman_hook_target(target: str, cache_dir: Path = Path("/var/cache/pacman/pkg")) -> str:
    if os.path.exists(target):
        return target
    matches = list(cache_dir.glob(f"{target}-*.pkg.tar.zst"))
    if not matches:
        return ""
    return str(max(matches, key=lambda path: path.stat().st_mtime))


def scan_pacman_hook_targets(engine: AuraScanEngine, targets: List[str], *, cache_dir: Path = Path("/var/cache/pacman/pkg"), stderr=None) -> bool:
    stderr = stderr or sys.stderr
    failed = False
    for target in targets:
        resolved = resolve_pacman_hook_target(target, cache_dir=cache_dir)
        if not resolved:
            print(f"[AuraScan] Warning: Could not locate package file for {target}", file=stderr)
            continue
        if not engine.scan_package(resolved):
            failed = True
    return not failed


def main(argv=None):
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    load_env()
    if raw_argv and raw_argv[0] == "init":
        sys.exit(run_init(raw_argv[1:]))
    if raw_argv and raw_argv[0] == "doctor":
        sys.exit(run_doctor(raw_argv[1:]))
    if raw_argv and raw_argv[0] == "upgrade":
        sys.exit(run_upgrade(raw_argv[1:]))
    if raw_argv and raw_argv[0] == "config-drift":
        sys.exit(run_config_drift(raw_argv[1:]))
    if raw_argv and raw_argv[0] == "updater":
        sys.exit(run_updater(raw_argv[1:]))

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
        if not engine.scan_pkgbuild(args.pkgbuild):
            sys.exit(1)
        return

    if args.pkg:
        if not engine.scan_package(args.pkg):
            sys.exit(1)
        return

    targets = read_pacman_hook_targets(sys.stdin)
    if not targets:
        return

    if not scan_pacman_hook_targets(engine, targets):
        print("\n[AuraScan] Transaction blocked due to security threats.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
