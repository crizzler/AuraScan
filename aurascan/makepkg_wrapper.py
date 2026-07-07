import os
import subprocess
import sys
import json
import hashlib
import io
import time
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Sequence, TextIO

from aurascan.analyzers.history import HistoryAnalyzer
from aurascan.core.engine import AuraScanEngine
from aurascan.core.review import (
    ReviewDecision,
    ReviewDecisionStatus,
    ReviewDecisionStore,
    annotate_report_for_review,
    build_scan_fingerprint,
    get_manual_review_acceptance_candidates,
    get_non_acceptance_blockers,
    validate_review_token,
)


EXIT_USAGE = 2
EXIT_SCAN_BLOCKED = 17
EXIT_MANUAL_REVIEW = 18
EXIT_REVIEW_NOT_FOUND = 19
EXIT_MAKEPKG_NOT_FOUND = 127
WRAPPER_VERSION = "1.0"

_BOOL_FLAGS = {
    "--aurascan-deep-static": "deep_static",
    "--aurascan-allow-user-asserted-update-context": "allow_user_asserted_update_context",
    "--aurascan-offline": "offline",
    "--aurascan-no-auto-key-fetch": "no_auto_key_fetch",
    "--aurascan-json": "json_output",
    "--aurascan-verbose": "verbose",
    "--aurascan-remember-review": "remember_review",
    "--aurascan-review-once": "review_once",
    "--aurascan-list-review-decisions": "list_review_decisions",
}

_VALUE_FLAGS = {
    "--aurascan-update-scan-policy": "update_scan_policy",
    "--aurascan-scan-context": "scan_context",
    "--aurascan-keyserver": "keyserver",
    "--aurascan-trusted-key-dir": "trusted_key_dirs",
    "--aurascan-accept-review": "accept_review",
    "--aurascan-review-reason": "review_reason",
    "--aurascan-review-db": "review_db_path",
    "--aurascan-revoke-review": "revoke_review",
    "--aurascan-review-package": "review_package",
    "--aurascan-review-status": "review_status",
    "--aurascan-review-expire-days": "review_expire_days",
}

_SCAN_CONTEXTS = {"auto", "install", "update", "dependency", "unknown"}
_UPDATE_POLICIES = {"full", "smart", "new-only"}
_REVIEW_STATUSES = {status.value for status in ReviewDecisionStatus} | {"used"}


class WrapperArgumentError(ValueError):
    pass


@dataclass
class MakepkgWrapperOptions:
    makepkg_args: List[str] = field(default_factory=list)
    deep_static: bool = False
    update_scan_policy: str = "full"
    scan_context: str = "auto"
    allow_user_asserted_update_context: bool = False
    offline: bool = False
    no_auto_key_fetch: bool = False
    keyserver: Optional[str] = None
    trusted_key_dirs: List[str] = field(default_factory=list)
    json_output: bool = False
    verbose: bool = False
    accept_review: str = ""
    review_reason: str = ""
    remember_review: bool = False
    review_once: bool = False
    review_db_path: str = ""
    list_review_decisions: bool = False
    revoke_review: str = ""
    review_package: str = ""
    review_status: str = ""
    review_expire_days: Optional[float] = None
    stripped_aurascan_args: List[str] = field(default_factory=list)


def main(argv: Optional[Sequence[str]] = None) -> int:
    return run(argv)


def run(
    argv: Optional[Sequence[str]] = None,
    *,
    cwd: Optional[Path] = None,
    engine_factory: Callable[..., AuraScanEngine] = AuraScanEngine,
    makepkg_locator: Callable[[], str] = None,
    subprocess_run: Callable[..., object] = subprocess.run,
    review_store: Optional[ReviewDecisionStore] = None,
    stdout: TextIO = None,
    stderr: TextIO = None,
) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    cwd_path = Path(cwd or os.getcwd())
    makepkg_locator = makepkg_locator or locate_real_makepkg
    raw_argv = list(argv if argv is not None else sys.argv[1:])
    json_requested = _argv_requests_json(raw_argv)

    try:
        options = parse_args(raw_argv)
    except WrapperArgumentError as exc:
        if json_requested:
            _emit_json(stdout, _wrapper_envelope(
                None,
                action="error",
                wrapper_exit_code=EXIT_USAGE,
                errors=[str(exc)],
            ))
        else:
            print(f"[AuraScan] {exc}", file=stderr)
        return EXIT_USAGE

    if options.list_review_decisions:
        return _handle_list_review_decisions(options, review_store, stdout, stderr)

    if options.revoke_review:
        return _handle_revoke_review(options, review_store, stdout, stderr)

    pkgbuild_path = cwd_path / "PKGBUILD"
    if not pkgbuild_path.is_file():
        error = "PKGBUILD not found in the current directory."
        if options.json_output:
            _emit_json(stdout, _wrapper_envelope(
                options,
                action="error",
                wrapper_exit_code=EXIT_USAGE,
                pkgbuild_path=str(pkgbuild_path),
                errors=[error],
            ))
        else:
            print(f"[AuraScan] {error}", file=stderr)
        return EXIT_USAGE

    engine = engine_factory(
        json_output=options.json_output,
        deep_static=options.deep_static,
        offline=options.offline,
        auto_key_fetch=not options.no_auto_key_fetch,
        keyserver=options.keyserver,
        trusted_key_dirs=options.trusted_key_dirs,
        verbose=options.verbose,
        update_scan_policy=options.update_scan_policy,
        scan_context=options.scan_context,
        scan_context_source=_scan_context_source(options.scan_context),
        allow_user_asserted_update_context=options.allow_user_asserted_update_context,
    )

    scan_warnings = []
    if options.json_output:
        captured_stdout = io.StringIO()
        captured_stderr = io.StringIO()
        with redirect_stdout(captured_stdout), redirect_stderr(captured_stderr):
            scan_ok = engine.scan_pkgbuild(str(pkgbuild_path))
        scan_warnings = _captured_lines(captured_stderr.getvalue())
    else:
        scan_ok = engine.scan_pkgbuild(str(pkgbuild_path))
    report = _report_from_engine(engine)
    risk = _risk_summary_from_engine(engine)
    blockers = get_non_acceptance_blockers(report)
    candidates = get_manual_review_acceptance_candidates(report)

    if not scan_ok or _risk_blocks(risk) or blockers:
        annotate_report_for_review(
            report,
            fingerprint=None,
            blockers=blockers,
            candidates=candidates,
            acceptance_status="hard_blocker",
        )
        if options.json_output:
            _emit_json(stdout, _wrapper_envelope(
                options,
                action="scan_blocked",
                wrapper_exit_code=EXIT_SCAN_BLOCKED,
                pkgbuild_path=str(pkgbuild_path),
                scan_report=report,
                makepkg_invoked=False,
                warnings=scan_warnings,
            ))
        else:
            if options.accept_review:
                _print_hard_blocker(stdout)
            else:
                _print_blocked(stdout)
        return EXIT_SCAN_BLOCKED

    if _risk_requires_review(risk):
        fingerprint = None
        if candidates:
            fingerprint = build_scan_fingerprint(
                report,
                pkgbuild_path,
                scanner_version=getattr(engine, "scanner_version", ""),
                rule_version=getattr(engine, "rule_version", ""),
                scan_config_hash=_scan_config_hash(options),
            )
        annotate_report_for_review(
            report,
            fingerprint=fingerprint,
            blockers=[],
            candidates=candidates,
            acceptance_status="review_required",
        )
        if not candidates:
            if options.json_output:
                _emit_json(stdout, _wrapper_envelope(
                    options,
                    action="manual_review_required",
                    wrapper_exit_code=EXIT_MANUAL_REVIEW,
                    pkgbuild_path=str(pkgbuild_path),
                    scan_report=report,
                    makepkg_invoked=False,
                    warnings=scan_warnings,
                ))
            else:
                _print_manual_review(stdout)
            return EXIT_MANUAL_REVIEW
        if not options.accept_review:
            if options.json_output:
                _emit_json(stdout, _wrapper_envelope(
                    options,
                    action="manual_review_required",
                    wrapper_exit_code=EXIT_MANUAL_REVIEW,
                    pkgbuild_path=str(pkgbuild_path),
                    scan_report=report,
                    makepkg_invoked=False,
                    warnings=scan_warnings,
                ))
            else:
                _print_manual_review_with_token(stdout, fingerprint.review_token)
            return EXIT_MANUAL_REVIEW

        store = _review_store(options, review_store, stderr, emit_error=not options.json_output)
        if store is None:
            report["acceptance_status"] = "review_store_unavailable"
            if options.json_output:
                _emit_json(stdout, _wrapper_envelope(
                    options,
                    action="error",
                    wrapper_exit_code=EXIT_MANUAL_REVIEW,
                    pkgbuild_path=str(pkgbuild_path),
                    scan_report=report,
                    makepkg_invoked=False,
                    errors=["Review decision storage is unavailable."],
                    warnings=scan_warnings,
                ))
            else:
                _print_invalid_review(stdout, "Review decision storage is unavailable.")
            return EXIT_MANUAL_REVIEW

        valid, status = validate_review_token(options.accept_review, fingerprint, store)
        if not valid:
            report["acceptance_status"] = status
            if options.json_output:
                _emit_json(stdout, _wrapper_envelope(
                    options,
                    action="manual_review_required",
                    wrapper_exit_code=EXIT_MANUAL_REVIEW,
                    pkgbuild_path=str(pkgbuild_path),
                    scan_report=report,
                    makepkg_invoked=False,
                    errors=[status],
                    warnings=scan_warnings,
                ))
            else:
                _print_invalid_review(stdout, status)
            return EXIT_MANUAL_REVIEW

        decision = store.record_acceptance(
            fingerprint,
            reason=options.review_reason,
            remember=options.remember_review and not options.review_once,
            expires_at=_review_expires_at(options),
        )
        annotate_report_for_review(
            report,
            fingerprint=fingerprint,
            blockers=[],
            candidates=candidates,
            acceptance_status=decision.decision_status.value,
            decision_id=decision.decision_id,
        )
        _record_manual_review_acceptance(engine, pkgbuild_path, decision.decision_id)
        if not options.json_output:
            _print_review_accepted(stdout)
    else:
        decision = None

    if not options.json_output:
        _print_passed(stdout)
    makepkg_path = makepkg_locator()
    if not makepkg_path:
        error = "Could not locate a real makepkg executable in PATH."
        if options.json_output:
            _emit_json(stdout, _wrapper_envelope(
                options,
                action="error",
                wrapper_exit_code=EXIT_MAKEPKG_NOT_FOUND,
                pkgbuild_path=str(pkgbuild_path),
                scan_report=report,
                makepkg_invoked=False,
                errors=[error],
                warnings=scan_warnings,
            ))
        else:
            print(f"[AuraScan] {error}", file=stderr)
        return EXIT_MAKEPKG_NOT_FOUND

    result = subprocess_run([makepkg_path] + options.makepkg_args, cwd=str(cwd_path), check=False)
    makepkg_exit_code = int(getattr(result, "returncode", 0))
    if options.json_output:
        if makepkg_exit_code != 0:
            action = "makepkg_failed"
        elif decision is not None:
            action = "review_accepted"
        else:
            action = "makepkg_invoked"
        _emit_json(stdout, _wrapper_envelope(
            options,
            action=action,
            wrapper_exit_code=makepkg_exit_code,
            pkgbuild_path=str(pkgbuild_path),
            scan_report=report,
            makepkg_invoked=True,
            makepkg_exit_code=makepkg_exit_code,
            review_decision=decision,
            warnings=scan_warnings,
        ))
    return makepkg_exit_code


def parse_args(argv: List[str]) -> MakepkgWrapperOptions:
    options = MakepkgWrapperOptions()
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--":
            options.makepkg_args.extend(argv[i + 1:])
            break

        key, value = _split_equals(arg)
        if key in _BOOL_FLAGS:
            setattr(options, _BOOL_FLAGS[key], True)
            options.stripped_aurascan_args.append(arg)
            i += 1
            continue
        if key in _VALUE_FLAGS:
            stripped = [arg]
            if value is None:
                i += 1
                if i >= len(argv):
                    raise WrapperArgumentError(f"{key} requires a value")
                value = argv[i]
                stripped.append(value)
            _set_value_option(options, key, value)
            options.stripped_aurascan_args.extend(stripped)
            i += 1
            continue

        options.makepkg_args.append(arg)
        i += 1

    if options.scan_context not in _SCAN_CONTEXTS:
        raise WrapperArgumentError("--aurascan-scan-context must be one of auto, install, update, dependency, unknown")
    if options.update_scan_policy not in _UPDATE_POLICIES:
        raise WrapperArgumentError("--aurascan-update-scan-policy must be one of full, smart, new-only")
    if options.review_status and options.review_status not in _REVIEW_STATUSES:
        raise WrapperArgumentError(
            "--aurascan-review-status must be one of accepted_once, accepted_persistent_for_exact_scan, revoked, expired, used"
        )
    if options.review_once:
        options.remember_review = False
    return options


def locate_real_makepkg(current_executable: Optional[str] = None, path_env: Optional[str] = None) -> str:
    current = _realpath(current_executable or sys.argv[0])
    for directory in (path_env if path_env is not None else os.environ.get("PATH", "")).split(os.pathsep):
        if not directory:
            continue
        candidate = Path(directory) / "makepkg"
        if not candidate.is_file() or not os.access(candidate, os.X_OK):
            continue
        if _realpath(str(candidate)) == current:
            continue
        return str(candidate)
    return ""


def _handle_list_review_decisions(
    options: MakepkgWrapperOptions,
    review_store: Optional[ReviewDecisionStore],
    stdout: TextIO,
    stderr: TextIO,
) -> int:
    store = _review_store(options, review_store, stderr, emit_error=not options.json_output)
    if store is None:
        error = "Review decision storage is unavailable."
        if options.json_output:
            _emit_json(stdout, _wrapper_envelope(
                options,
                action="error",
                wrapper_exit_code=EXIT_USAGE,
                errors=[error],
            ))
        else:
            print(f"[AuraScan] {error}", file=stderr)
        return EXIT_USAGE
    decisions = store.list_decisions(
        package_name=options.review_package,
        status=options.review_status,
    )
    if options.json_output:
        _emit_json(stdout, _wrapper_envelope(
            options,
            action="review_listed",
            wrapper_exit_code=0,
            review_decisions=[
                _decision_to_json(decision, verbose=options.verbose)
                for decision in decisions
            ],
        ))
    else:
        _print_review_decision_list(stdout, decisions, verbose=options.verbose)
    return 0


def _handle_revoke_review(
    options: MakepkgWrapperOptions,
    review_store: Optional[ReviewDecisionStore],
    stdout: TextIO,
    stderr: TextIO,
) -> int:
    store = _review_store(options, review_store, stderr, emit_error=not options.json_output)
    if store is None:
        error = "Review decision storage is unavailable."
        if options.json_output:
            _emit_json(stdout, _wrapper_envelope(
                options,
                action="error",
                wrapper_exit_code=EXIT_USAGE,
                errors=[error],
            ))
        else:
            print(f"[AuraScan] {error}", file=stderr)
        return EXIT_USAGE
    revoked = store.revoke(options.revoke_review)
    if not revoked:
        error = f"Review decision not found: {options.revoke_review}"
        if options.json_output:
            _emit_json(stdout, _wrapper_envelope(
                options,
                action="error",
                wrapper_exit_code=EXIT_REVIEW_NOT_FOUND,
                review={
                    "accepted_decision_id": options.revoke_review,
                    "decision_status": "not_found",
                },
                errors=[error],
            ))
        else:
            _print_review_decision_not_found(stdout, options.revoke_review)
        return EXIT_REVIEW_NOT_FOUND
    decision = store.decision_by_id(options.revoke_review)
    if options.json_output:
        _emit_json(stdout, _wrapper_envelope(
            options,
            action="review_revoked",
            wrapper_exit_code=0,
            review={
                "accepted_decision_id": options.revoke_review,
                "decision_status": "revoked",
            },
            review_decision=decision,
        ))
    else:
        _print_review_revoked(stdout)
    return 0


def _set_value_option(options: MakepkgWrapperOptions, key: str, value: str) -> None:
    attr = _VALUE_FLAGS[key]
    if attr == "trusted_key_dirs":
        options.trusted_key_dirs.append(value)
    elif attr == "review_expire_days":
        try:
            days = float(value)
        except ValueError:
            raise WrapperArgumentError("--aurascan-review-expire-days must be a number")
        if days < 0:
            raise WrapperArgumentError("--aurascan-review-expire-days must be zero or greater")
        options.review_expire_days = days
    else:
        setattr(options, attr, value)


def _split_equals(arg: str):
    if "=" not in arg:
        return arg, None
    key, value = arg.split("=", 1)
    return key, value


def _scan_context_source(scan_context: str) -> str:
    if scan_context == "auto":
        return "local_package_db"
    if scan_context != "unknown":
        return "explicit_cli"
    return "unknown"


def _risk_summary_from_engine(engine) -> dict:
    report = _report_from_engine(engine)
    risk = report.get("risk_summary") or {}
    return risk if isinstance(risk, dict) else {}


def _report_from_engine(engine) -> dict:
    report = getattr(engine, "last_report", None)
    if not isinstance(report, dict):
        return {}
    return report


def _risk_blocks(risk: dict) -> bool:
    return bool(risk.get("blocks_installation")) or risk.get("action") == "BLOCKED"


def _risk_requires_review(risk: dict) -> bool:
    return bool(risk.get("requires_manual_review")) or risk.get("recommended_action") == "manual_review"


def _argv_requests_json(argv: Sequence[str]) -> bool:
    return any(arg == "--aurascan-json" for arg in argv)


def _captured_lines(text: str) -> List[str]:
    return [line.strip() for line in text.splitlines() if line.strip()]


def _emit_json(stream: TextIO, data: dict) -> None:
    print(json.dumps(data, indent=2, sort_keys=True), file=stream)


def _wrapper_envelope(
    options: Optional[MakepkgWrapperOptions],
    *,
    action: str,
    wrapper_exit_code: int,
    pkgbuild_path: str = "",
    scan_report: Optional[dict] = None,
    makepkg_invoked: bool = False,
    makepkg_exit_code: Optional[int] = None,
    review_decision: Optional[ReviewDecision] = None,
    review: Optional[dict] = None,
    review_decisions: Optional[List[dict]] = None,
    errors: Optional[List[str]] = None,
    warnings: Optional[List[str]] = None,
) -> dict:
    data = {
        "schema_version": "1.0",
        "wrapper": "aurascan-makepkg",
        "wrapper_version": WRAPPER_VERSION,
        "action": action,
        "makepkg_invoked": makepkg_invoked,
        "makepkg_exit_code": makepkg_exit_code,
        "wrapper_exit_code": wrapper_exit_code,
        "pkgbuild_path": pkgbuild_path,
        "makepkg_args": list(options.makepkg_args) if options else [],
        "stripped_aurascan_args": list(options.stripped_aurascan_args) if options else [],
        "review": review or _review_json_from_report(scan_report or {}, review_decision),
        "scan_report": scan_report,
        "errors": list(errors or []),
        "warnings": list(warnings or []),
    }
    if review_decisions is not None:
        data["review_decisions"] = review_decisions
    return data


def _review_json_from_report(report: dict, decision: Optional[ReviewDecision] = None) -> dict:
    return {
        "review_required": bool(report.get("review_acceptance_required")),
        "review_eligible": bool(report.get("review_acceptance_eligible")),
        "review_token": report.get("review_token", ""),
        "accepted_decision_id": report.get("review_decision_id", "") or (decision.decision_id if decision else ""),
        "acceptance_status": report.get("acceptance_status", ""),
        "non_acceptance_blockers": list(report.get("non_acceptance_blockers", [])),
        "accepted_finding_ids": list(report.get("accepted_finding_ids", [])),
        "decision_status": decision.decision_status.value if decision else report.get("acceptance_status", ""),
    }


def _decision_to_json(decision: ReviewDecision, *, verbose: bool = False) -> dict:
    data = decision.to_dict()
    data["effective_status"] = decision.effective_status()
    data["accepted_at_text"] = _format_timestamp(decision.accepted_at)
    data["used_at_text"] = _format_timestamp(decision.used_at)
    data["revoked_at_text"] = _format_timestamp(decision.revoked_at)
    data["expires_at_text"] = _format_timestamp(decision.expires_at)
    data["finding_count"] = len(decision.finding_ids)
    if not verbose:
        data.pop("finding_fingerprints", None)
        data.pop("scan_fingerprint", None)
        data.pop("pkgbuild_hash", None)
        data.pop("install_hook_hashes", None)
        data.pop("source_metadata_hash", None)
        data.pop("scan_config_hash", None)
    return data


def _format_timestamp(value: Optional[float]) -> str:
    if value is None:
        return ""
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S %z", time.localtime(float(value)))
    except (TypeError, ValueError, OSError):
        return ""


def _print_passed(stream: TextIO) -> None:
    print("AuraScan check passed", file=stream)
    print("AuraScan checked the PKGBUILD before makepkg runs.", file=stream)
    print("Recommended action: Continuing with makepkg.", file=stream)


def _print_blocked(stream: TextIO) -> None:
    print("AuraScan blocked makepkg", file=stream)
    print("AuraScan found a high-risk issue before package build commands were allowed to run.", file=stream)
    print("Why it matters: PKGBUILD build steps can execute commands during the build process, so blocking before makepkg runs protects the system.", file=stream)
    print("Recommended action: Review the findings before building this package.", file=stream)


def _print_manual_review(stream: TextIO) -> None:
    print("AuraScan needs review before makepkg", file=stream)
    print("AuraScan found something that is not confirmed malicious but deserves review before build commands run.", file=stream)
    print("Recommended action: Review the details. Continue only through a scoped review acceptance workflow if the finding is eligible.", file=stream)


def _print_manual_review_with_token(stream: TextIO, review_token: str) -> None:
    print("AuraScan needs review before makepkg", file=stream)
    print("AuraScan found something that is not confirmed malicious, but it deserves review before build commands run.", file=stream)
    print("Why it matters: PKGBUILD build steps can execute commands during the build process. AuraScan is stopping here so you can review the warning before makepkg runs.", file=stream)
    print("What AuraScan checked: AuraScan checked the PKGBUILD, install hooks, source metadata, history, and available static findings.", file=stream)
    print("What AuraScan did not prove: AuraScan did not prove this package is malicious. It found risk signals that need a decision.", file=stream)
    print("Recommended action: Review the findings. If you understand and accept the risk for this exact scan, rerun with the review acceptance token shown below.", file=stream)
    print(f"Review token: {review_token}", file=stream)
    print(f"Example: aurascan-makepkg --aurascan-accept-review {review_token} [makepkg args...]", file=stream)


def _print_invalid_review(stream: TextIO, reason: str) -> None:
    print("Review acceptance no longer matches this scan", file=stream)
    print("The package or findings changed since the review token was created.", file=stream)
    print("Why it matters: AuraScan only accepts review decisions for the exact scan they were created for.", file=stream)
    print(f"Reason: {reason}", file=stream)
    print("Recommended action: Review the new findings and create a new acceptance if appropriate.", file=stream)


def _print_hard_blocker(stream: TextIO) -> None:
    print("AuraScan cannot accept this review", file=stream)
    print("This scan contains a blocker that is not eligible for ordinary review acceptance.", file=stream)
    print("Why it matters: Some findings, such as checksum mismatches, invalid signatures, unsafe archives, or confirmed malware signatures, are treated as hard stops.", file=stream)
    print("Recommended action: Do not build this package unless you independently verify and fix the issue.", file=stream)


def _print_review_accepted(stream: TextIO) -> None:
    print("Review accepted for this scan", file=stream)
    print("AuraScan recorded your review decision for this exact scan and will continue with makepkg.", file=stream)
    print("Why it matters: The decision is tied to this package state and finding set. If the package changes, the acceptance will no longer apply.", file=stream)
    print("Recommended action: Continuing with makepkg.", file=stream)


def _print_review_decision_list(stream: TextIO, decisions: List[ReviewDecision], *, verbose: bool = False) -> None:
    print("Review decisions", file=stream)
    if not decisions:
        print("No local review decisions matched the selected filters.", file=stream)
        return
    for decision in decisions:
        mode = "one-time" if decision.one_time else "remembered exact scan"
        print("", file=stream)
        print(f"Decision ID: {decision.decision_id}", file=stream)
        print(f"Package: {decision.package_name} {decision.package_version}", file=stream)
        print(f"Status: {decision.effective_status()}", file=stream)
        print(f"Scope: {decision.acceptance_scope.value}", file=stream)
        print(f"Accepted: {_format_timestamp(decision.accepted_at)}", file=stream)
        if decision.used_at is not None:
            print(f"Used: {_format_timestamp(decision.used_at)}", file=stream)
        if decision.revoked_at is not None:
            print(f"Revoked: {_format_timestamp(decision.revoked_at)}", file=stream)
        if decision.expires_at is not None:
            print(f"Expires: {_format_timestamp(decision.expires_at)}", file=stream)
        print(f"Mode: {mode}", file=stream)
        if decision.reason:
            print(f"Reason: {decision.reason[:160]}", file=stream)
        print(f"Findings: {len(decision.finding_ids)} stored finding(s)", file=stream)
        if verbose:
            print(f"Scan fingerprint: {decision.scan_fingerprint}", file=stream)
            print(f"Finding IDs: {', '.join(decision.finding_ids)}", file=stream)


def _print_review_revoked(stream: TextIO) -> None:
    print("Review decision revoked", file=stream)
    print("AuraScan will no longer use this review decision for future makepkg runs.", file=stream)
    print("Why it matters: Revoking a decision prevents an old acceptance from being reused.", file=stream)
    print("Recommended action: No further action needed.", file=stream)


def _print_review_decision_not_found(stream: TextIO, decision_id: str) -> None:
    print("Review decision not found", file=stream)
    print(f"AuraScan could not find a local review decision with ID: {decision_id}", file=stream)
    print("Recommended action: List review decisions and check the decision ID.", file=stream)


def _scan_config_hash(options: MakepkgWrapperOptions) -> str:
    data = {
        "allow_user_asserted_update_context": options.allow_user_asserted_update_context,
        "deep_static": options.deep_static,
        "keyserver": options.keyserver or "",
        "no_auto_key_fetch": options.no_auto_key_fetch,
        "offline": options.offline,
        "scan_context": options.scan_context,
        "trusted_key_dirs": list(options.trusted_key_dirs),
        "update_scan_policy": options.update_scan_policy,
    }
    return json_hash(data)


def json_hash(data) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode("utf-8")).hexdigest()


def _review_expires_at(options: MakepkgWrapperOptions) -> Optional[float]:
    if options.review_expire_days is None:
        return None
    return time.time() + (options.review_expire_days * 86400)


def _review_store(
    options: MakepkgWrapperOptions,
    review_store: Optional[ReviewDecisionStore],
    stderr: TextIO,
    *,
    emit_error: bool = True,
):
    if review_store is not None:
        return review_store
    try:
        return ReviewDecisionStore(Path(options.review_db_path) if options.review_db_path else None)
    except Exception as exc:
        if emit_error:
            print(f"[AuraScan] Review decision store unavailable: {exc}", file=stderr)
        return None


def _record_manual_review_acceptance(engine, pkgbuild_path: Path, review_decision_id: str) -> None:
    try:
        content = pkgbuild_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    report = _report_from_engine(engine)
    trust_diff = None
    decision = report.get("fast_path_decision") or {}
    technical = decision.get("technical_details") if isinstance(decision, dict) else {}
    if isinstance(technical, dict):
        trust_diff = technical.get("trust_boundary_diff")
    for analyzer in getattr(engine, "analyzers", []):
        if isinstance(analyzer, HistoryAnalyzer):
            analyzer.record_manual_review_accepted(
                str(pkgbuild_path),
                content,
                review_decision_id=review_decision_id,
                scanner_version=getattr(engine, "scanner_version", ""),
                rule_version=getattr(engine, "rule_version", ""),
                trust_diff=trust_diff,
            )


def _realpath(path: str) -> str:
    try:
        return str(Path(path).resolve())
    except OSError:
        return str(Path(path).absolute())


if __name__ == "__main__":
    sys.exit(main())
