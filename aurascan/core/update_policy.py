from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence


class UpdateScanPolicy(Enum):
    full = "full"
    smart = "smart"
    new_only = "new-only"


class ScanContext(Enum):
    install = "install"
    update = "update"
    dependency = "dependency"
    unknown = "unknown"
    auto = "auto"


class ScanContextSource(Enum):
    explicit_cli = "explicit_cli"
    pacman_hook = "pacman_hook"
    makepkg_wrapper = "makepkg_wrapper"
    local_package_db = "local_package_db"
    test_fixture = "test_fixture"
    unknown = "unknown"


class UpdateFastPathAction(Enum):
    use_full_scan = "use_full_scan"
    use_smart_fast_path = "use_smart_fast_path"
    skip_update_scan = "skip_update_scan"
    cannot_fast_path = "cannot_fast_path"


FULL_SCAN_PHASES = [
    "deterministic_static",
    "history_diff",
    "source_metadata",
    "clamav_signature",
    "ai_review",
    "sandbox_runtime",
]

EXPENSIVE_PHASES = [
    "source_acquisition",
    "clamav_signature",
    "ai_review",
    "deep_static",
    "sandbox_runtime",
]

# These are normalized signals from cheap update-diff checks. A caller should
# only pass source/checksum churn here after deciding it is trust-relevant; a
# plain version bump on the same host with strong verification can remain clean.
TRUST_BOUNDARY_REASON_CODES = {
    "maintainer_changed",
    "orphan_adopted",
    "source_url_changed",
    "source_host_changed",
    "source_host_same_version_bump",
    "source_path_version_only_change",
    "checksum_value_changed",
    "checksum_changed_unexpectedly",
    "checksum_changed_with_version_bump",
    "checksum_changed_without_source_version_pattern",
    "checksum_algorithm_weakened",
    "checksum_became_skip",
    "checksum_added",
    "checksum_removed",
    "pgp_removed",
    "pgp_weakened",
    "validpgpkeys_changed",
    "validpgpkeys_removed",
    "signature_source_added",
    "signature_source_removed",
    "checksum_weakened",
    "install_hook_added",
    "install_hook_changed",
    "dependency_added",
    "dependency_removed",
    "dependency_replaced",
    "makedepends_changed",
    "checkdepends_changed",
    "optdepends_changed",
    "prepare_function_changed",
    "build_function_changed",
    "check_function_changed",
    "package_function_changed",
    "new_network_fetch",
    "new_network_fetch_pattern",
    "new_credential_path_reference",
    "new_credential_reference_pattern",
    "new_persistence_behavior",
    "new_persistence_pattern",
    "new_systemd_behavior",
    "new_cron_behavior",
    "new_suid_behavior",
    "new_suid_pattern",
    "previous_scan_manual_review",
    "metadata_changed_but_low_risk",
}


@dataclass
class UpdateScanState:
    policy: UpdateScanPolicy = UpdateScanPolicy.full
    context: ScanContext = ScanContext.unknown
    context_source: ScanContextSource = ScanContextSource.unknown
    already_installed: bool = False
    prior_baseline_exists: bool = False
    prior_baseline_accepted: bool = False
    previous_scan_blocked: bool = False
    previous_scan_required_manual_review: bool = False
    explicit_deep_static: bool = False
    cache_stale: bool = False
    scanner_or_rules_changed: bool = False
    trust_boundary_changes: List[str] = field(default_factory=list)
    trust_diff_result: Optional[Any] = None
    context_proof: Optional[Any] = None

    def __post_init__(self) -> None:
        self.policy = normalize_policy(self.policy)
        self.context = normalize_context(self.context)
        self.context_source = normalize_context_source(self.context_source)
        self.trust_boundary_changes = [
            str(item) for item in self.trust_boundary_changes if str(item)
        ]


@dataclass
class UpdateFastPathDecision:
    action: UpdateFastPathAction
    policy: UpdateScanPolicy
    scan_context: ScanContext
    scan_context_source: ScanContextSource
    reason_codes: List[str]
    title: str
    summary: str
    why_it_matters: str
    what_checked: str
    what_not_checked: str
    recommended_action: str
    technical_details: Dict[str, object]
    expensive_phases_skipped: bool
    skipped_phases: List[str]
    may_update_history_baseline: bool
    scan_level: str

    def __post_init__(self) -> None:
        self.action = normalize_action(self.action)
        self.policy = normalize_policy(self.policy)
        self.scan_context = normalize_context(self.scan_context)
        self.scan_context_source = normalize_context_source(self.scan_context_source)
        self.reason_codes = [str(item) for item in self.reason_codes]
        self.skipped_phases = [str(item) for item in self.skipped_phases]

    def to_dict(self) -> Dict[str, object]:
        return {
            "action": self.action.value,
            "policy": self.policy.value,
            "scan_context": self.scan_context.value,
            "scan_context_source": self.scan_context_source.value,
            "reason_codes": list(self.reason_codes),
            "title": self.title,
            "summary": self.summary,
            "why_it_matters": self.why_it_matters,
            "what_checked": self.what_checked,
            "what_not_checked": self.what_not_checked,
            "recommended_action": self.recommended_action,
            "technical_details": dict(self.technical_details),
            "expensive_phases_skipped": self.expensive_phases_skipped,
            "skipped_phases": list(self.skipped_phases),
            "may_update_history_baseline": self.may_update_history_baseline,
            "scan_level": self.scan_level,
        }


def normalize_policy(value: object) -> UpdateScanPolicy:
    if isinstance(value, UpdateScanPolicy):
        return value
    normalized = str(value).replace("_", "-")
    return UpdateScanPolicy(normalized)


def normalize_context(value: object) -> ScanContext:
    if isinstance(value, ScanContext):
        return value
    return ScanContext(str(value))


def normalize_context_source(value: object) -> ScanContextSource:
    if isinstance(value, ScanContextSource):
        return value
    return ScanContextSource(str(value))


def normalize_action(value: object) -> UpdateFastPathAction:
    if isinstance(value, UpdateFastPathAction):
        return value
    return UpdateFastPathAction(str(value))


def decide_update_fast_path(state: UpdateScanState) -> UpdateFastPathDecision:
    state = UpdateScanState(
        policy=state.policy,
        context=state.context,
        context_source=state.context_source,
        already_installed=state.already_installed,
        prior_baseline_exists=state.prior_baseline_exists,
        prior_baseline_accepted=state.prior_baseline_accepted,
        previous_scan_blocked=state.previous_scan_blocked,
        previous_scan_required_manual_review=state.previous_scan_required_manual_review,
        explicit_deep_static=state.explicit_deep_static,
        cache_stale=state.cache_stale,
        scanner_or_rules_changed=state.scanner_or_rules_changed,
        trust_boundary_changes=list(state.trust_boundary_changes),
        trust_diff_result=state.trust_diff_result,
        context_proof=state.context_proof,
    )

    if state.explicit_deep_static:
        return _full_scan(
            state,
            ["explicit_deep_static_requested"],
            "Full scan requested explicitly.",
            "The user requested deep source inspection, so AuraScan should not use an update fast path.",
        )

    if state.policy == UpdateScanPolicy.full:
        return _full_scan(
            state,
            ["policy_full"],
            "Full update scan selected.",
            "The selected policy runs the normal scan path for installs and updates.",
        )

    if state.context in (ScanContext.unknown, ScanContext.auto):
        return _cannot_fast_path(
            state,
            ["unknown_scan_context"],
            "Update fast path is not available.",
            "AuraScan does not have a reliable install/update context for this scan, so it should use the conservative full scan path.",
        )

    if state.policy == UpdateScanPolicy.new_only:
        return _decide_new_only(state)

    return _decide_smart(state)


def _decide_new_only(state: UpdateScanState) -> UpdateFastPathDecision:
    if state.context == ScanContext.update and state.already_installed and _context_fast_path_eligible(state):
        return _decision(
            state,
            UpdateFastPathAction.skip_update_scan,
            ["new_only_update_already_installed"],
            "Update scan skipped by new-only policy.",
            "This package is already installed, and the selected policy only scans newly introduced packages.",
            "This is a weaker protection mode. It can miss malicious changes added during an update.",
            "AuraScan checked that the runtime context was an update for an already installed package.",
            "AuraScan did not inspect changed PKGBUILD content, source metadata, source archives, signatures, or generated package contents for this update.",
            "Use --update-scan-policy full or smart for update coverage.",
            expensive_phases_skipped=True,
            skipped_phases=list(FULL_SCAN_PHASES) + ["source_acquisition", "deep_static"],
            may_update_history_baseline=False,
            scan_level="skipped_update",
        )

    return _full_scan(
        state,
        ["new_only_context_not_eligible"],
        "New package scan required.",
        "The new-only policy can skip updates only when update context is explicitly proven or deliberately allowed.",
    )


def _decide_smart(state: UpdateScanState) -> UpdateFastPathDecision:
    if state.context != ScanContext.update or not state.already_installed:
        return _full_scan(
            state,
            ["not_update_context"],
            "Full scan required for this context.",
            "Smart fast path only applies to updates of packages that are already installed.",
        )
    if not _context_fast_path_eligible(state):
        return _full_scan(
            state,
            ["context_not_eligible_for_fast_path"],
            "Update fast path not used.",
            "AuraScan could not prove this scan is a package update, so it used the normal scan.",
        )
    if not state.prior_baseline_exists or not state.prior_baseline_accepted:
        return _full_scan(
            state,
            ["missing_accepted_baseline"],
            "Full scan required before smart updates.",
            "AuraScan needs a previous accepted baseline before it can safely shorten update checks.",
        )
    if state.previous_scan_blocked:
        return _full_scan(
            state,
            ["previous_scan_blocked"],
            "Full scan required after a blocked scan.",
            "A package that previously blocked installation should not use a shortened update path.",
        )
    if state.previous_scan_required_manual_review:
        return _full_scan(
            state,
            ["previous_scan_required_manual_review"],
            "Full scan required after manual-review findings.",
            "A package that previously needed manual review should be scanned normally on the next update.",
        )
    if state.cache_stale:
        return _full_scan(
            state,
            ["cache_stale"],
            "Full scan required because scan state is stale.",
            "Smart fast path requires fresh local history and cache metadata.",
        )
    if state.scanner_or_rules_changed:
        return _full_scan(
            state,
            ["scanner_or_rules_changed"],
            "Full scan required after scanner or rule changes.",
            "A rule update may add checks that were not part of the previous accepted baseline.",
        )
    if state.trust_diff_result is not None:
        return _decision_from_trust_diff(state)
    trust_changes = normalized_trust_boundary_changes(state.trust_boundary_changes)
    if trust_changes:
        return _full_scan(
            state,
            ["trust_boundary_changed"] + trust_changes,
            "Full scan required because trust boundaries changed.",
            "Source locations, maintainers, verification settings, dependencies, or install behavior changed since the accepted baseline.",
        )

    return _decision(
        state,
        UpdateFastPathAction.use_smart_fast_path,
        ["accepted_baseline", "no_trust_boundary_changes"],
        "Smart update fast path selected.",
        "This update can use a shortened scan because it has an accepted baseline and no detected trust-boundary changes.",
        "This saves work while still requiring a full scan whenever trust boundaries move.",
        "AuraScan checked install/update context, prior baseline acceptance, previous scan outcome, scanner/rule freshness, and trust-boundary change signals.",
        "AuraScan did not run expensive deep source acquisition, ClamAV, AI review, or sandbox phases in this fast-path decision.",
        "Continue with normal package trust checks. Use --update-scan-policy full for maximum coverage.",
        expensive_phases_skipped=True,
        skipped_phases=list(EXPENSIVE_PHASES),
        may_update_history_baseline=False,
        scan_level="smart_fast_path",
    )


def _decision_from_trust_diff(state: UpdateScanState) -> UpdateFastPathDecision:
    diff = _trust_diff_to_dict(state.trust_diff_result)
    if not diff:
        return _full_scan(
            state,
            ["trust_diff_unreadable"],
            "Update needs normal scan.",
            "AuraScan could not read the trust-boundary diff result, so it should use the conservative full scan path.",
        )

    reason_codes = [str(item) for item in diff.get("reason_codes", []) if str(item)]
    if not reason_codes:
        reason_codes = ["trust_diff_result"]

    allow_fast_path = bool(diff.get("allow_smart_fast_path")) and not bool(diff.get("require_full_scan"))
    title = str(diff.get("user_title") or diff.get("title") or "Update fast path decision recorded.")
    summary = str(diff.get("user_summary") or diff.get("summary") or "")
    why = str(diff.get("why_it_matters") or "AuraScan used a local trust-boundary diff to decide whether smart update behavior is appropriate.")
    checked = str(diff.get("what_checked") or "AuraScan compared local package metadata against the previous accepted snapshot.")
    not_checked = str(diff.get("what_not_proved") or diff.get("what_not_checked") or "This does not prove the package is safe.")
    action_text = str(diff.get("recommended_action") or "Use the normal scan path if anything looks unexpected.")

    if allow_fast_path:
        decision = _decision(
            state,
            UpdateFastPathAction.use_smart_fast_path,
            reason_codes,
            title,
            summary,
            why,
            checked,
            not_checked,
            action_text,
            expensive_phases_skipped=True,
            skipped_phases=list(EXPENSIVE_PHASES),
            may_update_history_baseline=False,
            scan_level="smart_fast_path",
        )
    else:
        decision = _decision(
            state,
            UpdateFastPathAction.use_full_scan,
            reason_codes,
            title,
            summary,
            why,
            checked,
            not_checked,
            action_text,
            expensive_phases_skipped=False,
            skipped_phases=[],
            may_update_history_baseline=True,
            scan_level="full",
        )
    decision.technical_details["trust_boundary_diff"] = diff
    return decision


def _context_fast_path_eligible(state: UpdateScanState) -> bool:
    proof = _context_proof_to_dict(state.context_proof)
    return bool(proof.get("eligible_for_fast_path"))


def normalized_trust_boundary_changes(changes: Sequence[str]) -> List[str]:
    normalized = []
    for item in changes:
        value = str(item).strip()
        if not value:
            continue
        normalized.append(value)
    return sorted(set(normalized))


def _trust_diff_to_dict(value: object) -> Dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return dict(value)
    if hasattr(value, "to_dict"):
        data = value.to_dict()
        if isinstance(data, dict):
            return dict(data)
    return {}


def _context_proof_to_dict(value: object) -> Dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return dict(value)
    if hasattr(value, "to_dict"):
        data = value.to_dict()
        if isinstance(data, dict):
            return dict(data)
    return {}


def _full_scan(
    state: UpdateScanState,
    reason_codes: List[str],
    title: str,
    summary: str,
) -> UpdateFastPathDecision:
    return _decision(
        state,
        UpdateFastPathAction.use_full_scan,
        reason_codes,
        title,
        summary,
        "Full scanning preserves coverage when AuraScan cannot prove that a shortened update path is safe.",
        "AuraScan checked the selected update scan policy and available update context.",
        "No expensive phases were skipped by this decision.",
        "Run the normal scan and update history only if the result is accepted.",
        expensive_phases_skipped=False,
        skipped_phases=[],
        may_update_history_baseline=True,
        scan_level="full",
    )


def _cannot_fast_path(
    state: UpdateScanState,
    reason_codes: List[str],
    title: str,
    summary: str,
) -> UpdateFastPathDecision:
    decision = _full_scan(state, reason_codes, title, summary)
    decision.action = UpdateFastPathAction.cannot_fast_path
    decision.recommended_action = "Run the normal full scan. Do not infer update state from incomplete runtime context."
    return decision


def _decision(
    state: UpdateScanState,
    action: UpdateFastPathAction,
    reason_codes: List[str],
    title: str,
    summary: str,
    why_it_matters: str,
    what_checked: str,
    what_not_checked: str,
    recommended_action: str,
    *,
    expensive_phases_skipped: bool,
    skipped_phases: List[str],
    may_update_history_baseline: bool,
    scan_level: str,
) -> UpdateFastPathDecision:
    return UpdateFastPathDecision(
        action=action,
        policy=state.policy,
        scan_context=state.context,
        scan_context_source=state.context_source,
        reason_codes=reason_codes,
        title=title,
        summary=summary,
        why_it_matters=why_it_matters,
        what_checked=what_checked,
        what_not_checked=what_not_checked,
        recommended_action=recommended_action,
        technical_details={
            "already_installed": state.already_installed,
            "scan_context_source": state.context_source.value,
            "context_proof": _context_proof_to_dict(state.context_proof),
            "prior_baseline_exists": state.prior_baseline_exists,
            "prior_baseline_accepted": state.prior_baseline_accepted,
            "previous_scan_blocked": state.previous_scan_blocked,
            "previous_scan_required_manual_review": state.previous_scan_required_manual_review,
            "explicit_deep_static": state.explicit_deep_static,
            "cache_stale": state.cache_stale,
            "scanner_or_rules_changed": state.scanner_or_rules_changed,
            "trust_boundary_changes": normalized_trust_boundary_changes(state.trust_boundary_changes),
        },
        expensive_phases_skipped=expensive_phases_skipped,
        skipped_phases=skipped_phases,
        may_update_history_baseline=may_update_history_baseline,
        scan_level=scan_level,
    )
