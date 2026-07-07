from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple
from urllib.parse import unquote, urlparse

from aurascan.core.models import Severity


class TrustBoundaryClassification(Enum):
    no_relevant_change = "no_relevant_change"
    likely_normal_version_bump = "likely_normal_version_bump"
    metadata_changed_but_low_risk = "metadata_changed_but_low_risk"
    trust_boundary_changed = "trust_boundary_changed"
    verification_weakened = "verification_weakened"
    maintainer_or_ownership_changed = "maintainer_or_ownership_changed"
    source_location_changed = "source_location_changed"
    install_behavior_changed = "install_behavior_changed"
    dependency_trust_chain_changed = "dependency_trust_chain_changed"
    build_logic_changed = "build_logic_changed"
    insufficient_history = "insufficient_history"


FUNC_NAMES = ("prepare", "build", "check", "package")
CHECKSUM_STRENGTH = {
    "skip": 0,
    "md5": 1,
    "sha1": 2,
    "sha224": 3,
    "sha256": 4,
    "sha384": 5,
    "sha512": 6,
    "b2": 6,
    "blake2": 6,
    "blake2b": 6,
    "blake2s": 6,
}


@dataclass
class TrustBoundaryDiffInput:
    previous_snapshot: Optional[Mapping[str, Any]] = None
    current_snapshot: Optional[Mapping[str, Any]] = None
    package_name: str = ""
    previous_version: str = ""
    current_version: str = ""
    previous_maintainer: Optional[str] = None
    current_maintainer: Optional[str] = None
    previous_sources: Optional[Sequence[str]] = None
    current_sources: Optional[Sequence[str]] = None
    previous_source_hosts: Optional[Sequence[str]] = None
    current_source_hosts: Optional[Sequence[str]] = None
    previous_checksums: Optional[Sequence[str]] = None
    current_checksums: Optional[Sequence[str]] = None
    previous_checksum_algorithms: Optional[Sequence[str]] = None
    current_checksum_algorithms: Optional[Sequence[str]] = None
    previous_validpgpkeys: Optional[Sequence[str]] = None
    current_validpgpkeys: Optional[Sequence[str]] = None
    previous_dependencies: Optional[Sequence[str]] = None
    current_dependencies: Optional[Sequence[str]] = None
    previous_makedepends: Optional[Sequence[str]] = None
    current_makedepends: Optional[Sequence[str]] = None
    previous_checkdepends: Optional[Sequence[str]] = None
    current_checkdepends: Optional[Sequence[str]] = None
    previous_optdepends: Optional[Sequence[str]] = None
    current_optdepends: Optional[Sequence[str]] = None
    previous_install_hook_hash: str = ""
    current_install_hook_hash: str = ""
    previous_prepare_hash: str = ""
    current_prepare_hash: str = ""
    previous_build_hash: str = ""
    current_build_hash: str = ""
    previous_check_hash: str = ""
    current_check_hash: str = ""
    previous_package_hash: str = ""
    current_package_hash: str = ""
    previous_source_metadata_risk_summary: Optional[Mapping[str, Any]] = None
    current_source_metadata_risk_summary: Optional[Mapping[str, Any]] = None
    previous_scan_blocked: bool = False
    previous_scan_required_manual_review: bool = False
    scanner_or_rules_changed: bool = False
    cache_stale: bool = False


@dataclass
class TrustBoundaryDiffResult:
    classification: TrustBoundaryClassification
    allow_smart_fast_path: bool
    require_full_scan: bool
    requires_manual_review: bool
    severity: Severity
    reason_codes: List[str]
    user_title: str
    user_summary: str
    why_it_matters: str
    what_checked: str
    what_not_proved: str
    recommended_action: str
    technical_details: Dict[str, Any] = field(default_factory=dict)
    changed_fields: List[str] = field(default_factory=list)
    normal_churn_fields: List[str] = field(default_factory=list)
    suspicious_fields: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.classification = normalize_classification(self.classification)
        self.severity = Severity(self.severity.value if isinstance(self.severity, Severity) else self.severity)
        self.reason_codes = sorted(set(str(item) for item in self.reason_codes if str(item)))
        self.changed_fields = sorted(set(str(item) for item in self.changed_fields if str(item)))
        self.normal_churn_fields = sorted(set(str(item) for item in self.normal_churn_fields if str(item)))
        self.suspicious_fields = sorted(set(str(item) for item in self.suspicious_fields if str(item)))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "classification": self.classification.value,
            "allow_smart_fast_path": self.allow_smart_fast_path,
            "require_full_scan": self.require_full_scan,
            "requires_manual_review": self.requires_manual_review,
            "severity": self.severity.value,
            "reason_codes": list(self.reason_codes),
            "user_title": self.user_title,
            "user_summary": self.user_summary,
            "why_it_matters": self.why_it_matters,
            "what_checked": self.what_checked,
            "what_not_proved": self.what_not_proved,
            "recommended_action": self.recommended_action,
            "technical_details": dict(self.technical_details),
            "changed_fields": list(self.changed_fields),
            "normal_churn_fields": list(self.normal_churn_fields),
            "suspicious_fields": list(self.suspicious_fields),
        }


class HistoryTrustDiffAdapter:
    def build_input(
        self,
        previous_snapshot: Optional[Mapping[str, Any]],
        current_snapshot: Optional[Mapping[str, Any]],
        *,
        scanner_or_rules_changed: bool = False,
        cache_stale: bool = False,
    ) -> TrustBoundaryDiffInput:
        previous = dict(previous_snapshot or {})
        current = dict(current_snapshot or {})
        return TrustBoundaryDiffInput(
            previous_snapshot=previous or None,
            current_snapshot=current or None,
            package_name=str(current.get("package_name") or previous.get("package_name") or ""),
            previous_scan_blocked=bool(previous.get("blocked")) or previous.get("scan_status") == "blocked",
            previous_scan_required_manual_review=(
                bool(previous.get("required_manual_review"))
                and not bool(previous.get("manual_review_resolved"))
            ) or previous.get("scan_status") == "manual_review_required",
            scanner_or_rules_changed=scanner_or_rules_changed,
            cache_stale=cache_stale,
        )

    def classify(
        self,
        previous_snapshot: Optional[Mapping[str, Any]],
        current_snapshot: Optional[Mapping[str, Any]],
        *,
        scanner_or_rules_changed: bool = False,
        cache_stale: bool = False,
    ) -> TrustBoundaryDiffResult:
        return classify_trust_boundary_diff(
            self.build_input(
                previous_snapshot,
                current_snapshot,
                scanner_or_rules_changed=scanner_or_rules_changed,
                cache_stale=cache_stale,
            )
        )


def normalize_classification(value: object) -> TrustBoundaryClassification:
    if isinstance(value, TrustBoundaryClassification):
        return value
    return TrustBoundaryClassification(str(value))


def classify_trust_boundary_diff(diff_input: TrustBoundaryDiffInput) -> TrustBoundaryDiffResult:
    previous = dict(diff_input.previous_snapshot or {})
    current = dict(diff_input.current_snapshot or {})
    fields = _ResolvedFields.from_input(diff_input, previous, current)

    reason_codes: Set[str] = set()
    changed_fields: Set[str] = set()
    normal_churn_fields: Set[str] = set()
    suspicious_fields: Set[str] = set()
    technical_details: Dict[str, Any] = {
        "package_name": fields.package_name,
        "previous_version": fields.previous_version,
        "current_version": fields.current_version,
    }

    if not previous and not fields.has_previous_values:
        return _result(
            TrustBoundaryClassification.insufficient_history,
            Severity.MEDIUM,
            {"no_prior_baseline"},
            "Fast path blocked because no prior baseline exists.",
            "AuraScan does not have a previous accepted local scan to compare with this update.",
            "Smart update decisions need a trusted local baseline. Without one, AuraScan should use the normal scan path.",
            changed_fields=set(),
            normal_churn_fields=set(),
            suspicious_fields={"history"},
            technical_details=technical_details,
            manual_review=False,
        )

    if diff_input.previous_scan_blocked:
        reason_codes.add("previous_scan_blocked")
        suspicious_fields.add("history")
    if diff_input.previous_scan_required_manual_review:
        reason_codes.add("previous_scan_manual_review")
        suspicious_fields.add("history")
    if diff_input.scanner_or_rules_changed:
        reason_codes.add("scanner_or_rules_changed")
        suspicious_fields.add("scanner_state")
    if diff_input.cache_stale:
        reason_codes.add("cache_stale")
        suspicious_fields.add("cache_state")

    _classify_maintainer(fields, reason_codes, changed_fields, suspicious_fields, technical_details)
    source_churn = _classify_sources(fields, reason_codes, changed_fields, normal_churn_fields, suspicious_fields, technical_details)
    _classify_checksums(fields, source_churn, reason_codes, changed_fields, normal_churn_fields, suspicious_fields, technical_details)
    _classify_pgp(fields, reason_codes, changed_fields, normal_churn_fields, suspicious_fields, technical_details)
    _classify_dependencies(fields, reason_codes, changed_fields, normal_churn_fields, suspicious_fields, technical_details)
    _classify_install_hook(fields, reason_codes, changed_fields, suspicious_fields, technical_details)
    _classify_functions(fields, reason_codes, changed_fields, suspicious_fields, technical_details)
    _classify_new_risk_patterns(fields, reason_codes, changed_fields, suspicious_fields, technical_details)

    blocking_reasons = _blocking_reason_codes(reason_codes)
    low_risk_reasons = reason_codes - blocking_reasons
    if blocking_reasons:
        classification = _blocking_classification(blocking_reasons)
        severity = _severity_for_blocking_reasons(blocking_reasons)
        return _result(
            classification,
            severity,
            reason_codes,
            "Update changed an important trust boundary.",
            "AuraScan found a change that can affect package trust, so the smart fast path should not be used.",
            "Changes to maintainers, source hosts, signature verification, install hooks, dependencies, or build logic can be legitimate, but they deserve a normal scan.",
            changed_fields=changed_fields,
            normal_churn_fields=normal_churn_fields,
            suspicious_fields=suspicious_fields or changed_fields,
            technical_details=technical_details,
            manual_review=_requires_manual_review(blocking_reasons),
        )

    if _is_likely_normal_version_bump(fields, reason_codes, normal_churn_fields):
        return _result(
            TrustBoundaryClassification.likely_normal_version_bump,
            Severity.LOW,
            reason_codes or {"source_host_same_version_bump", "source_path_version_only_change"},
            "Update looks like normal version churn.",
            "AuraScan compared this update with the previous local scan and did not find major trust-boundary changes.",
            "Many package updates only change the upstream version and matching checksum. AuraScan can use this to avoid unnecessary expensive scans.",
            changed_fields=changed_fields,
            normal_churn_fields=normal_churn_fields or changed_fields,
            suspicious_fields=set(),
            technical_details=technical_details,
            manual_review=False,
            allow_fast_path=True,
        )

    if low_risk_reasons or changed_fields:
        return _result(
            TrustBoundaryClassification.metadata_changed_but_low_risk,
            Severity.LOW,
            reason_codes or {"metadata_changed_but_low_risk"},
            "Update metadata changed without a major trust-boundary move.",
            "AuraScan found metadata changes, but they appear to preserve or improve the package trust checks it can see.",
            "Low-risk metadata churn is still recorded so users can inspect it in JSON or verbose output.",
            changed_fields=changed_fields,
            normal_churn_fields=normal_churn_fields or changed_fields,
            suspicious_fields=set(),
            technical_details=technical_details,
            manual_review=False,
            allow_fast_path=True,
        )

    return _result(
        TrustBoundaryClassification.no_relevant_change,
        Severity.LOW,
        {"no_relevant_change"},
        "No major trust-boundary change detected.",
        "AuraScan compared this update with the previous local scan and did not find relevant metadata movement.",
        "This only means the cheap update-diff checks stayed clean; it does not prove the package is safe.",
        changed_fields=set(),
        normal_churn_fields=set(),
        suspicious_fields=set(),
        technical_details=technical_details,
        manual_review=False,
        allow_fast_path=True,
    )


@dataclass
class _ResolvedFields:
    package_name: str
    previous_version: str
    current_version: str
    previous_maintainer: str
    current_maintainer: str
    previous_sources: List[str]
    current_sources: List[str]
    previous_source_hosts: List[str]
    current_source_hosts: List[str]
    previous_checksums: List[str]
    current_checksums: List[str]
    previous_checksum_algorithms: List[str]
    current_checksum_algorithms: List[str]
    previous_validpgpkeys: List[str]
    current_validpgpkeys: List[str]
    previous_dependencies: List[str]
    current_dependencies: List[str]
    previous_makedepends: List[str]
    current_makedepends: List[str]
    previous_checkdepends: List[str]
    current_checkdepends: List[str]
    previous_optdepends: List[str]
    current_optdepends: List[str]
    previous_install_hook_hash: str
    current_install_hook_hash: str
    previous_function_hashes: Dict[str, str]
    current_function_hashes: Dict[str, str]
    previous_function_network_fetch: Dict[str, bool]
    current_function_network_fetch: Dict[str, bool]
    previous_source_metadata_risk_summary: Dict[str, Any]
    current_source_metadata_risk_summary: Dict[str, Any]
    has_previous_values: bool

    @classmethod
    def from_input(cls, diff_input: TrustBoundaryDiffInput, previous: Dict[str, Any], current: Dict[str, Any]) -> "_ResolvedFields":
        previous_sources = _list_field(diff_input.previous_sources, previous, "source_urls", "sources", "source")
        current_sources = _list_field(diff_input.current_sources, current, "source_urls", "sources", "source")
        previous_hosts = _list_field(diff_input.previous_source_hosts, previous, "source_hosts") or _hosts(previous_sources)
        current_hosts = _list_field(diff_input.current_source_hosts, current, "source_hosts") or _hosts(current_sources)
        previous_checksums = _list_field(diff_input.previous_checksums, previous, "checksums", "sha256sums")
        current_checksums = _list_field(diff_input.current_checksums, current, "checksums", "sha256sums")
        previous_algorithms = _algorithms(diff_input.previous_checksum_algorithms, previous, previous_checksums)
        current_algorithms = _algorithms(diff_input.current_checksum_algorithms, current, current_checksums)
        previous_function_hashes = {
            name: getattr(diff_input, f"previous_{name}_hash") or str(previous.get(f"{name}_hash") or "")
            for name in FUNC_NAMES
        }
        current_function_hashes = {
            name: getattr(diff_input, f"current_{name}_hash") or str(current.get(f"{name}_hash") or "")
            for name in FUNC_NAMES
        }
        previous_network = {name: bool(previous.get(f"{name}_network_fetch")) for name in FUNC_NAMES}
        current_network = {name: bool(current.get(f"{name}_network_fetch")) for name in FUNC_NAMES}
        has_previous = any(
            [
                previous,
                diff_input.previous_version,
                diff_input.previous_maintainer,
                previous_sources,
                previous_checksums,
                _list_field(diff_input.previous_dependencies, previous, "depends", "dependencies"),
            ]
        )
        return cls(
            package_name=diff_input.package_name or str(current.get("package_name") or previous.get("package_name") or current.get("pkgbase") or previous.get("pkgbase") or ""),
            previous_version=diff_input.previous_version or str(previous.get("version") or previous.get("pkgver") or ""),
            current_version=diff_input.current_version or str(current.get("version") or current.get("pkgver") or ""),
            previous_maintainer=_string_field(diff_input.previous_maintainer, previous, "maintainer"),
            current_maintainer=_string_field(diff_input.current_maintainer, current, "maintainer"),
            previous_sources=previous_sources,
            current_sources=current_sources,
            previous_source_hosts=previous_hosts,
            current_source_hosts=current_hosts,
            previous_checksums=previous_checksums,
            current_checksums=current_checksums,
            previous_checksum_algorithms=previous_algorithms,
            current_checksum_algorithms=current_algorithms,
            previous_validpgpkeys=_list_field(diff_input.previous_validpgpkeys, previous, "validpgpkeys"),
            current_validpgpkeys=_list_field(diff_input.current_validpgpkeys, current, "validpgpkeys"),
            previous_dependencies=_list_field(diff_input.previous_dependencies, previous, "depends", "dependencies"),
            current_dependencies=_list_field(diff_input.current_dependencies, current, "depends", "dependencies"),
            previous_makedepends=_list_field(diff_input.previous_makedepends, previous, "makedepends"),
            current_makedepends=_list_field(diff_input.current_makedepends, current, "makedepends"),
            previous_checkdepends=_list_field(diff_input.previous_checkdepends, previous, "checkdepends"),
            current_checkdepends=_list_field(diff_input.current_checkdepends, current, "checkdepends"),
            previous_optdepends=_list_field(diff_input.previous_optdepends, previous, "optdepends"),
            current_optdepends=_list_field(diff_input.current_optdepends, current, "optdepends"),
            previous_install_hook_hash=diff_input.previous_install_hook_hash or str(previous.get("install_file_hash") or previous.get("install_hook_hash") or ""),
            current_install_hook_hash=diff_input.current_install_hook_hash or str(current.get("install_file_hash") or current.get("install_hook_hash") or ""),
            previous_function_hashes=previous_function_hashes,
            current_function_hashes=current_function_hashes,
            previous_function_network_fetch=previous_network,
            current_function_network_fetch=current_network,
            previous_source_metadata_risk_summary=dict(diff_input.previous_source_metadata_risk_summary or previous.get("source_metadata_risk_summary") or {}),
            current_source_metadata_risk_summary=dict(diff_input.current_source_metadata_risk_summary or current.get("source_metadata_risk_summary") or {}),
            has_previous_values=bool(has_previous),
        )


def _classify_maintainer(fields: _ResolvedFields, reason_codes: Set[str], changed_fields: Set[str], suspicious_fields: Set[str], technical_details: Dict[str, Any]) -> None:
    if fields.previous_maintainer != fields.current_maintainer:
        changed_fields.add("maintainer")
        technical_details["maintainer"] = {"previous": fields.previous_maintainer, "current": fields.current_maintainer}
        if not fields.previous_maintainer and fields.current_maintainer:
            reason_codes.add("orphan_adopted")
        else:
            reason_codes.add("maintainer_changed")
        suspicious_fields.add("maintainer")


def _classify_sources(
    fields: _ResolvedFields,
    reason_codes: Set[str],
    changed_fields: Set[str],
    normal_churn_fields: Set[str],
    suspicious_fields: Set[str],
    technical_details: Dict[str, Any],
) -> bool:
    if fields.previous_sources == fields.current_sources:
        return False

    changed_fields.add("sources")
    technical_details["sources"] = {"previous": fields.previous_sources, "current": fields.current_sources}
    if fields.previous_source_hosts != fields.current_source_hosts:
        reason_codes.add("source_host_changed")
        suspicious_fields.add("sources")
        technical_details["source_hosts"] = {"previous": fields.previous_source_hosts, "current": fields.current_source_hosts}
        return False

    if _source_paths_are_version_churn(fields):
        reason_codes.add("source_host_same_version_bump")
        reason_codes.add("source_path_version_only_change")
        normal_churn_fields.add("sources")
        return True

    reason_codes.add("source_url_changed")
    suspicious_fields.add("sources")
    return False


def _classify_checksums(
    fields: _ResolvedFields,
    source_version_churn: bool,
    reason_codes: Set[str],
    changed_fields: Set[str],
    normal_churn_fields: Set[str],
    suspicious_fields: Set[str],
    technical_details: Dict[str, Any],
) -> None:
    previous = [_normalize_checksum(value) for value in fields.previous_checksums]
    current = [_normalize_checksum(value) for value in fields.current_checksums]
    if previous != current:
        changed_fields.add("checksums")
        technical_details["checksums"] = {"previous": fields.previous_checksums, "current": fields.current_checksums}
        reason_codes.add("checksum_value_changed")
        if previous and not current:
            reason_codes.add("checksum_removed")
            suspicious_fields.add("checksums")
        elif (not previous or all(_checksum_is_skip(value) for value in previous)) and current and not all(_checksum_is_skip(value) for value in current):
            reason_codes.add("checksum_added")
            normal_churn_fields.add("checksums")
        elif any(not _checksum_is_skip(old) and _checksum_is_skip(new) for old, new in _zip_longest(previous, current)):
            reason_codes.add("checksum_became_skip")
            suspicious_fields.add("checksums")
        elif source_version_churn:
            reason_codes.add("checksum_changed_with_version_bump")
            normal_churn_fields.add("checksums")
        else:
            reason_codes.add("checksum_changed_without_source_version_pattern")
            suspicious_fields.add("checksums")

    previous_algorithms = [_normalize_algorithm(value) for value in fields.previous_checksum_algorithms]
    current_algorithms = [_normalize_algorithm(value) for value in fields.current_checksum_algorithms]
    if previous_algorithms != current_algorithms:
        changed_fields.add("checksum_algorithms")
        technical_details["checksum_algorithms"] = {"previous": previous_algorithms, "current": current_algorithms}
    if _checksum_algorithms_weakened(previous_algorithms, current_algorithms):
        reason_codes.add("checksum_algorithm_weakened")
        suspicious_fields.add("checksum_algorithms")
    elif previous_algorithms != current_algorithms and not any(algorithm == "skip" for algorithm in current_algorithms):
        normal_churn_fields.add("checksum_algorithms")


def _classify_pgp(
    fields: _ResolvedFields,
    reason_codes: Set[str],
    changed_fields: Set[str],
    normal_churn_fields: Set[str],
    suspicious_fields: Set[str],
    technical_details: Dict[str, Any],
) -> None:
    previous_keys = sorted(fields.previous_validpgpkeys)
    current_keys = sorted(fields.current_validpgpkeys)
    if previous_keys != current_keys:
        changed_fields.add("validpgpkeys")
        technical_details["validpgpkeys"] = {"previous": previous_keys, "current": current_keys}
        if previous_keys and not current_keys:
            reason_codes.add("validpgpkeys_removed")
            reason_codes.add("pgp_removed")
            suspicious_fields.add("validpgpkeys")
        elif previous_keys and current_keys:
            reason_codes.add("validpgpkeys_changed")
            suspicious_fields.add("validpgpkeys")
        elif current_keys:
            normal_churn_fields.add("validpgpkeys")

    previous_signatures = _signature_sources(fields.previous_sources)
    current_signatures = _signature_sources(fields.current_sources)
    if previous_signatures != current_signatures:
        changed_fields.add("signature_sources")
        technical_details["signature_sources"] = {"previous": sorted(previous_signatures), "current": sorted(current_signatures)}
        if previous_signatures and not current_signatures:
            reason_codes.add("signature_source_removed")
            reason_codes.add("pgp_removed")
            suspicious_fields.add("signature_sources")
        elif current_signatures - previous_signatures:
            reason_codes.add("signature_source_added")
            normal_churn_fields.add("signature_sources")


def _classify_dependencies(
    fields: _ResolvedFields,
    reason_codes: Set[str],
    changed_fields: Set[str],
    normal_churn_fields: Set[str],
    suspicious_fields: Set[str],
    technical_details: Dict[str, Any],
) -> None:
    pairs = {
        "dependencies": (fields.previous_dependencies, fields.current_dependencies),
        "makedepends": (fields.previous_makedepends, fields.current_makedepends),
        "checkdepends": (fields.previous_checkdepends, fields.current_checkdepends),
        "optdepends": (fields.previous_optdepends, fields.current_optdepends),
    }
    for name, (old_values, new_values) in pairs.items():
        old = set(old_values)
        new = set(new_values)
        if old == new:
            continue
        changed_fields.add(name)
        technical_details[name] = {"previous": sorted(old), "current": sorted(new)}
        added = new - old
        removed = old - new
        if name == "dependencies":
            if added and removed:
                reason_codes.add("dependency_replaced")
            elif added:
                reason_codes.add("dependency_added")
            elif removed:
                reason_codes.add("dependency_removed")
            suspicious_fields.add(name)
        elif name == "makedepends":
            reason_codes.add("makedepends_changed")
            suspicious_fields.add(name)
        elif name == "checkdepends":
            reason_codes.add("checkdepends_changed")
            suspicious_fields.add(name)
        else:
            reason_codes.add("optdepends_changed")
            normal_churn_fields.add(name)


def _classify_install_hook(fields: _ResolvedFields, reason_codes: Set[str], changed_fields: Set[str], suspicious_fields: Set[str], technical_details: Dict[str, Any]) -> None:
    old_hash = fields.previous_install_hook_hash
    new_hash = fields.current_install_hook_hash
    if old_hash == new_hash:
        return
    changed_fields.add("install_hook")
    suspicious_fields.add("install_hook")
    technical_details["install_hook_hash"] = {"previous": old_hash, "current": new_hash}
    if not old_hash and new_hash:
        reason_codes.add("install_hook_added")
    else:
        reason_codes.add("install_hook_changed")


def _classify_functions(fields: _ResolvedFields, reason_codes: Set[str], changed_fields: Set[str], suspicious_fields: Set[str], technical_details: Dict[str, Any]) -> None:
    for name in FUNC_NAMES:
        old_hash = fields.previous_function_hashes[name]
        new_hash = fields.current_function_hashes[name]
        if old_hash != new_hash:
            changed_fields.add(f"{name}_function")
            suspicious_fields.add(f"{name}_function")
            reason_codes.add(f"{name}_function_changed")
            technical_details[f"{name}_function_hash"] = {"previous": old_hash, "current": new_hash}
        if not fields.previous_function_network_fetch[name] and fields.current_function_network_fetch[name]:
            changed_fields.add(f"{name}_function")
            suspicious_fields.add(f"{name}_function")
            reason_codes.add("new_network_fetch_pattern")


def _classify_new_risk_patterns(fields: _ResolvedFields, reason_codes: Set[str], changed_fields: Set[str], suspicious_fields: Set[str], technical_details: Dict[str, Any]) -> None:
    pattern_map = {
        "new_network_fetch_pattern": ("network_fetch", "network", "DEEPSTATIC-NETWORK-FETCH"),
        "new_credential_reference_pattern": ("credential_reference", "credential", "DEEPSTATIC-CREDENTIAL-PATH"),
        "new_persistence_pattern": (
            "persistence",
            "systemd",
            "cron",
            "DEEPSTATIC-SYSTEMD-PERSISTENCE",
            "DEEPSTATIC-SYSTEMD-AUTO-001",
            "DEEPSTATIC-SYSTEMD-USER-001",
            "DEEPSTATIC-CRON-PERSISTENCE",
        ),
        "new_suid_pattern": ("suid", "setuid", "DEEPSTATIC-SUID-LOGIC"),
    }
    for reason_code, markers in pattern_map.items():
        previous_has = _summary_has_pattern(fields.previous_source_metadata_risk_summary, markers)
        current_has = _summary_has_pattern(fields.current_source_metadata_risk_summary, markers)
        if current_has and not previous_has:
            reason_codes.add(reason_code)
            changed_fields.add("source_metadata_risk_summary")
            suspicious_fields.add("source_metadata_risk_summary")
    if "source_metadata_risk_summary" in changed_fields:
        technical_details["source_metadata_risk_summary"] = {
            "previous": fields.previous_source_metadata_risk_summary,
            "current": fields.current_source_metadata_risk_summary,
        }


def _blocking_reason_codes(reason_codes: Set[str]) -> Set[str]:
    blocking = {
        "previous_scan_blocked",
        "previous_scan_manual_review",
        "scanner_or_rules_changed",
        "cache_stale",
        "maintainer_changed",
        "orphan_adopted",
        "source_url_changed",
        "source_host_changed",
        "checksum_became_skip",
        "checksum_removed",
        "checksum_algorithm_weakened",
        "checksum_changed_without_source_version_pattern",
        "validpgpkeys_changed",
        "validpgpkeys_removed",
        "pgp_removed",
        "signature_source_removed",
        "dependency_added",
        "dependency_removed",
        "dependency_replaced",
        "makedepends_changed",
        "checkdepends_changed",
        "install_hook_added",
        "install_hook_changed",
        "prepare_function_changed",
        "build_function_changed",
        "check_function_changed",
        "package_function_changed",
        "new_network_fetch_pattern",
        "new_credential_reference_pattern",
        "new_persistence_pattern",
        "new_suid_pattern",
    }
    return reason_codes & blocking


def _blocking_classification(reason_codes: Set[str]) -> TrustBoundaryClassification:
    if {"maintainer_changed", "orphan_adopted"} & reason_codes:
        return TrustBoundaryClassification.maintainer_or_ownership_changed
    if "source_host_changed" in reason_codes:
        return TrustBoundaryClassification.source_location_changed
    if {"checksum_became_skip", "checksum_removed", "checksum_algorithm_weakened", "checksum_changed_without_source_version_pattern", "validpgpkeys_changed", "validpgpkeys_removed", "pgp_removed", "signature_source_removed"} & reason_codes:
        return TrustBoundaryClassification.verification_weakened
    if "source_url_changed" in reason_codes:
        return TrustBoundaryClassification.source_location_changed
    if {"install_hook_added", "install_hook_changed"} & reason_codes:
        return TrustBoundaryClassification.install_behavior_changed
    if {"dependency_added", "dependency_removed", "dependency_replaced", "makedepends_changed", "checkdepends_changed"} & reason_codes:
        return TrustBoundaryClassification.dependency_trust_chain_changed
    if {
        "prepare_function_changed",
        "build_function_changed",
        "check_function_changed",
        "package_function_changed",
        "new_network_fetch_pattern",
        "new_credential_reference_pattern",
        "new_persistence_pattern",
        "new_suid_pattern",
    } & reason_codes:
        return TrustBoundaryClassification.build_logic_changed
    return TrustBoundaryClassification.trust_boundary_changed


def _severity_for_blocking_reasons(reason_codes: Set[str]) -> Severity:
    high = {
        "source_host_changed",
        "checksum_became_skip",
        "checksum_removed",
        "checksum_algorithm_weakened",
        "validpgpkeys_removed",
        "pgp_removed",
        "signature_source_removed",
        "install_hook_added",
        "new_credential_reference_pattern",
        "new_persistence_pattern",
        "new_suid_pattern",
        "previous_scan_blocked",
    }
    return Severity.HIGH if reason_codes & high else Severity.MEDIUM


def _requires_manual_review(reason_codes: Set[str]) -> bool:
    review = {
        "maintainer_changed",
        "orphan_adopted",
        "source_host_changed",
        "source_url_changed",
        "checksum_became_skip",
        "checksum_removed",
        "checksum_algorithm_weakened",
        "validpgpkeys_changed",
        "validpgpkeys_removed",
        "pgp_removed",
        "signature_source_removed",
        "install_hook_added",
        "install_hook_changed",
        "dependency_added",
        "dependency_replaced",
        "prepare_function_changed",
        "build_function_changed",
        "check_function_changed",
        "package_function_changed",
        "new_network_fetch_pattern",
        "new_credential_reference_pattern",
        "new_persistence_pattern",
        "new_suid_pattern",
        "previous_scan_blocked",
        "previous_scan_manual_review",
    }
    return bool(reason_codes & review)


def _is_likely_normal_version_bump(fields: _ResolvedFields, reason_codes: Set[str], normal_churn_fields: Set[str]) -> bool:
    version_changed = bool(fields.previous_version and fields.current_version and fields.previous_version != fields.current_version)
    source_version_churn = {"source_host_same_version_bump", "source_path_version_only_change"} <= reason_codes
    checksum_ok = not reason_codes or (
        "checksum_changed_without_source_version_pattern" not in reason_codes
        and "checksum_became_skip" not in reason_codes
        and "checksum_algorithm_weakened" not in reason_codes
    )
    return version_changed and source_version_churn and checksum_ok and bool(normal_churn_fields)


def _result(
    classification: TrustBoundaryClassification,
    severity: Severity,
    reason_codes: Set[str],
    title: str,
    summary: str,
    why: str,
    *,
    changed_fields: Set[str],
    normal_churn_fields: Set[str],
    suspicious_fields: Set[str],
    technical_details: Dict[str, Any],
    manual_review: bool,
    allow_fast_path: bool = False,
) -> TrustBoundaryDiffResult:
    require_full_scan = not allow_fast_path
    if classification == TrustBoundaryClassification.insufficient_history:
        action = "Run the normal scan first. Smart fast path can be considered after an accepted baseline exists."
        checked = "AuraScan checked whether a previous accepted local snapshot was available."
        not_proved = "AuraScan did not compare this update against a trusted baseline."
    elif allow_fast_path:
        action = "No action needed for normal use. Use --deep-static if you want AuraScan to fetch and inspect the updated source."
        checked = "AuraScan checked maintainer, source host, checksum policy, signing metadata, dependencies, install hooks, and build metadata available in fast mode."
        not_proved = "This does not prove the new upstream source is safe. It only means the package metadata did not show major trust-boundary changes."
    else:
        action = "Review the warning details. Use --deep-static for a deeper source check if needed."
        checked = "AuraScan compared the current package metadata and local history snapshot for trust-boundary changes."
        not_proved = "This does not prove the update is malicious; it means the update should use the normal scan path."

    return TrustBoundaryDiffResult(
        classification=classification,
        allow_smart_fast_path=allow_fast_path,
        require_full_scan=require_full_scan,
        requires_manual_review=manual_review,
        severity=severity,
        reason_codes=list(reason_codes),
        user_title=title,
        user_summary=summary,
        why_it_matters=why,
        what_checked=checked,
        what_not_proved=not_proved,
        recommended_action=action,
        technical_details=technical_details,
        changed_fields=list(changed_fields),
        normal_churn_fields=list(normal_churn_fields),
        suspicious_fields=list(suspicious_fields),
    )


def _source_paths_are_version_churn(fields: _ResolvedFields) -> bool:
    if not fields.previous_sources or len(fields.previous_sources) != len(fields.current_sources):
        return False
    if fields.previous_source_hosts != fields.current_source_hosts:
        return False
    comparisons = [
        _normalized_source_pattern(old, fields.previous_version, fields.current_version)
        == _normalized_source_pattern(new, fields.previous_version, fields.current_version)
        for old, new in zip(fields.previous_sources, fields.current_sources)
    ]
    return all(comparisons) and any(old != new for old, new in zip(fields.previous_sources, fields.current_sources))


def _normalized_source_pattern(value: str, previous_version: str, current_version: str) -> Tuple[str, str, str]:
    parsed = urlparse(value)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    path = unquote(parsed.path or value)
    for version in sorted({previous_version, current_version}, key=len, reverse=True):
        if version:
            path = path.replace(version, "{version}")
    query = parsed.query
    for version in sorted({previous_version, current_version}, key=len, reverse=True):
        if version:
            query = query.replace(version, "{version}")
    return scheme, host, f"{path}?{query}" if query else path


def _checksum_algorithms_weakened(previous: List[str], current: List[str]) -> bool:
    for old, new in _zip_longest(previous, current):
        if not old or not new:
            continue
        if CHECKSUM_STRENGTH.get(new, 0) < CHECKSUM_STRENGTH.get(old, 0):
            return True
    return False


def _summary_has_pattern(summary: Mapping[str, Any], markers: Sequence[str]) -> bool:
    if not summary:
        return False
    lowered_markers = tuple(marker.lower() for marker in markers)
    for key, value in summary.items():
        key_lower = str(key).lower()
        if any(marker in key_lower for marker in lowered_markers) and bool(value):
            return True
        if isinstance(value, str) and any(marker in value.lower() for marker in lowered_markers):
            return True
        if isinstance(value, (list, tuple, set)):
            for item in value:
                if any(marker in str(item).lower() for marker in lowered_markers):
                    return True
    return False


def _signature_sources(sources: Sequence[str]) -> Set[str]:
    return {source for source in sources if str(source).lower().split("?", 1)[0].endswith((".sig", ".asc"))}


def _hosts(sources: Sequence[str]) -> List[str]:
    hosts = sorted({(urlparse(source).hostname or "").lower() for source in sources if "://" in source})
    return [host for host in hosts if host]


def _list_field(explicit: Optional[Sequence[str]], snapshot: Mapping[str, Any], *keys: str) -> List[str]:
    if explicit is not None:
        return _normalize_list(explicit)
    for key in keys:
        if key in snapshot:
            return _normalize_list(snapshot.get(key))
    return []


def _string_field(explicit: Optional[str], snapshot: Mapping[str, Any], key: str) -> str:
    if explicit is not None:
        return str(explicit)
    return str(snapshot.get(key) or "")


def _normalize_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    return [str(item) for item in value if str(item)]


def _algorithms(explicit: Optional[Sequence[str]], snapshot: Mapping[str, Any], checksums: Sequence[str]) -> List[str]:
    values = _list_field(explicit, snapshot, "checksum_algorithms", "checksum_algorithm")
    if values:
        return [_normalize_algorithm(value) for value in values]
    if checksums:
        return ["skip" if _checksum_is_skip(value) else "sha256" for value in checksums]
    return []


def _normalize_checksum(value: str) -> str:
    return str(value).strip().strip("'\"").lower()


def _checksum_is_skip(value: str) -> bool:
    return _normalize_checksum(value) == "skip"


def _normalize_algorithm(value: str) -> str:
    normalized = str(value).strip().strip("'\"").lower().replace("sums", "").replace("sum", "")
    if normalized == "blake2b":
        return "blake2b"
    if normalized == "b2":
        return "b2"
    return normalized or "unknown"


def _zip_longest(left: Sequence[str], right: Sequence[str]) -> List[Tuple[str, str]]:
    size = max(len(left), len(right))
    return [
        (left[index] if index < len(left) else "", right[index] if index < len(right) else "")
        for index in range(size)
    ]
