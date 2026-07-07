from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Protocol

from aurascan.core.update_policy import ScanContext, ScanContextSource, normalize_context, normalize_context_source


class ScanContextAuthority(Enum):
    unknown = "unknown"
    user_asserted = "user_asserted"
    test_only = "test_only"
    verified_local_package_db = "verified_local_package_db"
    verified_transaction_provider = "verified_transaction_provider"


@dataclass
class ScanContextProof:
    context: ScanContext = ScanContext.unknown
    source: ScanContextSource = ScanContextSource.unknown
    authority: ScanContextAuthority = ScanContextAuthority.unknown
    package_name: str = ""
    package_base: str = ""
    installed_version: str = ""
    candidate_version: str = ""
    transaction_operation: str = ""
    installed_package_present: Optional[bool] = None
    provider_name: str = ""
    proof_reasons: List[str] = field(default_factory=list)
    proof_errors: List[str] = field(default_factory=list)
    eligible_for_fast_path: bool = False
    user_warning: str = ""

    def __post_init__(self) -> None:
        self.context = normalize_context(self.context)
        self.source = normalize_context_source(self.source)
        self.authority = normalize_authority(self.authority)
        self.proof_reasons = [str(item) for item in self.proof_reasons if str(item)]
        self.proof_errors = [str(item) for item in self.proof_errors if str(item)]
        if not self.provider_name:
            self.provider_name = self.source.value

    def to_dict(self) -> Dict[str, object]:
        return {
            "context": self.context.value,
            "source": self.source.value,
            "authority": self.authority.value,
            "package_name": self.package_name,
            "package_base": self.package_base,
            "installed_version": self.installed_version,
            "candidate_version": self.candidate_version,
            "transaction_operation": self.transaction_operation,
            "installed_package_present": self.installed_package_present,
            "provider_name": self.provider_name,
            "proof_reasons": list(self.proof_reasons),
            "proof_errors": list(self.proof_errors),
            "eligible_for_fast_path": self.eligible_for_fast_path,
            "user_warning": self.user_warning,
        }


class ScanContextProvider(Protocol):
    """Contract for future package-manager context providers.

    Providers must return unknown/not eligible whenever package identity,
    installed state, transaction operation, or split-package mapping is
    ambiguous. They must not infer update context from package name, dependency
    stability, version strings alone, AUR metadata alone, or user intent.
    """

    name: str

    def build_proof(self) -> ScanContextProof:
        ...


def normalize_authority(value: object) -> ScanContextAuthority:
    if isinstance(value, ScanContextAuthority):
        return value
    return ScanContextAuthority(str(value))


def build_scan_context_proof(
    *,
    context: object = ScanContext.unknown,
    source: object = ScanContextSource.unknown,
    allow_user_asserted_update_context: bool = False,
    package_name: str = "",
    package_base: str = "",
    installed_version: str = "",
    candidate_version: str = "",
    transaction_operation: str = "",
    installed_package_present: Optional[bool] = None,
    provider_name: str = "",
    proof_reasons: Optional[List[str]] = None,
    proof_errors: Optional[List[str]] = None,
) -> ScanContextProof:
    normalized_context = normalize_context(context)
    normalized_source = normalize_context_source(source)
    reasons = list(proof_reasons or [])
    errors = list(proof_errors or [])
    if normalized_context == ScanContext.auto:
        normalized_context = ScanContext.unknown
        errors.append("auto_context_not_resolved")
    authority = _authority_for_source(normalized_source)
    eligible = False
    warning = ""

    if normalized_context in (ScanContext.unknown, ScanContext.auto):
        errors.append("unknown_context")
    elif normalized_context == ScanContext.install:
        reasons.append("install_context_not_update")
    elif normalized_context == ScanContext.dependency:
        reasons.append("dependency_context_not_update_by_default")
    elif normalized_context == ScanContext.update:
        if authority == ScanContextAuthority.user_asserted:
            reasons.append("user_asserted_update_context")
            warning = (
                "This update context was provided manually. It is not verified "
                "by a package transaction provider."
            )
            eligible = bool(allow_user_asserted_update_context)
            if not eligible:
                errors.append("user_asserted_context_requires_opt_in")
        elif authority in (
            ScanContextAuthority.test_only,
            ScanContextAuthority.verified_local_package_db,
            ScanContextAuthority.verified_transaction_provider,
        ):
            reasons.append("verified_update_context")
            eligible = True
        else:
            errors.append("untrusted_update_context_authority")

    if normalized_context == ScanContext.update and authority in (
        ScanContextAuthority.verified_local_package_db,
        ScanContextAuthority.verified_transaction_provider,
    ):
        if not package_name and not package_base:
            errors.append("missing_package_identity")
        if installed_package_present is not True:
            errors.append("installed_package_not_confirmed")
        if not installed_version:
            errors.append("missing_installed_version")
        if not candidate_version:
            errors.append("missing_candidate_version")
        if not transaction_operation:
            errors.append("missing_transaction_operation")
        elif transaction_operation not in {"upgrade", "update"}:
            errors.append("operation_not_update")
        eligible = eligible and not errors

    if errors:
        eligible = False

    return ScanContextProof(
        context=normalized_context,
        source=normalized_source,
        authority=authority,
        package_name=package_name,
        package_base=package_base,
        installed_version=installed_version,
        candidate_version=candidate_version,
        transaction_operation=transaction_operation,
        installed_package_present=installed_package_present,
        provider_name=provider_name or normalized_source.value,
        proof_reasons=sorted(set(reasons)),
        proof_errors=sorted(set(errors)),
        eligible_for_fast_path=eligible,
        user_warning=warning,
    )


def unknown_context_proof(error: str = "unknown_context") -> ScanContextProof:
    return ScanContextProof(
        proof_errors=[error],
        provider_name=ScanContextSource.unknown.value,
    )


def _authority_for_source(source: ScanContextSource) -> ScanContextAuthority:
    if source == ScanContextSource.explicit_cli:
        return ScanContextAuthority.user_asserted
    if source == ScanContextSource.test_fixture:
        return ScanContextAuthority.test_only
    if source == ScanContextSource.pacman_hook:
        return ScanContextAuthority.verified_transaction_provider
    if source == ScanContextSource.makepkg_wrapper:
        return ScanContextAuthority.verified_local_package_db
    if source == ScanContextSource.local_package_db:
        return ScanContextAuthority.verified_local_package_db
    return ScanContextAuthority.unknown
