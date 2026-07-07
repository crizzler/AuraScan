import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from aurascan.core.context_provider import ScanContextProof, build_scan_context_proof
from aurascan.core.update_policy import ScanContext, ScanContextSource


DEFAULT_LOCAL_PACKAGE_DB_ROOT = Path("/var/lib/pacman/local")
VersionCompare = Callable[[str, str], Optional[int]]

_PACKAGE_NAME_RE = re.compile(r"^[A-Za-z0-9@._+-]+$")


@dataclass
class CandidatePackageMetadata:
    package_names: List[str] = field(default_factory=list)
    package_base: str = ""
    candidate_version: str = ""
    proof_reasons: List[str] = field(default_factory=list)
    proof_errors: List[str] = field(default_factory=list)


class LocalPackageDbContextProvider:
    """Build scan-context proof from the read-only local pacman package DB."""

    name = "local_package_db"

    def __init__(
        self,
        *,
        pkgbuild_path: Optional[str] = None,
        content: str = "",
        metadata: Optional[Dict[str, object]] = None,
        local_db_root: Optional[Path] = None,
        version_compare: Optional[VersionCompare] = None,
    ) -> None:
        self.pkgbuild_path = str(pkgbuild_path or "")
        self.content = content
        self.metadata = dict(metadata or {})
        self.local_db_root = Path(local_db_root) if local_db_root is not None else DEFAULT_LOCAL_PACKAGE_DB_ROOT
        self.version_compare = version_compare or compare_versions_with_vercmp

    def build_proof(self) -> ScanContextProof:
        try:
            candidate = self._candidate_metadata()
            if candidate.proof_errors:
                return self._unknown(candidate, candidate.proof_errors)

            installed, db_error = self._load_installed_packages()
            if db_error:
                return self._unknown(candidate, [db_error])

            names = candidate.package_names
            installed_versions = {name: installed[name] for name in names if name in installed}
            absent_names = [name for name in names if name not in installed]

            if len(names) > 1 and absent_names and installed_versions:
                return self._unknown(candidate, ["partial_split_package_installed"])

            if not installed_versions:
                return build_scan_context_proof(
                    context=ScanContext.install,
                    source=ScanContextSource.local_package_db,
                    package_name=" ".join(names),
                    package_base=candidate.package_base,
                    candidate_version=candidate.candidate_version,
                    transaction_operation="install",
                    installed_package_present=False,
                    provider_name=self.name,
                    proof_reasons=candidate.proof_reasons + ["local_package_not_installed"],
                )

            comparisons = []
            for name in names:
                installed_version = installed_versions.get(name)
                if not installed_version:
                    return self._unknown(candidate, ["split_package_install_state_incomplete"])
                comparison = self._compare_versions(installed_version, candidate.candidate_version)
                if comparison is None:
                    return self._unknown(
                        candidate,
                        ["version_comparison_unavailable"],
                        installed_version=_joined_versions(installed_versions),
                        installed_package_present=True,
                    )
                comparisons.append(comparison)

            installed_version = _joined_versions(installed_versions)
            if all(item < 0 for item in comparisons):
                return build_scan_context_proof(
                    context=ScanContext.update,
                    source=ScanContextSource.local_package_db,
                    package_name=" ".join(names),
                    package_base=candidate.package_base,
                    installed_version=installed_version,
                    candidate_version=candidate.candidate_version,
                    transaction_operation="upgrade",
                    installed_package_present=True,
                    provider_name=self.name,
                    proof_reasons=candidate.proof_reasons + ["local_package_installed", "candidate_version_newer"],
                )

            if all(item == 0 for item in comparisons):
                return self._unknown(
                    candidate,
                    ["candidate_version_not_newer"],
                    installed_version=installed_version,
                    installed_package_present=True,
                    transaction_operation="reinstall",
                )

            if all(item > 0 for item in comparisons):
                return self._unknown(
                    candidate,
                    ["candidate_version_older_than_installed"],
                    installed_version=installed_version,
                    installed_package_present=True,
                    transaction_operation="downgrade",
                )

            return self._unknown(
                candidate,
                ["split_package_version_state_mixed"],
                installed_version=installed_version,
                installed_package_present=True,
            )
        except Exception:
            return self._unknown(CandidatePackageMetadata(), ["provider_error"])

    def _candidate_metadata(self) -> CandidatePackageMetadata:
        if self.content:
            return parse_pkgbuild_candidate_metadata(self.content)

        package_name = str(self.metadata.get("package_name") or "")
        package_names = [item for item in package_name.split() if item]
        package_base = str(self.metadata.get("pkgbase") or "")
        candidate_version = str(self.metadata.get("version") or "")
        errors = []
        if not package_names:
            errors.append("package_name_parse_failed")
        if len(package_names) > 1 and not package_base:
            errors.append("ambiguous_split_package_mapping")
        if not candidate_version:
            errors.append("missing_candidate_version")
        return CandidatePackageMetadata(
            package_names=package_names,
            package_base=package_base or (package_names[0] if len(package_names) == 1 else ""),
            candidate_version=candidate_version,
            proof_errors=errors,
        )

    def _load_installed_packages(self) -> Tuple[Dict[str, str], str]:
        if not self.local_db_root.exists() or not self.local_db_root.is_dir():
            return {}, "local_package_db_missing"

        installed: Dict[str, str] = {}
        for child in sorted(self.local_db_root.iterdir()):
            if not child.is_dir():
                continue
            desc_path = child / "desc"
            if not desc_path.exists():
                return {}, "malformed_local_package_db"
            try:
                desc = _parse_pacman_desc(desc_path.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                return {}, "local_package_db_read_error"
            name = desc.get("NAME", "")
            version = desc.get("VERSION", "")
            if not name or not version:
                return {}, "malformed_local_package_db"
            if name in installed and installed[name] != version:
                return {}, "duplicate_local_package_db_entry"
            installed[name] = version
        return installed, ""

    def _compare_versions(self, installed_version: str, candidate_version: str) -> Optional[int]:
        try:
            result = self.version_compare(installed_version, candidate_version)
        except Exception:
            return None
        if result is None:
            return None
        if result < 0:
            return -1
        if result > 0:
            return 1
        return 0

    def _unknown(
        self,
        candidate: CandidatePackageMetadata,
        errors: List[str],
        *,
        installed_version: str = "",
        installed_package_present: Optional[bool] = None,
        transaction_operation: str = "",
    ) -> ScanContextProof:
        package_name = " ".join(candidate.package_names)
        return build_scan_context_proof(
            context=ScanContext.unknown,
            source=ScanContextSource.local_package_db,
            package_name=package_name,
            package_base=candidate.package_base,
            installed_version=installed_version,
            candidate_version=candidate.candidate_version,
            transaction_operation=transaction_operation,
            installed_package_present=installed_package_present,
            provider_name=self.name,
            proof_reasons=candidate.proof_reasons,
            proof_errors=errors,
        )


def parse_pkgbuild_candidate_metadata(content: str) -> CandidatePackageMetadata:
    errors: List[str] = []
    reasons: List[str] = []

    package_names = _parse_assignment_values(content, "pkgname")
    if package_names is None or not package_names:
        errors.append("package_name_parse_failed")
        package_names = []
    elif any(not _valid_package_name(name) for name in package_names):
        errors.append("package_name_parse_failed")

    pkgbase_values = _parse_assignment_values(content, "pkgbase")
    package_base = pkgbase_values[0] if pkgbase_values and len(pkgbase_values) == 1 else ""

    pkgver_values = _parse_assignment_values(content, "pkgver")
    pkgrel_values = _parse_assignment_values(content, "pkgrel")
    epoch_values = _parse_assignment_values(content, "epoch")
    candidate_version = ""
    if (
        not pkgver_values
        or len(pkgver_values) != 1
        or pkgrel_values is None
        or epoch_values is None
        or len(pkgrel_values) > 1
        or len(epoch_values) > 1
    ):
        errors.append("missing_candidate_version")
    else:
        candidate_version = pkgver_values[0]
        if pkgrel_values and len(pkgrel_values) == 1:
            candidate_version = f"{candidate_version}-{pkgrel_values[0]}"
        if epoch_values and len(epoch_values) == 1:
            candidate_version = f"{epoch_values[0]}:{candidate_version}"

    if len(package_names) == 1 and not package_base:
        package_base = package_names[0]
    elif len(package_names) > 1:
        reasons.append("split_package_detected")
        if not package_base:
            errors.append("ambiguous_split_package_mapping")
        if len(set(package_names)) != len(package_names):
            errors.append("ambiguous_split_package_mapping")

    return CandidatePackageMetadata(
        package_names=package_names,
        package_base=package_base,
        candidate_version=candidate_version,
        proof_reasons=reasons,
        proof_errors=sorted(set(errors)),
    )


def compare_versions_with_vercmp(installed_version: str, candidate_version: str, *, timeout: float = 2.0) -> Optional[int]:
    vercmp = shutil.which("vercmp")
    if not vercmp:
        return None
    try:
        result = subprocess.run(
            [vercmp, installed_version, candidate_version],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
        return None
    output = result.stdout.strip().splitlines()
    if not output:
        return None
    try:
        comparison = int(output[-1].strip())
    except ValueError:
        return None
    if comparison < 0:
        return -1
    if comparison > 0:
        return 1
    return 0


def _parse_assignment_values(content: str, key: str) -> Optional[List[str]]:
    array_match = re.search(rf"^\s*{re.escape(key)}\s*=\s*\((?P<body>.*?)\)", content, re.M | re.S)
    if array_match:
        return _split_static_tokens(array_match.group("body"))

    scalar_match = re.search(rf"^\s*{re.escape(key)}\s*=\s*(?P<value>[^\n]+)", content, re.M)
    if not scalar_match:
        return []
    tokens = _split_static_tokens(scalar_match.group("value"))
    if tokens is None or len(tokens) != 1:
        return None
    return tokens


def _split_static_tokens(raw: str) -> Optional[List[str]]:
    if "$" in raw or "`" in raw or "<(" in raw or ">(" in raw:
        return None
    try:
        tokens = shlex.split(raw, comments=True, posix=True)
    except ValueError:
        return None
    if any("$" in token or "`" in token for token in tokens):
        return None
    return [token.strip() for token in tokens if token.strip()]


def _valid_package_name(name: str) -> bool:
    return bool(name and _PACKAGE_NAME_RE.match(name))


def _parse_pacman_desc(content: str) -> Dict[str, str]:
    sections: Dict[str, List[str]] = {}
    current = ""
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("%") and line.endswith("%") and len(line) > 2:
            current = line.strip("%")
            sections.setdefault(current, [])
            continue
        if current:
            sections[current].append(line)
    return {key: values[0] for key, values in sections.items() if values}


def _joined_versions(installed_versions: Dict[str, str]) -> str:
    versions = sorted(set(installed_versions.values()))
    return versions[0] if len(versions) == 1 else ", ".join(f"{name}={version}" for name, version in sorted(installed_versions.items()))
