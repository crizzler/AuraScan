import urllib.parse
from pathlib import Path
from typing import Dict, List, Tuple

from aurascan.analyzers.base import BaseAnalyzer
from aurascan.core.models import AnalysisResult, Confidence, EvidenceQuality, Finding, Phase, Severity, Source
from aurascan.core.source_acquisition import PgpKeyNormalizer, SourceKind, SourceParser, SourceReference


ARCHIVE_SUFFIXES = (
    ".tar", ".tar.gz", ".tgz", ".tar.xz", ".tar.zst", ".zip", ".gz", ".xz", ".bz2"
)
WEAK_CHECKSUM_ALGORITHMS = {"md5", "sha1"}


class SourceMetadataAnalyzer(BaseAnalyzer):
    def __init__(self, parser: SourceParser = None):
        self.parser = parser or SourceParser()

    def analyze_pkgbuild(self, pkgbuild_path: str, content: str) -> AnalysisResult:
        refs, _parser_findings = self.parser.parse(pkgbuild_path, content)
        if not refs:
            return AnalysisResult(True, "No source metadata findings", [])

        findings: List[Finding] = []
        source_count, checksum_count = self._source_checksum_counts(pkgbuild_path, content, len(refs))
        if checksum_count and checksum_count != source_count:
            findings.append(self._finding(
                "SOURCE-META-CHECKSUM-COUNT-MISMATCH",
                pkgbuild_path,
                Severity.HIGH,
                "Checksum count does not match source count.",
                "The package has a different number of source entries and declared checksums.",
                "A mismatch can mean a source is not protected by the checksum the maintainer intended.",
                "Review the PKGBUILD carefully before installing.",
                f"sources={source_count}, checksums={checksum_count}",
                100,
            ))

        signatures = self._signature_map(refs)
        for ref in refs:
            if ref.kind == SourceKind.signature:
                findings.append(self._signature_present(pkgbuild_path, ref))
                continue

            has_signature = ref.filename in signatures
            checksum = (ref.checksum or "").upper()
            if ref.checksum is None:
                findings.append(self._finding(
                    "SOURCE-META-MISSING-CHECKSUM",
                    pkgbuild_path,
                    Severity.MEDIUM,
                    "Source is missing checksum metadata.",
                    "One source entry does not have a matching declared checksum.",
                    "Without checksum metadata, fast scan cannot confirm from the PKGBUILD that this source has an intended digest.",
                    "Use --deep-static for a closer check or review the PKGBUILD manually.",
                    ref.original,
                    75,
                ))
            elif ref.checksum_algorithm in WEAK_CHECKSUM_ALGORITHMS and ref.kind != SourceKind.local:
                findings.append(self._weak_checksum(pkgbuild_path, ref))

            if ref.kind == SourceKind.http and urllib.parse.urlparse(ref.resolved).scheme == "http":
                severity = Severity.HIGH if checksum == "SKIP" else Severity.MEDIUM
                findings.append(self._http_not_https(pkgbuild_path, ref, severity))

            if checksum == "SKIP":
                findings.extend(self._skip_findings(pkgbuild_path, ref, has_signature))

        findings.extend(self._validpgpkey_findings(pkgbuild_path, refs, bool(signatures)))
        return AnalysisResult(not any(f.blocks_installation for f in findings), "Source metadata checked", findings)

    def _skip_findings(self, path: str, ref: SourceReference, has_signature: bool) -> List[Finding]:
        if ref.kind == SourceKind.git_https:
            if ref.fragment_type == "commit" and ref.fragment_value:
                return [self._finding(
                    "SOURCE-META-SKIP-GIT-COMMIT",
                    path,
                    Severity.LOW,
                    "Source is pinned to a Git commit.",
                    "This package uses a Git source pinned to a specific commit.",
                    "This is usually more reproducible than using a moving branch. SKIP checksums are common for Git sources.",
                    "No immediate action needed unless other warnings appear.",
                    ref.original,
                    10,
                    show=False,
                    is_common="Yes. This is a common and usually reasonable AUR pattern.",
                )]
            if ref.fragment_type == "tag":
                return [self._finding(
                    "SOURCE-META-SKIP-GIT-TAG",
                    path,
                    Severity.MEDIUM,
                    "Source uses a Git tag.",
                    "This package uses a Git tag with SKIP checksum.",
                    "Tags are more stable than branches, but tag signing is not checked in fast scan.",
                    "Use --deep-static for a closer source check if other warnings appear.",
                    ref.original,
                    35,
                    show=False,
                )]
            if ref.fragment_type == "branch":
                return [self._finding(
                    "SOURCE-META-SKIP-GIT-BRANCH",
                    path,
                    Severity.MEDIUM,
                    "Source follows a moving Git branch.",
                    "This package pulls code from a Git branch instead of a fixed commit.",
                    "Branches can change over time. Two installs of the same package may build from different source code.",
                    "Usually okay for packages you already trust. Use --deep-static for a closer source check if the package is new or recently changed.",
                    ref.original,
                    55,
                    is_common="Yes. This is common for some AUR packages, especially development packages.",
                )]
            return [self._finding(
                "SOURCE-META-SKIP-GIT-NO-FRAGMENT",
                path,
                Severity.MEDIUM,
                "Git source is not pinned.",
                "This package uses a Git source without a commit, tag, or branch fragment.",
                "Unpinned sources can change over time in ways fast scan cannot inspect.",
                "Use --deep-static or review the source manually before installing.",
                ref.original,
                70,
            )]

        if self._is_archive(ref):
            if has_signature:
                return [self._finding(
                    "SOURCE-META-SKIP-ARCHIVE-WITH-SIGNATURE",
                    path,
                    Severity.LOW,
                    "Source uses signature-based verification.",
                    "This package skips the normal checksum, but it declares a detached signature file.",
                    "Some packages use signatures instead of checksums. This can be fine if the signature is valid and matches validpgpkeys.",
                    "Use --deep-static to verify the signature automatically in an isolated keyring.",
                    ref.original,
                    30,
                    show=False,
                    is_common="Yes, this is a normal pattern for some packages.",
                )]
            severity = Severity.HIGH if urllib.parse.urlparse(ref.resolved).scheme == "http" else Severity.MEDIUM
            return [self._finding(
                "SOURCE-META-SKIP-ARCHIVE-NO-SIGNATURE",
                path,
                severity,
                "Source archive has no checksum verification.",
                "This package declares a downloadable archive but marks its checksum as SKIP, and no detached signature was found.",
                "Without a checksum or signature, AuraScan cannot confirm from metadata that the downloaded source is the exact file the maintainer intended.",
                "Use --deep-static for a closer check. Be extra careful if the package was recently adopted or changed source hosts.",
                ref.original,
                90 if severity == Severity.HIGH else 80,
                is_common="It is less ideal for archive downloads. SKIP is more common for Git sources.",
            )]
        return []

    def _validpgpkey_findings(self, path: str, refs: List[SourceReference], has_signature: bool) -> List[Finding]:
        keys = sorted({key for ref in refs for key in ref.validpgpkeys})
        findings: List[Finding] = []
        for key in keys:
            if PgpKeyNormalizer.is_weak(key):
                findings.append(self._finding(
                    "SOURCE-META-WEAK-VALIDPGPKEY",
                    path,
                    Severity.MEDIUM,
                    "Signing key identifier is too short.",
                    "This package declares a signing key using a short key ID instead of a full fingerprint.",
                    "Short key IDs are weaker identifiers and can be easier to confuse. Full fingerprints are safer.",
                    "Prefer packages that use full signing-key fingerprints. Use --deep-static if you want AuraScan to attempt signature verification.",
                    key,
                    85,
                ))
        if has_signature and not keys:
            findings.append(self._finding(
                "SOURCE-META-VALIDPGPKEYS-MISSING",
                path,
                Severity.MEDIUM,
                "Signature is present but signing key metadata is missing.",
                "This package declares a detached signature but does not declare validpgpkeys.",
                "Fast scan can see that signature verification is intended, but it cannot identify the expected signer from metadata.",
                "Use --deep-static or manually verify the signature and signer identity.",
                "signature present, validpgpkeys missing",
                80,
            ))
        return findings

    def _http_not_https(self, path: str, ref: SourceReference, severity: Severity) -> Finding:
        return self._finding(
            "SOURCE-META-HTTP-NOT-HTTPS",
            path,
            severity,
            "Source uses plain HTTP.",
            "This package downloads at least one source over plain HTTP instead of HTTPS.",
            "Plain HTTP is not encrypted, so someone on the network could potentially tamper with the download. A valid checksum or signature can still protect against tampering.",
            "Use --deep-static for a closer check. Be more careful if the source also uses SKIP or lacks a signature.",
            ref.original,
            95 if severity == Severity.HIGH else 65,
            is_common="It happens, but HTTPS is preferred when available.",
        )

    def _signature_present(self, path: str, ref: SourceReference) -> Finding:
        return self._finding(
            "SOURCE-META-SIGNATURE-PRESENT",
            path,
            Severity.LOW,
            "Detached signature metadata is present.",
            "This package declares a detached source signature.",
            "Signatures can provide strong integrity evidence when they are valid and match validpgpkeys.",
            "Use --deep-static to verify the signature automatically in an isolated keyring.",
            ref.original,
            20,
            show=False,
        )

    def _weak_checksum(self, path: str, ref: SourceReference) -> Finding:
        algorithm = (ref.checksum_algorithm or "weak").upper()
        return self._finding(
            "SOURCE-META-WEAK-CHECKSUM",
            path,
            Severity.MEDIUM,
            "Source uses a weak checksum algorithm.",
            f"This package verifies a remote source with {algorithm} checksum metadata.",
            f"{algorithm} checksums are useful for catching accidental corruption, but they are weaker integrity protection than SHA-256, SHA-512, or BLAKE2.",
            "Prefer packages that use stronger checksums or detached signatures. Use --deep-static if you want a closer source check.",
            ref.original,
            60,
            is_common="It still appears in some older AUR packages, but stronger checksums are preferred.",
        )

    def _source_checksum_counts(self, pkgbuild_path: str, content: str, source_count: int) -> Tuple[int, int]:
        srcinfo_path = Path(pkgbuild_path).with_name(".SRCINFO")
        if srcinfo_path.exists():
            text = srcinfo_path.read_text(encoding="utf-8", errors="replace")
            count = sum(1 for line in text.splitlines() if self.parser._srcinfo_checksum_key(line.strip()))
            return source_count, count
        _algorithm, checksums = self.parser._parse_checksum_arrays(content)
        return source_count, len(checksums)

    def _signature_map(self, refs: List[SourceReference]) -> Dict[str, SourceReference]:
        signatures: Dict[str, SourceReference] = {}
        for ref in refs:
            if ref.kind != SourceKind.signature:
                continue
            for suffix in (".sig", ".asc"):
                if ref.filename.endswith(suffix):
                    signatures[ref.filename[:-len(suffix)]] = ref
        return signatures

    def _is_archive(self, ref: SourceReference) -> bool:
        return ref.kind in {SourceKind.http, SourceKind.local} and ref.filename.endswith(ARCHIVE_SUFFIXES)

    def _finding(
        self,
        rule_id: str,
        path: str,
        severity: Severity,
        title: str,
        summary: str,
        why: str,
        action: str,
        evidence: str,
        priority: int,
        *,
        show: bool = True,
        is_common: str = "",
    ) -> Finding:
        return Finding(
            rule_id=rule_id,
            package_name="unknown",
            package_version="unknown",
            phase=Phase.pkgbuild_static,
            source=Source.deterministic_rule,
            severity=severity,
            confidence=Confidence.HIGH,
            evidence_quality=EvidenceQuality.weak_heuristic if severity == Severity.LOW else EvidenceQuality.strong_heuristic,
            file_path=path,
            explanation=summary,
            recommendation=action,
            blocks_installation=False,
            requires_manual_review=severity in {Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL},
            evidence_snippet=evidence,
            user_title=title,
            user_summary=summary,
            why_it_matters=why,
            is_this_common=is_common,
            what_aurascan_checked="AuraScan inspected the package source metadata without downloading or executing source code.",
            what_aurascan_did_not_check="Fast scan did not download, unpack, clone, or verify source contents.",
            recommended_user_action=action,
            technical_details=evidence,
            show_by_default=show,
            display_group=rule_id,
            display_priority=priority,
        )
