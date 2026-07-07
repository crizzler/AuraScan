import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from aurascan.core.models import Confidence, EvidenceQuality, Finding, Phase, Severity, Source


class SourceKind(Enum):
    local = "local"
    http = "http"
    git_https = "git_https"
    signature = "signature"
    unsupported = "unsupported"
    ambiguous = "ambiguous"


CHECKSUM_FAMILIES = (
    ("b2sums", "b2"),
    ("sha512sums", "sha512"),
    ("sha384sums", "sha384"),
    ("sha256sums", "sha256"),
    ("sha224sums", "sha224"),
    ("sha1sums", "sha1"),
    ("md5sums", "md5"),
)


@dataclass
class SourceReference:
    original: str
    resolved: str
    index: int
    filename: str
    checksum_index: int
    checksum: Optional[str] = None
    checksum_algorithm: Optional[str] = None
    kind: SourceKind = SourceKind.unsupported
    fragment_type: Optional[str] = None
    fragment_value: Optional[str] = None
    validpgpkeys: List[str] = field(default_factory=list)

    @property
    def is_signature(self) -> bool:
        return self.filename.endswith((".sig", ".asc")) or self.resolved.endswith((".sig", ".asc"))


@dataclass
class SourceAcquisitionResult:
    reference: SourceReference
    local_path: Optional[Path] = None
    final_url: Optional[str] = None
    size: int = 0
    sha256: Optional[str] = None
    status: str = "skipped"
    findings: List[Finding] = field(default_factory=list)
    pgp_verification: Optional[Dict[str, object]] = None

    def to_dict(self) -> Dict[str, object]:
        return {
            "original": self.reference.original,
            "resolved": self.reference.resolved,
            "index": self.reference.index,
            "filename": self.reference.filename,
            "kind": self.reference.kind.value,
            "checksum_index": self.reference.checksum_index,
            "checksum_algorithm": self.reference.checksum_algorithm,
            "checksum": self.reference.checksum,
            "local_path": str(self.local_path) if self.local_path else None,
            "final_url": self.final_url,
            "size": self.size,
            "sha256": self.sha256,
            "status": self.status,
            "findings": [finding.to_dict() for finding in self.findings],
            "pgp_verification": self.pgp_verification,
        }


class SourcePolicy:
    def __init__(
        self,
        max_download_size: int = 100 * 1024 * 1024,
        timeout: int = 30,
        max_redirects: int = 5,
        auto_key_fetch: bool = True,
        offline: bool = False,
        keyserver: str = "https://keys.openpgp.org",
        trusted_key_dirs: Optional[List[Path]] = None,
        key_cache_dir: Optional[Path] = None,
    ):
        self.max_download_size = max_download_size
        self.timeout = timeout
        self.max_redirects = max_redirects
        self.allowed_redirect_schemes = {"http", "https"}
        self.auto_key_fetch = auto_key_fetch
        self.offline = offline
        self.keyserver = keyserver.rstrip("/")
        self.trusted_key_dirs = [Path(p) for p in (trusted_key_dirs or [])]
        self.key_cache_dir = Path(key_cache_dir) if key_cache_dir else Path.home() / ".cache" / "aurascan" / "pgp-keys"


class SourceParser:
    def parse(self, pkgbuild_path: str, content: str) -> Tuple[List[SourceReference], List[Finding]]:
        srcinfo_path = Path(pkgbuild_path).with_name(".SRCINFO")
        if srcinfo_path.exists():
            return self.parse_srcinfo(srcinfo_path.read_text(encoding="utf-8", errors="replace"), str(srcinfo_path))
        return self.parse_pkgbuild(content, pkgbuild_path)

    def parse_srcinfo(self, content: str, path: str = ".SRCINFO") -> Tuple[List[SourceReference], List[Finding]]:
        sources: List[str] = []
        checksum_values: Dict[str, List[str]] = {}
        validpgpkeys: List[str] = []
        for line in content.splitlines():
            stripped = line.strip()
            if self._srcinfo_source_key(stripped):
                sources.append(stripped.split("=", 1)[1].strip())
            elif self._srcinfo_checksum_key(stripped):
                key = self._srcinfo_checksum_key(stripped)
                checksum_values.setdefault(key, []).append(stripped.split("=", 1)[1].strip())
            elif stripped.startswith("validpgpkeys = "):
                validpgpkeys.append(stripped.split("=", 1)[1].strip())
        checksum_algorithm, checksums = self._choose_checksums(checksum_values)
        refs = self._references_from_tokens(sources, checksums, validpgpkeys, checksum_algorithm)
        return refs, self._signature_metadata_findings(refs, validpgpkeys, path)

    def parse_pkgbuild(self, content: str, path: str = "PKGBUILD") -> Tuple[List[SourceReference], List[Finding]]:
        variables = self._parse_basic_variables(content)
        source_bodies = self._parse_source_bodies(content)
        if not source_bodies:
            return [], []

        findings: List[Finding] = []
        joined_source_body = "\n".join(source_bodies)
        if "$(" in joined_source_body or "`" in joined_source_body or re.search(r"\$\{[^}]+:[^}]+}", joined_source_body):
            findings.append(_finding(
                "SOURCE-PARSER-AMBIGUOUS",
                path,
                Severity.MEDIUM,
                "PKGBUILD source array contains dynamic Bash syntax AuraScan will not evaluate.",
                "Review source acquisition manually. AuraScan does not execute Bash to resolve sources.",
                False,
                joined_source_body.strip()[:300],
            ))
            return [], findings

        source_tokens: List[str] = []
        for source_body in source_bodies:
            source_tokens.extend(self._tokenize_array(source_body))
        source_tokens = [self._interpolate(token, variables) for token in source_tokens]
        checksum_algorithm, checksums = self._parse_checksum_arrays(content)
        validpgpkeys = self._parse_checksums(content, "validpgpkeys")
        refs = self._references_from_tokens(source_tokens, checksums, validpgpkeys, checksum_algorithm)
        findings.extend(self._signature_metadata_findings(refs, validpgpkeys, path))
        return refs, findings

    def _references_from_tokens(self, tokens: List[str], checksums: List[str], validpgpkeys: Optional[List[str]] = None, checksum_algorithm: Optional[str] = None) -> List[SourceReference]:
        refs: List[SourceReference] = []
        normalized_keys = [PgpKeyNormalizer.normalize(key) for key in (validpgpkeys or []) if PgpKeyNormalizer.normalize(key)]
        for index, token in enumerate(tokens):
            original = token
            filename, resolved = self._split_renamed(token)
            checksum = checksums[index] if index < len(checksums) else None
            ref = SourceReference(
                original=original,
                resolved=resolved,
                index=index,
                filename=filename or self._filename_from_source(resolved),
                checksum_index=index,
                checksum=checksum,
                checksum_algorithm=checksum_algorithm if checksum is not None else None,
                validpgpkeys=normalized_keys,
            )
            ref.kind, ref.fragment_type, ref.fragment_value = self._classify(ref)
            refs.append(ref)
        return refs

    def _parse_basic_variables(self, content: str) -> Dict[str, str]:
        variables: Dict[str, str] = {}
        for key in ("pkgname", "pkgver", "pkgrel", "pkgbase"):
            match = re.search(rf"^{key}=([^\n]+)", content, re.M)
            if match:
                value = match.group(1).strip().strip("'\"()")
                if re.search(r"[$`(]", value):
                    continue
                variables[key] = value
        return variables

    def _parse_checksums(self, content: str, key: str) -> List[str]:
        match = re.search(rf"^{key}=\((?P<body>.*?)\)", content, re.M | re.S)
        if match:
            return self._tokenize_array(match.group("body"))
        scalar = re.search(rf"^{key}=([^\n]+)", content, re.M)
        return [scalar.group(1).strip().strip("'\"()")] if scalar else []

    def _parse_checksum_arrays(self, content: str) -> Tuple[Optional[str], List[str]]:
        for prefix, algorithm in CHECKSUM_FAMILIES:
            values: List[str] = []
            for key in self._pkgbuild_checksum_keys(content, prefix):
                values.extend(self._parse_checksums(content, key))
            if values:
                return algorithm, values
        return None, []

    def _pkgbuild_checksum_keys(self, content: str, prefix: str) -> List[str]:
        keys: List[str] = []
        pattern = rf"^({re.escape(prefix)}(?:_[A-Za-z0-9_]+)?)="
        for match in re.finditer(pattern, content, re.M):
            key = match.group(1)
            if key not in keys:
                keys.append(key)
        return keys

    def _parse_source_bodies(self, content: str) -> List[str]:
        bodies: List[str] = []
        pattern = r"^source(?:_[A-Za-z0-9_]+)?=(?:\((?P<array>.*?)\)|(?P<scalar>[^\n]+))"
        for match in re.finditer(pattern, content, re.M | re.S):
            bodies.append(match.group("array") if match.group("array") is not None else match.group("scalar"))
        return bodies

    def _srcinfo_source_key(self, line: str) -> Optional[str]:
        key = line.split("=", 1)[0].strip() if "=" in line else ""
        return key if key == "source" or key.startswith("source_") else None

    def _srcinfo_checksum_key(self, line: str) -> Optional[str]:
        key = line.split("=", 1)[0].strip() if "=" in line else ""
        for prefix, _algorithm in CHECKSUM_FAMILIES:
            if key == prefix or key.startswith(prefix + "_"):
                return key
        return None

    def _choose_checksums(self, checksum_values: Dict[str, List[str]]) -> Tuple[Optional[str], List[str]]:
        for prefix, algorithm in CHECKSUM_FAMILIES:
            selected: List[str] = []
            for key, values in checksum_values.items():
                if key == prefix or key.startswith(prefix + "_"):
                    selected.extend(values)
            if selected:
                return algorithm, selected
        return None, []

    def _signature_metadata_findings(self, refs: List[SourceReference], validpgpkeys: List[str], path: str) -> List[Finding]:
        findings: List[Finding] = []
        weak_keys = [key for key in validpgpkeys if PgpKeyNormalizer.is_weak(key)]
        for key in weak_keys:
            findings.append(_finding(
                "SOURCE-VALIDPGPKEY-WEAK",
                path,
                Severity.MEDIUM,
                "validpgpkeys contains a short or weak key ID.",
                "Use a full 40-hex-character fingerprint as the trust anchor.",
                False,
                key,
            ))
        if not any(ref.kind == SourceKind.signature for ref in refs):
            if validpgpkeys:
                findings.append(_finding(
                    "SIGNATURE-MISSING",
                    path,
                    Severity.MEDIUM,
                    "validpgpkeys is declared but no detached source signature was found.",
                    "Review whether the source is expected to be signature-verified.",
                    False,
                    ", ".join(validpgpkeys),
                ))
            return findings
        if validpgpkeys:
            finding = _finding(
                "SOURCE-VALIDPGPKEYS-DETECTED",
                path,
                Severity.LOW,
                "Detached signature source and validpgpkeys metadata were detected.",
                "AuraScan will verify detached signatures in an isolated keyring during source acquisition.",
                False,
                ", ".join(validpgpkeys),
                EvidenceQuality.weak_heuristic,
            )
            finding.requires_manual_review = False
            findings.append(finding)
            return findings
        findings.append(_finding(
            "SOURCE-SIGNATURE-WITHOUT-VALIDPGPKEYS",
            path,
            Severity.MEDIUM,
            "Detached signature source was detected without validpgpkeys metadata.",
            "Manually verify the signature and expected signer identity.",
            False,
            "",
        ))
        return findings

    def _tokenize_array(self, body: str) -> List[str]:
        return [token for token in re.findall(r"""(?:"([^"]+)"|'([^']+)'|([^\s()]+))""", body) for token in token if token]

    def _interpolate(self, token: str, variables: Dict[str, str]) -> str:
        for key, value in variables.items():
            token = token.replace(f"${key}", value).replace(f"${{{key}}}", value)
        return token

    def _split_renamed(self, token: str) -> Tuple[str, str]:
        if "::" not in token:
            return "", token
        filename, resolved = token.split("::", 1)
        return _safe_filename(filename), resolved

    def _filename_from_source(self, source: str) -> str:
        parsed = urllib.parse.urlparse(source)
        name = Path(parsed.path).name if parsed.path else Path(source).name
        return _safe_filename(name or "source")

    def _classify(self, ref: SourceReference) -> Tuple[SourceKind, Optional[str], Optional[str]]:
        if ref.is_signature:
            return SourceKind.signature, None, None
        source = ref.resolved
        if source.startswith("git+https://"):
            parsed = urllib.parse.urlparse(source[4:])
            fragment = urllib.parse.parse_qs(parsed.fragment)
            for key in ("commit", "tag", "branch"):
                if key in fragment:
                    return SourceKind.git_https, key, fragment[key][0]
            return SourceKind.git_https, None, None
        parsed = urllib.parse.urlparse(source)
        if parsed.scheme in {"http", "https"}:
            return SourceKind.http, None, None
        if parsed.scheme in {"git", "ssh", "svn", "hg", "bzr"} or source.startswith(("git+ssh://", "ssh://")):
            return SourceKind.unsupported, None, None
        if parsed.scheme and parsed.scheme not in {"file"}:
            return SourceKind.unsupported, None, None
        return SourceKind.local, None, None


class PgpKeyNormalizer:
    @staticmethod
    def normalize(value: str) -> str:
        return re.sub(r"[^0-9A-Fa-f]", "", value).upper()

    @staticmethod
    def is_full_fingerprint(value: str) -> bool:
        return bool(re.fullmatch(r"[0-9A-F]{40}", PgpKeyNormalizer.normalize(value)))

    @staticmethod
    def is_weak(value: str) -> bool:
        normalized = PgpKeyNormalizer.normalize(value)
        return bool(normalized) and len(normalized) < 40


@dataclass
class PublicKeySource:
    fingerprint: str
    path: Optional[Path] = None
    source_type: str = "unavailable"
    error: Optional[str] = None


@dataclass
class PublicKeyImportResult:
    fingerprint: str
    imported: bool
    key_source: Optional[PublicKeySource] = None
    gpg_status: str = ""
    error: Optional[str] = None


@dataclass
class PgpVerificationResult:
    signature_path: str
    signed_file_path: str
    verification_status: str
    signer_fingerprint: Optional[str] = None
    normalized_validpgpkeys: List[str] = field(default_factory=list)
    matched_validpgpkey: bool = False
    key_source: Optional[str] = None
    key_fetch_attempted: bool = False
    key_fetch_provider: Optional[str] = None
    key_fetch_error: Optional[str] = None
    gpg_status: str = ""
    related_finding_ids: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "signature_path": self.signature_path,
            "signed_file_path": self.signed_file_path,
            "verification_status": self.verification_status,
            "signer_fingerprint": self.signer_fingerprint,
            "normalized_validpgpkeys": self.normalized_validpgpkeys,
            "matched_validpgpkey": self.matched_validpgpkey,
            "key_source": self.key_source,
            "key_fetch_attempted": self.key_fetch_attempted,
            "key_fetch_provider": self.key_fetch_provider,
            "key_fetch_error": self.key_fetch_error,
            "gpg_status": self.gpg_status,
            "related_finding_ids": self.related_finding_ids,
        }


class PublicKeyProvider:
    def get_key(self, fingerprint: str) -> PublicKeySource:
        return PublicKeySource(fingerprint=PgpKeyNormalizer.normalize(fingerprint), error="KEY_UNAVAILABLE")


class TrustedKeyDirectoryProvider(PublicKeyProvider):
    def __init__(
        self,
        policy: Optional[SourcePolicy] = None,
        opener: Optional[urllib.request.OpenerDirector] = None,
    ):
        self.policy = policy or SourcePolicy()
        self.opener = opener or urllib.request.build_opener()
        self.policy.key_cache_dir.mkdir(parents=True, exist_ok=True)

    def get_key(self, fingerprint: str) -> PublicKeySource:
        normalized = PgpKeyNormalizer.normalize(fingerprint)
        cached = self.policy.key_cache_dir / f"{normalized}.asc"
        if cached.exists():
            return PublicKeySource(normalized, cached, "cache")
        for directory in self.policy.trusted_key_dirs:
            for suffix in (".asc", ".gpg", ".pgp"):
                candidate = directory / f"{normalized}{suffix}"
                if candidate.exists():
                    return PublicKeySource(normalized, candidate, "trusted_key_dir")
        if self.policy.offline or not self.policy.auto_key_fetch:
            return PublicKeySource(normalized, error="KEY_UNAVAILABLE")
        if not PgpKeyNormalizer.is_full_fingerprint(normalized):
            return PublicKeySource(normalized, error="WEAK_KEY_ID")
        url = f"{self.policy.keyserver}/pks/lookup?op=get&options=mr&search=0x{normalized}"
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "AuraScan/0.1"})
            with self.opener.open(request, timeout=self.policy.timeout) as response, cached.open("wb") as handle:
                handle.write(response.read(self.policy.max_download_size + 1))
            if cached.stat().st_size > self.policy.max_download_size:
                cached.unlink(missing_ok=True)
                return PublicKeySource(normalized, error="KEY_FETCH_OVERSIZED")
        except (OSError, urllib.error.URLError, ValueError) as exc:
            cached.unlink(missing_ok=True)
            return PublicKeySource(normalized, error=str(exc))
        return PublicKeySource(normalized, cached, "keyserver")


class ChecksumVerifier:
    def verify(self, result: SourceAcquisitionResult) -> List[Finding]:
        ref = result.reference
        if ref.kind == SourceKind.signature:
            return []
        if ref.checksum is None:
            return [_finding(
                "SOURCE-CHECKSUM-MISSING",
                ref.original,
                Severity.MEDIUM,
                "No checksum was declared for this source.",
                "Add or verify an integrity checksum before trusting this source.",
                False,
                ref.original,
            )]
        if ref.checksum.upper() == "SKIP":
            return [self._skip_finding(ref)]
        if not result.local_path or not result.local_path.exists():
            return []
        digest = _hash_file(result.local_path, ref.checksum_algorithm or "sha256")
        result.sha256 = digest
        if digest != ref.checksum.lower():
            return [_finding(
                "SOURCE-CHECKSUM-MISMATCH",
                str(result.local_path),
                Severity.CRITICAL,
                f"Downloaded source {ref.checksum_algorithm or 'sha256'} does not match the declared checksum.",
                "Do not install. Treat this as tampering or an invalid PKGBUILD until proven otherwise.",
                True,
                f"expected {ref.checksum}; got {digest}",
                EvidenceQuality.confirmed_static_pattern,
            )]
        finding = _finding(
            "SOURCE-CHECKSUM-MATCH",
            str(result.local_path),
            Severity.LOW,
            f"Declared {ref.checksum_algorithm or 'sha256'} checksum matched the acquired source.",
            "Checksum confirms integrity against the PKGBUILD, but it is not proof the source is safe.",
            False,
            digest,
            EvidenceQuality.confirmed_static_pattern,
        )
        finding.requires_manual_review = False
        return [finding]

    def _skip_finding(self, ref: SourceReference) -> Finding:
        if ref.kind == SourceKind.git_https and ref.fragment_type == "commit" and _is_full_commit(ref.fragment_value or ""):
            severity = Severity.LOW
            explanation = "Checksum is SKIP, but git source is pinned to a full commit hash."
        elif ref.kind == SourceKind.git_https and ref.fragment_type == "tag":
            severity = Severity.MEDIUM
            explanation = "Checksum is SKIP for a git tag source; signed tag verification is not implemented yet."
        elif ref.kind == SourceKind.git_https:
            severity = Severity.HIGH
            explanation = "Checksum is SKIP for an unpinned or branch-based git source."
        elif ref.kind == SourceKind.http:
            severity = Severity.HIGH
            explanation = "Checksum is SKIP for an HTTP/HTTPS source archive."
        else:
            severity = Severity.MEDIUM
            explanation = "Checksum is SKIP for this source."
        return _finding(
            "SOURCE-CHECKSUM-SKIP",
            ref.original,
            severity,
            explanation,
            "Manually verify source provenance and integrity.",
            False,
            ref.original,
            EvidenceQuality.weak_heuristic if severity == Severity.LOW else EvidenceQuality.strong_heuristic,
        )


class SignatureVerifier:
    def __init__(
        self,
        policy: Optional[SourcePolicy] = None,
        key_provider: Optional[PublicKeyProvider] = None,
        runner: Callable = subprocess.run,
    ):
        self.policy = policy or SourcePolicy()
        self.key_provider = key_provider or TrustedKeyDirectoryProvider(self.policy)
        self.runner = runner
        self.last_result: Optional[PgpVerificationResult] = None

    def verify(
        self,
        source: SourceReference,
        signature: SourceReference,
        source_path: Optional[Path] = None,
        signature_path: Optional[Path] = None,
    ) -> Tuple[List[Finding], Optional[PgpVerificationResult]]:
        valid_keys = [key for key in source.validpgpkeys if PgpKeyNormalizer.is_full_fingerprint(key)]
        if not signature_path or not source_path:
            result = self._result(source, signature, "signature_unavailable", valid_keys)
            finding = _finding(
                "SIGNATURE-FILE-MISSING",
                source.original,
                Severity.MEDIUM,
                "A detached signature was declared but the signature file was not acquired.",
                "Acquire the signature and verify it manually.",
                False,
                signature.original,
            )
            result.related_finding_ids.append(finding.finding_id)
            self.last_result = result
            return [finding], result
        if not source.validpgpkeys:
            result = self._result(source, signature, "missing_validpgpkeys", [])
            finding = _finding(
                "SOURCE-SIGNATURE-WITHOUT-VALIDPGPKEYS",
                source.original,
                Severity.MEDIUM,
                "Detached signature is present but validpgpkeys is missing.",
                "Review signer identity manually; AuraScan has no fingerprint trust anchor.",
                False,
                str(signature_path),
            )
            result.related_finding_ids.append(finding.finding_id)
            self.last_result = result
            return [finding], result
        weak_keys = [key for key in source.validpgpkeys if not PgpKeyNormalizer.is_full_fingerprint(key)]
        if weak_keys and not valid_keys:
            result = self._result(source, signature, "weak_validpgpkeys", source.validpgpkeys)
            finding = _finding(
                "SOURCE-VALIDPGPKEY-WEAK",
                source.original,
                Severity.MEDIUM,
                "validpgpkeys contains only short or weak key IDs.",
                "Use a full 40-hex-character fingerprint before automatic PGP verification.",
                False,
                ", ".join(weak_keys),
            )
            result.related_finding_ids.append(finding.finding_id)
            self.last_result = result
            return [finding], result
        if shutil.which("gpg") is None:
            result = self._result(source, signature, "gpg_unavailable", valid_keys)
            finding = _finding(
                "SIGNATURE-VERIFICATION-UNAVAILABLE",
                source.original,
                Severity.MEDIUM,
                "gpg is unavailable, so AuraScan could not verify the detached signature.",
                "Install GnuPG or verify the signature manually.",
                False,
                str(signature_path),
            )
            result.related_finding_ids.append(finding.finding_id)
            self.last_result = result
            return [finding], result

        key_sources: List[PublicKeySource] = []
        key_findings: List[Finding] = []
        for fingerprint in valid_keys:
            key_source = self.key_provider.get_key(fingerprint)
            key_sources.append(key_source)
            if key_source.path is None:
                finding = _finding(
                    "KEY_UNAVAILABLE",
                    source.original,
                    Severity.MEDIUM,
                    "Public key for validpgpkeys fingerprint is unavailable.",
                    "AuraScan could not complete signature verification. Review manually or retry with key fetching enabled.",
                    False,
                    key_source.error or fingerprint,
                )
                key_findings.append(finding)
        if not any(item.path for item in key_sources):
            result = self._result(source, signature, "key_unavailable", valid_keys)
            result.key_fetch_attempted = any(item.source_type == "keyserver" or item.error not in (None, "KEY_UNAVAILABLE", "WEAK_KEY_ID") for item in key_sources)
            result.key_fetch_provider = self.policy.keyserver if self.policy.auto_key_fetch and not self.policy.offline else None
            result.key_fetch_error = "; ".join(filter(None, [item.error for item in key_sources])) or None
            result.related_finding_ids.extend(f.finding_id for f in key_findings)
            self.last_result = result
            return key_findings, result

        gnupg_home = Path(tempfile.mkdtemp(prefix="aurascan-gnupg-"))
        os.chmod(gnupg_home, 0o700)
        try:
            import_status = ""
            imported_source = None
            for key_source in key_sources:
                if key_source.path is None:
                    continue
                imported_source = key_source
                import_proc = self.runner(
                    ["gpg", "--homedir", str(gnupg_home), "--batch", "--no-tty", "--import", str(key_source.path)],
                    capture_output=True,
                    text=True,
                    timeout=self.policy.timeout,
                    check=False,
                    env=self._gpg_env(gnupg_home),
                )
                import_status += (import_proc.stdout or "") + (import_proc.stderr or "")
            verify_proc = self.runner(
                ["gpg", "--homedir", str(gnupg_home), "--batch", "--no-tty", "--status-fd", "1", "--no-auto-key-retrieve", "--verify", str(signature_path), str(source_path)],
                capture_output=True,
                text=True,
                timeout=self.policy.timeout,
                check=False,
                env=self._gpg_env(gnupg_home),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            result = self._result(source, signature, "verification_error", valid_keys)
            finding = _finding(
                "SIGNATURE-VERIFICATION-ERROR",
                source.original,
                Severity.MEDIUM,
                f"Detached signature verification failed to run: {exc}",
                "Review the source signature manually.",
                False,
                str(signature_path),
            )
            result.related_finding_ids.append(finding.finding_id)
            self.last_result = result
            return [finding], result
        finally:
            shutil.rmtree(gnupg_home, ignore_errors=True)

        gpg_status = (verify_proc.stdout or "") + (verify_proc.stderr or "")
        signer = self._parse_signer_fingerprint(gpg_status)
        matched = signer in valid_keys if signer else False
        result = self._result(source, signature, "valid" if verify_proc.returncode == 0 else "invalid", valid_keys)
        result.signer_fingerprint = signer
        result.matched_validpgpkey = matched
        result.key_source = imported_source.source_type if imported_source else None
        result.key_fetch_attempted = any(item.source_type == "keyserver" for item in key_sources)
        result.key_fetch_provider = self.policy.keyserver if result.key_fetch_attempted else None
        result.gpg_status = self._sanitize_status(import_status + gpg_status)

        if verify_proc.returncode != 0:
            finding = _finding(
                "SIGNATURE-INVALID",
                source.original,
                Severity.CRITICAL,
                "Detached source signature is invalid.",
                "Do not install. Treat this as tampering or an invalid source until proven otherwise.",
                True,
                str(signature_path),
                EvidenceQuality.confirmed_static_pattern,
            )
        elif not matched:
            result.verification_status = "fingerprint_mismatch"
            finding = _finding(
                "SIGNATURE-FINGERPRINT-MISMATCH",
                source.original,
                Severity.HIGH,
                "Detached signature is valid, but signer fingerprint does not match validpgpkeys.",
                "Review signer identity manually before trusting this source.",
                False,
                signer or "unknown signer",
            )
        else:
            finding = _finding(
                "SIGNATURE-VERIFIED",
                source.original,
                Severity.LOW,
                "Detached signature is valid and signer fingerprint matches validpgpkeys.",
                "Signature confirms integrity against the declared signer, but it is not proof the source is safe.",
                False,
                signer or "",
                EvidenceQuality.confirmed_static_pattern,
            )
            finding.requires_manual_review = False
        result.related_finding_ids.append(finding.finding_id)
        self.last_result = result
        return key_findings + [finding], result

    def _result(self, source: SourceReference, signature: SourceReference, status: str, valid_keys: List[str]) -> PgpVerificationResult:
        return PgpVerificationResult(
            signature_path=signature.original,
            signed_file_path=source.original,
            verification_status=status,
            normalized_validpgpkeys=valid_keys,
        )

    def _gpg_env(self, gnupg_home: Path) -> Dict[str, str]:
        return {
            "GNUPGHOME": str(gnupg_home),
            "HOME": str(gnupg_home),
            "GPG_TTY": "",
        }

    def _parse_signer_fingerprint(self, status: str) -> Optional[str]:
        for line in status.splitlines():
            if line.startswith("[GNUPG:] VALIDSIG "):
                parts = line.split()
                if len(parts) >= 3:
                    return PgpKeyNormalizer.normalize(parts[2])
        for line in status.splitlines():
            if line.startswith("[GNUPG:] GOODSIG "):
                parts = line.split()
                if len(parts) >= 3:
                    return PgpKeyNormalizer.normalize(parts[2])
        return None

    def _sanitize_status(self, status: str) -> str:
        return "\n".join(line[:500] for line in status.splitlines() if "[GNUPG:]" in line or "gpg:" in line)[:4000]


class HttpSourceFetcher:
    def __init__(self, policy: Optional[SourcePolicy] = None, opener: Optional[urllib.request.OpenerDirector] = None):
        self.policy = policy or SourcePolicy()
        self.opener = opener or urllib.request.build_opener(_SafeRedirectHandler(self.policy))

    def fetch(self, ref: SourceReference, output_dir: Path) -> SourceAcquisitionResult:
        output_path = output_dir / ref.filename
        digest = hashlib.sha256()
        size = 0
        try:
            request = urllib.request.Request(ref.resolved, headers={"User-Agent": "AuraScan/0.1"})
            with self.opener.open(request, timeout=self.policy.timeout) as response, output_path.open("wb") as handle:
                final_url = response.geturl()
                if urllib.parse.urlparse(final_url).scheme not in self.policy.allowed_redirect_schemes:
                    raise ValueError(f"redirected to unsupported scheme: {final_url}")
                while True:
                    chunk = response.read(65536)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > self.policy.max_download_size:
                        raise ValueError("download exceeded maximum size")
                    digest.update(chunk)
                    handle.write(chunk)
        except (OSError, urllib.error.URLError, ValueError) as exc:
            if output_path.exists():
                output_path.unlink()
            return SourceAcquisitionResult(
                reference=ref,
                status="failed",
                findings=[_finding(
                    "SOURCE-HTTP-FETCH-FAILED",
                    ref.original,
                    Severity.HIGH,
                    f"HTTP/HTTPS source acquisition failed: {exc}",
                    "Do not treat this package as fully inspected. Retry or review the source manually.",
                    False,
                    ref.original,
                )],
            )
        return SourceAcquisitionResult(ref, output_path, final_url, size, digest.hexdigest(), "acquired", [])


class GitSourceFetcher:
    def __init__(self, policy: Optional[SourcePolicy] = None, runner: Callable = subprocess.run):
        self.policy = policy or SourcePolicy()
        self.runner = runner

    def fetch(self, ref: SourceReference, output_dir: Path) -> SourceAcquisitionResult:
        findings = self.classification_findings(ref)
        if ref.fragment_type == "commit" and not _is_full_commit(ref.fragment_value or ""):
            findings.append(_finding(
                "SOURCE-GIT-COMMIT-NOT-FULL",
                ref.original,
                Severity.HIGH,
                "git+https source commit fragment is not a full 40-character commit hash.",
                "Pin to a full commit hash before relying on automated source acquisition.",
                False,
                ref.fragment_value or "",
            ))
            return SourceAcquisitionResult(ref, status="skipped", findings=findings)
        if shutil.which("git") is None:
            findings.append(_finding(
                "SOURCE-GIT-UNAVAILABLE",
                ref.original,
                Severity.MEDIUM,
                "git is not available, so AuraScan could not acquire this source.",
                "Install git or review the source manually.",
                False,
                ref.original,
            ))
            return SourceAcquisitionResult(ref, status="skipped", findings=findings)

        repo_url = self._repo_url(ref)
        checkout_dir = output_dir / ref.filename
        env = {
            "HOME": str(output_dir / "empty-home"),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ASKPASS": "true",
            "SSH_AUTH_SOCK": "",
            "GIT_LFS_SKIP_SMUDGE": "1",
        }
        Path(env["HOME"]).mkdir(parents=True, exist_ok=True)
        try:
            self.runner(
                ["git", "-c", "credential.helper=", "-c", "core.hooksPath=/dev/null", "clone", "--no-recurse-submodules", "--filter=blob:none", repo_url, str(checkout_dir)],
                capture_output=True,
                text=True,
                timeout=self.policy.timeout,
                env=env,
                check=True,
            )
            if ref.fragment_type in {"commit", "tag", "branch"} and ref.fragment_value:
                self.runner(
                    ["git", "-C", str(checkout_dir), "-c", "credential.helper=", "-c", "core.hooksPath=/dev/null", "checkout", "--detach" if ref.fragment_type != "branch" else ref.fragment_value, ref.fragment_value] if ref.fragment_type != "branch" else ["git", "-C", str(checkout_dir), "-c", "credential.helper=", "-c", "core.hooksPath=/dev/null", "checkout", ref.fragment_value],
                    capture_output=True,
                    text=True,
                    timeout=self.policy.timeout,
                    env=env,
                    check=True,
                )
        except (subprocess.SubprocessError, OSError) as exc:
            shutil.rmtree(checkout_dir, ignore_errors=True)
            findings.append(_finding(
                "SOURCE-GIT-FETCH-FAILED",
                ref.original,
                Severity.HIGH,
                f"git+https source acquisition failed: {exc}",
                "Do not treat this package as fully inspected. Review the git source manually.",
                False,
                ref.original,
            ))
            return SourceAcquisitionResult(ref, status="failed", findings=findings)
        return SourceAcquisitionResult(ref, checkout_dir, ref.resolved, 0, None, "acquired", findings)

    def classification_findings(self, ref: SourceReference) -> List[Finding]:
        if ref.fragment_type == "commit" and _is_full_commit(ref.fragment_value or ""):
            return [_finding(
                "SOURCE-GIT-PINNED-COMMIT",
                ref.original,
                Severity.LOW,
                "git+https source is pinned to a full commit hash.",
                "Pinned commits reduce source drift risk, but do not prove safety.",
                False,
                ref.fragment_value or "",
                EvidenceQuality.weak_heuristic,
            )]
        if ref.fragment_type == "tag":
            return [_finding(
                "SOURCE-GIT-TAG",
                ref.original,
                Severity.MEDIUM,
                "git+https source is pinned to a tag; signed tag verification is not implemented.",
                "Verify tag provenance manually.",
                False,
                ref.fragment_value or "",
            )]
        if ref.fragment_type == "branch":
            return [_finding(
                "SOURCE-GIT-BRANCH",
                ref.original,
                Severity.HIGH,
                "git+https source tracks a branch, which can change over time.",
                "Prefer a full commit hash or manually review the exact revision.",
                False,
                ref.fragment_value or "",
            )]
        return [_finding(
            "SOURCE-GIT-UNPINNED",
            ref.original,
            Severity.HIGH,
            "git+https source has no commit, tag, or branch fragment.",
            "Pin the source before relying on automated acquisition.",
            False,
            ref.original,
        )]

    def _repo_url(self, ref: SourceReference) -> str:
        parsed = urllib.parse.urlparse(ref.resolved[4:] if ref.resolved.startswith("git+") else ref.resolved)
        return urllib.parse.urlunparse(parsed._replace(fragment=""))


class SourceFetcher:
    def __init__(
        self,
        policy: Optional[SourcePolicy] = None,
        http_fetcher: Optional[HttpSourceFetcher] = None,
        git_fetcher: Optional[GitSourceFetcher] = None,
        checksum_verifier: Optional[ChecksumVerifier] = None,
        signature_verifier: Optional[SignatureVerifier] = None,
    ):
        self.policy = policy or SourcePolicy()
        self.http_fetcher = http_fetcher or HttpSourceFetcher(self.policy)
        self.git_fetcher = git_fetcher or GitSourceFetcher(self.policy)
        self.checksum_verifier = checksum_verifier or ChecksumVerifier()
        self.signature_verifier = signature_verifier or SignatureVerifier()
        self.last_output_dir: Optional[Path] = None

    def acquire_all(self, refs: List[SourceReference], pkg_dir: Path) -> List[SourceAcquisitionResult]:
        output_dir = Path(tempfile.mkdtemp(prefix="aurascan-sources-"))
        self.last_output_dir = output_dir
        results: List[SourceAcquisitionResult] = []
        for ref in refs:
            result = self.acquire(ref, pkg_dir, output_dir)
            result.findings.extend(self.checksum_verifier.verify(result))
            results.append(result)
        by_ref_index = {result.reference.index: result for result in results}
        for source_ref, signature_ref in self._matched_signatures(refs):
            source_result = by_ref_index.get(source_ref.index)
            signature_result = by_ref_index.get(signature_ref.index)
            if source_result is None:
                continue
            findings, pgp_result = self.signature_verifier.verify(
                source_ref,
                signature_ref,
                source_result.local_path,
                signature_result.local_path if signature_result else None,
            )
            if pgp_result:
                source_result.pgp_verification = pgp_result.to_dict()
            source_result.findings.extend(findings)
            if pgp_result and pgp_result.verification_status == "valid" and pgp_result.matched_validpgpkey:
                source_result.findings = [
                    finding for finding in source_result.findings
                    if finding.rule_id != "SOURCE-CHECKSUM-SKIP"
                ]
        return results

    def acquire(self, ref: SourceReference, pkg_dir: Path, output_dir: Path) -> SourceAcquisitionResult:
        if ref.kind == SourceKind.local:
            path = Path(ref.resolved)
            path = path if path.is_absolute() else pkg_dir / path
            if not path.exists():
                return SourceAcquisitionResult(ref, status="failed", findings=[_finding(
                    "SOURCE-LOCAL-MISSING",
                    str(path),
                    Severity.MEDIUM,
                    "Declared local source does not exist.",
                    "Verify the source path or fetch it manually before deep static scanning.",
                    False,
                    ref.original,
                )])
            return SourceAcquisitionResult(ref, path, None, path.stat().st_size, _sha256_file(path), "acquired", [])
        if ref.kind == SourceKind.http:
            return self.http_fetcher.fetch(ref, output_dir)
        if ref.kind == SourceKind.git_https:
            return self.git_fetcher.fetch(ref, output_dir)
        if ref.kind == SourceKind.signature:
            acquired = self._acquire_signature(ref, pkg_dir, output_dir)
            acquired.findings.append(_finding(
                "SOURCE-SIGNATURE-DETECTED",
                ref.original,
                Severity.LOW,
                "Detached signature source detected.",
                "AuraScan will verify it in an isolated keyring when the signed source is also available.",
                False,
                ref.original,
                EvidenceQuality.weak_heuristic,
            ))
            acquired.findings[-1].requires_manual_review = False
            return acquired
        return SourceAcquisitionResult(ref, status="unsupported", findings=[_finding(
            "SOURCE-UNSUPPORTED",
            ref.original,
            Severity.MEDIUM,
            f"Unsupported source scheme or VCS type for automated acquisition: {ref.original}",
            "This can be normal for AUR packages, but AuraScan could only continue partially. Review this source manually.",
            False,
            ref.original,
        )])

    def _acquire_signature(self, ref: SourceReference, pkg_dir: Path, output_dir: Path) -> SourceAcquisitionResult:
        parsed = urllib.parse.urlparse(ref.resolved)
        if parsed.scheme in {"http", "https"}:
            temp_ref = SourceReference(
                ref.original,
                ref.resolved,
                ref.index,
                ref.filename,
                ref.checksum_index,
                ref.checksum,
                ref.checksum_algorithm,
                SourceKind.http,
                validpgpkeys=ref.validpgpkeys,
            )
            result = self.http_fetcher.fetch(temp_ref, output_dir)
            result.reference = ref
            return result
        path = Path(ref.resolved)
        path = path if path.is_absolute() else pkg_dir / path
        if path.exists():
            return SourceAcquisitionResult(ref, path, None, path.stat().st_size, _sha256_file(path), "acquired", [])
        return SourceAcquisitionResult(ref, status="failed", findings=[_finding(
            "SIGNATURE-FILE-MISSING",
            str(path),
            Severity.MEDIUM,
            "Declared detached signature file was not acquired.",
            "Review signature availability manually.",
            False,
            ref.original,
        )])

    def _matched_signatures(self, refs: List[SourceReference]) -> List[Tuple[SourceReference, SourceReference]]:
        signatures = [ref for ref in refs if ref.kind == SourceKind.signature]
        sources = [ref for ref in refs if ref.kind != SourceKind.signature]
        matches: List[Tuple[SourceReference, SourceReference]] = []
        for signature in signatures:
            sig_base = self._signature_base(signature.filename) or self._signature_base(Path(urllib.parse.urlparse(signature.resolved).path).name)
            matched = next((source for source in sources if source.filename == sig_base), None)
            if matched is None:
                matched = next((source for source in sources if source.index == signature.index - 1), None)
            if matched:
                matches.append((matched, signature))
        return matches

    def _signature_base(self, name: str) -> str:
        for suffix in (".sig", ".asc"):
            if name.endswith(suffix):
                return name[:-len(suffix)]
        return ""


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, policy: SourcePolicy):
        self.policy = policy
        self.redirect_count = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.redirect_count += 1
        parsed = urllib.parse.urlparse(newurl)
        if self.redirect_count > self.policy.max_redirects:
            raise urllib.error.HTTPError(req.full_url, code, "too many redirects", headers, fp)
        if parsed.scheme not in self.policy.allowed_redirect_schemes:
            raise urllib.error.HTTPError(req.full_url, code, f"unsupported redirect scheme: {parsed.scheme}", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _safe_filename(name: str) -> str:
    name = Path(name).name
    name = re.sub(r"[^A-Za-z0-9._+-]", "_", name)
    return name or "source"


def _sha256_file(path: Path) -> str:
    return _hash_file(path, "sha256")


def _hash_file(path: Path, algorithm: str) -> str:
    if algorithm == "sha512":
        digest = hashlib.sha512()
    elif algorithm == "sha384":
        digest = hashlib.sha384()
    elif algorithm == "sha256":
        digest = hashlib.sha256()
    elif algorithm == "sha224":
        digest = hashlib.sha224()
    elif algorithm == "sha1":
        digest = hashlib.sha1()
    elif algorithm == "md5":
        digest = hashlib.md5()
    elif algorithm == "b2":
        digest = hashlib.blake2b()
    else:
        raise ValueError(f"unsupported checksum algorithm: {algorithm}")
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_full_commit(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{40}", value))


def _finding(
    rule_id: str,
    file_path: str,
    severity: Severity,
    explanation: str,
    recommendation: str,
    blocks: bool,
    evidence: str = "",
    evidence_quality: EvidenceQuality = EvidenceQuality.strong_heuristic,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        package_name="unknown",
        package_version="unknown",
        phase=Phase.source_archive_scan,
        source=Source.deterministic_rule,
        severity=severity,
        confidence=Confidence.CONFIRMED if evidence_quality == EvidenceQuality.confirmed_static_pattern else Confidence.HIGH,
        evidence_quality=evidence_quality,
        file_path=file_path,
        explanation=explanation,
        recommendation=recommendation,
        blocks_installation=blocks,
        requires_manual_review=not blocks,
        evidence_snippet=evidence,
    )
