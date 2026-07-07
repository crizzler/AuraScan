import hashlib
import os
import subprocess
from pathlib import Path

import pytest

from aurascan.core.models import Severity
from aurascan.core.source_acquisition import (
    ChecksumVerifier,
    GitSourceFetcher,
    HttpSourceFetcher,
    PgpKeyNormalizer,
    PublicKeySource,
    SignatureVerifier,
    SourceAcquisitionResult,
    SourceFetcher,
    SourceKind,
    SourceParser,
    SourcePolicy,
    SourceReference,
    TrustedKeyDirectoryProvider,
)


def parse_pkgbuild(content: str):
    return SourceParser().parse_pkgbuild(content, "PKGBUILD")


def test_parse_local_source():
    refs, findings = parse_pkgbuild("pkgname=demo\nsource=(local.tar.gz)\nsha256sums=(SKIP)\n")

    assert findings == []
    assert refs[0].kind == SourceKind.local
    assert refs[0].resolved == "local.tar.gz"
    assert refs[0].filename == "local.tar.gz"


def test_parse_https_source():
    refs, _ = parse_pkgbuild('source=("https://example.invalid/demo.tar.gz")\nsha256sums=(abc)\n')

    assert refs[0].kind == SourceKind.http
    assert refs[0].filename == "demo.tar.gz"


def test_parse_renamed_source_syntax():
    refs, _ = parse_pkgbuild('source=("renamed.tar.gz::https://example.invalid/source.tar.gz")\nsha256sums=(abc)\n')

    assert refs[0].kind == SourceKind.http
    assert refs[0].filename == "renamed.tar.gz"
    assert refs[0].resolved == "https://example.invalid/source.tar.gz"


def test_parse_basic_variable_interpolation():
    refs, _ = parse_pkgbuild('pkgname=demo\npkgver=1.2.3\nsource=("https://example.invalid/$pkgname-${pkgver}.tar.gz")\nsha256sums=(abc)\n')

    assert refs[0].resolved == "https://example.invalid/demo-1.2.3.tar.gz"


def test_parse_srcinfo_source_metadata():
    content = """
pkgbase = demo
	source = https://example.invalid/demo.tar.gz
	sha256sums = abc
"""
    refs, findings = SourceParser().parse_srcinfo(content)

    assert findings == []
    assert refs[0].kind == SourceKind.http
    assert refs[0].checksum == "abc"


def test_parse_srcinfo_sha512_source_metadata():
    content = """
pkgbase = demo
	source = https://example.invalid/demo.tar.gz
	sha512sums = abc
"""
    refs, findings = SourceParser().parse_srcinfo(content)

    assert findings == []
    assert refs[0].checksum == "abc"
    assert refs[0].checksum_algorithm == "sha512"


def test_parse_pkgbuild_b2_source_metadata():
    refs, _ = parse_pkgbuild('source=("https://example.invalid/demo.tar.gz")\nb2sums=(abc)\n')

    assert refs[0].checksum == "abc"
    assert refs[0].checksum_algorithm == "b2"


def test_parse_srcinfo_md5_source_metadata():
    content = """
pkgbase = demo
	source = https://example.invalid/demo.tar.gz
	md5sums = abc
"""
    refs, findings = SourceParser().parse_srcinfo(content)

    assert findings == []
    assert refs[0].checksum == "abc"
    assert refs[0].checksum_algorithm == "md5"


def test_parse_pkgbuild_sha1_source_metadata():
    refs, _ = parse_pkgbuild('source=("https://example.invalid/demo.tar.gz")\nsha1sums=(abc)\n')

    assert refs[0].checksum == "abc"
    assert refs[0].checksum_algorithm == "sha1"


def test_parse_srcinfo_arch_specific_source_metadata():
    content = """
pkgbase = demo
	source = https://example.invalid/common.tar.gz
	source_x86_64 = https://example.invalid/x86_64.tar.gz
	sha256sums = common
	sha256sums_x86_64 = x86_64
"""
    refs, findings = SourceParser().parse_srcinfo(content)

    assert findings == []
    assert [ref.resolved for ref in refs] == [
        "https://example.invalid/common.tar.gz",
        "https://example.invalid/x86_64.tar.gz",
    ]
    assert [ref.checksum for ref in refs] == ["common", "x86_64"]
    assert all(ref.checksum_algorithm == "sha256" for ref in refs)


def test_parse_pkgbuild_arch_specific_source_metadata():
    refs, findings = parse_pkgbuild(
        'source=("common.tar.gz")\n'
        'source_x86_64=("https://example.invalid/x86_64.tar.gz")\n'
        'sha256sums=(common)\n'
        'sha256sums_x86_64=(x86_64)\n'
    )

    assert findings == []
    assert [ref.resolved for ref in refs] == [
        "common.tar.gz",
        "https://example.invalid/x86_64.tar.gz",
    ]
    assert [ref.checksum for ref in refs] == ["common", "x86_64"]


def test_reject_ambiguous_dynamic_source_safely():
    refs, findings = parse_pkgbuild('source=("https://example.invalid/$(uname).tar.gz")\n')

    assert refs == []
    assert any(f.rule_id == "SOURCE-PARSER-AMBIGUOUS" for f in findings)


def test_reject_unsupported_scheme_safely():
    refs, _ = parse_pkgbuild('source=("git://example.invalid/repo.git")\nsha256sums=(SKIP)\n')

    assert refs[0].kind == SourceKind.unsupported


@pytest.mark.parametrize(
    ("source", "fragment_type"),
    [
        ("git+https://example.invalid/repo.git#commit=0123456789abcdef0123456789abcdef01234567", "commit"),
        ("git+https://example.invalid/repo.git#tag=v1.0", "tag"),
        ("git+https://example.invalid/repo.git#branch=main", "branch"),
        ("git+https://example.invalid/repo.git", None),
    ],
)
def test_classify_git_sources(source, fragment_type):
    refs, _ = parse_pkgbuild(f'source=("{source}")\nsha256sums=(SKIP)\n')

    assert refs[0].kind == SourceKind.git_https
    assert refs[0].fragment_type == fragment_type


def test_skip_on_https_archive_creates_manual_review_warning():
    refs, _ = parse_pkgbuild('source=("https://example.invalid/demo.tar.gz")\nsha256sums=(SKIP)\n')
    result = SourceAcquisitionResult(refs[0], status="failed")

    findings = ChecksumVerifier().verify(result)

    assert any(f.rule_id == "SOURCE-CHECKSUM-SKIP" and f.severity == Severity.HIGH and f.requires_manual_review for f in findings)


def test_skip_on_git_full_commit_creates_lower_warning():
    refs, _ = parse_pkgbuild('source=("git+https://example.invalid/repo.git#commit=0123456789abcdef0123456789abcdef01234567")\nsha256sums=(SKIP)\n')
    result = SourceAcquisitionResult(refs[0], status="skipped")

    findings = ChecksumVerifier().verify(result)

    assert findings[0].severity == Severity.LOW


def test_skip_on_git_branch_creates_high_manual_review():
    refs, _ = parse_pkgbuild('source=("git+https://example.invalid/repo.git#branch=main")\nsha256sums=(SKIP)\n')
    result = SourceAcquisitionResult(refs[0], status="skipped")

    findings = ChecksumVerifier().verify(result)

    assert findings[0].severity == Severity.HIGH
    assert findings[0].requires_manual_review is True


def test_checksum_match(tmp_path: Path):
    source = tmp_path / "src.tar.gz"
    source.write_text("hello")
    digest = hashlib.sha256(b"hello").hexdigest()
    ref = SourceReference("src.tar.gz", "src.tar.gz", 0, "src.tar.gz", 0, digest, "sha256", SourceKind.local)
    result = SourceAcquisitionResult(ref, source, size=5, sha256=digest, status="acquired")

    findings = ChecksumVerifier().verify(result)

    assert findings[0].rule_id == "SOURCE-CHECKSUM-MATCH"
    assert findings[0].requires_manual_review is False


def test_md5_checksum_match(tmp_path: Path):
    source = tmp_path / "src.tar.gz"
    source.write_text("hello")
    digest = hashlib.md5(b"hello").hexdigest()
    ref = SourceReference("src.tar.gz", "src.tar.gz", 0, "src.tar.gz", 0, digest, "md5", SourceKind.local)
    result = SourceAcquisitionResult(ref, source, size=5, status="acquired")

    findings = ChecksumVerifier().verify(result)

    assert findings[0].rule_id == "SOURCE-CHECKSUM-MATCH"


def test_checksum_mismatch_blocks(tmp_path: Path):
    source = tmp_path / "src.tar.gz"
    source.write_text("hello")
    ref = SourceReference("src.tar.gz", "src.tar.gz", 0, "src.tar.gz", 0, "0" * 64, "sha256", SourceKind.local)
    result = SourceAcquisitionResult(ref, source, size=5, status="acquired")

    findings = ChecksumVerifier().verify(result)

    assert findings[0].rule_id == "SOURCE-CHECKSUM-MISMATCH"
    assert findings[0].blocks_installation is True


def test_missing_checksum_warning():
    ref = SourceReference("src.tar.gz", "src.tar.gz", 0, "src.tar.gz", 0, None, None, SourceKind.local)

    findings = ChecksumVerifier().verify(SourceAcquisitionResult(ref))

    assert findings[0].rule_id == "SOURCE-CHECKSUM-MISSING"
    assert findings[0].requires_manual_review is True


def test_detached_sig_and_validpgpkeys_detected():
    refs, findings = parse_pkgbuild('source=("demo.tar.gz" "demo.tar.gz.sig")\nsha256sums=(SKIP SKIP)\nvalidpgpkeys=("ABCDEF")\n')

    assert refs[1].kind == SourceKind.signature
    assert any(f.rule_id == "SOURCE-VALIDPGPKEYS-DETECTED" for f in findings)


class FakeResponse:
    def __init__(self, body: bytes, final_url: str):
        self.body = body
        self.final_url = final_url
        self.offset = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def geturl(self):
        return self.final_url

    def read(self, size=-1):
        if self.offset >= len(self.body):
            return b""
        end = len(self.body) if size < 0 else min(len(self.body), self.offset + size)
        chunk = self.body[self.offset:end]
        self.offset = end
        return chunk


class FakeOpener:
    def __init__(self, body: bytes, final_url: str = "https://example.invalid/src.tar.gz"):
        self.body = body
        self.final_url = final_url

    def open(self, request, timeout):
        return FakeResponse(self.body, self.final_url)


def test_http_download_success_using_mocked_transport(tmp_path: Path):
    ref = SourceReference("https://example.invalid/src.tar.gz", "https://example.invalid/src.tar.gz", 0, "src.tar.gz", 0, None, None, SourceKind.http)
    fetcher = HttpSourceFetcher(SourcePolicy(max_download_size=100), opener=FakeOpener(b"hello"))

    result = fetcher.fetch(ref, tmp_path)

    assert result.status == "acquired"
    assert result.size == 5
    assert result.local_path.read_bytes() == b"hello"


def test_redirect_to_unsupported_scheme_rejected(tmp_path: Path):
    ref = SourceReference("https://example.invalid/src.tar.gz", "https://example.invalid/src.tar.gz", 0, "src.tar.gz", 0, None, None, SourceKind.http)
    fetcher = HttpSourceFetcher(SourcePolicy(max_download_size=100), opener=FakeOpener(b"hello", "file:///tmp/src.tar.gz"))

    result = fetcher.fetch(ref, tmp_path)

    assert result.status == "failed"
    assert any(f.rule_id == "SOURCE-HTTP-FETCH-FAILED" for f in result.findings)


def test_oversized_download_rejected(tmp_path: Path):
    ref = SourceReference("https://example.invalid/src.tar.gz", "https://example.invalid/src.tar.gz", 0, "src.tar.gz", 0, None, None, SourceKind.http)
    fetcher = HttpSourceFetcher(SourcePolicy(max_download_size=3), opener=FakeOpener(b"hello"))

    result = fetcher.fetch(ref, tmp_path)

    assert result.status == "failed"
    assert result.local_path is None


def test_signature_only_flow_reports_key_unavailable_when_pgp_key_missing():
    refs, parser_findings = parse_pkgbuild('source=("demo.tar.gz" "demo.tar.gz.sig")\nsha256sums=(SKIP SKIP)\nvalidpgpkeys=("ABCDEF")\n')

    fetcher = SourceFetcher()
    results = fetcher.acquire_all(refs, Path("/tmp/does-not-matter"))
    findings = parser_findings + [finding for result in results for finding in result.findings]

    assert any(f.rule_id in {"SOURCE-VALIDPGPKEY-WEAK", "KEY_UNAVAILABLE"} for f in findings)


def test_git_fetch_uses_isolated_home_and_disables_credentials(tmp_path: Path, monkeypatch):
    ref = SourceReference(
        "git+https://example.invalid/repo.git#commit=0123456789abcdef0123456789abcdef01234567",
        "git+https://example.invalid/repo.git#commit=0123456789abcdef0123456789abcdef01234567",
        0,
        "repo",
        0,
        "SKIP",
        "sha256",
        SourceKind.git_https,
        "commit",
        "0123456789abcdef0123456789abcdef01234567",
    )
    calls = []

    def fake_runner(args, **kwargs):
        calls.append((args, kwargs))
        if "clone" in args:
            Path(args[-1]).mkdir(parents=True)
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr("aurascan.core.source_acquisition.shutil.which", lambda name: "/usr/bin/git")
    fetcher = GitSourceFetcher(runner=fake_runner)

    result = fetcher.fetch(ref, tmp_path)

    assert result.status == "acquired"
    assert all(call[1]["env"]["GIT_TERMINAL_PROMPT"] == "0" for call in calls)
    assert all(call[1]["env"]["GIT_CONFIG_NOSYSTEM"] == "1" for call in calls)
    assert all(call[1]["env"]["SSH_AUTH_SOCK"] == "" for call in calls)
    assert all("-c" in call[0] and "credential.helper=" in call[0] for call in calls)


FULL_FP = "0123456789ABCDEF0123456789ABCDEF01234567"
OTHER_FP = "FEDCBA9876543210FEDCBA9876543210FEDCBA98"


def source_and_signature(tmp_path: Path, fingerprint: str = FULL_FP, sig_name: str = "src.tar.gz.sig"):
    source = tmp_path / "src.tar.gz"
    signature = tmp_path / sig_name
    key = tmp_path / f"{fingerprint}.asc"
    source.write_text("source")
    signature.write_text("signature")
    key.write_text("public key")
    source_ref = SourceReference("src.tar.gz", "src.tar.gz", 0, "src.tar.gz", 0, "SKIP", "sha256", SourceKind.local, validpgpkeys=[fingerprint])
    sig_ref = SourceReference(sig_name, sig_name, 1, sig_name, 1, "SKIP", "sha256", SourceKind.signature, validpgpkeys=[fingerprint])
    return source, signature, key, source_ref, sig_ref


class StaticKeyProvider:
    def __init__(self, path=None, fingerprint=FULL_FP, error=None):
        self.path = path
        self.fingerprint = fingerprint
        self.error = error
        self.requests = []

    def get_key(self, fingerprint):
        self.requests.append(fingerprint)
        if self.path:
            return PublicKeySource(fingerprint, self.path, "test")
        return PublicKeySource(fingerprint, error=self.error or "KEY_UNAVAILABLE")


def gpg_runner(status_fingerprint=FULL_FP, verify_returncode=0, calls=None):
    def runner(args, **kwargs):
        if calls is not None:
            calls.append((args, kwargs))
        if "--import" in args:
            return subprocess.CompletedProcess(args, 0, "[GNUPG:] IMPORT_OK 1 test\n", "")
        stdout = f"[GNUPG:] VALIDSIG {status_fingerprint} 2026-01-01 0 4 0 1 10 00 {status_fingerprint}\n"
        if verify_returncode != 0:
            stdout = "[GNUPG:] BADSIG BAD signer\n"
        return subprocess.CompletedProcess(args, verify_returncode, stdout, "")
    return runner


def test_full_fingerprint_normalization():
    assert PgpKeyNormalizer.normalize("0123 4567 89ab cdef 0123 4567 89ab cdef 0123 4567") == FULL_FP


def test_short_key_id_warning():
    refs, findings = parse_pkgbuild('source=("src.tar.gz" "src.tar.gz.sig")\nsha256sums=(SKIP SKIP)\nvalidpgpkeys=("89ABCDEF")\n')

    assert refs[0].validpgpkeys == ["89ABCDEF"]
    assert any(f.rule_id == "SOURCE-VALIDPGPKEY-WEAK" for f in findings)


def test_detached_asc_matched_to_source_archive(tmp_path: Path):
    source, signature, key, source_ref, sig_ref = source_and_signature(tmp_path, sig_name="src.tar.gz.asc")
    fetcher = SourceFetcher(signature_verifier=SignatureVerifier(key_provider=StaticKeyProvider(key), runner=gpg_runner()))

    results = fetcher.acquire_all([source_ref, sig_ref], tmp_path)

    assert results[0].pgp_verification["signature_path"] == "src.tar.gz.asc"
    assert any(f.rule_id == "SIGNATURE-VERIFIED" for f in results[0].findings)


def test_automatic_key_fetch_attempted_only_for_full_fingerprint(tmp_path: Path, monkeypatch):
    key_cache = tmp_path / "cache"
    provider = TrustedKeyDirectoryProvider(SourcePolicy(key_cache_dir=key_cache), opener=FakeOpener(b"public key"))

    source = provider.get_key(FULL_FP)

    assert source.path.exists()
    assert source.source_type == "keyserver"


def test_automatic_key_fetch_not_attempted_for_short_key_ids(tmp_path: Path):
    provider = TrustedKeyDirectoryProvider(SourcePolicy(key_cache_dir=tmp_path / "cache"), opener=FakeOpener(b"public key"))

    source = provider.get_key("89ABCDEF")

    assert source.path is None
    assert source.error == "WEAK_KEY_ID"


def test_cached_key_is_reused_by_fingerprint(tmp_path: Path):
    cache = tmp_path / "cache"
    cache.mkdir()
    cached = cache / f"{FULL_FP}.asc"
    cached.write_text("public key")
    provider = TrustedKeyDirectoryProvider(SourcePolicy(key_cache_dir=cache), opener=FakeOpener(b"new key"))

    source = provider.get_key(FULL_FP)

    assert source.path == cached
    assert source.source_type == "cache"


def test_valid_signature_matching_fingerprint(tmp_path: Path, monkeypatch):
    source, signature, key, source_ref, sig_ref = source_and_signature(tmp_path)
    calls = []
    verifier = SignatureVerifier(key_provider=StaticKeyProvider(key), runner=gpg_runner(calls=calls))
    monkeypatch.setattr("aurascan.core.source_acquisition.shutil.which", lambda name: "/usr/bin/gpg")

    findings, result = verifier.verify(source_ref, sig_ref, source, signature)

    assert result.verification_status == "valid"
    assert result.matched_validpgpkey is True
    assert any(f.rule_id == "SIGNATURE-VERIFIED" and not f.requires_manual_review for f in findings)
    assert all(call[1]["env"]["GNUPGHOME"] != os.environ.get("GNUPGHOME") for call in calls)


def test_valid_signature_fingerprint_mismatch(tmp_path: Path, monkeypatch):
    source, signature, key, source_ref, sig_ref = source_and_signature(tmp_path)
    verifier = SignatureVerifier(key_provider=StaticKeyProvider(key), runner=gpg_runner(status_fingerprint=OTHER_FP))
    monkeypatch.setattr("aurascan.core.source_acquisition.shutil.which", lambda name: "/usr/bin/gpg")

    findings, result = verifier.verify(source_ref, sig_ref, source, signature)

    assert result.verification_status == "fingerprint_mismatch"
    assert any(f.rule_id == "SIGNATURE-FINGERPRINT-MISMATCH" and f.severity == Severity.HIGH for f in findings)


def test_invalid_signature_blocks(tmp_path: Path, monkeypatch):
    source, signature, key, source_ref, sig_ref = source_and_signature(tmp_path)
    verifier = SignatureVerifier(key_provider=StaticKeyProvider(key), runner=gpg_runner(verify_returncode=1))
    monkeypatch.setattr("aurascan.core.source_acquisition.shutil.which", lambda name: "/usr/bin/gpg")

    findings, result = verifier.verify(source_ref, sig_ref, source, signature)

    assert result.verification_status == "invalid"
    assert any(f.rule_id == "SIGNATURE-INVALID" and f.blocks_installation for f in findings)


def test_missing_public_key_creates_key_unavailable(tmp_path: Path, monkeypatch):
    source, signature, key, source_ref, sig_ref = source_and_signature(tmp_path)
    verifier = SignatureVerifier(key_provider=StaticKeyProvider(None))
    monkeypatch.setattr("aurascan.core.source_acquisition.shutil.which", lambda name: "/usr/bin/gpg")

    findings, result = verifier.verify(source_ref, sig_ref, source, signature)

    assert result.verification_status == "key_unavailable"
    assert any(f.rule_id == "KEY_UNAVAILABLE" and f.requires_manual_review for f in findings)


def test_gpg_unavailable_creates_signature_verification_unavailable(tmp_path: Path, monkeypatch):
    source, signature, key, source_ref, sig_ref = source_and_signature(tmp_path)
    verifier = SignatureVerifier(key_provider=StaticKeyProvider(key))
    monkeypatch.setattr("aurascan.core.source_acquisition.shutil.which", lambda name: None)

    findings, result = verifier.verify(source_ref, sig_ref, source, signature)

    assert result.verification_status == "gpg_unavailable"
    assert any(f.rule_id == "SIGNATURE-VERIFICATION-UNAVAILABLE" for f in findings)


def test_signature_present_but_validpgpkeys_missing(tmp_path: Path, monkeypatch):
    source, signature, key, source_ref, sig_ref = source_and_signature(tmp_path)
    source_ref.validpgpkeys = []
    verifier = SignatureVerifier(key_provider=StaticKeyProvider(key))
    monkeypatch.setattr("aurascan.core.source_acquisition.shutil.which", lambda name: "/usr/bin/gpg")

    findings, result = verifier.verify(source_ref, sig_ref, source, signature)

    assert result.verification_status == "missing_validpgpkeys"
    assert any(f.rule_id == "SOURCE-SIGNATURE-WITHOUT-VALIDPGPKEYS" for f in findings)


def test_validpgpkeys_present_but_signature_missing():
    refs, findings = parse_pkgbuild(f'source=("src.tar.gz")\nsha256sums=(SKIP)\nvalidpgpkeys=("{FULL_FP}")\n')

    assert any(f.rule_id == "SIGNATURE-MISSING" for f in findings)


def test_skip_valid_signature_treated_better_than_skip_alone(tmp_path: Path, monkeypatch):
    source, signature, key, source_ref, sig_ref = source_and_signature(tmp_path)
    fetcher = SourceFetcher(signature_verifier=SignatureVerifier(key_provider=StaticKeyProvider(key), runner=gpg_runner()))
    monkeypatch.setattr("aurascan.core.source_acquisition.shutil.which", lambda name: "/usr/bin/gpg")

    results = fetcher.acquire_all([source_ref, sig_ref], tmp_path)

    assert not any(f.rule_id == "SOURCE-CHECKSUM-SKIP" for f in results[0].findings)
    assert any(f.rule_id == "SIGNATURE-VERIFIED" for f in results[0].findings)


def test_skip_key_unavailable_remains_manual_review(tmp_path: Path, monkeypatch):
    source, signature, key, source_ref, sig_ref = source_and_signature(tmp_path)
    fetcher = SourceFetcher(signature_verifier=SignatureVerifier(key_provider=StaticKeyProvider(None)))
    monkeypatch.setattr("aurascan.core.source_acquisition.shutil.which", lambda name: "/usr/bin/gpg")

    results = fetcher.acquire_all([source_ref, sig_ref], tmp_path)

    assert any(f.rule_id == "SOURCE-CHECKSUM-SKIP" and f.requires_manual_review for f in results[0].findings)
    assert any(f.rule_id == "KEY_UNAVAILABLE" for f in results[0].findings)
