"""Deterministic evidence for Git object signature verification.

Every cryptographic verdict here is scripted text: the fixtures exercise
AuraScan's own classification, declared-fingerprint correlation and coverage
handling without requiring a live Git, GnuPG or network.  They never assert that
a signature is trustworthy, only what AuraScan may and may not conclude.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from aurascan.core import source_acquisition
from aurascan.core.models import Severity
from aurascan.core.source_acquisition import (
    GitSignatureVerification,
    GitSignatureVerifier,
    GitSourceFetcher,
    PublicKeySource,
    SourceAcquisitionResult,
    SourceKind,
    SourceParser,
    SourcePolicy,
    SourceReference,
)
from aurascan.core.trusted_tools import TrustedTool


def parse_pkgbuild(content: str):
    return SourceParser().parse_pkgbuild(content, "PKGBUILD")


COMMIT = "0123456789abcdef0123456789abcdef01234567"
TAG_OBJECT = "89abcdef0123456789abcdef0123456789abcdef"
FINGERPRINT = "0123456789ABCDEF0123456789ABCDEF01234567"
OTHER_FINGERPRINT = "FEDCBA9876543210FEDCBA9876543210FEDCBA98"

GPG_TOOL = TrustedTool(
    name="gpg", path="/usr/bin/gpg", device=1, inode=1, owner=0, group=0, mode=0o100755,
)

SIGNED_TAG_PAYLOAD = (
    f"object {COMMIT}\n"
    "type commit\n"
    "tag v1.0\n"
    "tagger Inert Test <inert@example.invalid> 0 +0000\n"
    "\n"
    "inert annotation\n"
    "\n"
    "-----BEGIN PGP SIGNATURE-----\n"
    "\n"
    "iQEzBAABCgAdFiEEinertarmoredsignaturebody\n"
    "-----END PGP SIGNATURE-----\n"
)

UNSIGNED_TAG_PAYLOAD = (
    f"object {COMMIT}\n"
    "type commit\n"
    "tag v1.0\n"
    "tagger Inert Test <inert@example.invalid> 0 +0000\n"
    "\n"
    "inert annotation\n"
)

SSH_TAG_PAYLOAD = (
    f"object {COMMIT}\n"
    "type commit\n"
    "tag v1.0\n"
    "tagger Inert Test <inert@example.invalid> 0 +0000\n"
    "\n"
    "inert annotation\n"
    "\n"
    "-----BEGIN SSH SIGNATURE-----\n"
    "\n"
    "inertsshsignaturebody\n"
    "-----END SSH SIGNATURE-----\n"
)

PUBLIC_KEY_TAG_PAYLOAD = (
    f"object {COMMIT}\n"
    "type commit\n"
    "tag v1.0\n"
    "tagger Inert Test <inert@example.invalid> 0 +0000\n"
    "\n"
    "-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
    "\n"
    "inertkeyblockbody\n"
    "-----END PGP PUBLIC KEY BLOCK-----\n"
)


def commit_payload(signed=True):
    signature = (
        "gpgsig -----BEGIN PGP SIGNATURE-----\n"
        " \n"
        " iQEzBAABCgAdFiEEinertarmoredsignaturebody\n"
        " -----END PGP SIGNATURE-----\n"
    ) if signed else ""
    return (
        f"tree {COMMIT}\n"
        f"author Inert Test <inert@example.invalid> 0 +0000\n"
        f"committer Inert Test <inert@example.invalid> 0 +0000\n"
        + signature
        + "\n"
        "inert commit message\n"
    )


class StaticKeyProvider:
    def __init__(self, data=b"public key", error=None, fingerprint=None):
        self.data = data
        self.error = error
        self.fingerprint = fingerprint
        self.requests = []

    def get_key(self, fingerprint):
        self.requests.append(fingerprint)
        if self.data is None:
            return PublicKeySource(fingerprint, error=self.error or "KEY_UNAVAILABLE")
        return PublicKeySource(fingerprint, Path("/inert/key-0.asc"), "trusted_key_dir", data=self.data)


class GitCalls:
    """Scripted Git boundary: no real repository, no process, no network."""

    def __init__(self, payload="", object_type="commit", tag_object=None, verify=None):
        self.payload = payload
        self.object_type = object_type
        self.tag_object = tag_object
        self.calls = []
        self.verify = verify or (lambda arguments: completed(0, ""))

    def __call__(self, arguments, extra_env=None):
        arguments = list(arguments)
        self.calls.append((arguments, extra_env))
        if "cat-file" in arguments:
            index = arguments.index("cat-file")
            if arguments[index + 1] == "-t":
                if self.object_type is None:
                    return completed(128, "", "fatal: not a valid object name")
                return completed(0, self.object_type + "\n")
            return completed(0, self.payload)
        if "rev-parse" in arguments:
            return completed(0, (self.tag_object or COMMIT) + "\n")
        return self.verify(arguments)

    def verify_calls(self):
        return [arguments for arguments, _env in self.calls if "verify-tag" in arguments or "verify-commit" in arguments]


def completed(returncode, stdout, stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


def gpg_runner(import_ok=True):
    def runner(arguments, **_kwargs):
        if "--import" in arguments:
            return completed(0 if import_ok else 2, "[GNUPG:] IMPORT_OK 1 test\n")
        raise AssertionError("the scripted Git boundary owns verification")
    return runner


@pytest.fixture(autouse=True)
def inert_trust_boundary(monkeypatch):
    # The Git boundary resolves executables through the trusted-tool helper; the
    # check itself is substituted so the fixtures stay inert and offline.
    monkeypatch.setattr(
        source_acquisition, "revalidate_trusted_system_tool", lambda _tool: None
    )


def tag_ref(fragment_value="v1.0", validpgpkeys=None):
    return SourceReference(
        "git+https://example.invalid/repo.git#tag=" + fragment_value,
        "git+https://example.invalid/repo.git#tag=" + fragment_value,
        0,
        "repo",
        0,
        "SKIP",
        "sha256",
        SourceKind.git_https,
        fragment_type="tag",
        fragment_value=fragment_value,
        validpgpkeys=list(validpgpkeys or []),
    )


def commit_ref(fragment_value=COMMIT, validpgpkeys=None, fragment_type="commit", resolved=None):
    return SourceReference(
        resolved or "git+https://example.invalid/repo.git",
        resolved or "git+https://example.invalid/repo.git",
        0,
        "repo",
        0,
        "SKIP",
        "sha256",
        SourceKind.git_https,
        fragment_type=fragment_type,
        fragment_value=fragment_value,
        validpgpkeys=list(validpgpkeys or []),
    )


def verifier(key_provider=None, tool_capturer=None, policy=None):
    return GitSignatureVerifier(
        policy=policy or SourcePolicy(auto_key_fetch=False, offline=True),
        key_provider=key_provider or StaticKeyProvider(),
        tool_capturer=tool_capturer or (lambda _name: GPG_TOOL),
    )


def run(git_verifier, ref, git=None, resolved=COMMIT, runner=None):
    git = git if git is not None else GitCalls()
    findings, evidence = git_verifier.verify(
        ref,
        resolved,
        run_git=git,
        runner=runner or gpg_runner(),
    )
    return findings, evidence, git


def validsig(fingerprint=FINGERPRINT):
    return f"[GNUPG:] NEWSIG\n[GNUPG:] VALIDSIG {fingerprint} 2026-09-16 0 4 0 1 10 00 {fingerprint}\n"


# --- Git object semantics -------------------------------------------------


def test_annotated_signed_tag_with_declared_signer_is_bounded_evidence():
    git = GitCalls(
        payload=SIGNED_TAG_PAYLOAD, object_type="tag", tag_object=TAG_OBJECT,
        verify=lambda _arguments: completed(0, "", validsig()),
    )

    findings, evidence, _git = run(verifier(), tag_ref(validpgpkeys=[FINGERPRINT]), git)

    assert evidence.object_type == "annotated_tag"
    assert evidence.verified_object == "tag_object"
    assert evidence.tag_object == TAG_OBJECT
    assert evidence.resolved_revision == COMMIT
    assert evidence.signature_present is True
    assert evidence.signature_format == "openpgp"
    assert evidence.verification_status == "valid"
    assert evidence.signer_fingerprint == FINGERPRINT
    assert evidence.matched_declared_validpgpkey is True
    assert [finding.rule_id for finding in findings] == ["SIGNATURE-VERIFIED"]
    assert findings[0].severity == Severity.LOW
    assert findings[0].blocks_installation is False
    assert findings[0].requires_manual_review is False


def test_unsigned_annotated_tag_reports_no_signature_and_no_finding():
    git = GitCalls(payload=UNSIGNED_TAG_PAYLOAD, object_type="tag", tag_object=TAG_OBJECT)

    findings, evidence, _git = run(verifier(), tag_ref(validpgpkeys=[FINGERPRINT]), git)

    assert evidence.signature_present is False
    assert evidence.verification_status == "unsigned"
    assert evidence.matched_declared_validpgpkey is False
    assert findings == []
    assert git.verify_calls() == []


def test_lightweight_tag_never_becomes_a_signed_tag():
    git = GitCalls(
        payload=commit_payload(signed=True), object_type="commit",
        verify=lambda _arguments: completed(0, "", validsig()),
    )

    findings, evidence, _git = run(verifier(), tag_ref(validpgpkeys=[FINGERPRINT]), git)

    assert evidence.object_type == "lightweight_tag"
    assert evidence.verified_object == "commit"
    assert evidence.tag_object is None
    assert evidence.verification_status == "valid"
    assert git.verify_calls()[0][-2:] == ["--raw", "refs/tags/v1.0"]
    assert "verify-commit" in git.verify_calls()[0]
    assert [finding.rule_id for finding in findings] == ["SIGNATURE-VERIFIED"]


def test_explicit_commit_selector_verifies_the_commit_object():
    git = GitCalls(
        payload=commit_payload(signed=True), object_type="commit",
        verify=lambda _arguments: completed(0, "", validsig()),
    )

    _findings, evidence, _git = run(verifier(), commit_ref(validpgpkeys=[FINGERPRINT]), git)

    assert evidence.selector_kind == "commit"
    assert evidence.object_type == "commit"
    assert evidence.verified_object == "commit"
    assert evidence.verification_status == "valid"


def test_branch_selector_keeps_mutability_posture_and_still_reports_signature():
    ref = commit_ref(
        fragment_value="main",
        fragment_type="branch",
        resolved="git+https://example.invalid/repo.git#branch=main",
    )
    git = GitCalls(
        payload=commit_payload(signed=True), object_type="commit",
        verify=lambda _arguments: completed(0, "", validsig(FINGERPRINT)),
    )

    findings, evidence, _git = run(verifier(tool_capturer=lambda _name: None), ref, git)

    classification = GitSourceFetcher().classification_findings(ref)
    branch = [finding for finding in classification if finding.rule_id == "SOURCE-GIT-BRANCH"]
    assert branch and branch[0].severity == Severity.HIGH
    # A branch fingerprint cannot be declared, so the signer stays untrusted.
    assert evidence.verification_status == "missing_validpgpkeys"
    assert evidence.matched_declared_validpgpkey is False
    assert [finding.rule_id for finding in findings] == ["SOURCE-SIGNATURE-WITHOUT-VALIDPGPKEYS"]


def test_unpinned_selector_is_inspected_as_a_commit():
    ref = commit_ref(fragment_value=None, fragment_type=None)
    git = GitCalls(payload=commit_payload(signed=False), object_type="commit")

    _findings, evidence, _git = run(verifier(), ref, git)

    assert evidence.selector_kind == "unpinned"
    assert evidence.object_type == "commit"
    assert evidence.verification_status == "unsigned"


# --- Signature states -----------------------------------------------------


def test_valid_signature_from_undeclared_signer_is_not_trusted():
    git = GitCalls(
        payload=SIGNED_TAG_PAYLOAD, object_type="tag", tag_object=TAG_OBJECT,
        verify=lambda _arguments: completed(0, "", validsig(OTHER_FINGERPRINT)),
    )

    findings, evidence, _git = run(verifier(), tag_ref(validpgpkeys=[FINGERPRINT]), git)

    assert evidence.verification_status == "valid"
    assert evidence.matched_declared_validpgpkey is False
    assert [finding.rule_id for finding in findings] == ["SIGNATURE-FINGERPRINT-MISMATCH"]
    assert findings[0].severity == Severity.HIGH
    assert findings[0].blocks_installation is False


def test_bad_signature_is_reported_distinctly_without_blocking():
    git = GitCalls(
        payload=SIGNED_TAG_PAYLOAD, object_type="tag", tag_object=TAG_OBJECT,
        verify=lambda _arguments: completed(
            1, "", "[GNUPG:] BADSIG 0123456789ABCDEF Inert Test <inert@example.invalid>\n"
        ),
    )

    findings, evidence, _git = run(verifier(), tag_ref(validpgpkeys=[FINGERPRINT]), git)

    assert evidence.verification_status == "invalid"
    assert evidence.status_reason == "bad_signature"
    assert [finding.rule_id for finding in findings] == ["SOURCE-GIT-SIGNATURE-INVALID"]
    assert findings[0].severity == Severity.HIGH
    assert findings[0].blocks_installation is False
    assert findings[0].requires_manual_review is True
    assert "Inert Test" not in findings[0].evidence_snippet


def test_unknown_signing_key_is_coverage_not_invalid():
    git = GitCalls(
        payload=SIGNED_TAG_PAYLOAD, object_type="tag", tag_object=TAG_OBJECT,
        verify=lambda _arguments: completed(
            2, "", "[GNUPG:] ERRSIG 0123456789ABCDEF 1 10 00 1 9 " + FINGERPRINT
            + "\n[GNUPG:] NO_PUBKEY 0123456789ABCDEF\n",
        ),
    )

    findings, evidence, _git = run(verifier(), tag_ref(validpgpkeys=[FINGERPRINT]), git)

    assert evidence.verification_status == "key_unavailable"
    assert evidence.matched_declared_validpgpkey is False
    assert [finding.rule_id for finding in findings] == ["KEY_UNAVAILABLE"]
    assert findings[0].severity == Severity.MEDIUM


def test_expired_or_revoked_key_status_is_not_reassuring_provenance():
    git = GitCalls(
        payload=SIGNED_TAG_PAYLOAD, object_type="tag", tag_object=TAG_OBJECT,
        verify=lambda _arguments: completed(
            0, "", "[GNUPG:] EXPKEYSIG 0123456789ABCDEF Inert Test <inert@example.invalid>\n"
        ),
    )

    findings, evidence, _git = run(verifier(), tag_ref(validpgpkeys=[FINGERPRINT]), git)

    assert evidence.verification_status == "signature_unusable"
    assert evidence.status_reason == "expired_or_revoked_key"
    assert evidence.matched_declared_validpgpkey is False
    assert [finding.rule_id for finding in findings] == ["SOURCE-GIT-SIGNATURE-UNVERIFIED"]
    assert findings[0].severity == Severity.LOW


def test_human_readable_goodsig_alone_never_establishes_a_fingerprint():
    git = GitCalls(
        payload=SIGNED_TAG_PAYLOAD, object_type="tag", tag_object=TAG_OBJECT,
        verify=lambda _arguments: completed(
            0, "", "[GNUPG:] GOODSIG 0123456789ABCDEF Inert Test <inert@example.invalid>\n"
        ),
    )

    findings, evidence, _git = run(verifier(), tag_ref(validpgpkeys=[FINGERPRINT]), git)

    assert evidence.signer_fingerprint is None
    assert evidence.verification_status == "fingerprint_unavailable"
    assert evidence.matched_declared_validpgpkey is False
    assert [finding.rule_id for finding in findings] == ["SOURCE-GIT-SIGNATURE-UNVERIFIED"]


def test_unsupported_signature_format_is_not_reported_as_invalid():
    git = GitCalls(payload=SSH_TAG_PAYLOAD, object_type="tag", tag_object=TAG_OBJECT)

    findings, evidence, _git = run(verifier(), tag_ref(validpgpkeys=[FINGERPRINT]), git)

    assert evidence.signature_present is True
    assert evidence.signature_format == "ssh"
    assert evidence.verification_status == "unsupported_signature_format"
    assert [finding.rule_id for finding in findings] == ["SOURCE-GIT-SIGNATURE-UNVERIFIED"]
    assert git.verify_calls() == []


def test_trailing_public_key_block_is_not_a_signature():
    git = GitCalls(payload=PUBLIC_KEY_TAG_PAYLOAD, object_type="tag", tag_object=TAG_OBJECT)

    findings, evidence, _git = run(verifier(), tag_ref(validpgpkeys=[FINGERPRINT]), git)

    assert evidence.signature_present is False
    assert evidence.verification_status == "unsigned"
    assert findings == []


def test_signature_without_declared_fingerprints_has_no_trust_anchor():
    git = GitCalls(payload=SIGNED_TAG_PAYLOAD, object_type="tag", tag_object=TAG_OBJECT)

    findings, evidence, _git = run(verifier(), tag_ref(validpgpkeys=[]), git)

    assert evidence.verification_status == "missing_validpgpkeys"
    assert [finding.rule_id for finding in findings] == ["SOURCE-SIGNATURE-WITHOUT-VALIDPGPKEYS"]
    assert git.verify_calls() == []


def test_missing_key_material_is_coverage_not_a_verdict():
    provider = StaticKeyProvider(data=None, error="KEY_UNAVAILABLE")
    git = GitCalls(payload=SIGNED_TAG_PAYLOAD, object_type="tag", tag_object=TAG_OBJECT)

    findings, evidence, _git = run(
        verifier(key_provider=provider), tag_ref(validpgpkeys=[FINGERPRINT]), git
    )

    assert evidence.verification_status == "key_unavailable"
    assert [finding.rule_id for finding in findings] == ["KEY_UNAVAILABLE"]
    assert git.verify_calls() == []


def test_missing_verifier_is_explicit_coverage():
    git = GitCalls(payload=SIGNED_TAG_PAYLOAD, object_type="tag", tag_object=TAG_OBJECT)

    findings, evidence, _git = run(
        verifier(tool_capturer=lambda _name: None), tag_ref(validpgpkeys=[FINGERPRINT]), git
    )

    assert evidence.verification_status == "verifier_unavailable"
    assert [finding.rule_id for finding in findings] == ["SIGNATURE-VERIFICATION-UNAVAILABLE"]
    assert git.verify_calls() == []


def test_object_inspection_failure_never_raises():
    git = GitCalls(object_type=None)

    findings, evidence, _git = run(verifier(), tag_ref(validpgpkeys=[FINGERPRINT]), git)

    assert evidence.verification_status == "inspection_failed"
    assert evidence.status_reason == "object_inspection_failed"
    assert [finding.rule_id for finding in findings] == ["SOURCE-GIT-SIGNATURE-UNVERIFIED"]
    assert findings[0].blocks_installation is False


def test_older_git_without_machine_status_keeps_the_fingerprint_unavailable():
    calls = []

    def verify(arguments):
        calls.append(list(arguments))
        if "--raw" in arguments:
            return completed(129, "", "usage: git verify-tag [--raw] <tag>...")
        return completed(0, "", "[GNUPG:] GOODSIG 0123456789ABCDEF Inert Test\n")

    git = GitCalls(payload=SIGNED_TAG_PAYLOAD, object_type="tag", tag_object=TAG_OBJECT, verify=verify)

    findings, evidence, _git = run(verifier(), tag_ref(validpgpkeys=[FINGERPRINT]), git)

    assert len(calls) == 2
    assert "--raw" in calls[0]
    assert "--raw" not in calls[1]
    assert evidence.verification_status == "fingerprint_unavailable"
    assert evidence.matched_declared_validpgpkey is False
    assert [finding.rule_id for finding in findings] == ["SOURCE-GIT-SIGNATURE-UNVERIFIED"]


def test_verification_uses_the_trusted_gpg_program_and_private_home():
    git = GitCalls(
        payload=SIGNED_TAG_PAYLOAD, object_type="tag", tag_object=TAG_OBJECT,
        verify=lambda _arguments: completed(0, "", validsig()),
    )

    _findings, _evidence, _git = run(verifier(), tag_ref(validpgpkeys=[FINGERPRINT]), git)

    arguments, env = [entry for entry in git.calls if "verify-tag" in entry[0]][0]
    assert f"gpg.program={GPG_TOOL.path}" in arguments
    assert "--no-tty" not in arguments  # Git never receives gpg options directly.
    assert arguments[-2:] == ["--raw", "refs/tags/v1.0"]
    assert env is not None and env["GNUPGHOME"] == env["HOME"]
    assert "GPG_TTY" in env


def test_declared_fingerprint_correlation_normalizes_case_and_spacing():
    git = GitCalls(
        payload=SIGNED_TAG_PAYLOAD, object_type="tag", tag_object=TAG_OBJECT,
        verify=lambda _arguments: completed(0, "", validsig()),
    )

    _findings, evidence, _git = run(
        verifier(), tag_ref(validpgpkeys=["0123 4567 89ab cdef 0123 4567 89ab cdef 0123 4567"]), git
    )

    assert evidence.normalized_validpgpkeys == [FINGERPRINT]
    assert evidence.matched_declared_validpgpkey is True


def test_evidence_is_bound_to_the_acquired_object_not_a_later_remote_move():
    git = GitCalls(
        payload=SIGNED_TAG_PAYLOAD, object_type="tag", tag_object=TAG_OBJECT,
        verify=lambda _arguments: completed(0, "", validsig()),
    )
    _findings, evidence, _git = run(verifier(), tag_ref(validpgpkeys=[FINGERPRINT]), git)
    captured = evidence.to_dict()

    # The upstream tag is repointed after acquisition: the verified evidence for
    # the already acquired snapshot must stay byte-identical.
    git.tag_object = "1111111111111111111111111111111111111111"
    git.payload = SIGNED_TAG_PAYLOAD.replace(COMMIT, "2222222222222222222222222222222222222222")

    assert evidence.to_dict() == captured
    assert captured["tag_object"] == TAG_OBJECT
    assert captured["resolved_revision"] == COMMIT


# --- Structured output ----------------------------------------------------


def test_structured_evidence_is_bounded_and_secret_free():
    git = GitCalls(
        payload=SIGNED_TAG_PAYLOAD, object_type="tag", tag_object=TAG_OBJECT,
        verify=lambda _arguments: completed(
            0, "", validsig() + "gpg: /tmp/private/gnupg path leaked\n"
        ),
    )
    _findings, evidence, _git = run(verifier(), tag_ref(validpgpkeys=[FINGERPRINT]), git)

    payload = evidence.to_dict()
    serialized = json.dumps(payload)

    assert set(payload) == {
        "selector_kind", "object_type", "verified_object", "resolved_revision",
        "tag_object", "signature_present", "signature_format",
        "verification_status", "status_reason", "signer_fingerprint",
        "normalized_validpgpkeys", "matched_declared_validpgpkey", "key_source",
        "gpg_status", "related_finding_ids",
    }
    assert "/tmp/private/gnupg" not in serialized
    assert "inert annotation" not in serialized
    assert "armoredsignaturebody" not in serialized
    assert "VALIDSIG " + FINGERPRINT in payload["gpg_status"]
    assert "GOODSIG" not in payload["gpg_status"]


def test_acquisition_result_serialization_is_additive():
    ref = tag_ref(validpgpkeys=[FINGERPRINT])
    result = SourceAcquisitionResult(ref, status="acquired")

    assert result.to_dict()["git_signature"] is None
    assert result.git_signature is None
    assert isinstance(GitSignatureVerification().to_dict(), dict)


# --- Fetch-level integration ---------------------------------------------


def test_git_fetch_reports_signature_evidence_without_changing_status(tmp_path):
    refs, _findings = parse_pkgbuild(
        'source=("git+https://example.invalid/repo.git#tag=v1.0")\n'
        'sha256sums=(SKIP)\n'
        f'validpgpkeys=("{FINGERPRINT}")\n'
    )
    calls = []

    def runner(arguments, **kwargs):
        arguments = list(arguments)
        calls.append(arguments)
        if "clone" in arguments:
            return completed(0, "")
        if "cat-file" in arguments:
            index = arguments.index("cat-file")
            if arguments[index + 1] == "-t":
                return completed(0, "tag\n")
            return completed(0, SIGNED_TAG_PAYLOAD)
        if "rev-parse" in arguments:
            if arguments[-1].endswith("^{commit}"):
                return completed(0, COMMIT + "\n")
            return completed(0, TAG_OBJECT + "\n")
        if "verify-tag" in arguments:
            return completed(0, "", validsig())
        return completed(0, "")

    fetcher = GitSourceFetcher(
        policy=SourcePolicy(auto_key_fetch=False),
        runner=runner,
        signature_verifier=verifier(
            key_provider=StaticKeyProvider(),
            tool_capturer=lambda _name: GPG_TOOL,
        ),
    )

    result = fetcher.fetch(refs[0], tmp_path)

    assert result.status == "acquired"
    assert result.resolved_revision == COMMIT
    payload = result.to_dict()["git_signature"]
    assert payload["verification_status"] == "valid"
    assert payload["matched_declared_validpgpkey"] is True
    assert payload["tag_object"] == TAG_OBJECT
    assert [finding.rule_id for finding in result.findings if finding.rule_id.startswith("SIGNATURE")] == [
        "SIGNATURE-VERIFIED"
    ]
    # Tag mutability evidence stays independent of signature evidence.
    assert any(finding.rule_id == "SOURCE-GIT-TAG" for finding in result.findings)
    assert not any(finding.blocks_installation for finding in result.findings)
    # No key retrieval or extra transport happened during verification.
    assert not any("keyserver" in " ".join(arguments) for arguments in calls)
    assert json.dumps(result.to_dict())


def test_git_fetch_verification_failure_never_fails_acquisition(tmp_path):
    refs, _findings = parse_pkgbuild(
        'source=("git+https://example.invalid/repo.git#tag=v1.0")\n'
        'sha256sums=(SKIP)\n'
    )

    def runner(arguments, **kwargs):
        arguments = list(arguments)
        if "clone" in arguments:
            return completed(0, "")
        if "cat-file" in arguments:
            raise AssertionError("injected verification failure")
        if "rev-parse" in arguments:
            return completed(0, COMMIT + "\n")
        return completed(0, "")

    fetcher = GitSourceFetcher(
        policy=SourcePolicy(auto_key_fetch=False),
        runner=runner,
        signature_verifier=verifier(),
    )

    result = fetcher.fetch(refs[0], tmp_path)

    assert result.status == "acquired"
    assert result.git_signature["verification_status"] == "inspection_failed"
    assert not any(finding.blocks_installation for finding in result.findings)


def test_git_fetch_deadline_expiry_during_verification_keeps_acquisition(tmp_path, monkeypatch):
    refs, _findings = parse_pkgbuild(
        'source=("git+https://example.invalid/repo.git#tag=v1.0")\n'
        'sha256sums=(SKIP)\n'
    )
    ticks = iter([0.0, 0.0, 0.0, 0.0, 0.0, 100.0, 200.0, 300.0])

    monkeypatch.setattr("aurascan.core.source_acquisition.time.monotonic", lambda: next(ticks))

    def runner(arguments, **kwargs):
        return completed(0, COMMIT + "\n" if "rev-parse" in list(arguments) else "")

    result = GitSourceFetcher(
        policy=SourcePolicy(timeout=1, auto_key_fetch=False),
        runner=runner,
        signature_verifier=verifier(),
    ).fetch(refs[0], tmp_path)

    assert result.status == "acquired"
    assert result.git_signature["verification_status"] == "inspection_failed"


# --- Real cryptographic integration (guarded) -----------------------------


def _real_tools_available():
    return bool(shutil.which("git")) and bool(shutil.which("gpg"))


@pytest.mark.skipif(not _real_tools_available(), reason="requires local Git and GnuPG")
def test_real_signed_tag_verifies_end_to_end(tmp_path):
    """One real throwaway key signs one inert tag; nothing persistent is kept."""
    git_tool = source_acquisition.capture_trusted_system_tool("git")
    gpg_tool = source_acquisition.capture_trusted_system_tool("gpg")
    if git_tool is None or gpg_tool is None:
        pytest.skip("trusted absolute Git and GnuPG paths are unavailable")

    home = tmp_path / "gnupg"
    home.mkdir(mode=0o700)
    env = {
        "GNUPGHOME": str(home),
        "HOME": str(home),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_AUTHOR_NAME": "Inert Test",
        "GIT_AUTHOR_EMAIL": "inert@example.invalid",
        "GIT_COMMITTER_NAME": "Inert Test",
        "GIT_COMMITTER_EMAIL": "inert@example.invalid",
        "GIT_AUTHOR_DATE": "2000-01-01T00:00:00+0000",
        "GIT_COMMITTER_DATE": "2000-01-01T00:00:00+0000",
    }

    def git(*arguments, check=True):
        return subprocess.run(
            [git_tool.path] + list(arguments),
            capture_output=True, text=True, check=check, env=env, timeout=60,
        )

    def gpg(*arguments):
        return subprocess.run(
            [gpg_tool.path] + list(arguments),
            capture_output=True, text=True, check=True, env=env, timeout=60,
        )

    try:
        gpg(
            "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
            "--quick-generate-key", "Inert Test <inert@example.invalid>",
            "ed25519", "sign", "0",
        )
        listing = gpg("--batch", "--with-colons", "--list-keys").stdout
        fingerprint = next(
            line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")
        )
        exported = gpg("--batch", "--armor", "--export", fingerprint).stdout

        repository = tmp_path / "inert-repository"
        repository.mkdir()
        git("init", "--template=", str(repository))
        (repository / "README").write_text("inert content\n", encoding="utf-8")
        git("-C", str(repository), "add", "README")
        git("-C", str(repository), "commit", "-m", "inert snapshot")
        revision = git("-C", str(repository), "rev-parse", "HEAD").stdout.strip()
        git(
            "-C", str(repository), "-c", f"gpg.program={gpg_tool.path}",
            "-c", f"user.signingkey={fingerprint}", "tag", "-a", "signed",
            "-m", "inert signed annotation", "-s",
        )

        refs, _findings = parse_pkgbuild(
            'source=("git+https://example.invalid/repo.git#tag=signed")\n'
            'sha256sums=(SKIP)\n'
            f'validpgpkeys=("{fingerprint}")\n'
        )

        def transport(arguments, **kwargs):
            arguments = list(arguments)
            if "clone" in arguments:
                arguments[-2] = str(repository)
            kwargs.pop("check", None)
            extra = dict(kwargs.pop("env", {}) or {})
            return subprocess.run(
                arguments, capture_output=True, text=True, check=False,
                timeout=kwargs.get("timeout", 60), env=dict(env, **extra),
            )

        result = GitSourceFetcher(
            policy=SourcePolicy(auto_key_fetch=False),
            runner=transport,
            signature_verifier=GitSignatureVerifier(
                policy=SourcePolicy(auto_key_fetch=False, offline=True),
                key_provider=StaticKeyProvider(
                    data=exported.encode("utf-8"), fingerprint=fingerprint,
                ),
            ),
        ).fetch(refs[0], tmp_path / "capture")

        assert result.status == "acquired"
        assert result.resolved_revision == revision
        evidence = result.git_signature
        assert evidence["object_type"] == "annotated_tag"
        assert evidence["verification_status"] == "valid"
        assert evidence["signer_fingerprint"] == fingerprint.upper()
        assert evidence["matched_declared_validpgpkey"] is True
        assert any(finding.rule_id == "SIGNATURE-VERIFIED" for finding in result.findings)
    finally:
        # Never retain throwaway key material, sockets or agent state.
        subprocess.run(
            [gpg_tool.path, "--homedir", str(home), "--batch", "--kill", "all"],
            capture_output=True, text=True, check=False, timeout=30,
        )
