"""Real detached signatures over inert metadata in temporary private keyrings."""

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from aurascan.core import intelligence_crypto as crypto
from aurascan.core.intelligence import IntelligenceError
from aurascan.core.trusted_tools import capture_trusted_system_tool, revalidate_trusted_system_tool, run_bounded_trusted_tool


@pytest.fixture(scope="module")
def signing_material(tmp_path_factory):
    # The generated key has no production authority and never enters a package.
    root = tmp_path_factory.mktemp("intelligence-inert-gpg")
    root.chmod(0o700)
    tool = capture_trusted_system_tool("gpg", which=lambda _name: "/usr/bin/gpg")
    assert tool is not None, "GnuPG is required for the complete intelligence validation suite"
    env = {"PATH": "/usr/bin", "HOME": str(root), "GNUPGHOME": str(root), "LC_ALL": "C"}
    base = [tool.path, "--no-options", "--homedir", str(root), "--batch", "--no-tty", "--no-auto-key-retrieve", "--disable-dirmngr"]

    def run(arguments):
        revalidate_trusted_system_tool(tool)
        result = run_bounded_trusted_tool(base + arguments, env=env, capture_output=True, text=True, timeout=20, check=False)
        assert result.returncode == 0, "temporary inert signing setup failed"
        return result.stdout

    run(["--pinentry-mode", "loopback", "--passphrase", "", "--quick-generate-key", "AuraScan inert test <test@example.invalid>", "ed25519", "sign", "0"])
    fingerprint = next(line.split(":")[9] for line in run(["--with-colons", "--list-keys"]).splitlines() if line.startswith("fpr:"))
    public = run(["--armor", "--export", fingerprint]).encode("ascii")
    manifest = b'{"inert":"signed metadata, never executable"}\n'
    source = root / "manifest.json"
    source.write_bytes(manifest)
    run(["--pinentry-mode", "loopback", "--passphrase", "", "--digest-algo", "SHA256", "--local-user", fingerprint, "--armor", "--detach-sign", str(source)])
    try:
        yield manifest, (root / "manifest.json.asc").read_bytes(), crypto.PinnedKey(fingerprint, public), run, root
    finally:
        # Stop only the temporary keyring's agent, never the user's real agent.
        cleanup = capture_trusted_system_tool("gpgconf", which=lambda _name: "/usr/bin/gpgconf")
        assert cleanup is not None
        revalidate_trusted_system_tool(cleanup)
        run_bounded_trusted_tool([cleanup.path, "--homedir", str(root), "--kill", "gpg-agent"], env=env, capture_output=True, text=True, timeout=10, check=False)


def test_real_detached_signature_accepts_only_exact_pinned_primary(signing_material):
    manifest, signature, key, *_ = signing_material
    assert crypto.verify_detached(manifest, signature, (key,)) == key.fingerprint


def test_real_payload_tampering_rejected(signing_material):
    manifest, signature, key, *_ = signing_material
    with pytest.raises(IntelligenceError, match="rejected"):
        crypto.verify_detached(manifest + b" ", signature, (key,))


def test_real_unexpected_signer_rejected_even_with_imported_public_bytes(signing_material):
    manifest, signature, key, *_ = signing_material
    with pytest.raises(IntelligenceError):
        crypto.verify_detached(manifest, signature, (crypto.PinnedKey("F" * 40, key.data),))


def test_real_malformed_signature_rejected(signing_material):
    manifest, _, key, *_ = signing_material
    with pytest.raises(IntelligenceError):
        crypto.verify_detached(manifest, b"not a signature", (key,))


def test_real_signed_bundle_activates_and_is_read_offline(tmp_path, signing_material):
    from datetime import datetime, timezone
    from aurascan.core.intelligence import build_manifest, canonical_json, MANIFEST_FILENAME, PAYLOAD_FILENAME, SIGNATURE_FILENAME
    from aurascan.core.intelligence_store import IntelligenceStore
    _, _, key, sign, signing_root = signing_material
    now = datetime(2026, 9, 12, 12, tzinfo=timezone.utc)
    payload = (Path(__file__).parents[1] / "aurascan/assets/runtime-intelligence.json").read_bytes()
    manifest = canonical_json(build_manifest(payload, 1, now))
    source = signing_root / "activation-manifest.json"
    source.write_bytes(manifest)
    sign(["--pinentry-mode", "loopback", "--passphrase", "", "--digest-algo", "SHA256", "--local-user", key.fingerprint, "--armor", "--detach-sign", str(source)])
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    (inbox / MANIFEST_FILENAME).write_bytes(manifest)
    (inbox / PAYLOAD_FILENAME).write_bytes(payload)
    (inbox / SIGNATURE_FILENAME).write_bytes(source.with_suffix(".json.asc").read_bytes())
    target = IntelligenceStore(tmp_path / "state", expected_uid=os.getuid(), keys=(key,), clock=lambda: now)
    activated = target.activate(inbox)
    snapshot = target.load()
    assert activated["activation"] == "updated"
    assert snapshot.identity == activated["identity"]
    assert snapshot.npm_campaigns and snapshot.vendor_advisories


@pytest.mark.parametrize("status", ["EXPKEYSIG", "REVKEYSIG", "EXPSIG", "KEYEXPIRED", "SIGEXPIRED", "ERRSIG", "BADSIG", "NO_PUBKEY", "FAILURE", "ERROR"])
def test_any_bad_machine_status_rejects_even_with_validsig_and_zero_exit(status):
    fingerprint = "A" * 40
    valid = "[GNUPG:] VALIDSIG %s 2026-09-12 1789200000 0 4 0 22 8 00 %s\n" % (fingerprint, fingerprint)
    calls = []
    def runner(command, **kwargs):
        calls.append((command, kwargs))
        output = "" if "--import" in command else valid + "[GNUPG:] " + status + " inert\n"
        return SimpleNamespace(returncode=0, stdout=output, stderr="ignored untrusted diagnostics")
    with pytest.raises(IntelligenceError, match="status"):
        crypto.verify_detached(b"{}", b"test-only", (crypto.PinnedKey(fingerprint, b"test-only"),), runner=runner)
    assert all("--no-options" in args and "--no-auto-key-retrieve" in args and "--no-auto-key-import" in args and "--disable-dirmngr" in args for args, _ in calls)
    assert all(set(options["env"]) == {"PATH", "HOME", "GNUPGHOME", "LC_ALL"} for _, options in calls)


@pytest.mark.parametrize("variant", ["goodsig-only", "two-valid", "weak-hash", "missing-primary"])
def test_incomplete_or_ambiguous_machine_identity_never_suffices(variant):
    fingerprint = "A" * 40
    valid = "[GNUPG:] VALIDSIG %s 2026-09-12 1789200000 0 4 0 22 8 00 %s\n" % (fingerprint, fingerprint)
    output = {
        "goodsig-only": "[GNUPG:] GOODSIG AAAAAAAAAAAAAAAA inert\n",
        "two-valid": valid * 2,
        "weak-hash": valid.replace("22 8 00", "22 2 00"),
        "missing-primary": " ".join(valid.split()[:-1]) + "\n",
    }[variant]
    def runner(command, **_kwargs):
        return SimpleNamespace(returncode=0, stdout="" if "--import" in command else output, stderr="")
    with pytest.raises(IntelligenceError):
        crypto.verify_detached(b"{}", b"inert", (crypto.PinnedKey(fingerprint, b"inert"),), runner=runner)


def test_missing_gpg_does_not_substitute_another_executable(monkeypatch):
    monkeypatch.setattr(crypto, "capture_trusted_system_tool", lambda *_args, **_kwargs: None)
    with pytest.raises(IntelligenceError, match="unavailable"):
        crypto.verify_detached(b"{}", b"inert", (crypto.PinnedKey("A" * 40, b"inert"),))
