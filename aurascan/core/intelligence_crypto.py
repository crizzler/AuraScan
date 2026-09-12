"""Detached signatures using packaged trust and the bounded system GPG runner."""

import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from aurascan.core.intelligence import IntelligenceError, MAX_MANIFEST_BYTES, MAX_SIGNATURE_BYTES
from aurascan.core.trusted_tools import capture_trusted_system_tool, revalidate_trusted_system_tool, run_bounded_trusted_tool


@dataclass(frozen=True)
class PinnedKey:
    fingerprint: str
    data: bytes


# Provisioning production trust is a separate application release operation.
PRODUCTION_KEYS = ()  # type: Sequence[PinnedKey]
_FINGERPRINT = re.compile(r"(?:[A-F0-9]{40}|[A-F0-9]{64})\Z")
_BAD_STATUS = frozenset(("BADSIG", "ERRSIG", "EXPSIG", "EXPKEYSIG", "REVKEYSIG", "KEYEXPIRED", "SIGEXPIRED", "KEYREVOKED", "NO_PUBKEY", "NODATA", "FAILURE", "ERROR"))


def assert_production_trust_configured():
    if not PRODUCTION_KEYS:
        raise IntelligenceError("production intelligence trust is not configured")


def _private_write(path, data):
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        raise


def verify_detached(manifest: bytes, signature: bytes, keys: Sequence[PinnedKey], *, runner=run_bounded_trusted_tool) -> str:
    if not keys:
        raise IntelligenceError("production intelligence trust is not configured")
    if len(keys) > 8 or not manifest or len(manifest) > MAX_MANIFEST_BYTES or not signature or len(signature) > MAX_SIGNATURE_BYTES:
        raise IntelligenceError("intelligence signature inputs exceed their bounds")
    fingerprints = set()
    for key in keys:
        if not _FINGERPRINT.fullmatch(key.fingerprint) or not isinstance(key.data, bytes) or not key.data or len(key.data) > 65536:
            raise IntelligenceError("packaged intelligence trust is malformed")
        if key.fingerprint in fingerprints:
            raise IntelligenceError("packaged intelligence trust contains duplicate keys")
        fingerprints.add(key.fingerprint)
    try:
        tool = capture_trusted_system_tool("gpg", which=lambda _name: "/usr/bin/gpg")
        if tool is None:
            raise IntelligenceError("trusted GPG is unavailable")
        with tempfile.TemporaryDirectory(prefix="aurascan-intelligence-verify-", dir="/tmp") as temporary:
            root = Path(temporary)
            os.chmod(str(root), 0o700)
            env = {"PATH": "/usr/bin", "HOME": temporary, "GNUPGHOME": temporary, "LC_ALL": "C"}
            common = [tool.path, "--no-options", "--homedir", temporary, "--batch", "--no-tty",
                      "--no-auto-key-retrieve", "--no-auto-key-import", "--no-auto-key-locate",
                      "--no-autostart", "--disable-dirmngr", "--status-fd", "1"]
            for index, key in enumerate(keys):
                path = root / ("key-%d.asc" % index)
                _private_write(path, key.data)
                revalidate_trusted_system_tool(tool)
                result = runner(common + ["--import", str(path)], env=env, capture_output=True, text=True, timeout=10, check=False)
                if result.returncode != 0:
                    raise IntelligenceError("packaged intelligence trust could not be imported")
            _private_write(root / "manifest.json", manifest)
            _private_write(root / "manifest.asc", signature)
            revalidate_trusted_system_tool(tool)
            result = runner(common + ["--verify", str(root / "manifest.asc"), str(root / "manifest.json")], env=env, capture_output=True, text=True, timeout=10, check=False)
            if result.returncode != 0:
                raise IntelligenceError("intelligence detached signature was rejected")
            valid = []
            for line in (result.stdout or "").splitlines():
                if not line.startswith("[GNUPG:] "):
                    continue
                fields = line.split()
                if len(fields) < 2:
                    continue
                if fields[1] in _BAD_STATUS:
                    raise IntelligenceError("intelligence signature status was rejected")
                if fields[1] == "VALIDSIG":
                    if len(fields) != 12 or not _FINGERPRINT.fullmatch(fields[2]) or not _FINGERPRINT.fullmatch(fields[11]):
                        raise IntelligenceError("intelligence signer identity was incomplete")
                    if fields[9] not in ("8", "9", "10") or fields[11] not in fingerprints:
                        raise IntelligenceError("intelligence signer or digest algorithm is not permitted")
                    valid.append(fields[11])
            if len(valid) != 1:
                raise IntelligenceError("intelligence signature did not identify exactly one pinned signer")
            return valid[0]
    except IntelligenceError:
        raise
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        raise IntelligenceError("intelligence verification could not use the trusted GPG boundary") from exc
