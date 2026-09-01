import base64
import hashlib
import io
import importlib.util
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
AUDITOR = ROOT / "packaging/recovery/audit-artifacts.py"


def _load_auditor():
    spec = importlib.util.spec_from_file_location(
        "aurascan_recovery_artifact_auditor", AUDITOR
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    prior = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = prior
    return module


def _release_files(tmp_path: Path) -> Path:
    iso = tmp_path / "aurascan-recovery-0.10.3-x86_64.iso"
    iso.write_bytes(b"defanged recovery image bytes")
    digest = hashlib.sha256(iso.read_bytes()).hexdigest()
    Path(str(iso) + ".sha256").write_text(
        f"{digest}  {iso.name}\n", encoding="ascii"
    )
    Path(str(iso) + ".packages.txt").write_text(
        "base 1-1\nlinux-lts 2-1\n", encoding="utf-8"
    )
    return iso


def _audit(iso: Path, scan_root: Path, *extra: str):
    return subprocess.run(
        [
            sys.executable,
            str(AUDITOR),
            "--iso",
            str(iso),
            "--version",
            "0.10.3",
            "--scan-root",
            str(scan_root),
            *extra,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
    )


def _audit_tar(iso: Path, payload: bytes, *extra: str):
    return subprocess.run(
        [
            sys.executable,
            str(AUDITOR),
            "--iso",
            str(iso),
            "--version",
            "0.10.3",
            "--tar-stream",
            *extra,
        ],
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
    )


def _tar_bytes(*members):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for member, content in members:
            if member.isfile():
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
            else:
                archive.addfile(member)
    return output.getvalue()


def test_artifact_auditor_rejects_fixed_credential_assignment_without_echoing_it(tmp_path):
    iso = _release_files(tmp_path)
    scan_root = tmp_path / "scan-root"
    scan_root.mkdir()
    secret = b"fixture-private-credential"
    (scan_root / "provider.env").write_bytes(
        b"AURASCAN_OPENAI_API_KEY=" + secret + b"\n"
    )

    result = _audit(iso, scan_root)

    combined = result.stdout + result.stderr
    assert result.returncode == 1
    assert b"private build or credential material" in combined
    assert secret not in combined


def test_artifact_auditor_rejects_fixed_provider_token_prefix(tmp_path):
    iso = _release_files(tmp_path)
    scan_root = tmp_path / "scan-root"
    scan_root.mkdir()
    (scan_root / "opaque-state").write_bytes(b"sk-proj-fixture-private-value")

    result = _audit(iso, scan_root)

    assert result.returncode == 1
    assert b"private build or credential material" in result.stderr


def test_artifact_auditor_allows_its_inert_credential_label_definition(tmp_path):
    iso = _release_files(tmp_path)
    scan_root = tmp_path / "scan-root"
    scan_root.mkdir()
    (scan_root / "scanner-source.py").write_bytes(
        b'marker = b"AURASCAN_OPENAI_API_KEY=",\n'
    )

    result = _audit(iso, scan_root)

    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")


def test_artifact_auditor_applies_private_path_policy_to_tree_symlinks(tmp_path):
    iso = _release_files(tmp_path)
    scan_root = tmp_path / "scan-root"
    public = scan_root / "usr/share"
    public.mkdir(parents=True)
    (public / "recovery-link").symlink_to("/root/.ssh/id_ed25519")

    result = _audit(iso, scan_root)

    assert result.returncode == 1
    assert b"SSH identity material" in result.stderr
    assert b"id_ed25519" not in result.stderr


def test_artifact_auditor_normalizes_tar_hardlink_targets_before_path_policy(tmp_path):
    iso = _release_files(tmp_path)
    source = tarfile.TarInfo("usr/share/defanged-source")
    source.size = len(b"defanged")
    link = tarfile.TarInfo("usr/share/recovery-link")
    link.type = tarfile.LNKTYPE
    link.linkname = "./root/../root/.ssh/id_ed25519"
    payload = _tar_bytes((source, b"defanged"), (link, b""))

    result = _audit_tar(iso, payload)

    assert result.returncode == 1
    assert b"SSH identity material" in result.stderr


def test_artifact_auditor_rejects_tar_symlink_target_that_escapes_root(tmp_path):
    iso = _release_files(tmp_path)
    link = tarfile.TarInfo("usr/share/recovery-link")
    link.type = tarfile.SYMTYPE
    link.linkname = "../../../outside"

    result = _audit_tar(iso, _tar_bytes((link, b"")))

    assert result.returncode == 1
    assert b"link target escapes its root" in result.stderr


def test_artifact_auditor_checks_host_identity_beyond_preview_window(tmp_path):
    iso = _release_files(tmp_path)
    scan_root = tmp_path / "scan-root"
    identity = scan_root / "etc/machine-id"
    identity.parent.mkdir(parents=True)
    identity.write_bytes(b" " * 5000 + b"defanged-host-identity\n")

    result = _audit(iso, scan_root)

    assert result.returncode == 1
    assert b"persistent host identity" in result.stderr
    assert b"defanged-host-identity" not in result.stderr


def test_artifact_auditor_scans_tree_and_tar_member_names(tmp_path):
    iso = _release_files(tmp_path)
    marker = "fixture-private-marker"
    scan_root = tmp_path / "scan-root"
    scan_root.mkdir()
    (scan_root / marker).write_bytes(b"benign content")

    tree_result = _audit(iso, scan_root, "--forbid", marker)

    member = tarfile.TarInfo("usr/share/{}".format(marker))
    tar_result = _audit_tar(
        iso,
        _tar_bytes((member, b"benign content")),
        "--forbid",
        marker,
    )
    assert tree_result.returncode == 1
    assert tar_result.returncode == 1
    assert marker.encode() not in tree_result.stderr + tar_result.stderr


def test_artifact_auditor_scans_pax_and_decoded_libarchive_xattrs(tmp_path):
    iso = _release_files(tmp_path)
    marker = "fixture-private-marker"
    members = []
    schily = tarfile.TarInfo("usr/share/schily")
    schily.pax_headers = {"SCHILY.xattr.user.fixture": marker}
    members.append(schily)
    libarchive = tarfile.TarInfo("usr/share/libarchive")
    unpadded = base64.b64encode(marker.encode("ascii")).rstrip(b"=").decode("ascii")
    libarchive.pax_headers = {
        "LIBARCHIVE.xattr.user.fixture": unpadded
    }
    members.append(libarchive)

    for member in members:
        result = _audit_tar(
            iso,
            _tar_bytes((member, b"")),
            "--forbid",
            marker,
        )
        assert result.returncode == 1
        assert b"artifact metadata" in result.stderr
        assert marker.encode() not in result.stderr

    benign = tarfile.TarInfo("usr/share/benign-libarchive")
    benign.pax_headers = {
        "LIBARCHIVE.xattr.user.fixture": base64.b64encode(b"benign-xattr")
        .rstrip(b"=")
        .decode("ascii")
    }
    accepted = _audit_tar(iso, _tar_bytes((benign, b"")))
    assert accepted.returncode == 0, accepted.stderr.decode(
        "utf-8", errors="replace"
    )


def test_artifact_auditor_refuses_short_explicit_and_host_identity_markers(
    tmp_path,
):
    iso = _release_files(tmp_path)
    scan_root = tmp_path / "scan-root"
    scan_root.mkdir()

    explicit = _audit(iso, scan_root, "--forbid", "shortid")

    auditor = _load_auditor()
    hostname = tmp_path / "hostname"
    machine_id = tmp_path / "machine-id"
    hostname.write_text("arch\n", encoding="utf-8")
    machine_id.write_text("a" * 32 + "\n", encoding="utf-8")
    with pytest.raises(auditor.AuditFailure, match="host identity marker is too short"):
        auditor._marker_values((), identity_paths=(hostname, machine_id))

    assert explicit.returncode == 1
    assert b"explicit private marker" in explicit.stderr
    assert b"shortid" not in explicit.stderr


def test_recovery_builder_places_the_private_repo_before_official_repositories():
    builder = (ROOT / "packaging/recovery/build-iso.sh").read_text(encoding="utf-8")

    assert 'needle = "\\n[core]\\n"' in builder
    assert 'headers[:3] != ["options", "aurascan-recovery", "core"]' in builder
    assert 'original.replace(needle, block + needle, 1)' in builder
    assert '/usr/bin/cat >> "$profile/pacman.conf"' not in builder
