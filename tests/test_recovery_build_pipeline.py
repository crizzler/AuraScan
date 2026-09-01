import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tarfile
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
AUDITOR = ROOT / "packaging/recovery/audit-artifacts.py"
BUILD_HELPER = ROOT / "packaging/recovery/recovery-build-helper.py"
ASSET_LIMIT = 2 * 1024 * 1024 * 1024

_HELPER_SPEC = importlib.util.spec_from_file_location("recovery_build_helper", BUILD_HELPER)
assert _HELPER_SPEC is not None and _HELPER_SPEC.loader is not None
BUILD_HELPER_MODULE = importlib.util.module_from_spec(_HELPER_SPEC)
_DONT_WRITE_BYTECODE = sys.dont_write_bytecode
sys.dont_write_bytecode = True
try:
    _HELPER_SPEC.loader.exec_module(BUILD_HELPER_MODULE)
finally:
    sys.dont_write_bytecode = _DONT_WRITE_BYTECODE

_AUDITOR_SPEC = importlib.util.spec_from_file_location(
    "recovery_artifact_auditor_for_pipeline", AUDITOR
)
assert _AUDITOR_SPEC is not None and _AUDITOR_SPEC.loader is not None
AUDITOR_MODULE = importlib.util.module_from_spec(_AUDITOR_SPEC)
_DONT_WRITE_BYTECODE = sys.dont_write_bytecode
sys.dont_write_bytecode = True
try:
    _AUDITOR_SPEC.loader.exec_module(AUDITOR_MODULE)
finally:
    sys.dont_write_bytecode = _DONT_WRITE_BYTECODE


def _release_files(tmp_path: Path, *, version: str = "0.10.3") -> Path:
    iso = tmp_path / f"aurascan-recovery-{version}-x86_64.iso"
    iso.write_bytes(b"defanged recovery image bytes")
    digest = hashlib.sha256(iso.read_bytes()).hexdigest()
    Path(str(iso) + ".sha256").write_text(
        f"{digest}  {iso.name}\n", encoding="ascii"
    )
    Path(str(iso) + ".packages.txt").write_text(
        "base 1-1\nlinux-lts 2-1\n", encoding="utf-8"
    )
    return iso


def _tar_stream(files):
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w") as archive:
        for name, content in files:
            info = tarfile.TarInfo(name)
            info.size = len(content)
            archive.addfile(info, io.BytesIO(content))
    return result.getvalue()


def _tar_link_stream(name: str, target: str) -> bytes:
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w") as archive:
        info = tarfile.TarInfo(name)
        info.type = tarfile.SYMTYPE
        info.linkname = target
        archive.addfile(info)
    return result.getvalue()


def _tar_special_stream(name: str) -> bytes:
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w") as archive:
        info = tarfile.TarInfo(name)
        info.type = tarfile.FIFOTYPE
        archive.addfile(info)
    return result.getvalue()


def _audit(iso: Path, *extra: str, input_bytes: bytes = b""):
    return subprocess.run(
        [
            sys.executable,
            str(AUDITOR),
            "--iso",
            str(iso),
            "--version",
            "0.10.3",
            *extra,
        ],
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
    )


def _candidate_tree(tmp_path: Path) -> Path:
    root = tmp_path / "candidate"
    (root / "aurascan/assets").mkdir(parents=True)
    (root / "packaging/arch").mkdir(parents=True)
    manifest = {
        "schema": "aurascan_recovery_iso/2.0",
        "application_version": "0.10.3",
        "release_disposition": "recovery-bearing",
        "version": "0.10.3",
        "architecture": "x86_64",
        "filename": "aurascan-recovery-0.10.3-x86_64.iso",
        "released_at": "2026-09-01",
        "url": "",
        "sha256": "",
        "status": "build-required",
    }
    (root / "aurascan/assets/aurascan-recovery-iso.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    (root / "packaging/arch/PKGBUILD").write_text(
        "pkgver=0.10.3\npkgrel=1\nsha256sums=('SKIP')\n", encoding="utf-8"
    )
    (root / "packaging/arch/.SRCINFO").write_text(
        "pkgver = 0.10.3\npkgrel = 1\nsha256sums = SKIP\n", encoding="utf-8"
    )
    return root


def test_builder_refuses_stale_selection_and_sanitizes_release_processes():
    builder = (ROOT / "packaging/recovery/build-iso.sh").read_text(encoding="utf-8")
    profile = (ROOT / "packaging/recovery/archiso/profiledef.sh").read_text(
        encoding="utf-8"
    )

    assert 'must be empty; refusing stale build state' in builder.lower()
    assert 'work directory"' in builder
    assert 'recovery-archiso-$pkgver.XXXXXXXX' in builder
    assert 'expected_iso="$output/aurascan-recovery-$pkgver-x86_64.iso"' in builder
    assert "Release-candidate source commit: %s" in builder
    assert "multi-user.target.wants/aurascan-recovery-smoke-marker.service" in builder
    assert 'iso_size < release_asset_limit' in builder
    assert '${#output_entries[@]} == 3' in builder
    assert "find \"$output\" -maxdepth 1 -type f -name '*.iso'" not in builder
    assert 'mkarchiso_runner="$work/trusted-tools/mkarchiso-archiso89"' in builder
    assert '"$env_bin" -i' in builder
    for flag in (
        "AURASCAN_AI_ENABLED=0",
        "AURASCAN_INSTRUCTION_AI_ENABLED=0",
        "AURASCAN_INCIDENT_AI_ENABLED=0",
        "AURASCAN_RECOVERY_AI_ENABLED=0",
    ):
        assert flag in builder
    assert '--tar-stream' in builder
    assert "Recovery ISO construction must run entirely as root" in builder
    assert builder.startswith("#!/usr/bin/bash\n")
    assert "compgen -e" in builder
    assert "requires the documented minimal root environment" in builder
    assert "assert_root_safe_components \"$repo_root\"" in builder
    assert "assert_root_tree_safe \"$profile\"" in builder
    assert "assert_root_tree_safe \"$package_repo\"" in builder
    assert "assert_root_tree_safe \"$package_cache\"" in builder
    assert builder.count("--others --ignored --exclude-standard") == 2
    assert "verify-no-mounts" in builder
    assert "--kernel=mountinfo --json --list --output TARGET" in builder
    assert "Current mount table could not be captured completely" in builder
    assert 'ulimit -f 8192' in builder
    assert 'ulimit -f 8192 || exit 1' in builder
    assert '--signal=TERM --kill-after=5s 30s "$findmnt_bin"' in builder
    assert "Mount-table snapshot destination already exists" in builder
    assert 'if "$findmnt_bin" -R' not in builder
    assert 'test -z "$(' not in builder
    assert "readonly env_bin=\"$(" not in builder
    assert "readonly source_commit=\"$(" not in builder
    assert "readonly source_date_epoch=\"$(" not in builder
    assert "assert_identity_unassigned passwd" in builder
    assert "assert_identity_unassigned group" in builder
    assert "query_status == 2" in builder
    assert "isolated_uid_process_state" in builder
    assert "query_status == 1" in builder
    assert "could not be queried reliably" in builder
    assert "Recovery issue banner could not be verified" in builder
    assert "Recovery bootloader configuration could not be inspected completely" in builder
    assert "grep_status == 1" in builder
    assert "PYTHONDONTWRITEBYTECODE=1" in builder
    assert "sys.dont_write_bytecode = True" in BUILD_HELPER.read_text(encoding="utf-8")
    assert "Exact recovery candidate snapshot must not contain symlinks" in builder
    snapshot_link_gate = builder.index(
        "Exact recovery candidate snapshot must not contain symlinks"
    )
    snapshot_mode_normalization = builder.index(
        '/usr/bin/chmod -R go-w -- "$snapshot_root"'
    )
    snapshot_tree_gate = builder.index(
        'assert_root_tree_safe "$snapshot_root" "Exact recovery candidate snapshot"'
    )
    assert snapshot_link_gate < snapshot_mode_normalization < snapshot_tree_gate
    assert "Archiso hostname input is not a no-follow regular file" in builder
    assert "printf 'aurascan-recovery\\n' > \"$recovery_hostname\"" in builder
    assert "Recovery ISO builds require a checkout without symlinks" in builder
    assert "--net --fork --kill-child=KILL --forward-signals" in builder
    assert "--reuid=\"$isolated_build_uid\"" in builder
    assert "terminate_isolated_uid" in builder
    assert "makepkg_log_size < 16 * 1024 * 1024" in builder
    assert "3600s" in builder
    assert "trap 'handle_signal 130' INT" in builder
    assert "trap 'terminate_isolated_uid || true' EXIT HUP INT TERM" not in builder
    assert "AURASCAN_ARCHISO_ROOT_HELPER" not in builder
    assert "build-validation-uki" in builder
    assert '--source-date-epoch "$source_date_epoch"' in builder
    assert "$pkgver-$source_commit-validation-unsigned.efi" in builder
    assert "Validation UKI for QEMU (not a release asset)" in builder
    assert '--scan-root "$work/validation-uki"' in builder
    assert "MAX_UKI_BYTES = 512 * 1024 * 1024" in BUILD_HELPER.read_text(
        encoding="utf-8"
    )
    helper_source = BUILD_HELPER.read_text(encoding="utf-8")
    assert "_ensure_root_owned_tree(work)" not in helper_source
    assert "_ensure_root_owned_directory(work)" in helper_source
    assert 'iso_version="$AURASCAN_RECOVERY_VERSION"' in profile
    assert "0.6.0" not in profile


def test_validation_uki_private_parent_check_does_not_walk_unrelated_siblings():
    # /usr is a canonical root-owned non-writable directory whose descendants
    # include package-specific modes.  Only the selected parent is relevant.
    BUILD_HELPER_MODULE._ensure_root_owned_directory(Path("/usr"))


def test_validation_uki_tree_prerequisite_errors_name_the_missing_input(tmp_path):
    for label in ("selected kernel module tree", "host firmware tree"):
        try:
            BUILD_HELPER_MODULE._ensure_root_owned_tree(
                tmp_path / "missing", label=label
            )
        except BUILD_HELPER_MODULE.BuildRefusal as exc:
            assert str(exc) == "{} is unavailable".format(label)
        else:
            raise AssertionError("missing validation UKI input was accepted")


def test_validation_uki_tree_check_fails_closed_on_incomplete_walk(monkeypatch):
    def refused_walk(_root, *, followlinks, onerror):
        assert followlinks is False
        onerror(PermissionError("defanged traversal refusal"))
        return iter(())

    monkeypatch.setattr(BUILD_HELPER_MODULE.os, "walk", refused_walk)
    try:
        BUILD_HELPER_MODULE._ensure_root_owned_tree(
            Path("/usr"), label="host firmware tree"
        )
    except BUILD_HELPER_MODULE.BuildRefusal as exc:
        assert str(exc) == "host firmware tree could not be traversed completely"
    else:
        raise AssertionError("incomplete validation UKI input traversal was accepted")


def _mount_snapshot(*targets: str) -> bytes:
    return json.dumps(
        {"filesystems": [{"target": target} for target in targets]},
        separators=(",", ":"),
    ).encode("utf-8")


def test_mount_snapshot_requires_complete_clear_strict_findmnt_output(tmp_path):
    expanded_root = tmp_path / "work/x86_64/airootfs"

    BUILD_HELPER_MODULE._parse_mount_snapshot(
        _mount_snapshot("/", "/proc", "/var"), expanded_root
    )

    invalid_snapshots = (
        b"",
        b"not-json",
        b'\xff',
        b'{"filesystems":[]}',
        b'{"filesystems":[{"target":"/proc"}]}',
        b'{"filesystems":[{"target":"/","extra":true}]}',
        b'{"filesystems":[{"target":"/"}],"extra":true}',
        b'{"filesystems":[{"target":"/"}],"filesystems":[]}',
        b'{"filesystems":[{"target":"relative"}]}',
        b'{"filesystems":[{"target":42}]}',
        b'{"filesystems":[{"target":"/"},{"target":"//tmp/alias"}]}',
        b'{"filesystems":[{"target":"/var/../proc"}]}',
        b'{"filesystems":[{"target":"/proc\\npoison"}]}',
    )
    for snapshot in invalid_snapshots:
        try:
            BUILD_HELPER_MODULE._parse_mount_snapshot(snapshot, expanded_root)
        except BUILD_HELPER_MODULE.BuildRefusal:
            pass
        else:
            raise AssertionError("incomplete or malformed mount table was accepted")

    bounded_failures = (
        b"x" * (BUILD_HELPER_MODULE.MAX_MOUNT_SNAPSHOT_BYTES + 1),
        json.dumps(
            {
                "filesystems": [{"target": "/"}]
                * (BUILD_HELPER_MODULE.MAX_MOUNT_ENTRIES + 1)
            },
            separators=(",", ":"),
        ).encode("utf-8"),
    )
    for snapshot in bounded_failures:
        try:
            BUILD_HELPER_MODULE._parse_mount_snapshot(snapshot, expanded_root)
        except BUILD_HELPER_MODULE.BuildRefusal:
            pass
        else:
            raise AssertionError("oversized mount table was accepted")

    for invalid_root in (
        Path("relative/root"),
        Path("/tmp/root/../other"),
        Path("//tmp/double-leading-root"),
        Path("/"),
    ):
        try:
            BUILD_HELPER_MODULE._parse_mount_snapshot(
                _mount_snapshot("/", "/proc"), invalid_root
            )
        except BUILD_HELPER_MODULE.BuildRefusal:
            pass
        else:
            raise AssertionError("noncanonical expanded root was accepted")


def test_mount_snapshot_rejects_mount_at_or_below_expanded_root(tmp_path):
    expanded_root = tmp_path / "work/x86_64/airootfs"
    for target in (str(expanded_root), str(expanded_root / "proc")):
        try:
            BUILD_HELPER_MODULE._parse_mount_snapshot(
                _mount_snapshot("/", "/proc", target), expanded_root
            )
        except BUILD_HELPER_MODULE.BuildRefusal as exc:
            assert "live mount" in str(exc)
        else:
            raise AssertionError("live mount below expanded root was accepted")


def test_mount_snapshot_does_not_confuse_path_prefixes(tmp_path):
    expanded_root = tmp_path / "work/x86_64/airootfs"

    BUILD_HELPER_MODULE._parse_mount_snapshot(
        _mount_snapshot("/", str(expanded_root) + "-other"), expanded_root
    )


def test_exact_recovery_candidate_helper_accepts_only_build_required_skip_state(tmp_path):
    root = _candidate_tree(tmp_path)

    BUILD_HELPER_MODULE.validate_candidate(root, "0.10.3", "2026-09-01")

    manifest_path = root / "aurascan/assets/aurascan-recovery-iso.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest.update(
        {
            "status": "release-ready",
            "url": "https://example.invalid/recovery.iso",
            "sha256": "a" * 64,
        }
    )
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    try:
        BUILD_HELPER_MODULE.validate_candidate(root, "0.10.3", "2026-09-01")
    except BUILD_HELPER_MODULE.BuildRefusal as exc:
        assert "build-required candidate" in str(exc)
    else:
        raise AssertionError("release-ready manifest was accepted for an ISO source build")


def test_exact_recovery_candidate_helper_rejects_fixed_or_ambiguous_checksums(tmp_path):
    root = _candidate_tree(tmp_path)
    pkgbuild = root / "packaging/arch/PKGBUILD"

    pkgbuild.write_text(
        "pkgver=0.10.3\npkgrel=1\nsha256sums=('{}')\n".format("b" * 64),
        encoding="utf-8",
    )
    try:
        BUILD_HELPER_MODULE.validate_candidate(root, "0.10.3", "2026-09-01")
    except BUILD_HELPER_MODULE.BuildRefusal as exc:
        assert "PKGBUILD" in str(exc)
    else:
        raise AssertionError("fixed final checksum was accepted for the source candidate")

    pkgbuild.write_text(
        "pkgver=0.10.3\npkgrel=1\nsha256sums=('SKIP')\nsha256sums=('SKIP')\n",
        encoding="utf-8",
    )
    try:
        BUILD_HELPER_MODULE.validate_candidate(root, "0.10.3", "2026-09-01")
    except BUILD_HELPER_MODULE.BuildRefusal as exc:
        assert "PKGBUILD" in str(exc)
    else:
        raise AssertionError("ambiguous source checksums were accepted")


def test_exact_recovery_candidate_helper_rejects_duplicate_manifest_keys(tmp_path):
    root = _candidate_tree(tmp_path)
    manifest_path = root / "aurascan/assets/aurascan-recovery-iso.json"
    text = manifest_path.read_text(encoding="utf-8")
    manifest_path.write_text(text[:-1] + ', "status": "build-required"}', encoding="utf-8")

    try:
        BUILD_HELPER_MODULE.validate_candidate(root, "0.10.3", "2026-09-01")
    except BUILD_HELPER_MODULE.BuildRefusal as exc:
        assert "duplicate keys" in str(exc)
    else:
        raise AssertionError("duplicate manifest key was accepted")


def test_bounded_native_validation_rejects_output_overflow_and_timeout():
    try:
        BUILD_HELPER_MODULE._bounded_tool_run(
            [sys.executable, "-c", "import sys; sys.stdout.write('x' * 4096)"],
            timeout=5,
            output_limit=1024,
        )
    except BUILD_HELPER_MODULE.BuildRefusal as exc:
        assert "output bound" in str(exc)
    else:
        raise AssertionError("native validation output overflow was accepted")

    try:
        BUILD_HELPER_MODULE._bounded_tool_run(
            [sys.executable, "-c", "import time; time.sleep(2)"],
            timeout=1,
            output_limit=1024,
        )
    except BUILD_HELPER_MODULE.BuildRefusal as exc:
        assert "runtime bound" in str(exc)
    else:
        raise AssertionError("native validation timeout was accepted")


def test_builder_identity_markers_do_not_blanket_reject_root_literals(tmp_path):
    markers = BUILD_HELPER_MODULE._identity_markers(
        tmp_path / "root-owned-candidate", tmp_path / "root-owned-work"
    )

    assert b"/root/" not in markers
    assert b"AURASCAN_RECOVERY_BUILDER_IDENTITY_V1" in markers


def test_secure_boot_harness_derives_and_payload_binds_its_unsigned_control():
    harness = (ROOT / "packaging/recovery/qemu-uki-smoke.sh").read_text(
        encoding="utf-8"
    )

    assert "/usr/bin/sbattach --" not in harness
    assert "--detach" in harness
    assert "--remove" in harness
    assert "--attach" in harness
    assert "verify-payload-binding" in harness
    assert "firmware-rejection" in harness
    assert "complete bounded run" in harness
    assert "AURASCAN_RECOVERY_READY" in harness
    assert "aurascan-recovery-marker" in harness
    assert 'if=virtio,format=raw,readonly=on,file=fat:ro:$run_dir/esp' in harness
    assert 'ulimit -f "$((16 * 1024))"' in harness
    assert "ulimit -f 64" in harness


def test_builder_exports_the_exact_retained_validation_harness_root():
    builder = (ROOT / "packaging/recovery/build-iso.sh").read_text(
        encoding="utf-8"
    )
    recovery_readme = (ROOT / "packaging/recovery/README.md").read_text(
        encoding="utf-8"
    )
    scenario = (ROOT / "packaging/recovery/SCENARIO_VALIDATION.md").read_text(
        encoding="utf-8"
    )

    assert "Trusted validation harness root: %s" in builder
    assert '"$snapshot_root"' in builder
    assert "RECOVERY_HARNESS_ROOT='%s'" in builder
    assert "RECOVERY_ATTESTATION='%s'" in builder
    for document in (recovery_readme, scenario):
        assert "RECOVERY_HARNESS_ROOT" in document
        assert '"$RECOVERY_HARNESS_ROOT/packaging/recovery/recovery-smoke-bootstrap.py"' in document
        assert "RECOVERY_ATTESTATION" in document
        assert "ROOT_SMOKE" in document
        assert "user-writable" in document
        assert "Do not discover them with a wildcard" in document
        assert ".REPLACE" not in document
    assert 'if ! UNSAFE_CHECKOUT_ENTRY="$(/usr/bin/find' in recovery_readme


def test_artifact_auditor_accepts_exact_trio_sorted_manifest_and_bounded_tar(tmp_path):
    iso = _release_files(tmp_path)
    scan_root = tmp_path / "scan-root"
    scan_root.mkdir()
    (scan_root / "ordinary.txt").write_text("release material\n", encoding="utf-8")
    tar_bytes = _tar_stream(
        [("./etc/machine-id", b"\n"), ("./usr/share/aurascan/readme", b"offline\n")]
    )

    result = _audit(
        iso,
        "--scan-root",
        str(scan_root),
        "--tar-stream",
        input_bytes=tar_bytes,
    )

    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    assert b"Recovery artifact audit passed" in result.stdout


def test_artifact_auditor_rejects_checksum_not_bound_to_exact_iso(tmp_path):
    iso = _release_files(tmp_path)
    Path(str(iso) + ".sha256").write_text(
        f"{'0' * 64}  {iso.name}\n", encoding="ascii"
    )

    result = _audit(iso)

    assert result.returncode == 1
    assert b"bind the exact release image" in result.stderr


def test_artifact_auditor_rejects_unsorted_or_duplicate_package_manifest(tmp_path):
    iso = _release_files(tmp_path)
    Path(str(iso) + ".packages.txt").write_text(
        "linux-lts 2-1\nbase 1-1\nbase 1-1\n", encoding="utf-8"
    )

    result = _audit(iso)

    assert result.returncode == 1
    assert b"sorted and unique" in result.stderr


def test_artifact_auditor_rejects_iso_at_github_two_gib_boundary_without_reading_it():
    args = SimpleNamespace(
        iso="/nonexistent/aurascan-recovery-0.10.3-x86_64.iso",
        version="0.10.3",
        forbid=[],
        scan_root=[],
        tar_stream=False,
    )
    original_regular_file = AUDITOR_MODULE._regular_file
    AUDITOR_MODULE._regular_file = lambda _path, _label: SimpleNamespace(
        st_size=ASSET_LIMIT
    )
    try:
        AUDITOR_MODULE.audit(args)
    except AUDITOR_MODULE.AuditFailure as exc:
        assert "strictly smaller than the 2 GiB" in str(exc)
    else:
        raise AssertionError("ISO at the GitHub release boundary was accepted")
    finally:
        AUDITOR_MODULE._regular_file = original_regular_file


def test_artifact_auditor_fails_closed_on_private_marker_without_echoing_value(tmp_path):
    iso = _release_files(tmp_path)
    marker = "fixture-private-marker"
    tar_bytes = _tar_stream([("./usr/share/fixture", marker.encode("ascii"))])

    result = _audit(
        iso,
        "--forbid",
        marker,
        "--tar-stream",
        input_bytes=tar_bytes,
    )

    assert result.returncode == 1
    combined = result.stdout + result.stderr
    assert marker.encode("ascii") not in combined
    assert b"private build or credential material" in combined


def test_artifact_auditor_rejects_persistent_identity_in_expanded_root(tmp_path):
    iso = _release_files(tmp_path)
    tar_bytes = _tar_stream([("./etc/machine-id", b"0123456789abcdef\n")])

    result = _audit(iso, "--tar-stream", input_bytes=tar_bytes)

    assert result.returncode == 1
    assert b"persistent host identity" in result.stderr


def test_artifact_auditor_rejects_symlinked_iso(tmp_path):
    real_iso = _release_files(tmp_path)
    linked = tmp_path / "linked"
    linked.mkdir()
    symlink = linked / real_iso.name
    symlink.symlink_to(real_iso)

    result = _audit(symlink)

    assert result.returncode == 1
    assert b"no-follow regular file" in result.stderr


def test_artifact_auditor_allows_legitimate_symlink_without_following_target(tmp_path):
    iso = _release_files(tmp_path)
    scan_root = tmp_path / "scan-root"
    scan_root.mkdir()
    (scan_root / "service-link").symlink_to(
        "/usr/lib/systemd/system/aurascan-recovery.service"
    )

    result = _audit(
        iso,
        "--scan-root",
        str(scan_root),
        "--forbid",
        "fixture-private-marker",
    )

    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")


def test_artifact_auditor_rejects_private_marker_in_filesystem_symlink_target(tmp_path):
    iso = _release_files(tmp_path)
    scan_root = tmp_path / "scan-root"
    scan_root.mkdir()
    marker = "fixture-private-marker"
    (scan_root / "service-link").symlink_to(f"/run/{marker}/service")

    result = _audit(
        iso,
        "--scan-root",
        str(scan_root),
        "--forbid",
        marker,
    )

    combined = result.stdout + result.stderr
    assert result.returncode == 1
    assert b"artifact metadata" in combined
    assert marker.encode("ascii") not in combined


def test_artifact_auditor_scans_tar_symlink_target_without_rejecting_normal_link(tmp_path):
    iso = _release_files(tmp_path)
    normal = _tar_link_stream(
        "./etc/systemd/system/example.service", "/usr/lib/systemd/system/example.service"
    )

    clear = _audit(iso, "--tar-stream", input_bytes=normal)

    assert clear.returncode == 0, clear.stderr.decode("utf-8", errors="replace")

    marker = "fixture-private-marker"
    poisoned = _tar_link_stream("./usr/lib/example", f"/run/{marker}/payload")
    blocked = _audit(
        iso,
        "--forbid",
        marker,
        "--tar-stream",
        input_bytes=poisoned,
    )

    combined = blocked.stdout + blocked.stderr
    assert blocked.returncode == 1
    assert b"artifact metadata" in combined
    assert marker.encode("ascii") not in combined


def test_artifact_auditor_rejects_special_filesystem_and_tar_members(tmp_path):
    iso = _release_files(tmp_path)
    scan_root = tmp_path / "scan-root"
    scan_root.mkdir()
    os.mkfifo(scan_root / "fixture-fifo")

    filesystem_result = _audit(iso, "--scan-root", str(scan_root))
    tar_result = _audit(
        iso,
        "--tar-stream",
        input_bytes=_tar_special_stream("./fixture-fifo"),
    )

    assert filesystem_result.returncode == 1
    assert b"unsupported special file type" in filesystem_result.stderr
    assert tar_result.returncode == 1
    assert b"unsupported special file type" in tar_result.stderr
