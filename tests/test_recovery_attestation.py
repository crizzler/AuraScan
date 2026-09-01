import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = ROOT / "packaging/recovery/recovery-build-helper.py"
LAUNCHER_PATH = ROOT / "packaging/recovery/recovery-smoke-launcher.py"
BOOTSTRAP_PATH = ROOT / "packaging/recovery/recovery-smoke-bootstrap.py"
GUARD_PATH = ROOT / "packaging/recovery/smoke_guard.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    prior = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = prior
    return module


def _record(path: Path, digest: str = "a" * 64):
    return {
        "path": str(path),
        "sha256": digest,
        "size": 1,
        "device": 1,
        "inode": 1,
        "mode": 0o444,
        "uid": 0,
        "gid": 0,
        "mtime_ns": 1,
        "ctime_ns": 1,
    }


def test_builder_writes_exact_private_base_attestation_roles(tmp_path, monkeypatch):
    helper = _load("recovery_attestation_helper", HELPER_PATH)
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    iso = tmp_path / "aurascan-recovery-0.10.3-x86_64.iso"
    uki = tmp_path / "validation.efi"
    destination = tmp_path / "recovery-validation-attestation.json"

    monkeypatch.setattr(helper.os, "geteuid", lambda: 0)
    monkeypatch.setattr(helper, "_root_safe_components", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        helper,
        "_attested_file",
        lambda path, **kwargs: _record(Path(path), "b" * 64),
    )

    helper.write_validation_attestation(
        snapshot,
        iso,
        uki,
        destination,
        "0.10.3",
        "c" * 40,
    )

    value = json.loads(destination.read_text(encoding="utf-8"))
    assert value["schema"] == "aurascan_recovery_validation_attestation/1.0"
    assert value["version"] == "0.10.3"
    assert value["source_commit"] == "c" * 40
    assert set(value["files"]) == {
        "smoke_bootstrap",
        "smoke_launcher",
        "secure_boot_preparer",
        "qemu_iso_harness",
        "qemu_uki_harness",
        "smoke_tool_guard",
        "smoke_guard",
        "smoke_marker_asset",
        "smoke_marker_iso_profile",
        "smoke_marker_expanded_iso",
        "smoke_marker_validation_uki_overlay",
        "iso",
        "iso_sha256",
        "iso_packages",
        "validation_uki",
        "validation_uki_sha256",
    }
    assert value["firmware"] == {}
    assert value["run_inputs"] == {}
    assert value["run"] is None
    assert stat.S_IMODE(destination.stat().st_mode) == 0o400


def test_builder_refuses_marker_units_with_different_bytes(tmp_path, monkeypatch):
    helper = _load("recovery_attestation_marker_helper", HELPER_PATH)
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    destination = tmp_path / "recovery-validation-attestation.json"

    monkeypatch.setattr(helper.os, "geteuid", lambda: 0)
    monkeypatch.setattr(helper, "_root_safe_components", lambda *args, **kwargs: None)

    def described(path, **kwargs):
        del kwargs
        digest = "d" * 64
        if "expanded_iso" in str(path):
            digest = "e" * 64
        # The derived path has no role in its basename, so distinguish the
        # expanded-root component used by the helper.
        if "/x86_64/airootfs/" in str(path):
            digest = "e" * 64
        return _record(Path(path), digest)

    monkeypatch.setattr(helper, "_attested_file", described)
    with pytest.raises(helper.BuildRefusal, match="readiness marker"):
        helper.write_validation_attestation(
            snapshot,
            tmp_path / "image.iso",
            tmp_path / "validation.efi",
            destination,
            "0.10.3",
            "c" * 40,
        )


def test_launcher_base_parser_rejects_duplicate_or_incomplete_file_sets(tmp_path):
    launcher = _load("recovery_attestation_launcher_parser", LAUNCHER_PATH)
    receipt_path = tmp_path / "receipt.json"
    files = {role: _record(tmp_path / role) for role in launcher.BASE_ROLES}
    value = {
        "schema": launcher.SCHEMA,
        "version": "0.10.3",
        "source_commit": "c" * 40,
        "files": files,
        "firmware": {},
        "run_inputs": {},
        "run": None,
    }
    receipt_path.write_text(json.dumps(value), encoding="utf-8")
    descriptor = os.open(receipt_path, os.O_RDONLY)
    try:
        parsed = launcher._parse_receipt(descriptor, receipt_path, os.fstat(descriptor))
    finally:
        os.close(descriptor)
    assert parsed == value

    del value["files"]["smoke_guard"]
    receipt_path.write_text(json.dumps(value), encoding="utf-8")
    descriptor = os.open(receipt_path, os.O_RDONLY)
    try:
        with pytest.raises(launcher.LaunchRefusal, match="file set is incomplete"):
            launcher._parse_receipt(descriptor, receipt_path, os.fstat(descriptor))
    finally:
        os.close(descriptor)


def test_smoke_guard_binds_private_copy_and_firmware_digests(monkeypatch, tmp_path):
    guard = _load("recovery_attestation_smoke_guard", GUARD_PATH)
    selected = tmp_path / "private.iso"
    digest = "a" * 64
    files = {role: _record(tmp_path / role, digest) for role in guard.ATTESTED_BASE_ROLES}
    value = {
        "files": files,
        "firmware": {},
        "run_inputs": {
            "selected_input": _record(selected, digest),
            "selected_input_sha256": _record(tmp_path / "private.iso.sha256", digest),
            "iso_packages": _record(tmp_path / "private.iso.packages.txt", digest),
        },
        "run": {"kind": "iso", "mode": "bios", "secure_preparation": None},
    }
    monkeypatch.setattr(guard, "_read_attestation", lambda path, descriptor: value)
    monkeypatch.setattr(guard, "_verify_attested_record", lambda *args, **kwargs: None)

    guard.verify_attestation(
        tmp_path / "receipt",
        9,
        "qemu_iso_harness",
        tmp_path / "qemu-smoke.sh",
        tmp_path / "smoke-tool-guard.sh",
        tmp_path / "smoke_guard.py",
        "iso",
        "bios",
        selected,
    )

    value["run_inputs"]["selected_input"]["sha256"] = "f" * 64
    with pytest.raises(guard.GuardFailure, match="differs from the base"):
        guard.verify_attestation(
            tmp_path / "receipt",
            9,
            "qemu_iso_harness",
            tmp_path / "qemu-smoke.sh",
            tmp_path / "smoke-tool-guard.sh",
            tmp_path / "smoke_guard.py",
            "iso",
            "bios",
            selected,
        )


def test_secure_harness_uses_attestation_bound_stripped_uki_comparison():
    harness = (ROOT / "packaging/recovery/qemu-uki-smoke.sh").read_text(
        encoding="utf-8"
    )
    launcher = LAUNCHER_PATH.read_text(encoding="utf-8")

    stripped_block = harness.split('unsigned_digest="', 1)[1].split(
        'detached="$work/detached-signature.p7"', 1
    )[0]
    assert "verify-stripped-uki" in stripped_block
    assert '--attestation "$AURASCAN_RECOVERY_ATTESTATION_PATH"' in stripped_block
    assert '--fd "$AURASCAN_RECOVERY_ATTESTATION_FD"' in stripped_block
    assert '--stripped "$unsigned"' in stripped_block
    assert 'snapshot-digest --kind uki --path "$unsigned"' not in stripped_block
    assert "base_unsigned_digest=" not in harness
    assert '[[ "$unsigned_digest" == "$base_unsigned_digest" ]]' not in harness
    assert "--reuid={}" in launcher
    assert '"--net"' in launcher
    assert '"--no-new-privs"' in launcher
    assert '"--bounding-set=-all"' in launcher
    assert '"--pdeathsig=KILL"' in launcher
    assert "resource.RLIMIT_AS" in launcher
    assert "resource.RLIMIT_CPU" in launcher
    assert "libc.prctl(1, signal.SIGKILL" in launcher
    assert "os.getppid() != parent_pid" in launcher
    assert "signal.SIGTERM" in launcher
    assert "os.killpg(process.pid, signal.SIGKILL)" in launcher
    assert "_retire_drop_uid()" in launcher
    assert "not isolation_started or uid_retired" in launcher
    assert "retirement could not be proven" in launcher
    assert "cwd=os.fspath(runtime_root)" in launcher
    assert "Private validation PASS receipt" in launcher
    assert "untrusted terminal" in launcher
    assert 'sys.stdout.write(captured.decode' not in launcher
    assert "_validated_smoke_outcome(" in launcher
    assert "recovery-smoke-result.json" in launcher

    command_block = launcher.split("command = [", 1)[1].split(
        "] + dropped_arguments", 1
    )[0]
    assert command_block.index('"/usr/bin/setsid"') < command_block.index(
        '"/usr/bin/unshare"'
    )
    assert command_block.index('"/usr/bin/unshare"') < command_block.index(
        '"/usr/bin/timeout"'
    )
    assert '"--kill-child=TERM"' in command_block
    assert '"--forward-signals"' in command_block


def test_launcher_requires_strict_result_and_serial_evidence_before_pass(
    tmp_path, monkeypatch
):
    launcher = _load("recovery_attestation_launcher_outcome", LAUNCHER_PATH)
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    monkeypatch.setattr(launcher, "DROP_UID", os.getuid())
    monkeypatch.setattr(launcher, "DROP_GID", os.getgid())
    ready = (
        b"firmware output\n"
        b"[   18.501600] aurascan-recovery-marker[217]: "
        b"AURASCAN_RECOVERY_READY\r\n"
    )
    ready_path = runtime / "recovery-smoke-readiness.log"
    ready_path.write_bytes(ready)
    ready_path.chmod(0o400)
    result = {
        "schema": launcher.SMOKE_RESULT_SCHEMA,
        "kind": "iso",
        "mode": "bios",
        "outcome": "service-readiness",
        "ready_marker": True,
        "unsigned_rejection": False,
        "serial_evidence": [
            {
                "role": "readiness",
                "expect": "ready",
                "file": ready_path.name,
                "sha256": hashlib.sha256(ready).hexdigest(),
                "size": len(ready),
            }
        ],
    }
    result_path = runtime / launcher.SMOKE_RESULT_NAME
    result_path.write_text(
        json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    result_path.chmod(0o400)
    captured = launcher._expected_harness_output("iso", "bios")

    outcome = launcher._validated_smoke_outcome(
        0, len(captured), captured, runtime, "iso", "bios"
    )

    assert outcome["outcome"] == "service-readiness"
    assert outcome["serial_evidence"] == [
        {
            "role": "readiness",
            "expect": "ready",
            "sha256": hashlib.sha256(ready).hexdigest(),
            "size": len(ready),
        }
    ]
    assert outcome["harness_output_sha256"] == hashlib.sha256(captured).hexdigest()

    result_path.unlink()
    with pytest.raises(launcher.LaunchRefusal, match="unavailable"):
        launcher._validated_smoke_outcome(
            0, len(captured), captured, runtime, "iso", "bios"
        )


def test_launcher_exit_zero_without_exact_outcome_text_cannot_pass(tmp_path):
    launcher = _load("recovery_attestation_launcher_empty", LAUNCHER_PATH)

    with pytest.raises(launcher.LaunchRefusal, match="incomplete outcome"):
        launcher._validated_smoke_outcome(0, 0, b"", tmp_path, "iso", "bios")
    with pytest.raises(launcher.LaunchRefusal, match="incomplete outcome"):
        launcher._validated_smoke_outcome(
            0,
            len(b"smoke passed\n"),
            b"smoke passed\n",
            tmp_path,
            "iso",
            "bios",
        )


def test_launcher_child_file_limit_matches_guarded_artifact_ceiling():
    launcher = _load("recovery_attestation_launcher_file_limit", LAUNCHER_PATH)

    assert launcher._smoke_file_limit("iso") == 2 * 1024 * 1024 * 1024
    assert launcher._smoke_file_limit("uki") == 512 * 1024 * 1024
    with pytest.raises(launcher.LaunchRefusal, match="unsupported"):
        launcher._smoke_file_limit("archive")


def test_launcher_ready_marker_requires_journal_identity():
    launcher = _load("recovery_attestation_launcher_marker", LAUNCHER_PATH)

    for line in (
        b"[   18.501600] aurascan-recovery-marker[217]: "
        b"AURASCAN_RECOVERY_READY\r\n",
        b"[   18.501600] aurascan-recovery-marker[217]: "
        b"AURASCAN_RECOVERY_READY\r\r\n",
        b"aurascan-recovery-marker[217]: AURASCAN_RECOVERY_READY\n",
        b"aurascan-recovery-marker[217]: AURASCAN_RECOVERY_READY\r\r",
    ):
        assert launcher._READY_LINE.search(line) is not None
    for line in (
        b"AURASCAN_RECOVERY_READY\n",
        b"echo[217]: AURASCAN_RECOVERY_READY\n",
        b"aurascan-recovery-marker[0]: AURASCAN_RECOVERY_READY\n",
        b"aurascan-recovery-marker[217]: AURASCAN_RECOVERY_READY\r\r\r\n",
        b"aurascan-recovery-marker[217]: AURASCAN_RECOVERY_READY \r\r\n",
    ):
        assert launcher._READY_LINE.search(line) is None


def test_launcher_independently_accepts_only_exact_current_ovmf_rejection(
    tmp_path, monkeypatch
):
    launcher = _load("recovery_attestation_launcher_current_ovmf", LAUNCHER_PATH)
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    monkeypatch.setattr(launcher, "DROP_UID", os.getuid())
    monkeypatch.setattr(launcher, "DROP_GID", os.getgid())
    ready = (
        b"firmware output\n"
        b"aurascan-recovery-marker[217]: AURASCAN_RECOVERY_READY\n"
    )
    rejection = (
        b'BdsDxe: failed to load Boot0002 "UEFI Misc Device" from '
        b"PciRoot(0x0)/Pci(0x2,0x0): Access Denied -- rejected probably by Secure Boot\r\n"
    )

    def write_result(rejection_content):
        evidence = []
        for role, expectation, name, content in (
            ("readiness", "ready", "recovery-smoke-readiness.log", ready),
            (
                "unsigned-rejection",
                "firmware-rejection",
                "recovery-smoke-unsigned-rejection.log",
                rejection_content,
            ),
        ):
            path = runtime / name
            if path.exists():
                path.chmod(0o600)
            path.write_bytes(content)
            path.chmod(0o400)
            evidence.append(
                {
                    "role": role,
                    "expect": expectation,
                    "file": name,
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "size": len(content),
                }
            )
        result = {
            "schema": launcher.SMOKE_RESULT_SCHEMA,
            "kind": "uki",
            "mode": "secure-boot",
            "outcome": "unsigned-rejection-and-signed-readiness",
            "ready_marker": True,
            "unsigned_rejection": True,
            "serial_evidence": evidence,
        }
        result_path = runtime / launcher.SMOKE_RESULT_NAME
        if result_path.exists():
            result_path.chmod(0o600)
        result_path.write_text(
            json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        result_path.chmod(0o400)

    write_result(rejection)
    outcome = launcher._read_smoke_result(runtime, "uki", "secure-boot")
    assert outcome["unsigned_rejection"] is True

    broad = b"guest reported Access Denied -- rejected probably by Secure Boot\n"
    write_result(broad)
    with pytest.raises(launcher.LaunchRefusal, match="unsigned-rejection"):
        launcher._read_smoke_result(runtime, "uki", "secure-boot")


def test_minimal_bootstrap_verifies_candidate_code_before_exec():
    bootstrap = BOOTSTRAP_PATH.read_text(encoding="utf-8")
    assert "O_NOFOLLOW" in bootstrap
    assert '_verify(value["files"]["smoke_bootstrap"], running)' in bootstrap
    assert '_verify(value["files"]["smoke_launcher"])' in bootstrap
    assert "_verify(value[\"files\"][harness_role])" in bootstrap
    assert '_verify(value["files"]["smoke_tool_guard"])' in bootstrap
    assert '_verify(value["files"]["smoke_guard"])' in bootstrap
    assert "_root_chain(python, include_final=True)" in bootstrap
    assert "python_metadata.st_uid != 0" in bootstrap
    assert "python_metadata.st_mode & 0o022" in bootstrap
    assert bootstrap.index('_verify(value["files"][harness_role])') < bootstrap.index(
        "os.execve("
    )


def test_launcher_requires_fixed_clean_edk2_ovmf_package(monkeypatch):
    launcher = _load("recovery_attestation_launcher_pacman", LAUNCHER_PATH)
    calls = []

    def clean(arguments):
        calls.append(arguments)
        if arguments[0] == "-Qqo":
            return "edk2-ovmf\n"
        return "edk2-ovmf: 29 total files, 0 altered files\n"

    monkeypatch.setattr(launcher, "_bounded_pacman", clean)
    launcher._verify_packaged_firmware([launcher.OVMF_CODE, launcher.OVMF_VARS])
    assert calls[-1] == ["-Qkk", "edk2-ovmf"]

    monkeypatch.setattr(
        launcher,
        "_bounded_pacman",
        lambda arguments: (
            "other-package\n"
            if arguments[0] == "-Qqo"
            else "edk2-ovmf: 29 total files, 0 altered files\n"
        ),
    )
    with pytest.raises(launcher.LaunchRefusal, match="not owned"):
        launcher._verify_packaged_firmware([launcher.OVMF_CODE])


def test_launcher_requires_secure_preparation_to_bind_base_and_exact_outputs(
    tmp_path, monkeypatch
):
    launcher = _load("recovery_attestation_secure_receipt", LAUNCHER_PATH)
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    output_names = {
        "signed_uki": "aurascan-recovery-validation-signed.efi",
        "signed_uki_sha256": "aurascan-recovery-validation-signed.efi.sha256",
        "enrolled_vars": "OVMF_VARS.aurascan-secure-boot.4m.fd",
        "secure_code": "OVMF_CODE.aurascan-secure-boot.4m.fd",
    }
    output_records = {}
    for index, (role, name) in enumerate(output_names.items(), start=1):
        path = artifacts / name
        path.write_bytes(("output-{}".format(index)).encode("ascii"))
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        output_records[path] = _record(path, digest)
        output_records[path]["size"] = path.stat().st_size

    base_record = _record(tmp_path / "base.json", "b" * 64)
    base_uki = _record(tmp_path / "validation.efi", "c" * 64)
    base_receipt = {
        "version": "0.10.3",
        "source_commit": "d" * 40,
        "files": {"validation_uki": base_uki},
    }
    identity_fields = {
        "sha256",
        "size",
        "device",
        "inode",
        "mode",
        "uid",
        "gid",
        "mtime_ns",
        "ctime_ns",
    }
    uki_identity_fields = {
        "device",
        "inode",
        "mode",
        "uid",
        "gid",
        "mtime_ns",
        "ctime_ns",
    }
    receipt = {
        "schema": "aurascan_recovery_secure_boot_preparation/1.0",
        "version": "0.10.3",
        "source_commit": "d" * 40,
        "created_at": "2026-09-01T12:00:00Z",
        "builder_attestation": {key: base_record[key] for key in identity_fields},
        "unsigned_validation_uki": {
            "filename": "validation.efi",
            "sha256": base_uki["sha256"],
            "size": base_uki["size"],
            "builder_identity": {
                key: base_uki[key] for key in uki_identity_fields
            },
        },
        "firmware_inputs": {},
        "tools": {},
        "certificates": {},
        "enrolled_variables": {},
        "outputs": {},
        "private_keys_deleted": True,
        "network_namespace": "isolated-by-root-launcher",
    }
    for role, path in ((role, artifacts / name) for role, name in output_names.items()):
        observed = output_records[path]
        receipt["outputs"][role] = {
            "filename": path.name,
            **{
                key: observed[key]
                for key in launcher.ENTRY_FIELDS - {"path"}
            },
        }
    receipt_path = artifacts / "secure-boot-preparation-receipt.json"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    receipt_path.chmod(0o600)

    real_open = launcher.os.open

    def open_for_test(path, limit, **kwargs):
        del limit, kwargs
        descriptor = real_open(path, os.O_RDONLY)
        return descriptor, os.fstat(descriptor)

    monkeypatch.setattr(launcher, "_open_root_regular", open_for_test)
    monkeypatch.setattr(
        launcher,
        "_entry",
        lambda path, **kwargs: output_records[Path(path)],
    )
    _parsed, resolved, _receipt_record = launcher._read_secure_preparation(
        receipt_path, base_receipt, base_record
    )
    assert resolved["signed_uki"] == artifacts / output_names["signed_uki"]

    receipt["private_keys_deleted"] = False
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    receipt_path.chmod(0o600)
    with pytest.raises(launcher.LaunchRefusal, match="private-key deletion"):
        launcher._read_secure_preparation(receipt_path, base_receipt, base_record)


def test_qemu_harnesses_use_tcg_sandbox_and_private_runtime_only():
    for name in ("qemu-smoke.sh", "qemu-uki-smoke.sh"):
        harness = (ROOT / "packaging/recovery" / name).read_text(encoding="utf-8")
        assert "-accel tcg" in harness
        assert "-cpu max" in harness
        assert "-sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny" in harness
        assert '/dev/kvm' not in harness
        assert '--tmpdir="$TMPDIR"' in harness
        assert "verify-attestation" in harness
        assert '"$EUID" != "60998"' in harness
        assert "recovery-validation-run-[0-9a-f]{24}/runtime" in harness
        assert '"${PWD-}" != "${TMPDIR-}"' in harness
        assert 'builtin : <&"$AURASCAN_RECOVERY_ATTESTATION_FD"' in harness
        assert "^([3-9]|[1-9][0-9]+)$" in harness
        assert harness.index('"$EUID" != "60998"') < harness.index(
            'builtin source "$tool_guard"'
        )
        assert "active_runner_pid" in harness
        assert "trap cleanup EXIT" in harness
        assert "trap 'exit 129' HUP" in harness
        assert "trap 'exit 130' INT" in harness
        assert "trap 'exit 143' TERM" in harness


@pytest.mark.parametrize(
    ("harness_name", "mode"),
    (("qemu-smoke.sh", "bios"), ("qemu-uki-smoke.sh", "uefi")),
)
def test_harness_refuses_before_sourcing_copied_guard_when_boundary_is_absent(
    tmp_path, harness_name, mode
):
    harness = tmp_path / harness_name
    harness.write_bytes((ROOT / "packaging/recovery" / harness_name).read_bytes())
    harness.chmod(0o755)
    side_effect = tmp_path / "guard-was-sourced"
    (tmp_path / "smoke-tool-guard.sh").write_text(
        "builtin printf sourced > {!r}\n".format(str(side_effect)),
        encoding="utf-8",
    )
    fake_runtime = (
        "/var/lib/aurascan-recovery-builder/recovery-archiso-test.12345678/"
        "recovery-validation-run-0123456789abcdef01234567/runtime"
    )
    completed = subprocess.run(
        ["/usr/bin/bash", str(harness), str(tmp_path / "candidate"), mode],
        cwd=str(tmp_path),
        env={
            "PATH": "/usr/bin:/bin",
            "AURASCAN_RECOVERY_SMOKE_CLEAN_ENV": "1",
            "AURASCAN_RECOVERY_ATTESTATION_FD": "9",
            "AURASCAN_RECOVERY_ATTESTATION_PATH": (
                fake_runtime[: -len("/runtime")]
                + "/inputs/recovery-validation-attestation.json"
            ),
            "TMPDIR": fake_runtime,
        },
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=5,
    )
    assert completed.returncode != 0
    assert not side_effect.exists()


def test_documented_builder_preflight_occurs_before_candidate_bash():
    readme = (ROOT / "packaging/recovery/README.md").read_text(encoding="utf-8")
    preflight = readme.index("EXTERNAL_ROOT_TREE_CHECK")
    candidate_bash = readme.index("/usr/bin/bash packaging/recovery/build-iso.sh")
    assert preflight < candidate_bash
    assert "-type l" in readme[preflight:candidate_bash]
    assert '/usr/bin/git -C "$CHECKOUT" rev-parse HEAD' in readme
    assert "! -user root" in readme[preflight:candidate_bash]
    assert "-perm /022" in readme[preflight:candidate_bash]
