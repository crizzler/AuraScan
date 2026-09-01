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
GUARD_PATH = ROOT / "packaging/recovery/smoke_guard.py"
TOOL_GUARD_PATH = ROOT / "packaging/recovery/smoke-tool-guard.sh"


def _load_guard():
    spec = importlib.util.spec_from_file_location("aurascan_recovery_smoke_guard", GUARD_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    prior = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = prior
    return module


def _run_guard(*arguments: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(GUARD_PATH), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
    )


def _run_tool_guard(*paths: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            "/usr/bin/env",
            "-i",
            "PATH=/usr/bin:/bin",
            "/usr/bin/bash",
            "--noprofile",
            "--norc",
            str(TOOL_GUARD_PATH),
            *paths,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def _write_release_input(path: Path, content: bytes) -> str:
    path.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    Path(str(path) + ".sha256").write_text(
        f"{digest}  {path.name}\n", encoding="ascii"
    )
    return digest


def test_iso_release_input_is_snapshotted_from_an_exact_stable_sidecar(tmp_path):
    source = tmp_path / "aurascan-recovery-0.10.3-x86_64.iso"
    expected = _write_release_input(source, b"defanged iso image")
    destination = tmp_path / "private.iso"

    result = _run_guard(
        "snapshot-release",
        "--kind",
        "iso",
        "--source",
        str(source),
        "--destination",
        str(destination),
    )

    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert result.stdout.decode("ascii").strip() == expected
    assert destination.read_bytes() == b"defanged iso image"
    assert stat.S_IMODE(destination.stat().st_mode) == 0o400

    source.write_bytes(b"later unrelated replacement")
    verify = _run_guard(
        "verify-snapshot",
        "--kind",
        "iso",
        "--path",
        str(destination),
        "--sha256",
        expected,
    )
    assert verify.returncode == 0, verify.stderr.decode(errors="replace")


def test_release_snapshot_rejects_symlinked_sidecar_and_qemu_unsafe_path(tmp_path):
    source = tmp_path / "aurascan-recovery-0.10.3-x86_64.iso"
    source.write_bytes(b"defanged iso image")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    real_sidecar = tmp_path / "real.sha256"
    real_sidecar.write_text(f"{digest}  {source.name}\n", encoding="ascii")
    Path(str(source) + ".sha256").symlink_to(real_sidecar)

    result = _run_guard(
        "snapshot-release",
        "--kind",
        "iso",
        "--source",
        str(source),
        "--destination",
        str(tmp_path / "snapshot.iso"),
    )
    assert result.returncode == 1
    assert b"no-follow regular file" in result.stderr

    source_link = tmp_path / "aurascan-recovery-0.10.4-x86_64.iso"
    source_link.symlink_to(source)
    Path(str(source_link) + ".sha256").write_text(
        f"{digest}  {source_link.name}\n", encoding="ascii"
    )
    result = _run_guard(
        "snapshot-release",
        "--kind",
        "iso",
        "--source",
        str(source_link),
        "--destination",
        str(tmp_path / "linked-snapshot.iso"),
    )
    assert result.returncode == 1
    assert b"no-follow regular file" in result.stderr

    unsafe_root = tmp_path / "comma,path"
    unsafe_root.mkdir()
    unsafe = unsafe_root / "aurascan-recovery-0.10.3-x86_64.iso"
    _write_release_input(unsafe, b"defanged iso image")
    result = _run_guard(
        "snapshot-release",
        "--kind",
        "iso",
        "--source",
        str(unsafe),
        "--destination",
        str(tmp_path / "other.iso"),
    )
    assert result.returncode == 1
    assert b"comma or control character" in result.stderr


def test_stable_read_detects_atomic_input_replacement(tmp_path, monkeypatch):
    guard = _load_guard()
    source = tmp_path / "input.fd"
    source.write_bytes(b"original firmware")
    replacement = tmp_path / "replacement.fd"
    replacement.write_bytes(b"replacement bytes")
    original_read = guard.os.read
    replaced = False

    def replacing_read(descriptor, count):
        nonlocal replaced
        chunk = original_read(descriptor, count)
        if not replaced:
            replaced = True
            os.replace(str(replacement), str(source))
        return chunk

    monkeypatch.setattr(guard.os, "read", replacing_read)
    with pytest.raises(guard.GuardFailure, match="changed while reading"):
        guard.snapshot_digest(source, "firmware")


def test_uki_size_ceiling_is_realistic_and_enforced_before_native_tools(
    tmp_path, monkeypatch
):
    guard = _load_guard()
    assert guard.UKI_LIMIT == 512 * 1024 * 1024
    monkeypatch.setattr(guard, "UKI_LIMIT", 8)
    oversized = tmp_path / "control.efi"
    oversized.write_bytes(b"MZ123456")

    with pytest.raises(guard.GuardFailure, match="bounded size"):
        guard.snapshot_digest(oversized, "uki")


def test_signature_inventory_requires_positive_exact_states(tmp_path):
    guard = _load_guard()
    unsigned = tmp_path / "unsigned.inventory"
    unsigned.write_text("No signature table present\n", encoding="utf-8")
    guard.check_signature_inventory(unsigned, "unsigned")
    with pytest.raises(guard.GuardFailure):
        guard.check_signature_inventory(unsigned, "signed")

    signed = tmp_path / "signed.inventory"
    signed.write_text(
        "signature 1\nimage signature certificates:\n - subject: CN=Disposable Test\n",
        encoding="utf-8",
    )
    guard.check_signature_inventory(signed, "signed")
    with pytest.raises(guard.GuardFailure):
        guard.check_signature_inventory(signed, "unsigned")

    ambiguous = tmp_path / "ambiguous.inventory"
    ambiguous.write_text("image appears signed\n", encoding="utf-8")
    with pytest.raises(guard.GuardFailure):
        guard.check_signature_inventory(ambiguous, "signed")


def test_boot_log_requires_an_exact_ready_line(tmp_path):
    guard = _load_guard()
    journal = tmp_path / "journal-ready.log"
    for marker in (
        b"[   18.501600] aurascan-recovery-marker[217]: "
        b"AURASCAN_RECOVERY_READY\r\n",
        b"aurascan-recovery-marker[217]: AURASCAN_RECOVERY_READY\n",
        b"aurascan-recovery-marker[217]: AURASCAN_RECOVERY_READY\r\n",
    ):
        journal.write_bytes(b"firmware output\n" + marker)
        guard.evaluate_log(journal, "ready")

    broad = tmp_path / "broad.log"
    broad.write_bytes(b"guest quoted AURASCAN_RECOVERY_READY but did not reach it\n")
    with pytest.raises(guard.GuardFailure, match="not observed"):
        guard.evaluate_log(broad, "ready")

    for near_miss in (
        b"AURASCAN_RECOVERY_READY\n",
        b"[   18.501600] echo[217]: AURASCAN_RECOVERY_READY\n",
        b"[   18.501600] aurascan-recovery-marker[0]: AURASCAN_RECOVERY_READY\n",
        b"[ 18.5016] aurascan-recovery-marker[217]: AURASCAN_RECOVERY_READY\n",
    ):
        broad.write_bytes(near_miss)
        with pytest.raises(guard.GuardFailure, match="not observed"):
            guard.evaluate_log(broad, "ready")


def test_unsigned_log_requires_no_ready_and_narrow_firmware_rejection(tmp_path):
    guard = _load_guard()
    broad = tmp_path / "broad.log"
    broad.write_bytes(b"guest application reported Security Violation\n")
    with pytest.raises(guard.GuardFailure, match="firmware-attributable"):
        guard.evaluate_log(broad, "firmware-rejection")

    rejection = tmp_path / "rejection.log"
    rejection.write_bytes(
        b'BdsDxe: failed to load Boot0001 "UEFI QEMU HARDDISK" from '
        b"PciRoot(0x0)/Pci(0x1,0x1): Security Violation\n"
    )
    guard.evaluate_log(rejection, "firmware-rejection")

    current_ovmf_rejection = tmp_path / "current-ovmf-rejection.log"
    current_ovmf_rejection.write_bytes(
        b'BdsDxe: failed to load Boot0002 "UEFI Misc Device" from '
        b"PciRoot(0x0)/Pci(0x2,0x0): Access Denied -- rejected probably by Secure Boot\r\n"
    )
    guard.evaluate_log(current_ovmf_rejection, "firmware-rejection")

    broad.write_bytes(b"guest reported Access Denied -- rejected probably by Secure Boot\n")
    with pytest.raises(guard.GuardFailure, match="firmware-attributable"):
        guard.evaluate_log(broad, "firmware-rejection")

    broad.write_bytes(
        b'BdsDxe: failed to load Boot0002 "UEFI Misc Device" from '
        b"PciRoot(0x0)/Pci(0x2,0x0): Access Denied\n"
    )
    with pytest.raises(guard.GuardFailure, match="firmware-attributable"):
        guard.evaluate_log(broad, "firmware-rejection")

    rejection.write_bytes(
        rejection.read_bytes()
        + b"aurascan-recovery-marker[217]: AURASCAN_RECOVERY_READY\n"
    )
    with pytest.raises(guard.GuardFailure, match="reached"):
        guard.evaluate_log(rejection, "firmware-rejection")


def test_smoke_result_binds_private_serial_snapshots_and_both_secure_controls(
    tmp_path, monkeypatch
):
    guard = _load_guard()
    runtime = tmp_path / "runtime"
    work = runtime / "work"
    work.mkdir(parents=True)
    monkeypatch.setenv("TMPDIR", str(runtime))
    ready = work / "ready.log"
    ready.write_bytes(
        b"firmware output\n"
        b"aurascan-recovery-marker[217]: AURASCAN_RECOVERY_READY\n"
    )
    rejection = work / "rejection.log"
    rejection.write_bytes(
        b'BdsDxe: failed to load Boot0001 "UEFI QEMU HARDDISK" from '
        b"PciRoot(0x0)/Pci(0x1,0x1): Security Violation\n"
    )
    destination = runtime / guard.SMOKE_RESULT_NAME

    guard.write_smoke_result(
        destination,
        "uki",
        "secure-boot",
        ready,
        rejection,
    )

    result = json.loads(destination.read_text(encoding="utf-8"))
    assert result["schema"] == guard.SMOKE_RESULT_SCHEMA
    assert result["outcome"] == "unsigned-rejection-and-signed-readiness"
    assert result["ready_marker"] is True
    assert result["unsigned_rejection"] is True
    assert [item["role"] for item in result["serial_evidence"]] == [
        "readiness",
        "unsigned-rejection",
    ]
    for item in result["serial_evidence"]:
        evidence = runtime / item["file"]
        content = evidence.read_bytes()
        assert hashlib.sha256(content).hexdigest() == item["sha256"]
        assert len(content) == item["size"]
        assert stat.S_IMODE(evidence.stat().st_mode) == 0o400
    assert stat.S_IMODE(destination.stat().st_mode) == 0o400


def test_smoke_result_refuses_missing_secure_control_and_replacement(
    tmp_path, monkeypatch
):
    guard = _load_guard()
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    monkeypatch.setenv("TMPDIR", str(runtime))
    ready = runtime / "ready.log"
    ready.write_bytes(
        b"aurascan-recovery-marker[217]: AURASCAN_RECOVERY_READY\n"
    )
    destination = runtime / guard.SMOKE_RESULT_NAME

    with pytest.raises(guard.GuardFailure, match="exactly two controls"):
        guard.write_smoke_result(destination, "uki", "secure-boot", ready)

    guard.write_smoke_result(destination, "iso", "bios", ready)
    with pytest.raises(guard.GuardFailure, match="could not be created"):
        guard.write_smoke_result(destination, "iso", "bios", ready)


def test_detach_reattach_binding_requires_exact_signed_bytes(tmp_path):
    guard = _load_guard()
    signed = tmp_path / "signed.efi"
    unsigned = tmp_path / "unsigned.efi"
    reattached = tmp_path / "reattached.efi"
    signed.write_bytes(b"MZpayload-and-signature")
    unsigned.write_bytes(b"MZpayload")
    reattached.write_bytes(signed.read_bytes())

    guard.verify_payload_binding(signed, unsigned, reattached)

    reattached.write_bytes(b"MZunrelated-signed-image")
    with pytest.raises(guard.GuardFailure, match="exact signed UKI"):
        guard.verify_payload_binding(signed, unsigned, reattached)


def test_trusted_tool_guard_checks_the_complete_absolute_component_chain(tmp_path):
    trusted_python = str(Path("/usr/bin/python3").resolve(strict=True))
    accepted = _run_tool_guard("/usr/bin/stat", trusted_python)
    assert accepted.returncode == 0, accepted.stderr.decode(errors="replace")

    user_tool_root = tmp_path / "bin"
    user_tool_root.mkdir()
    user_tool = user_tool_root / "tool"
    user_tool.write_text("#!/usr/bin/bash\nexit 0\n", encoding="utf-8")
    user_tool.chmod(0o755)
    rejected = _run_tool_guard(str(user_tool))
    assert rejected.returncode == 1
    assert b"path-component boundary" in rejected.stderr

    symlink_component = _run_tool_guard("/proc/self/root/usr/bin/stat")
    assert symlink_component.returncode == 1
    assert b"path-component boundary" in symlink_component.stderr


def test_minimal_tool_environment_strips_python_and_loader_influence():
    probe = "\n".join(
        (
            f'source "{TOOL_GUARD_PATH}"',
            "export PYTHONPATH=/defanged/python-injection",
            "export PYTHONHOME=/defanged/python-home",
            "export LD_BIND_NOW=1",
            "export LD_LIBRARY_PATH=/defanged/loader-path",
            "run_smoke_minimal /usr/bin/env",
        )
    )
    result = subprocess.run(
        [
            "/usr/bin/env",
            "-i",
            "PATH=/usr/bin:/bin",
            "/usr/bin/bash",
            "--noprofile",
            "--norc",
            "-c",
            probe,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 0, result.stderr.decode(errors="replace")
    child_environment = result.stdout.decode("utf-8").splitlines()
    assert "PATH=/usr/bin:/bin" in child_environment
    assert "AURASCAN_AI_ENABLED=0" in child_environment
    assert "AURASCAN_INSTRUCTION_AI_ENABLED=0" in child_environment
    assert "AURASCAN_INCIDENT_AI_ENABLED=0" in child_environment
    assert "AURASCAN_RECOVERY_AI_ENABLED=0" in child_environment
    assert not any(line.startswith("PYTHON") for line in child_environment)
    assert not any(line.startswith("LD_") for line in child_environment)
