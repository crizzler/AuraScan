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


def _pe32_plus_image(
    *,
    checksum: bytes = b"\x00\x00\x00\x00",
    payload: bytes = b"defanged-uki-payload",
    pe_offset: int = 0x80,
    optional_size: int = 0xF0,
    machine: int = 0x8664,
    section_count: int = 1,
    magic: int = 0x20B,
    directory_count: int = 16,
    certificate_entry: bytes = b"\x00" * 8,
    total_size: int = 0,
) -> bytes:
    assert len(checksum) == 4
    assert len(certificate_entry) == 8
    optional_offset = pe_offset + 24
    payload_offset = optional_offset + optional_size + section_count * 40
    minimum_size = payload_offset + len(payload)
    image = bytearray(max(total_size, minimum_size))
    image[:2] = b"MZ"
    image[0x3C:0x40] = pe_offset.to_bytes(4, "little")
    image[pe_offset : pe_offset + 4] = b"PE\x00\x00"
    image[pe_offset + 4 : pe_offset + 6] = machine.to_bytes(2, "little")
    image[pe_offset + 6 : pe_offset + 8] = section_count.to_bytes(2, "little")
    image[pe_offset + 20 : pe_offset + 22] = optional_size.to_bytes(2, "little")
    image[optional_offset : optional_offset + 2] = magic.to_bytes(2, "little")
    image[optional_offset + 64 : optional_offset + 68] = checksum
    image[optional_offset + 108 : optional_offset + 112] = directory_count.to_bytes(
        4, "little"
    )
    image[optional_offset + 144 : optional_offset + 152] = certificate_entry
    image[payload_offset : payload_offset + len(payload)] = payload
    return bytes(image)


def _attested_record(path: Path):
    metadata = path.lstat()
    return {
        "path": str(path),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "size": metadata.st_size,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "mtime_ns": metadata.st_mtime_ns,
        "ctime_ns": metadata.st_ctime_ns,
    }


def _write_private_uki(path: Path, content: bytes) -> None:
    if path.exists():
        path.chmod(0o600)
    path.write_bytes(content)
    path.chmod(0o400)


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


def test_stripped_uki_allows_only_the_exact_pe32_plus_checksum_field(
    tmp_path, monkeypatch
):
    guard = _load_guard()
    base = tmp_path / "attested-validation.efi"
    stripped = tmp_path / "runtime" / "unsigned-control.efi"
    stripped.parent.mkdir()
    base_bytes = _pe32_plus_image(checksum=b"\x10\x20\x30\x40")
    stripped_bytes = _pe32_plus_image(checksum=b"\x50\x60\x70\x80")
    _write_private_uki(base, base_bytes)
    _write_private_uki(stripped, stripped_bytes)
    record = _attested_record(base)

    # Split the four-byte CheckSum field across two streaming chunks. The
    # comparison still normalizes exactly that field and hashes the raw copy.
    checksum_offset = 0x80 + 24 + 64
    monkeypatch.setattr(guard, "CHUNK_SIZE", checksum_offset + 2)
    digest = guard._compare_stripped_uki_to_attested_base(base, stripped, record)

    assert digest == hashlib.sha256(stripped_bytes).hexdigest()
    assert digest != record["sha256"]

    for changed_offset in (checksum_offset - 1, checksum_offset + 4):
        changed = bytearray(stripped_bytes)
        changed[changed_offset] ^= 0x01
        _write_private_uki(stripped, bytes(changed))
        with pytest.raises(guard.GuardFailure, match="payload differs"):
            guard._compare_stripped_uki_to_attested_base(base, stripped, record)


def test_stripped_uki_requires_equal_size_checksum_offset_and_recorded_path(tmp_path):
    guard = _load_guard()
    base = tmp_path / "attested-validation.efi"
    stripped = tmp_path / "unsigned-control.efi"
    base_bytes = _pe32_plus_image(checksum=b"\x01\x02\x03\x04", total_size=512)
    _write_private_uki(base, base_bytes)
    record = _attested_record(base)

    _write_private_uki(stripped, base_bytes + b"x")
    with pytest.raises(guard.GuardFailure, match="size differs"):
        guard._compare_stripped_uki_to_attested_base(base, stripped, record)

    moved_header = _pe32_plus_image(
        checksum=b"\x05\x06\x07\x08", pe_offset=0x88, total_size=512
    )
    _write_private_uki(stripped, moved_header)
    with pytest.raises(guard.GuardFailure, match="checksum offset differs"):
        guard._compare_stripped_uki_to_attested_base(base, stripped, record)

    other = tmp_path / "other-validation.efi"
    _write_private_uki(other, base_bytes)
    with pytest.raises(guard.GuardFailure, match="path differs"):
        guard._compare_stripped_uki_to_attested_base(other, stripped, record)

    _write_private_uki(
        stripped, _pe32_plus_image(checksum=b"\x05\x06\x07\x08", total_size=512)
    )
    wrong_metadata = dict(record)
    wrong_metadata["size"] += 1
    with pytest.raises(guard.GuardFailure, match="identity changed"):
        guard._compare_stripped_uki_to_attested_base(
            base, stripped, wrong_metadata
        )

    wrong_digest = dict(record)
    wrong_digest["sha256"] = "f" * 64
    with pytest.raises(guard.GuardFailure, match="digest changed"):
        guard._compare_stripped_uki_to_attested_base(base, stripped, wrong_digest)


@pytest.mark.parametrize(
    "mutation, message",
    (
        (lambda image: image.__setitem__(slice(0, 2), b"NO"), "not an MZ"),
        (
            lambda image: image.__setitem__(slice(0x3C, 0x40), (63).to_bytes(4, "little")),
            "offset is outside",
        ),
        (
            lambda image: image.__setitem__(
                slice(0x3C, 0x40), (1024 * 1024).to_bytes(4, "little")
            ),
            "offset is outside",
        ),
        (lambda image: image.__setitem__(slice(0x80, 0x84), b"PX\x00\x00"), "signature"),
        (
            lambda image: image.__setitem__(
                slice(0x84, 0x86), (0x14C).to_bytes(2, "little")
            ),
            "not an x86-64",
        ),
        (
            lambda image: image.__setitem__(
                slice(0x94, 0x96), (151).to_bytes(2, "little")
            ),
            "invalid size",
        ),
        (
            lambda image: image.__setitem__(
                slice(0x98, 0x9A), (0x10B).to_bytes(2, "little")
            ),
            r"does not use the PE32\+",
        ),
        (
            lambda image: image.__setitem__(
                slice(0x104, 0x108), (4).to_bytes(4, "little")
            ),
            "omits the certificate",
        ),
        (
            lambda image: image.__setitem__(
                slice(0x104, 0x108), (17).to_bytes(4, "little")
            ),
            "count exceeds",
        ),
        (
            lambda image: image.__setitem__(slice(0x128, 0x130), b"\x01" + b"\x00" * 7),
            "retains a certificate",
        ),
        (
            lambda image: image.__setitem__(slice(0x86, 0x88), b"\x00\x00"),
            "section count",
        ),
        (
            lambda image: image.__setitem__(
                slice(0x86, 0x88), (97).to_bytes(2, "little")
            ),
            "section count",
        ),
        (
            lambda image: image.__setitem__(
                slice(0x86, 0x88), (2).to_bytes(2, "little")
            ),
            "section table is truncated",
        ),
    ),
)
def test_pe32_plus_checksum_parser_rejects_malformed_headers(
    tmp_path, mutation, message
):
    guard = _load_guard()
    image = bytearray(_pe32_plus_image())
    mutation(image)
    path = tmp_path / "malformed.efi"
    _write_private_uki(path, bytes(image))
    descriptor, metadata = guard._open_stable_regular(path, guard.UKI_LIMIT)
    try:
        with pytest.raises(guard.GuardFailure, match=message):
            guard._pe32_plus_checksum_offset(descriptor, metadata)
    finally:
        os.close(descriptor)


def test_pe32_plus_checksum_parser_rejects_truncated_optional_header(tmp_path):
    guard = _load_guard()
    image = _pe32_plus_image()
    path = tmp_path / "truncated.efi"
    _write_private_uki(path, image[: 0x80 + 24 + 151])
    descriptor, metadata = guard._open_stable_regular(path, guard.UKI_LIMIT)
    try:
        with pytest.raises(guard.GuardFailure, match="truncated"):
            guard._pe32_plus_checksum_offset(descriptor, metadata)
    finally:
        os.close(descriptor)

    short_dos = tmp_path / "short-dos.efi"
    _write_private_uki(short_dos, b"MZ" + b"\x00" * 31)
    descriptor, metadata = guard._open_stable_regular(short_dos, guard.UKI_LIMIT)
    try:
        with pytest.raises(guard.GuardFailure, match="truncated"):
            guard._pe32_plus_checksum_offset(descriptor, metadata)
    finally:
        os.close(descriptor)

    header_past_end = bytearray(_pe32_plus_image())
    header_past_end[0x3C:0x40] = (0x800).to_bytes(4, "little")
    past_end = tmp_path / "header-past-end.efi"
    _write_private_uki(past_end, bytes(header_past_end))
    descriptor, metadata = guard._open_stable_regular(past_end, guard.UKI_LIMIT)
    try:
        with pytest.raises(guard.GuardFailure, match="truncated"):
            guard._pe32_plus_checksum_offset(descriptor, metadata)
    finally:
        os.close(descriptor)

    huge_optional = bytearray(_pe32_plus_image())
    huge_optional[0x94:0x96] = (4097).to_bytes(2, "little")
    huge = tmp_path / "huge-optional.efi"
    _write_private_uki(huge, bytes(huge_optional))
    descriptor, metadata = guard._open_stable_regular(huge, guard.UKI_LIMIT)
    try:
        with pytest.raises(guard.GuardFailure, match="invalid size"):
            guard._pe32_plus_checksum_offset(descriptor, metadata)
    finally:
        os.close(descriptor)


def test_stripped_uki_rejects_symlinks_replacement_and_size_bound(
    tmp_path, monkeypatch
):
    guard = _load_guard()
    base = tmp_path / "attested-validation.efi"
    stripped = tmp_path / "unsigned-control.efi"
    replacement = tmp_path / "replacement.efi"
    content = _pe32_plus_image(checksum=b"\x01\x02\x03\x04")
    _write_private_uki(base, content)
    _write_private_uki(stripped, content)
    record = _attested_record(base)

    linked = tmp_path / "linked-control.efi"
    linked.symlink_to(stripped)
    with pytest.raises(guard.GuardFailure, match="no-follow regular file"):
        guard._compare_stripped_uki_to_attested_base(base, linked, record)

    hardlink = tmp_path / "hardlinked-control.efi"
    os.link(base, hardlink)
    record = _attested_record(base)
    with pytest.raises(guard.GuardFailure, match="aliases the attested base"):
        guard._compare_stripped_uki_to_attested_base(base, hardlink, record)

    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    parent_control = real_parent / "control.efi"
    _write_private_uki(parent_control, content)
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(guard.GuardFailure, match="symlinked path component"):
        guard._compare_stripped_uki_to_attested_base(
            base, linked_parent / "control.efi", record
        )

    stripped.chmod(0o600)
    with pytest.raises(guard.GuardFailure, match="unsafe private identity"):
        guard._compare_stripped_uki_to_attested_base(base, stripped, record)
    stripped.chmod(0o400)

    original_pread = guard.os.pread
    replaced = False

    def replacing_pread(descriptor, count, offset):
        nonlocal replaced
        result = original_pread(descriptor, count, offset)
        if not replaced and offset == 0 and count == len(content):
            replaced = True
            _write_private_uki(replacement, content)
            os.replace(str(replacement), str(stripped))
        return result

    monkeypatch.setattr(guard.os, "pread", replacing_pread)
    with pytest.raises(guard.GuardFailure, match="changed while reading"):
        guard._compare_stripped_uki_to_attested_base(base, stripped, record)
    assert replaced

    monkeypatch.setattr(guard.os, "pread", original_pread)
    _write_private_uki(stripped, content)
    monkeypatch.setattr(guard, "UKI_LIMIT", len(content))
    with pytest.raises(guard.GuardFailure, match="bounded size"):
        guard._compare_stripped_uki_to_attested_base(base, stripped, record)


def test_stripped_uki_operation_is_bound_to_secure_attested_runtime(
    tmp_path, monkeypatch
):
    guard = _load_guard()
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    base = tmp_path / "attested-validation.efi"
    stripped = runtime / "work" / "unsigned-control.efi"
    stripped.parent.mkdir()
    base_bytes = _pe32_plus_image(checksum=b"\x11\x22\x33\x44")
    stripped_bytes = _pe32_plus_image(checksum=b"\xaa\xbb\xcc\xdd")
    _write_private_uki(base, base_bytes)
    _write_private_uki(stripped, stripped_bytes)
    value = {
        "run": {
            "kind": "uki",
            "mode": "secure-boot",
            "runtime_root": str(runtime),
            "secure_preparation": {"bound": True},
        },
        "files": {"validation_uki": _attested_record(base)},
    }
    monkeypatch.setattr(guard, "_read_attestation", lambda path, descriptor: value)
    monkeypatch.setattr(guard, "_verify_attested_record", lambda record: None)

    assert guard.verify_stripped_uki(tmp_path / "attestation", 9, stripped) == (
        hashlib.sha256(stripped_bytes).hexdigest()
    )

    outside = tmp_path / "outside.efi"
    _write_private_uki(outside, stripped_bytes)
    with pytest.raises(guard.GuardFailure, match="escaped the private runtime"):
        guard.verify_stripped_uki(tmp_path / "attestation", 9, outside)

    noncanonical = stripped.parent / ".." / "work" / stripped.name
    with pytest.raises(guard.GuardFailure, match="not canonical"):
        guard.verify_stripped_uki(tmp_path / "attestation", 9, noncanonical)

    value["run"]["mode"] = "uefi"
    with pytest.raises(guard.GuardFailure, match="does not bind"):
        guard.verify_stripped_uki(tmp_path / "attestation", 9, stripped)

    value["run"]["mode"] = "secure-boot"
    value["run"]["secure_preparation"] = None
    with pytest.raises(guard.GuardFailure, match="does not bind"):
        guard.verify_stripped_uki(tmp_path / "attestation", 9, stripped)


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
        b"aurascan-recovery-marker[217]: AURASCAN_RECOVERY_READY\r\r\n",
        b"aurascan-recovery-marker[217]: AURASCAN_RECOVERY_READY\r\r",
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
        b"aurascan-recovery-marker[217]: AURASCAN_RECOVERY_READY\r\r\r\n",
        b"aurascan-recovery-marker[217]: AURASCAN_RECOVERY_READY \r\r\n",
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


def _run_minimal_tool_environment(runtime: str = "attested") -> subprocess.CompletedProcess:
    expected_runtime = (
        "/var/lib/aurascan-recovery-builder/recovery-archiso-test.12345678/"
        "recovery-validation-run-0123456789abcdef01234567/runtime"
    )
    environment = {
        "PATH": "/usr/bin:/bin",
        "AURASCAN_RECOVERY_SMOKE_CLEAN_ENV": "1",
        "AURASCAN_RECOVERY_ATTESTATION_PATH": (
            expected_runtime[: -len("/runtime")]
            + "/inputs/recovery-validation-attestation.json"
        ),
    }
    if runtime in {
        "attested",
        "closed-fd",
        "missing-fd",
        "wrong-attestation",
        "wrong-clean-marker",
    }:
        environment["TMPDIR"] = expected_runtime
    elif runtime == "unsafe":
        environment["TMPDIR"] = "/tmp/unattested-runtime"
    elif runtime == "traversal":
        environment["TMPDIR"] = (
            "/var/lib/aurascan-recovery-builder/../"
            "recovery-validation-run-0123456789abcdef01234567/runtime"
        )
    elif runtime != "missing":
        raise AssertionError("unsupported test runtime")
    read_fd, write_fd = os.pipe()
    environment["AURASCAN_RECOVERY_ATTESTATION_FD"] = str(read_fd)
    if runtime == "wrong-attestation":
        environment["AURASCAN_RECOVERY_ATTESTATION_PATH"] = (
            expected_runtime[: -len("/runtime")]
            + "/inputs/unrelated-attestation.json"
        )
    elif runtime == "traversal":
        environment["AURASCAN_RECOVERY_ATTESTATION_PATH"] = (
            environment["TMPDIR"][: -len("/runtime")]
            + "/inputs/recovery-validation-attestation.json"
        )
    elif runtime == "missing-fd":
        del environment["AURASCAN_RECOVERY_ATTESTATION_FD"]
    elif runtime == "closed-fd":
        environment["AURASCAN_RECOVERY_ATTESTATION_FD"] = "99"
    elif runtime == "wrong-clean-marker":
        environment["AURASCAN_RECOVERY_SMOKE_CLEAN_ENV"] = "0"
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
    try:
        return subprocess.run(
            [
                "/usr/bin/bash",
                "--noprofile",
                "--norc",
                "-c",
                probe,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=environment,
            pass_fds=() if runtime == "closed-fd" else (read_fd,),
        )
    finally:
        os.close(write_fd)
        os.close(read_fd)


def test_minimal_tool_environment_passes_only_attested_runtime():
    result = _run_minimal_tool_environment()

    assert result.returncode == 0, result.stderr.decode(errors="replace")
    child_environment = result.stdout.decode("utf-8").splitlines()
    assert set(child_environment) == {
        "PATH=/usr/bin:/bin",
        "HOME=/nonexistent",
        "USER=aurascan",
        "LOGNAME=aurascan",
        "LANG=C.UTF-8",
        "LC_ALL=C.UTF-8",
        "TZ=UTC",
        (
            "TMPDIR=/var/lib/aurascan-recovery-builder/"
            "recovery-archiso-test.12345678/"
            "recovery-validation-run-0123456789abcdef01234567/runtime"
        ),
        "AURASCAN_AI_ENABLED=0",
        "AURASCAN_INSTRUCTION_AI_ENABLED=0",
        "AURASCAN_INCIDENT_AI_ENABLED=0",
        "AURASCAN_RECOVERY_AI_ENABLED=0",
    }


@pytest.mark.parametrize(
    "runtime",
    (
        "closed-fd",
        "missing",
        "missing-fd",
        "traversal",
        "unsafe",
        "wrong-attestation",
        "wrong-clean-marker",
    ),
)
def test_minimal_tool_environment_refuses_unattested_runtime(runtime):
    result = _run_minimal_tool_environment(runtime)

    assert result.returncode == 1
    assert result.stdout == b""
