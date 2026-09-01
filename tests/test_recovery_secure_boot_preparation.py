import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "packaging/recovery/prepare-secure-boot.py"


def _load_helper():
    spec = importlib.util.spec_from_file_location("secure_boot_preparation", HELPER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


def _entry(path: Path, data: bytes, *, mode: int = 0o644):
    digest = hashlib.sha256(data).hexdigest()
    return {
        "path": str(path),
        "sha256": digest,
        "size": len(data),
        "device": 1,
        "inode": 2,
        "mode": mode,
        "uid": 0,
        "gid": 0,
        "mtime_ns": 3,
        "ctime_ns": 4,
    }


def _base_attestation(uki: Path, sidecar: Path, uki_data: bytes):
    digest = hashlib.sha256(uki_data).hexdigest()
    sidecar_data = f"{digest}  {uki.name}\n".encode("ascii")
    return {
        "schema": "aurascan_recovery_validation_attestation/1.0",
        "version": "0.10.3",
        "source_commit": "a" * 40,
        "files": {
            "validation_uki": _entry(uki, uki_data),
            "validation_uki_sha256": _entry(sidecar, sidecar_data),
        },
        "firmware": {},
        "run_inputs": {},
        "run": None,
    }


def _encoded(value) -> bytes:
    return (json.dumps(value, sort_keys=True) + "\n").encode("utf-8")


def test_base_attestation_accepts_only_the_private_builder_shape(tmp_path):
    helper = _load_helper()
    uki = tmp_path / "candidate-validation-unsigned.efi"
    sidecar = Path(str(uki) + ".sha256")
    value = _base_attestation(uki, sidecar, b"MZcandidate")

    parsed, uki_entry, sidecar_entry = helper._parse_base_attestation(_encoded(value))

    assert parsed["version"] == "0.10.3"
    assert uki_entry["sha256"] == hashlib.sha256(b"MZcandidate").hexdigest()
    assert sidecar_entry["path"] == str(sidecar)

    value["run"] = {"kind": "uki"}
    with pytest.raises(helper.PreparationRefusal, match="per-run extension"):
        helper._parse_base_attestation(_encoded(value))


def test_attestation_and_firmware_json_reject_duplicate_or_inexact_state():
    helper = _load_helper()
    duplicate = b'{"schema":"a","schema":"b"}'
    with pytest.raises(helper.PreparationRefusal, match="duplicate"):
        helper._strict_json(duplicate, maximum=1024, label="fixture")

    variables = {
        "version": 2,
        "variables": [
            {"name": name, "guid": "00000000-0000-0000-0000-000000000000", "attr": 3, "data": data}
            for name, data in (
                ("PK", "aa"),
                ("KEK", "bb"),
                ("db", "cc"),
                ("dbx", "dd"),
                ("SecureBootEnable", "01"),
                ("CustomMode", "00"),
            )
        ],
    }
    summary = helper._validate_vars_json(_encoded(variables))
    assert summary["SecureBootEnable"]["data"] == "01"
    assert summary["CustomMode"]["data"] == "00"
    assert all(summary[name]["size"] > 0 for name in ("PK", "KEK", "db", "dbx"))

    variables["variables"][-1]["data"] = "01"
    with pytest.raises(helper.PreparationRefusal, match="mode flags"):
        helper._validate_vars_json(_encoded(variables))


def test_bounded_native_runner_retires_timeout_and_output_files(tmp_path):
    helper = _load_helper()
    result = helper._bounded_process(
        [sys.executable, "-c", "import sys; sys.stdout.write('bounded')"],
        work=tmp_path,
        label="small",
        timeout=5,
        output_limit=1024,
        environment=helper._worker_environment(),
        validate_tool=False,
    )
    assert result == b"bounded"
    assert list(tmp_path.iterdir()) == []

    with pytest.raises(helper.PreparationRefusal, match="output bound|failed"):
        helper._bounded_process(
            [sys.executable, "-c", "import sys; sys.stdout.write('x' * 65536)"],
            work=tmp_path,
            label="overflow",
            timeout=5,
            output_limit=1024,
            environment=helper._worker_environment(),
            validate_tool=False,
        )
    assert list(tmp_path.iterdir()) == []

    with pytest.raises(helper.PreparationRefusal, match="runtime bound"):
        helper._bounded_process(
            [sys.executable, "-c", "import time; time.sleep(2)"],
            work=tmp_path,
            label="timeout",
            timeout=1,
            output_limit=1024,
            environment=helper._worker_environment(),
            validate_tool=False,
        )
    assert list(tmp_path.iterdir()) == []


def test_native_capture_and_artifact_file_size_limits_are_independent(tmp_path):
    helper = _load_helper()
    allowed = tmp_path / "allowed.bin"
    result = helper._bounded_process(
        [
            sys.executable,
            "-c",
            "from pathlib import Path; Path({!r}).write_bytes(b'x' * 4096); print('ok')".format(
                str(allowed)
            ),
        ],
        work=tmp_path,
        label="larger-artifact",
        timeout=5,
        output_limit=128,
        artifact_limit=8192,
        environment=helper._worker_environment(),
        validate_tool=False,
    )
    assert result == b"ok\n"
    assert allowed.stat().st_size == 4096

    refused = tmp_path / "refused.bin"
    with pytest.raises(helper.PreparationRefusal, match="failed|output bound"):
        helper._bounded_process(
            [
                sys.executable,
                "-c",
                "from pathlib import Path; Path({!r}).write_bytes(b'x' * 16384)".format(
                    str(refused)
                ),
            ],
            work=tmp_path,
            label="oversized-artifact",
            timeout=5,
            output_limit=128,
            artifact_limit=4096,
            environment=helper._worker_environment(),
            validate_tool=False,
        )
    assert not refused.exists() or refused.stat().st_size <= 4096


def test_trusted_tool_resolution_executes_on_the_python38_compatible_path_api():
    helper = _load_helper()
    resolved, metadata = helper._resolved_trusted_tool("/usr/bin/stat")

    assert resolved.is_absolute()
    assert stat.S_ISREG(metadata.st_mode)
    assert metadata.st_uid == 0
    assert "os.path.realpath" not in HELPER.read_text(encoding="utf-8")


def test_worker_failure_deletes_disposable_keys_and_transient_copies(tmp_path, monkeypatch):
    helper = _load_helper()
    staging = tmp_path / "staging"
    staging.mkdir(mode=0o700)
    uki = tmp_path / "candidate-validation-unsigned.efi"
    uki_data = b"MZcandidate"
    uki.write_bytes(uki_data)
    sidecar = Path(str(uki) + ".sha256")
    sidecar_data = f"{hashlib.sha256(uki_data).hexdigest()}  {uki.name}\n".encode("ascii")
    sidecar.write_bytes(sidecar_data)
    attestation = _base_attestation(uki, sidecar, uki_data)
    raw = _encoded(attestation)
    fake_attestation_stat = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o400,
        st_uid=0,
        st_gid=0,
        st_size=len(raw),
        st_dev=10,
        st_ino=11,
        st_mtime_ns=12,
        st_ctime_ns=13,
    )
    fake_uki_stat = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o644,
        st_uid=0,
        st_gid=0,
        st_size=len(uki_data),
        st_dev=1,
        st_ino=2,
        st_mtime_ns=3,
        st_ctime_ns=4,
    )
    fake_sidecar_stat = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o644,
        st_uid=0,
        st_gid=0,
        st_size=len(sidecar_data),
        st_dev=1,
        st_ino=2,
        st_mtime_ns=3,
        st_ctime_ns=4,
    )

    monkeypatch.setattr(helper, "_validate_worker_context", lambda *args, **kwargs: None)
    monkeypatch.setattr(helper, "_verify_attested_self", lambda *args, **kwargs: {})
    monkeypatch.setattr(helper, "_validate_component_chain", lambda *args, **kwargs: fake_uki_stat)
    monkeypatch.setattr(
        helper,
        "_read_inherited_attestation",
        lambda *args, **kwargs: (raw, fake_attestation_stat, hashlib.sha256(raw).hexdigest()),
    )
    tool_records = {
        name: {
            "path": f"/usr/bin/{name}",
            "sha256": "b" * 64,
            "size": 1,
            "package": package,
            "package_version": "1-1",
        }
        for name, (_path, package) in helper.TOOLS.items()
    }
    monkeypatch.setattr(
        helper,
        "_collect_tool_records",
        lambda work: (tool_records, {package: "1-1" for package in helper.PACKAGE_SET}),
    )
    monkeypatch.setattr(
        helper,
        "_validate_package_managed_firmware",
        lambda *args, **kwargs: {
            "filename": "firmware.fd",
            "sha256": "c" * 64,
            "size": 1,
            "package": "edk2-ovmf",
            "package_version": "1-1",
        },
    )

    def fake_copy(source, destination, **kwargs):
        if Path(source) == helper.OVMF_VARS:
            destination.write_bytes(b"v")
            return "c" * 64, 1, fake_uki_stat
        destination.write_bytes(uki_data)
        return hashlib.sha256(uki_data).hexdigest(), len(uki_data), fake_uki_stat

    monkeypatch.setattr(helper, "_copy_nofollow", fake_copy)
    original_read = helper._read_nofollow

    def fake_read(path, **kwargs):
        if Path(path) == sidecar:
            return sidecar_data, fake_sidecar_stat
        return original_read(Path(path), **kwargs)

    monkeypatch.setattr(helper, "_read_nofollow", fake_read)
    monkeypatch.setattr(helper, "_prefix_nofollow", lambda *args, **kwargs: b"MZ")

    def fake_process(command, **kwargs):
        if "--list" in command:
            return b"No signature table present\n"
        if "req" in command:
            key = Path(command[command.index("-keyout") + 1])
            cert = Path(command[command.index("-out") + 1])
            key.write_text("disposable private material", encoding="utf-8")
            cert.write_text("disposable certificate", encoding="utf-8")
            raise helper.PreparationRefusal("injected certificate failure")
        raise AssertionError(command)

    monkeypatch.setattr(helper, "_bounded_process", fake_process)
    monkeypatch.setattr(
        helper,
        "_certificate_command",
        lambda role, key, cert: ["/usr/bin/openssl", "req", "-keyout", str(key), "-out", str(cert)],
    )

    with pytest.raises(helper.PreparationRefusal, match="injected certificate failure"):
        helper._prepare_worker(
            attestation_fd=99,
            attestation_path=tmp_path / "recovery-validation-attestation.json",
            staging=staging,
        )

    assert not list(staging.glob("*.key"))
    assert not list(staging.glob("*.crt"))
    assert not (staging / ".unsigned-validation.efi").exists()
    assert not (staging / ".variables.json").exists()


def test_receipt_finalization_binds_root_reclaimed_output_identities(tmp_path, monkeypatch):
    helper = _load_helper()
    staging = tmp_path / "staging"
    staging.mkdir(mode=0o700)
    uki = tmp_path / "candidate-validation-unsigned.efi"
    uki_data = b"MZcandidate"
    uki.write_bytes(uki_data)
    source_sidecar = Path(str(uki) + ".sha256")
    source_sidecar.write_text(
        f"{hashlib.sha256(uki_data).hexdigest()}  {uki.name}\n", encoding="ascii"
    )
    base = _base_attestation(uki, source_sidecar, uki_data)
    raw_base = _encoded(base)
    fake_attestation_stat = SimpleNamespace(
        st_mode=stat.S_IFREG | 0o400,
        st_uid=0,
        st_gid=0,
        st_size=len(raw_base),
        st_dev=20,
        st_ino=21,
        st_mtime_ns=22,
        st_ctime_ns=23,
    )
    builder_attestation = {
        "sha256": hashlib.sha256(raw_base).hexdigest(),
        "size": len(raw_base),
        "device": 20,
        "inode": 21,
        "mode": 0o400,
        "uid": 0,
        "gid": 0,
        "mtime_ns": 22,
        "ctime_ns": 23,
    }

    output_bytes = {
        "signed_uki": b"MZsigned",
        "enrolled_vars": b"vars",
        "secure_code": b"code",
    }
    signed_digest = hashlib.sha256(output_bytes["signed_uki"]).hexdigest()
    output_bytes["signed_uki_sha256"] = (
        f"{signed_digest}  {helper.OUTPUT_NAMES['signed_uki']}\n".encode("ascii")
    )
    for role, data in output_bytes.items():
        (staging / helper.OUTPUT_NAMES[role]).write_bytes(data)

    evidence = {
        "schema": helper.EVIDENCE_SCHEMA,
        "version": "0.10.3",
        "source_commit": "a" * 40,
        "created_at": "2026-09-01T10:00:00Z",
        "builder_attestation": builder_attestation,
        "unsigned_validation_uki": {
            "filename": uki.name,
            "sha256": hashlib.sha256(uki_data).hexdigest(),
            "size": len(uki_data),
            "builder_identity": {
                key: base["files"]["validation_uki"][key]
                for key in ("device", "inode", "mode", "uid", "gid", "mtime_ns", "ctime_ns")
            },
        },
        "firmware_inputs": {},
        "tools": {},
        "certificates": {},
        "enrolled_variables": {},
        "outputs": {
            role: {
                "filename": helper.OUTPUT_NAMES[role],
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }
            for role, data in output_bytes.items()
        },
        "private_keys_deleted": True,
        "network_namespace": "isolated-by-root-launcher",
    }
    evidence_path = staging / helper.EVIDENCE_NAME
    evidence_path.write_bytes(_encoded(evidence))
    evidence_path.chmod(0o400)

    monkeypatch.setattr(helper, "_validate_worker_context", lambda *args, **kwargs: None)
    monkeypatch.setattr(helper, "_verify_attested_self", lambda *args, **kwargs: {})
    monkeypatch.setattr(
        helper,
        "_read_inherited_attestation",
        lambda *args, **kwargs: (
            raw_base,
            fake_attestation_stat,
            hashlib.sha256(raw_base).hexdigest(),
        ),
    )
    original_read = helper._read_nofollow

    def fake_read(path, **kwargs):
        raw, metadata = original_read(Path(path), **kwargs)
        if Path(path) == evidence_path:
            metadata = SimpleNamespace(
                st_uid=helper.VALIDATION_UID,
                st_gid=helper.VALIDATION_GID,
                st_mode=stat.S_IFREG | 0o400,
            )
        return raw, metadata

    monkeypatch.setattr(helper, "_read_nofollow", fake_read)

    def fake_final_entry(path, maximum):
        data = Path(path).read_bytes()
        return {
            "filename": Path(path).name,
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "device": 30,
            "inode": 31,
            "mode": 0o644,
            "uid": 0,
            "gid": 0,
            "mtime_ns": 32,
            "ctime_ns": 33,
        }

    monkeypatch.setattr(helper, "_final_output_entry", fake_final_entry)
    receipt = helper._finalize_receipt_worker(
        attestation_fd=99,
        attestation_path=tmp_path / "recovery-validation-attestation.json",
        staging=staging,
    )

    assert receipt["schema"] == helper.RECEIPT_SCHEMA
    assert receipt["builder_attestation"] == builder_attestation
    assert receipt["outputs"]["signed_uki"]["sha256"] == signed_digest
    assert set(receipt["outputs"]["signed_uki"]) == {
        "filename",
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
    assert not evidence_path.exists()
    final_receipt = json.loads(
        (staging / helper.OUTPUT_NAMES["receipt"]).read_text(encoding="utf-8")
    )
    assert final_receipt == receipt


def test_root_cleanup_is_exact_and_does_not_follow_child_symlinks(tmp_path, monkeypatch):
    helper = _load_helper()
    build_base = tmp_path / "builder"
    build_base.mkdir()
    preparation = build_base / "secure-boot-prep.0123456789abcdef"
    preparation.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep").write_text("keep", encoding="utf-8")
    (preparation / "outside-link").symlink_to(outside, target_is_directory=True)
    (preparation / "private.key").write_text("disposable", encoding="utf-8")
    monkeypatch.setattr(helper, "BUILD_BASE", build_base.resolve())

    helper._cleanup_root(preparation, required_uid=os.getuid())

    assert not preparation.exists()
    assert (outside / "keep").read_text(encoding="utf-8") == "keep"
    with pytest.raises(helper.PreparationRefusal, match="outside"):
        helper._cleanup_root(outside, required_uid=os.getuid())


def test_validation_uid_retirement_is_bounded_and_kills_before_recheck(monkeypatch):
    helper = _load_helper()
    observed = []
    statuses = iter((0, 0, 1))

    def fake_run(command, **kwargs):
        observed.append((command, kwargs))
        return SimpleNamespace(returncode=next(statuses))

    monkeypatch.setattr(helper.subprocess, "run", fake_run)
    monkeypatch.setattr(helper.time, "sleep", lambda _seconds: None)
    helper._retire_validation_uid(
        {"pgrep": Path("/usr/bin/pgrep"), "pkill": Path("/usr/bin/pkill")}
    )

    assert observed[0][0] == ["/usr/bin/pgrep", "-u", str(helper.VALIDATION_UID)]
    assert observed[1][0] == [
        "/usr/bin/pkill",
        "-KILL",
        "-u",
        str(helper.VALIDATION_UID),
    ]
    assert observed[2][0] == observed[0][0]
    assert all(call[1]["timeout"] == 2 for call in observed)
    assert all(call[1]["stdout"] is subprocess.DEVNULL for call in observed)


def test_committed_helper_contract_is_unprivileged_network_isolated_and_keyless_on_success():
    source = HELPER.read_text(encoding="utf-8")
    assert "--net" in source
    assert "--no-new-privs" in source
    assert "--bounding-set=-all" in source
    assert "--inh-caps=-all" in source
    assert "--ambient-caps=-all" in source
    assert "--pdeathsig=KILL" in source
    assert "--reuid={}" in source
    assert "pass_fds=(attestation_fd,)" in source
    assert "O_NOFOLLOW" in source
    assert "files[\"validation_uki\"]" in source
    assert "files[\"validation_uki_sha256\"]" in source
    assert 'attestation["files"]["secure_boot_preparer"]' in source
    assert "_verify_attested_self(attestation)" in source
    assert "private_keys_deleted" in source
    assert "_unlink_private(keys)" in source
    assert "RLIMIT_AS" in source
    assert "RLIMIT_NPROC" in source
    assert "RLIMIT_CPU" in source
    assert "libc.prctl(1, signal.SIGKILL" in source
    assert "_retire_validation_uid(tools)" in source
    assert "isolated-by-root-launcher" in source
    assert str(helper_path := "/usr/share/edk2/x64/OVMF_CODE.secboot.4m.fd") in source
    assert helper_path.endswith("OVMF_CODE.secboot.4m.fd")
    assert "/usr/share/edk2/x64/OVMF_VARS.4m.fd" in source
    assert "--secure-boot" in source
    assert "--cert" in source
    assert "--output-json" in source
    assert "SecureBootEnable" in source and "CustomMode" in source
    assert "AURASCAN_RECOVERY_AI_ENABLED\": \"0" in source
