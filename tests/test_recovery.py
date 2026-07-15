import io
import json
import os
import subprocess
import time
from pathlib import Path

import pytest

from aurascan.core.models import Severity
from aurascan.core.incidents import CoredumpGroup, IncidentEvidence
from aurascan.core.recovery import (
    RECOVERY_AI_ENABLED_ENV,
    RecoveryAction,
    RecoveryTargetCandidate,
    RecoveryPolicy,
    RecoveryRepairResult,
    RecoveryReport,
    _collect_target_coredumps,
    _initramfs_status,
    _transaction_incomplete,
    activate_recovery_storage_layers,
    apply_recovery_ai_plan,
    build_recovery_ai_prompt,
    discover_recovery_probes,
    discover_recovery_target_candidates,
    inspect_recovery_target,
    execute_recovery_probe,
    mount_recovery_target_read_only,
    parse_recovery_policy,
    render_recovery_policy,
    resolve_recovery_config,
    scan_recovery_target,
)
from aurascan.core.recovery_cli import (
    _load_target_recovery_context,
    _recovery_subprocess_runner,
    build_recovery_parser,
    create_recovery_overlay,
    install_or_refresh_recovery,
    recovery_status,
    run_recovery,
)
from aurascan.core.recovery_boot import UsbDeviceInfo
from aurascan.core.recovery_network import RecoveryNetworkState
from aurascan.core.recovery_repairs import (
    _execute_initramfs,
    _execute_snapshot_restore,
    _pacman_transaction_preconditions,
    _prepare_write_target,
    execute_recovery_plan,
    save_recovery_report,
)


class Response:
    def __init__(self, content):
        self.content = content

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps({"choices": [{"message": {"content": json.dumps(self.content)}}]}).encode()


class UrlOpenQueue:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def __call__(self, request, timeout=0):
        self.requests.append((request, timeout))
        return Response(self.responses.pop(0))


def write_package(root: Path, name: str, version: str = "1-1") -> None:
    directory = root / "var/lib/pacman/local" / f"{name}-{version}"
    directory.mkdir(parents=True, exist_ok=True)
    directory.joinpath("desc").write_text(
        f"%NAME%\n{name}\n\n%VERSION%\n{version}\n",
        encoding="utf-8",
    )


def make_target(tmp_path: Path, *, broken_repo: bool = False, interrupted: bool = False, modules: bool = True) -> Path:
    root = tmp_path / "target"
    (root / "etc/pacman.d").mkdir(parents=True)
    (root / "etc/os-release").write_text("ID=arch\nNAME=Arch Linux\n", encoding="utf-8")
    (root / "etc/pacman.conf").write_text("[core]\nInclude = /etc/pacman.d/mirrorlist\n", encoding="utf-8")
    mirror = root / "etc/pacman.d/mirrorlist"
    mirror.write_text("# Server = https://inactive.invalid/$repo/os/$arch\n" if broken_repo else "Server = https://mirror.example/$repo/os/$arch\n", encoding="utf-8")
    if broken_repo:
        (root / "etc/pacman.d/mirrorlist.pacnew").write_text("Server = https://mirror.example/$repo/os/$arch\n", encoding="utf-8")
    write_package(root, "linux-lts", "6.12.1-1")
    write_package(root, "linux-lts-headers", "6.12.1-1")
    if modules:
        module = root / "usr/lib/modules/6.12.1-arch1-1"
        module.mkdir(parents=True)
        (module / "pkgbase").write_text("linux-lts\n", encoding="utf-8")
        (module / "vmlinuz").write_bytes(b"kernel")
    (root / "boot/loader").mkdir(parents=True)
    (root / "boot/loader/loader.conf").write_text("default arch.conf\n", encoding="utf-8")
    (root / "boot/EFI/systemd").mkdir(parents=True)
    (root / "boot/EFI/systemd/systemd-bootx64.efi").write_bytes(b"MZfixture")
    (root / "boot/initramfs-linux-lts.img").write_bytes(b"image")
    (root / "var/log").mkdir(parents=True)
    log = "[ALPM] transaction failed\n" if interrupted else "[ALPM] transaction completed\n"
    (root / "var/log/pacman.log").write_text(log, encoding="utf-8")
    return root


def inspect_target(root: Path, **kwargs):
    return inspect_recovery_target(root, filesystem_hint="btrfs", **kwargs)


def test_recovery_policy_round_trip_and_config_defaults():
    policy = RecoveryPolicy(True, "limine", "automatic", 1000, "ask", "0.6.0", "ok")
    parsed = parse_recovery_policy(render_recovery_policy(policy))

    assert parsed.enabled is True
    assert parsed.bootloader == "limine"
    assert parsed.opted_in_uid == 1000
    assert parsed.wifi_profiles == "ask"
    assert resolve_recovery_config({}, policy=parsed).ai_enabled is False
    assert resolve_recovery_config({RECOVERY_AI_ENABLED_ENV: "1"}, policy=parsed).ai_enabled is True
    assert resolve_recovery_config({RECOVERY_AI_ENABLED_ENV: "maybe"}).error


def test_recovery_subprocesses_never_inherit_ai_credentials(monkeypatch):
    monkeypatch.setenv("AURASCAN_AI_KEY", "must-not-reach-tools")
    monkeypatch.setenv("AURASCAN_DEEPSEEK_API_KEY", "also-private")
    observed = {}

    def runner(command, **kwargs):
        observed.update(kwargs.get("env", {}))
        return subprocess.CompletedProcess(command, 0, "", "")

    _recovery_subprocess_runner(runner)(["probe"], capture_output=True, text=True)

    assert observed["HOME"] == "/root"
    assert "PATH" in observed
    assert "AURASCAN_AI_KEY" not in observed
    assert "AURASCAN_DEEPSEEK_API_KEY" not in observed


def test_recovery_reuses_incident_facts_only_privacy_policy():
    config = resolve_recovery_config({"AURASCAN_INCIDENT_AI_EVIDENCE": "facts-only"})

    assert config.facts_only is True
    assert resolve_recovery_config({"AURASCAN_INCIDENT_AI_EVIDENCE": "raw"}).error


def test_recovery_runtime_loads_separate_ai_consent_from_mounted_target(tmp_path, monkeypatch):
    root = make_target(tmp_path)
    uid = os.getuid()
    (root / "etc/passwd").write_text(f"fixture:x:{uid}:{uid}:Fixture:/home/fixture:/bin/bash\n", encoding="utf-8")
    config = root / "home/fixture/.config/aurascan/.env"
    config.parent.mkdir(parents=True)
    config.write_text(f"{RECOVERY_AI_ENABLED_ENV}=1\nAURASCAN_AI_PROVIDER=deepseek\n", encoding="utf-8")
    config.chmod(0o600)
    policy = RecoveryPolicy(enabled=True, opted_in_uid=uid, wifi_profiles="auto")
    monkeypatch.setattr("aurascan.core.recovery_cli.read_recovery_policy", lambda _path: policy)

    loaded_policy, loaded_config, loaded_env, note, loaded = _load_target_recovery_context(inspect_target(root), {})

    assert loaded_policy.opted_in_uid == uid
    assert loaded_config.ai_enabled is True
    assert loaded_config.wifi_profiles == "auto"
    assert loaded_env[RECOVERY_AI_ENABLED_ENV] == "1"
    assert note == "validated"
    assert loaded is True


def test_internal_overlay_explicitly_enables_recovery_service(tmp_path):
    overlay = create_recovery_overlay(tmp_path / "overlay")
    link = overlay / "etc/systemd/system/multi-user.target.wants/aurascan-recovery.service"

    assert link.is_symlink()
    assert os.readlink(link) == "/usr/lib/systemd/system/aurascan-recovery.service"
    assert not (overlay / "etc/hostname").exists()


def test_target_inspection_and_clean_scan_do_not_offer_destructive_repairs(tmp_path):
    root = make_target(tmp_path)
    target = inspect_target(root, mounted_read_only=True)
    report = scan_recovery_target(target)

    assert target.distro["id"] == "arch"
    assert target.filesystem == "btrfs"
    assert target.bootloader.kind == "systemd-boot"
    assert target.installed_kernels == ["linux-lts"]
    assert report.highest_severity == Severity.LOW
    assert report.eligible_actions == []


def test_recovery_snapshot_order_is_numeric(tmp_path):
    root = make_target(tmp_path)
    (root / ".snapshots/9/snapshot").mkdir(parents=True)
    (root / ".snapshots/10/snapshot").mkdir(parents=True)

    target = inspect_target(root)

    assert [item["id"] for item in target.snapshots] == [9, 10]


def test_plain_linux_kernel_does_not_match_linux_lts_initramfs(tmp_path):
    root = make_target(tmp_path)
    write_package(root, "linux", "7.1.0-1")
    target = inspect_target(root)

    _images, missing = _initramfs_status(target)

    assert "linux" in missing
    assert "linux-lts" not in missing


def test_unrelated_pacman_error_line_does_not_imply_interrupted_transaction():
    log = "[ALPM] transaction completed\n[hook] error: optional mirror timed out\n"

    assert _transaction_incomplete(log) is False
    assert _transaction_incomplete("[ALPM] transaction failed\n") is True


def test_recovery_scan_prepares_bounded_repo_repair(tmp_path):
    root = make_target(tmp_path, broken_repo=True)
    report = scan_recovery_target(inspect_target(root))

    assert {item.rule_id for item in report.findings} >= {"REC-REPOSITORY-BROKEN"}
    actions = [item for item in report.eligible_actions if item.recipe_id == "repository_restore"]
    assert len(actions) == 1
    assert actions[0].reversible is True
    assert all("/etc/pacman.d" in pair["target"] for pair in actions[0].parameters["pairs"])


def test_recovery_scan_detects_interrupted_transaction_and_missing_modules(tmp_path):
    root = make_target(tmp_path, interrupted=True, modules=False)
    report = scan_recovery_target(inspect_target(root))
    rule_ids = {item.rule_id for item in report.findings}

    assert "REC-PACMAN-INTERRUPTED" in rule_ids
    assert "REC-KERNEL-MODULES-MISSING" in rule_ids
    assert report.highest_severity == Severity.CRITICAL
    assert any(item.recipe_id == "complete_pacman_transaction" for item in report.eligible_actions)
    assert any(item.recipe_id == "kernel_module_restore" for item in report.eligible_actions)


def test_network_dependent_recovery_plan_defaults_no_while_offline(tmp_path):
    report = scan_recovery_target(inspect_target(make_target(tmp_path, interrupted=True)))

    assert any(item.recipe_id == "complete_pacman_transaction" for item in report.eligible_actions)
    assert report.network.connected is False
    assert report.apply_prompt_default_yes is False


def test_recovery_write_preparation_remounts_proven_containing_mount(tmp_path, monkeypatch):
    root = make_target(tmp_path)
    report = scan_recovery_target(inspect_target(root, mounted_read_only=True))
    commands = []

    def runner(command, **_kwargs):
        commands.append(command)
        if command[:5] == ["findmnt", "--noheadings", "--output", "TARGET,OPTIONS", "--target"]:
            return subprocess.CompletedProcess(command, 0, f"{root} ro,nosuid,nodev\n", "")
        if command[:4] == ["findmnt", "--noheadings", "--output", "OPTIONS"]:
            return subprocess.CompletedProcess(command, 0, "rw,nosuid,nodev\n", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr("aurascan.core.recovery_repairs.os.geteuid", lambda: 0)
    ready, _message = _prepare_write_target(report, runner)

    assert ready is True
    assert ["mount", "-o", "remount,rw", str(root)] in commands
    assert report.target.mounted_read_only is False


def test_recovery_report_schema_round_trip(tmp_path):
    report = scan_recovery_target(inspect_target(make_target(tmp_path, broken_repo=True)))
    report.network = RecoveryNetworkState(True, True, "full", "ethernet")

    loaded = RecoveryReport.from_dict(report.to_dict())

    assert loaded.schema_version == "1.0"
    assert loaded.target.distro["id"] == "arch"
    assert loaded.network.connected is True
    assert loaded.repair_actions[0].recipe_id == "repository_restore"


def test_two_pass_ai_can_select_probe_and_rank_only_known_action(tmp_path):
    report = scan_recovery_target(inspect_target(make_target(tmp_path, broken_repo=True)))
    report.network = RecoveryNetworkState(True, True, "full", "ethernet")
    probes = discover_recovery_probes(report)
    storage_probe = next(item.probe_id for item in probes if item.probe_type == "storage_space")
    action_id = report.eligible_actions[0].action_id
    urlopen = UrlOpenQueue([
        {
            "summary": "Run local repository and storage checks.",
            "likely_causes": [],
            "requested_probe_ids": [storage_probe, "invented-probe"],
            "recommended_action_ids": ["invented-action"],
        },
        {
            "summary": "The verified mirror restoration is the recommended plan.",
            "likely_causes": [],
            "requested_probe_ids": [storage_probe],
            "recommended_action_ids": [action_id, "invented-action"],
        },
    ])
    env = {
        "AURASCAN_AI_PROVIDER": "openai",
        "AURASCAN_OPENAI_API_KEY": "fixture-secret-key",
        "AURASCAN_AI_ENABLED": "1",
    }

    apply_recovery_ai_plan(report, enabled=True, env=env, urlopen=urlopen)

    assert report.ai_review["status"] == "ok"
    assert report.ai_review["provider_requests"] == 2
    assert report.ai_review["recommended_action_ids"] == [action_id]
    assert next(item for item in report.repair_actions if item.action_id == action_id).ai_recommended is True
    assert {item.probe_id for item in report.probe_results} >= {storage_probe}
    request_text = b"\n".join(item.data or b"" for item, _timeout in urlopen.requests)
    assert b"fixture-secret-key" not in request_text
    assert str(tmp_path).encode() not in request_text


def test_recovery_ai_skips_second_request_when_selected_probe_is_unavailable(tmp_path):
    report = scan_recovery_target(inspect_target(make_target(tmp_path)))
    report.network = RecoveryNetworkState(True, True, "full", "ethernet")
    unavailable_probe = next(
        item.probe_id for item in discover_recovery_probes(report)
        if item.probe_type == "failed_boot_services"
    )
    urlopen = UrlOpenQueue([{
        "summary": "Check target service evidence.",
        "likely_causes": [],
        "requested_probe_ids": [unavailable_probe],
        "recommended_action_ids": [],
    }])
    env = {
        "AURASCAN_AI_PROVIDER": "openai",
        "AURASCAN_OPENAI_API_KEY": "fixture-secret-key",
        "AURASCAN_AI_ENABLED": "1",
    }

    apply_recovery_ai_plan(
        report,
        enabled=True,
        env=env,
        urlopen=urlopen,
        which=lambda name: None if name == "journalctl" else f"/usr/bin/{name}",
    )

    assert report.ai_review["provider_requests"] == 1
    assert report.ai_review["status"] == "triage_only"
    assert len(urlopen.requests) == 1


def test_recovery_ai_prompt_remains_valid_json_inside_total_input_bound(tmp_path):
    report = scan_recovery_target(inspect_target(make_target(tmp_path, broken_repo=True)))
    assert report.incident_report is not None
    for index in range(120):
        report.incident_report.evidence.append(IncidentEvidence(f"extra-{index}", "fixture", "x" * 1000))

    prompt = build_recovery_ai_prompt(report, phase="triage", facts_only=False)
    payload = json.loads(prompt.partition("RECOVERY_DATA=")[2])

    assert len(prompt) <= 12000
    assert payload["phase"] == "triage"


def test_offline_ai_falls_back_to_required_local_probes(tmp_path):
    report = scan_recovery_target(inspect_target(make_target(tmp_path, broken_repo=True)))
    report.network = RecoveryNetworkState(True, False, "none")

    apply_recovery_ai_plan(report, enabled=True, env={})

    assert report.ai_review["status"] == "offline"
    assert report.ai_review["provider_requests"] == 0
    assert any(item.probe_type == "repository_health" for item in report.probe_results)


def test_repeated_crash_can_prepare_only_an_exact_signed_cached_reinstall(tmp_path, monkeypatch):
    root = make_target(tmp_path)
    write_package(root, "demo", "1-1")
    cache = root / "var/cache/pacman/pkg"
    cache.mkdir(parents=True)
    archive = cache / "demo-1-1-x86_64.pkg.tar.zst"
    archive.write_bytes(b"signed package fixture")
    Path(str(archive) + ".sig").write_bytes(b"signature fixture")
    report = scan_recovery_target(inspect_target(root))
    assert report.incident_report is not None
    report.incident_report.coredumps = [CoredumpGroup(
        "demo|SIGSEGV|frame",
        "/usr/bin/demo",
        "demo",
        "SIGSEGV",
        "frame",
        count=4,
        evidence_ids=["core-demo"],
    )]

    def runner(command, **_kwargs):
        if "-Qm" in command:
            return subprocess.CompletedProcess(command, 1, "", "")
        if "-Qkk" in command:
            return subprocess.CompletedProcess(command, 1, "warning: missing file: demo /usr/bin/demo\n", "")
        if "-Qp" in command:
            return subprocess.CompletedProcess(command, 0, "demo 1-1\n", "")
        if "--verify" in command:
            return subprocess.CompletedProcess(command, 0, "signature valid\n", "")
        return subprocess.CompletedProcess(command, 1, "", "unsupported fixture command")

    monkeypatch.setattr(
        "aurascan.core.recovery._root_owned_target_file",
        lambda path, target_root, max_size: path.is_file()
        and not path.is_symlink()
        and path.stat().st_size <= max_size
        and path.resolve().is_relative_to(target_root.resolve()),
    )
    probe = next(item for item in discover_recovery_probes(report) if item.probe_type == "crashed_package_integrity")

    result = execute_recovery_probe(
        report,
        probe,
        runner=runner,
        which=lambda name: f"/usr/bin/{name}",
    )

    assert probe.required is True
    assert result.status == "action_ready"
    action = next(item for item in report.eligible_actions if item.recipe_id == "exact_package_reinstall")
    assert action.parameters["package"] == "demo"
    assert action.parameters["version"] == "1-1"
    assert action.parameters["archive_sha256"]
    assert result.action_ids == [action.action_id]


def test_latest_target_boot_service_failure_is_probed_without_ai(tmp_path):
    root = make_target(tmp_path)
    (root / "var/log/journal").mkdir(parents=True)
    commands = []
    journal = "Jul 15 08:00:00 target systemd[1]: Failed to start demo.service - Demo service.\n"

    def runner(command, **_kwargs):
        commands.append(command)
        if command[0] == "journalctl":
            return subprocess.CompletedProcess(command, 0, journal, "")
        return subprocess.CompletedProcess(command, 1, "", "")

    report = scan_recovery_target(
        inspect_target(root),
        runner=runner,
        which=lambda name: f"/usr/bin/{name}" if name == "journalctl" else None,
    )
    apply_recovery_ai_plan(
        report,
        enabled=False,
        runner=runner,
        which=lambda name: f"/usr/bin/{name}" if name == "journalctl" else None,
    )

    assert "INC-SYSTEMD-FAILED" in {item.rule_id for item in report.findings}
    assert any(item.recipe_id == "disable_boot_service" for item in report.eligible_actions)
    assert all("--boot=0" in command for command in commands if command[0] == "journalctl")


def test_target_coredump_collection_is_scoped_to_mounted_root(tmp_path):
    root = make_target(tmp_path)
    (root / "var/log/journal").mkdir(parents=True)
    commands = []

    def runner(command, **_kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    _collect_target_coredumps(
        root,
        runner=runner,
        which=lambda name: f"/usr/bin/{name}" if name in {"coredumpctl", "journalctl"} else None,
    )

    coredump_command = next(command for command in commands if command[0] == "coredumpctl")
    journal_command = next(command for command in commands if command[0] == "journalctl")
    assert f"--root={root}" in coredump_command
    assert f"--directory={root / 'var/log/journal'}" in journal_command


def test_target_candidate_parser_tracks_encryption_layers():
    payload = {
        "blockdevices": [{
            "path": "/dev/nvme0n1p2", "fstype": "crypto_LUKS", "label": "cryptroot", "uuid": "abc", "size": 1000,
            "mountpoints": [None], "type": "part",
            "children": [{"path": "/dev/mapper/root", "fstype": "btrfs", "label": "root", "uuid": "def", "size": 900, "mountpoints": [None], "type": "crypt"}],
        }]
    }

    def runner(command, **_kwargs):
        return subprocess.CompletedProcess(command, 0, json.dumps(payload), "")

    candidates = discover_recovery_target_candidates(runner=runner, which=lambda _name: "/usr/bin/lsblk")

    assert candidates[0].device == "/dev/mapper/root"
    assert candidates[0].encrypted is True
    assert "crypto_luks" in candidates[0].storage_layers


def test_unknown_filesystem_is_listed_as_diagnosis_only():
    payload = {
        "blockdevices": [{
            "path": "/dev/sdz9",
            "fstype": "futurefs",
            "label": "unknown-root",
            "uuid": "fixture",
            "size": 1000,
            "mountpoints": [None],
            "type": "part",
        }]
    }

    candidates = discover_recovery_target_candidates(
        runner=lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, json.dumps(payload), ""),
        which=lambda _name: "/usr/bin/lsblk",
    )

    assert len(candidates) == 1
    assert candidates[0].supported is False
    assert "diagnosis only" in candidates[0].reason


def test_lvm_discovery_activates_logical_volumes_read_only():
    commands = []

    def runner(command, **_kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "", "")

    activate_recovery_storage_layers(
        runner=runner,
        which=lambda name: "/usr/bin/vgchange" if name == "vgchange" else None,
    )

    assert commands == [["/usr/bin/vgchange", "--activate", "y", "--readonly"]]


def test_recovery_cli_parser_has_management_and_safety_flags():
    parser = build_recovery_parser()
    args = parser.parse_args(["--install", "--dry-run", "--no-ai", "--facts-only", "--yes"])

    assert args.install is True
    assert args.dry_run is True
    assert args.no_ai is True
    assert args.facts_only is True
    assert args.yes is True


def test_internal_install_dry_run_requires_no_esp_write(tmp_path):
    root = make_target(tmp_path)
    paths = {
        "mkosi": "/usr/bin/mkosi",
        "ukify": "/usr/bin/ukify",
    }

    result = install_or_refresh_recovery(
        root=root,
        dry_run=True,
        runner=lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, "", ""),
        which=lambda name: paths.get(name),
    )

    assert result.ok is True
    assert result.status == "dry_run"
    assert result.details["build_command"][0] == "/usr/bin/mkosi"
    assert not (root / "boot/EFI/Linux/aurascan-recovery.efi").exists()


def test_recovery_iso_download_dry_run_never_opens_network(tmp_path, monkeypatch):
    manifest = {
        "version": "0.6.0",
        "url": "https://github.com/crizzler/AuraScan/releases/download/v0.6.0/AuraScan-Recovery-0.6.0.iso",
        "sha256": "a" * 64,
    }
    monkeypatch.setattr("aurascan.core.recovery_cli.load_iso_manifest", lambda _path: manifest)
    stdout = io.StringIO()

    status = run_recovery(
        ["--download-iso", "--iso", str(tmp_path / "recovery.iso"), "--dry-run", "--json"],
        stdout=stdout,
        urlopen=lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("dry-run opened the network")),
    )

    data = json.loads(stdout.getvalue())
    assert status == 0
    assert data["status"] == "dry_run"
    assert not (tmp_path / "recovery.iso").exists()


def test_recovery_usb_dry_run_is_read_only_and_noninteractive(tmp_path, monkeypatch):
    iso = tmp_path / "recovery.iso"
    iso.write_bytes(b"fixture")
    device = UsbDeviceInfo("/dev/sdz", "disk", True, 8 * 1024 ** 3, "Fixture USB", "SERIAL", eligible=True)
    monkeypatch.setattr("aurascan.core.recovery_cli.load_iso_manifest", lambda _path: {"version": "0.6.0", "sha256": "a" * 64})
    monkeypatch.setattr("aurascan.core.recovery_cli.verify_recovery_iso", lambda *_args, **_kwargs: (True, "verified", "a" * 64))
    monkeypatch.setattr("aurascan.core.recovery_cli.inspect_usb_device", lambda *_args, **_kwargs: device)
    monkeypatch.setattr("aurascan.core.recovery_cli.write_iso_to_usb", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("dry-run wrote USB")))
    stdout = io.StringIO()

    status = run_recovery(
        ["--write-usb", "/dev/sdz", "--iso", str(iso), "--dry-run", "--json"],
        stdout=stdout,
        input_func=lambda _prompt: (_ for _ in ()).throw(AssertionError("dry-run prompted")),
        runner=lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, "/dev/nvme0n1p2\n", ""),
    )

    data = json.loads(stdout.getvalue())
    assert status == 0
    assert data["status"] == "dry_run"
    assert data["details"]["device"]["path"] == "/dev/sdz"


def test_luks_target_is_opened_read_only_and_closed_after_mount_failure(tmp_path, monkeypatch):
    candidate = RecoveryTargetCandidate(
        device="/dev/nvme0n1p2",
        fstype="crypto_luks",
        encrypted=True,
        storage_layers=["crypto_luks"],
        supported=True,
    )
    commands = []

    def runner(command, **_kwargs):
        commands.append(command)
        if command[:2] == ["lsblk", "--noheadings"]:
            return subprocess.CompletedProcess(command, 0, "ext4\n", "")
        if command[0] == "mount":
            return subprocess.CompletedProcess(command, 1, "", "mount failed")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr("aurascan.core.recovery.os.geteuid", lambda: 0)
    target, _message = mount_recovery_target_read_only(
        candidate,
        mount_root=tmp_path / "mount",
        runner=runner,
        which=lambda name: f"/usr/bin/{name}" if name == "cryptsetup" else None,
    )

    assert target is None
    open_command = next(command for command in commands if command[:2] == ["cryptsetup", "open"])
    assert "--readonly" in open_command
    assert any(command[:2] == ["cryptsetup", "close"] for command in commands)


@pytest.mark.parametrize(("filesystem", "required_option"), [("ext4", "noload"), ("xfs", "norecovery")])
def test_recovery_mount_uses_no_replay_option_for_read_only_filesystems(tmp_path, monkeypatch, filesystem, required_option):
    candidate = RecoveryTargetCandidate(device="/dev/sdz1", fstype=filesystem, supported=True)
    commands = []

    def runner(command, **_kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 1, "", "mount refused")

    monkeypatch.setattr("aurascan.core.recovery.os.geteuid", lambda: 0)
    mount_recovery_target_read_only(candidate, mount_root=tmp_path / "mount", runner=runner)

    mount_command = next(command for command in commands if command[0] == "mount")
    assert required_option in mount_command[2].split(",")


def test_status_command_is_management_only_outside_recovery(tmp_path):
    root = make_target(tmp_path)
    stdout = io.StringIO()

    status = run_recovery(
        ["--status", "--root", str(root), "--json"],
        stdout=stdout,
        runner=lambda command, **_kwargs: subprocess.CompletedProcess(command, 1, "", ""),
        which=lambda _name: None,
    )

    assert status == 0
    data = json.loads(stdout.getvalue())
    assert data["schema"] == "recovery_status/1.0"
    assert data["image"]["bootloader"]["kind"] == "systemd-boot"


def test_json_recovery_is_report_only_and_does_not_prompt_without_yes(tmp_path):
    root = make_target(tmp_path, broken_repo=True)
    stdout = io.StringIO()
    stderr = io.StringIO()

    status = run_recovery(
        ["--root", str(root), "--json", "--no-ai"],
        stdout=stdout,
        stderr=stderr,
        input_func=lambda _prompt: (_ for _ in ()).throw(AssertionError("JSON recovery prompted")),
        runner=lambda command, **_kwargs: subprocess.CompletedProcess(command, 1, "", ""),
        which=lambda _name: None,
    )

    data = json.loads(stdout.getvalue())
    assert status == 0
    assert data["schema"] == "recovery_report/1.0"
    assert data["repair_results"] == []
    assert "Discovering" in stderr.getvalue()


def test_json_yes_emits_one_post_repair_report_and_never_requests_typed_confirmation(tmp_path, monkeypatch):
    root = make_target(tmp_path)
    report = scan_recovery_target(inspect_target(root))
    ordinary = RecoveryAction(
        "rec-ordinary",
        "fixture",
        "Apply ordinary repair",
        "Fixture repair",
        Severity.LOW,
        eligible=True,
        verified=True,
    )
    destructive = RecoveryAction(
        "rec-destructive",
        "snapshot_restore",
        "Restore snapshot",
        "Fixture destructive repair",
        Severity.CRITICAL,
        eligible=True,
        verified=True,
        confirmation_phrase="RESTORE SNAPSHOT 7",
    )
    report.repair_actions = [ordinary, destructive]

    def execute(candidate, *, typed_confirmations, **_kwargs):
        assert typed_confirmations == {}
        candidate.repair_results = [
            RecoveryRepairResult(ordinary.action_id, ordinary.recipe_id, "applied", "ordinary repair applied", True),
            RecoveryRepairResult(destructive.action_id, destructive.recipe_id, "declined", "typed confirmation was not supplied"),
        ]
        return candidate.repair_results

    monkeypatch.setattr("aurascan.core.recovery_cli.scan_recovery_target", lambda *_args, **_kwargs: report)
    monkeypatch.setattr(
        "aurascan.core.recovery_cli._configure_runtime_network",
        lambda *_args, **_kwargs: RecoveryNetworkState(True, False, "none"),
    )
    monkeypatch.setattr("aurascan.core.recovery_cli.apply_recovery_ai_plan", lambda *_args, **_kwargs: report)
    monkeypatch.setattr("aurascan.core.recovery_cli.execute_recovery_plan", execute)
    monkeypatch.setattr("aurascan.core.recovery_cli.save_recovery_report", lambda *_args, **_kwargs: (None, "saved"))
    stdout = io.StringIO()

    status = run_recovery(
        ["--root", str(root), "--json", "--yes", "--no-ai"],
        stdout=stdout,
        stderr=io.StringIO(),
        input_func=lambda _prompt: (_ for _ in ()).throw(AssertionError("JSON recovery prompted")),
        runner=lambda command, **_kwargs: subprocess.CompletedProcess(command, 1, "", ""),
        which=lambda _name: None,
    )

    payload = json.loads(stdout.getvalue())
    assert status == 0
    assert [item["status"] for item in payload["repair_results"]] == ["applied", "declined"]


def test_yes_does_not_supply_snapshot_or_bootloader_typed_confirmation(tmp_path, monkeypatch):
    root = make_target(tmp_path, interrupted=True)
    snapshot = root / ".snapshots/7/snapshot"
    snapshot.mkdir(parents=True)
    report = scan_recovery_target(inspect_target(root, mounted_read_only=False))
    destructive = [item for item in report.eligible_actions if item.confirmation_phrase]
    assert destructive
    report.repair_actions = destructive
    monkeypatch.setattr("aurascan.core.recovery_repairs.os.geteuid", lambda: 0)

    results = execute_recovery_plan(report, typed_confirmations={}, runner=lambda command, **_kwargs: subprocess.CompletedProcess(command, 0, "", ""))

    assert all(item.status == "declined" for item in results)


def test_snapshot_restore_validates_a_new_pre_recovery_snapshot_before_rollback(tmp_path):
    root = make_target(tmp_path, interrupted=True)
    (root / ".snapshots/7/snapshot").mkdir(parents=True)
    (root / ".snapshots/8/snapshot").mkdir(parents=True)
    (root / "usr/bin").mkdir(parents=True, exist_ok=True)
    (root / "usr/bin/snapper").write_text("fixture\n", encoding="utf-8")
    report = scan_recovery_target(inspect_target(root, mounted_read_only=False))
    action = next(item for item in report.eligible_actions if item.recipe_id == "snapshot_restore")
    commands = []

    def runner(command, **_kwargs):
        commands.append(command)
        if "create" in command:
            (root / ".snapshots/9/snapshot").mkdir(parents=True)
            output = "9\n"
        else:
            output = "rollback complete\n"
        return subprocess.CompletedProcess(command, 0, output, "")

    result = _execute_snapshot_restore(report, action, runner)

    assert result.status == "applied"
    assert result.verified is True
    assert result.rollback_available is True
    assert result.backup_path.endswith("/.snapshots/9/snapshot")
    assert any("create" in command for command in commands)
    assert any("rollback" in command for command in commands)


def test_snapshot_restore_refuses_rollback_when_new_snapshot_cannot_be_proven(tmp_path):
    root = make_target(tmp_path, interrupted=True)
    (root / ".snapshots/7/snapshot").mkdir(parents=True)
    (root / "usr/bin").mkdir(parents=True, exist_ok=True)
    (root / "usr/bin/snapper").write_text("fixture\n", encoding="utf-8")
    report = scan_recovery_target(inspect_target(root, mounted_read_only=False))
    action = next(item for item in report.eligible_actions if item.recipe_id == "snapshot_restore")
    commands = []

    def runner(command, **_kwargs):
        commands.append(command)
        return subprocess.CompletedProcess(command, 0, "8\n", "")

    result = _execute_snapshot_restore(report, action, runner)

    assert result.status == "failed"
    assert "could not be validated" in result.message
    assert not any("rollback" in command for command in commands)


def test_failed_initramfs_rebuild_restores_previous_image_set(tmp_path):
    root = make_target(tmp_path, interrupted=True)
    generator = root / "usr/bin/mkinitcpio"
    generator.parent.mkdir(parents=True, exist_ok=True)
    generator.write_text("fixture\n", encoding="utf-8")
    report = scan_recovery_target(inspect_target(root, mounted_read_only=False))
    action = RecoveryAction(
        "fixture-initramfs",
        "initramfs_rebuild",
        "Rebuild initramfs",
        "Fixture action",
        Severity.HIGH,
        parameters={"generator": "mkinitcpio"},
        eligible=True,
        verified=True,
    )
    original = root / "boot/initramfs-linux-lts.img"
    created = root / "boot/initramfs-new.img"

    def runner(command, **_kwargs):
        original.write_bytes(b"broken")
        created.write_bytes(b"partial")
        return subprocess.CompletedProcess(command, 1, "", "generator failed")

    result = _execute_initramfs(report, action, tmp_path / "backups", [], runner)

    assert result.status == "rolled_back"
    assert original.read_bytes() == b"image"
    assert not created.exists()


def test_recovery_pacman_transaction_requires_trusted_signatures_and_servers(tmp_path):
    root = make_target(tmp_path)

    def runner(command, **_kwargs):
        if command[-1] == "SigLevel" and not any(item.startswith("--repo=") for item in command):
            output = "PackageRequired\nPackageTrustedOnly\nDatabaseOptional\nDatabaseTrustedOnly\n"
        elif command[-1] == "--repo-list":
            output = "core\nextra\n"
        elif command[-1] == "Server":
            output = "https://mirror.example/$repo/os/$arch\n"
        else:
            output = ""
        return subprocess.CompletedProcess(command, 0, output, "")

    ready, message = _pacman_transaction_preconditions(root, runner)

    assert ready is True
    assert "passed" in message


def test_recovery_pacman_transaction_refuses_optional_package_signatures(tmp_path):
    root = make_target(tmp_path)

    def runner(command, **_kwargs):
        output = "PackageOptional\nPackageTrustAll\n" if command[-1] == "SigLevel" else "core\n"
        return subprocess.CompletedProcess(command, 0, output, "")

    ready, message = _pacman_transaction_preconditions(root, runner)

    assert ready is False
    assert "signature" in message


def test_recovery_status_contains_no_ai_key(tmp_path):
    root = make_target(tmp_path)
    status = recovery_status(root=root, runner=lambda command, **_kwargs: subprocess.CompletedProcess(command, 1, "", ""), which=lambda _name: None)

    assert "api_key" not in json.dumps(status).lower()


def test_recovery_report_refuses_target_state_symlink_and_falls_back_to_runtime(tmp_path, monkeypatch):
    root = make_target(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    state_parent = root / "var/lib"
    state_parent.mkdir(parents=True, exist_ok=True)
    (state_parent / "aurascan").symlink_to(outside, target_is_directory=True)
    runtime = tmp_path / "runtime"
    monkeypatch.setattr("aurascan.core.recovery_repairs.RECOVERY_STATE_ROOT", runtime)
    report = scan_recovery_target(inspect_target(root))

    path, message = save_recovery_report(report)

    assert path is not None
    assert path.relative_to(runtime)
    assert not list(outside.iterdir())
    assert "recovery RAM" in message
