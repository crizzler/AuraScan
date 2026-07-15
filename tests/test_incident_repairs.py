import json
import os
from pathlib import Path

import aurascan.core.incident_repairs as incident_repairs
from aurascan.core.incident_repairs import (
    execute_dkms_autoinstall,
    execute_exact_package_reinstall,
    execute_initramfs_rebuild,
    execute_kernel_headers,
    execute_repository_restore,
    execute_repair_request,
    make_action,
    package_manager_processes,
    parse_repair_response,
    plan_exact_package_reinstall,
    plan_kernel_headers,
    plan_service_restart,
    plan_stale_lock,
    rollback_repository_repair,
)
from aurascan.core.models import Confidence, Severity


class Completed:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


class FakeRunner:
    def __init__(self, responses=None):
        self.responses = responses or {}
        self.calls = []

    def __call__(self, command, **_kwargs):
        command = list(command)
        self.calls.append(command)
        return self.responses.get(tuple(command), Completed())


def fake_which(found):
    return lambda name: f"/usr/bin/{name}" if name in found else None


def test_stale_lock_plan_requires_age_and_no_package_manager(tmp_path):
    lock = tmp_path / "db.lck"
    lock.write_text("", encoding="utf-8")
    os.utime(lock, (1, 1))
    proc = tmp_path / "proc"
    (proc / "100").mkdir(parents=True)
    (proc / "100" / "comm").write_text("bash\n", encoding="utf-8")

    action = plan_stale_lock(lock, proc_root=proc)

    assert action is not None
    assert action.recipe_id == "stale_pacman_lock"
    assert action.eligible and action.verified

    (proc / "101").mkdir()
    (proc / "101" / "comm").write_text("pacman\n", encoding="utf-8")
    assert package_manager_processes(proc) == ["pacman"]
    assert plan_stale_lock(lock, proc_root=proc) is None


def test_service_restart_denylist_blocks_critical_and_malformed_units():
    assert plan_service_restart("display-manager.service") is None
    assert plan_service_restart("sddm.service") is None
    assert plan_service_restart("../../evil.service") is None

    action = plan_service_restart("demo.service")

    assert action is not None
    assert action.recipe_id == "restart_system_service"
    assert action.requires_root is True


def test_user_service_restart_is_non_root_action():
    action = plan_service_restart("demo.service", user_service=True)

    assert action is not None
    assert action.recipe_id == "restart_user_service"
    assert action.requires_root is False
    assert action.command_preview[0][:2] == ["systemctl", "--user"]


def test_exact_package_reinstall_requires_missing_immutable_file_and_signed_exact_cache(tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()
    archive = cache / "demo-1.0-1-x86_64.pkg.tar.zst"
    archive.write_bytes(b"fixture package")
    signature = Path(str(archive) + ".sig")
    signature.write_bytes(b"fixture signature")
    responses = {
        ("pacman", "-Qm", "demo"): Completed(returncode=1),
        ("pacman", "-Q", "demo"): Completed("demo 1.0-1\n"),
        ("pacman", "-Qkk", "demo"): Completed("warning: missing file: demo /usr/bin/demo\n", returncode=1),
        ("pacman", "-Qp", str(archive)): Completed("demo 1.0-1\n"),
        ("pacman-key", "--verify", str(signature), str(archive)): Completed("valid", returncode=0),
    }

    action = plan_exact_package_reinstall(
        "demo",
        "demo",
        runner=FakeRunner(responses),
        which=fake_which({"pacman", "pacman-key", "demo"}),
        cache_root=cache,
    )

    assert action is not None
    assert action.recipe_id == "exact_package_reinstall"
    assert action.parameters["version"] == "1.0-1"
    assert action.parameters["archive"] == str(archive)


def test_package_integrity_parser_accepts_real_pacman_missing_file_wording():
    runner = FakeRunner({
        ("pacman", "-Qkk", "demo"): Completed(
            "warning: demo: /usr/bin/demo (No such file or directory)\n"
            "warning: demo: /opt/demo/data.bin (No such file or directory)\n"
            "warning: demo: /etc/demo.conf (No such file or directory)\n",
            returncode=1,
        )
    })

    assert incident_repairs.package_missing_immutable_files("demo", runner=runner) == [
        "/usr/bin/demo",
        "/opt/demo/data.bin",
    ]


def test_exact_package_reinstall_rejects_foreign_package(tmp_path):
    runner = FakeRunner({("pacman", "-Qm", "demo-aur"): Completed("demo-aur 1\n")})

    action = plan_exact_package_reinstall(
        "demo",
        "demo-aur",
        runner=runner,
        which=fake_which({"pacman", "demo"}),
        cache_root=tmp_path,
    )

    assert action is None


def test_repair_request_rejects_unknown_recipe_without_running_command(tmp_path):
    request = tmp_path / "request.json"
    action = make_action(
        "run_arbitrary_command",
        "Bad",
        "Bad",
        Severity.LOW,
        parameters={"command": ["rm", "-rf", "/"]},
        command_preview=[["rm", "-rf", "/"]],
    )
    request.write_text(json.dumps({"schema_version": "1.0", "actions": [action.to_dict()]}), encoding="utf-8")
    runner = FakeRunner()

    results, ok = execute_repair_request(request, runner=runner, repair_root=tmp_path / "repairs")

    assert ok is False
    assert results[0].status == "refused"
    assert runner.calls == []


def test_applied_repair_writes_bounded_manifest_with_trusted_commands(tmp_path):
    action = make_action(
        "restart_system_service",
        "Restart demo",
        "summary",
        Severity.MEDIUM,
        {"unit": "demo.service", "user_service": False, "category": "failed_service"},
        [["systemctl", "restart", "demo.service"]],
    )
    request = tmp_path / "request.json"
    request.write_text(json.dumps({"schema_version": "1.0", "actions": [action.to_dict()]}), encoding="utf-8")
    responses = {
        ("systemctl", "is-failed", "demo.service"): Completed("failed\n"),
        ("systemctl", "is-enabled", "demo.service"): Completed("enabled\n"),
        ("systemctl", "reset-failed", "demo.service"): Completed(),
        ("systemctl", "restart", "demo.service"): Completed(stderr="token=manifest-secret\n"),
        ("systemctl", "is-active", "demo.service"): Completed("active\n"),
    }
    repair_root = tmp_path / "repairs"

    results, ok = execute_repair_request(request, runner=FakeRunner(responses), repair_root=repair_root)

    manifest_path = next(repair_root.glob("*/manifest.json"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert ok is True
    assert results[0].status == "applied"
    assert oct(manifest_path.stat().st_mode & 0o777) == "0o600"
    assert manifest["schema"] == "incident_repair_manifest/1.0"
    assert manifest["actions"][0]["commands"][1] == ["systemctl", "restart", "demo.service"]
    assert manifest["actions"][0]["pre_validation"] == "passed"
    assert manifest["actions"][0]["post_validation"] == "passed"
    assert "manifest-secret" not in manifest_path.read_text(encoding="utf-8")
    assert "<redacted>" in manifest["actions"][0]["bounded_redacted_output"]


def test_dkms_autoinstall_refuses_when_fresh_status_is_clean(tmp_path):
    action = make_action(
        "dkms_autoinstall",
        "Rebuild DKMS",
        "summary",
        Severity.MEDIUM,
        {"kernels": ["linux"], "category": "kernel_module"},
        [["dkms", "autoinstall"]],
    )
    runner = FakeRunner({
        ("pacman", "-Qq"): Completed("linux\nlinux-headers\ndemo-dkms\n"),
        ("dkms", "status"): Completed("demo/1.0, 6.0, x86_64: installed\n"),
    })

    result = execute_dkms_autoinstall(action, runner=runner, which=fake_which({"dkms"}), run_root=tmp_path)

    assert result.status == "refused"
    assert ["dkms", "autoinstall"] not in runner.calls


def test_kernel_header_recipe_requires_exact_kernel_and_sync_versions(tmp_path):
    matching = FakeRunner({
        ("pacman", "-Q", "linux"): Completed("linux 6.1-1\n"),
        ("pacman", "-Sp", "--print-format", "%n %v", "linux-headers"): Completed("linux-headers 6.1-1\n"),
    })
    action = plan_kernel_headers(["linux", "demo-dkms"], runner=matching)

    assert action is not None
    assert action.parameters["versions"] == {"linux-headers": "6.1-1"}

    mismatch = FakeRunner({
        ("pacman", "-Q", "linux"): Completed("linux 6.1-1\n"),
        ("pacman", "-Sp", "--print-format", "%n %v", "linux-headers"): Completed("linux-headers 6.2-1\n"),
    })
    assert plan_kernel_headers(["linux", "demo-dkms"], runner=mismatch) is None

    responses = {
        ("pacman", "-Qq"): Completed("linux\ndemo-dkms\n"),
        ("pacman", "-Q", "linux"): Completed("linux 6.1-1\n"),
        ("pacman", "-Sp", "--print-format", "%n %v", "linux-headers"): Completed("linux-headers 6.2-1\n"),
    }
    fresh_mismatch = FakeRunner(responses)
    result = execute_kernel_headers(action, runner=fresh_mismatch, which=fake_which({"pacman"}), run_root=tmp_path)

    assert result.status == "refused"
    assert all(call[:2] != ["pacman", "-S"] for call in fresh_mismatch.calls)


def test_initramfs_rebuild_requires_fresh_failure_evidence(tmp_path):
    action = make_action(
        "initramfs_rebuild",
        "Rebuild initramfs",
        "summary",
        Severity.MEDIUM,
        {"generator": "mkinitcpio", "target_boot": "-1", "category": "initramfs"},
        [["mkinitcpio", "-P"]],
    )
    runner = FakeRunner()

    result = execute_initramfs_rebuild(action, runner=runner, which=fake_which({"mkinitcpio"}), run_root=tmp_path)

    assert result.status == "refused"
    assert ["mkinitcpio", "-P"] not in runner.calls


def test_repository_restore_rejects_non_system_pacman_config(tmp_path):
    action = make_action(
        "repository_restore",
        "Repair repos",
        "summary",
        Severity.MEDIUM,
        {"pacman_conf_path": str(tmp_path / "pacman.conf"), "category": "repository"},
        [],
    )

    result = execute_repository_restore(action, runner=FakeRunner(), which=fake_which(set()), run_root=tmp_path)

    assert result.status == "refused"


def test_repository_repair_rollback_restores_previous_file(tmp_path):
    target = tmp_path / "etc" / "mirrorlist"
    target.parent.mkdir()
    target.write_text("new\n", encoding="utf-8")
    backup_dir = tmp_path / "backup"
    backup_dir.mkdir()
    (backup_dir / "mirrorlist").write_text("old\n", encoding="utf-8")

    assert rollback_repository_repair([str(target)], backup_dir) is True
    assert target.read_text(encoding="utf-8") == "old\n"


def test_exact_package_reinstall_freshly_rejects_foreign_package(monkeypatch, tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()
    archive = cache / "demo-1.0-1-x86_64.pkg.tar.zst"
    archive.write_bytes(b"fixture")
    Path(str(archive) + ".sig").write_bytes(b"signature")
    monkeypatch.setattr(incident_repairs, "PACMAN_CACHE_ROOT", cache)
    action = make_action(
        "exact_package_reinstall",
        "Reinstall demo",
        "summary",
        Severity.MEDIUM,
        {
            "package": "demo",
            "version": "1.0-1",
            "archive": str(archive),
            "archive_sha256": incident_repairs.sha256_file(archive),
            "category": "application_crash",
        },
        [["pacman", "-U", str(archive)]],
    )
    runner = FakeRunner({
        ("pacman", "-Q", "demo"): Completed("demo 1.0-1\n"),
        ("pacman", "-Qm", "demo"): Completed("demo 1.0-1\n"),
    })

    result = execute_exact_package_reinstall(action, runner=runner, which=fake_which({"pacman", "pacman-key"}), run_root=tmp_path)

    assert result.status == "refused"
    assert "foreign" in result.message.lower()


def test_repair_response_requires_valid_json_and_success_exit():
    results, ok = parse_repair_response("not-json", 0)
    assert ok is False
    assert results[0].status == "failed"

    text = json.dumps({"ok": True, "results": [{"action_id": "a", "recipe_id": "r", "status": "applied", "message": "done"}]})
    results, ok = parse_repair_response(text, 0)
    assert ok is True
    assert results[0].verified is False
