import io
import json
import subprocess

from aurascan.core import config_drift
from aurascan.core.config_drift import (
    EXIT_CONFIG_DRIFT_USER_DECLINED,
    apply_ai_config_drift_review,
    apply_config_drift_actions,
    build_config_drift_report,
    classify_config_drift_file,
    config_drift_options_from_args,
    discover_config_drift_files,
    drift_target_path,
    plan_config_drift_action,
    redact_text,
    redacted_preview_diff,
    run_config_drift,
)


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


def test_discover_config_drift_files_classifies_risk_and_targets(tmp_path):
    root = tmp_path / "etc"
    (root / "pacman.d").mkdir(parents=True)
    (root / "pacman.d" / "mirrorlist").write_text("old\n", encoding="utf-8")
    (root / "pacman.d" / "mirrorlist.pacnew").write_text("new\n", encoding="utf-8")
    (root / "pacman.conf.pacnew").write_text("[options]\n", encoding="utf-8")
    (root / "demo.conf.pacsave").write_text("saved\n", encoding="utf-8")

    files, truncated = discover_config_drift_files(root)
    by_name = {item.path.name: item for item in files}

    assert truncated is False
    assert drift_target_path(root / "pacman.conf.pacnew") == root / "pacman.conf"
    assert by_name["mirrorlist.pacnew"].risk == "low"
    assert by_name["mirrorlist.pacnew"].low_risk is True
    assert by_name["pacman.conf.pacnew"].risk == "sensitive"
    assert by_name["pacman.conf.pacnew"].sensitive is True
    assert by_name["demo.conf.pacsave"].kind == "pacsave"


def test_discovery_truncation_is_reported(tmp_path):
    root = tmp_path / "etc"
    root.mkdir()
    for index in range(3):
        (root / f"demo{index}.conf.pacnew").write_text("new\n", encoding="utf-8")

    files, truncated = discover_config_drift_files(root, max_entries=2)

    assert truncated is True
    assert len(files) <= 2


def test_plan_config_drift_actions_cover_safe_and_manual_cases(tmp_path):
    root = tmp_path / "etc"
    root.mkdir()
    identical = root / "same.conf"
    identical.write_text("value=1\n", encoding="utf-8")
    identical_pacnew = root / "same.conf.pacnew"
    identical_pacnew.write_text("value=1\n", encoding="utf-8")
    mirror = root / "mirrorlist"
    mirror.write_text("old\n", encoding="utf-8")
    mirror_pacnew = root / "mirrorlist.pacnew"
    mirror_pacnew.write_text("new\n", encoding="utf-8")
    pacman = root / "pacman.conf"
    pacman.write_text("[options]\nHoldPkg = pacman\n", encoding="utf-8")
    pacman_pacnew = root / "pacman.conf.pacnew"
    pacman_pacnew.write_text("[options]\nColor\n", encoding="utf-8")
    comments = root / "resolv.conf"
    comments.write_text("nameserver 1.1.1.1\n", encoding="utf-8")
    comments_pacnew = root / "resolv.conf.pacnew"
    comments_pacnew.write_text("# packaged\nnameserver 1.1.1.1\n", encoding="utf-8")
    pacsave = root / "old.conf.pacsave"
    pacsave.write_text("old\n", encoding="utf-8")
    binary = root / "binary.conf.pacnew"
    binary.write_bytes(b"a\x00b")

    actions = {
        path.name: plan_config_drift_action(classify_config_drift_file(path, root=root))
        for path in (identical_pacnew, mirror_pacnew, pacman_pacnew, comments_pacnew, pacsave, binary)
    }

    assert actions["same.conf.pacnew"].action == "remove_identical_drift"
    assert actions["same.conf.pacnew"].applies is True
    assert actions["mirrorlist.pacnew"].action == "replace_low_risk_config"
    assert actions["mirrorlist.pacnew"].requires_confirmation is False
    assert actions["pacman.conf.pacnew"].action == "manual_merge_required"
    assert actions["pacman.conf.pacnew"].applies is False
    assert actions["resolv.conf.pacnew"].action == "replace_comments_only_config"
    assert actions["resolv.conf.pacnew"].requires_confirmation is True
    assert actions["old.conf.pacsave"].action == "explain_pacsave"
    assert actions["binary.conf.pacnew"].action == "manual_review"


def test_apply_config_drift_actions_backs_up_writes_and_removes_pacnew(tmp_path):
    root = tmp_path / "etc"
    root.mkdir()
    target = root / "mirrorlist"
    drift = root / "mirrorlist.pacnew"
    target.write_text("old\n", encoding="utf-8")
    drift.write_text("new\n", encoding="utf-8")
    report = build_config_drift_report(root)

    ok = apply_config_drift_actions(report, backup_root=tmp_path / "backups")

    assert ok is True
    assert target.read_text(encoding="utf-8") == "new\n"
    assert not drift.exists()
    assert report.applied
    manifest = next((tmp_path / "backups").glob("*/manifest.json"))
    data = json.loads(manifest.read_text(encoding="utf-8"))
    assert data["actions"][0]["target_sha256"]
    assert (manifest.parent / "files").exists()


def test_apply_failure_restores_original_target(tmp_path, monkeypatch):
    root = tmp_path / "etc"
    root.mkdir()
    target = root / "mirrorlist"
    drift = root / "mirrorlist.pacnew"
    target.write_text("old\n", encoding="utf-8")
    drift.write_text("new\n", encoding="utf-8")
    report = build_config_drift_report(root)

    def broken_apply(action):
        action.drift_file.target_path.write_text("broken\n", encoding="utf-8")
        raise OSError("simulated write failure")

    monkeypatch.setattr(config_drift, "apply_one_action", broken_apply)

    ok = apply_config_drift_actions(report, backup_root=tmp_path / "backups")

    assert ok is False
    assert target.read_text(encoding="utf-8") == "old\n"
    assert drift.exists()
    assert report.errors


def test_redaction_removes_secrets_from_ai_diffs(tmp_path):
    root = tmp_path / "etc"
    root.mkdir()
    target = root / "demo.conf"
    drift = root / "demo.conf.pacnew"
    target.write_text("password=super-secret\nurl=https://user:pass@example.invalid\n", encoding="utf-8")
    drift.write_text(
        "password=other-secret\n"
        "key: abc123\n"
        "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n",
        encoding="utf-8",
    )

    redacted = redacted_preview_diff(target, drift)

    assert "super-secret" not in redacted
    assert "other-secret" not in redacted
    assert "user:pass" not in redacted
    assert "abc123" not in redacted
    assert "PRIVATE KEY-----\nsecret" not in redacted
    assert "<redacted>" in redact_text("api_key=abc")


def test_ai_review_is_opt_in_and_adds_notes_when_enabled(tmp_path, monkeypatch):
    root = tmp_path / "etc"
    root.mkdir()
    (root / "mirrorlist").write_text("old\n", encoding="utf-8")
    drift = root / "mirrorlist.pacnew"
    drift.write_text("new\n", encoding="utf-8")
    report = build_config_drift_report(root)
    monkeypatch.setenv("AURASCAN_AI_ENABLED", "1")
    monkeypatch.setenv("AURASCAN_AI_PROVIDER", "openai")
    monkeypatch.setenv("AURASCAN_OPENAI_API_KEY", "fixture-only-value")

    def fake_urlopen(_req, timeout):
        return FakeResponse({
            "choices": [{
                "message": {
                    "content": json.dumps({
                        "summary": "mirror update",
                        "files": [{"path": str(drift), "risk_notes": "Mirrorlist replacement looks routine.", "confidence": "high"}],
                    })
                }
            }]
        })

    apply_ai_config_drift_review(report, urlopen=fake_urlopen)

    assert report.ai_review["status"] == "ok"
    assert report.actions[0].ai_note == "Mirrorlist replacement looks routine."


def test_config_drift_cli_dry_run_and_json_do_not_apply(tmp_path):
    root = tmp_path / "etc"
    root.mkdir()
    target = root / "mirrorlist"
    drift = root / "mirrorlist.pacnew"
    target.write_text("old\n", encoding="utf-8")
    drift.write_text("new\n", encoding="utf-8")
    stdout = io.StringIO()

    status = run_config_drift(["--dry-run", "--no-ai", "--root", str(root)], stdout=stdout)

    assert status == 0
    assert target.read_text(encoding="utf-8") == "old\n"
    assert "Config Drift Assistant" in stdout.getvalue()

    json_stdout = io.StringIO()
    status = run_config_drift(["--json", "--no-ai", "--root", str(root)], stdout=json_stdout)
    data = json.loads(json_stdout.getvalue())

    assert status == 0
    assert data["report_type"] == "config_drift"
    assert target.read_text(encoding="utf-8") == "old\n"


def test_config_drift_cli_yes_applies_and_prompt_decline_does_not(tmp_path):
    root = tmp_path / "etc"
    root.mkdir()
    target = root / "mirrorlist"
    drift = root / "mirrorlist.pacnew"
    target.write_text("old\n", encoding="utf-8")
    drift.write_text("new\n", encoding="utf-8")

    declined = run_config_drift(
        ["--no-ai", "--root", str(root)],
        input_func=lambda _prompt: "",
        stdout=io.StringIO(),
        stderr=io.StringIO(),
        backup_root=tmp_path / "backups-declined",
    )

    assert declined == EXIT_CONFIG_DRIFT_USER_DECLINED
    assert target.read_text(encoding="utf-8") == "old\n"

    status = run_config_drift(
        ["--yes", "--no-ai", "--root", str(root)],
        stdout=io.StringIO(),
        backup_root=tmp_path / "backups",
    )

    assert status == 0
    assert target.read_text(encoding="utf-8") == "new\n"
    assert not drift.exists()


def test_config_drift_cli_yes_reexecs_with_sudo_for_default_backup_root(tmp_path, monkeypatch):
    root = tmp_path / "etc"
    root.mkdir()
    target = root / "mirrorlist"
    drift = root / "mirrorlist.pacnew"
    target.write_text("old\n", encoding="utf-8")
    drift.write_text("new\n", encoding="utf-8")
    calls = []
    monkeypatch.setattr(config_drift.os, "geteuid", lambda: 1000)

    def runner(cmd, **_kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0)

    status = run_config_drift(
        ["--yes", "--no-ai", "--root", str(root)],
        stdout=io.StringIO(),
        stderr=io.StringIO(),
        runner=runner,
    )

    assert status == 0
    assert calls
    assert calls[0][:3] == ["sudo", config_drift.sys.executable, "-m"]
    assert target.read_text(encoding="utf-8") == "old\n"


def test_config_drift_options_read_env_defaults():
    args = config_drift.build_config_drift_parser().parse_args(["--root", "/tmp/etc"])

    options = config_drift_options_from_args(args, {
        "AURASCAN_CONFIG_DRIFT_ENABLED": "1",
        "AURASCAN_CONFIG_DRIFT_AI_DIFFS": "never",
    })

    assert options.enabled is True
    assert options.no_ai is True
    assert options.root == config_drift.Path("/tmp/etc")
