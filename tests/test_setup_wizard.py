import io
import json
import subprocess
from pathlib import Path

from aurascan.setup_wizard import (
    build_doctor_checks,
    install_pacman_hook,
    is_release_safe_hook_template,
    run_doctor,
    run_init,
)


class FakeResponse:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return b'{"choices":[{"message":{"content":"BENIGN: connectivity check passed"}}]}'


def test_init_writes_hidden_key_without_printing_secret(tmp_path):
    env_path = tmp_path / ".config" / "aurascan" / ".env"
    stdout = io.StringIO()
    answers = iter([""])

    status = run_init(
        ["--provider", "openai", "--enable-ai", "--no-install-hook"],
        input_func=lambda _prompt: next(answers),
        getpass_func=lambda _prompt: "fixture-only-value",
        stdout=stdout,
        env_path=env_path,
    )

    output = stdout.getvalue()
    text = env_path.read_text(encoding="utf-8")
    assert status == 0
    assert "fixture-only-value" not in output
    assert "AURASCAN_AI_PROVIDER=openai" in text
    assert "AURASCAN_AI_ENABLED=1" in text
    assert "AURASCAN_OPENAI_API_KEY=fixture-only-value" in text
    assert oct(env_path.stat().st_mode & 0o777) == "0o600"


def test_init_can_write_disabled_local_only_config(tmp_path):
    env_path = tmp_path / ".config" / "aurascan" / ".env"
    stdout = io.StringIO()

    status = run_init(
        ["--disable-ai", "--no-install-hook"],
        stdout=stdout,
        env_path=env_path,
    )

    assert status == 0
    assert "AURASCAN_AI_ENABLED=0" in env_path.read_text(encoding="utf-8")
    assert "local-only" not in stdout.getvalue().lower()


def test_doctor_json_reports_missing_key_without_leaking_values(tmp_path):
    env_path = tmp_path / ".config" / "aurascan" / ".env"
    env_path.parent.mkdir(parents=True)
    env_path.write_text(
        "AURASCAN_AI_ENABLED=1\nAURASCAN_AI_PROVIDER=openai\nAURASCAN_OPENAI_API_KEY=\n",
        encoding="utf-8",
    )
    env_path.chmod(0o600)
    stdout = io.StringIO()

    status = run_doctor(
        ["--json"],
        stdout=stdout,
        env_path=env_path,
        env={},
        executable_path=tmp_path / "usr" / "bin" / "aurascan",
        local_hook_path=tmp_path / "etc" / "pacman.d" / "hooks" / "aurascan.hook",
        packaged_hook_path=tmp_path / "usr" / "share" / "libalpm" / "hooks" / "aurascan.hook",
    )
    data = json.loads(stdout.getvalue())

    assert status == 1
    assert data["ok"] is False
    assert "fixture-only-value" not in stdout.getvalue()
    assert any(check["name"] == "ai_key" and check["status"] == "error" for check in data["checks"])


def test_doctor_reports_missing_config_as_warning(tmp_path):
    checks = build_doctor_checks(
        env_path=tmp_path / "missing.env",
        env={},
        executable_path=tmp_path / "usr" / "bin" / "aurascan",
        local_hook_path=tmp_path / "local.hook",
        packaged_hook_path=tmp_path / "packaged.hook",
    )

    by_name = {check.name: check for check in checks}
    assert by_name["config_file"].status == "warn"
    assert by_name["ai_enabled"].status == "warn"


def test_doctor_reports_bad_permissions_and_unsupported_provider(tmp_path):
    env_path = tmp_path / ".env"
    env_path.write_text(
        "AURASCAN_AI_ENABLED=1\nAURASCAN_AI_PROVIDER=unknown-provider\n",
        encoding="utf-8",
    )
    env_path.chmod(0o644)

    checks = build_doctor_checks(
        env_path=env_path,
        env={},
        executable_path=tmp_path / "usr" / "bin" / "aurascan",
        local_hook_path=tmp_path / "local.hook",
        packaged_hook_path=tmp_path / "packaged.hook",
    )

    by_name = {check.name: check for check in checks}
    assert by_name["config_permissions"].status == "warn"
    assert by_name["ai_provider"].status == "error"


def test_doctor_check_ai_uses_mocked_provider(tmp_path):
    env_path = tmp_path / ".config" / "aurascan" / ".env"
    env_path.parent.mkdir(parents=True)
    env_path.write_text(
        "AURASCAN_AI_ENABLED=1\n"
        "AURASCAN_AI_PROVIDER=openai\n"
        "AURASCAN_OPENAI_API_KEY=fixture-only-value\n",
        encoding="utf-8",
    )
    env_path.chmod(0o600)
    stdout = io.StringIO()
    seen = {}

    def fake_urlopen(req, timeout):
        seen["url"] = req.full_url
        return FakeResponse()

    status = run_doctor(
        ["--json", "--check-ai"],
        stdout=stdout,
        env_path=env_path,
        env={},
        urlopen=fake_urlopen,
        executable_path=tmp_path / "usr" / "bin" / "aurascan",
        local_hook_path=tmp_path / "etc" / "pacman.d" / "hooks" / "aurascan.hook",
        packaged_hook_path=tmp_path / "usr" / "share" / "libalpm" / "hooks" / "aurascan.hook",
    )
    data = json.loads(stdout.getvalue())

    assert status == 0
    assert seen["url"] == "https://api.openai.com/v1/chat/completions"
    assert any(check["name"] == "ai_connectivity" and check["status"] == "ok" for check in data["checks"])
    assert "fixture-only-value" not in stdout.getvalue()


def test_hook_install_refuses_missing_installed_executable(tmp_path):
    template = tmp_path / "aurascan.hook"
    template.write_text("Exec = /usr/bin/aurascan\nNeedsTargets\n", encoding="utf-8")

    result = install_pacman_hook(
        template_path=template,
        executable_path=tmp_path / "missing-aurascan",
        hook_path=tmp_path / "hook",
        runner=lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0),
    )

    assert result.ok is False
    assert "does not exist" in result.message


def test_hook_install_uses_sudo_install_for_release_safe_template(tmp_path):
    template = tmp_path / "aurascan.hook"
    executable = tmp_path / "aurascan"
    hook = tmp_path / "etc" / "pacman.d" / "hooks" / "aurascan.hook"
    template.write_text("Exec = /usr/bin/aurascan\nNeedsTargets\n", encoding="utf-8")
    executable.write_text("#!/bin/sh\n", encoding="utf-8")
    calls = []

    def runner(cmd, check):
        calls.append((cmd, check))
        return subprocess.CompletedProcess(cmd, 0)

    result = install_pacman_hook(
        template_path=template,
        executable_path=executable,
        hook_path=hook,
        runner=runner,
    )

    assert result.ok is True
    assert calls == [(["sudo", "install", "-Dm644", str(template), str(hook)], False)]


def test_hook_template_safety_rejects_development_paths(tmp_path):
    template = tmp_path / "aurascan.hook"
    template.write_text("Exec = /home/arawn/project/.venv/bin/python -m aurascan --deep-static\n", encoding="utf-8")

    assert is_release_safe_hook_template(template) is False
