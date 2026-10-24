"""Tests for the ``aurascan settings`` desktop settings surface.

These tests never touch a developer's real home directory: every path is
explicit and lives under ``tmp_path``.
"""

import io
import json
import stat

import pytest

from aurascan.core import settings_cli

SECRET = "sk-test-abcdef1234567890"


def _project(tmp_path, env=None, *, state=None):
    config_path = tmp_path / "config" / ".env"
    return settings_cli.project_settings(
        env or {},
        config_path=config_path,
        config_state=state,
    )


def _json(value):
    return json.dumps(value, sort_keys=True)


def test_projection_reports_absent_configuration(tmp_path):
    projection = _project(tmp_path)

    assert projection["schema"] == "aurascan-settings/1"
    assert projection["config"]["present"] is False
    assert projection["config"]["readable"] is False
    assert projection["ai"]["enabled"] is False
    assert projection["ai"]["key_present"] is False
    assert projection["ai"]["ready"] is False
    assert projection["mutation"]["secret_input"] == "stdin"


def test_projection_lists_every_provider_once(tmp_path):
    projection = _project(tmp_path)
    provider_ids = [entry["id"] for entry in projection["providers"]]

    assert provider_ids == sorted(provider_ids)
    assert len(provider_ids) == len(set(provider_ids))
    assert "deepseek" in provider_ids
    local = {entry["id"]: entry for entry in projection["providers"]}
    assert local["lmstudio"]["local"] is True
    assert local["lmstudio"]["requires_key"] is False
    assert local["deepseek"]["requires_key"] is True


def test_projection_never_serializes_a_credential(tmp_path):
    projection = _project(
        tmp_path,
        {
            "AURASCAN_AI_PROVIDER": "deepseek",
            "AURASCAN_AI_MODEL": "deepseek-chat",
            "AURASCAN_AI_ENABLED": "1",
            "AURASCAN_DEEPSEEK_API_KEY": SECRET,
        },
    )

    serialized = _json(projection)
    assert SECRET not in serialized
    assert projection["ai"]["key_present"] is True
    assert projection["ai"]["key_env"] == "AURASCAN_DEEPSEEK_API_KEY"
    assert projection["ai"]["ready"] is True
    assert projection["ai"]["provider_label"] == "DeepSeek"


def test_projection_without_a_key_is_not_ready(tmp_path):
    projection = _project(
        tmp_path,
        {"AURASCAN_AI_PROVIDER": "deepseek", "AURASCAN_AI_ENABLED": "1"},
    )

    assert projection["ai"]["enabled"] is True
    assert projection["ai"]["key_present"] is False
    assert projection["ai"]["authentication_ready"] is False
    assert projection["ai"]["ready"] is False


def test_projection_sanitizes_a_base_url_with_credentials(tmp_path):
    projection = _project(
        tmp_path,
        {
            "AURASCAN_AI_PROVIDER": "lmstudio",
            "AURASCAN_AI_BASE_URL": "http://user:token@127.0.0.1:1234/v1?key=token#frag",
        },
    )

    assert projection["ai"]["base_url"] is None
    assert "token" not in _json(projection)


def test_projection_reports_loopback_base_url_without_query(tmp_path):
    projection = _project(
        tmp_path,
        {
            "AURASCAN_AI_PROVIDER": "lmstudio",
            "AURASCAN_AI_BASE_URL": "http://127.0.0.1:1234/v1",
        },
    )

    assert projection["ai"]["base_url"] == "http://127.0.0.1:1234/v1"


def test_projection_reports_feature_states(tmp_path):
    projection = _project(
        tmp_path,
        {
            "AURASCAN_INCIDENT_MONITOR_ENABLED": "1",
            "AURASCAN_INSTRUCTION_MONITOR_ENABLED": "0",
            "AURASCAN_INSTRUCTION_AI_ENABLED": "maybe",
        },
    )

    features = {entry["id"]: entry for entry in projection["features"]}
    assert features["incident_monitor"]["enabled"] is True
    assert features["instruction_monitor"]["enabled"] is False
    assert features["instruction_monitor"]["declared"] is True
    assert features["instruction_ai"]["enabled"] is None
    assert features["instruction_ai"]["declared"] is True
    assert features["recovery_ai"]["enabled"] is None
    assert features["recovery_ai"]["declared"] is False


def test_store_ai_key_writes_a_private_file(tmp_path):
    config_path = tmp_path / "config" / ".env"

    result = settings_cli.store_ai_key("deepseek", SECRET, config_path=config_path)

    assert result["stored"] is True
    assert result["provider"] == "deepseek"
    assert SECRET not in json.dumps(result)
    assert SECRET in config_path.read_text(encoding="utf-8")
    assert stat.S_IMODE(config_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(config_path.parent.stat().st_mode) == 0o700
    assert result["ai"]["key_present"] is True
    assert result["ai"]["provider"] == "deepseek"


def test_store_ai_key_does_not_silently_enable_ai(tmp_path):
    config_path = tmp_path / "config" / ".env"

    result = settings_cli.store_ai_key("deepseek", SECRET, config_path=config_path)

    assert "AURASCAN_AI_ENABLED=0" in config_path.read_text(encoding="utf-8")
    assert result["ai"]["enabled"] is False
    assert result["ai"]["ready"] is False


def test_store_ai_key_preserves_an_explicit_enable_flag(tmp_path):
    config_path = tmp_path / "config" / ".env"
    config_path.parent.mkdir(parents=True)
    config_path.write_text("AURASCAN_AI_ENABLED=1\n", encoding="utf-8")

    result = settings_cli.store_ai_key("deepseek", SECRET, config_path=config_path)

    assert result["ai"]["enabled"] is True
    assert result["ai"]["ready"] is True


def test_store_ai_key_rejects_an_unsupported_provider(tmp_path):
    with pytest.raises(settings_cli.SettingsError):
        settings_cli.store_ai_key("not-a-provider", SECRET, config_path=tmp_path / ".env")


@pytest.mark.parametrize("secret", ["", "   ", "line\nbreak", "tab\there", "x" * 5000])
def test_store_ai_key_rejects_malformed_input(tmp_path, secret):
    with pytest.raises(settings_cli.SettingsError):
        settings_cli.store_ai_key("deepseek", secret, config_path=tmp_path / ".env")


def test_run_settings_reads_only_the_explicit_config(tmp_path, monkeypatch):
    config_path = tmp_path / "config" / ".env"
    monkeypatch.setattr(settings_cli, "user_env_path", lambda: config_path)
    stdout = io.StringIO()

    code = settings_cli.run_settings(["show", "--json"], stdin=io.StringIO(""), stdout=stdout, stderr=io.StringIO())

    assert code == 0
    payload = json.loads(stdout.getvalue())
    assert payload["schema"] == "aurascan-settings/1"
    assert payload["config"]["present"] is False


def test_run_settings_stores_a_key_from_stdin_without_echo(tmp_path, monkeypatch):
    config_path = tmp_path / "config" / ".env"
    monkeypatch.setattr(settings_cli, "user_env_path", lambda: config_path)
    stdout = io.StringIO()
    stderr = io.StringIO()

    code = settings_cli.run_settings(
        ["set-ai-key", "--provider", "deepseek", "--json"],
        stdin=io.StringIO(SECRET + "\n"),
        stdout=stdout,
        stderr=stderr,
    )

    assert code == 0
    assert SECRET not in stdout.getvalue()
    assert SECRET not in stderr.getvalue()
    assert json.loads(stdout.getvalue())["stored"] is True
    assert SECRET in config_path.read_text(encoding="utf-8")


def test_run_settings_reports_missing_stdin_without_creating_a_file(tmp_path, monkeypatch):
    config_path = tmp_path / "config" / ".env"
    monkeypatch.setattr(settings_cli, "user_env_path", lambda: config_path)
    stdout = io.StringIO()

    code = settings_cli.run_settings(
        ["set-ai-key", "--provider", "deepseek", "--json"],
        stdin=io.StringIO(""),
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert code == 2
    assert json.loads(stdout.getvalue())["error"]
    assert config_path.exists() is False


def test_run_settings_rejects_a_bad_provider_without_leaking_the_secret(tmp_path, monkeypatch):
    config_path = tmp_path / "config" / ".env"
    monkeypatch.setattr(settings_cli, "user_env_path", lambda: config_path)
    stdout = io.StringIO()

    code = settings_cli.run_settings(
        ["set-ai-key", "--provider", "nope", "--json"],
        stdin=io.StringIO(SECRET + "\n"),
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert code == 2
    assert SECRET not in stdout.getvalue()
    assert config_path.exists() is False
