"""Tests for the ``aurascan settings`` desktop settings surface.

These tests never touch a developer's real home directory: every path is
explicit and lives under ``tmp_path``.
"""

import io
import json
import stat

import pytest

from aurascan.core import ai_provider, settings_cli

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


def test_store_ai_config_writes_only_supplied_values_at_0600(tmp_path):
    config_path = tmp_path / "config" / ".env"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        "AURASCAN_AI_PROVIDER=deepseek\nAURASCAN_AI_ENABLED=0\n", encoding="utf-8"
    )
    settings_cli.store_ai_key("venice", SECRET, config_path=config_path)

    result = settings_cli.store_ai_config(
        "venice",
        model="fixture-model",
        enabled=True,
        config_path=config_path,
    )

    text = config_path.read_text(encoding="utf-8")
    assert result["action"] == "set_ai_config"
    assert result["ai"]["provider"] == "venice"
    assert result["ai"]["ready"] is True
    assert "AURASCAN_AI_PROVIDER=venice" in text
    assert "AURASCAN_AI_MODEL=fixture-model" in text
    assert "AURASCAN_AI_ENABLED=1" in text
    assert stat.S_IMODE(config_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(config_path.parent.stat().st_mode) == 0o700


def test_store_ai_config_switching_to_a_preset_clears_the_base_url(tmp_path):
    config_path = tmp_path / "config" / ".env"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        "AURASCAN_AI_PROVIDER=custom\n"
        "AURASCAN_AI_MODEL=fixture-custom-model\n"
        "AURASCAN_AI_BASE_URL=https://api.example.invalid/v1\n",
        encoding="utf-8",
    )

    settings_cli.store_ai_config("xiaomi", config_path=config_path)

    text = config_path.read_text(encoding="utf-8")
    assert "AURASCAN_AI_BASE_URL" not in text
    assert "AURASCAN_AI_MODEL" not in text
    assert "AURASCAN_AI_PROVIDER=xiaomi" in text


def test_store_ai_config_preserves_the_stored_key(tmp_path):
    config_path = tmp_path / "config" / ".env"
    config_path.parent.mkdir(parents=True)
    settings_cli.store_ai_key("venice", SECRET, config_path=config_path)

    result = settings_cli.store_ai_config("venice", model="fixture-model", config_path=config_path)

    assert SECRET in config_path.read_text(encoding="utf-8")
    assert result["ai"]["key_present"] is True
    assert result["ai"]["provider"] == "venice"


def test_store_ai_config_never_enables_ai_implicitly(tmp_path):
    config_path = tmp_path / "config" / ".env"
    config_path.parent.mkdir(parents=True)

    result = settings_cli.store_ai_config("refuseless", config_path=config_path)

    assert "AURASCAN_AI_ENABLED=0" in config_path.read_text(encoding="utf-8")
    assert result["ai"]["enabled"] is False


def test_store_ai_config_keeps_an_explicit_enable_flag(tmp_path):
    config_path = tmp_path / "config" / ".env"
    config_path.parent.mkdir(parents=True)
    config_path.write_text("AURASCAN_AI_ENABLED=1\n", encoding="utf-8")

    settings_cli.store_ai_config("apinex", config_path=config_path)

    assert "AURASCAN_AI_ENABLED=1" in config_path.read_text(encoding="utf-8")


def test_store_ai_config_custom_requires_a_url_and_a_model(tmp_path):
    config_path = tmp_path / "config" / ".env"
    config_path.parent.mkdir(parents=True)

    with pytest.raises(settings_cli.SettingsError, match="model"):
        settings_cli.store_ai_config(
            "custom", base_url="https://api.example.invalid/v1", config_path=config_path
        )
    with pytest.raises(settings_cli.SettingsError, match="base URL"):
        settings_cli.store_ai_config(
            "custom", model="fixture-model", config_path=config_path
        )


def test_store_ai_config_switching_to_custom_requires_new_values(tmp_path):
    config_path = tmp_path / "config" / ".env"
    config_path.parent.mkdir(parents=True)
    config_path.write_text(
        "AURASCAN_AI_PROVIDER=deepseek\n"
        "AURASCAN_AI_MODEL=deepseek-chat\n"
        "AURASCAN_AI_BASE_URL=http://127.0.0.1:1234/v1\n",
        encoding="utf-8",
    )

    with pytest.raises(settings_cli.SettingsError, match="model"):
        settings_cli.store_ai_config(
            "custom",
            base_url="https://api.example.invalid/v1",
            config_path=config_path,
        )
    with pytest.raises(settings_cli.SettingsError, match="base URL"):
        settings_cli.store_ai_config(
            "custom",
            model="fixture-model",
            config_path=config_path,
        )


def test_store_ai_config_rejects_an_unknown_provider(tmp_path):
    with pytest.raises(settings_cli.SettingsError, match="unsupported AI provider"):
        settings_cli.store_ai_config("not-a-provider", config_path=tmp_path / ".env")


@pytest.mark.parametrize(
    "base_url",
    [
        "http://api.example.invalid/v1",
        "https://192.168.1.4/v1",
        "https://user:secret@api.example.invalid/v1",
        "https://api.example.invalid/v1?token=secret",
        "https://api.example.invalid/v1#fragment",
        "https://api.example.invalid/v1\x01",
    ],
)
def test_store_ai_config_rejects_bad_custom_urls_without_writing(tmp_path, base_url):
    config_path = tmp_path / "config" / ".env"
    config_path.parent.mkdir(parents=True)
    config_path.write_text("AURASCAN_AI_ENABLED=1\n", encoding="utf-8")

    with pytest.raises(settings_cli.SettingsError):
        settings_cli.store_ai_config(
            "custom",
            model="fixture-model",
            base_url=base_url,
            config_path=config_path,
        )

    # A rejected field never leaves a half-written file behind.
    assert config_path.read_text(encoding="utf-8") == "AURASCAN_AI_ENABLED=1\n"


@pytest.mark.parametrize("model", ["bad model", "a" * 121, "tab\tmodel"])
def test_store_ai_config_rejects_bad_model_ids(tmp_path, model):
    with pytest.raises(settings_cli.SettingsError, match="model"):
        settings_cli.store_ai_config("deepseek", model=model, config_path=tmp_path / ".env")


@pytest.mark.parametrize(
    "provider",
    [name for name, spec in sorted(ai_provider.PROVIDERS.items()) if spec.default_model],
)
def test_every_shipped_default_model_can_be_written(tmp_path, provider):
    # The Settings form prefills the provider default and submits it unchanged,
    # so the shipped OpenRouter `~openai/gpt-latest` must save like any other.
    spec = ai_provider.PROVIDERS[provider]
    config_path = tmp_path / ".env"

    payload = settings_cli.store_ai_config(
        provider, model=spec.default_model, config_path=config_path
    )

    assert payload["stored"] is True
    assert payload["provider"] == provider
    assert payload["ai"]["model"] == spec.default_model
    assert payload["ai"]["error"] == ""


def test_store_ai_config_refuses_a_base_url_for_a_cloud_preset(tmp_path):
    with pytest.raises(settings_cli.SettingsError, match="base URL"):
        settings_cli.store_ai_config(
            "openai",
            base_url="https://api.example.invalid/v1",
            config_path=tmp_path / ".env",
        )


def test_run_settings_set_ai_config_never_echoes_the_secret(tmp_path, monkeypatch):
    config_path = tmp_path / "config" / ".env"
    monkeypatch.setattr(settings_cli, "user_env_path", lambda: config_path)
    settings_cli.store_ai_key("venice", SECRET, config_path=config_path)
    stdout = io.StringIO()
    stderr = io.StringIO()

    code = settings_cli.run_settings(
        ["set-ai-config", "--provider", "venice", "--model", "fixture-model", "--enabled", "1", "--json"],
        stdin=io.StringIO(""),
        stdout=stdout,
        stderr=stderr,
    )

    assert code == 0
    payload = json.loads(stdout.getvalue())
    assert payload["action"] == "set_ai_config"
    assert payload["ai"]["ready"] is True
    assert SECRET not in stdout.getvalue()
    assert SECRET not in stderr.getvalue()


def test_run_settings_set_ai_config_reports_a_safe_error(tmp_path, monkeypatch):
    config_path = tmp_path / "config" / ".env"
    monkeypatch.setattr(settings_cli, "user_env_path", lambda: config_path)
    stdout = io.StringIO()

    code = settings_cli.run_settings(
        ["set-ai-config", "--provider", "nope", "--json"],
        stdin=io.StringIO(""),
        stdout=stdout,
        stderr=io.StringIO(),
    )

    assert code == 2
    assert "unsupported AI provider" in json.loads(stdout.getvalue())["error"]
    assert config_path.exists() is False


def test_projection_prefills_default_model_and_base_url(tmp_path):
    projection = _project(tmp_path)
    entries = {entry["id"]: entry for entry in projection["providers"]}

    assert entries["venice"]["default_model"] == "deepseek-v4-1-flash-uncensored"
    assert entries["venice"]["base_url"] == "https://api.venice.ai/api/v1"
    assert entries["custom"]["default_model"] == ""
    assert entries["custom"]["user_base_url"] is True
    assert "set_ai_config" in projection["mutation"]["supported"]
