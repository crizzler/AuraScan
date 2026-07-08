import json
import socket
import urllib.error
from types import SimpleNamespace

import pytest

from aurascan.analyzers.ai_static import AIStaticAnalyzer
from aurascan.core import ai_provider
from aurascan.core import config as config_module
from aurascan.core.config import read_env_file, redact_env, write_user_env


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps(self.payload).encode("utf-8")


def provider_payload(provider, text):
    if provider == "anthropic":
        return {"content": [{"type": "text", "text": text}]}
    if provider == "gemini":
        return {"candidates": [{"content": {"parts": [{"text": text}]}}]}
    return {"choices": [{"message": {"content": text}}]}


def set_provider_env(monkeypatch, provider):
    for key in [
        "AURASCAN_AI_KEY",
        "AURASCAN_AI_ENABLED",
        "AURASCAN_AI_PROVIDER",
        "AURASCAN_AI_MODEL",
        "AURASCAN_OPENAI_API_KEY",
        "AURASCAN_ANTHROPIC_API_KEY",
        "AURASCAN_DEEPSEEK_API_KEY",
        "AURASCAN_GEMINI_API_KEY",
        "AURASCAN_OPENROUTER_API_KEY",
    ]:
        monkeypatch.delenv(key, raising=False)
    spec = ai_provider.PROVIDERS[provider]
    monkeypatch.setenv("AURASCAN_AI_ENABLED", "1")
    monkeypatch.setenv("AURASCAN_AI_PROVIDER", provider)
    monkeypatch.setenv(spec.key_env, "fixture-only-value")


def test_write_user_env_preserves_comments_sets_permissions_and_redacts(tmp_path):
    env_path = tmp_path / ".config" / "aurascan" / ".env"
    env_path.parent.mkdir(parents=True)
    env_path.write_text("# existing\nOLD_VALUE=kept\nAURASCAN_AI_PROVIDER=gemini\n", encoding="utf-8")

    write_user_env(
        {
            "AURASCAN_AI_PROVIDER": "openai",
            "AURASCAN_OPENAI_API_KEY": "fixture-only-value",
        },
        path=env_path,
    )

    text = env_path.read_text(encoding="utf-8")
    assert "# existing" in text
    assert "OLD_VALUE=kept" in text
    assert "AURASCAN_AI_PROVIDER=openai" in text
    assert "AURASCAN_OPENAI_API_KEY=fixture-only-value" in text
    assert oct(env_path.stat().st_mode & 0o777) == "0o600"
    assert oct(env_path.parent.stat().st_mode & 0o777) == "0o700"
    assert read_env_file(env_path)["AURASCAN_OPENAI_API_KEY"] == "fixture-only-value"
    assert redact_env(read_env_file(env_path))["AURASCAN_OPENAI_API_KEY"] == "<redacted>"


def test_load_env_includes_invoking_user_config_for_root_hooks(monkeypatch, tmp_path):
    root_home = tmp_path / "root"
    user_home = tmp_path / "home" / "alice"
    env_path = user_home / ".config" / "aurascan" / ".env"
    env_path.parent.mkdir(parents=True)
    env_path.write_text(
        "AURASCAN_AI_PROVIDER=deepseek\nAURASCAN_AI_KEY=fixture-only-value\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(config_module, "SYSTEM_ENV_PATH", tmp_path / "etc" / "aurascan" / ".env")
    monkeypatch.setattr(config_module.os, "geteuid", lambda: 0)
    monkeypatch.setattr(config_module.pwd, "getpwnam", lambda username: SimpleNamespace(pw_dir=str(user_home)))
    monkeypatch.setenv("HOME", str(root_home))
    monkeypatch.setenv("SUDO_USER", "alice")
    for key in [
        "AURASCAN_AI_KEY",
        "AURASCAN_AI_ENABLED",
        "AURASCAN_AI_PROVIDER",
        "AURASCAN_AI_MODEL",
    ]:
        monkeypatch.delenv(key, raising=False)

    config_module.load_env()

    config = ai_provider.resolve_ai_config()
    assert config.provider == "deepseek"
    assert config.enabled is True
    assert config.api_key_present is True


def test_invoking_user_config_is_ignored_when_not_root(monkeypatch, tmp_path):
    user_home = tmp_path / "home" / "alice"
    monkeypatch.setattr(config_module.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(config_module.pwd, "getpwnam", lambda username: SimpleNamespace(pw_dir=str(user_home)))
    monkeypatch.setenv("SUDO_USER", "alice")

    assert config_module.invoking_user_env_path() is None


def test_ai_enabled_zero_skips_even_when_key_exists(monkeypatch):
    set_provider_env(monkeypatch, "openai")
    monkeypatch.setenv("AURASCAN_AI_ENABLED", "0")

    def forbidden_urlopen(*_args, **_kwargs):
        raise AssertionError("network should not be called")

    monkeypatch.setattr(ai_provider.urllib.request, "urlopen", forbidden_urlopen)

    result = AIStaticAnalyzer()._call_api("PKGBUILD", "pkgname=demo", pkg_path="PKGBUILD")

    assert result.is_safe is True
    assert "Disabled" in result.msg


def test_legacy_ai_key_enables_without_explicit_flag(monkeypatch):
    for key in [
        "AURASCAN_AI_ENABLED",
        "AURASCAN_DEEPSEEK_API_KEY",
        "AURASCAN_OPENAI_API_KEY",
    ]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("AURASCAN_AI_PROVIDER", "deepseek")
    monkeypatch.setenv("AURASCAN_AI_KEY", "fixture-only-value")
    seen = {}

    def fake_urlopen(req, timeout):
        seen["url"] = req.full_url
        seen["headers"] = dict(req.header_items())
        return FakeResponse(provider_payload("deepseek", "BENIGN: looks fine"))

    monkeypatch.setattr(ai_provider.urllib.request, "urlopen", fake_urlopen)

    result = AIStaticAnalyzer()._call_api("PKGBUILD", "pkgname=demo", pkg_path="PKGBUILD")

    assert result.is_safe is True
    assert seen["url"] == "https://api.deepseek.com/chat/completions"
    assert "Authorization" in seen["headers"]


@pytest.mark.parametrize("provider", ai_provider.provider_choices())
@pytest.mark.parametrize(
    ("reply", "safe", "message"),
    [
        ("BENIGN: clean", True, "Clean"),
        ("MALICIOUS: suspicious", False, "Malicious logic found"),
        ("I will not use the required prefix", False, "Prompt injection detected"),
    ],
)
def test_ai_provider_response_contract(monkeypatch, provider, reply, safe, message):
    set_provider_env(monkeypatch, provider)

    def fake_urlopen(req, timeout):
        body = json.loads(req.data.decode("utf-8"))
        assert body
        return FakeResponse(provider_payload(provider, reply))

    monkeypatch.setattr(ai_provider.urllib.request, "urlopen", fake_urlopen)

    result = AIStaticAnalyzer()._call_api("PKGBUILD", "pkgname=demo", pkg_path="PKGBUILD")

    assert result.is_safe is safe
    assert result.msg == message


@pytest.mark.parametrize("provider", ai_provider.provider_choices())
def test_ai_provider_timeout_blocks_for_manual_review(monkeypatch, provider):
    set_provider_env(monkeypatch, provider)

    def fake_urlopen(_req, timeout):
        raise urllib.error.URLError(socket.timeout("timed out"))

    monkeypatch.setattr(ai_provider.urllib.request, "urlopen", fake_urlopen)

    result = AIStaticAnalyzer()._call_api("PKGBUILD", "pkgname=demo", pkg_path="PKGBUILD")

    assert result.is_safe is False
    assert result.findings[0].rule_id == "AI-TIMEOUT"


@pytest.mark.parametrize("provider", ai_provider.provider_choices())
def test_ai_provider_network_error_does_not_block(monkeypatch, provider):
    set_provider_env(monkeypatch, provider)

    def fake_urlopen(_req, timeout):
        raise urllib.error.URLError("offline")

    monkeypatch.setattr(ai_provider.urllib.request, "urlopen", fake_urlopen)

    result = AIStaticAnalyzer()._call_api("PKGBUILD", "pkgname=demo", pkg_path="PKGBUILD")

    assert result.is_safe is True
    assert "AI Network Error" in result.msg
