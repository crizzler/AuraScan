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
        "AURASCAN_AI_BASE_URL",
        "AURASCAN_LOCAL_AI_API_KEY",
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
    if spec.requires_api_key:
        monkeypatch.setenv(spec.key_env, "fixture-only-value")


def set_provider_urlopen(monkeypatch, provider, fake_urlopen):
    if ai_provider.PROVIDERS[provider].local:
        monkeypatch.setattr(ai_provider, "_local_urlopen", fake_urlopen)
    else:
        monkeypatch.setattr(ai_provider.urllib.request, "urlopen", fake_urlopen)


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


@pytest.mark.parametrize(
    ("provider", "base_url", "model"),
    [
        ("lmstudio", "http://127.0.0.1:1234/v1", "local-model"),
        ("llamacpp", "http://127.0.0.1:8080/v1", "aurascan-local"),
    ],
)
def test_local_provider_presets_are_keyless_and_explicitly_enabled(provider, base_url, model):
    disabled = ai_provider.resolve_ai_config({"AURASCAN_AI_PROVIDER": provider})
    enabled = ai_provider.resolve_ai_config({
        "AURASCAN_AI_PROVIDER": provider,
        "AURASCAN_AI_ENABLED": "1",
    })

    assert disabled.enabled is False
    assert disabled.ready is False
    assert enabled.ready is True
    assert enabled.authentication_ready is True
    assert enabled.api_key_present is False
    assert enabled.base_url == base_url
    assert enabled.model == model


@pytest.mark.parametrize(
    ("raw", "normalized"),
    [
        ("http://localhost:1234", "http://localhost:1234/v1"),
        ("http://127.0.0.2:8080/", "http://127.0.0.2:8080/v1"),
        ("https://[::1]:9443/v1/", "https://[::1]:9443/v1"),
    ],
)
def test_local_base_url_normalization(raw, normalized):
    assert ai_provider.normalize_local_base_url(raw) == normalized


@pytest.mark.parametrize(
    "base_url",
    [
        "",
        "ftp://127.0.0.1:8080/v1",
        "http://0.0.0.0:8080/v1",
        "http://192.168.1.4:8080/v1",
        "http://localhost.evil:8080/v1",
        "http://user:secret@127.0.0.1:8080/v1",
        "http://127.0.0.1:8080/v1?token=secret",
        "http://127.0.0.1:8080/v1#fragment",
        "http://127.0.0.1:8080/v1/chat/completions",
        "http://127.0.0.1:0/v1",
        "http://127.0.0.1:99999/v1",
    ],
)
def test_local_base_url_rejects_non_loopback_or_unsafe_values(base_url):
    with pytest.raises(ai_provider.AIProviderError):
        ai_provider.normalize_local_base_url(base_url)


def test_invalid_local_base_url_makes_configuration_not_ready():
    config = ai_provider.resolve_ai_config({
        "AURASCAN_AI_PROVIDER": "lmstudio",
        "AURASCAN_AI_ENABLED": "1",
        "AURASCAN_AI_BASE_URL": "http://localhost.evil:1234/v1",
    })

    assert config.error == "invalid_base_url"
    assert config.ready is False
    with pytest.raises(ai_provider.AIProviderError, match="invalid_base_url"):
        ai_provider.build_request(config, "must not silently use the preset")


def test_disabled_local_provider_cannot_contact_endpoint():
    config = ai_provider.resolve_ai_config({"AURASCAN_AI_PROVIDER": "lmstudio"})

    with pytest.raises(ai_provider.AIProviderError, match="disabled"):
        ai_provider.call_ai_provider(
            config,
            "fixture prompt",
            urlopen=lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("disabled AI contacted provider")),
        )


@pytest.mark.parametrize("provider", ["lmstudio", "llamacpp"])
def test_local_request_uses_openai_compatible_endpoint_without_dummy_key(provider):
    config = ai_provider.resolve_ai_config({
        "AURASCAN_AI_PROVIDER": provider,
        "AURASCAN_AI_ENABLED": "1",
        "AURASCAN_AI_MODEL": "fixture-model",
    })

    request = ai_provider.build_request(config, "fixture prompt")
    body = json.loads(request.data.decode("utf-8"))
    headers = dict(request.header_items())

    assert request.full_url == f"{config.base_url}/chat/completions"
    assert "Authorization" not in headers
    assert body == {
        "model": "fixture-model",
        "messages": [{"role": "user", "content": "fixture prompt"}],
        "temperature": 0.0,
        "stream": False,
        "max_tokens": 1024,
    }


def test_local_request_supports_optional_bearer_token():
    config = ai_provider.resolve_ai_config({
        "AURASCAN_AI_PROVIDER": "lmstudio",
        "AURASCAN_AI_ENABLED": "1",
        "AURASCAN_LOCAL_AI_API_KEY": "fixture-only-local-token",
    })

    request = ai_provider.build_request(config, "fixture prompt")

    assert dict(request.header_items())["Authorization"] == "Bearer fixture-only-local-token"


def test_cloud_provider_ignores_local_base_url_override():
    config = ai_provider.resolve_ai_config({
        "AURASCAN_AI_PROVIDER": "openai",
        "AURASCAN_AI_ENABLED": "1",
        "AURASCAN_OPENAI_API_KEY": "fixture-only-value",
        "AURASCAN_AI_BASE_URL": "http://127.0.0.1:9999/v1",
    })

    request = ai_provider.build_request(config, "fixture prompt")

    assert config.base_url == ""
    assert request.full_url == "https://api.openai.com/v1/chat/completions"


def test_local_call_rejects_oversized_response():
    class OversizedResponse(FakeResponse):
        def read(self, size=-1):
            return b"x" * (ai_provider.MAX_AI_RESPONSE_BYTES + 1)

    config = ai_provider.resolve_ai_config({
        "AURASCAN_AI_PROVIDER": "llamacpp",
        "AURASCAN_AI_ENABLED": "1",
    })

    with pytest.raises(ai_provider.AIProviderError, match="size limit"):
        ai_provider.call_ai_provider(
            config,
            "fixture prompt",
            urlopen=lambda *_args, **_kwargs: OversizedResponse({}),
        )


def test_local_default_opener_disables_proxies_and_redirects(monkeypatch):
    captured = {}

    class FakeOpener:
        def open(self, request, timeout):
            captured["request"] = request
            captured["timeout"] = timeout
            return FakeResponse(provider_payload("llamacpp", "BENIGN: local"))

    def fake_build_opener(*handlers):
        captured["handlers"] = handlers
        return FakeOpener()

    monkeypatch.setattr(ai_provider.urllib.request, "build_opener", fake_build_opener)
    config = ai_provider.resolve_ai_config({
        "AURASCAN_AI_PROVIDER": "llamacpp",
        "AURASCAN_AI_ENABLED": "1",
    })

    assert ai_provider.call_ai_provider(config, "fixture prompt") == "BENIGN: local"
    proxy_handler, redirect_handler = captured["handlers"]
    assert proxy_handler.proxies == {}
    assert isinstance(redirect_handler, ai_provider._NoRedirectHandler)


@pytest.mark.parametrize("provider", ai_provider.provider_choices())
@pytest.mark.parametrize(
    ("reply", "safe", "message"),
    [
        ("BENIGN: clean", True, "Clean"),
        ("MALICIOUS: suspicious", False, "Malicious logic found"),
        ("I will not use the required prefix", False, "AI response requires manual review"),
    ],
)
def test_ai_provider_response_contract(monkeypatch, provider, reply, safe, message):
    set_provider_env(monkeypatch, provider)

    def fake_urlopen(req, timeout):
        body = json.loads(req.data.decode("utf-8"))
        assert body
        return FakeResponse(provider_payload(provider, reply))

    set_provider_urlopen(monkeypatch, provider, fake_urlopen)

    result = AIStaticAnalyzer()._call_api("PKGBUILD", "pkgname=demo", pkg_path="PKGBUILD")

    assert result.is_safe is safe
    assert result.msg == message
    if reply == "I will not use the required prefix":
        assert result.findings[0].confidence.name == "LOW"
        assert result.findings[0].requires_manual_review is True
        assert "does not confirm prompt injection" in result.findings[0].explanation


@pytest.mark.parametrize("provider", ai_provider.provider_choices())
def test_ai_provider_timeout_blocks_for_manual_review(monkeypatch, provider):
    set_provider_env(monkeypatch, provider)

    def fake_urlopen(_req, timeout):
        raise urllib.error.URLError(socket.timeout("timed out"))

    set_provider_urlopen(monkeypatch, provider, fake_urlopen)

    result = AIStaticAnalyzer()._call_api("PKGBUILD", "pkgname=demo", pkg_path="PKGBUILD")

    assert result.is_safe is False
    assert result.findings[0].rule_id == "AI-TIMEOUT"


@pytest.mark.parametrize("provider", ai_provider.provider_choices())
def test_ai_provider_network_error_does_not_block(monkeypatch, provider):
    set_provider_env(monkeypatch, provider)

    def fake_urlopen(_req, timeout):
        raise urllib.error.URLError("offline")

    set_provider_urlopen(monkeypatch, provider, fake_urlopen)

    result = AIStaticAnalyzer()._call_api("PKGBUILD", "pkgname=demo", pkg_path="PKGBUILD")

    assert result.is_safe is True
    assert "AI Network Error" in result.msg
