import json
import os
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable, Dict, Mapping, Optional, Tuple


@dataclass(frozen=True)
class AIProviderSpec:
    provider_id: str
    label: str
    key_env: str
    default_model: str
    api_family: str


@dataclass
class AIProviderConfig:
    provider: str
    model: str
    enabled: bool
    api_key: str = ""
    key_env: str = ""
    explicit_enabled: Optional[bool] = None
    error: str = ""

    @property
    def api_key_present(self) -> bool:
        return bool(self.api_key)

    @property
    def supported(self) -> bool:
        return not self.error and self.provider in PROVIDERS


PROVIDERS: Dict[str, AIProviderSpec] = {
    "openai": AIProviderSpec("openai", "OpenAI", "AURASCAN_OPENAI_API_KEY", "gpt-4o", "chat_completions"),
    "anthropic": AIProviderSpec("anthropic", "Anthropic", "AURASCAN_ANTHROPIC_API_KEY", "claude-3-5-sonnet-latest", "anthropic_messages"),
    "deepseek": AIProviderSpec("deepseek", "DeepSeek", "AURASCAN_DEEPSEEK_API_KEY", "deepseek-chat", "chat_completions"),
    "gemini": AIProviderSpec("gemini", "Gemini", "AURASCAN_GEMINI_API_KEY", "gemini-1.5-flash", "gemini_generate_content"),
    "openrouter": AIProviderSpec("openrouter", "OpenRouter", "AURASCAN_OPENROUTER_API_KEY", "~openai/gpt-latest", "chat_completions"),
}

LEGACY_KEY_ENV = "AURASCAN_AI_KEY"
AI_ENABLED_ENV = "AURASCAN_AI_ENABLED"
AI_PROVIDER_ENV = "AURASCAN_AI_PROVIDER"
AI_MODEL_ENV = "AURASCAN_AI_MODEL"

TRUE_VALUES = {"1", "true", "yes", "y", "on"}
FALSE_VALUES = {"0", "false", "no", "n", "off"}


class AIProviderError(RuntimeError):
    pass


def parse_bool(value: Optional[str]) -> Optional[bool]:
    if value is None:
        return None
    normalized = value.strip().lower()
    if normalized in TRUE_VALUES:
        return True
    if normalized in FALSE_VALUES:
        return False
    return None


def provider_choices() -> Tuple[str, ...]:
    return tuple(PROVIDERS.keys())


def get_provider_spec(provider: str) -> Optional[AIProviderSpec]:
    return PROVIDERS.get((provider or "").strip().lower())


def resolve_ai_config(env: Optional[Mapping[str, str]] = None) -> AIProviderConfig:
    source = env if env is not None else os.environ
    provider = source.get(AI_PROVIDER_ENV, "gemini").strip().lower() or "gemini"
    spec = get_provider_spec(provider)
    error = "" if spec else "unsupported_provider"
    model = source.get(AI_MODEL_ENV, "").strip() or (spec.default_model if spec else "")

    api_key = ""
    key_env = ""
    if spec and source.get(spec.key_env):
        api_key = source.get(spec.key_env, "")
        key_env = spec.key_env
    elif source.get(LEGACY_KEY_ENV):
        api_key = source.get(LEGACY_KEY_ENV, "")
        key_env = LEGACY_KEY_ENV

    enabled_raw = source.get(AI_ENABLED_ENV)
    explicit_enabled = parse_bool(enabled_raw)
    if enabled_raw is not None and explicit_enabled is None:
        error = error or "invalid_enabled_value"
        enabled = False
    elif explicit_enabled is None:
        enabled = bool(api_key)
    else:
        enabled = explicit_enabled

    return AIProviderConfig(
        provider=provider,
        model=model,
        enabled=enabled,
        api_key=api_key,
        key_env=key_env or (spec.key_env if spec else ""),
        explicit_enabled=explicit_enabled,
        error=error,
    )


def build_request(config: AIProviderConfig, prompt: str) -> urllib.request.Request:
    spec = get_provider_spec(config.provider)
    if spec is None:
        raise AIProviderError(f"unsupported AI provider: {config.provider}")
    if not config.api_key:
        raise AIProviderError("missing AI API key")

    headers = {"Content-Type": "application/json"}
    payload = {}

    if config.provider == "openai":
        url = "https://api.openai.com/v1/chat/completions"
        headers["Authorization"] = f"Bearer {config.api_key}"
        payload = _chat_payload(config.model, prompt)
    elif config.provider == "deepseek":
        url = "https://api.deepseek.com/chat/completions"
        headers["Authorization"] = f"Bearer {config.api_key}"
        payload = _chat_payload(config.model, prompt)
    elif config.provider == "openrouter":
        url = "https://openrouter.ai/api/v1/chat/completions"
        headers["Authorization"] = f"Bearer {config.api_key}"
        headers["X-OpenRouter-Title"] = "AuraScan"
        payload = _chat_payload(config.model, prompt)
    elif config.provider == "anthropic":
        url = "https://api.anthropic.com/v1/messages"
        headers["x-api-key"] = config.api_key
        headers["anthropic-version"] = "2023-06-01"
        payload = {
            "model": config.model,
            "max_tokens": 256,
            "temperature": 0,
            "messages": [{"role": "user", "content": prompt}],
        }
    elif config.provider == "gemini":
        model = urllib.parse.quote(config.model, safe="")
        api_key = urllib.parse.quote(config.api_key, safe="")
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        payload = {"contents": [{"parts": [{"text": prompt}]}]}
    else:
        raise AIProviderError(f"unsupported AI provider: {config.provider}")

    data = json.dumps(payload).encode("utf-8")
    return urllib.request.Request(url, data=data, headers=headers)


def _chat_payload(model: str, prompt: str) -> Dict[str, object]:
    return {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.0,
    }


def call_ai_provider(
    config: AIProviderConfig,
    prompt: str,
    *,
    timeout: int = 30,
    urlopen: Optional[Callable] = None,
) -> str:
    opener = urlopen or urllib.request.urlopen
    req = build_request(config, prompt)
    with opener(req, timeout=timeout) as response:
        result = json.loads(response.read().decode("utf-8"))
    return extract_response_text(config.provider, result)


def extract_response_text(provider: str, result: Mapping[str, object]) -> str:
    if provider in {"openai", "deepseek", "openrouter"}:
        choices = result.get("choices", [])
        if not choices:
            return ""
        message = choices[0].get("message", {}) if isinstance(choices[0], dict) else {}
        return str(message.get("content") or "").strip()

    if provider == "anthropic":
        parts = result.get("content", [])
        if not isinstance(parts, list):
            return ""
        text_parts = []
        for part in parts:
            if isinstance(part, dict) and part.get("type") == "text":
                text_parts.append(str(part.get("text") or ""))
        return "\n".join(text_parts).strip()

    if provider == "gemini":
        candidates = result.get("candidates", [])
        if not candidates or not isinstance(candidates[0], dict):
            return ""
        content = candidates[0].get("content", {})
        if not isinstance(content, dict):
            return ""
        parts = content.get("parts", [])
        if not isinstance(parts, list):
            return ""
        text_parts = []
        for part in parts:
            if isinstance(part, dict):
                text_parts.append(str(part.get("text") or ""))
        return "\n".join(text_parts).strip()

    return ""


def connectivity_prompt() -> str:
    return (
        "AuraScan connectivity check. Reply with exactly: "
        "BENIGN: connectivity check passed"
    )
