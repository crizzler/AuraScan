import ipaddress
import json
import os
import socket
import urllib.error
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
    requires_api_key: bool = True
    local: bool = False
    default_base_url: str = ""


@dataclass
class AIProviderConfig:
    provider: str
    model: str
    enabled: bool
    api_key: str = ""
    key_env: str = ""
    base_url: str = ""
    explicit_enabled: Optional[bool] = None
    error: str = ""

    @property
    def api_key_present(self) -> bool:
        return bool(self.api_key)

    @property
    def supported(self) -> bool:
        return not self.error and self.provider in PROVIDERS

    @property
    def is_local(self) -> bool:
        spec = get_provider_spec(self.provider)
        return bool(spec and spec.local)

    @property
    def authentication_ready(self) -> bool:
        spec = get_provider_spec(self.provider)
        return bool(spec and (not spec.requires_api_key or self.api_key_present))

    @property
    def ready(self) -> bool:
        return self.supported and self.enabled and self.authentication_ready


PROVIDERS: Dict[str, AIProviderSpec] = {
    "openai": AIProviderSpec("openai", "OpenAI", "AURASCAN_OPENAI_API_KEY", "gpt-4o", "chat_completions"),
    "anthropic": AIProviderSpec("anthropic", "Anthropic", "AURASCAN_ANTHROPIC_API_KEY", "claude-3-5-sonnet-latest", "anthropic_messages"),
    "deepseek": AIProviderSpec("deepseek", "DeepSeek", "AURASCAN_DEEPSEEK_API_KEY", "deepseek-chat", "chat_completions"),
    "gemini": AIProviderSpec("gemini", "Gemini", "AURASCAN_GEMINI_API_KEY", "gemini-1.5-flash", "gemini_generate_content"),
    "openrouter": AIProviderSpec("openrouter", "OpenRouter", "AURASCAN_OPENROUTER_API_KEY", "~openai/gpt-latest", "chat_completions"),
    "lmstudio": AIProviderSpec(
        "lmstudio",
        "LM Studio",
        "AURASCAN_LOCAL_AI_API_KEY",
        "local-model",
        "chat_completions",
        requires_api_key=False,
        local=True,
        default_base_url="http://127.0.0.1:1234/v1",
    ),
    "llamacpp": AIProviderSpec(
        "llamacpp",
        "llama.cpp",
        "AURASCAN_LOCAL_AI_API_KEY",
        "aurascan-local",
        "chat_completions",
        requires_api_key=False,
        local=True,
        default_base_url="http://127.0.0.1:8080/v1",
    ),
}

LEGACY_KEY_ENV = "AURASCAN_AI_KEY"
AI_ENABLED_ENV = "AURASCAN_AI_ENABLED"
AI_PROVIDER_ENV = "AURASCAN_AI_PROVIDER"
AI_MODEL_ENV = "AURASCAN_AI_MODEL"
AI_BASE_URL_ENV = "AURASCAN_AI_BASE_URL"
LOCAL_AI_KEY_ENV = "AURASCAN_LOCAL_AI_API_KEY"
MAX_AI_RESPONSE_BYTES = 1024 * 1024

TRUE_VALUES = {"1", "true", "yes", "y", "on"}
FALSE_VALUES = {"0", "false", "no", "n", "off"}


class AIProviderError(RuntimeError):
    def __init__(self, message: str, *, category: str = "provider_error"):
        super().__init__(message)
        self.category = category


class AIProviderTimeoutError(TimeoutError):
    def __init__(self):
        super().__init__("AI provider request timed out")
        self.category = "timeout"


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise AIProviderError("AI provider redirects are disabled", category="redirect")


def safe_provider_error_detail(error: BaseException) -> str:
    """Return a bounded error label that never includes request data or URLs."""
    category = getattr(error, "category", "")
    if not category:
        if isinstance(error, urllib.error.HTTPError):
            category = "http"
        elif isinstance(error, urllib.error.URLError):
            reason = getattr(error, "reason", None)
            category = "timeout" if isinstance(reason, (socket.timeout, TimeoutError)) else "network"
        elif isinstance(error, (socket.timeout, TimeoutError)):
            category = "timeout"
        elif isinstance(error, (json.JSONDecodeError, UnicodeError)):
            category = "invalid_response"
        else:
            category = "provider_error"
    return {
        "redirect": "AI provider redirect was refused",
        "timeout": "AI provider request timed out",
        "network": "AI provider network request failed",
        "http": "AI provider HTTP request failed",
        "invalid_response": "AI provider returned an invalid response",
        "response_too_large": "AI provider response exceeded the size limit",
        "configuration": "AI provider configuration is invalid",
        "disabled": "AI provider is disabled",
        "authentication": "AI provider authentication is not configured",
    }.get(category, "AI provider request failed")


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


def normalize_local_base_url(value: str) -> str:
    raw = (value or "").strip()
    try:
        parsed = urllib.parse.urlsplit(raw)
        port = parsed.port
    except ValueError as exc:
        raise AIProviderError("invalid local AI base URL") from exc

    if parsed.scheme.lower() not in {"http", "https"}:
        raise AIProviderError("local AI base URL must use http or https")
    if not parsed.netloc or parsed.hostname is None:
        raise AIProviderError("local AI base URL must include a loopback host")
    if parsed.username is not None or parsed.password is not None:
        raise AIProviderError("local AI base URL must not contain credentials")
    if parsed.query or parsed.fragment:
        raise AIProviderError("local AI base URL must not contain a query or fragment")
    if port is not None and not 1 <= port <= 65535:
        raise AIProviderError("local AI base URL has an invalid port")

    host = parsed.hostname.lower()
    # Never leave `localhost` to mutable DNS/hosts-file resolution.  Plain HTTP
    # local model servers can be pinned directly to the IPv4 loopback address;
    # HTTPS callers must supply an explicit loopback literal so certificate
    # identity and routing are not silently rewritten.
    if host == "localhost":
        if parsed.scheme.lower() != "http":
            raise AIProviderError("HTTPS local AI URLs must use a loopback IP literal")
        host = "127.0.0.1"
    try:
        is_loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        is_loopback = False
    if not is_loopback:
        raise AIProviderError("local AI base URL must use a loopback host")

    path = parsed.path or ""
    if path not in {"", "/", "/v1", "/v1/"}:
        raise AIProviderError("local AI base URL path must be /v1")

    normalized_host = f"[{host}]" if ":" in host else host
    netloc = normalized_host if port is None else f"{normalized_host}:{port}"
    return urllib.parse.urlunsplit((parsed.scheme.lower(), netloc, "/v1", "", ""))


def resolve_ai_config(env: Optional[Mapping[str, str]] = None) -> AIProviderConfig:
    source = env if env is not None else os.environ
    provider = source.get(AI_PROVIDER_ENV, "gemini").strip().lower() or "gemini"
    spec = get_provider_spec(provider)
    error = "" if spec else "unsupported_provider"
    model = source.get(AI_MODEL_ENV, "").strip() or (spec.default_model if spec else "")

    base_url = ""
    if spec and spec.local:
        candidate = source.get(AI_BASE_URL_ENV, "").strip() or spec.default_base_url
        try:
            base_url = normalize_local_base_url(candidate)
        except AIProviderError:
            error = error or "invalid_base_url"

    api_key = ""
    key_env = ""
    if spec and source.get(spec.key_env):
        api_key = source.get(spec.key_env, "")
        key_env = spec.key_env
    elif spec and not spec.local and source.get(LEGACY_KEY_ENV):
        api_key = source.get(LEGACY_KEY_ENV, "")
        key_env = LEGACY_KEY_ENV

    enabled_raw = source.get(AI_ENABLED_ENV)
    explicit_enabled = parse_bool(enabled_raw)
    if enabled_raw is not None and explicit_enabled is None:
        error = error or "invalid_enabled_value"
        enabled = False
    elif explicit_enabled is None:
        enabled = bool(api_key) if spec and spec.requires_api_key else False
    else:
        enabled = explicit_enabled

    return AIProviderConfig(
        provider=provider,
        model=model,
        enabled=enabled,
        api_key=api_key,
        key_env=key_env or (spec.key_env if spec else ""),
        base_url=base_url,
        explicit_enabled=explicit_enabled,
        error=error,
    )


def build_request(config: AIProviderConfig, prompt: str) -> urllib.request.Request:
    if config.error:
        raise AIProviderError(
            f"invalid AI provider configuration: {config.error}",
            category="configuration",
        )
    if not config.enabled:
        raise AIProviderError("AI provider is disabled", category="disabled")
    spec = get_provider_spec(config.provider)
    if spec is None:
        raise AIProviderError(f"unsupported AI provider: {config.provider}")
    if spec.requires_api_key and not config.api_key:
        raise AIProviderError("missing AI API key", category="authentication")

    headers = {"Content-Type": "application/json"}
    payload = {}

    if spec.local:
        base_url = normalize_local_base_url(config.base_url or spec.default_base_url)
        url = f"{base_url}/chat/completions"
        if config.api_key:
            headers["Authorization"] = f"Bearer {config.api_key}"
        payload = _chat_payload(config.model, prompt, max_tokens=1024)
    elif config.provider == "openai":
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
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        headers["x-goog-api-key"] = config.api_key
        payload = {"contents": [{"parts": [{"text": prompt}]}]}
    else:
        raise AIProviderError(f"unsupported AI provider: {config.provider}")

    data = json.dumps(payload).encode("utf-8")
    return urllib.request.Request(url, data=data, headers=headers)


def _chat_payload(model: str, prompt: str, *, max_tokens: Optional[int] = None) -> Dict[str, object]:
    payload: Dict[str, object] = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.0,
        "stream": False,
    }
    if max_tokens is not None:
        payload["max_tokens"] = max_tokens
    return payload


def _read_json_response(response) -> Mapping[str, object]:
    try:
        raw = response.read(MAX_AI_RESPONSE_BYTES + 1)
    except TypeError:
        # Compatibility for small test doubles and response-like integrations.
        raw = response.read()
    if len(raw) > MAX_AI_RESPONSE_BYTES:
        raise AIProviderError(
            "AI provider response exceeded the size limit",
            category="response_too_large",
        )
    try:
        result = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise AIProviderError(
            "AI provider returned invalid JSON",
            category="invalid_response",
        ) from exc
    if not isinstance(result, Mapping):
        raise AIProviderError(
            "AI provider response was not a JSON object",
            category="invalid_response",
        )
    return result


def _local_urlopen(request: urllib.request.Request, *, timeout: int):
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        _NoRedirectHandler(),
    )
    return opener.open(request, timeout=timeout)


def _cloud_urlopen(request: urllib.request.Request, *, timeout: int):
    # Omitting a ProxyHandler preserves urllib's normal environment-proxy
    # behavior. The explicit redirect handler still refuses every redirect.
    opener = urllib.request.build_opener(_NoRedirectHandler())
    return opener.open(request, timeout=timeout)


def call_ai_provider(
    config: AIProviderConfig,
    prompt: str,
    *,
    timeout: int = 30,
    urlopen: Optional[Callable] = None,
) -> str:
    opener = urlopen
    if opener is None:
        opener = _local_urlopen if config.is_local else _cloud_urlopen
    try:
        req = build_request(config, prompt)
        with opener(req, timeout=timeout) as response:
            result = _read_json_response(response)
    except AIProviderError:
        raise
    except urllib.error.HTTPError as exc:
        raise AIProviderError(
            safe_provider_error_detail(exc),
            category="http",
        ) from None
    except urllib.error.URLError as exc:
        reason = getattr(exc, "reason", None)
        category = "timeout" if isinstance(reason, (socket.timeout, TimeoutError)) else "network"
        if category == "timeout":
            raise AIProviderTimeoutError() from None
        raise AIProviderError(
            safe_provider_error_detail(exc),
            category=category,
        ) from None
    except (socket.timeout, TimeoutError):
        raise AIProviderTimeoutError() from None
    except OSError:
        raise AIProviderError(
            "AI provider network request failed",
            category="network",
        ) from None
    except AssertionError:
        # Preserve assertion failures from injected test transports.
        raise
    except Exception:
        raise AIProviderError(
            "AI provider request failed",
            category="provider_error",
        ) from None
    return extract_response_text(config.provider, result)


def extract_response_text(provider: str, result: Mapping[str, object]) -> str:
    spec = get_provider_spec(provider)
    if spec and spec.api_family == "chat_completions":
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
