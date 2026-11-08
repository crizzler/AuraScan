# AI provider support and desktop configuration

Status: implemented (option B) in the unreleased tree. See
"Implementation status" at the end for the exact shipped surface and the
remaining limits.

## What exists today (verified at HEAD `19fbcc5`)

Pre-implementation baseline. Everything in this section is the state before
option B; the "Implementation status" section at the end describes what the
unreleased tree now does.

- `aurascan/core/ai_provider.py:56-93` defines seven providers: OpenAI, Anthropic,
  DeepSeek, Gemini, OpenRouter, LM Studio, llama.cpp.
- Cloud endpoints are hardcoded in `build_request` (`ai_provider.py:269-310`). Only the
  local providers accept `AURASCAN_AI_BASE_URL`, and only through
  `normalize_local_base_url` (loopback, `/v1`).
- `aurascan settings` exposes one mutation, `set-ai-key` (`settings_cli.py:67, 244-287`).
  It writes `~/.config/aurascan/.env` at `0600` from stdin and never echoes the value.
- The Electron Settings view can store a credential for any provider in its list
  (`desktop/src/views/Settings.tsx:145-200`), but it cannot choose the active provider,
  edit the model or base URL, or enable AI. Feature switches are read-only.
- The Electron shell mirrors the Python provider list in `desktop/electron/argv.cjs:34-42`.
  Adding a provider today requires editing both lists.

So a user cannot point AuraScan at Venice.ai, Refuseless or ExperientialLabs from the app,
and a provider that is not in the list cannot receive a key at all.

## Provider matrix to add

All of these are OpenAI-compatible `chat_completions` endpoints. Model IDs are suggestions
from the owner's Hermes profiles and remain editable in the UI.

| id | label | base URL | key env | suggested model |
|---|---|---|---|---|
| `venice` | Venice.ai | `https://api.venice.ai/api/v1` | `AURASCAN_VENICE_API_KEY` | `deepseek-v4-1-flash-uncensored` |
| `refuseless` | Refuseless | `https://api.refuseless.com/v1` | `AURASCAN_REFUSELESS_API_KEY` | `glm-5.3-abliterated` |
| `experientiallabs` | ExperientialLabs | `https://api.experientiallabs.ai/v1` | `AURASCAN_EXPERIENTIALLABS_API_KEY` | `deepseek-v4.1-flash-uncensored` |
| `apinex` | Apinex | `https://api.apinex.bond/v1` | `AURASCAN_APINEX_API_KEY` | `gpt-6.1-sol` |
| `xiaomi` | Xiaomi MiMo | `https://api.xiaomimimo.com/v1` | `AURASCAN_XIAOMI_API_KEY` | `mimo-v2.6-pro` |
| `custom` | Custom (OpenAI-compatible) | required from user | `AURASCAN_CUSTOM_API_KEY` | required from user |

## Design

### 1. Data-driven transport

Add `base_url` to `AIProviderSpec`. For `api_family == "chat_completions"`, build the URL as
`base_url.rstrip("/") + "/chat/completions"` with a Bearer key. Keep Anthropic and Gemini
special-cased. Set each existing provider's `base_url` so the current URLs remain
byte-identical (`deepseek` stays `https://api.deepseek.com` with `/chat/completions`;
`openai` stays `https://api.openai.com/v1`).

This turns "support another provider" into a data change for OpenAI-compatible services.
`custom` covers services that are not in the preset list; no per-provider Python branch.

### 2. Base URL rules

- Presets: fixed HTTPS endpoint; `AURASCAN_AI_BASE_URL` is ignored so a typo cannot send
  package text to a different host.
- Local presets: loopback only, as today.
- `custom`: HTTPS anywhere, or plain HTTP only on a loopback literal. Reject credentials,
  query strings, fragments, non-`/v1`-style trailing junk that could hide a second host.
  Reject literal private/link-local/multicast IPs for a non-loopback custom endpoint.
  DNS rebinding is a documented residual; requests still refuse redirects.
- Model: required for `custom`; presets have an editable default. The accepted
  shape is 1-120 characters of `A-Za-z0-9._~:/@+-`, which admits the shipped
  OpenRouter default `~openai/gpt-latest` unchanged; both the CLI and the shell
  check that shape, and the CLI revalidates the stored value.

### 3. Settings writes

Add one atomic mutation, `aurascan settings set-ai-config`:

```
aurascan settings set-ai-config --provider ID [--model MODEL] [--base-url URL]
    [--enabled 0|1] --json
```

It validates every field, writes only the keys whose values were supplied, clears the base
URL override when switching to a preset, and preserves the stored credential. It never
enables AI implicitly. The existing `set-ai-key` remains the only secret path (stdin).

`project_settings` keeps returning presence, never values, and gains `default_model` and
`base_url` per provider so the UI can prefill fields.

### 4. Electron controls

The Settings view gets one card that edits the active configuration:

- provider dropdown (all presets plus Custom);
- model text field, prefilled with the provider default;
- base URL field, shown for Custom and local endpoints, fixed/read-only otherwise;
- enable switch, off by default, with one line of consent text;
- the existing credential field, scoped to the selected provider;
- a readiness badge and the existing "Store credential" action.

The shell gets one new fixed action, `configure_ai`, with a fixed argv. The renderer never
sends a command. Provider IDs are validated against a format regex in Electron and against
`PROVIDERS` by the CLI; the CLI is the authority. This removes the duplicated list problem:
the shell no longer needs a new release to accept a provider the CLI knows. A parity test
keeps the known list aligned.

All fields are ordinary config, not secrets. The key is passed on stdin and never in argv
or logs. "No key in the renderer" means no *stored* credential is returned to it: the
configuration projection carries presence only. The fresh password input necessarily holds
the user-entered text until it is submitted on stdin.

### 5. Key storage

Keep `~/.config/aurascan/.env` at `0600` for this slice. It is the file the CLI already
reads and the Settings panel already explains. OS keyring storage is a separate decision:
it adds a libsecret dependency and a second read path, and it would break the documented
"one private file" contract. The UI must state the path and permissions.

## Options

| Option | Effort | Benefit | Risk |
|---|---|---|---|
| A. Add presets only | low | keys can be stored for the new names | still cannot select a provider in the app; misses the request |
| **B. Presets + generic transport + settings writes + desktop controls** | medium | full configure-and-switch flow, custom endpoint escape hatch, one secret path | new config mutation surface; must validate URL and fields strictly |
| C. User-editable provider manifest | high | any future provider without a release | arbitrary endpoints and labels become user data; larger SSRF/UI surface |
| D. OS keyring now | medium | better at-rest protection | libsecret dependency, second credential source, migration |

**Recommendation: B.** It meets the request with one new mutation and one new shell action,
keeps secrets on stdin, and makes future OpenAI-compatible providers a data edit. Defer C
until a real provider cannot be expressed as a preset or a custom endpoint. Defer D until
the key file becomes a support burden.

## Tests

- `tests/test_ai_provider.py`: every preset builds the expected URL and Authorization header;
  `custom` requires base URL and model; unknown provider is rejected; HTTP/private-IP custom
  endpoints are rejected; error strings never contain the key or URL.
- `tests/test_ui_settings.py`: `set-ai-config` writes provider/model/base URL/enable
  atomically at `0600`; rejects unknown provider, control characters, invalid URL; preserves
  the key; `set-ai-key` still refuses unknown providers.
- `tests/test_setup_wizard.py`: new providers appear in choices; `--provider venice` stores
  `AURASCAN_VENICE_API_KEY`; `--base-url` remains restricted to local/custom.
- `desktop/src/settings.test.ts`, `shell.test.ts`, `shell-boundary.test.ts`: parser accepts
  the new fields; `configure_ai` argv is fixed; invalid provider/model/URL is refused; no
  secret appears in argv or the child environment; the view renders the controls.
- A small parity check between the Electron known-provider list and `PROVIDERS`.
- Manual smoke: choose Venice, paste a read-only test key, save, enable, run `aurascan doctor
  --check-ai`; confirm no stored key is projected back into the renderer and the value never
  appears in argv or logs.

## Out of scope for this slice

- Model discovery / live model list from `/models`.
- OS keyring.
- A user-editable provider manifest.
- Provider-specific headers beyond Bearer (Venice and the others work with Bearer).
- Changing the strict JSON output validation; all providers still go through it.

## Implementation status

Option B is implemented in the unreleased tree. What shipped, with the parts
that differ from the design above:

- `AIProviderSpec.base_url` is the single endpoint source. Every
  `chat_completions` provider — preset, local and `custom` — builds
  `base_url.rstrip("/") + "/chat/completions"`; Anthropic and Gemini keep their
  own branches. Existing URLs are byte-identical.
- `user_base_url` on the spec marks the providers whose endpoint the user may
  override (`lmstudio`, `llamacpp`, `custom`); every other preset ignores
  `AURASCAN_AI_BASE_URL`. `set-ai-config` drops a stale override when switching
  to a fixed-URL preset.
- `normalize_custom_base_url` enforces the documented rules: HTTPS anywhere,
  plain HTTP only on a loopback literal, no userinfo/query/fragment/control
  characters, ≤512 characters, an ASCII path without `..`, and no literal
  private/link-local/multicast/unspecified/reserved IP. The error strings never
  contain the URL or the key. `desktop/electron/argv.cjs` mirrors the same rules
  on the raw string before a child is spawned, including IPv6 literals; the CLI
  remains authoritative and revalidates the stored value.
- `normalize_model` accepts 1-120 characters of `A-Za-z0-9._~:/@+-`, so every
  shipped default — including OpenRouter's `~openai/gpt-latest` — saves without
  a manual edit. The desktop model shape is the same.
- `parseSettingsWrite` in both `desktop/electron/argv.cjs` and
  `desktop/src/contract.ts` accepts only `set_ai_key`/`set_ai_config` together
  with an explicit `stored: true`; a missing or non-boolean confirmation, or an
  unrelated action, is a failed save.
- `settings set-ai-config` writes only supplied fields, uses the existing
  atomic temp-file replace at `0600`, preserves the credential, and writes an
  explicit `AURASCAN_AI_ENABLED=0` only when the flag is absent. `set-ai-key` is
  unchanged.
- Electron validates provider/model/URL shapes in `argv.cjs` and lets the CLI
  own the provider inventory; a desktop test reads `PROVIDERS` from the Python
  source so the two stay aligned without a mirrored list.
- The Settings view is one card: provider, model (prefilled), base URL for
  Custom/local only, an off-by-default switch, and the credential field scoped
  to the selection. The readiness badge, config path and `0600` note stay.

### Transport proxy policy

Every transport refuses redirects. Proxy handling depends on the endpoint:

- Local presets (`lmstudio`, `llamacpp`) and a `custom` endpoint on a loopback host
  (`127.0.0.0/8`, `::1`, `::ffff:127.0.0.1`, `localhost`) disregard the environment:
  the opener is built with `ProxyHandler({})`, so `HTTP_PROXY`/`ALL_PROXY` never see the
  request line, the prompt or the Bearer key. No `NO_PROXY` entry is required.
- Every other endpoint, including a public `custom` host, keeps urllib's normal
  environment-proxy discovery: `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` and `NO_PROXY` are
  honoured exactly as for a preset cloud provider. A `custom` endpoint reached through a
  proxy therefore exposes the prompt and key to that proxy.

These controls are permanent offline regressions in `tests/test_ai_provider.py`
(`test_custom_loopback_endpoint_disables_proxies` and
`test_custom_public_endpoint_keeps_environment_proxy_discovery`): the transports are
fake, `HTTP_PROXY` is set explicitly, and no provider or network call is made.

### Remaining limits

- A public hostname is not re-resolved here, so DNS rebinding of a `custom`
  endpoint stays a documented residual (redirects are still refused).
- Recovery-session AI prompts for the custom endpoint but is not tested against a
  live provider.
- No live provider was contacted; every desktop/Python test uses fixtures.
