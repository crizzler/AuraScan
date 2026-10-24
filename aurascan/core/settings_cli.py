"""Read and update the invoking user's AuraScan settings for desktop clients.

This is a user-facing entry point. It reads only the invoking user's own
configuration (``~/.config/aurascan/.env``) and:

* reports secret settings as presence booleans, never as values;
* accepts a secret on stdin, so it never appears in argv or shell history;
* never contacts a network endpoint, starts a service, or runs a package tool.

Storing an AI credential does not enable AI. ``resolve_ai_config`` treats a
present key as enabled when the enable flag is unset, so this command writes an
explicit ``AURASCAN_AI_ENABLED=0`` in that case. Enabling AI stays a separate,
explicit user action.
"""

import argparse
import json
import sys
import urllib.parse
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence

from aurascan.core.ai_provider import (
    AI_BASE_URL_ENV,
    AI_ENABLED_ENV,
    AI_MODEL_ENV,
    AI_PROVIDER_ENV,
    PROVIDERS,
    get_provider_spec,
    parse_bool,
    resolve_ai_config,
)
from aurascan.core.config import (
    file_mode,
    read_env_file,
    user_env_path,
    write_user_env,
)

SETTINGS_SCHEMA = "aurascan-settings/1"
MAX_SECRET_BYTES = 4096
MAX_VALUE_CHARS = 512

# Fixed, ordered feature inventory. Every entry is an existing switch that the
# runtime already reads; the desktop never learns a setting the CLI does not
# own.
FEATURES = (
    ("ai", AI_ENABLED_ENV, "AI assistance"),
    ("upgrade_preflight", "AURASCAN_UPGRADE_PREFLIGHT_ENABLED", "Upgrade preflight"),
    ("upgrade_preflight_ai", "AURASCAN_UPGRADE_PREFLIGHT_AI", "Upgrade preflight AI"),
    ("kernel_module_autopilot", "AURASCAN_KERNEL_MODULE_AUTOPILOT_ENABLED", "Kernel module autopilot"),
    ("config_drift", "AURASCAN_CONFIG_DRIFT_ENABLED", "Configuration drift"),
    ("config_drift_ai", "AURASCAN_CONFIG_DRIFT_AI_DIFFS", "Configuration drift AI diffs"),
    ("incident_monitor", "AURASCAN_INCIDENT_MONITOR_ENABLED", "Incident monitor"),
    ("incident_ai", "AURASCAN_INCIDENT_AI_ENABLED", "Incident AI"),
    ("incident_background_ai", "AURASCAN_INCIDENT_BACKGROUND_AI", "Incident background AI"),
    ("incident_auto_repair", "AURASCAN_INCIDENT_AUTO_REPAIR", "Incident auto repair"),
    ("instruction_monitor", "AURASCAN_INSTRUCTION_MONITOR_ENABLED", "Instruction Guard monitor"),
    ("instruction_ai", "AURASCAN_INSTRUCTION_AI_ENABLED", "Instruction Guard AI"),
    ("recovery_ai", "AURASCAN_RECOVERY_AI_ENABLED", "Recovery AI"),
    ("recovery_auto_refresh", "AURASCAN_RECOVERY_AUTO_REFRESH", "Recovery auto refresh"),
    ("updater_tray", "AURASCAN_UPDATER_TRAY_ENABLED", "Updater tray"),
)

# Mutations this command exposes. A desktop client may only ever name one of
# these; there is no generic key/value writer.
MUTATIONS = ("set_ai_key",)


class SettingsError(RuntimeError):
    """An input or configuration problem that is safe to show to the user."""


def _bounded(value: object, limit: int = MAX_VALUE_CHARS) -> str:
    text = str(value or "").strip()
    return text[:limit]


def _display_path(path: Path) -> str:
    try:
        relative = path.resolve().relative_to(Path.home().resolve())
    except (OSError, ValueError):
        return str(path)
    return "~/" + str(relative)


def _safe_url(value: str) -> Optional[str]:
    """Return a display-safe URL, or ``None`` when it is not a plain URL.

    Credentials, query strings and fragments are never rendered, because a user
    may paste a token into a base URL.
    """

    raw = _bounded(value)
    if not raw:
        return None
    try:
        parsed = urllib.parse.urlsplit(raw)
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return None
    try:
        port = parsed.port
    except ValueError:
        port = None
    host = parsed.hostname
    if port is not None:
        host = "{0}:{1}".format(host, port)
    path = parsed.path.rstrip("/")
    return "{0}://{1}{2}".format(parsed.scheme.lower(), host, path)


def _config_state(path: Path) -> Dict[str, object]:
    present = path.exists()
    mode = file_mode(path) if present else None
    state: Dict[str, object] = {
        "path": _display_path(path),
        "present": present,
        "mode": None if mode is None else "{0:04o}".format(mode),
        "mode_ok": bool(mode is not None and not mode & 0o077),
        "readable": False,
    }
    if present:
        try:
            read_env_file(path)
            state["readable"] = True
        except OSError:
            state["readable"] = False
    return state


def _provider_entries(env: Mapping[str, str]) -> List[Dict[str, object]]:
    selected = _bounded(env.get(AI_PROVIDER_ENV, ""), 40).lower()
    entries: List[Dict[str, object]] = []
    for provider_id in sorted(PROVIDERS):
        spec = PROVIDERS[provider_id]
        entries.append(
            {
                "id": provider_id,
                "label": spec.label,
                "local": bool(spec.local),
                "requires_key": bool(spec.requires_api_key),
                "key_env": spec.key_env,
                "default_model": spec.default_model,
                "key_present": bool(env.get(spec.key_env, "").strip()),
                "selected": provider_id == selected,
            }
        )
    return entries


def _feature_entries(env: Mapping[str, str]) -> List[Dict[str, object]]:
    entries: List[Dict[str, object]] = []
    for feature_id, env_name, label in FEATURES:
        raw = env.get(env_name)
        entries.append(
            {
                "id": feature_id,
                "label": label,
                "env": env_name,
                "enabled": parse_bool(raw),
                "declared": raw is not None,
            }
        )
    return entries


def project_settings(
    env: Mapping[str, str],
    *,
    config_path: Path,
    config_state: Optional[Mapping[str, object]] = None,
) -> Dict[str, object]:
    """Return the ``aurascan-settings/1`` projection for one config snapshot.

    The AI section is derived from :func:`resolve_ai_config`, but every derived
    value is captured before the credential is discarded. Only booleans and
    labels leave this function, so a caller cannot accidentally serialize the
    secret.
    """

    resolved = resolve_ai_config(env)
    spec = get_provider_spec(resolved.provider)
    ai_state = {
        "enabled": bool(resolved.enabled),
        "provider": _bounded(resolved.provider, 40),
        "provider_label": spec.label if spec else "",
        "model": _bounded(resolved.model, 120),
        "base_url": _safe_url(resolved.base_url),
        "local": bool(spec.local) if spec else False,
        "requires_key": bool(spec.requires_api_key) if spec else True,
        "key_env": _bounded(resolved.key_env, 60),
        "key_present": bool(resolved.api_key),
        "supported": bool(resolved.supported),
        "authentication_ready": bool(resolved.authentication_ready),
        "error": _bounded(resolved.error, 60),
        "ready": bool(resolved.ready),
    }
    resolved.api_key = ""

    return {
        "schema": SETTINGS_SCHEMA,
        "config": dict(config_state or _config_state(config_path)),
        "ai": ai_state,
        "providers": _provider_entries(env),
        "features": _feature_entries(env),
        "mutation": {
            "supported": list(MUTATIONS),
            "secret_input": "stdin",
            "elevation_required": False,
            "policy_mutating": True,
        },
    }


def read_settings(config_path: Optional[Path] = None) -> Dict[str, object]:
    path = config_path or user_env_path()
    env: Dict[str, str] = {}
    state = _config_state(path)
    if state["readable"]:
        env = read_env_file(path)
    return project_settings(env, config_path=path, config_state=state)


def _validate_secret(value: str) -> str:
    secret = (value or "").strip()
    if not secret:
        raise SettingsError("no credential was provided on stdin")
    if len(secret) > MAX_SECRET_BYTES:
        raise SettingsError("credential input is too large")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in secret):
        raise SettingsError("credential input contains control characters")
    return secret


def _read_secret(stream) -> str:
    raw = stream.readline(MAX_SECRET_BYTES + 1)
    if len(raw) > MAX_SECRET_BYTES:
        raise SettingsError("credential input is too large")
    return _validate_secret(raw)


def store_ai_key(provider: str, secret: str, *, config_path: Optional[Path] = None) -> Dict[str, object]:
    """Persist one provider credential without echoing it anywhere."""

    spec = get_provider_spec(provider)
    if spec is None:
        raise SettingsError("unsupported AI provider: {0}".format(_bounded(provider, 40)))
    value = _validate_secret(secret)

    path = config_path or user_env_path()
    updates: Dict[str, str] = {spec.key_env: value}
    try:
        existing = read_env_file(path) if path.exists() else {}
    except OSError as exc:
        raise SettingsError("existing configuration could not be read") from exc
    # A stored credential is useless until a provider selects it. Only adopt the
    # requested provider when the user has not chosen one yet.
    if AI_PROVIDER_ENV not in existing:
        updates[AI_PROVIDER_ENV] = spec.provider_id
    # Never let a stored credential silently enable AI: the runtime treats a
    # present key as enabled when the flag is unset.
    if AI_ENABLED_ENV not in existing:
        updates[AI_ENABLED_ENV] = "0"

    try:
        written = write_user_env(updates, path)
    except (OSError, ValueError) as exc:
        raise SettingsError("configuration could not be written") from exc

    state = _config_state(written)
    projection = project_settings(
        read_env_file(written) if state["readable"] else {},
        config_path=written,
        config_state=state,
    )
    return {
        "schema": SETTINGS_SCHEMA,
        "action": "set_ai_key",
        "stored": True,
        "provider": spec.provider_id,
        "key_env": spec.key_env,
        "config": projection["config"],
        "ai": projection["ai"],
    }


def _print_summary(projection: Mapping[str, object], stream) -> None:
    config = projection.get("config", {})
    ai = projection.get("ai", {})
    print("AuraScan settings", file=stream)
    print(
        "Config: {0} ({1})".format(
            config.get("path", "unknown"),
            "present" if config.get("present") else "not created",
        ),
        file=stream,
    )
    print(
        "AI: {0} | provider: {1} | model: {2} | credential: {3}".format(
            "enabled" if ai.get("enabled") else "disabled",
            ai.get("provider") or "unset",
            ai.get("model") or "unset",
            "stored" if ai.get("key_present") else ("not required" if not ai.get("requires_key") else "missing"),
        ),
        file=stream,
    )
    for feature in projection.get("features", []):
        state = "on" if feature.get("enabled") else ("off" if feature.get("declared") else "unset")
        print("  {0}: {1}".format(feature.get("label"), state), file=stream)


def build_settings_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aurascan settings",
        description="Inspect or update the invoking user's AuraScan settings.",
    )
    parser.add_argument("--json", action="store_true", dest="json_mode", help="emit a structured JSON document")
    commands = parser.add_subparsers(dest="verb")
    show = commands.add_parser("show", help="show effective settings (default)")
    show.add_argument("--json", action="store_true", dest="json_mode", help="emit a structured JSON document")
    set_key = commands.add_parser(
        "set-ai-key",
        help="store one provider credential read from stdin",
    )
    set_key.add_argument("--provider", required=True, help="AI provider id")
    set_key.add_argument("--json", action="store_true", dest="json_mode", help="emit a structured JSON document")
    return parser


def run_settings(argv: Sequence[str], *, stdin=None, stdout=None, stderr=None) -> int:
    parser = build_settings_parser()
    try:
        args = parser.parse_args(list(argv))
    except SystemExit:
        return 2
    out = stdout or sys.stdout
    err = stderr or sys.stderr

    try:
        if args.verb == "set-ai-key":
            secret = _read_secret(stdin or sys.stdin)
            result = store_ai_key(args.provider, secret)
            del secret
            print(json.dumps(result, indent=2, sort_keys=True), file=out)
            return 0
        projection = read_settings()
    except SettingsError as exc:
        message = str(exc)
        if args.json_mode:
            print(json.dumps({"error": message}, indent=2, sort_keys=True), file=out)
        else:
            print("[AuraScan] {0}".format(message), file=err)
        return 2

    if args.json_mode:
        print(json.dumps(projection, indent=2, sort_keys=True), file=out)
    else:
        _print_summary(projection, out)
    return 0
