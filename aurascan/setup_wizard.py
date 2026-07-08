import argparse
import getpass
import json
import os
import shutil
import subprocess
import sys
import urllib.error
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Mapping, Optional

from aurascan.core.ai_provider import (
    AI_ENABLED_ENV,
    AI_MODEL_ENV,
    AI_PROVIDER_ENV,
    PROVIDERS,
    call_ai_provider,
    connectivity_prompt,
    get_provider_spec,
    provider_choices,
    resolve_ai_config,
)
from aurascan.core.config import file_mode, read_env_file, user_env_path, write_user_env
from aurascan.core.config_drift import (
    CONFIG_DRIFT_AI_DIFFS_ENV,
    CONFIG_DRIFT_AI_DIFFS_VALUES,
    CONFIG_DRIFT_ENABLED_ENV,
    resolve_config_drift_config,
)
from aurascan.core.upgrade_preflight import (
    UPGRADE_AUR_HELPERS,
    UPGRADE_PREFLIGHT_AI_ENV,
    UPGRADE_PREFLIGHT_AUR_HELPER_ENV,
    UPGRADE_PREFLIGHT_ENABLED_ENV,
    resolve_upgrade_config,
)

LOCAL_HOOK_PATH = Path("/etc/pacman.d/hooks/aurascan.hook")
PACKAGED_HOOK_PATH = Path("/usr/share/libalpm/hooks/aurascan.hook")
INSTALLED_AURASCAN = Path("/usr/bin/aurascan")
TEMPLATE_HOOK_PATH = Path(__file__).resolve().parents[1] / "packaging" / "arch" / "aurascan.hook"


@dataclass
class HookInstallResult:
    ok: bool
    status: str
    message: str


@dataclass
class DoctorCheck:
    name: str
    status: str
    message: str
    details: Optional[Dict[str, object]] = None

    def to_dict(self) -> Dict[str, object]:
        data = {"name": self.name, "status": self.status, "message": self.message}
        if self.details:
            data["details"] = self.details
        return data


def build_init_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aurascan init",
        description="Configure AuraScan AI provider settings and optional pacman hook setup.",
    )
    parser.add_argument("--provider", choices=provider_choices(), help="AI provider to configure")
    parser.add_argument("--model", help="AI model override")
    ai = parser.add_mutually_exclusive_group()
    ai.add_argument("--enable-ai", action="store_true", help="enable configured network AI analysis")
    ai.add_argument("--disable-ai", action="store_true", help="write config that keeps network AI disabled")
    parser.add_argument("--check-ai", action="store_true", help="run one harmless provider connectivity check")
    upgrade = parser.add_mutually_exclusive_group()
    upgrade.add_argument("--enable-upgrade-preflight", action="store_true", help="enable aurascan upgrade preflight defaults")
    upgrade.add_argument("--disable-upgrade-preflight", action="store_true", help="disable aurascan upgrade preflight defaults")
    parser.add_argument("--upgrade-aur-helper", choices=sorted(UPGRADE_AUR_HELPERS), help="default AUR helper for aurascan upgrade")
    upgrade_ai = parser.add_mutually_exclusive_group()
    upgrade_ai.add_argument("--enable-upgrade-ai", action="store_true", help="allow AI risk review during upgrade preflight when AI is configured")
    upgrade_ai.add_argument("--disable-upgrade-ai", action="store_true", help="disable AI risk review during upgrade preflight")
    config_drift = parser.add_mutually_exclusive_group()
    config_drift.add_argument("--enable-config-drift", action="store_true", help="enable the config drift assistant for upgrades")
    config_drift.add_argument("--disable-config-drift", action="store_true", help="disable the config drift assistant for upgrades")
    parser.add_argument("--config-drift-ai-diffs", choices=sorted(CONFIG_DRIFT_AI_DIFFS_VALUES), help="AI diff sharing policy for the config drift assistant")
    hook = parser.add_mutually_exclusive_group()
    hook.add_argument("--install-hook", action="store_true", help="offer sudo install of the local pacman hook")
    hook.add_argument("--no-install-hook", action="store_true", help="skip pacman hook setup")
    return parser


def build_doctor_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aurascan doctor",
        description="Check AuraScan configuration, optional tools, AI provider readiness, and hook health.",
    )
    parser.add_argument("--json", action="store_true", dest="json_mode", help="emit doctor results as JSON")
    parser.add_argument("--check-ai", action="store_true", help="run one harmless provider connectivity check")
    return parser


def run_init(
    argv=None,
    *,
    input_func: Callable[[str], str] = input,
    getpass_func: Callable[[str], str] = getpass.getpass,
    stdout=None,
    stderr=None,
    env_path: Optional[Path] = None,
    runner: Callable = subprocess.run,
    urlopen: Optional[Callable] = None,
    executable_path: Path = INSTALLED_AURASCAN,
    hook_path: Path = LOCAL_HOOK_PATH,
    template_path: Path = TEMPLATE_HOOK_PATH,
) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    args = build_init_parser().parse_args(argv)
    target_env = env_path or user_env_path()
    existing = _safe_read_env(target_env)

    print("AuraScan first-run setup", file=stdout)
    print("Network AI analysis can send package metadata, PKGBUILD text, and install-script text to the selected provider.", file=stdout)

    updates: Dict[str, str] = {}
    configure_ai = bool(args.provider)
    if not configure_ai and not args.disable_ai:
        configure_ai = _prompt_yes_no("Configure a network AI provider now?", input_func, default=False)

    if args.disable_ai or not configure_ai:
        updates[AI_ENABLED_ENV] = "0"
        print("Network AI analysis will stay disabled unless you enable it later.", file=stdout)
    else:
        provider = args.provider or _prompt_provider(input_func, existing.get(AI_PROVIDER_ENV, "openai"), stdout)
        spec = get_provider_spec(provider)
        if spec is None:
            print(f"Unsupported AI provider: {provider}", file=stderr)
            return 1

        model = args.model
        if model is None:
            model = input_func(f"Model [{spec.default_model}]: ").strip() or spec.default_model
        key = getpass_func(f"{spec.label} API key (input hidden): ").strip()
        if not key:
            print("No API key entered; leaving network AI disabled.", file=stdout)
            updates[AI_ENABLED_ENV] = "0"
        else:
            enabled = args.enable_ai
            if not args.enable_ai and not args.disable_ai:
                enabled = _prompt_yes_no(
                    "Enable network AI analysis for normal scans?",
                    input_func,
                    default=False,
                )
            updates.update({
                AI_PROVIDER_ENV: provider,
                AI_MODEL_ENV: model,
                spec.key_env: key,
                AI_ENABLED_ENV: "1" if enabled else "0",
            })
            print(f"Configured {spec.label}. API key saved without printing it.", file=stdout)
            if not enabled:
                print("Network AI analysis is configured but disabled.", file=stdout)

    configure_upgrade = (
        args.enable_upgrade_preflight
        or args.disable_upgrade_preflight
        or args.upgrade_aur_helper is not None
        or args.enable_upgrade_ai
        or args.disable_upgrade_ai
    )
    should_prompt_upgrade = not configure_upgrade and not (
        args.provider
        or args.enable_ai
        or args.disable_ai
        or args.install_hook
        or args.no_install_hook
    )
    if configure_upgrade or should_prompt_upgrade:
        existing_upgrade = resolve_upgrade_config(existing)
        upgrade_enabled = existing_upgrade.preflight_enabled if not existing_upgrade.error else True
        if args.enable_upgrade_preflight:
            upgrade_enabled = True
        elif args.disable_upgrade_preflight:
            upgrade_enabled = False
        elif should_prompt_upgrade:
            upgrade_enabled = _prompt_yes_no(
                "Enable upgrade preflight for aurascan upgrade?",
                input_func,
                default=upgrade_enabled,
            )
        updates[UPGRADE_PREFLIGHT_ENABLED_ENV] = "1" if upgrade_enabled else "0"

        if upgrade_enabled:
            helper_default = existing_upgrade.aur_helper if not existing_upgrade.error else "auto"
            helper = args.upgrade_aur_helper or (
                _prompt_upgrade_helper(input_func, helper_default, stdout) if should_prompt_upgrade else helper_default
            )
            updates[UPGRADE_PREFLIGHT_AUR_HELPER_ENV] = helper

            upgrade_ai_enabled = existing_upgrade.ai_enabled if not existing_upgrade.error else True
            if args.enable_upgrade_ai:
                upgrade_ai_enabled = True
            elif args.disable_upgrade_ai:
                upgrade_ai_enabled = False
            elif should_prompt_upgrade:
                upgrade_ai_enabled = _prompt_yes_no(
                    "Allow AI risk review during upgrade preflight when network AI is enabled?",
                    input_func,
                    default=upgrade_ai_enabled,
                )
            updates[UPGRADE_PREFLIGHT_AI_ENV] = "1" if upgrade_ai_enabled else "0"
            print("Configured upgrade preflight defaults.", file=stdout)
        else:
            print("Upgrade preflight will be disabled unless you enable it later.", file=stdout)

    configure_config_drift = (
        args.enable_config_drift
        or args.disable_config_drift
        or args.config_drift_ai_diffs is not None
    )
    should_prompt_config_drift = should_prompt_upgrade and updates.get(UPGRADE_PREFLIGHT_ENABLED_ENV, "1") == "1"
    if configure_config_drift or should_prompt_config_drift:
        existing_drift = resolve_config_drift_config(existing)
        drift_enabled = existing_drift.enabled if not existing_drift.error else True
        if args.enable_config_drift:
            drift_enabled = True
        elif args.disable_config_drift:
            drift_enabled = False
        elif should_prompt_config_drift:
            drift_enabled = _prompt_yes_no(
                "Enable config drift assistant for .pacnew/.pacsave files during upgrades?",
                input_func,
                default=drift_enabled,
            )
        updates[CONFIG_DRIFT_ENABLED_ENV] = "1" if drift_enabled else "0"
        if drift_enabled:
            ai_diff_policy = existing_drift.ai_diffs if not existing_drift.error else "ask"
            ai_diff_policy = args.config_drift_ai_diffs or (
                _prompt_config_drift_ai_diffs(input_func, ai_diff_policy, stdout) if should_prompt_config_drift else ai_diff_policy
            )
            updates[CONFIG_DRIFT_AI_DIFFS_ENV] = ai_diff_policy
            print("Configured config drift assistant defaults.", file=stdout)
        else:
            print("Config drift assistant will be disabled unless you enable it later.", file=stdout)

    write_user_env(updates, path=target_env)
    print(f"Wrote user config: {target_env}", file=stdout)

    if args.check_ai:
        check_env = dict(os.environ)
        check_env.update(_safe_read_env(target_env))
        check = _check_ai_connectivity(check_env, urlopen=urlopen)
        print(_format_check_line(check), file=stdout)

    install_hook = args.install_hook
    if not args.install_hook and not args.no_install_hook:
        install_hook = _prompt_yes_no("Install or repair the local pacman hook now?", input_func, default=False)
    if install_hook:
        result = install_pacman_hook(
            template_path=template_path,
            executable_path=executable_path,
            hook_path=hook_path,
            runner=runner,
        )
        stream = stdout if result.ok else stderr
        print(result.message, file=stream)
        return 0 if result.ok else 1

    print("Pacman hook setup skipped.", file=stdout)
    return 0


def run_doctor(
    argv=None,
    *,
    stdout=None,
    env_path: Optional[Path] = None,
    env: Optional[Mapping[str, str]] = None,
    urlopen: Optional[Callable] = None,
    executable_path: Path = INSTALLED_AURASCAN,
    local_hook_path: Path = LOCAL_HOOK_PATH,
    packaged_hook_path: Path = PACKAGED_HOOK_PATH,
) -> int:
    stdout = stdout or sys.stdout
    args = build_doctor_parser().parse_args(argv)
    checks = build_doctor_checks(
        env_path=env_path or user_env_path(),
        env=env,
        check_ai=args.check_ai,
        urlopen=urlopen,
        executable_path=executable_path,
        local_hook_path=local_hook_path,
        packaged_hook_path=packaged_hook_path,
    )
    has_error = any(check.status == "error" for check in checks)
    if args.json_mode:
        print(json.dumps({
            "ok": not has_error,
            "checks": [check.to_dict() for check in checks],
        }, indent=2), file=stdout)
    else:
        print("AuraScan doctor", file=stdout)
        for check in checks:
            print(_format_check_line(check), file=stdout)
    return 1 if has_error else 0


def build_doctor_checks(
    *,
    env_path: Path,
    env: Optional[Mapping[str, str]] = None,
    check_ai: bool = False,
    urlopen: Optional[Callable] = None,
    executable_path: Path = INSTALLED_AURASCAN,
    local_hook_path: Path = LOCAL_HOOK_PATH,
    packaged_hook_path: Path = PACKAGED_HOOK_PATH,
) -> List[DoctorCheck]:
    checks: List[DoctorCheck] = []
    file_values = _safe_read_env(env_path)
    effective_env = dict(os.environ if env is None else env)
    effective_env.update(file_values)

    if env_path.exists():
        checks.append(DoctorCheck("config_file", "ok", f"User config found at {env_path}"))
        mode = file_mode(env_path)
        if mode == 0o600:
            checks.append(DoctorCheck("config_permissions", "ok", "User config permissions are 0600", {"mode": "0600"}))
        else:
            mode_text = "unknown" if mode is None else oct(mode)
            checks.append(DoctorCheck("config_permissions", "warn", f"User config permissions are {mode_text}; expected 0600", {"mode": mode_text}))
    else:
        checks.append(DoctorCheck("config_file", "warn", f"User config not found at {env_path}"))

    ai_config = resolve_ai_config(effective_env)
    if ai_config.error == "unsupported_provider":
        checks.append(DoctorCheck("ai_provider", "error", f"Unsupported AI provider: {ai_config.provider}"))
    elif ai_config.error == "invalid_enabled_value":
        checks.append(DoctorCheck("ai_enabled", "error", f"Invalid {AI_ENABLED_ENV} value"))
    else:
        spec = get_provider_spec(ai_config.provider)
        label = spec.label if spec else ai_config.provider
        checks.append(DoctorCheck("ai_provider", "ok", f"AI provider: {label}", {"provider": ai_config.provider, "model": ai_config.model}))
        if ai_config.enabled:
            if ai_config.api_key_present:
                checks.append(DoctorCheck("ai_key", "ok", f"AI key present in {ai_config.key_env}", {"key_env": ai_config.key_env, "key_present": True}))
            else:
                checks.append(DoctorCheck("ai_key", "error", f"AI is enabled but {ai_config.key_env} is not set", {"key_env": ai_config.key_env, "key_present": False}))
        else:
            checks.append(DoctorCheck("ai_enabled", "warn", "Network AI analysis is disabled", {"enabled": False}))

    if check_ai:
        checks.append(_check_ai_connectivity(effective_env, urlopen=urlopen))

    upgrade_config = resolve_upgrade_config(effective_env)
    if upgrade_config.error:
        checks.append(DoctorCheck("upgrade_preflight", "error", upgrade_config.error))
    elif upgrade_config.preflight_enabled:
        checks.append(DoctorCheck(
            "upgrade_preflight",
            "ok",
            "Upgrade preflight is enabled",
            {
                "enabled": True,
                "aur_helper": upgrade_config.aur_helper,
                "ai_review_enabled": upgrade_config.ai_enabled,
            },
        ))
        if upgrade_config.aur_helper in {"paru", "yay", "shelly"} and not shutil.which(upgrade_config.aur_helper):
            checks.append(DoctorCheck(
                "upgrade_aur_helper",
                "warn",
                f"Configured AUR helper {upgrade_config.aur_helper} was not found in PATH",
                {"aur_helper": upgrade_config.aur_helper},
            ))
    else:
        checks.append(DoctorCheck("upgrade_preflight", "warn", "Upgrade preflight is disabled", {"enabled": False}))

    drift_config = resolve_config_drift_config(effective_env)
    if drift_config.error:
        checks.append(DoctorCheck("config_drift", "error", drift_config.error))
    elif drift_config.enabled:
        checks.append(DoctorCheck(
            "config_drift",
            "ok",
            "Config drift assistant is enabled",
            {"enabled": True, "ai_diff_policy": drift_config.ai_diffs},
        ))
    else:
        checks.append(DoctorCheck("config_drift", "warn", "Config drift assistant is disabled", {"enabled": False}))

    for tool in ("clamscan", "bsdtar", "gpg", "makepkg", "pacman", "vercmp"):
        found = shutil.which(tool)
        status = "ok" if found else "warn"
        message = f"{tool} found at {found}" if found else f"{tool} not found; related checks will be skipped when optional"
        checks.append(DoctorCheck(f"tool_{tool}", status, message))

    checks.append(_check_executable(executable_path))
    checks.extend(_hook_checks(local_hook_path=local_hook_path, packaged_hook_path=packaged_hook_path))
    return checks


def install_pacman_hook(
    *,
    template_path: Path = TEMPLATE_HOOK_PATH,
    executable_path: Path = INSTALLED_AURASCAN,
    hook_path: Path = LOCAL_HOOK_PATH,
    runner: Callable = subprocess.run,
) -> HookInstallResult:
    if not executable_path.exists():
        return HookInstallResult(False, "error", f"Refusing hook install: {executable_path} does not exist.")
    if not is_release_safe_hook_template(template_path):
        return HookInstallResult(False, "error", f"Refusing hook install: {template_path} is not release-safe.")
    try:
        result = runner(["sudo", "install", "-Dm644", str(template_path), str(hook_path)], check=False)
    except OSError as exc:
        return HookInstallResult(False, "error", f"Hook install failed: {exc}")
    if result.returncode != 0:
        return HookInstallResult(False, "error", f"Hook install failed with exit code {result.returncode}.")
    return HookInstallResult(True, "ok", f"Installed pacman hook at {hook_path}.")


def is_release_safe_hook_template(path: Path) -> bool:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return False
    forbidden = ["/home/", ".venv", "PYTHONPATH", "--scan-context", "--deep-static"]
    return "Exec = /usr/bin/aurascan" in text and not any(item in text for item in forbidden)


def _prompt_provider(input_func: Callable[[str], str], default: str, stdout) -> str:
    choices = list(provider_choices())
    default = default if default in PROVIDERS else "openai"
    print("Available AI providers:", file=stdout)
    for index, provider in enumerate(choices, start=1):
        spec = PROVIDERS[provider]
        marker = " default" if provider == default else ""
        print(f"  {index}. {spec.label} ({provider}){marker}", file=stdout)
    while True:
        answer = input_func(f"Provider [{default}]: ").strip().lower()
        if not answer:
            return default
        if answer in PROVIDERS:
            return answer
        if answer.isdigit() and 1 <= int(answer) <= len(choices):
            return choices[int(answer) - 1]
        print("Please choose a listed provider.", file=stdout)


def _prompt_upgrade_helper(input_func: Callable[[str], str], default: str, stdout) -> str:
    choices = ["auto", "paru", "yay", "shelly", "none"]
    default = default if default in choices else "auto"
    print("Upgrade preflight AUR helper defaults:", file=stdout)
    for index, helper in enumerate(choices, start=1):
        marker = " default" if helper == default else ""
        print(f"  {index}. {helper}{marker}", file=stdout)
    while True:
        answer = input_func(f"Upgrade AUR helper [{default}]: ").strip().lower()
        if not answer:
            return default
        if answer in choices:
            return answer
        if answer.isdigit() and 1 <= int(answer) <= len(choices):
            return choices[int(answer) - 1]
        print("Please choose a listed helper.", file=stdout)


def _prompt_config_drift_ai_diffs(input_func: Callable[[str], str], default: str, stdout) -> str:
    choices = ["ask", "never", "always"]
    default = default if default in choices else "ask"
    print("Config drift AI diff sharing defaults:", file=stdout)
    for index, policy in enumerate(choices, start=1):
        marker = " default" if policy == default else ""
        print(f"  {index}. {policy}{marker}", file=stdout)
    while True:
        answer = input_func(f"Config drift AI diffs [{default}]: ").strip().lower()
        if not answer:
            return default
        if answer in choices:
            return answer
        if answer.isdigit() and 1 <= int(answer) <= len(choices):
            return choices[int(answer) - 1]
        print("Please choose a listed policy.", file=stdout)


def _prompt_yes_no(prompt: str, input_func: Callable[[str], str], *, default: bool) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    answer = input_func(f"{prompt} {suffix} ").strip().lower()
    if not answer:
        return default
    return answer in {"y", "yes"}


def _safe_read_env(path: Path) -> Dict[str, str]:
    if not path.exists():
        return {}
    try:
        return read_env_file(path)
    except OSError:
        return {}


def _check_ai_connectivity(env: Mapping[str, str], *, urlopen: Optional[Callable] = None) -> DoctorCheck:
    config = resolve_ai_config(env)
    if config.error:
        return DoctorCheck("ai_connectivity", "error", f"AI connectivity check skipped: {config.error}")
    if not config.enabled:
        return DoctorCheck("ai_connectivity", "warn", "AI connectivity check skipped because network AI is disabled")
    if not config.api_key_present:
        return DoctorCheck("ai_connectivity", "error", f"AI connectivity check skipped: {config.key_env} is missing")
    try:
        text = call_ai_provider(config, connectivity_prompt(), timeout=15, urlopen=urlopen)
    except urllib.error.URLError as exc:
        return DoctorCheck("ai_connectivity", "error", f"AI connectivity failed: {exc}")
    except Exception as exc:
        return DoctorCheck("ai_connectivity", "error", f"AI connectivity failed: {exc}")
    if text.startswith("BENIGN:"):
        return DoctorCheck("ai_connectivity", "ok", "AI provider connectivity check passed")
    return DoctorCheck("ai_connectivity", "warn", "AI provider responded, but not with AuraScan's expected test format")


def _check_executable(path: Path) -> DoctorCheck:
    if path.exists():
        return DoctorCheck("installed_executable", "ok", f"Installed executable found at {path}")
    return DoctorCheck("installed_executable", "warn", f"{path} not found; pacman hook install will be refused until AuraScan is installed system-wide")


def _hook_checks(*, local_hook_path: Path = LOCAL_HOOK_PATH, packaged_hook_path: Path = PACKAGED_HOOK_PATH) -> List[DoctorCheck]:
    checks = []
    for name, path in (("local_pacman_hook", local_hook_path), ("packaged_pacman_hook", packaged_hook_path)):
        if not path.exists():
            checks.append(DoctorCheck(name, "warn", f"{path} is not installed"))
            continue
        if is_release_safe_hook_template(path):
            checks.append(DoctorCheck(name, "ok", f"{path} is installed and release-safe"))
        else:
            checks.append(DoctorCheck(name, "error", f"{path} is installed but does not match AuraScan release-safety rules"))
    return checks


def _format_check_line(check: DoctorCheck) -> str:
    label = check.status.upper()
    return f"[{label}] {check.message}"
